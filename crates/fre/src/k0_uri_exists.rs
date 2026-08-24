//! Exact value-only existence for a class-guarded literal corridor.
//!
//! The established value-only language is
//! `START_CLASS CONTINUE_CLASS* LITERAL RIGHT_CLASS+ OPTIONAL?`, where the
//! optional tail is one zero-or-one repetition. The literal's leading byte is
//! outside both left classes, so occurrences partition the backward class
//! scans. A root two-branch alternation may pair this language with the
//! existing exact `BYTE_CLASS+ BYTE BYTE_CLASS+` predicate.
//!
//! A direct non-composite `CLASS+ LITERAL CLASS+` topology also admits bounded
//! ordinary full-input projections. Ascending literal occurrences and the
//! excluded leading byte prove the globally earliest left run; a greedy right
//! repetition proves the selected end. Dense candidate streams decline to the
//! generic K0 owner without publishing a partial result.

use memchr::{memchr2_iter, memchr_iter, memmem};
use regex_syntax::hir::{Class, ClassBytes, Hir, HirKind};

use crate::k0_class_delimiter_exists;

pub(crate) const PLAN_ID: &str = "k0.class-star-literal-class-plus.v1";
pub(crate) const CLASS_PLUS_PLAN_ID: &str = "k0.class-plus-literal-class-plus.v1";
pub(crate) const COMPOSITE_PLAN_ID: &str = "k0.class-star-literal-class-plus-or-class-delimiter.v2";
pub(crate) const OPERATION_ID: &str = "k0.exists.class-star-literal-class-plus.v1";
pub(crate) const CLASS_PLUS_OPERATION_ID: &str =
    "k0.exists.class-plus-literal-class-plus.v1";
pub(crate) const COMPOSITE_OPERATION_ID: &str =
    "k0.exists.class-star-literal-class-plus-or-class-delimiter.fused-delimiters.v2";

const MAX_LITERAL_BYTES: usize = 8;
const MAX_ORDINARY_LEADING_CANDIDATES: usize = 8;
const DIRECT_WORK_PER_INPUT_BYTE: u64 = 6;
// The fused stream removes the second whole-input scan while retaining the
// prior conservative envelope: candidate-byte loads, bounded literal checks,
// partitioned backward class walks, and the two adjacent delimiter checks fit
// within the original 9N certificate.
const COMPOSITE_WORK_PER_INPUT_BYTE: u64 = 9;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Identity {
    pub(crate) plan_id: &'static str,
    pub(crate) operation_id: &'static str,
    pub(crate) start_words: [u64; 4],
    pub(crate) continue_words: [u64; 4],
    pub(crate) literal: [u8; MAX_LITERAL_BYTES],
    pub(crate) literal_len: u8,
    pub(crate) right_words: [u64; 4],
    pub(crate) optional_tail: bool,
    pub(crate) alternative: Option<k0_class_delimiter_exists::Identity>,
    pub(crate) unicode: bool,
    pub(crate) full_input: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Plan {
    identity: Identity,
    alternative: Option<k0_class_delimiter_exists::Plan>,
}

impl Plan {
    pub(crate) const fn identity(self) -> Identity {
        self.identity
    }

    pub(crate) const fn prepared_work_per_input_byte(self) -> u64 {
        if self.alternative.is_some() {
            COMPOSITE_WORK_PER_INPUT_BYTE
        } else {
            DIRECT_WORK_PER_INPUT_BYTE
        }
    }

    pub(crate) const fn is_composite(self) -> bool {
        self.alternative.is_some()
    }

    #[inline]
    pub(crate) fn try_ordinary_is_match_full(self, haystack: &[u8]) -> Option<bool> {
        if self.identity.plan_id != CLASS_PLUS_PLAN_ID || self.alternative.is_some() {
            return None;
        }
        self.try_class_plus_is_match_full(haystack)
    }

    #[inline]
    pub(crate) fn try_ordinary_find_full(
        self,
        haystack: &[u8],
    ) -> Option<Option<(usize, usize)>> {
        if self.identity.plan_id != CLASS_PLUS_PLAN_ID || self.alternative.is_some() {
            return None;
        }
        self.try_class_plus_find_full(haystack)
    }

    #[inline]
    pub(crate) fn is_match_full(self, haystack: &[u8]) -> bool {
        if self.uri_like_is_match(haystack) {
            return true;
        }
        self.alternative
            .is_some_and(|plan| plan.is_match_full(haystack))
    }

    #[inline]
    pub(crate) fn is_match_fused_composite_full(self, haystack: &[u8]) -> bool {
        let Some(alternative) = self.alternative else {
            return self.uri_like_is_match(haystack);
        };
        if haystack.len() < 3 {
            return false;
        }
        let alternative = alternative.identity();
        let literal_len = usize::from(self.identity.literal_len);
        let literal = &self.identity.literal[..literal_len];
        for start in memchr2_iter(literal[0], alternative.delimiter, haystack) {
            if haystack[start] == literal[0] {
                let Some(end) = start.checked_add(literal_len) else {
                    return false;
                };
                if haystack.get(start..end) == Some(literal)
                    && self.uri_like_is_match_at(haystack, start, end)
                {
                    return true;
                }
            }
            let Some(right) = start.checked_add(1) else {
                return false;
            };
            if haystack[start] == alternative.delimiter
                && start != 0
                && right < haystack.len()
                && contains(alternative.left_words, haystack[start - 1])
                && contains(alternative.right_words, haystack[right])
            {
                return true;
            }
        }
        false
    }

    #[inline]
    fn uri_like_is_match(self, haystack: &[u8]) -> bool {
        let literal_len = usize::from(self.identity.literal_len);
        if haystack.len() < literal_len.saturating_add(2) {
            return false;
        }
        let literal = &self.identity.literal[..literal_len];
        for start in memmem::find_iter(haystack, literal) {
            let Some(end) = start.checked_add(literal_len) else {
                return false;
            };
            if start == 0
                || end >= haystack.len()
                || !contains(self.identity.right_words, haystack[end])
            {
                continue;
            }
            let mut left = start;
            while left != 0 {
                left -= 1;
                let byte = haystack[left];
                if contains(self.identity.start_words, byte) {
                    return true;
                }
                if !contains(self.identity.continue_words, byte) {
                    break;
                }
            }
        }
        false
    }

    #[inline]
    fn uri_like_is_match_at(&self, haystack: &[u8], start: usize, end: usize) -> bool {
        if start == 0
            || end >= haystack.len()
            || !contains(self.identity.right_words, haystack[end])
        {
            return false;
        }
        let mut left = start;
        while left != 0 {
            left -= 1;
            let byte = haystack[left];
            if contains(self.identity.start_words, byte) {
                return true;
            }
            if !contains(self.identity.continue_words, byte) {
                break;
            }
        }
        false
    }

    #[inline]
    fn try_class_plus_find_full(self, haystack: &[u8]) -> Option<Option<(usize, usize)>> {
        let literal_len = usize::from(self.identity.literal_len);
        if haystack.len() < literal_len.saturating_add(2) {
            return Some(None);
        }
        let literal = &self.identity.literal[..literal_len];
        let mut leading_candidates = 0usize;
        for literal_start in memchr_iter(literal[0], haystack) {
            leading_candidates = leading_candidates.saturating_add(1);
            if leading_candidates > MAX_ORDINARY_LEADING_CANDIDATES {
                return None;
            }
            let literal_end = literal_start.checked_add(literal_len)?;
            if haystack.get(literal_start..literal_end) != Some(literal)
                || literal_start == 0
                || literal_end >= haystack.len()
                || !contains(self.identity.right_words, haystack[literal_end])
            {
                continue;
            }

            let mut match_start = literal_start;
            while match_start != 0
                && contains(self.identity.start_words, haystack[match_start - 1])
            {
                match_start -= 1;
            }
            if match_start == literal_start {
                continue;
            }

            let mut match_end = literal_end + 1;
            while match_end < haystack.len()
                && contains(self.identity.right_words, haystack[match_end])
            {
                match_end += 1;
            }
            return Some(Some((match_start, match_end)));
        }
        Some(None)
    }

    #[inline]
    fn try_class_plus_is_match_full(self, haystack: &[u8]) -> Option<bool> {
        let literal_len = usize::from(self.identity.literal_len);
        if haystack.len() < literal_len.saturating_add(2) {
            return Some(false);
        }
        let literal = &self.identity.literal[..literal_len];
        let mut leading_candidates = 0usize;
        for literal_start in memchr_iter(literal[0], haystack) {
            leading_candidates = leading_candidates.saturating_add(1);
            if leading_candidates > MAX_ORDINARY_LEADING_CANDIDATES {
                return None;
            }
            let literal_end = literal_start.checked_add(literal_len)?;
            if haystack.get(literal_start..literal_end) == Some(literal)
                && literal_start != 0
                && literal_end < haystack.len()
                && contains(self.identity.start_words, haystack[literal_start - 1])
                && contains(self.identity.right_words, haystack[literal_end])
            {
                return Some(true);
            }
        }
        Some(false)
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

pub(crate) fn inspect(
    hir: &Hir,
    initial_work: u64,
    work_limit: u64,
) -> Result<InspectionOutcome, InspectionError> {
    let mut budget = Budget::new(initial_work, work_limit);
    let root = transparent(hir, &mut budget)?;
    if let Some(identity) = inspect_uri_like(root, true, &mut budget)? {
        return Ok(InspectionOutcome::Eligible {
            plan: Plan {
                identity,
                alternative: None,
            },
            planner_work: budget.actual,
        });
    }
    let HirKind::Alternation(branches) = root.kind() else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: budget.actual,
        });
    };
    budget.charge(1)?;
    let [first, second] = branches.as_slice() else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: budget.actual,
        });
    };
    let mut uri = None;
    let mut delimiter = None;
    for branch in [first, second] {
        if uri.is_none() {
            uri = inspect_uri_like(branch, false, &mut budget)?;
            if uri.is_some() {
                continue;
            }
        }
        let inspected = k0_class_delimiter_exists::inspect(branch, budget.actual, budget.limit)
            .map_err(map_delimiter_error)?;
        budget.actual = inspected.planner_work();
        match inspected {
            k0_class_delimiter_exists::InspectionOutcome::Eligible { plan, .. }
                if delimiter.is_none() =>
            {
                delimiter = Some(plan);
            }
            _ => {
                return Ok(InspectionOutcome::Ineligible {
                    planner_work: budget.actual,
                });
            }
        }
    }
    let (Some(mut identity), Some(alternative)) = (uri, delimiter) else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: budget.actual,
        });
    };
    identity.plan_id = COMPOSITE_PLAN_ID;
    identity.operation_id = COMPOSITE_OPERATION_ID;
    identity.alternative = Some(alternative.identity());
    Ok(InspectionOutcome::Eligible {
        plan: Plan {
            identity,
            alternative: Some(alternative),
        },
        planner_work: budget.actual,
    })
}

fn inspect_uri_like(
    hir: &Hir,
    allow_class_plus: bool,
    budget: &mut Budget,
) -> Result<Option<Identity>, InspectionError> {
    let root = transparent(hir, budget)?;
    let HirKind::Concat(parts) = root.kind() else {
        return Ok(None);
    };
    budget.charge(1)?;
    let Some(first) = parts.first() else {
        return Ok(None);
    };
    let scheme = transparent(first, budget)?;
    if allow_class_plus && let HirKind::Repetition(repetition) = scheme.kind() {
        return inspect_class_plus_literal_class_plus(parts, repetition, budget);
    }
    let (start, continuation, literal, right, tail) =
        if let HirKind::Concat(scheme_parts) = scheme.kind() {
            budget.charge(1)?;
            let [start, continuation] = scheme_parts.as_slice() else {
                return Ok(None);
            };
            if !(3..=4).contains(&parts.len()) {
                return Ok(None);
            }
            (start, continuation, &parts[1], &parts[2], parts.get(3))
        } else {
            if !(4..=5).contains(&parts.len()) {
                return Ok(None);
            }
            (scheme, &parts[1], &parts[2], &parts[3], parts.get(4))
        };
    let Some(start) = byte_class(start, budget)? else {
        return Ok(None);
    };
    let Some(continuation) = byte_class_repetition(continuation, 0, None, budget)? else {
        return Ok(None);
    };
    let literal = transparent(literal, budget)?;
    let HirKind::Literal(literal) = literal.kind() else {
        return Ok(None);
    };
    budget.charge(1)?;
    if literal.0.is_empty() || literal.0.len() > MAX_LITERAL_BYTES {
        return Ok(None);
    }
    let Some(right) = byte_class_repetition(right, 1, None, budget)? else {
        return Ok(None);
    };
    let optional_tail = if let Some(tail) = tail {
        let tail = transparent(tail, budget)?;
        let HirKind::Repetition(repetition) = tail.kind() else {
            return Ok(None);
        };
        budget.charge(1)?;
        if repetition.min != 0 || repetition.max != Some(1) {
            return Ok(None);
        }
        true
    } else {
        false
    };
    let start_words = class_words(start, budget)?;
    let continue_words = class_words(continuation, budget)?;
    let right_words = class_words(right, budget)?;
    let leading = literal.0[0];
    if contains(start_words, leading)
        || contains(continue_words, leading)
        || literal.0[1..].contains(&leading)
    {
        return Ok(None);
    }
    let mut literal_bytes = [0_u8; MAX_LITERAL_BYTES];
    literal_bytes[..literal.0.len()].copy_from_slice(literal.0.as_ref());
    Ok(Some(Identity {
        plan_id: PLAN_ID,
        operation_id: OPERATION_ID,
        start_words,
        continue_words,
        literal: literal_bytes,
        literal_len: u8::try_from(literal.0.len())
            .map_err(|_| InspectionError::ArithmeticOverflow)?,
        right_words,
        optional_tail,
        alternative: None,
        unicode: false,
        full_input: true,
    }))
}

fn inspect_class_plus_literal_class_plus(
    parts: &[Hir],
    left_repetition: &regex_syntax::hir::Repetition,
    budget: &mut Budget,
) -> Result<Option<Identity>, InspectionError> {
    budget.charge(1)?;
    if left_repetition.min != 1
        || left_repetition.max.is_some()
        || !left_repetition.greedy
        || parts.len() != 3
    {
        return Ok(None);
    }
    let Some(left) = byte_class(left_repetition.sub.as_ref(), budget)? else {
        return Ok(None);
    };

    let literal = transparent(&parts[1], budget)?;
    let HirKind::Literal(literal) = literal.kind() else {
        return Ok(None);
    };
    budget.charge(1)?;
    if literal.0.is_empty() || literal.0.len() > MAX_LITERAL_BYTES {
        return Ok(None);
    }

    let right = transparent(&parts[2], budget)?;
    let HirKind::Repetition(right_repetition) = right.kind() else {
        return Ok(None);
    };
    budget.charge(1)?;
    if right_repetition.min != 1
        || right_repetition.max.is_some()
        || !right_repetition.greedy
    {
        return Ok(None);
    }
    let Some(right) = byte_class(right_repetition.sub.as_ref(), budget)? else {
        return Ok(None);
    };

    let left_words = class_words(left, budget)?;
    let right_words = class_words(right, budget)?;
    let leading = literal.0[0];
    if contains(left_words, leading) || literal.0[1..].contains(&leading) {
        return Ok(None);
    }
    let mut literal_bytes = [0_u8; MAX_LITERAL_BYTES];
    literal_bytes[..literal.0.len()].copy_from_slice(literal.0.as_ref());
    Ok(Some(Identity {
        plan_id: CLASS_PLUS_PLAN_ID,
        operation_id: CLASS_PLUS_OPERATION_ID,
        start_words: left_words,
        continue_words: left_words,
        literal: literal_bytes,
        literal_len: u8::try_from(literal.0.len())
            .map_err(|_| InspectionError::ArithmeticOverflow)?,
        right_words,
        optional_tail: false,
        alternative: None,
        unicode: false,
        full_input: true,
    }))
}

fn byte_class<'a>(
    hir: &'a Hir,
    budget: &mut Budget,
) -> Result<Option<&'a ClassBytes>, InspectionError> {
    let hir = transparent(hir, budget)?;
    let HirKind::Class(Class::Bytes(class)) = hir.kind() else {
        return Ok(None);
    };
    budget.charge(1)?;
    Ok((!class.ranges().is_empty()).then_some(class))
}

fn byte_class_repetition<'a>(
    hir: &'a Hir,
    minimum: u32,
    maximum: Option<u32>,
    budget: &mut Budget,
) -> Result<Option<&'a ClassBytes>, InspectionError> {
    let hir = transparent(hir, budget)?;
    let HirKind::Repetition(repetition) = hir.kind() else {
        return Ok(None);
    };
    budget.charge(1)?;
    if repetition.min != minimum || repetition.max != maximum {
        return Ok(None);
    }
    byte_class(repetition.sub.as_ref(), budget)
}

fn class_words(class: &ClassBytes, budget: &mut Budget) -> Result<[u64; 4], InspectionError> {
    let mut words = [0_u64; 4];
    for range in class.ranges() {
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

fn transparent<'a>(mut hir: &'a Hir, budget: &mut Budget) -> Result<&'a Hir, InspectionError> {
    loop {
        budget.charge(1)?;
        let HirKind::Capture(capture) = hir.kind() else {
            return Ok(hir);
        };
        hir = capture.sub.as_ref();
    }
}

fn map_delimiter_error(error: k0_class_delimiter_exists::InspectionError) -> InspectionError {
    match error {
        k0_class_delimiter_exists::InspectionError::WorkLimit {
            actual,
            needed,
            limit,
        } => InspectionError::WorkLimit {
            actual,
            needed,
            limit,
        },
        k0_class_delimiter_exists::InspectionError::ArithmeticOverflow => {
            InspectionError::ArithmeticOverflow
        }
    }
}

#[inline]
fn contains(words: [u64; 4], byte: u8) -> bool {
    let index = usize::from(byte);
    words[index / 64] & (1_u64 << (index % 64)) != 0
}

#[cfg(test)]
mod tests {
    use regex_syntax::ParserBuilder;

    use super::{
        CLASS_PLUS_OPERATION_ID, CLASS_PLUS_PLAN_ID, COMPOSITE_OPERATION_ID, COMPOSITE_PLAN_ID,
        InspectionOutcome, PLAN_ID, inspect,
    };

    fn plan(pattern: &str) -> super::Plan {
        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(pattern)
            .unwrap();
        let InspectionOutcome::Eligible { plan, .. } = inspect(&hir, 0, u64::MAX).unwrap() else {
            panic!("expected eligible plan for {pattern}");
        };
        plan
    }

    #[test]
    fn uri_and_uri_or_email_existence_is_exact_on_directed_cases() {
        let uri = plan(r"([a-zA-Z][a-zA-Z0-9]*)://([^ /]+)(/[^ ]*)?");
        assert_eq!(uri.identity().plan_id, PLAN_ID);
        for (haystack, expected) in [
            (&b"http://x"[..], true),
            (b"1http2://x", true),
            (b"123://x", false),
            (b"http://", false),
            (b"http:///x", false),
            (b"http:// x", false),
            (b"x http://host/path y", true),
            (&[0xff, b'h', b':', b'/', b'/', 0xfe], true),
        ] {
            assert_eq!(uri.is_match_full(haystack), expected, "{haystack:?}");
        }
        let capture_free = plan(r"[a-zA-Z][a-zA-Z0-9]*://[^ /]+(?:/[^ ]*)?");
        assert_eq!(capture_free.identity().plan_id, PLAN_ID);
        assert!(capture_free.is_match_full(b"scheme9://host"));

        // The executor is a generic class-guarded literal corridor. A
        // one-byte delimiter remains exact when its leading byte is excluded
        // from both left-hand classes.
        let colon = plan(r"[a-z][a-z0-9]*:[^ /]+");
        assert!(colon.is_match_full(b"scheme9:value"));
        assert!(colon.is_match_full(b"9scheme:value"));
        assert!(!colon.is_match_full(b"9:value"));

        let either = plan(r"([a-zA-Z][a-zA-Z0-9]*)://([^ /]+)(/[^ ]*)?|([^ @]+)@([^ @]+)");
        assert_eq!(either.identity().plan_id, COMPOSITE_PLAN_ID);
        assert_eq!(either.identity().operation_id, COMPOSITE_OPERATION_ID);
        for (haystack, expected) in [
            (&b"http://x"[..], true),
            (b"a@b", true),
            (b"123://x", false),
            (b"a@ b", false),
            (b"plain text", false),
        ] {
            assert_eq!(
                either.is_match_fused_composite_full(haystack),
                expected,
                "{haystack:?}"
            );
        }

        let reversed = plan(
            r"([^ @]+)@([^ @]+)|([a-zA-Z][a-zA-Z0-9]*)://([^ /]+)(/[^ ]*)?",
        );
        assert_eq!(reversed.identity().plan_id, COMPOSITE_PLAN_ID);
        assert_eq!(
            reversed.identity().operation_id,
            COMPOSITE_OPERATION_ID
        );
        for haystack in [&b"http://x"[..], b"a@b", b"plain text"] {
            assert_eq!(
                reversed.is_match_fused_composite_full(haystack),
                either.is_match_fused_composite_full(haystack),
                "reversing the source branches changed the fused predicate for {haystack:?}",
            );
        }
    }

    #[test]
    fn fused_composite_equals_the_two_independent_predicates() {
        let either = plan(r"([a-zA-Z][a-zA-Z0-9]*)://([^ /]+)(/[^ ]*)?|([^ @]+)@([^ @]+)");
        let uri = plan(r"([a-zA-Z][a-zA-Z0-9]*)://([^ /]+)(/[^ ]*)?");
        let email = either.alternative.expect("composite delimiter plan");
        let oracle = regex::bytes::RegexBuilder::new(
            r"([a-zA-Z][a-zA-Z0-9]*)://([^ /]+)(/[^ ]*)?|([^ @]+)@([^ @]+)",
        )
        .unicode(false)
        .build()
        .expect("bytes oracle");

        let alphabet = [b'a', b'1', b':', b'/', b'@', b' ', 0xff];
        let mut corpus = vec![Vec::new()];
        let mut frontier = vec![Vec::new()];
        for _ in 0..7 {
            let mut next = Vec::new();
            for prefix in frontier {
                for byte in alphabet {
                    let mut candidate = prefix.clone();
                    candidate.push(byte);
                    next.push(candidate);
                }
            }
            corpus.extend(next.iter().cloned());
            frontier = next;
        }
        for haystack in &corpus {
            assert_eq!(
                either.is_match_fused_composite_full(haystack),
                uri.is_match_full(haystack) || email.is_match_full(haystack),
                "fused composite differed over {haystack:?}",
            );
            assert_eq!(
                either.is_match_fused_composite_full(haystack),
                oracle.is_match(haystack),
                "fused composite differed from the bytes oracle over {haystack:?}",
            );
        }

        let mut state = 0xd1b5_4a32_d192_ed03_u64;
        let mut haystack = vec![0_u8; 257];
        for length in 0..=haystack.len() {
            for _ in 0..128 {
                for byte in &mut haystack[..length] {
                    state ^= state << 7;
                    state ^= state >> 9;
                    state ^= state << 8;
                    *byte = state.to_le_bytes()[0];
                }
                let haystack = &haystack[..length];
                assert_eq!(
                    either.is_match_fused_composite_full(haystack),
                    uri.is_match_full(haystack) || email.is_match_full(haystack),
                    "fused composite differed over randomized {haystack:?}",
                );
                assert_eq!(
                    either.is_match_fused_composite_full(haystack),
                    oracle.is_match(haystack),
                    "fused composite differed from the bytes oracle over randomized {haystack:?}",
                );
            }
        }

        // memchr2 also permits identical event bytes. Exercise that boundary
        // directly by making the class-guarded literal equal the alternative
        // delimiter while retaining the same construction-proved classes.
        let mut same_event = either;
        same_event.identity.literal = [0; super::MAX_LITERAL_BYTES];
        same_event.identity.literal[0] = b'@';
        same_event.identity.literal_len = 1;
        let mut same_event_uri = uri;
        same_event_uri.identity = same_event.identity;
        same_event_uri.identity.alternative = None;
        for haystack in &corpus {
            assert_eq!(
                same_event.is_match_fused_composite_full(haystack),
                same_event_uri.is_match_full(haystack) || email.is_match_full(haystack),
                "identical fused event bytes differed over {haystack:?}",
            );
        }
    }

    #[test]
    fn fused_composite_checks_both_branches_for_one_shared_event_byte() {
        const URI: &str = r"([a-z][a-z0-9]*)@([^ ]+)";
        const EITHER: &str = r"([a-z][a-z0-9]*)@([^ ]+)|([^ @]+)@([^ @]+)";
        let either = plan(EITHER);
        let uri = plan(URI);
        let delimiter = either.alternative.expect("composite delimiter plan");
        assert_eq!(either.identity().literal[0], delimiter.identity().delimiter);
        let oracle = regex::bytes::RegexBuilder::new(EITHER)
            .unicode(false)
            .build()
            .expect("bytes oracle");

        for haystack in [
            &b""[..],
            b"plain",
            b"@",
            b"a@",
            b"@b",
            b"a@b",
            b"1@b",
            b"1@ ",
            b"a@ ",
            b"tail@",
            b"x@@y",
            b"\xff@\xfe",
            b"a@\xff",
        ] {
            let independent = uri.is_match_full(haystack) || delimiter.is_match_full(haystack);
            assert_eq!(
                either.is_match_fused_composite_full(haystack),
                independent,
                "{haystack:?}"
            );
            assert_eq!(
                either.is_match_fused_composite_full(haystack),
                oracle.is_match(haystack)
            );
        }
    }

    #[test]
    fn class_plus_ordinary_projection_matches_the_bytes_oracle() {
        const PATTERN: &str = r"[ab]+XY[01]+";
        let projected = plan(PATTERN);
        assert_eq!(projected.identity().plan_id, CLASS_PLUS_PLAN_ID);
        assert_eq!(
            projected.identity().operation_id,
            CLASS_PLUS_OPERATION_ID
        );
        assert_eq!(
            projected.identity().start_words,
            projected.identity().continue_words
        );
        let oracle = regex::bytes::RegexBuilder::new(PATTERN)
            .unicode(false)
            .build()
            .expect("bytes oracle");

        let alphabet = [b'a', b'b', b'X', b'Y', b'0', b'!'];
        let mut corpus = vec![Vec::new()];
        let mut frontier = vec![Vec::new()];
        for _ in 0..7 {
            let mut next = Vec::new();
            for prefix in frontier {
                for byte in alphabet {
                    let mut candidate = prefix.clone();
                    candidate.push(byte);
                    next.push(candidate);
                }
            }
            corpus.extend(next.iter().cloned());
            frontier = next;
        }
        for haystack in &corpus {
            let expected = oracle.find(haystack).map(|matched| {
                (matched.start(), matched.end())
            });
            assert_eq!(
                projected.try_ordinary_find_full(haystack),
                Some(expected),
                "selected span differed over {haystack:?}",
            );
            assert_eq!(
                projected.try_ordinary_is_match_full(haystack),
                Some(expected.is_some()),
                "existence differed over {haystack:?}",
            );
        }

        let target = plan(r"[a-z]+MID[0-9]+");
        for (haystack, expected) in [
            (&b"!alphabeticMID12345!"[..], Some((1, 19))),
            (b"abMID!cdMID12", Some((6, 13))),
            (b"!MID1", None),
            (b"abcMID!", None),
            (b"abcMID123!defMID45", Some((0, 9))),
        ] {
            assert_eq!(
                target.try_ordinary_find_full(haystack),
                Some(expected),
                "directed selected span differed over {haystack:?}",
            );
            assert_eq!(
                target.try_ordinary_is_match_full(haystack),
                Some(expected.is_some()),
                "directed existence differed over {haystack:?}",
            );
        }
    }

    #[test]
    fn class_plus_ordinary_projection_abandons_dense_candidates_exactly() {
        let projected = plan(r"[ab]+X[01]+");
        let mut eight_candidates = Vec::new();
        for _ in 0..7 {
            eight_candidates.extend_from_slice(b"!X!");
        }
        eight_candidates.extend_from_slice(b"aX01");
        let expected_start = eight_candidates.len() - 4;
        assert_eq!(
            projected.try_ordinary_find_full(&eight_candidates),
            Some(Some((expected_start, eight_candidates.len()))),
        );
        assert_eq!(
            projected.try_ordinary_is_match_full(&eight_candidates),
            Some(true),
        );

        let mut nine_candidates = Vec::new();
        for _ in 0..8 {
            nine_candidates.extend_from_slice(b"!X!");
        }
        nine_candidates.extend_from_slice(b"aX01");
        assert_eq!(projected.try_ordinary_find_full(&nine_candidates), None);
        assert_eq!(projected.try_ordinary_is_match_full(&nine_candidates), None);

        let multi_byte = plan(r"[ab]+XY[01]+");
        let mut eight_leading_bytes = Vec::new();
        for _ in 0..7 {
            eight_leading_bytes.extend_from_slice(b"!X!");
        }
        eight_leading_bytes.extend_from_slice(b"aXY0");
        let expected_start = eight_leading_bytes.len() - 4;
        assert_eq!(
            multi_byte.try_ordinary_find_full(&eight_leading_bytes),
            Some(Some((expected_start, eight_leading_bytes.len())))
        );
        assert_eq!(
            multi_byte.try_ordinary_is_match_full(&eight_leading_bytes),
            Some(true)
        );

        let mut false_leading_bytes = Vec::new();
        for _ in 0..8 {
            false_leading_bytes.extend_from_slice(b"!X!");
        }
        false_leading_bytes.extend_from_slice(b"aXY0");
        assert_eq!(multi_byte.try_ordinary_find_full(&false_leading_bytes), None);
        assert_eq!(
            multi_byte.try_ordinary_is_match_full(&false_leading_bytes),
            None
        );
    }

    #[test]
    fn class_plus_planner_work_is_cumulative_and_exactly_bounded() {
        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(r"[a-z]+MID[0-9]+")
            .unwrap();
        let InspectionOutcome::Eligible { planner_work, .. } =
            inspect(&hir, 0, u64::MAX).unwrap()
        else {
            panic!("class-plus shape should be eligible");
        };
        assert!(matches!(
            inspect(&hir, 0, planner_work - 1),
            Err(super::InspectionError::WorkLimit { needed, limit, .. })
                if needed == planner_work && limit == planner_work - 1
        ));

        let initial_work = 17;
        let InspectionOutcome::Eligible {
            planner_work: cumulative,
            ..
        } = inspect(&hir, initial_work, u64::MAX).unwrap()
        else {
            panic!("class-plus shape should remain eligible with prior work");
        };
        assert_eq!(cumulative, planner_work + initial_work);
    }

    #[test]
    fn nearby_languages_are_rejected() {
        for pattern in [
            r"[a-z][a-z0-9]+://[^ /]+",
            r"[a-z][a-z0-9]*://[^ /]*",
            r"[a-z][a-z0-9]*a[^ /]+",
            r"[a-z][a-z0-9]*://[^ /]+x",
            r"[ab]*X[01]+",
            r"[ab]{2,}X[01]+",
            r"[ab]{1,3}X[01]+",
            r"[ab]+?X[01]+",
            r"[ab]+X[01]*",
            r"[ab]+X[01]{2,}",
            r"[ab]+X[01]+?",
            r"[ab]+X[01]+Y?",
            r"[aX]+X[01]+",
            r"[cd]+aba[01]+",
            r"[ab]+X[01]+|[^ @]+@[^ @]+",
        ] {
            let hir = ParserBuilder::new()
                .unicode(false)
                .utf8(false)
                .build()
                .parse(pattern)
                .unwrap();
            assert!(matches!(
                inspect(&hir, 0, u64::MAX).unwrap(),
                InspectionOutcome::Ineligible { .. }
            ));
        }
    }
}
