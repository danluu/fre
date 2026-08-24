//! Exact ordinary search for an LF-anchored literal prefix and open line tail.
//!
//! Construction admits byte-mode `StartLF LITERAL CLASS* EndLF` when the
//! class is exactly every byte except LF, optionally also except CR. A match
//! can therefore begin only at a line start. Seeking the literal first and
//! authenticating that boundary avoids constructing generic K0 scratch for
//! the common whole-line prefix predicate.

use memchr::{memchr, memchr2, memmem};
use regex_syntax::hir::{Class, ClassBytes, Hir, HirKind, Look};

const MAX_PREFIX_BYTES: usize = 32;
pub(crate) const MIN_INPUT_BYTES: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Plan {
    prefix: [u8; MAX_PREFIX_BYTES],
    prefix_len: u8,
    reject_cr: bool,
}

impl Plan {
    pub(crate) const fn storage_bytes() -> usize {
        core::mem::size_of::<Self>()
    }

    #[inline]
    pub(crate) fn is_match_full(&self, haystack: &[u8]) -> bool {
        self.find_full(haystack).is_some()
    }

    #[inline]
    pub(crate) fn find_full(&self, haystack: &[u8]) -> Option<(usize, usize)> {
        let prefix = &self.prefix[..usize::from(self.prefix_len)];
        let mut search_start = 0_usize;
        loop {
            let relative = memmem::find(&haystack[search_start..], prefix)?;
            let start = search_start.checked_add(relative)?;
            let tail_start = start.checked_add(prefix.len())?;
            if start != 0 && haystack[start - 1] != b'\n' {
                search_start = start.checked_add(1)?;
                continue;
            }
            let tail = &haystack[tail_start..];
            if !self.reject_cr {
                let end = memchr(b'\n', tail)
                    .and_then(|relative| tail_start.checked_add(relative))
                    .unwrap_or(haystack.len());
                return Some((start, end));
            }
            match memchr2(b'\r', b'\n', tail) {
                None => return Some((start, haystack.len())),
                Some(relative) => {
                    let delimiter = tail_start.checked_add(relative)?;
                    if haystack[delimiter] == b'\n' {
                        return Some((start, delimiter));
                    }
                    let after_cr = delimiter.checked_add(1)?;
                    let next_lf = memchr(b'\n', &haystack[after_cr..])?;
                    search_start = after_cr.checked_add(next_lf)?.checked_add(1)?;
                }
            }
        }
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
    let [start, prefix, repeated, end] = parts.as_slice() else {
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

    let prefix = transparent(prefix, &mut budget)?;
    let HirKind::Literal(literal) = prefix.kind() else {
        return ineligible(budget.actual);
    };
    budget.charge(1)?;
    if literal.0.is_empty() || literal.0.len() > MAX_PREFIX_BYTES || literal.0.contains(&b'\n') {
        return ineligible(budget.actual);
    }
    budget
        .charge(u64::try_from(literal.0.len()).map_err(|_| InspectionError::ArithmeticOverflow)?)?;

    let repeated = transparent(repeated, &mut budget)?;
    let HirKind::Repetition(repetition) = repeated.kind() else {
        return ineligible(budget.actual);
    };
    budget.charge(1)?;
    if repetition.min != 0 || repetition.max.is_some() || !repetition.greedy {
        return ineligible(budget.actual);
    }
    let repeated = transparent(repetition.sub.as_ref(), &mut budget)?;
    let HirKind::Class(Class::Bytes(class)) = repeated.kind() else {
        return ineligible(budget.actual);
    };
    budget.charge(
        u64::try_from(class.ranges().len()).map_err(|_| InspectionError::ArithmeticOverflow)?,
    )?;
    let Some(reject_cr) = open_line_class(class) else {
        return ineligible(budget.actual);
    };

    let mut retained = [0_u8; MAX_PREFIX_BYTES];
    retained[..literal.0.len()].copy_from_slice(&literal.0);
    Ok(InspectionOutcome::Eligible {
        plan: Plan {
            prefix: retained,
            prefix_len: u8::try_from(literal.0.len())
                .expect("the admitted prefix is at most 32 bytes"),
            reject_cr,
        },
        planner_work: budget.actual,
    })
}

fn open_line_class(class: &ClassBytes) -> Option<bool> {
    let ranges = class.ranges();
    if matches!(
        ranges,
        [first, second]
            if first.start() == u8::MIN
                && first.end() == b'\n' - 1
                && second.start() == b'\n' + 1
                && second.end() == u8::MAX
    ) {
        return Some(false);
    }
    if matches!(
        ranges,
        [first, second, third]
            if first.start() == u8::MIN
                && first.end() == b'\n' - 1
                && second.start() == b'\n' + 1
                && second.end() == b'\r' - 1
                && third.start() == b'\r' + 1
                && third.end() == u8::MAX
    ) {
        return Some(true);
    }
    None
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

    use super::{InspectionError, InspectionOutcome, inspect};

    fn plan(pattern: &str) -> super::Plan {
        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(pattern)
            .unwrap();
        let InspectionOutcome::Eligible { plan, .. } =
            inspect(&hir, false, false, b'\n', 0, u64::MAX).unwrap()
        else {
            panic!("expected eligible plan for {pattern:?}");
        };
        plan
    }

    #[test]
    fn complete_spans_cover_lf_and_cr_rejection() {
        let plan = plan(r"(?m)^Subject:[^\r\n]*$");
        for (haystack, expected) in [
            (&b""[..], None),
            (b"Subject:", Some((0, 8))),
            (b"Subject: value\nrest", Some((0, 14))),
            (b"x Subject: value\n", None),
            (b"bad\nSubject: value\n", Some((4, 18))),
            (b"Subject: bad\r\nSubject: good\n", Some((14, 27))),
            (b"Subject: bad\rwithout LF", None),
            (b"\xff\nSubject:\xff", Some((2, 11))),
        ] {
            assert_eq!(plan.find_full(haystack), expected, "{haystack:?}");
            assert_eq!(
                plan.is_match_full(haystack),
                expected.is_some(),
                "{haystack:?}"
            );
        }
    }

    #[test]
    fn exhaustive_small_domain_matches_independent_regex() {
        for pattern in [r"(?m)^ab[^\r\n]*$", r"(?m)^ab(?-u:.)*$"] {
            let plan = plan(pattern);
            let upstream = RegexBuilder::new(pattern).unicode(false).build().unwrap();
            fn visit(plan: super::Plan, upstream: &regex::bytes::Regex, haystack: &mut Vec<u8>) {
                let expected = upstream
                    .find(haystack)
                    .map(|matched| (matched.start(), matched.end()));
                assert_eq!(plan.find_full(haystack), expected, "{haystack:?}");
                assert_eq!(
                    plan.is_match_full(haystack),
                    expected.is_some(),
                    "{haystack:?}"
                );
                if haystack.len() == 6 {
                    return;
                }
                for byte in [b'a', b'b', b'x', b'\r', b'\n', 0xff] {
                    haystack.push(byte);
                    visit(plan, upstream, haystack);
                    haystack.pop();
                }
            }
            visit(plan, &upstream, &mut Vec::new());
        }
    }

    #[test]
    fn nearby_languages_and_work_overrun_are_rejected() {
        for pattern in [
            r"ab[^\r\n]*",
            r"(?m)^ab[^\r\n]+$",
            r"(?m)^ab[^\r\n]{0,8}$",
            r"(?m)^ab[^\r\nx]*$",
            r"(?m)^ab[^\r\n]*?$",
            r"(?m)^[^\r\n]*$",
            r"(?m)^abcdefghijklmnopqrstuvwxyzabcdefg[^\r\n]*$",
        ] {
            let hir = ParserBuilder::new()
                .unicode(false)
                .utf8(false)
                .build()
                .parse(pattern)
                .unwrap();
            assert!(
                matches!(
                    inspect(&hir, false, false, b'\n', 0, u64::MAX).unwrap(),
                    InspectionOutcome::Ineligible { .. }
                ),
                "{pattern:?}"
            );
        }

        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(r"(?m)^ab[^\r\n]*$")
            .unwrap();
        assert!(matches!(
            inspect(&hir, false, false, b'\n', 0, 1),
            Err(InspectionError::WorkLimit { .. })
        ));
        assert!(matches!(
            inspect(&hir, true, false, b'\n', 0, u64::MAX).unwrap(),
            InspectionOutcome::Ineligible { .. }
        ));
        assert!(matches!(
            inspect(&hir, false, false, b'\r', 0, u64::MAX).unwrap(),
            InspectionOutcome::Ineligible { .. }
        ));
    }
}
