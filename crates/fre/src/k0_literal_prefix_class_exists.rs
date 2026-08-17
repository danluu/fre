//! Exact value-only existence for `(LIT4|...|LIT4) BYTE_CLASS{N}`.
//!
//! Construction accepts one to four distinct four-byte literals that share
//! their first byte, followed by one nonempty exact byte-class repetition.
//! A complete match is found by seeking that shared byte, authenticating the
//! selected literal and then checking the fixed-width class tail. Captures are
//! transparent because this plan serves only value-only existence.

use memchr::memchr_iter;
use regex_syntax::hir::{Class, ClassBytes, Hir, HirKind};

pub(crate) const PLAN_ID: &str = "k0.literal4-alternation-fixed-byte-class.v1";
pub(crate) const OPERATION_ID: &str = "k0.exists.literal4-alternation-fixed-byte-class.v1";

const MAX_LITERALS: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Identity {
    pub(crate) plan_id: &'static str,
    pub(crate) operation_id: &'static str,
    pub(crate) literals: [u32; MAX_LITERALS],
    pub(crate) literal_count: u8,
    pub(crate) shared_first: u8,
    pub(crate) class_words: [u64; 4],
    pub(crate) class_bytes: u8,
    pub(crate) unicode: bool,
    pub(crate) case_insensitive: bool,
    pub(crate) full_input: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Plan {
    identity: Identity,
}

impl Plan {
    pub(crate) const fn identity(self) -> Identity {
        self.identity
    }

    pub(crate) fn prepared_work_per_input_byte(self) -> u64 {
        // One seek visit, up to four literal comparisons, one candidate
        // branch and every fixed-tail class probe are charged for every byte
        // even though candidates are normally sparse. This intentionally
        // overstates the direct executor, including maximally overlapping
        // candidates.
        6 + u64::from(self.identity.class_bytes)
    }

    #[inline]
    pub(crate) fn is_match_full(self, haystack: &[u8]) -> bool {
        let match_bytes = 4 + usize::from(self.identity.class_bytes);
        if haystack.len() < match_bytes {
            return false;
        }
        let last_start = haystack.len() - match_bytes;
        for start in memchr_iter(self.identity.shared_first, &haystack[..=last_start]) {
            let literal = u32::from_ne_bytes(
                haystack[start..start + 4]
                    .try_into()
                    .expect("the admitted candidate retains four bytes"),
            );
            if !self.identity.literals[..usize::from(self.identity.literal_count)]
                .contains(&literal)
            {
                continue;
            }
            let tail = &haystack[start + 4..start + match_bytes];
            if tail
                .iter()
                .all(|&byte| contains(self.identity.class_words, byte))
            {
                return true;
            }
        }
        false
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
    initial_work: u64,
    work_limit: u64,
) -> Result<InspectionOutcome, InspectionError> {
    let mut budget = Budget::new(initial_work, work_limit);
    budget.charge(1)?;
    if unicode || case_insensitive {
        return ineligible(budget.actual);
    }
    let root = transparent(hir, &mut budget)?;
    let HirKind::Concat(parts) = root.kind() else {
        return ineligible(budget.actual);
    };
    budget.charge(1)?;
    let [prefix, tail] = parts.as_slice() else {
        return ineligible(budget.actual);
    };

    let prefix = transparent(prefix, &mut budget)?;
    let mut literals = [0_u32; MAX_LITERALS];
    let literal_count = match prefix.kind() {
        HirKind::Literal(literal) => {
            let Some(packed) = literal4(literal.0.as_ref(), &mut budget)? else {
                return ineligible(budget.actual);
            };
            literals[0] = packed;
            1
        }
        HirKind::Alternation(branches)
            if !branches.is_empty() && branches.len() <= MAX_LITERALS =>
        {
            budget.charge(1)?;
            for (index, branch) in branches.iter().enumerate() {
                let branch = transparent(branch, &mut budget)?;
                let HirKind::Literal(literal) = branch.kind() else {
                    return ineligible(budget.actual);
                };
                let Some(packed) = literal4(literal.0.as_ref(), &mut budget)? else {
                    return ineligible(budget.actual);
                };
                if literals[..index].contains(&packed) {
                    return ineligible(budget.actual);
                }
                literals[index] = packed;
            }
            branches.len()
        }
        _ => return ineligible(budget.actual),
    };
    let shared_first = literals[0].to_ne_bytes()[0];
    if literals[..literal_count]
        .iter()
        .any(|literal| literal.to_ne_bytes()[0] != shared_first)
    {
        return ineligible(budget.actual);
    }

    let tail = transparent(tail, &mut budget)?;
    let HirKind::Repetition(repetition) = tail.kind() else {
        return ineligible(budget.actual);
    };
    budget.charge(1)?;
    if repetition.min == 0 || repetition.max != Some(repetition.min) || repetition.min > 64 {
        return ineligible(budget.actual);
    }
    let repeated = transparent(repetition.sub.as_ref(), &mut budget)?;
    let HirKind::Class(Class::Bytes(class)) = repeated.kind() else {
        return ineligible(budget.actual);
    };
    budget.charge(1)?;
    if class.ranges().is_empty() {
        return ineligible(budget.actual);
    }
    let class_words = class_words(class, &mut budget)?;
    Ok(InspectionOutcome::Eligible {
        plan: Plan {
            identity: Identity {
                plan_id: PLAN_ID,
                operation_id: OPERATION_ID,
                literals,
                literal_count: u8::try_from(literal_count)
                    .expect("at most four literal branches fit u8"),
                shared_first,
                class_words,
                class_bytes: u8::try_from(repetition.min)
                    .expect("the admitted exact repetition is at most 64"),
                unicode,
                case_insensitive,
                full_input: true,
            },
        },
        planner_work: budget.actual,
    })
}

fn ineligible(work: u64) -> Result<InspectionOutcome, InspectionError> {
    Ok(InspectionOutcome::Ineligible { planner_work: work })
}

fn literal4(bytes: &[u8], budget: &mut Budget) -> Result<Option<u32>, InspectionError> {
    budget.charge(1)?;
    let Ok(bytes) = <[u8; 4]>::try_from(bytes) else {
        return Ok(None);
    };
    budget.charge(4)?;
    Ok(Some(u32::from_ne_bytes(bytes)))
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

#[inline]
fn contains(words: [u64; 4], byte: u8) -> bool {
    let index = usize::from(byte);
    words[index / 64] & (1_u64 << (index % 64)) != 0
}

#[cfg(test)]
mod tests {
    use regex_syntax::ParserBuilder;

    use super::{InspectionOutcome, inspect};

    fn plan(pattern: &str) -> super::Plan {
        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(pattern)
            .unwrap();
        let InspectionOutcome::Eligible { plan, .. } =
            inspect(&hir, false, false, 0, u64::MAX).unwrap()
        else {
            panic!("expected eligible plan for {pattern}");
        };
        plan
    }

    #[test]
    fn literal_alternation_and_fixed_class_are_exact() {
        let plan = plan(r"((?:ASIA|AKIA|AROA|AIDA)([A-Z0-7]{16}))");
        for (haystack, expected) in [
            (&b"plain text"[..], false),
            (b"AKIA01234567ABCDEFGH", true),
            (b"prefix ASIAABCDEFGHIJKLMNOP suffix", true),
            (b"AROA0000000000000000", true),
            (b"AKIA0000000000000008", false),
            (b"BKIA01234567ABCDEFGH", false),
            (&b"\xffAIDA01234567ABCDEFGH\xfe"[..], true),
        ] {
            assert_eq!(plan.is_match_full(haystack), expected, "{haystack:?}");
        }
    }

    #[test]
    fn small_structural_domain_matches_independent_oracle() {
        let plan = plan(r"((?:ABCD|AXYZ)([ab]{2}))");
        fn reference(haystack: &[u8]) -> bool {
            haystack.windows(6).any(|window| {
                (&window[..4] == b"ABCD" || &window[..4] == b"AXYZ")
                    && window[4..].iter().all(|byte| matches!(byte, b'a' | b'b'))
            })
        }
        fn visit(plan: super::Plan, line: &mut Vec<u8>) {
            assert_eq!(
                plan.is_match_full(line),
                reference(line),
                "small-domain result differed for {line:?}",
            );
            if line.len() == 6 {
                return;
            }
            for byte in [b'A', b'B', b'C', b'D', b'X', b'Y', b'Z', b'a', b'b', 0xff] {
                line.push(byte);
                visit(plan, line);
                line.pop();
            }
        }
        visit(plan, &mut Vec::new());
    }

    #[test]
    fn nearby_languages_are_rejected() {
        for pattern in [
            r"(?:ASIA|BKIA)[A-Z0-7]{16}",
            r"(?:ASIA|AKIA)[A-Z0-7]+",
            r"(?:ASIA|AKIA)[A-Z0-7]{0}",
            r"(?:ASIA|AKIA)[A-Z0-7]{65}",
            r"(?:ASIA|AKIA)[A-Z0-7]{16}x",
            r"(?:ASI|AKI)[A-Z0-7]{16}",
        ] {
            let hir = ParserBuilder::new()
                .unicode(false)
                .utf8(false)
                .build()
                .parse(pattern)
                .unwrap();
            assert!(matches!(
                inspect(&hir, false, false, 0, u64::MAX).unwrap(),
                InspectionOutcome::Ineligible { .. }
            ));
        }

        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(r"(?:ASIA|AKIA)[A-Z0-7]{16}")
            .unwrap();
        for (unicode, case_insensitive) in [(true, false), (false, true)] {
            assert!(matches!(
                inspect(&hir, unicode, case_insensitive, 0, u64::MAX).unwrap(),
                InspectionOutcome::Ineligible { .. }
            ));
        }
    }
}
