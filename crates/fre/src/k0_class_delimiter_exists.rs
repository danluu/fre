//! Exact value-only existence for `BYTE_CLASS+ BYTE BYTE_CLASS+`.
//!
//! Construction peels only transparent capture nodes and accepts one
//! canonical byte-class repetition on each side of one literal byte. A match
//! exists exactly when an occurrence of that byte has an immediately adjacent
//! left-class byte and an immediately adjacent right-class byte. Greedy extent
//! and capture history cannot change that existence result.

use memchr::memchr_iter;
use regex_syntax::hir::{Class, ClassBytes, Hir, HirKind};

pub(crate) const PLAN_ID: &str = "k0.byte-class-plus-byte-byte-class-plus.v1";
pub(crate) const OPERATION_ID: &str = "k0.exists.byte-class-plus-byte-byte-class-plus.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Identity {
    pub(crate) plan_id: &'static str,
    pub(crate) operation_id: &'static str,
    pub(crate) left_words: [u64; 4],
    pub(crate) delimiter: u8,
    pub(crate) right_words: [u64; 4],
    pub(crate) unicode: bool,
    pub(crate) positive_repetitions: bool,
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

    #[inline]
    pub(crate) fn is_match_full(self, haystack: &[u8]) -> bool {
        if haystack.len() < 3 {
            return false;
        }
        for relative in memchr_iter(self.identity.delimiter, &haystack[1..haystack.len() - 1]) {
            let delimiter = relative + 1;
            if contains(self.identity.left_words, haystack[delimiter - 1])
                && contains(self.identity.right_words, haystack[delimiter + 1])
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
    initial_work: u64,
    work_limit: u64,
) -> Result<InspectionOutcome, InspectionError> {
    let mut budget = Budget::new(initial_work, work_limit);
    let root = transparent(hir, &mut budget)?;
    let HirKind::Concat(parts) = root.kind() else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: budget.actual,
        });
    };
    budget.charge(1)?;
    let [left, delimiter, right] = parts.as_slice() else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: budget.actual,
        });
    };
    let Some(left) = positive_byte_class(left, &mut budget)? else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: budget.actual,
        });
    };
    let delimiter = transparent(delimiter, &mut budget)?;
    let HirKind::Literal(delimiter) = delimiter.kind() else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: budget.actual,
        });
    };
    budget.charge(1)?;
    let [delimiter] = delimiter.0.as_ref() else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: budget.actual,
        });
    };
    let Some(right) = positive_byte_class(right, &mut budget)? else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: budget.actual,
        });
    };
    let left_words = class_words(left, &mut budget)?;
    let right_words = class_words(right, &mut budget)?;
    Ok(InspectionOutcome::Eligible {
        plan: Plan {
            identity: Identity {
                plan_id: PLAN_ID,
                operation_id: OPERATION_ID,
                left_words,
                delimiter: *delimiter,
                right_words,
                unicode: false,
                positive_repetitions: true,
                full_input: true,
            },
        },
        planner_work: budget.actual,
    })
}

fn positive_byte_class<'a>(
    hir: &'a Hir,
    budget: &mut Budget,
) -> Result<Option<&'a ClassBytes>, InspectionError> {
    let hir = transparent(hir, budget)?;
    let HirKind::Repetition(repetition) = hir.kind() else {
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
    budget.charge(1)?;
    Ok((!class.ranges().is_empty()).then_some(class))
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
        let InspectionOutcome::Eligible { plan, .. } = inspect(&hir, 0, u64::MAX).unwrap() else {
            panic!("expected eligible plan for {pattern}");
        };
        plan
    }

    #[test]
    fn transparent_captures_and_arbitrary_byte_classes_are_exact() {
        let plan = plan(r"([^ @]+)@([^ @]+)");
        for (haystack, expected) in [
            (&b"a@b"[..], true),
            (b"xx a@b yy", true),
            (b"@b", false),
            (b"a@", false),
            (b"a@ b", false),
            (b"a @b", false),
            (b"a@@b", false),
            (&[0xff, b'@', 0xfe], true),
        ] {
            assert_eq!(plan.is_match_full(haystack), expected, "{haystack:?}");
        }
    }

    #[test]
    fn other_languages_are_rejected() {
        for pattern in [
            r"[^ @]*@[^ @]+",
            r"[^ @]+@@[^ @]+",
            r"[^ @]+@[^ @]+x",
            r"(?-u:\w+)@(?-u:\w+)?",
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
