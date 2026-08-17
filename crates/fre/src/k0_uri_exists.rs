//! Exact value-only existence for a class-guarded literal corridor.
//!
//! The admitted language is
//! `START_CLASS CONTINUE_CLASS* LITERAL RIGHT_CLASS+ OPTIONAL?`, where the
//! optional tail is one zero-or-one repetition. The literal's leading byte is
//! outside both left classes, so occurrences partition the backward class
//! scans. A root two-branch alternation may pair this language with the
//! existing exact `BYTE_CLASS+ BYTE BYTE_CLASS+` predicate.

use memchr::memmem;
use regex_syntax::hir::{Class, ClassBytes, Hir, HirKind};

use crate::k0_class_delimiter_exists;

pub(crate) const PLAN_ID: &str = "k0.class-star-literal-class-plus.v1";
pub(crate) const COMPOSITE_PLAN_ID: &str = "k0.class-star-literal-class-plus-or-class-delimiter.v1";
pub(crate) const OPERATION_ID: &str = "k0.exists.class-star-literal-class-plus.v1";
pub(crate) const COMPOSITE_OPERATION_ID: &str =
    "k0.exists.class-star-literal-class-plus-or-class-delimiter.v1";

const MAX_LITERAL_BYTES: usize = 8;
const DIRECT_WORK_PER_INPUT_BYTE: u64 = 6;
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

    #[inline]
    pub(crate) fn is_match_full(self, haystack: &[u8]) -> bool {
        if self.uri_like_is_match(haystack) {
            return true;
        }
        self.alternative
            .is_some_and(|plan| plan.is_match_full(haystack))
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
    if let Some(identity) = inspect_uri_like(root, &mut budget)? {
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
            uri = inspect_uri_like(branch, &mut budget)?;
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

fn inspect_uri_like(hir: &Hir, budget: &mut Budget) -> Result<Option<Identity>, InspectionError> {
    let root = transparent(hir, budget)?;
    let HirKind::Concat(parts) = root.kind() else {
        return Ok(None);
    };
    budget.charge(1)?;
    let Some(first) = parts.first() else {
        return Ok(None);
    };
    let scheme = transparent(first, budget)?;
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

    use super::{COMPOSITE_PLAN_ID, InspectionOutcome, PLAN_ID, inspect};

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

        let either = plan(r"([a-zA-Z][a-zA-Z0-9]*)://([^ /]+)(/[^ ]*)?|([^ @]+)@([^ @]+)");
        assert_eq!(either.identity().plan_id, COMPOSITE_PLAN_ID);
        for (haystack, expected) in [
            (&b"http://x"[..], true),
            (b"a@b", true),
            (b"123://x", false),
            (b"a@ b", false),
            (b"plain text", false),
        ] {
            assert_eq!(either.is_match_full(haystack), expected, "{haystack:?}");
        }
    }

    #[test]
    fn nearby_languages_are_rejected() {
        for pattern in [
            r"[a-z][a-z0-9]+://[^ /]+",
            r"[a-z][a-z0-9]*:[^ /]+",
            r"[a-z][a-z0-9]*://[^ /]*",
            r"[a-z][a-z0-9]*a[^ /]+",
            r"[a-z][a-z0-9]*://[^ /]+x",
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
