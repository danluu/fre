//! Exact value-only existence for three bounded byte-class fields.
//!
//! Construction admits `FIELD DELIMITER FIELD DELIMITER FIELD`, where each
//! field is a finite, non-empty language made only from the same contiguous
//! byte range, concatenation, capture wrappers and finite greedy repetition.
//! The same one-byte delimiter separates both fields and is outside that
//! range. An occurrence therefore uses two consecutive delimiter bytes. The
//! outer fields may start or end at any allowed width, so their smallest
//! admitted widths are sufficient for existence; the bounded middle width is
//! checked exactly.

use memchr::memchr_iter;
use regex_syntax::hir::{Class, ClassBytes, Hir, HirKind};

const FIELD_COUNT: usize = 3;
const MAX_FIELD_BYTES: usize = 15;
const DIRECT_WORK_PER_INPUT_BYTE: u64 = 48;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Identity {
    class_start: u8,
    class_end: u8,
    delimiter: u8,
    left_minimum: u8,
    right_minimum: u8,
    middle_length_mask: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Plan {
    identity: Identity,
}

impl Plan {
    pub(crate) const fn identity(self) -> Identity {
        self.identity
    }

    pub(crate) const fn prepared_work_per_input_byte(self) -> u64 {
        DIRECT_WORK_PER_INPUT_BYTE
    }

    #[inline]
    pub(crate) fn is_match_full(self, haystack: &[u8]) -> bool {
        let identity = self.identity;
        let left_min = usize::from(identity.left_minimum);
        let middle_min = minimum_length(identity.middle_length_mask);
        let right_min = usize::from(identity.right_minimum);
        let minimum = left_min
            .saturating_add(middle_min)
            .saturating_add(right_min)
            .saturating_add(2);
        if haystack.len() < minimum {
            return false;
        }

        let mut delimiters = memchr_iter(identity.delimiter, haystack);
        let Some(mut first) = delimiters.next() else {
            return false;
        };
        for second in delimiters {
            let middle_len = second - first - 1;
            if first >= left_min
                && second
                    .checked_add(1)
                    .and_then(|start| start.checked_add(right_min))
                    .is_some_and(|end| end <= haystack.len())
                && length_is_allowed(identity.middle_length_mask, middle_len)
                && all_in_range(
                    identity.class_start,
                    identity.class_end,
                    &haystack[first - left_min..first],
                )
                && all_in_range(
                    identity.class_start,
                    identity.class_end,
                    &haystack[first + 1..second],
                )
                && all_in_range(
                    identity.class_start,
                    identity.class_end,
                    &haystack[second + 1..second + 1 + right_min],
                )
            {
                return true;
            }
            first = second;
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

#[derive(Clone, Copy)]
struct Field {
    class_start: u8,
    class_end: u8,
    length_mask: u16,
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
    let [first, left_delimiter, middle, right_delimiter, last] = parts.as_slice() else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: budget.actual,
        });
    };
    let Some(left_delimiter) = delimiter(left_delimiter, &mut budget)? else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: budget.actual,
        });
    };
    let Some(right_delimiter) = delimiter(right_delimiter, &mut budget)? else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: budget.actual,
        });
    };
    if left_delimiter != right_delimiter {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: budget.actual,
        });
    }

    let mut fields = [None; FIELD_COUNT];
    for (slot, hir) in fields.iter_mut().zip([first, middle, last]) {
        *slot = field(hir, &mut budget)?;
        if slot.is_none() {
            return Ok(InspectionOutcome::Ineligible {
                planner_work: budget.actual,
            });
        }
    }
    let [Some(first), Some(middle), Some(last)] = fields else {
        unreachable!("all three bounded fields were checked above");
    };
    let fields = [first, middle, last];
    if fields
        .iter()
        .any(|field| in_range(field.class_start, field.class_end, left_delimiter))
        || fields.windows(2).any(|fields| {
            fields[0].class_start != fields[1].class_start
                || fields[0].class_end != fields[1].class_end
        })
    {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: budget.actual,
        });
    }
    Ok(InspectionOutcome::Eligible {
        plan: Plan {
            identity: Identity {
                class_start: first.class_start,
                class_end: first.class_end,
                delimiter: left_delimiter,
                left_minimum: u8::try_from(minimum_length(first.length_mask))
                    .map_err(|_| InspectionError::ArithmeticOverflow)?,
                right_minimum: u8::try_from(minimum_length(last.length_mask))
                    .map_err(|_| InspectionError::ArithmeticOverflow)?,
                middle_length_mask: middle.length_mask,
            },
        },
        planner_work: budget.actual,
    })
}

fn delimiter(hir: &Hir, budget: &mut Budget) -> Result<Option<u8>, InspectionError> {
    let hir = transparent(hir, budget)?;
    let HirKind::Literal(literal) = hir.kind() else {
        return Ok(None);
    };
    budget.charge(1)?;
    let [byte] = literal.0.as_ref() else {
        return Ok(None);
    };
    Ok(Some(*byte))
}

fn field(hir: &Hir, budget: &mut Budget) -> Result<Option<Field>, InspectionError> {
    let Some(field) = field_language(hir, budget)? else {
        return Ok(None);
    };
    if field.length_mask & 1 != 0 || field.length_mask == 0 {
        return Ok(None);
    }
    Ok(Some(field))
}

fn field_language(hir: &Hir, budget: &mut Budget) -> Result<Option<Field>, InspectionError> {
    budget.charge(1)?;
    match hir.kind() {
        HirKind::Capture(capture) => field_language(capture.sub.as_ref(), budget),
        HirKind::Class(Class::Bytes(class)) => {
            let Some((class_start, class_end)) = class_range(class, budget)? else {
                return Ok(None);
            };
            Ok(Some(Field {
                class_start,
                class_end,
                length_mask: 1_u16 << 1,
            }))
        }
        HirKind::Concat(parts) => {
            if parts.is_empty() {
                return Ok(None);
            }
            let mut combined = None::<Field>;
            for part in parts {
                let Some(next) = field_language(part, budget)? else {
                    return Ok(None);
                };
                combined = Some(match combined {
                    None => next,
                    Some(previous) => {
                        if previous.class_start != next.class_start
                            || previous.class_end != next.class_end
                        {
                            return Ok(None);
                        }
                        let Some(length_mask) =
                            concatenate_lengths(previous.length_mask, next.length_mask, budget)?
                        else {
                            return Ok(None);
                        };
                        Field {
                            class_start: previous.class_start,
                            class_end: previous.class_end,
                            length_mask,
                        }
                    }
                });
            }
            Ok(combined)
        }
        HirKind::Repetition(repetition) => {
            if !repetition.greedy {
                return Ok(None);
            }
            let Some(maximum) = repetition.max else {
                return Ok(None);
            };
            let minimum =
                usize::try_from(repetition.min).map_err(|_| InspectionError::ArithmeticOverflow)?;
            let maximum =
                usize::try_from(maximum).map_err(|_| InspectionError::ArithmeticOverflow)?;
            if minimum > maximum || maximum > MAX_FIELD_BYTES {
                return Ok(None);
            }
            let Some(sub) = field_language(repetition.sub.as_ref(), budget)? else {
                return Ok(None);
            };
            let Some(length_mask) = repeated_lengths(sub.length_mask, minimum, maximum, budget)?
            else {
                return Ok(None);
            };
            Ok(Some(Field {
                class_start: sub.class_start,
                class_end: sub.class_end,
                length_mask,
            }))
        }
        HirKind::Empty
        | HirKind::Literal(_)
        | HirKind::Class(Class::Unicode(_))
        | HirKind::Look(_)
        | HirKind::Alternation(_) => Ok(None),
    }
}

fn repeated_lengths(
    sub: u16,
    minimum: usize,
    maximum: usize,
    budget: &mut Budget,
) -> Result<Option<u16>, InspectionError> {
    let mut repeated = 1_u16;
    let mut result = (minimum == 0).then_some(1_u16).unwrap_or(0);
    for count in 1..=maximum {
        let Some(next) = concatenate_lengths(repeated, sub, budget)? else {
            return Ok(None);
        };
        repeated = next;
        if count >= minimum {
            result |= repeated;
        }
    }
    Ok((result != 0).then_some(result))
}

fn concatenate_lengths(
    left: u16,
    right: u16,
    budget: &mut Budget,
) -> Result<Option<u16>, InspectionError> {
    let mut result = 0_u16;
    for left_len in 0..=MAX_FIELD_BYTES {
        if left & (1_u16 << left_len) == 0 {
            continue;
        }
        for right_len in 0..=MAX_FIELD_BYTES {
            if right & (1_u16 << right_len) == 0 {
                continue;
            }
            budget.charge(1)?;
            let total = left_len + right_len;
            if total > MAX_FIELD_BYTES {
                return Ok(None);
            }
            result |= 1_u16 << total;
        }
    }
    Ok((result != 0).then_some(result))
}

fn class_range(
    class: &ClassBytes,
    budget: &mut Budget,
) -> Result<Option<(u8, u8)>, InspectionError> {
    budget.charge(1)?;
    let [range] = class.ranges() else {
        return Ok(None);
    };
    let population = u64::from(range.end())
        .checked_sub(u64::from(range.start()))
        .and_then(|width| width.checked_add(1))
        .ok_or(InspectionError::ArithmeticOverflow)?;
    budget.charge(population)?;
    Ok(Some((range.start(), range.end())))
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
fn minimum_length(mask: u16) -> usize {
    usize::try_from(mask.trailing_zeros()).expect("a u16 bit index fits usize")
}

#[inline]
fn length_is_allowed(mask: u16, length: usize) -> bool {
    length <= MAX_FIELD_BYTES && mask & (1_u16 << length) != 0
}

#[inline]
fn all_in_range(start: u8, end: u8, bytes: &[u8]) -> bool {
    bytes.iter().all(|&byte| in_range(start, end, byte))
}

#[inline]
fn in_range(start: u8, end: u8, byte: u8) -> bool {
    byte.wrapping_sub(start) <= end.wrapping_sub(start)
}

#[cfg(test)]
mod tests {
    use regex::bytes::RegexBuilder;
    use regex_syntax::ParserBuilder;

    use super::{InspectionOutcome, inspect};

    const DATE: &str = r"([0-9][0-9]?)/([0-9][0-9]?)/([0-9][0-9]([0-9][0-9])?)";

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
    fn bounded_delimited_fields_match_directed_and_exhaustive_bytes() {
        let plan = plan(DATE);
        let oracle = RegexBuilder::new(DATE).unicode(false).build().unwrap();
        for haystack in [
            b"1/2/34".as_slice(),
            b"12/34/5678",
            b"x12/3/45y",
            b"1/2/345",
            b"1//23",
            b"/1/23",
            b"1/2/",
            b"111/2/34",
            b"\xff12/3/45\xfe",
            b"12/34/56\n78",
        ] {
            assert_eq!(plan.is_match_full(haystack), oracle.is_match(haystack));
        }

        let alphabet = [b'0', b'/', b'x', 0xff];
        let mut corpus = vec![Vec::new()];
        let mut frontier = vec![Vec::new()];
        for _ in 0..=8 {
            for haystack in &frontier {
                assert_eq!(
                    plan.is_match_full(haystack),
                    oracle.is_match(haystack),
                    "bounded delimiter result differed for {haystack:?}",
                );
            }
            let mut next = Vec::new();
            for prefix in frontier {
                for byte in alphabet {
                    let mut value = prefix.clone();
                    value.push(byte);
                    next.push(value);
                }
            }
            corpus.extend(next.iter().cloned());
            frontier = next;
        }
        assert!(corpus.len() > 80_000);
    }

    #[test]
    fn planner_is_bounded_and_nearby_languages_are_rejected() {
        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(DATE)
            .unwrap();
        let InspectionOutcome::Eligible { planner_work, .. } = inspect(&hir, 0, u64::MAX).unwrap()
        else {
            panic!("date shape should be eligible");
        };
        assert!(matches!(
            inspect(&hir, 0, planner_work - 1),
            Err(super::InspectionError::WorkLimit { needed, limit, .. })
                if needed == planner_work && limit == planner_work - 1
        ));

        for pattern in [
            r"[0-9]+/[0-9]{1,2}/[0-9]{2,4}",
            r"[0-9]{1,2}-[0-9]{1,2}/[0-9]{2}",
            r"[0-9]{1,2}/[0-9]{1,2}/[0-9]{16}",
            r"[0-9]{1,2}/[0-9A-F]{1,2}/[0-9]{2}",
            r"[0-9]{1,2}/[0-9]{1,2}/[0-9]{2}|x",
            r"^[0-9]{1,2}/[0-9]{1,2}/[0-9]{2}",
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
