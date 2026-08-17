//! Exact value-only existence for an absolute-start scalar corridor.
//!
//! The admitted language is
//! `^ LEFT_CLASS* HEAD ANY_SCALAR_EXCEPT_LF* NEEDLE SEPARATOR SPACE_CLASS*
//! TAIL OPTIONAL? END`. All literals and the three finite classes are ASCII
//! in Unicode mode. The leading bytes of `HEAD` and `TAIL` are outside their
//! preceding classes, which makes both greedy class runs deterministic. The
//! corridor needle is self-nonoverlapping, so a non-overlapping literal scan
//! still visits every possible tail start.

use memchr::{memchr, memmem};
use regex_syntax::hir::{Class, Hir, HirKind, Look};

pub(crate) const PLAN_ID: &str = "k0.absolute-start-scalar-corridor-tail.v1";
pub(crate) const OPERATION_ID: &str = "k0.exists.absolute-start-scalar-corridor-tail.v1";

const MAX_LITERAL_BYTES: usize = 16;
const DIRECT_WORK_PER_INPUT_BYTE: u64 = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InlineLiteral {
    bytes: [u8; MAX_LITERAL_BYTES],
    len: u8,
}

impl InlineLiteral {
    fn new(bytes: &[u8]) -> Result<Option<Self>, InspectionError> {
        if bytes.is_empty() || bytes.len() > MAX_LITERAL_BYTES || !bytes.is_ascii() {
            return Ok(None);
        }
        let mut stored = [0_u8; MAX_LITERAL_BYTES];
        stored[..bytes.len()].copy_from_slice(bytes);
        Ok(Some(Self {
            bytes: stored,
            len: u8::try_from(bytes.len()).map_err(|_| InspectionError::ArithmeticOverflow)?,
        }))
    }

    const fn len(self) -> usize {
        self.len as usize
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Identity {
    pub(crate) plan_id: &'static str,
    pub(crate) operation_id: &'static str,
    leading_words: [u64; 4],
    head: InlineLiteral,
    needle: InlineLiteral,
    separator_words: [u64; 4],
    spacing_words: [u64; 4],
    tail: InlineLiteral,
    optional: InlineLiteral,
    end: InlineLiteral,
    unicode_corridor: bool,
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

    pub(crate) const fn prepared_work_per_input_byte(self) -> u64 {
        DIRECT_WORK_PER_INPUT_BYTE
    }

    #[inline]
    pub(crate) fn is_match_full(self, haystack: &[u8]) -> bool {
        let mut position = 0_usize;
        while position < haystack.len() && contains(self.identity.leading_words, haystack[position])
        {
            position += 1;
        }
        let Some(after_head) = self.literal_at(haystack, position, self.identity.head) else {
            return false;
        };

        let remaining = &haystack[after_head..];
        let before_lf = memchr(b'\n', remaining).unwrap_or(remaining.len());
        let corridor_bytes = &remaining[..before_lf];
        let corridor_len = if self.identity.unicode_corridor {
            match core::str::from_utf8(corridor_bytes) {
                Ok(_) => corridor_bytes.len(),
                Err(error) => error.valid_up_to(),
            }
        } else {
            corridor_bytes.len()
        };
        let corridor = &corridor_bytes[..corridor_len];
        let needle_len = self.identity.needle.len();
        let needle = &self.identity.needle.bytes[..needle_len];
        for relative in memmem::find_iter(corridor, needle) {
            let Some(after_needle) = after_head
                .checked_add(relative)
                .and_then(|start| start.checked_add(needle.len()))
            else {
                return false;
            };
            if self.tail_matches(haystack, after_needle) {
                return true;
            }
        }
        false
    }

    #[inline]
    fn tail_matches(self, haystack: &[u8], mut position: usize) -> bool {
        let Some(&separator) = haystack.get(position) else {
            return false;
        };
        if !contains(self.identity.separator_words, separator) {
            return false;
        }
        position += 1;
        while position < haystack.len() && contains(self.identity.spacing_words, haystack[position])
        {
            position += 1;
        }
        let Some(after_tail) = self.literal_at(haystack, position, self.identity.tail) else {
            return false;
        };
        if self
            .literal_at(haystack, after_tail, self.identity.end)
            .is_some()
        {
            return true;
        }
        self.literal_at(haystack, after_tail, self.identity.optional)
            .and_then(|after_optional| self.literal_at(haystack, after_optional, self.identity.end))
            .is_some()
    }

    #[inline]
    fn literal_at(self, haystack: &[u8], start: usize, literal: InlineLiteral) -> Option<usize> {
        let length = literal.len();
        let end = start.checked_add(length)?;
        (haystack.get(start..end) == Some(&literal.bytes[..length])).then_some(end)
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
        return ineligible(budget);
    };
    budget.charge(1)?;
    let [
        start,
        leading,
        head,
        corridor,
        needle,
        separator,
        spacing,
        tail,
        optional,
        end,
    ] = parts.as_slice()
    else {
        return ineligible(budget);
    };

    let start = transparent(start, &mut budget)?;
    if !matches!(start.kind(), HirKind::Look(Look::Start)) {
        return ineligible(budget);
    }
    budget.charge(1)?;

    let Some((leading_class, leading_unicode)) =
        repeated_ascii_class(leading, 0, None, &mut budget)?
    else {
        return ineligible(budget);
    };
    let Some(head) = ascii_literal(head, &mut budget)? else {
        return ineligible(budget);
    };
    if contains(leading_class, head.bytes[0]) {
        return ineligible(budget);
    }

    let Some(corridor_unicode) = universal_non_lf_repetition(corridor, &mut budget)? else {
        return ineligible(budget);
    };
    if leading_unicode != corridor_unicode {
        return ineligible(budget);
    }
    let Some(needle) = ascii_literal(needle, &mut budget)? else {
        return ineligible(budget);
    };
    if needle.len() < 2 || needle.bytes[1..needle.len()].contains(&needle.bytes[0]) {
        return ineligible(budget);
    }

    let Some((separator_class, separator_unicode)) = ascii_class(separator, &mut budget)? else {
        return ineligible(budget);
    };
    let Some((spacing_class, spacing_unicode)) =
        repeated_ascii_class(spacing, 0, None, &mut budget)?
    else {
        return ineligible(budget);
    };
    if separator_unicode != corridor_unicode || spacing_unicode != corridor_unicode {
        return ineligible(budget);
    }
    // Every failed tail probe may scan a spacing run. Keep those runs
    // disjoint from later needle starts so the prepared work envelope remains
    // linear even for adversarial accepted shapes.
    if contains(spacing_class, needle.bytes[0]) {
        return ineligible(budget);
    }
    let Some(tail) = ascii_literal(tail, &mut budget)? else {
        return ineligible(budget);
    };
    if contains(spacing_class, tail.bytes[0]) {
        return ineligible(budget);
    }
    let Some(optional) = optional_ascii_literal(optional, &mut budget)? else {
        return ineligible(budget);
    };
    let Some(end) = ascii_literal(end, &mut budget)? else {
        return ineligible(budget);
    };

    Ok(InspectionOutcome::Eligible {
        plan: Plan {
            identity: Identity {
                plan_id: PLAN_ID,
                operation_id: OPERATION_ID,
                leading_words: leading_class,
                head,
                needle,
                separator_words: separator_class,
                spacing_words: spacing_class,
                tail,
                optional,
                end,
                unicode_corridor: corridor_unicode,
                full_input: true,
            },
        },
        planner_work: budget.actual,
    })
}

fn ineligible(budget: Budget) -> Result<InspectionOutcome, InspectionError> {
    Ok(InspectionOutcome::Ineligible {
        planner_work: budget.actual,
    })
}

fn optional_ascii_literal(
    hir: &Hir,
    budget: &mut Budget,
) -> Result<Option<InlineLiteral>, InspectionError> {
    let hir = transparent(hir, budget)?;
    let HirKind::Repetition(repetition) = hir.kind() else {
        return Ok(None);
    };
    budget.charge(1)?;
    if repetition.min != 0 || repetition.max != Some(1) {
        return Ok(None);
    }
    ascii_literal(repetition.sub.as_ref(), budget)
}

fn ascii_literal(hir: &Hir, budget: &mut Budget) -> Result<Option<InlineLiteral>, InspectionError> {
    let hir = transparent(hir, budget)?;
    let HirKind::Literal(literal) = hir.kind() else {
        return Ok(None);
    };
    budget.charge(1)?;
    budget
        .charge(u64::try_from(literal.0.len()).map_err(|_| InspectionError::ArithmeticOverflow)?)?;
    InlineLiteral::new(literal.0.as_ref())
}

fn repeated_ascii_class(
    hir: &Hir,
    minimum: u32,
    maximum: Option<u32>,
    budget: &mut Budget,
) -> Result<Option<([u64; 4], bool)>, InspectionError> {
    let hir = transparent(hir, budget)?;
    let HirKind::Repetition(repetition) = hir.kind() else {
        return Ok(None);
    };
    budget.charge(1)?;
    if repetition.min != minimum || repetition.max != maximum {
        return Ok(None);
    }
    ascii_class(repetition.sub.as_ref(), budget)
}

fn ascii_class(
    hir: &Hir,
    budget: &mut Budget,
) -> Result<Option<([u64; 4], bool)>, InspectionError> {
    let hir = transparent(hir, budget)?;
    let mut words = [0_u64; 4];
    match hir.kind() {
        HirKind::Class(Class::Bytes(class)) => {
            budget.charge(1)?;
            if class.ranges().is_empty() {
                return Ok(None);
            }
            for range in class.ranges() {
                budget.charge(1)?;
                for byte in range.start()..=range.end() {
                    set(&mut words, byte);
                }
            }
            Ok(Some((words, false)))
        }
        HirKind::Class(Class::Unicode(class)) => {
            budget.charge(1)?;
            if class.ranges().is_empty()
                || class
                    .ranges()
                    .iter()
                    .any(|range| !range.start().is_ascii() || !range.end().is_ascii())
            {
                return Ok(None);
            }
            for range in class.ranges() {
                budget.charge(1)?;
                for scalar in u32::from(range.start())..=u32::from(range.end()) {
                    let byte =
                        u8::try_from(scalar).map_err(|_| InspectionError::ArithmeticOverflow)?;
                    set(&mut words, byte);
                }
            }
            Ok(Some((words, true)))
        }
        _ => Ok(None),
    }
}

fn universal_non_lf_repetition(
    hir: &Hir,
    budget: &mut Budget,
) -> Result<Option<bool>, InspectionError> {
    let hir = transparent(hir, budget)?;
    let HirKind::Repetition(repetition) = hir.kind() else {
        return Ok(None);
    };
    budget.charge(1)?;
    if repetition.min != 0 || repetition.max.is_some() {
        return Ok(None);
    }
    let class = transparent(repetition.sub.as_ref(), budget)?;
    match class.kind() {
        HirKind::Class(Class::Bytes(class)) => {
            budget.charge(2)?;
            let [before, after] = class.ranges() else {
                return Ok(None);
            };
            Ok((before.start() == u8::MIN
                && before.end() == b'\n' - 1
                && after.start() == b'\n' + 1
                && after.end() == u8::MAX)
                .then_some(false))
        }
        HirKind::Class(Class::Unicode(class)) => {
            budget.charge(2)?;
            let [before, after] = class.ranges() else {
                return Ok(None);
            };
            Ok((before.start() == '\0'
                && before.end() == '\t'
                && after.start() == '\u{b}'
                && after.end() == char::MAX)
                .then_some(true))
        }
        _ => Ok(None),
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

#[inline]
fn set(words: &mut [u64; 4], byte: u8) {
    let index = usize::from(byte);
    words[index / 64] |= 1_u64 << (index % 64);
}

#[inline]
fn contains(words: [u64; 4], byte: u8) -> bool {
    let index = usize::from(byte);
    words[index / 64] & (1_u64 << (index % 64)) != 0
}
