//! Allocation-free canonical-HIR proof for the ASCII token-phrase reducer.

use regex_syntax::hir::{Class, ClassBytes, Hir, HirKind, Look};

use crate::aggregate_construction::AggregateInspectionAttemptError;

const ASCII_WORD_RANGES: [(u8, u8); 4] = [(b'0', b'9'), (b'A', b'Z'), (b'_', b'_'), (b'a', b'z')];
const ASCII_SPACE_RANGES: [(u8, u8); 2] = [(b'\t', b'\r'), (b' ', b' ')];

pub(crate) struct Inspection<'a> {
    pub literal: &'a [u8],
    pub outer_word_assertions: bool,
    pub work: usize,
    pub hir_nodes: usize,
    pub captures: usize,
}

pub(crate) enum InspectionOutcome<'a> {
    Eligible(Inspection<'a>),
    Ineligible { work: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InspectionError {
    WorkLimit { needed: usize, limit: usize },
    Overflow,
}

struct Budget {
    work: usize,
    hir_nodes: usize,
    captures: usize,
    limit: usize,
}

impl Budget {
    const fn new(limit: usize) -> Self {
        Self {
            work: 0,
            hir_nodes: 0,
            captures: 0,
            limit,
        }
    }

    fn charge(&mut self, units: usize) -> Result<(), InspectionError> {
        let needed = self
            .work
            .checked_add(units)
            .ok_or(InspectionError::Overflow)?;
        if needed > self.limit {
            return Err(InspectionError::WorkLimit {
                needed,
                limit: self.limit,
            });
        }
        self.work = needed;
        Ok(())
    }

    fn visit_node(&mut self) -> Result<(), InspectionError> {
        self.charge(1)?;
        self.hir_nodes = self
            .hir_nodes
            .checked_add(1)
            .ok_or(InspectionError::Overflow)?;
        Ok(())
    }

    fn visit_capture(&mut self) -> Result<(), InspectionError> {
        self.captures = self
            .captures
            .checked_add(1)
            .ok_or(InspectionError::Overflow)?;
        Ok(())
    }

    const fn ineligible(&self) -> InspectionOutcome<'static> {
        InspectionOutcome::Ineligible { work: self.work }
    }
}

/// Prove exactly `W+ S+ L S+ W+`, optionally surrounded by two ASCII
/// `\b` assertions, where `W` is the complete ASCII word class, `S` is the
/// complete ASCII whitespace class, and `L` is a nonempty all-word literal.
///
/// Captures may wrap any structural component because aggregate value
/// operations erase them explicitly.
#[cfg(test)]
pub(crate) fn inspect(hir: &Hir, limit: usize) -> Result<InspectionOutcome<'_>, InspectionError> {
    inspect_attempt(hir, limit).map_err(AggregateInspectionAttemptError::into_source)
}

pub(crate) fn inspect_attempt(
    hir: &Hir,
    limit: usize,
) -> Result<InspectionOutcome<'_>, AggregateInspectionAttemptError<InspectionError>> {
    let mut budget = Budget::new(limit);
    inspect_with_budget(hir, &mut budget)
        .map_err(|source| AggregateInspectionAttemptError::new(source, budget.work))
}

fn inspect_with_budget<'a>(
    hir: &'a Hir,
    budget: &mut Budget,
) -> Result<InspectionOutcome<'a>, InspectionError> {
    let root = transparent(hir, budget)?;
    let HirKind::Concat(parts) = root.kind() else {
        return Ok(budget.ineligible());
    };
    budget.charge(parts.len())?;

    let (body, outer_word_assertions) = match parts.as_slice() {
        [
            left,
            first_word,
            left_space,
            literal,
            right_space,
            final_word,
            right,
        ] => {
            if !ascii_word_boundary(left, budget)? || !ascii_word_boundary(right, budget)? {
                return Ok(budget.ineligible());
            }
            (
                [first_word, left_space, literal, right_space, final_word],
                true,
            )
        }
        [first_word, left_space, literal, right_space, final_word] => (
            [first_word, left_space, literal, right_space, final_word],
            false,
        ),
        _ => return Ok(budget.ineligible()),
    };

    if !greedy_nonempty_exact_class(body[0], &ASCII_WORD_RANGES, budget)?
        || !greedy_nonempty_exact_class(body[1], &ASCII_SPACE_RANGES, budget)?
        || !greedy_nonempty_exact_class(body[3], &ASCII_SPACE_RANGES, budget)?
        || !greedy_nonempty_exact_class(body[4], &ASCII_WORD_RANGES, budget)?
    {
        return Ok(budget.ineligible());
    }
    let Some(literal) = word_literal(body[2], budget)? else {
        return Ok(budget.ineligible());
    };

    Ok(InspectionOutcome::Eligible(Inspection {
        literal,
        outer_word_assertions,
        work: budget.work,
        hir_nodes: budget.hir_nodes,
        captures: budget.captures,
    }))
}

fn ascii_word_boundary(hir: &Hir, budget: &mut Budget) -> Result<bool, InspectionError> {
    let hir = transparent(hir, budget)?;
    budget.charge(1)?;
    Ok(matches!(hir.kind(), HirKind::Look(Look::WordAscii)))
}

fn greedy_nonempty_exact_class(
    hir: &Hir,
    expected: &[(u8, u8)],
    budget: &mut Budget,
) -> Result<bool, InspectionError> {
    let hir = transparent(hir, budget)?;
    let HirKind::Repetition(repetition) = hir.kind() else {
        return Ok(false);
    };
    budget.charge(3)?;
    if repetition.min != 1 || repetition.max.is_some() || !repetition.greedy {
        return Ok(false);
    }
    let repeated = transparent(&repetition.sub, budget)?;
    let HirKind::Class(Class::Bytes(class)) = repeated.kind() else {
        return Ok(false);
    };
    exact_class(class, expected, budget)
}

fn exact_class(
    class: &ClassBytes,
    expected: &[(u8, u8)],
    budget: &mut Budget,
) -> Result<bool, InspectionError> {
    budget.charge(
        class
            .ranges()
            .len()
            .checked_add(expected.len())
            .and_then(|units| units.checked_add(1))
            .ok_or(InspectionError::Overflow)?,
    )?;
    if class.ranges().len() != expected.len() {
        return Ok(false);
    }
    for (range, &(start, end)) in class.ranges().iter().zip(expected) {
        budget.charge(2)?;
        if range.start() != start || range.end() != end {
            return Ok(false);
        }
    }
    Ok(true)
}

fn word_literal<'a>(
    hir: &'a Hir,
    budget: &mut Budget,
) -> Result<Option<&'a [u8]>, InspectionError> {
    let hir = transparent(hir, budget)?;
    let HirKind::Literal(literal) = hir.kind() else {
        return Ok(None);
    };
    budget.charge(
        literal
            .0
            .len()
            .checked_mul(2)
            .and_then(|units| units.checked_add(1))
            .ok_or(InspectionError::Overflow)?,
    )?;
    if literal.0.is_empty()
        || literal
            .0
            .iter()
            .any(|&byte| !(byte.is_ascii_alphanumeric() || byte == b'_'))
    {
        return Ok(None);
    }
    Ok(Some(literal.0.as_ref()))
}

fn transparent<'a>(mut hir: &'a Hir, budget: &mut Budget) -> Result<&'a Hir, InspectionError> {
    loop {
        budget.visit_node()?;
        let HirKind::Capture(capture) = hir.kind() else {
            return Ok(hir);
        };
        budget.visit_capture()?;
        hir = capture.sub.as_ref();
    }
}

#[cfg(test)]
mod tests {
    use regex_syntax::ParserBuilder;

    use super::{InspectionError, InspectionOutcome, inspect};

    fn parse(pattern: &str, unicode: bool) -> regex_syntax::hir::Hir {
        ParserBuilder::new()
            .unicode(unicode)
            .utf8(false)
            .build()
            .parse(pattern)
            .unwrap()
    }

    #[test]
    fn asserted_unasserted_and_transparent_captures_are_eligible() {
        for (pattern, asserted) in [
            (r"\w+\s+Holmes\s+\w+", false),
            (r"\b\w+\s+Holmes\s+\w+\b", true),
            (r"(\b)((\w+))(\s+)(Holmes)(\s+)((\w+))(\b)", true),
        ] {
            let hir = parse(pattern, false);
            let InspectionOutcome::Eligible(inspection) = inspect(&hir, usize::MAX).unwrap() else {
                panic!("expected eligible token phrase: {pattern}");
            };
            assert_eq!(inspection.literal, b"Holmes");
            assert_eq!(inspection.outer_word_assertions, asserted);
            assert_eq!(inspection.hir_nodes, count(&hir));
        }
    }

    #[test]
    fn every_semantic_perturbation_remains_ineligible() {
        for (pattern, unicode) in [
            (r"\b\w+\s+Holmes\s+\w+", true),
            (r"\b[A-Za-z]+\s+Holmes\s+\w+\b", false),
            (r"\b\w+ +Holmes\s+\w+\b", false),
            (r"\b\w*\s+Holmes\s+\w+\b", false),
            (r"\b\w+?\s+Holmes\s+\w+\b", false),
            (r"\b\w+\s+Holmes\s*\w+\b", false),
            (r"\b\w+\s+Hol-mes\s+\w+\b", false),
            (r"\b\w+\s+\s+\w+\b", false),
            (r"\b\w+\s+Holmes\s+\w+", false),
            (r"\w+\s+Holmes\s+\w+\b", false),
            (r"\b\w+\s+Holmes\s+\w+\bX", false),
        ] {
            assert!(
                matches!(
                    inspect(&parse(pattern, unicode), usize::MAX).unwrap(),
                    InspectionOutcome::Ineligible { .. }
                ),
                "unexpected eligibility for {pattern:?}, unicode={unicode}"
            );
        }
    }

    #[test]
    fn planner_limit_is_exact() {
        let hir = parse(r"\b\w+\s+Holmes\s+\w+\b", false);
        let InspectionOutcome::Eligible(inspection) = inspect(&hir, usize::MAX).unwrap() else {
            panic!("control must be eligible");
        };
        assert!(matches!(
            inspect(&hir, inspection.work - 1),
            Err(InspectionError::WorkLimit { .. })
        ));
        assert!(matches!(
            inspect(&hir, inspection.work),
            Ok(InspectionOutcome::Eligible(_))
        ));
    }

    fn count(hir: &regex_syntax::hir::Hir) -> usize {
        let descendants = match hir.kind() {
            regex_syntax::hir::HirKind::Capture(capture) => count(&capture.sub),
            regex_syntax::hir::HirKind::Concat(parts)
            | regex_syntax::hir::HirKind::Alternation(parts) => parts.iter().map(count).sum(),
            regex_syntax::hir::HirKind::Repetition(repetition) => count(&repetition.sub),
            _ => 0,
        };
        descendants
            .checked_add(1)
            .expect("test HIR node count must fit usize")
    }
}
