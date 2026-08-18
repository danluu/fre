//! Allocation-free canonical-HIR proof for delimiter-excluded class fields.

use regex_syntax::hir::{Class, ClassBytes, Hir, HirKind};

use crate::aggregate_construction::AggregateInspectionAttemptError;

#[derive(Debug)]
pub(crate) enum Inspection<'a> {
    Eligible {
        class: &'a ClassBytes,
        delimiter: u8,
        work: usize,
        hir_nodes: usize,
        captures: usize,
    },
    Ineligible {
        work: usize,
    },
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

    fn charge(&mut self, amount: usize) -> Result<(), InspectionError> {
        let needed = self
            .work
            .checked_add(amount)
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
}

pub(crate) fn inspect_attempt(
    hir: &Hir,
    limit: usize,
) -> Result<Inspection<'_>, AggregateInspectionAttemptError<InspectionError>> {
    let mut budget = Budget::new(limit);
    inspect_with_budget(hir, &mut budget)
        .map_err(|source| AggregateInspectionAttemptError::new(source, budget.work))
}

fn inspect_with_budget<'a>(
    hir: &'a Hir,
    budget: &mut Budget,
) -> Result<Inspection<'a>, InspectionError> {
    let root = transparent(hir, budget)?;
    let HirKind::Concat(parts) = root.kind() else {
        return Ok(Inspection::Ineligible { work: budget.work });
    };
    budget.charge(1)?;
    let [left, delimiter, right] = parts.as_slice() else {
        return Ok(Inspection::Ineligible { work: budget.work });
    };
    let Some(left) = class_plus(left, budget)? else {
        return Ok(Inspection::Ineligible { work: budget.work });
    };
    let Some(delimiter) = one_byte_literal(delimiter, budget)? else {
        return Ok(Inspection::Ineligible { work: budget.work });
    };
    let Some(right) = class_plus(right, budget)? else {
        return Ok(Inspection::Ineligible { work: budget.work });
    };
    if !same_class(left, right, budget)? || class_contains(left, delimiter, budget)? {
        return Ok(Inspection::Ineligible { work: budget.work });
    }
    Ok(Inspection::Eligible {
        class: left,
        delimiter,
        work: budget.work,
        hir_nodes: budget.hir_nodes,
        captures: budget.captures,
    })
}

fn class_plus<'a>(
    hir: &'a Hir,
    budget: &mut Budget,
) -> Result<Option<&'a ClassBytes>, InspectionError> {
    let hir = transparent(hir, budget)?;
    let HirKind::Repetition(repetition) = hir.kind() else {
        return Ok(None);
    };
    budget.charge(4)?;
    if repetition.min != 1 || repetition.max.is_some() || !repetition.greedy {
        return Ok(None);
    }
    let repeated = transparent(repetition.sub.as_ref(), budget)?;
    let HirKind::Class(Class::Bytes(class)) = repeated.kind() else {
        return Ok(None);
    };
    budget.charge(1)?;
    if class.ranges().is_empty() {
        return Ok(None);
    }
    Ok(Some(class))
}

fn one_byte_literal(hir: &Hir, budget: &mut Budget) -> Result<Option<u8>, InspectionError> {
    let hir = transparent(hir, budget)?;
    let HirKind::Literal(literal) = hir.kind() else {
        return Ok(None);
    };
    budget.charge(
        literal
            .0
            .len()
            .checked_add(1)
            .ok_or(InspectionError::Overflow)?,
    )?;
    let [delimiter] = literal.0.as_ref() else {
        return Ok(None);
    };
    Ok(Some(*delimiter))
}

fn same_class(
    left: &ClassBytes,
    right: &ClassBytes,
    budget: &mut Budget,
) -> Result<bool, InspectionError> {
    budget.charge(1)?;
    if left.ranges().len() != right.ranges().len() {
        return Ok(false);
    }
    for (left, right) in left.ranges().iter().zip(right.ranges()) {
        budget.charge(1)?;
        if left != right {
            return Ok(false);
        }
    }
    Ok(true)
}

fn class_contains(
    class: &ClassBytes,
    byte: u8,
    budget: &mut Budget,
) -> Result<bool, InspectionError> {
    let mut low = 0_usize;
    let mut high = class.ranges().len();
    while low < high {
        budget.charge(1)?;
        let width = high.checked_sub(low).ok_or(InspectionError::Overflow)?;
        let middle = low
            .checked_add(width / 2)
            .ok_or(InspectionError::Overflow)?;
        let range = class.ranges()[middle];
        if byte < range.start() {
            high = middle;
        } else if byte > range.end() {
            low = middle.checked_add(1).ok_or(InspectionError::Overflow)?;
        } else {
            return Ok(true);
        }
    }
    Ok(false)
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

    use super::{Inspection, InspectionError, inspect_attempt};

    fn parse(pattern: &str) -> regex_syntax::hir::Hir {
        ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(pattern)
            .unwrap()
    }

    fn assert_eligible(pattern: &str, delimiter: u8) -> (usize, usize, usize) {
        let Inspection::Eligible {
            delimiter: actual,
            work,
            hir_nodes,
            captures,
            ..
        } = inspect_attempt(&parse(pattern), usize::MAX).unwrap()
        else {
            panic!("delimiter-field shape was not recognized: {pattern}");
        };
        assert_eq!(actual, delimiter);
        (work, hir_nodes, captures)
    }

    fn assert_ineligible(pattern: &str) {
        assert!(matches!(
            inspect_attempt(&parse(pattern), usize::MAX).unwrap(),
            Inspection::Ineligible { .. }
        ));
    }

    #[test]
    fn exact_capture_erased_byte_shapes_are_eligible() {
        let (_, plain_nodes, plain_captures) = assert_eligible(r"\w+@\w+", b'@');
        let (_, captured_nodes, captured_captures) = assert_eligible(r"((\w+))@((\w+))", b'@');
        assert_eq!(plain_captures, 0);
        assert_eq!(captured_captures, 4);
        assert_eq!(captured_nodes, plain_nodes + 4);
        assert_eligible(r"[ab]+![ab]+", b'!');
    }

    #[test]
    fn neighboring_semantics_refuse_exactly() {
        for pattern in [
            r"\w*@\w+",
            r"\w+?@\w+",
            r"\w+@@\w+",
            r"\w+@\d+",
            r"[a@]+@[a@]+",
            r"^\w+@\w+",
            r"\w+@\w+$",
            r"(?:\w+@\w+)|x",
        ] {
            assert_ineligible(pattern);
        }
    }

    #[test]
    fn planner_limit_refuses_with_partial_work() {
        let hir = parse(r"\w+@\w+");
        let Inspection::Eligible { work, .. } =
            inspect_attempt(&hir, usize::MAX).expect("unlimited inspection")
        else {
            panic!("expected eligible shape");
        };
        assert!(matches!(
            inspect_attempt(&hir, work - 1).unwrap_err().into_source(),
            InspectionError::WorkLimit { needed, limit } if needed > limit
        ));
    }
}
