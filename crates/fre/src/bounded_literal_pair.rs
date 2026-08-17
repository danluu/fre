//! Allocation-free canonical-HIR proof for the bounded literal-pair reducer.

use regex_syntax::hir::{Class, ClassBytes, Hir, HirKind};

use crate::aggregate_construction::AggregateInspectionAttemptError;

pub(crate) enum Inspection<'a> {
    Eligible {
        left: &'a [u8],
        class: &'a ClassBytes,
        right: &'a [u8],
        gap_min: u32,
        gap_max: u32,
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

struct Branch<'a> {
    prefix: &'a [u8],
    class: &'a ClassBytes,
    suffix: &'a [u8],
    gap_min: u32,
    gap_max: u32,
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

/// Prove exactly `L C{M,K} R | R C{M,K} L` in canonical byte HIR.
///
/// Captures are transparent because the aggregate facade exposes only whole
/// matches. Distinct leading bytes make the two start streams disjoint, while
/// the kernel remains responsible for greedy endpoint selection and global
/// non-overlapping restart semantics.
#[cfg(test)]
pub(crate) fn inspect(hir: &Hir, limit: usize) -> Result<Inspection<'_>, InspectionError> {
    inspect_attempt(hir, limit).map_err(AggregateInspectionAttemptError::into_source)
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
    let HirKind::Alternation(branches) = root.kind() else {
        return Ok(Inspection::Ineligible { work: budget.work });
    };
    budget.charge(1)?;
    let [first, second] = branches.as_slice() else {
        return Ok(Inspection::Ineligible { work: budget.work });
    };
    let Some(first) = branch(first, budget)? else {
        return Ok(Inspection::Ineligible { work: budget.work });
    };
    let Some(second) = branch(second, budget)? else {
        return Ok(Inspection::Ineligible { work: budget.work });
    };

    if !same_literal(first.prefix, second.suffix, budget)?
        || !same_literal(first.suffix, second.prefix, budget)?
    {
        return Ok(Inspection::Ineligible { work: budget.work });
    }
    budget.charge(2)?;
    if first.gap_min != second.gap_min
        || first.gap_max != second.gap_max
        || first.prefix[0] == first.suffix[0]
    {
        return Ok(Inspection::Ineligible { work: budget.work });
    }
    if !same_class(first.class, second.class, budget)? {
        return Ok(Inspection::Ineligible { work: budget.work });
    }
    Ok(Inspection::Eligible {
        left: first.prefix,
        class: first.class,
        right: first.suffix,
        gap_min: first.gap_min,
        gap_max: first.gap_max,
        work: budget.work,
        hir_nodes: budget.hir_nodes,
        captures: budget.captures,
    })
}

fn branch<'a>(hir: &'a Hir, budget: &mut Budget) -> Result<Option<Branch<'a>>, InspectionError> {
    let hir = transparent(hir, budget)?;
    let HirKind::Concat(parts) = hir.kind() else {
        return Ok(None);
    };
    budget.charge(1)?;
    let [prefix, gap, suffix] = parts.as_slice() else {
        return Ok(None);
    };

    let prefix = transparent(prefix, budget)?;
    let HirKind::Literal(prefix) = prefix.kind() else {
        return Ok(None);
    };
    budget.charge(
        prefix
            .0
            .len()
            .checked_add(1)
            .ok_or(InspectionError::Overflow)?,
    )?;
    if prefix.0.is_empty() {
        return Ok(None);
    }

    let gap = transparent(gap, budget)?;
    let HirKind::Repetition(repetition) = gap.kind() else {
        return Ok(None);
    };
    budget.charge(4)?;
    let Some(gap_max) = repetition.max else {
        return Ok(None);
    };
    if repetition.min > gap_max || gap_max == 0 || !repetition.greedy {
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
    budget.charge(class.ranges().len())?;

    let suffix = transparent(suffix, budget)?;
    let HirKind::Literal(suffix) = suffix.kind() else {
        return Ok(None);
    };
    budget.charge(
        suffix
            .0
            .len()
            .checked_add(1)
            .ok_or(InspectionError::Overflow)?,
    )?;
    if suffix.0.is_empty() {
        return Ok(None);
    }

    Ok(Some(Branch {
        prefix: prefix.0.as_ref(),
        class,
        suffix: suffix.0.as_ref(),
        gap_min: repetition.min,
        gap_max,
    }))
}

fn same_literal(left: &[u8], right: &[u8], budget: &mut Budget) -> Result<bool, InspectionError> {
    let work = left
        .len()
        .min(right.len())
        .checked_add(1)
        .ok_or(InspectionError::Overflow)?;
    budget.charge(work)?;
    Ok(left == right)
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

    use super::{Inspection, InspectionError, inspect};

    fn parse(pattern: &str) -> regex_syntax::hir::Hir {
        ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(pattern)
            .unwrap()
    }

    #[test]
    fn exact_swapped_shape_and_transparent_captures_are_eligible() {
        let hir = parse(r"(Holmes(?:[^\n]{0,25})Watson)|(Watson[^\n]{0,25}Holmes)");
        let Inspection::Eligible {
            left,
            right,
            gap_min,
            gap_max,
            hir_nodes,
            captures,
            ..
        } = inspect(&hir, usize::MAX).unwrap()
        else {
            panic!("bounded literal pair was not recognized");
        };
        assert_eq!(left, b"Holmes");
        assert_eq!(right, b"Watson");
        assert_eq!(gap_min, 0);
        assert_eq!(gap_max, 25);
        assert!(hir_nodes > 0);
        assert_eq!(captures, 2);
    }

    #[test]
    fn exact_planner_limit_succeeds_and_one_below_refuses() {
        let hir = parse(r"Holmes.{0,25}Watson|Watson.{0,25}Holmes");
        let Inspection::Eligible { work, .. } = inspect(&hir, usize::MAX).unwrap() else {
            panic!("bounded literal pair was not recognized");
        };
        let one_below = work.checked_sub(1).unwrap();
        assert!(matches!(
            inspect(&hir, work),
            Ok(Inspection::Eligible { .. })
        ));
        assert!(matches!(
            inspect(&hir, one_below),
            Err(InspectionError::WorkLimit { needed, limit })
                if needed == work && limit == one_below
        ));
    }

    #[test]
    fn nearby_shapes_refuse_without_broadening_the_descriptor() {
        for pattern in [
            r"Holmes.{0,25}Watson",
            r"Holmes.{0,25}Watson|Watson.{0,24}Holmes",
            r"Holmes.{0,25}Watson|Watson[ -~]{0,25}Holmes",
            r"Holmes.*Watson|Watson.*Holmes",
            r"Holmes.{0,25}Watson|Holmes.{0,25}Watson",
        ] {
            assert!(matches!(
                inspect(&parse(pattern), usize::MAX).unwrap(),
                Inspection::Ineligible { .. }
            ));
        }
    }
}
