//! Allocation-free canonical-HIR proof for the literal line-assertion reducer.

use regex_syntax::hir::{Hir, HirKind, Look};

pub(crate) struct Inspection<'a> {
    pub literal: &'a [u8],
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
}

/// Prove exactly `(?m:^L)|(?m:L$)` with one shared nonempty literal.
///
/// Captures may wrap any structural component because aggregate value
/// operations erase them explicitly. Branch order remains exact, and the
/// kernel is responsible for rejected-overlap discovery and global restart.
pub(crate) fn inspect(hir: &Hir, limit: usize) -> Result<InspectionOutcome<'_>, InspectionError> {
    let mut budget = Budget::new(limit);
    let root = transparent(hir, &mut budget)?;
    let HirKind::Alternation(branches) = root.kind() else {
        return Ok(InspectionOutcome::Ineligible { work: budget.work });
    };
    budget.charge(1)?;
    let [start_branch, end_branch] = branches.as_slice() else {
        return Ok(InspectionOutcome::Ineligible { work: budget.work });
    };
    let Some(start_literal) = start_branch_literal(start_branch, &mut budget)? else {
        return Ok(InspectionOutcome::Ineligible { work: budget.work });
    };
    let Some(end_literal) = end_branch_literal(end_branch, &mut budget)? else {
        return Ok(InspectionOutcome::Ineligible { work: budget.work });
    };
    let comparisons = start_literal
        .len()
        .min(end_literal.len())
        .checked_add(1)
        .ok_or(InspectionError::Overflow)?;
    budget.charge(comparisons)?;
    if start_literal.is_empty() || start_literal != end_literal {
        return Ok(InspectionOutcome::Ineligible { work: budget.work });
    }
    Ok(InspectionOutcome::Eligible(Inspection {
        literal: start_literal,
        work: budget.work,
        hir_nodes: budget.hir_nodes,
        captures: budget.captures,
    }))
}

fn start_branch_literal<'a>(
    hir: &'a Hir,
    budget: &mut Budget,
) -> Result<Option<&'a [u8]>, InspectionError> {
    let hir = transparent(hir, budget)?;
    let HirKind::Concat(parts) = hir.kind() else {
        return Ok(None);
    };
    budget.charge(1)?;
    let [look, literal] = parts.as_slice() else {
        return Ok(None);
    };
    let look = transparent(look, budget)?;
    budget.charge(1)?;
    if !matches!(look.kind(), HirKind::Look(Look::StartLF)) {
        return Ok(None);
    }
    literal_bytes(literal, budget)
}

fn end_branch_literal<'a>(
    hir: &'a Hir,
    budget: &mut Budget,
) -> Result<Option<&'a [u8]>, InspectionError> {
    let hir = transparent(hir, budget)?;
    let HirKind::Concat(parts) = hir.kind() else {
        return Ok(None);
    };
    budget.charge(1)?;
    let [literal, look] = parts.as_slice() else {
        return Ok(None);
    };
    let Some(literal) = literal_bytes(literal, budget)? else {
        return Ok(None);
    };
    let look = transparent(look, budget)?;
    budget.charge(1)?;
    if !matches!(look.kind(), HirKind::Look(Look::EndLF)) {
        return Ok(None);
    }
    Ok(Some(literal))
}

fn literal_bytes<'a>(
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
            .checked_add(1)
            .ok_or(InspectionError::Overflow)?,
    )?;
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
    fn exact_shape_and_transparent_captures_are_eligible() {
        for (pattern, expected_captures) in [
            (r"(?m)^Sherlock Holmes|Sherlock Holmes$", 0),
            (r"(?m)(^(Sherlock Holmes))|((Sherlock Holmes)$)", 4),
        ] {
            let hir = parse(pattern, true);
            let InspectionOutcome::Eligible(inspection) = inspect(&hir, usize::MAX).unwrap() else {
                panic!("expected eligible literal assertions: {pattern}");
            };
            assert_eq!(inspection.literal, b"Sherlock Holmes");
            assert_eq!(inspection.hir_nodes, count(&hir));
            assert_eq!(inspection.captures, expected_captures);
        }
    }

    #[test]
    fn nearby_shapes_remain_ineligible() {
        for pattern in [
            r"Sherlock Holmes",
            r"(?m)^Sherlock Holmes",
            r"(?m)Sherlock Holmes$",
            r"(?m)Sherlock Holmes$|^Sherlock Holmes",
            r"(?m)^Sherlock|Holmes$",
            r"(?m)\ASherlock Holmes|Sherlock Holmes\z",
            r"(?m)^Sherlock Holmes|Sherlock Holmes$|Watson",
            r"(?m)^|$",
        ] {
            assert!(
                matches!(
                    inspect(&parse(pattern, false), usize::MAX).unwrap(),
                    InspectionOutcome::Ineligible { .. }
                ),
                "unexpected eligibility for {pattern}"
            );
        }
    }

    #[test]
    fn planner_limit_is_exact() {
        let hir = parse(r"(?m)^Sherlock Holmes|Sherlock Holmes$", true);
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
