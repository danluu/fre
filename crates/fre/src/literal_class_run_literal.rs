//! Allocation-free structural admission for `LITERAL BYTE_CLASS+ LITERAL`.

use regex_syntax::hir::{Class, ClassBytes, Hir, HirKind};

#[derive(Clone, Copy, Debug)]
pub(super) struct Inspection<'a> {
    pub prefix: &'a [u8],
    pub class: &'a ClassBytes,
    pub suffix: &'a [u8],
    pub work: usize,
    pub hir_nodes: usize,
    pub captures: usize,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum InspectionOutcome<'a> {
    Eligible(Inspection<'a>),
    Ineligible { work: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InspectionError {
    WorkLimit { needed: usize, limit: usize },
    Overflow,
}

#[derive(Default)]
struct Accounting {
    work: usize,
    hir_nodes: usize,
    captures: usize,
}

impl Accounting {
    fn charge(&mut self, units: usize, limit: usize) -> Result<(), InspectionError> {
        let needed = self
            .work
            .checked_add(units)
            .ok_or(InspectionError::Overflow)?;
        if needed > limit {
            return Err(InspectionError::WorkLimit { needed, limit });
        }
        self.work = needed;
        Ok(())
    }

    fn visit(&mut self, limit: usize) -> Result<(), InspectionError> {
        self.charge(1, limit)?;
        self.hir_nodes = self
            .hir_nodes
            .checked_add(1)
            .ok_or(InspectionError::Overflow)?;
        Ok(())
    }

    const fn ineligible(&self) -> InspectionOutcome<'static> {
        InspectionOutcome::Ineligible { work: self.work }
    }
}

/// Recognize exactly one canonical byte concat `L C+ R`, treating captures as
/// transparent because the aggregate facade exposes whole-match values only.
/// Every node, literal byte, range, repetition-role check and boundary
/// membership comparison is charged before it is inspected.
pub(super) fn inspect(hir: &Hir, limit: usize) -> Result<InspectionOutcome<'_>, InspectionError> {
    let mut accounting = Accounting::default();
    let root = peel_captures(hir, limit, &mut accounting)?;
    let HirKind::Concat(parts) = root.kind() else {
        return Ok(accounting.ineligible());
    };
    accounting.charge(parts.len(), limit)?;
    let [prefix_hir, repeated_hir, suffix_hir] = parts.as_slice() else {
        return Ok(accounting.ineligible());
    };

    let prefix_hir = peel_captures(prefix_hir, limit, &mut accounting)?;
    let HirKind::Literal(prefix) = prefix_hir.kind() else {
        return Ok(accounting.ineligible());
    };
    accounting.charge(prefix.0.len(), limit)?;
    if prefix.0.is_empty() {
        return Ok(accounting.ineligible());
    }

    let repeated_hir = peel_captures(repeated_hir, limit, &mut accounting)?;
    let HirKind::Repetition(repetition) = repeated_hir.kind() else {
        return Ok(accounting.ineligible());
    };
    accounting.charge(3, limit)?;
    if repetition.min != 1 || repetition.max.is_some() || !repetition.greedy {
        return Ok(accounting.ineligible());
    }
    let class_hir = peel_captures(&repetition.sub, limit, &mut accounting)?;
    let HirKind::Class(Class::Bytes(class)) = class_hir.kind() else {
        return Ok(accounting.ineligible());
    };
    accounting.charge(class.ranges().len(), limit)?;
    if class.ranges().is_empty() {
        return Ok(accounting.ineligible());
    }

    let suffix_hir = peel_captures(suffix_hir, limit, &mut accounting)?;
    let HirKind::Literal(suffix) = suffix_hir.kind() else {
        return Ok(accounting.ineligible());
    };
    accounting.charge(suffix.0.len(), limit)?;
    if suffix.0.is_empty() {
        return Ok(accounting.ineligible());
    }

    let prefix_last = *prefix.0.last().ok_or(InspectionError::Overflow)?;
    let suffix_first = *suffix.0.first().ok_or(InspectionError::Overflow)?;
    if class_contains(class, prefix_last, limit, &mut accounting)?
        || class_contains(class, suffix_first, limit, &mut accounting)?
    {
        return Ok(accounting.ineligible());
    }

    Ok(InspectionOutcome::Eligible(Inspection {
        prefix: &prefix.0,
        class,
        suffix: &suffix.0,
        work: accounting.work,
        hir_nodes: accounting.hir_nodes,
        captures: accounting.captures,
    }))
}

fn peel_captures<'a>(
    mut hir: &'a Hir,
    limit: usize,
    accounting: &mut Accounting,
) -> Result<&'a Hir, InspectionError> {
    loop {
        accounting.visit(limit)?;
        let HirKind::Capture(capture) = hir.kind() else {
            return Ok(hir);
        };
        accounting.captures = accounting
            .captures
            .checked_add(1)
            .ok_or(InspectionError::Overflow)?;
        hir = &capture.sub;
    }
}

fn class_contains(
    class: &ClassBytes,
    byte: u8,
    limit: usize,
    accounting: &mut Accounting,
) -> Result<bool, InspectionError> {
    for range in class.ranges() {
        accounting.charge(1, limit)?;
        if byte < range.start() {
            return Ok(false);
        }
        if byte <= range.end() {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use regex_syntax::ParserBuilder;

    use super::*;

    fn hir(pattern: &str) -> Hir {
        ParserBuilder::new()
            .unicode(false)
            .build()
            .parse(pattern)
            .unwrap()
    }

    #[test]
    fn admits_exact_shape_and_transparent_captures() {
        for pattern in [r"Sherlock\s+Holmes", r"((ab))([ \t]+)((cd))"] {
            let parsed = hir(pattern);
            let InspectionOutcome::Eligible(inspection) = inspect(&parsed, usize::MAX).unwrap()
            else {
                panic!("expected eligibility for {pattern:?}");
            };
            assert!(!inspection.prefix.is_empty());
            assert!(!inspection.suffix.is_empty());
            assert!(!inspection.class.ranges().is_empty());
            assert!(inspection.hir_nodes >= 5);
        }
    }

    #[test]
    fn refuses_every_semantic_perturbation() {
        for pattern in [
            r"ab[ ]*cd",
            r"ab[ ]+?cd",
            r"ab[ ]{1,3}cd",
            r"ab[ ]cd",
            r"[ ]+cd",
            r"ab[ ]+",
            r"ab[ ]+cd|xy[ ]+zz",
            r"a[ab]+c",
            r"a[bc]+b",
            r"ab(?:[ ]|\t)+cd",
        ] {
            assert!(matches!(
                inspect(&hir(pattern), usize::MAX).unwrap(),
                InspectionOutcome::Ineligible { .. }
            ));
        }
    }

    #[test]
    fn planner_work_exact_and_one_below() {
        let hir = hir(r"((Sherlock))(\s+)((Holmes))");
        let InspectionOutcome::Eligible(baseline) = inspect(&hir, usize::MAX).unwrap() else {
            panic!("baseline should be eligible");
        };
        assert!(baseline.work > 0);
        let InspectionOutcome::Eligible(exact) = inspect(&hir, baseline.work).unwrap() else {
            panic!("exact work limit should admit");
        };
        assert_eq!(exact.work, baseline.work);
        assert_eq!(exact.hir_nodes, baseline.hir_nodes);
        assert_eq!(exact.captures, baseline.captures);
        assert!(matches!(
            inspect(&hir, baseline.work - 1),
            Err(InspectionError::WorkLimit { needed, limit })
                if needed == baseline.work && limit == baseline.work - 1
        ));
    }
}
