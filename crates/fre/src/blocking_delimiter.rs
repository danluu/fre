//! Allocation-free structural admission for `D [^D]{0,N} T D`.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "planner resource arithmetic is checked; bitmap shifts use proved 0..=63 operands"
)]

use regex_syntax::hir::{Class, ClassBytes, Hir, HirKind};

#[derive(Clone, Copy, Debug)]
pub(super) struct Inspection {
    pub delimiters: [u8; 2],
    pub terminal_words: [u64; 4],
    pub terminal_members: usize,
    pub maximum_middle_bytes: usize,
    pub work: usize,
    pub hir_nodes: usize,
    pub captures: usize,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum InspectionOutcome {
    Eligible(Inspection),
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

    const fn ineligible(&self) -> InspectionOutcome {
        InspectionOutcome::Ineligible { work: self.work }
    }
}

/// Prove exactly two shared delimiters, their complete complement as a greedy
/// bounded byte repetition, a nonempty terminal byte class disjoint from the
/// delimiters, and the same closing delimiter class.
pub(super) fn inspect(hir: &Hir, limit: usize) -> Result<InspectionOutcome, InspectionError> {
    let mut accounting = Accounting::default();
    let root = peel_captures(hir, limit, &mut accounting)?;
    let HirKind::Concat(parts) = root.kind() else {
        return Ok(accounting.ineligible());
    };
    accounting.charge(parts.len(), limit)?;
    let [opening, middle, terminal, closing] = parts.as_slice() else {
        return Ok(accounting.ineligible());
    };

    let Some(delimiters) = two_singleton_bytes(opening, limit, &mut accounting)? else {
        return Ok(accounting.ineligible());
    };

    let middle = peel_captures(middle, limit, &mut accounting)?;
    let HirKind::Repetition(repetition) = middle.kind() else {
        return Ok(accounting.ineligible());
    };
    accounting.charge(3, limit)?;
    let Some(maximum) = repetition.max else {
        return Ok(accounting.ineligible());
    };
    if repetition.min != 0 || maximum == 0 || !repetition.greedy {
        return Ok(accounting.ineligible());
    }
    let maximum_middle_bytes = usize::try_from(maximum).map_err(|_| InspectionError::Overflow)?;
    let repeated = peel_captures(&repetition.sub, limit, &mut accounting)?;
    let HirKind::Class(Class::Bytes(repeated)) = repeated.kind() else {
        return Ok(accounting.ineligible());
    };
    accounting.charge(repeated.ranges().len(), limit)?;
    if !is_complete_delimiter_complement(repeated, delimiters, limit, &mut accounting)? {
        return Ok(accounting.ineligible());
    }

    let terminal = peel_captures(terminal, limit, &mut accounting)?;
    let HirKind::Class(Class::Bytes(terminal)) = terminal.kind() else {
        return Ok(accounting.ineligible());
    };
    let Some((terminal_words, terminal_members)) =
        byte_class_words(terminal, limit, &mut accounting)?
    else {
        return Ok(accounting.ineligible());
    };
    for delimiter in delimiters {
        accounting.charge(1, limit)?;
        if words_contain(terminal_words, delimiter) {
            return Ok(accounting.ineligible());
        }
    }

    let Some(closing_delimiters) = two_singleton_bytes(closing, limit, &mut accounting)? else {
        return Ok(accounting.ineligible());
    };
    accounting.charge(delimiters.len(), limit)?;
    if delimiters != closing_delimiters {
        return Ok(accounting.ineligible());
    }

    Ok(InspectionOutcome::Eligible(Inspection {
        delimiters,
        terminal_words,
        terminal_members,
        maximum_middle_bytes,
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

fn two_singleton_bytes(
    hir: &Hir,
    limit: usize,
    accounting: &mut Accounting,
) -> Result<Option<[u8; 2]>, InspectionError> {
    let hir = peel_captures(hir, limit, accounting)?;
    let HirKind::Class(Class::Bytes(class)) = hir.kind() else {
        return Ok(None);
    };
    accounting.charge(class.ranges().len(), limit)?;
    let [first, second] = class.ranges() else {
        return Ok(None);
    };
    accounting.charge(2, limit)?;
    if first.start() != first.end()
        || second.start() != second.end()
        || first.start() >= second.start()
    {
        return Ok(None);
    }
    Ok(Some([first.start(), second.start()]))
}

fn is_complete_delimiter_complement(
    class: &ClassBytes,
    delimiters: [u8; 2],
    limit: usize,
    accounting: &mut Accounting,
) -> Result<bool, InspectionError> {
    for byte in u8::MIN..=u8::MAX {
        accounting.charge(1, limit)?;
        let expected = byte != delimiters[0] && byte != delimiters[1];
        if class_contains(class, byte, limit, accounting)? != expected {
            return Ok(false);
        }
    }
    Ok(true)
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

fn byte_class_words(
    class: &ClassBytes,
    limit: usize,
    accounting: &mut Accounting,
) -> Result<Option<([u64; 4], usize)>, InspectionError> {
    accounting.charge(class.ranges().len(), limit)?;
    if class.ranges().is_empty() {
        return Ok(None);
    }
    let mut words = [0_u64; 4];
    let mut members = 0_usize;
    for range in class.ranges() {
        for byte in range.start()..=range.end() {
            accounting.charge(1, limit)?;
            members = members.checked_add(1).ok_or(InspectionError::Overflow)?;
            let word = usize::from(byte >> 6);
            let bit = u32::from(byte & 63);
            let mask = 1_u64.checked_shl(bit).ok_or(InspectionError::Overflow)?;
            let slot = words.get_mut(word).ok_or(InspectionError::Overflow)?;
            *slot |= mask;
        }
    }
    Ok(Some((words, members)))
}

fn words_contain(words: [u64; 4], byte: u8) -> bool {
    let word = usize::from(byte >> 6);
    let bit = u32::from(byte & 63);
    words
        .get(word)
        .is_some_and(|bits| bits & (1_u64 << bit) != 0)
}

#[cfg(test)]
mod tests {
    use regex_syntax::ParserBuilder;

    use super::{InspectionError, InspectionOutcome, inspect};

    const TARGET: &str = r#"["'][^"']{0,30}[?!.]["']"#;

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
        for (pattern, captures) in [
            (TARGET, 0),
            (r#"((["']))(([^"']{0,30}))(([?!.]))((["']))"#, 8),
        ] {
            let hir = parse(pattern, false);
            let InspectionOutcome::Eligible(inspection) = inspect(&hir, usize::MAX).unwrap() else {
                panic!("expected blocking-delimiter eligibility for {pattern:?}");
            };
            assert_eq!(inspection.delimiters, [b'"', b'\'']);
            assert_eq!(inspection.maximum_middle_bytes, 30);
            assert_eq!(inspection.terminal_members, 3);
            assert_eq!(inspection.captures, captures);
            assert_eq!(inspection.hir_nodes, node_count(&hir));
        }
    }

    #[test]
    fn every_semantic_perturbation_remains_ineligible() {
        for (pattern, unicode) in [
            (r#"["'][^"']{0,30}?[?!.]["']"#, false),
            (r#"["'][^"']{1,30}[?!.]["']"#, false),
            (r#"["'][^"']*[?!.]["']"#, false),
            (r#"["'][^"']{0,30}[?!.]["]"#, false),
            (r#"["'][^']{0,30}[?!.]["']"#, false),
            (r#"["'][^"']{0,30}["!.]["']"#, false),
            (TARGET, true),
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
        let hir = parse(TARGET, false);
        let InspectionOutcome::Eligible(baseline) = inspect(&hir, usize::MAX).unwrap() else {
            panic!("target must be eligible");
        };
        assert!(matches!(
            inspect(&hir, baseline.work - 1),
            Err(InspectionError::WorkLimit { needed, limit })
                if needed == baseline.work && limit == baseline.work - 1
        ));
        let InspectionOutcome::Eligible(exact) = inspect(&hir, baseline.work).unwrap() else {
            panic!("exact planner limit must admit");
        };
        assert_eq!(exact.work, baseline.work);
    }

    fn node_count(hir: &regex_syntax::hir::Hir) -> usize {
        let descendants = match hir.kind() {
            regex_syntax::hir::HirKind::Capture(capture) => node_count(&capture.sub),
            regex_syntax::hir::HirKind::Concat(parts)
            | regex_syntax::hir::HirKind::Alternation(parts) => parts.iter().map(node_count).sum(),
            regex_syntax::hir::HirKind::Repetition(repetition) => node_count(&repetition.sub),
            _ => 0,
        };
        descendants
            .checked_add(1)
            .expect("test HIR node count must fit usize")
    }
}
