//! Allocation-free structural admission for canonical one-byte-class runs.
//! The reduction route retains strict `LITERAL? CLASS+ LITERAL?` invariants;
//! the search-only route additionally admits a nonempty prefix before
//! `CLASS*`, prefix/class overlap, singleton literal repetitions, and
//! `\b ASCII_WORD_SUBSET+ WORD_SUFFIX \b`.

use fre_kernels::{
    LiteralClassRunLiteralBoundarySemantics as BoundarySemantics,
    LiteralClassRunSearchMinimum as SearchRunMinimum,
};
use regex_syntax::hir::{Class, ClassBytes, Hir, HirKind, Look};

use crate::aggregate_construction::AggregateInspectionAttemptError;

const ASCII_WORD_RANGES: [(u8, u8); 4] = [(b'0', b'9'), (b'A', b'Z'), (b'_', b'_'), (b'a', b'z')];

#[derive(Clone, Copy, Debug)]
pub(super) struct Inspection<'a> {
    pub prefix: &'a [u8],
    pub class: InspectedClass<'a>,
    pub suffix: &'a [u8],
    pub minimum: SearchRunMinimum,
    pub boundary_semantics: BoundarySemantics,
    pub generalized_search: bool,
    pub work: usize,
    pub hir_nodes: usize,
    pub captures: usize,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum InspectedClass<'a> {
    Bytes(&'a ClassBytes),
    Singleton(u8),
}

impl InspectedClass<'_> {
    pub(super) fn range_count(self) -> usize {
        match self {
            Self::Bytes(class) => class.ranges().len(),
            Self::Singleton(_) => 1,
        }
    }
}

pub(super) struct InspectedClassRanges<'a> {
    class: InspectedClass<'a>,
    index: usize,
}

impl<'a> InspectedClass<'a> {
    pub(super) const fn ranges(self) -> InspectedClassRanges<'a> {
        InspectedClassRanges {
            class: self,
            index: 0,
        }
    }
}

impl Iterator for InspectedClassRanges<'_> {
    type Item = (u8, u8);

    fn next(&mut self) -> Option<Self::Item> {
        let range = match self.class {
            InspectedClass::Bytes(class) => {
                let range = class.ranges().get(self.index)?;
                (range.start(), range.end())
            }
            InspectedClass::Singleton(byte) if self.index == 0 => (byte, byte),
            InspectedClass::Singleton(_) => return None,
        };
        self.index += 1;
        Some(range)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.class.range_count().saturating_sub(self.index);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for InspectedClassRanges<'_> {}

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

/// Recognize a canonical byte concat `L C{0,} R?`, `L? C+ R?`, or
/// `WordAscii ASCII_WORD_SUBSET+ S WordAscii`. The aggregate facade consumes
/// only the strict reduction-compatible subset; search may consume every
/// admitted shape. Captures are transparent because both facades expose
/// whole-match values only. Every node, literal byte, range, repetition-role
/// check and boundary comparison is charged before it is inspected.
pub(super) fn inspect(hir: &Hir, limit: usize) -> Result<InspectionOutcome<'_>, InspectionError> {
    inspect_attempt(hir, limit).map_err(AggregateInspectionAttemptError::into_source)
}

pub(super) fn inspect_attempt(
    hir: &Hir,
    limit: usize,
) -> Result<InspectionOutcome<'_>, AggregateInspectionAttemptError<InspectionError>> {
    let mut accounting = Accounting::default();
    inspect_with_accounting(hir, limit, &mut accounting)
        .map_err(|source| AggregateInspectionAttemptError::new(source, accounting.work))
}

#[allow(
    clippy::too_many_lines,
    reason = "the combined structural admission keeps charged one-sided and guarded concat dispatch adjacent to their shared proof"
)]
fn inspect_with_accounting<'a>(
    hir: &'a Hir,
    limit: usize,
    accounting: &mut Accounting,
) -> Result<InspectionOutcome<'a>, InspectionError> {
    let root = peel_captures(hir, limit, accounting)?;
    let HirKind::Concat(parts) = root.kind() else {
        return Ok(accounting.ineligible());
    };
    accounting.charge(parts.len(), limit)?;
    let empty: &'a [u8] = &[];
    let (prefix, repeated_hir, suffix) = match parts.as_slice() {
        [first_hir, second_hir] => {
            let first_hir = peel_captures(first_hir, limit, accounting)?;
            let second_hir = peel_captures(second_hir, limit, accounting)?;
            match (first_hir.kind(), second_hir.kind()) {
                (HirKind::Literal(prefix), HirKind::Repetition(_)) => {
                    accounting.charge(prefix.0.len(), limit)?;
                    if prefix.0.is_empty() {
                        return Ok(accounting.ineligible());
                    }
                    (&prefix.0[..], second_hir, empty)
                }
                (HirKind::Repetition(_), HirKind::Literal(suffix)) => {
                    accounting.charge(suffix.0.len(), limit)?;
                    if suffix.0.is_empty() {
                        return Ok(accounting.ineligible());
                    }
                    (empty, first_hir, &suffix.0[..])
                }
                _ => return Ok(accounting.ineligible()),
            }
        }
        [prefix_hir, repeated_hir, suffix_hir] => {
            let prefix_hir = peel_captures(prefix_hir, limit, accounting)?;
            let repeated_hir = peel_captures(repeated_hir, limit, accounting)?;
            let suffix_hir = peel_captures(suffix_hir, limit, accounting)?;
            let HirKind::Literal(prefix) = prefix_hir.kind() else {
                return Ok(accounting.ineligible());
            };
            accounting.charge(prefix.0.len(), limit)?;
            if prefix.0.is_empty() {
                return Ok(accounting.ineligible());
            }
            let HirKind::Literal(suffix) = suffix_hir.kind() else {
                return Ok(accounting.ineligible());
            };
            accounting.charge(suffix.0.len(), limit)?;
            if suffix.0.is_empty() {
                return Ok(accounting.ineligible());
            }
            (&prefix.0[..], repeated_hir, &suffix.0[..])
        }
        [left_hir, repeated_hir, suffix_hir, right_hir] => {
            return inspect_complete_ascii_word_run(
                left_hir,
                repeated_hir,
                suffix_hir,
                right_hir,
                limit,
                accounting,
            );
        }
        _ => return Ok(accounting.ineligible()),
    };

    let HirKind::Repetition(repetition) = repeated_hir.kind() else {
        return Ok(accounting.ineligible());
    };
    accounting.charge(3, limit)?;
    let minimum = match repetition.min {
        0 => SearchRunMinimum::Zero,
        1 => SearchRunMinimum::One,
        _ => return Ok(accounting.ineligible()),
    };
    if repetition.max.is_some() || !repetition.greedy {
        return Ok(accounting.ineligible());
    }
    if minimum == SearchRunMinimum::Zero && prefix.is_empty() {
        return Ok(accounting.ineligible());
    }
    let Some(class) = repeated_byte_class(&repetition.sub, limit, accounting)? else {
        return Ok(accounting.ineligible());
    };

    let mut generalized_search = minimum == SearchRunMinimum::Zero;
    if let Some(&prefix_last) = prefix.last()
        && class_contains(class, prefix_last, limit, accounting)?
    {
        generalized_search = true;
    }
    if let Some(&suffix_first) = suffix.first()
        && class_contains(class, suffix_first, limit, accounting)?
    {
        if !prefix.is_empty() {
            return Ok(accounting.ineligible());
        }
        for &byte in suffix.iter().skip(1) {
            if !class_contains(class, byte, limit, accounting)? {
                return Ok(accounting.ineligible());
            }
        }
    }

    Ok(InspectionOutcome::Eligible(Inspection {
        prefix,
        class,
        suffix,
        minimum,
        boundary_semantics: BoundarySemantics::Unguarded,
        generalized_search,
        work: accounting.work,
        hir_nodes: accounting.hir_nodes,
        captures: accounting.captures,
    }))
}

fn inspect_complete_ascii_word_run<'a>(
    left_hir: &'a Hir,
    repeated_hir: &'a Hir,
    suffix_hir: &'a Hir,
    right_hir: &'a Hir,
    limit: usize,
    accounting: &mut Accounting,
) -> Result<InspectionOutcome<'a>, InspectionError> {
    if !ascii_word_boundary(left_hir, limit, accounting)?
        || !ascii_word_boundary(right_hir, limit, accounting)?
    {
        return Ok(accounting.ineligible());
    }
    let Some((class, minimum)) = greedy_unbounded_repeated_class(repeated_hir, limit, accounting)?
    else {
        return Ok(accounting.ineligible());
    };
    if minimum != SearchRunMinimum::One || !ascii_word_subset_class(class, limit, accounting)? {
        return Ok(accounting.ineligible());
    }
    let generalized_search = !exact_ascii_word_class(class, limit, accounting)?;

    let suffix_hir = peel_captures(suffix_hir, limit, accounting)?;
    let HirKind::Literal(suffix) = suffix_hir.kind() else {
        return Ok(accounting.ineligible());
    };
    accounting.charge(suffix.0.len(), limit)?;
    if suffix.0.is_empty() {
        return Ok(accounting.ineligible());
    }
    for &byte in &suffix.0 {
        accounting.charge(1, limit)?;
        if !is_ascii_word(byte) {
            return Ok(accounting.ineligible());
        }
    }

    Ok(InspectionOutcome::Eligible(Inspection {
        prefix: &[],
        class,
        suffix: &suffix.0,
        minimum,
        boundary_semantics: BoundarySemantics::CompleteAsciiWordRun,
        generalized_search,
        work: accounting.work,
        hir_nodes: accounting.hir_nodes,
        captures: accounting.captures,
    }))
}

fn ascii_word_boundary(
    hir: &Hir,
    limit: usize,
    accounting: &mut Accounting,
) -> Result<bool, InspectionError> {
    let hir = peel_captures(hir, limit, accounting)?;
    accounting.charge(1, limit)?;
    Ok(matches!(hir.kind(), HirKind::Look(Look::WordAscii)))
}

fn greedy_unbounded_repeated_class<'a>(
    hir: &'a Hir,
    limit: usize,
    accounting: &mut Accounting,
) -> Result<Option<(InspectedClass<'a>, SearchRunMinimum)>, InspectionError> {
    let hir = peel_captures(hir, limit, accounting)?;
    let HirKind::Repetition(repetition) = hir.kind() else {
        return Ok(None);
    };
    accounting.charge(3, limit)?;
    let minimum = match repetition.min {
        0 => SearchRunMinimum::Zero,
        1 => SearchRunMinimum::One,
        _ => return Ok(None),
    };
    if repetition.max.is_some() || !repetition.greedy {
        return Ok(None);
    }
    Ok(repeated_byte_class(&repetition.sub, limit, accounting)?.map(|class| (class, minimum)))
}

fn exact_ascii_word_class(
    class: InspectedClass<'_>,
    limit: usize,
    accounting: &mut Accounting,
) -> Result<bool, InspectionError> {
    accounting.charge(1, limit)?;
    let InspectedClass::Bytes(class) = class else {
        return Ok(false);
    };
    if class.ranges().len() != ASCII_WORD_RANGES.len() {
        return Ok(false);
    }
    for (range, (start, end)) in class.ranges().iter().zip(ASCII_WORD_RANGES) {
        accounting.charge(2, limit)?;
        if range.start() != start || range.end() != end {
            return Ok(false);
        }
    }
    Ok(true)
}

fn ascii_word_subset_class(
    class: InspectedClass<'_>,
    limit: usize,
    accounting: &mut Accounting,
) -> Result<bool, InspectionError> {
    match class {
        InspectedClass::Singleton(byte) => {
            accounting.charge(1, limit)?;
            Ok(is_ascii_word(byte))
        }
        InspectedClass::Bytes(class) => {
            for range in class.ranges() {
                accounting.charge(2, limit)?;
                for byte in range.start()..=range.end() {
                    accounting.charge(1, limit)?;
                    if !is_ascii_word(byte) {
                        return Ok(false);
                    }
                }
            }
            Ok(true)
        }
    }
}

fn repeated_byte_class<'a>(
    hir: &'a Hir,
    limit: usize,
    accounting: &mut Accounting,
) -> Result<Option<InspectedClass<'a>>, InspectionError> {
    let hir = peel_captures(hir, limit, accounting)?;
    match hir.kind() {
        HirKind::Class(Class::Bytes(class)) => {
            accounting.charge(class.ranges().len(), limit)?;
            Ok((!class.ranges().is_empty()).then_some(InspectedClass::Bytes(class)))
        }
        HirKind::Literal(literal) if literal.0.len() == 1 => {
            accounting.charge(1, limit)?;
            Ok(Some(InspectedClass::Singleton(literal.0[0])))
        }
        HirKind::Empty
        | HirKind::Literal(_)
        | HirKind::Class(_)
        | HirKind::Look(_)
        | HirKind::Repetition(_)
        | HirKind::Capture(_)
        | HirKind::Concat(_)
        | HirKind::Alternation(_) => Ok(None),
    }
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
    class: InspectedClass<'_>,
    byte: u8,
    limit: usize,
    accounting: &mut Accounting,
) -> Result<bool, InspectionError> {
    match class {
        InspectedClass::Singleton(member) => {
            accounting.charge(1, limit)?;
            Ok(byte == member)
        }
        InspectedClass::Bytes(class) => {
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
    }
}

const fn is_ascii_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

#[cfg(test)]
mod tests {
    use regex_syntax::ParserBuilder;

    use super::*;

    fn hir(pattern: &str) -> Hir {
        ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(pattern)
            .unwrap()
    }

    #[test]
    fn admits_exact_shape_and_transparent_captures() {
        for pattern in [
            r"Sherlock\s+Holmes",
            r"((ab))([ \t]+)((cd))",
            r"[a-zA-Z]+ing",
            r"item[0-9]+",
            r"[0-9]+X5",
        ] {
            let parsed = hir(pattern);
            let InspectionOutcome::Eligible(inspection) = inspect(&parsed, usize::MAX).unwrap()
            else {
                panic!("expected eligibility for {pattern:?}");
            };
            assert!(!inspection.prefix.is_empty() || !inspection.suffix.is_empty());
            assert!(inspection.class.range_count() > 0);
            assert_eq!(inspection.minimum, SearchRunMinimum::One);
            assert_eq!(inspection.boundary_semantics, BoundarySemantics::Unguarded);
            assert!(inspection.hir_nodes >= 4);
        }
    }

    #[test]
    fn admits_complete_ascii_word_suffix_shape_and_transparent_captures() {
        for (pattern, suffix) in [
            (r"\b\w+n\b", b"n".as_slice()),
            (r"(\b)(\w+)((nn))(\b)", b"nn".as_slice()),
        ] {
            let parsed = hir(pattern);
            let InspectionOutcome::Eligible(inspection) = inspect(&parsed, usize::MAX).unwrap()
            else {
                panic!("expected guarded eligibility for {pattern:?}");
            };
            assert!(inspection.prefix.is_empty());
            assert_eq!(inspection.suffix, suffix);
            assert_eq!(
                inspection.boundary_semantics,
                BoundarySemantics::CompleteAsciiWordRun
            );
            assert_eq!(inspection.class.range_count(), ASCII_WORD_RANGES.len());
            assert!(!inspection.generalized_search);
        }
    }

    #[test]
    fn admits_singleton_star_overlap_and_ascii_word_subset_shapes() {
        for (pattern, minimum, guarded) in [
            (r"ab+c", SearchRunMinimum::One, false),
            (r"a[^z\r\n]*z", SearchRunMinimum::Zero, false),
            (r"a[ab]+c", SearchRunMinimum::One, false),
            (r"\b[A-Za-z]+TRAILER\b", SearchRunMinimum::One, true),
        ] {
            let parsed = hir(pattern);
            let InspectionOutcome::Eligible(inspection) = inspect(&parsed, usize::MAX).unwrap()
            else {
                panic!("expected generalized eligibility for {pattern:?}");
            };
            assert_eq!(inspection.minimum, minimum, "{pattern:?}");
            assert_eq!(
                inspection.boundary_semantics == BoundarySemantics::CompleteAsciiWordRun,
                guarded,
                "{pattern:?}"
            );
            if pattern != r"ab+c" {
                assert!(inspection.generalized_search, "{pattern:?}");
            }
        }
    }

    #[test]
    fn refuses_every_semantic_perturbation() {
        for pattern in [
            r"ab[ ]+?cd",
            r"ab[ ]{1,3}cd",
            r"ab[ ]cd",
            r"ab[ ]+cd|xy[ ]+zz",
            r"a[bc]+b",
            r"ab(?:[ ]|\t)+cd",
            r"\B\w+n\b",
            r"\b\w+n\B",
            r"\b\w+?n\b",
            r"\b\w{1,3}n\b",
            r"\b\w+n-\b",
            r"\b\w+\x7F\b",
            r"\b\w+\b",
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
