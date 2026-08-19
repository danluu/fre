//! Allocation-free structural admission for canonical one-byte-class runs.
//! The reduction route retains strict `LITERAL? CLASS+ LITERAL?` invariants;
//! the search-only route additionally admits a nonempty prefix before
//! `CLASS*`, prefix/class overlap, singleton literal repetitions,
//! `\b ASCII_WORD_SUBSET+ WORD_SUFFIX \b`, and defers exact two-barrier
//! `LITERAL CLASS{m,n} LITERAL` shapes for a later native-plan choice.

use fre_kernels::{
    BoundedLiteralClassRunPlan,
    LiteralClassRunLiteralBoundarySemantics as BoundarySemantics,
    LiteralClassRunLiteralBuildError, LiteralClassRunLiteralBuildLimits,
    LiteralClassRunSearchMinimum as SearchRunMinimum,
    SimdDispatchContext,
};
use regex_syntax::hir::{Class, ClassBytes, ClassUnicode, ClassUnicodeRange, Hir, HirKind, Look};

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
pub(super) struct FiniteInspection<'a> {
    prefix: &'a [u8],
    class: InspectedClass<'a>,
    suffix: &'a [u8],
    minimum: usize,
    maximum: usize,
}

impl FiniteInspection<'_> {
    pub(super) fn build(
        self,
        dispatch: SimdDispatchContext,
        limits: LiteralClassRunLiteralBuildLimits,
    ) -> Result<Option<BoundedLiteralClassRunPlan>, LiteralClassRunLiteralBuildError> {
        BoundedLiteralClassRunPlan::build_with_dispatch_if_admitted(
            dispatch,
            self.prefix,
            self.class.ranges(),
            self.suffix,
            self.minimum,
            self.maximum,
            limits,
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum InspectedClass<'a> {
    Bytes(&'a ClassBytes),
    Singleton(u8),
    UnicodeAllNonAscii(&'a ClassUnicode),
}

impl<'a> InspectedClass<'a> {
    pub(super) fn range_count(self) -> usize {
        match self {
            Self::Bytes(class) => class.ranges().len(),
            Self::Singleton(_) => 1,
            Self::UnicodeAllNonAscii(class) => class
                .ranges()
                .iter()
                .take_while(|range| range.start().is_ascii())
                .count(),
        }
    }

    pub(super) const fn is_unicode_all_non_ascii(self) -> bool {
        matches!(self, Self::UnicodeAllNonAscii(_))
    }

    pub(super) fn unicode_ranges(self) -> Option<&'a [ClassUnicodeRange]> {
        match self {
            Self::UnicodeAllNonAscii(class) => Some(class.ranges()),
            Self::Bytes(_) | Self::Singleton(_) => None,
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
            InspectedClass::UnicodeAllNonAscii(class) => {
                let range = class.ranges().get(self.index)?;
                if !range.start().is_ascii() {
                    return None;
                }
                (
                    u8::try_from(u32::from(range.start()))
                        .expect("proved ASCII Unicode range start"),
                    u8::try_from(u32::from(range.end().min('\u{7F}')))
                        .expect("clamped Unicode range end is ASCII"),
                )
            }
        };
        self.index = self
            .index
            .checked_add(1)
            .expect("range index is bounded by the inspected class");
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
    Ineligible {
        work: usize,
        finite: Option<FiniteInspection<'a>>,
    },
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
        InspectionOutcome::Ineligible {
            work: self.work,
            finite: None,
        }
    }
}

/// Recognize a canonical byte concat `L C{0,} R?`, `L? C+ R?`, or
/// `WordAscii ASCII_WORD_SUBSET+ S WordAscii`. The aggregate facade consumes
/// only the strict reduction-compatible subset; search may consume every
/// admitted shape. Captures are transparent because both facades expose
/// whole-match values only. Every node, literal byte, range, repetition-role
/// check and boundary comparison is charged before it is inspected.
pub(super) fn inspect(hir: &Hir, limit: usize) -> Result<InspectionOutcome<'_>, InspectionError> {
    let mut accounting = Accounting::default();
    inspect_with_accounting(hir, limit, &mut accounting, true)
}

pub(super) fn inspect_attempt(
    hir: &Hir,
    limit: usize,
) -> Result<InspectionOutcome<'_>, AggregateInspectionAttemptError<InspectionError>> {
    let mut accounting = Accounting::default();
    inspect_with_accounting(hir, limit, &mut accounting, false)
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
    defer_finite: bool,
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
            return inspect_four_part_run(
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
    if let Some(maximum) = repetition.max {
        if !defer_finite {
            return Ok(accounting.ineligible());
        }
        return inspect_finite_two_barrier_run(
            prefix,
            &repetition.sub,
            suffix,
            repetition.min,
            maximum,
            repetition.greedy,
            limit,
            accounting,
        );
    }
    let minimum = match repetition.min {
        0 => SearchRunMinimum::Zero,
        1 => SearchRunMinimum::One,
        _ => return Ok(accounting.ineligible()),
    };
    let lazy = !repetition.greedy;
    if lazy && (prefix.is_empty() || suffix.is_empty()) {
        return Ok(accounting.ineligible());
    }
    if minimum == SearchRunMinimum::Zero && prefix.is_empty() {
        return Ok(accounting.ineligible());
    }
    let Some(class) = repeated_class(&repetition.sub, limit, accounting)? else {
        return Ok(accounting.ineligible());
    };

    let inspection =
        finish_unbounded_inspection(prefix, class, suffix, minimum, lazy, accounting, limit)?;
    Ok(inspection.map_or_else(|| accounting.ineligible(), InspectionOutcome::Eligible))
}

fn inspect_four_part_run<'a>(
    left_hir: &'a Hir,
    second_hir: &'a Hir,
    third_hir: &'a Hir,
    right_hir: &'a Hir,
    limit: usize,
    accounting: &mut Accounting,
) -> Result<InspectionOutcome<'a>, InspectionError> {
    let left_hir = peel_captures(left_hir, limit, accounting)?;
    match left_hir.kind() {
        HirKind::Literal(prefix) => {
            let inspection = inspect_adjacent_same_class_run(
                &prefix.0, second_hir, third_hir, right_hir, limit, accounting,
            )?;
            Ok(inspection.map_or_else(|| accounting.ineligible(), InspectionOutcome::Eligible))
        }
        HirKind::Look(look) => {
            accounting.charge(1, limit)?;
            if *look != Look::WordAscii {
                return Ok(accounting.ineligible());
            }
            inspect_complete_ascii_word_run(second_hir, third_hir, right_hir, limit, accounting)
        }
        HirKind::Empty
        | HirKind::Class(_)
        | HirKind::Repetition(_)
        | HirKind::Capture(_)
        | HirKind::Concat(_)
        | HirKind::Alternation(_) => {
            accounting.charge(1, limit)?;
            Ok(accounting.ineligible())
        }
    }
}

/// Recognize the parser-preserved concat `L C C* R` when both class atoms
/// have exactly the same byte semantics. This is the canonical `L C+ R`
/// language with the same greedy boundary: the nonempty literal barriers and
/// the shared-class proof let the existing class-run owner consume it without
/// retaining a second runtime atom.
fn inspect_adjacent_same_class_run<'a>(
    prefix: &'a [u8],
    mandatory_hir: &'a Hir,
    repeated_hir: &'a Hir,
    suffix_hir: &'a Hir,
    limit: usize,
    accounting: &mut Accounting,
) -> Result<Option<Inspection<'a>>, InspectionError> {
    let mandatory_hir = peel_captures(mandatory_hir, limit, accounting)?;
    let repeated_hir = peel_captures(repeated_hir, limit, accounting)?;
    let suffix_hir = peel_captures(suffix_hir, limit, accounting)?;
    accounting.charge(prefix.len(), limit)?;
    if prefix.is_empty() {
        return Ok(None);
    }
    let HirKind::Literal(suffix) = suffix_hir.kind() else {
        return Ok(None);
    };
    accounting.charge(suffix.0.len(), limit)?;
    if suffix.0.is_empty() {
        return Ok(None);
    }
    let Some(mandatory_class) = repeated_class(mandatory_hir, limit, accounting)? else {
        return Ok(None);
    };
    let HirKind::Repetition(repetition) = repeated_hir.kind() else {
        return Ok(None);
    };
    accounting.charge(3, limit)?;
    if repetition.min != 0 || repetition.max.is_some() {
        return Ok(None);
    }
    let Some(repeated_class) = repeated_class(&repetition.sub, limit, accounting)? else {
        return Ok(None);
    };
    if !same_inspected_class(mandatory_class, repeated_class, limit, accounting)? {
        return Ok(None);
    }
    let lazy = !repetition.greedy;
    finish_unbounded_inspection(
        prefix,
        mandatory_class,
        &suffix.0,
        SearchRunMinimum::One,
        lazy,
        accounting,
        limit,
    )
}

fn same_inspected_class(
    left: InspectedClass<'_>,
    right: InspectedClass<'_>,
    limit: usize,
    accounting: &mut Accounting,
) -> Result<bool, InspectionError> {
    accounting.charge(2, limit)?;
    if left.is_unicode_all_non_ascii() != right.is_unicode_all_non_ascii()
        || left.range_count() != right.range_count()
    {
        return Ok(false);
    }
    for (left, right) in left.ranges().zip(right.ranges()) {
        accounting.charge(2, limit)?;
        if left != right {
            return Ok(false);
        }
    }
    Ok(true)
}

fn finish_unbounded_inspection<'a>(
    prefix: &'a [u8],
    class: InspectedClass<'a>,
    suffix: &'a [u8],
    minimum: SearchRunMinimum,
    lazy: bool,
    accounting: &mut Accounting,
    limit: usize,
) -> Result<Option<Inspection<'a>>, InspectionError> {
    if class.is_unicode_all_non_ascii() {
        accounting.charge(prefix.len(), limit)?;
        accounting.charge(suffix.len(), limit)?;
        if prefix.is_empty()
            || suffix.is_empty()
            || !prefix.iter().all(u8::is_ascii)
            || !suffix.iter().all(u8::is_ascii)
        {
            return Ok(None);
        }
    }

    let mut generalized_search =
        minimum == SearchRunMinimum::Zero || class.is_unicode_all_non_ascii() || lazy;
    if let Some(&prefix_last) = prefix.last()
        && class_contains(class, prefix_last, limit, accounting)?
    {
        generalized_search = true;
    }
    if let Some(&suffix_first) = suffix.first()
        && class_contains(class, suffix_first, limit, accounting)?
    {
        if !prefix.is_empty() {
            return Ok(None);
        }
        for &byte in suffix.iter().skip(1) {
            if !class_contains(class, byte, limit, accounting)? {
                return Ok(None);
            }
        }
    }

    Ok(Some(Inspection {
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

#[allow(
    clippy::too_many_arguments,
    reason = "the deferred finite proof retains the already-inspected exact HIR roles without a second traversal"
)]
fn inspect_finite_two_barrier_run<'a>(
    prefix: &'a [u8],
    repeated: &'a Hir,
    suffix: &'a [u8],
    minimum: u32,
    maximum: u32,
    greedy: bool,
    limit: usize,
    accounting: &mut Accounting,
) -> Result<InspectionOutcome<'a>, InspectionError> {
    if prefix.is_empty() || suffix.is_empty() || !greedy || maximum < minimum {
        return Ok(accounting.ineligible());
    }
    let minimum = usize::try_from(minimum).map_err(|_| InspectionError::Overflow)?;
    let maximum = usize::try_from(maximum).map_err(|_| InspectionError::Overflow)?;
    let Some(class) = repeated_class(repeated, limit, accounting)? else {
        return Ok(accounting.ineligible());
    };
    if class.is_unicode_all_non_ascii() {
        return Ok(accounting.ineligible());
    }
    accounting.charge(1, limit)?;
    if class_contains(
        class,
        *prefix.last().expect("nonempty finite prefix was checked"),
        limit,
        accounting,
    )? {
        return Ok(accounting.ineligible());
    }
    accounting.charge(1, limit)?;
    if class_contains(class, suffix[0], limit, accounting)? {
        return Ok(accounting.ineligible());
    }
    accounting.charge(1, limit)?;
    let fixed = prefix
        .len()
        .checked_add(suffix.len())
        .ok_or(InspectionError::Overflow)?;
    accounting.charge(1, limit)?;
    fixed
        .checked_add(maximum)
        .ok_or(InspectionError::Overflow)?;
    Ok(InspectionOutcome::Ineligible {
        work: accounting.work,
        finite: Some(FiniteInspection {
            prefix,
            class,
            suffix,
            minimum,
            maximum,
        }),
    })
}

fn inspect_complete_ascii_word_run<'a>(
    repeated_hir: &'a Hir,
    suffix_hir: &'a Hir,
    right_hir: &'a Hir,
    limit: usize,
    accounting: &mut Accounting,
) -> Result<InspectionOutcome<'a>, InspectionError> {
    if !ascii_word_boundary(right_hir, limit, accounting)? {
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
    Ok(repeated_class(&repetition.sub, limit, accounting)?.map(|class| (class, minimum)))
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
        InspectedClass::UnicodeAllNonAscii(_) => Ok(false),
    }
}

fn repeated_class<'a>(
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
        HirKind::Class(Class::Unicode(class))
            if unicode_class_contains_all_non_ascii(class, limit, accounting)? =>
        {
            Ok(Some(InspectedClass::UnicodeAllNonAscii(class)))
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

fn unicode_class_contains_all_non_ascii(
    class: &ClassUnicode,
    limit: usize,
    accounting: &mut Accounting,
) -> Result<bool, InspectionError> {
    let mut next_required = u32::from('\u{80}');
    let maximum = u32::from(char::MAX);
    for range in class.ranges() {
        accounting.charge(2, limit)?;
        let start = u32::from(range.start()).max(u32::from('\u{80}'));
        let end = u32::from(range.end());
        if end < next_required {
            continue;
        }
        if start > next_required {
            return Ok(false);
        }
        if end == maximum {
            return Ok(true);
        }
        next_required = end.checked_add(1).ok_or(InspectionError::Overflow)?;
        if (0xD800..=0xDFFF).contains(&next_required) {
            next_required = 0xE000;
        }
    }
    Ok(false)
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
        InspectedClass::UnicodeAllNonAscii(class) => {
            let scalar = char::from(byte);
            for range in class.ranges() {
                accounting.charge(1, limit)?;
                if scalar < range.start() {
                    return Ok(false);
                }
                if scalar <= range.end() {
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

    fn unicode_hir(pattern: &str) -> Hir {
        ParserBuilder::new()
            .unicode(true)
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
            (r"a[^z\r\n]*?z", SearchRunMinimum::Zero, false),
            (r"a[^z\r\n]+?z", SearchRunMinimum::One, false),
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
    fn admits_adjacent_identical_class_plus_star_as_one_nonempty_run() {
        for (pattern, generalized) in [
            (r"x[ab][ab]*y", false),
            (r"x([ab])([ab])*y", false),
            (r"x[ab][ab]*?y", true),
        ] {
            let parsed = hir(pattern);
            let InspectionOutcome::Eligible(inspection) = inspect(&parsed, usize::MAX).unwrap()
            else {
                panic!("expected adjacent-class eligibility for {pattern:?}");
            };
            assert_eq!(inspection.prefix, b"x", "{pattern:?}");
            assert_eq!(inspection.suffix, b"y", "{pattern:?}");
            assert_eq!(inspection.minimum, SearchRunMinimum::One, "{pattern:?}");
            assert_eq!(inspection.generalized_search, generalized, "{pattern:?}");
        }

        let parsed = hir(r"x[^xy][^xy]*y");
        let InspectionOutcome::Eligible(exact) = inspect(&parsed, usize::MAX).unwrap() else {
            panic!("expected exact adjacent-class eligibility");
        };
        assert!(matches!(
            inspect(&parsed, exact.work),
            Ok(InspectionOutcome::Eligible(_))
        ));
        assert!(matches!(
            inspect(&parsed, exact.work - 1),
            Err(InspectionError::WorkLimit { .. })
        ));
    }

    #[test]
    fn refuses_adjacent_class_semantic_perturbations() {
        for pattern in [
            r"x[ab][ac]*y",
            r"x[ab][ab]+y",
            r"x[ab][ab]{0,3}y",
            r"x[ab][ab]*a",
            r"x[ab](?:[ab]|c)*y",
        ] {
            assert!(
                matches!(
                    inspect(&hir(pattern), usize::MAX).unwrap(),
                    InspectionOutcome::Ineligible { .. }
                ),
                "pattern={pattern:?}"
            );
        }
    }

    #[test]
    fn admits_owned_unicode_class_with_complete_non_ascii_coverage() {
        let parsed = unicode_hir(r"a[^z\r\n]*z");
        let InspectionOutcome::Eligible(inspection) = inspect(&parsed, usize::MAX).unwrap() else {
            panic!("expected Unicode class-run eligibility");
        };
        assert!(inspection.class.is_unicode_all_non_ascii());
        assert!(inspection.generalized_search);
        assert_eq!(inspection.prefix, b"a");
        assert_eq!(inspection.suffix, b"z");
        assert_eq!(inspection.minimum, SearchRunMinimum::Zero);
        let ranges: Vec<_> = inspection.class.ranges().collect();
        assert!(
            ranges
                .iter()
                .any(|&(start, end)| start <= b'a' && b'a' <= end)
        );
        assert!(
            !ranges
                .iter()
                .any(|&(start, end)| start <= b'z' && b'z' <= end)
        );
        let unicode = inspection.class.unicode_ranges().unwrap();
        assert_eq!(unicode.last().map(ClassUnicodeRange::end), Some(char::MAX));

        for pattern in [r"a[^z\r\n]*?z", r"a[^z\r\n]+?z"] {
            assert!(matches!(
                inspect(&unicode_hir(pattern), usize::MAX).unwrap(),
                InspectionOutcome::Eligible(Inspection {
                    generalized_search: true,
                    ..
                })
            ));
        }
    }

    #[test]
    fn refuses_unicode_classes_with_semantic_or_anchor_gaps() {
        for pattern in [
            r"a[^z\r\n\u{80}]*z",
            r"a[\x00-\x7F]*z",
            r"é[^z]*z",
            r"a[^z]*é",
            r"[^z]+z",
            r"a[^z]+",
        ] {
            assert!(
                matches!(
                    inspect(&unicode_hir(pattern), usize::MAX).unwrap(),
                    InspectionOutcome::Ineligible { .. }
                ),
                "pattern={pattern:?}"
            );
        }
    }

    #[test]
    fn refuses_every_semantic_perturbation() {
        for pattern in [
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
    fn defers_exact_finite_two_barrier_shape_without_a_second_hir_walk() {
        for (pattern, minimum, maximum) in [
            (r"ab[0-9]{0,64}xy", 0, 64),
            (r"(ab)([0-9]{2,8})(xy)", 2, 8),
        ] {
            let hir = hir(pattern);
            let InspectionOutcome::Ineligible {
                work,
                finite: Some(finite),
            } = inspect(&hir, usize::MAX).unwrap()
            else {
                panic!("expected deferred finite eligibility for {pattern:?}");
            };
            assert_eq!(finite.prefix, b"ab");
            assert_eq!(finite.suffix, b"xy");
            assert_eq!(finite.minimum, minimum);
            assert_eq!(finite.maximum, maximum);
            assert!(work > 0);
            assert!(matches!(
                inspect(&hir, work - 1),
                Err(InspectionError::WorkLimit { needed, limit })
                    if needed == work && limit == work - 1
            ));
            assert!(matches!(
                inspect(&hir, work).unwrap(),
                InspectionOutcome::Ineligible {
                    finite: Some(_),
                    ..
                }
            ));
        }

        for pattern in [
            r"[0-9]{2,8}xy",
            r"ab[0-9]{2,8}",
            r"ab[b0-9]{2,8}xy",
            r"ab[0-9]{2,8}3y",
            r"ab[0-9]{2,8}?xy",
        ] {
            assert!(matches!(
                inspect(&hir(pattern), usize::MAX).unwrap(),
                InspectionOutcome::Ineligible { finite: None, .. }
            ));
        }
    }

    #[test]
    fn aggregate_attempt_retains_the_preexisting_finite_refusal_receipt() {
        let hir = hir(r"ab[0-9]{2,8}xy");
        let InspectionOutcome::Ineligible {
            work: portable_work,
            finite: Some(_),
        } = inspect(&hir, usize::MAX).unwrap()
        else {
            panic!("portable inspection should retain the deferred proof");
        };
        let InspectionOutcome::Ineligible {
            work: aggregate_work,
            finite: None,
        } = inspect_attempt(&hir, usize::MAX).unwrap()
        else {
            panic!("aggregate inspection should preserve its immediate refusal");
        };
        assert!(aggregate_work < portable_work);
        assert!(matches!(
            inspect_attempt(&hir, aggregate_work).unwrap(),
            InspectionOutcome::Ineligible {
                work,
                finite: None
            } if work == aggregate_work
        ));
        let error = inspect_attempt(&hir, aggregate_work - 1).unwrap_err();
        assert!(matches!(
            error.into_source(),
            InspectionError::WorkLimit { needed, limit }
                if needed == aggregate_work && limit == aggregate_work - 1
        ));
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
