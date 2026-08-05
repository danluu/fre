//! Allocation-free canonical-HIR proof for the Unicode reverse-inner reducer.

use fre_kernels::{
    REVERSE_INNER_MAX_ADMITTED_ASCII_SCALARS,
    REVERSE_INNER_MAX_ADMITTED_NON_ASCII_SCALARS, REVERSE_INNER_MAX_LITERALS,
};
use regex_syntax::hir::{Class, ClassUnicode, Hir, HirKind};

use crate::aggregate_construction::AggregateInspectionAttemptError;

#[allow(
    clippy::large_enum_variant,
    reason = "the fixed borrowed literal array keeps admission allocation-free and exactly bounded"
)]
pub(crate) enum Inspection<'a> {
    Eligible {
        class: &'a ClassUnicode,
        literals: [&'a [u8]; REVERSE_INNER_MAX_LITERALS],
        literal_count: usize,
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

struct FullBranch<'a> {
    left: &'a ClassUnicode,
    literal: &'a [u8],
    right: &'a ClassUnicode,
}

struct SuffixBranch<'a> {
    literal: &'a [u8],
    right: &'a ClassUnicode,
}

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
    match root.kind() {
        HirKind::Alternation(_) => inspect_unfactored(root, budget),
        HirKind::Concat(parts) if parts.len() == 2 => {
            Ok(inspect_factored(root, budget)?
                .unwrap_or(Inspection::Ineligible { work: budget.work }))
        }
        HirKind::Concat(parts) if parts.len() == 3 => inspect_single(root, budget),
        _ => Ok(Inspection::Ineligible { work: budget.work }),
    }
}

fn inspect_factored<'a>(
    root: &'a Hir,
    budget: &mut Budget,
) -> Result<Option<Inspection<'a>>, InspectionError> {
    let HirKind::Concat(parts) = root.kind() else {
        return Ok(None);
    };
    budget.charge(1)?;
    let [left, suffixes] = parts.as_slice() else {
        return Ok(None);
    };
    let Some(left) = class_plus(left, budget)? else {
        return Ok(None);
    };
    let suffixes = transparent(suffixes, budget)?;
    let HirKind::Alternation(branches) = suffixes.kind() else {
        return Ok(None);
    };
    budget.charge(1)?;
    if branches.is_empty() || branches.len() > REVERSE_INNER_MAX_LITERALS {
        return Ok(Some(Inspection::Ineligible { work: budget.work }));
    }

    let mut literals = [&[][..]; REVERSE_INNER_MAX_LITERALS];
    for (index, branch) in branches.iter().enumerate() {
        let Some(branch) = suffix_branch(branch, budget)? else {
            return Ok(Some(Inspection::Ineligible { work: budget.work }));
        };
        if !same_class(left, branch.right, budget)?
            || !literal_is_ascii_member(left, branch.literal, budget)?
        {
            return Ok(Some(Inspection::Ineligible { work: budget.work }));
        }
        literals[index] = branch.literal;
    }
    Ok(Some(eligible_inspection(
        left,
        literals,
        branches.len(),
        budget,
    )?))
}

fn inspect_unfactored<'a>(
    root: &'a Hir,
    budget: &mut Budget,
) -> Result<Inspection<'a>, InspectionError> {
    let HirKind::Alternation(branches) = root.kind() else {
        return Ok(Inspection::Ineligible { work: budget.work });
    };
    budget.charge(1)?;
    if branches.is_empty() || branches.len() > REVERSE_INNER_MAX_LITERALS {
        return Ok(Inspection::Ineligible { work: budget.work });
    }

    let mut literals = [&[][..]; REVERSE_INNER_MAX_LITERALS];
    let mut common_class = None::<&ClassUnicode>;
    for (index, branch) in branches.iter().enumerate() {
        let Some(branch) = full_branch(branch, budget)? else {
            return Ok(Inspection::Ineligible { work: budget.work });
        };
        if !same_class(branch.left, branch.right, budget)?
            || !literal_is_ascii_member(branch.left, branch.literal, budget)?
        {
            return Ok(Inspection::Ineligible { work: budget.work });
        }
        if let Some(common) = common_class {
            if !same_class(common, branch.left, budget)? {
                return Ok(Inspection::Ineligible { work: budget.work });
            }
        } else {
            common_class = Some(branch.left);
        }
        literals[index] = branch.literal;
    }
    let Some(class) = common_class else {
        return Ok(Inspection::Ineligible { work: budget.work });
    };
    eligible_inspection(class, literals, branches.len(), budget)
}

fn inspect_single<'a>(
    root: &'a Hir,
    budget: &mut Budget,
) -> Result<Inspection<'a>, InspectionError> {
    let HirKind::Concat(parts) = root.kind() else {
        return Ok(Inspection::Ineligible { work: budget.work });
    };
    budget.charge(1)?;
    let [left, literal, right] = parts.as_slice() else {
        return Ok(Inspection::Ineligible { work: budget.work });
    };
    let Some(left) = class_plus(left, budget)? else {
        return Ok(Inspection::Ineligible { work: budget.work });
    };
    let Some((literals, literal_count)) = middle_literals(literal, budget)? else {
        return Ok(Inspection::Ineligible { work: budget.work });
    };
    let Some(right) = class_plus(right, budget)? else {
        return Ok(Inspection::Ineligible { work: budget.work });
    };
    if !same_class(left, right, budget)? {
        return Ok(Inspection::Ineligible { work: budget.work });
    }
    for literal in literals.iter().take(literal_count) {
        if !literal_is_ascii_member(left, literal, budget)? {
            return Ok(Inspection::Ineligible { work: budget.work });
        }
    }
    eligible_inspection(left, literals, literal_count, budget)
}

fn middle_literals<'a>(
    hir: &'a Hir,
    budget: &mut Budget,
) -> Result<Option<([&'a [u8]; REVERSE_INNER_MAX_LITERALS], usize)>, InspectionError> {
    let hir = transparent(hir, budget)?;
    let mut literals = [&[][..]; REVERSE_INNER_MAX_LITERALS];
    match hir.kind() {
        HirKind::Literal(literal) => {
            budget.charge(
                literal
                    .0
                    .len()
                    .checked_add(1)
                    .ok_or(InspectionError::Overflow)?,
            )?;
            if literal.0.is_empty() {
                return Ok(None);
            }
            literals[0] = literal.0.as_ref();
            Ok(Some((literals, 1)))
        }
        HirKind::Alternation(branches) => {
            budget.charge(1)?;
            if branches.is_empty() || branches.len() > REVERSE_INNER_MAX_LITERALS {
                return Ok(None);
            }
            for (index, branch) in branches.iter().enumerate() {
                let Some(literal) = literal_node(branch, budget)? else {
                    return Ok(None);
                };
                literals[index] = literal;
            }
            Ok(Some((literals, branches.len())))
        }
        _ => Ok(None),
    }
}

fn eligible_inspection<'a>(
    class: &'a ClassUnicode,
    literals: [&'a [u8]; REVERSE_INNER_MAX_LITERALS],
    literal_count: usize,
    budget: &mut Budget,
) -> Result<Inspection<'a>, InspectionError> {
    if !sparse_mixed_unicode_class(class, budget)? {
        return Ok(Inspection::Ineligible { work: budget.work });
    }
    Ok(Inspection::Eligible {
        class,
        literals,
        literal_count,
        work: budget.work,
        hir_nodes: budget.hir_nodes,
        captures: budget.captures,
    })
}

fn sparse_mixed_unicode_class(
    class: &ClassUnicode,
    budget: &mut Budget,
) -> Result<bool, InspectionError> {
    let mut ascii_scalars = 0_usize;
    let mut class_scalars = 0_usize;
    for range in class.ranges() {
        budget.charge(1)?;
        let start = u32::from(range.start());
        let end = u32::from(range.end());
        class_scalars = class_scalars
            .checked_add(valid_scalar_population(start, end)?)
            .ok_or(InspectionError::Overflow)?;
        if start <= 0x7f {
            let ascii_end = end.min(0x7f);
            let population = usize::try_from(ascii_end - start + 1)
                .map_err(|_| InspectionError::Overflow)?;
            ascii_scalars = ascii_scalars
                .checked_add(population)
                .ok_or(InspectionError::Overflow)?;
            if ascii_scalars > REVERSE_INNER_MAX_ADMITTED_ASCII_SCALARS {
                return Ok(false);
            }
        }
    }
    let non_ascii_scalars = class_scalars
        .checked_sub(ascii_scalars)
        .ok_or(InspectionError::Overflow)?;
    if ascii_scalars.checked_add(non_ascii_scalars) != Some(class_scalars) {
        return Err(InspectionError::Overflow);
    }
    Ok(non_ascii_scalars != 0
        && non_ascii_scalars <= REVERSE_INNER_MAX_ADMITTED_NON_ASCII_SCALARS
        && ascii_scalars <= REVERSE_INNER_MAX_ADMITTED_ASCII_SCALARS)
}

fn valid_scalar_population(start: u32, end: u32) -> Result<usize, InspectionError> {
    let population = end
        .checked_sub(start)
        .and_then(|width| width.checked_add(1))
        .ok_or(InspectionError::Overflow)?;
    let surrogate_start = start.max(0xD800);
    let surrogate_end = end.min(0xDFFF);
    let surrogate_population = if surrogate_start <= surrogate_end {
        surrogate_end - surrogate_start + 1
    } else {
        0
    };
    let valid_population = population
        .checked_sub(surrogate_population)
        .ok_or(InspectionError::Overflow)?;
    usize::try_from(valid_population).map_err(|_| InspectionError::Overflow)
}

fn full_branch<'a>(
    hir: &'a Hir,
    budget: &mut Budget,
) -> Result<Option<FullBranch<'a>>, InspectionError> {
    let hir = transparent(hir, budget)?;
    let HirKind::Concat(parts) = hir.kind() else {
        return Ok(None);
    };
    budget.charge(1)?;
    let [left, literal, right] = parts.as_slice() else {
        return Ok(None);
    };
    let Some(left) = class_plus(left, budget)? else {
        return Ok(None);
    };
    let Some(literal) = literal_node(literal, budget)? else {
        return Ok(None);
    };
    let Some(right) = class_plus(right, budget)? else {
        return Ok(None);
    };
    Ok(Some(FullBranch {
        left,
        literal,
        right,
    }))
}

fn suffix_branch<'a>(
    hir: &'a Hir,
    budget: &mut Budget,
) -> Result<Option<SuffixBranch<'a>>, InspectionError> {
    let hir = transparent(hir, budget)?;
    let HirKind::Concat(parts) = hir.kind() else {
        return Ok(None);
    };
    budget.charge(1)?;
    let [literal, right] = parts.as_slice() else {
        return Ok(None);
    };
    let Some(literal) = literal_node(literal, budget)? else {
        return Ok(None);
    };
    let Some(right) = class_plus(right, budget)? else {
        return Ok(None);
    };
    Ok(Some(SuffixBranch { literal, right }))
}

fn class_plus<'a>(
    hir: &'a Hir,
    budget: &mut Budget,
) -> Result<Option<&'a ClassUnicode>, InspectionError> {
    let hir = transparent(hir, budget)?;
    let HirKind::Repetition(repetition) = hir.kind() else {
        return Ok(None);
    };
    budget.charge(4)?;
    if repetition.min != 1 || repetition.max.is_some() || !repetition.greedy {
        return Ok(None);
    }
    let repeated = transparent(repetition.sub.as_ref(), budget)?;
    let HirKind::Class(Class::Unicode(class)) = repeated.kind() else {
        return Ok(None);
    };
    budget.charge(1)?;
    if class.ranges().is_empty() {
        return Ok(None);
    }
    Ok(Some(class))
}

fn literal_node<'a>(
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
    if literal.0.is_empty() {
        return Ok(None);
    }
    Ok(Some(literal.0.as_ref()))
}

fn same_class(
    left: &ClassUnicode,
    right: &ClassUnicode,
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

fn literal_is_ascii_member(
    class: &ClassUnicode,
    literal: &[u8],
    budget: &mut Budget,
) -> Result<bool, InspectionError> {
    if literal.is_empty() {
        return Ok(false);
    }
    for &byte in literal {
        budget.charge(1)?;
        if !byte.is_ascii() || !class_contains(class, char::from(byte), budget)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn class_contains(
    class: &ClassUnicode,
    scalar: char,
    budget: &mut Budget,
) -> Result<bool, InspectionError> {
    let ranges = class.ranges();
    let mut low = 0_usize;
    let mut high = ranges.len();
    while low < high {
        budget.charge(1)?;
        let width = high.checked_sub(low).ok_or(InspectionError::Overflow)?;
        let middle = low
            .checked_add(width / 2)
            .ok_or(InspectionError::Overflow)?;
        let range = ranges[middle];
        if scalar < range.start() {
            high = middle;
        } else if scalar > range.end() {
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

    use super::{Inspection, InspectionError, inspect};

    fn parse(pattern: &str) -> regex_syntax::hir::Hir {
        ParserBuilder::new()
            .unicode(true)
            .utf8(false)
            .build()
            .parse(pattern)
            .unwrap()
    }

    fn assert_eligible(pattern: &str, expected: &[&[u8]]) -> (usize, usize, usize) {
        let hir = parse(pattern);
        let Inspection::Eligible {
            literals,
            literal_count,
            work,
            hir_nodes,
            captures,
            ..
        } = inspect(&hir, usize::MAX).unwrap()
        else {
            panic!("reverse-inner shape was not recognized: {pattern}");
        };
        assert_eq!(literal_count, expected.len());
        assert_eq!(&literals[..literal_count], expected);
        (work, hir_nodes, captures)
    }

    fn assert_ineligible(pattern: &str) {
        assert!(
            matches!(
                inspect(&parse(pattern), usize::MAX).unwrap(),
                Inspection::Ineligible { .. }
            ),
            "unexpectedly admitted reverse-inner shape: {pattern}"
        );
    }

    #[test]
    fn unfactored_and_factored_shapes_are_eligible() {
        let expected: [&[u8]; 2] = [b"herloc", b"olme"];
        let (_, unfactored_nodes, _) = assert_eligible(r"\pL+herloc\pL+|\pL+olme\pL+", &expected);
        let (_, factored_nodes, _) = assert_eligible(r"\pL+(?:herloc\pL+|olme\pL+)", &expected);
        assert!(unfactored_nodes >= factored_nodes);
    }

    #[test]
    fn canonical_middle_literal_alternations_through_sixteen_are_eligible() {
        let four: [&[u8]; 4] = [b"ab", b"cd", b"ef", b"gh"];
        assert_eligible(r"[a-zλ]+(?:ab|cd|ef|gh)[a-zλ]+", &four);

        let sixteen: [&[u8]; 16] = [
            b"ab", b"cd", b"ef", b"gh", b"ij", b"kl", b"mn", b"op", b"qr", b"st",
            b"uv", b"wx", b"yz", b"ba", b"dc", b"fe",
        ];
        assert_eligible(
            r"[a-zλ]+(?:ab|cd|ef|gh|ij|kl|mn|op|qr|st|uv|wx|yz|ba|dc|fe)[a-zλ]+",
            &sixteen,
        );
    }

    #[test]
    fn transparent_captures_preserve_whole_match_eligibility() {
        let expected: [&[u8]; 2] = [b"herloc", b"olme"];
        let (_, _, captures) =
            assert_eligible(r"((\pL+)(herloc)(\pL+))|((\pL+)(olme)(\pL+))", &expected);
        assert_eq!(captures, 8);
    }

    #[test]
    fn exact_planner_limit_succeeds_and_one_below_refuses() {
        let hir = parse(r"\pL+herloc\pL+|\pL+olme\pL+");
        let Inspection::Eligible { work, .. } = inspect(&hir, usize::MAX).unwrap() else {
            panic!("reverse-inner shape was not recognized");
        };
        assert!(matches!(
            inspect(&hir, work),
            Ok(Inspection::Eligible { .. })
        ));
        assert!(matches!(
            inspect(&hir, work - 1),
            Err(InspectionError::WorkLimit {
                needed,
                limit
            }) if needed == work && limit == work - 1
        ));
    }

    #[test]
    fn unsound_variants_are_ineligible() {
        for pattern in [
            r"\pL*herloc\pL+",
            r"\pL+?herloc\pL+",
            r"\pL+herloc\pL*",
            r"\pL+herloc\pN+",
            r"\pL+\xFF\pL+",
            r"\pL+\d+\pL+",
            r"\pL+123\pL+",
            r"\pL+herloc",
            r"herloc\pL+",
        ] {
            assert!(
                matches!(
                    inspect(&parse(pattern), usize::MAX).unwrap(),
                    Inspection::Ineligible { .. }
                ),
                "unexpectedly admitted {pattern}"
            );
        }
    }

    #[test]
    fn auto_gate_rejects_ascii_only_byte_dense_and_negated_classes() {
        for pattern in [
            r"[a-z]+ab[a-z]+",
            r"(?-u:[a-z]+ab[a-z]+)",
            r"[\x00-\x7Fλ]+ab[\x00-\x7Fλ]+",
            r"[^x]+ab[^x]+",
        ] {
            assert!(
                matches!(
                    inspect(&parse(pattern), usize::MAX).unwrap(),
                    Inspection::Ineligible { .. }
                ),
                "unexpectedly admitted structurally broad class: {pattern}"
            );
        }
    }

    #[test]
    fn auto_gate_uses_exact_ascii_and_non_ascii_scalar_populations() {
        assert_eligible(
            r"[\x00-\x3Fλ]+01[\x00-\x3Fλ]+",
            &[b"01"],
        );
        assert_ineligible(r"[\x00-\x40λ]+01[\x00-\x40λ]+");
        assert_ineligible(r"[\x00-\x3F]+01[\x00-\x3F]+");

        assert_eligible(
            r"[a\u{10000}-\u{53DDF}]+a[a\u{10000}-\u{53DDF}]+",
            &[b"a"],
        );
        assert_ineligible(
            r"[a\u{10000}-\u{53DE0}]+a[a\u{10000}-\u{53DE0}]+",
        );

        assert_eligible(r"\pL+ab\pL+", &[b"ab"]);
        assert_eligible(r"[a-zλ]+ab[a-zλ]+", &[b"ab"]);
        assert_ineligible(r"[^\x40-\x7F]+01[^\x40-\x7F]+");
    }
}
