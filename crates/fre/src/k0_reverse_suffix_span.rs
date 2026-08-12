//! Allocation-free source-order proofs for unbounded K0 reverse-suffix Span.
//!
//! A retained mandatory suffix is useful for recovering a match start only
//! when visiting suffix occurrences in source order cannot skip a globally
//! earlier match. This module proves three deliberately narrow sufficient
//! conditions over canonical HIR:
//!
//! * every sibling before the exact terminal suffix has one fixed finite byte
//!   width; or
//! * at least one suffix byte cannot be consumed anywhere in those siblings;
//!   or
//! * the prefix is one or more repetitions of a unit ending in a required
//!   byte-class separator that is disjoint from every other unit consumer and
//!   the suffix.
//!
//! Captures are transparent. The root must otherwise be a concatenation whose
//! last consuming child is one exact literal equal to the complete retained
//! suffix. All other shapes fail closed. Inspection allocates nothing and
//! returns cumulative planner work on both eligibility and semantic refusal.

use regex_syntax::hir::{Class, Hir, HirKind};

const NODE_INSPECTION_WORK: u64 = 1;
const WIDTH_INSPECTION_WORK: u64 = 1;
const WIDTH_ARITHMETIC_WORK: u64 = 1;
const SUFFIX_LENGTH_WORK: u64 = 1;
const SUFFIX_BYTE_WORK: u64 = 1;
const LITERAL_BYTE_WORK: u64 = 1;
const CLASS_RANGE_WORK: u64 = 1;
const CLASS_RANGE_COMPARISON_WORK: u64 = 1;

/// Source theorem that makes first-confirmed suffix order globally sound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Proof {
    /// Every prefix sibling has one finite byte width.
    FixedPrefix,
    /// Some byte in the suffix cannot occur anywhere in the prefix language.
    NoInternalSuffix,
    /// Each repeated prefix unit ends in a byte-class separator that cannot
    /// occur in another unit component or in the terminal suffix.
    CyclicTrailingClassSeparator,
}

/// Completed optional proof and its exact cumulative planner work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Inspection {
    proof: Proof,
    planner_work: u64,
}

impl Inspection {
    pub(crate) const fn proof(self) -> Proof {
        self.proof
    }

    pub(crate) const fn planner_work(self) -> u64 {
        self.planner_work
    }
}

/// Transactional result of one optional structural inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InspectionOutcome {
    Eligible(Inspection),
    Ineligible { planner_work: u64 },
}

impl InspectionOutcome {
    pub(crate) const fn planner_work(self) -> u64 {
        match self {
            Self::Eligible(inspection) => inspection.planner_work,
            Self::Ineligible { planner_work } => planner_work,
        }
    }
}

/// Hard planner refusal. Semantic shape mismatches are ordinary ineligibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InspectionError {
    WorkLimit {
        actual: u64,
        needed: u64,
        limit: u64,
    },
    ArithmeticOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Meter {
    work: u64,
    limit: u64,
}

impl Meter {
    const fn new(initial_work: u64, limit: u64) -> Result<Self, InspectionError> {
        if initial_work > limit {
            return Err(InspectionError::WorkLimit {
                actual: limit,
                needed: initial_work,
                limit,
            });
        }
        Ok(Self {
            work: initial_work,
            limit,
        })
    }

    fn charge(&mut self, additional: u64) -> Result<(), InspectionError> {
        let needed = self
            .work
            .checked_add(additional)
            .ok_or(InspectionError::ArithmeticOverflow)?;
        if needed > self.limit {
            return Err(InspectionError::WorkLimit {
                actual: self.work,
                needed,
                limit: self.limit,
            });
        }
        self.work = needed;
        Ok(())
    }
}

/// Prove that the first reverse-confirmed occurrence of `mandatory_suffix`
/// cannot hide a globally earlier match start.
///
/// The suffix must be nonempty and must equal the complete literal in the
/// root concatenation's last consuming child. `initial_work` is cumulative
/// work already spent by the caller. Every successful charge is reflected in
/// either the returned outcome or a [`InspectionError::WorkLimit`] receipt.
pub(crate) fn inspect(
    hir: &Hir,
    mandatory_suffix: &[u8],
    initial_work: u64,
    max_planner_work: u64,
) -> Result<InspectionOutcome, InspectionError> {
    let mut meter = Meter::new(initial_work, max_planner_work)?;
    let proof = inspect_inner(hir, mandatory_suffix, &mut meter)?;
    Ok(match proof {
        Some(proof) => InspectionOutcome::Eligible(Inspection {
            proof,
            planner_work: meter.work,
        }),
        None => InspectionOutcome::Ineligible {
            planner_work: meter.work,
        },
    })
}

fn inspect_inner(
    hir: &Hir,
    mandatory_suffix: &[u8],
    meter: &mut Meter,
) -> Result<Option<Proof>, InspectionError> {
    let root = peel_captures(hir, meter)?;
    let HirKind::Concat(parts) = root.kind() else {
        return Ok(None);
    };
    let Some((suffix_index, suffix_hir)) = last_consuming_child(parts, meter)? else {
        return Ok(None);
    };
    if !exact_suffix_matches(suffix_hir, mandatory_suffix, meter)? {
        return Ok(None);
    }

    let prefix = &parts[..suffix_index];
    if prefix_has_fixed_length(prefix, meter)? {
        return Ok(Some(Proof::FixedPrefix));
    }
    if !prefix_can_contain_literal(prefix, mandatory_suffix, meter)? {
        return Ok(Some(Proof::NoInternalSuffix));
    }
    if prefix_has_cyclic_trailing_class_separator(prefix, mandatory_suffix, meter)? {
        return Ok(Some(Proof::CyclicTrailingClassSeparator));
    }
    Ok(None)
}

/// Prove source ordering for the narrow cyclic shape `U+ S`.
///
/// `U` must be a concatenation whose final child is either one byte class `D`
/// or exactly `D+`. The class is required to be disjoint from every earlier
/// consumer in `U` and from `S`. Therefore every accepted candidate `S` is
/// immediately preceded by `D`. If an earlier match contained that candidate
/// inside its repeated prefix, disjointness forces the candidate to begin at
/// a complete `U` boundary. The earlier start would then also match through
/// this candidate, contradicting the reverse verifier's earliest start.
fn prefix_has_cyclic_trailing_class_separator(
    prefix: &[Hir],
    suffix: &[u8],
    meter: &mut Meter,
) -> Result<bool, InspectionError> {
    if prefix.len() != 1 {
        return Ok(false);
    }
    let repeated = peel_captures(&prefix[0], meter)?;
    let HirKind::Repetition(repetition) = repeated.kind() else {
        return Ok(false);
    };
    if repetition.min != 1 || repetition.max.is_some() {
        return Ok(false);
    }
    let unit = peel_captures(&repetition.sub, meter)?;
    let HirKind::Concat(parts) = unit.kind() else {
        return Ok(false);
    };
    let Some((separator_index, separator_hir)) = last_consuming_child(parts, meter)? else {
        return Ok(false);
    };
    // Keep the theorem independent of trailing assertions and identify the
    // designated separator by position, not structural equality. In
    // particular, an equal earlier class must still be checked and rejected.
    if separator_index + 1 != parts.len() {
        return Ok(false);
    }
    let Some(separator) = exact_trailing_byte_class(separator_hir, meter)? else {
        return Ok(false);
    };
    if separator.ranges().is_empty() {
        return Ok(false);
    }
    if !byte_class_is_disjoint_from_literal(separator, suffix, meter)? {
        return Ok(false);
    }
    for sibling in &parts[..separator_index] {
        if !byte_class_is_disjoint_from_hir(separator, sibling, meter)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Recognize one required trailing byte class, either directly or under the
/// exact `+` repetition shape. Other repetitions are sound in some cases but
/// deliberately remain outside this proof's small auditable surface.
fn exact_trailing_byte_class<'hir>(
    hir: &'hir Hir,
    meter: &mut Meter,
) -> Result<Option<&'hir regex_syntax::hir::ClassBytes>, InspectionError> {
    let hir = peel_captures(hir, meter)?;
    match hir.kind() {
        HirKind::Class(Class::Bytes(class)) => Ok(Some(class)),
        HirKind::Repetition(repetition)
            if repetition.min == 1 && repetition.max.is_none() =>
        {
            let sub = peel_captures(&repetition.sub, meter)?;
            match sub.kind() {
                HirKind::Class(Class::Bytes(class)) => Ok(Some(class)),
                _ => Ok(None),
            }
        }
        _ => Ok(None),
    }
}

fn byte_class_is_disjoint_from_literal(
    separator: &regex_syntax::hir::ClassBytes,
    literal: &[u8],
    meter: &mut Meter,
) -> Result<bool, InspectionError> {
    for &byte in literal {
        meter.charge(SUFFIX_BYTE_WORK)?;
        for range in separator.ranges() {
            meter.charge(CLASS_RANGE_WORK)?;
            if range.start() <= byte && byte <= range.end() {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn byte_class_is_disjoint_from_hir(
    separator: &regex_syntax::hir::ClassBytes,
    hir: &Hir,
    meter: &mut Meter,
) -> Result<bool, InspectionError> {
    meter.charge(NODE_INSPECTION_WORK)?;
    match hir.kind() {
        HirKind::Empty => Ok(true),
        // Look assertions consume no bytes, but accepting them would broaden
        // the theorem's boundary semantics without helping the target class.
        HirKind::Look(_) | HirKind::Class(Class::Unicode(_)) => Ok(false),
        HirKind::Literal(literal) => {
            for &byte in literal.0.iter() {
                meter.charge(LITERAL_BYTE_WORK)?;
                for range in separator.ranges() {
                    meter.charge(CLASS_RANGE_WORK)?;
                    if range.start() <= byte && byte <= range.end() {
                        return Ok(false);
                    }
                }
            }
            Ok(true)
        }
        HirKind::Class(Class::Bytes(class)) => {
            for candidate in class.ranges() {
                meter.charge(CLASS_RANGE_WORK)?;
                for separator_range in separator.ranges() {
                    meter.charge(CLASS_RANGE_COMPARISON_WORK)?;
                    if candidate.start() <= separator_range.end()
                        && separator_range.start() <= candidate.end()
                    {
                        return Ok(false);
                    }
                }
            }
            Ok(true)
        }
        HirKind::Repetition(repetition) => {
            byte_class_is_disjoint_from_hir(separator, &repetition.sub, meter)
        }
        HirKind::Capture(capture) => {
            byte_class_is_disjoint_from_hir(separator, &capture.sub, meter)
        }
        HirKind::Concat(children) | HirKind::Alternation(children) => {
            for child in children {
                if !byte_class_is_disjoint_from_hir(separator, child, meter)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
    }
}

fn last_consuming_child<'hir>(
    parts: &'hir [Hir],
    meter: &mut Meter,
) -> Result<Option<(usize, &'hir Hir)>, InspectionError> {
    for (index, child) in parts.iter().enumerate().rev() {
        let child = peel_captures(child, meter)?;
        meter.charge(WIDTH_INSPECTION_WORK)?;
        if child.properties().maximum_len() != Some(0) {
            return Ok(Some((index, child)));
        }
    }
    Ok(None)
}

fn exact_suffix_matches(
    hir: &Hir,
    mandatory_suffix: &[u8],
    meter: &mut Meter,
) -> Result<bool, InspectionError> {
    let HirKind::Literal(literal) = hir.kind() else {
        return Ok(false);
    };
    meter.charge(SUFFIX_LENGTH_WORK)?;
    if mandatory_suffix.is_empty() || literal.0.len() != mandatory_suffix.len() {
        return Ok(false);
    }
    for (&actual, &expected) in literal.0.iter().zip(mandatory_suffix) {
        meter.charge(SUFFIX_BYTE_WORK)?;
        if actual != expected {
            return Ok(false);
        }
    }
    Ok(true)
}

fn prefix_has_fixed_length(prefix: &[Hir], meter: &mut Meter) -> Result<bool, InspectionError> {
    let mut total = 0_usize;
    for hir in prefix {
        let hir = peel_captures(hir, meter)?;
        meter.charge(WIDTH_INSPECTION_WORK)?;
        let properties = hir.properties();
        let Some(minimum) = properties.minimum_len() else {
            return Ok(false);
        };
        let Some(maximum) = properties.maximum_len() else {
            return Ok(false);
        };
        if minimum != maximum {
            return Ok(false);
        }
        meter.charge(WIDTH_ARITHMETIC_WORK)?;
        total = total
            .checked_add(minimum)
            .ok_or(InspectionError::ArithmeticOverflow)?;
    }
    Ok(true)
}

/// This deliberately mirrors regex-automata's low-precision theorem: a
/// literal might occur internally when every one of its bytes is consumable
/// somewhere in the prefix, without attempting to prove adjacency or order.
fn prefix_can_contain_literal(
    prefix: &[Hir],
    literal: &[u8],
    meter: &mut Meter,
) -> Result<bool, InspectionError> {
    if literal.is_empty() {
        return Ok(true);
    }
    for &byte in literal {
        meter.charge(SUFFIX_BYTE_WORK)?;
        let mut consumable = false;
        for hir in prefix {
            if hir_can_consume_byte(hir, byte, meter)? {
                consumable = true;
                break;
            }
        }
        if !consumable {
            return Ok(false);
        }
    }
    Ok(true)
}

fn hir_can_consume_byte(hir: &Hir, byte: u8, meter: &mut Meter) -> Result<bool, InspectionError> {
    meter.charge(NODE_INSPECTION_WORK)?;
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => Ok(false),
        HirKind::Literal(literal) => {
            for &candidate in literal.0.iter() {
                meter.charge(LITERAL_BYTE_WORK)?;
                if candidate == byte {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        HirKind::Class(Class::Bytes(class)) => {
            for range in class.ranges() {
                meter.charge(CLASS_RANGE_WORK)?;
                if range.start() <= byte && byte <= range.end() {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        HirKind::Class(Class::Unicode(class)) => {
            // A non-ASCII UTF-8 byte is not independently a scalar. Treat any
            // Unicode class as capable of consuming it, exactly as the source
            // theorem we mirror does, so this proof can only become stricter.
            if !byte.is_ascii() {
                return Ok(true);
            }
            let scalar = char::from(byte);
            for range in class.ranges() {
                meter.charge(CLASS_RANGE_WORK)?;
                if range.start() <= scalar && scalar <= range.end() {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        HirKind::Repetition(repetition) => hir_can_consume_byte(&repetition.sub, byte, meter),
        HirKind::Capture(capture) => hir_can_consume_byte(&capture.sub, byte, meter),
        HirKind::Concat(children) | HirKind::Alternation(children) => {
            for child in children {
                if hir_can_consume_byte(child, byte, meter)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}

fn peel_captures<'hir>(
    mut hir: &'hir Hir,
    meter: &mut Meter,
) -> Result<&'hir Hir, InspectionError> {
    loop {
        meter.charge(NODE_INSPECTION_WORK)?;
        let HirKind::Capture(capture) = hir.kind() else {
            return Ok(hir);
        };
        hir = &capture.sub;
    }
}

#[cfg(test)]
mod tests {
    use regex_syntax::ParserBuilder;

    use super::{InspectionError, InspectionOutcome, Proof, inspect};

    fn parse_bytes(pattern: &str) -> regex_syntax::hir::Hir {
        ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(pattern)
            .unwrap()
    }

    fn parse_unicode(pattern: &str) -> regex_syntax::hir::Hir {
        ParserBuilder::new().build().parse(pattern).unwrap()
    }

    fn proof(pattern: &str, suffix: &[u8]) -> Proof {
        let InspectionOutcome::Eligible(inspection) =
            inspect(&parse_bytes(pattern), suffix, 0, u64::MAX).unwrap()
        else {
            panic!("reverse-suffix Span order proof was refused: {pattern:?}");
        };
        inspection.proof()
    }

    #[test]
    fn fixed_prefix_is_admitted_before_the_no_internal_suffix_proof() {
        for pattern in [r"(?-u:[A-Z][0-9]XYZ)", r"(?-u:([A-Z])([0-9])((XYZ)))"] {
            assert_eq!(proof(pattern, b"XYZ"), Proof::FixedPrefix);
        }
    }

    #[test]
    fn variable_prefix_without_every_suffix_byte_is_admitted() {
        for pattern in [r"(?-u:(?:[0-9]+[ab]+)+XYZ)", r"(?-u:[0-9]+XYZ)"] {
            assert_eq!(proof(pattern, b"XYZ"), Proof::NoInternalSuffix);
        }
    }

    #[test]
    fn captures_and_trailing_zero_width_children_are_transparent() {
        let hir = parse_bytes(r"(?-u:(([0-9]+))((XYZ))$)");
        let InspectionOutcome::Eligible(inspection) = inspect(&hir, b"XYZ", 0, u64::MAX).unwrap()
        else {
            panic!("capture-transparent suffix proof was refused");
        };
        assert_eq!(inspection.proof(), Proof::NoInternalSuffix);
    }

    #[test]
    fn possible_internal_suffixes_and_nonexact_tails_fail_closed() {
        for (pattern, suffix) in [
            (r"(?-u:[a-z]+[0-9a]+xyz)", b"xyz".as_slice()),
            (r"(?-u:[a-z]+[0-9]+a1)", b"a1".as_slice()),
            (r"(?-u:[a-z]+[0-9]+XYZ)", b"XY".as_slice()),
            (r"(?-u:[a-z]+[0-9]+[XYZ])", b"Z".as_slice()),
            (r"(?-u:XYZ)", b"XYZ".as_slice()),
            (r"(?-u:[a-z]+XYZ)", b"".as_slice()),
        ] {
            assert!(
                matches!(
                    inspect(&parse_bytes(pattern), suffix, 0, u64::MAX).unwrap(),
                    InspectionOutcome::Ineligible { .. },
                ),
                "invalid order proof was admitted: pattern={pattern:?} suffix={suffix:?}",
            );
        }
    }

    #[test]
    fn cyclic_trailing_class_separator_is_admitted() {
        for pattern in [
            r"(?-u:(?:[0-2XYZ]+[a-c]+[3-5]+[d-f]+)+XYZ)",
            r"(?-u:((?:([0-2XYZ]+)([a-c]+)([3-5]+)([d-f]+))+)(XYZ))",
            r"(?-u:(?:[0-2XYZ]+[a-c]+[3-5]+[d-f])+XYZ)",
        ] {
            assert_eq!(
                proof(pattern, b"XYZ"),
                Proof::CyclicTrailingClassSeparator,
            );
        }
    }

    #[test]
    fn cyclic_separator_relaxations_fail_closed() {
        for pattern in [
            // The outer repetition must execute at least once.
            r"(?-u:(?:[0-2XYZ]+[a-c]+[3-5]+[d-f]+)*XYZ)",
            // The separator itself must be required and have the exact class
            // or class-plus shape.
            r"(?-u:(?:[0-2XYZ]+[a-c]+[3-5]+[d-f]*)+XYZ)",
            r"(?-u:(?:[0-2XYZ]+[a-c]+[3-5]+[d-f]{1,2})+XYZ)",
            // An earlier sibling may not consume a separator byte, including
            // an equal class that must not be skipped by structural equality.
            r"(?-u:(?:[a-fXYZ]+[d-f]+)+XYZ)",
            r"(?-u:(?:[XYZ]+[d-f]+[a-c]+[d-f]+)+XYZ)",
            r"(?-u:(?:(?:[a-f]+XY)?[b-c]+)+XY)",
            // Nor may the separator consume a suffix byte.
            r"(?-u:(?:[0-2]+[X-Z]+)+XYZ)",
            // Keep the separator terminal within the repeated unit and keep
            // the root prefix to the exact one-child shape.
            r"(?-u:(?:[0-2XYZ]+[d-f]+[0-2]+)+XYZ)",
            r"(?-u:A(?:[0-2XYZ]+[a-c]+[3-5]+[d-f]+)+XYZ)",
        ] {
            assert!(
                matches!(
                    inspect(&parse_bytes(pattern), b"XYZ", 0, u64::MAX).unwrap(),
                    InspectionOutcome::Ineligible { .. },
                ),
                "unsafe cyclic separator proof was admitted: {pattern:?}",
            );
        }

        let unicode_separator = parse_unicode(r"(?:[XYZ]+[δ-ζ]+)+XYZ");
        assert!(matches!(
            inspect(&unicode_separator, b"XYZ", 0, u64::MAX).unwrap(),
            InspectionOutcome::Ineligible { .. },
        ));
    }

    #[test]
    fn cyclic_separator_work_closes_on_success_and_late_overlap() {
        for pattern in [
            r"(?-u:(?:[0-2XYZ]+[a-c]+[3-5]+[d-f]+)+XYZ)",
            r"(?-u:(?:[0-2XYZ]+[a-c]+[3-5]+[d-f]+[d-f]+)+XYZ)",
        ] {
            let hir = parse_bytes(pattern);
            let initial_work = 29;
            let unlimited = inspect(&hir, b"XYZ", initial_work, u64::MAX).unwrap();
            let exact_work = unlimited.planner_work();
            assert!(exact_work > initial_work);
            assert_eq!(
                inspect(&hir, b"XYZ", initial_work, exact_work).unwrap(),
                unlimited,
            );
            let one_below = exact_work.checked_sub(1).unwrap();
            assert!(matches!(
                inspect(&hir, b"XYZ", initial_work, one_below),
                Err(InspectionError::WorkLimit { limit, .. }) if limit == one_below,
            ));
        }
    }

    #[test]
    fn unicode_classes_use_the_conservative_byte_rule() {
        let greek = parse_unicode(r"\p{Greek}+XYZ");
        let InspectionOutcome::Eligible(inspection) = inspect(&greek, b"XYZ", 0, u64::MAX).unwrap()
        else {
            panic!("ASCII bytes absent from a Greek prefix should be proved absent");
        };
        assert_eq!(inspection.proof(), Proof::NoInternalSuffix);

        let arbitrary_scalars = parse_unicode(r"(?s:.+)\x{3B1}");
        assert!(matches!(
            inspect(&arbitrary_scalars, "α".as_bytes(), 0, u64::MAX,).unwrap(),
            InspectionOutcome::Ineligible { .. },
        ));
    }

    #[test]
    fn planner_work_closes_at_exact_and_one_below_limits() {
        let hir = parse_bytes(r"(?-u:(?:[0-9]+[ab]+)+XYZ)");
        let initial_work = 17;
        let InspectionOutcome::Eligible(unlimited) =
            inspect(&hir, b"XYZ", initial_work, u64::MAX).unwrap()
        else {
            panic!("resource fixture was refused");
        };
        let exact_work = unlimited.planner_work();
        assert!(exact_work > initial_work);

        let exact = inspect(&hir, b"XYZ", initial_work, exact_work).unwrap();
        assert_eq!(exact.planner_work(), exact_work);
        assert_eq!(
            match exact {
                InspectionOutcome::Eligible(inspection) => inspection.proof(),
                InspectionOutcome::Ineligible { .. } => panic!("exact limit declined"),
            },
            unlimited.proof(),
        );

        let one_below = exact_work.checked_sub(1).unwrap();
        assert_eq!(
            inspect(&hir, b"XYZ", initial_work, one_below),
            Err(InspectionError::WorkLimit {
                actual: one_below,
                needed: exact_work,
                limit: one_below,
            }),
        );
        assert_eq!(
            inspect(&hir, b"XYZ", 2, 1),
            Err(InspectionError::WorkLimit {
                actual: 1,
                needed: 2,
                limit: 1,
            }),
        );
    }

    #[test]
    fn planner_counter_overflow_is_transactional() {
        let hir = parse_bytes(r"(?-u:[0-9]+XYZ)");
        assert_eq!(
            inspect(&hir, b"XYZ", u64::MAX, u64::MAX),
            Err(InspectionError::ArithmeticOverflow),
        );
    }
}
