//! Source-only proof for a finite greedy universal-byte corridor and exact tail.
//!
//! The admitted HIR language is exactly `bytes{pmin,pmax} SUFFIX`: one or more
//! finite greedy repetitions (or fixed one-byte terms) whose body accepts every
//! byte independently, followed by one nonempty exact literal. Multiple prefix
//! terms remain safe even though their byte languages overlap completely. For
//! any fixed match start, each attainable total prefix width has one
//! lexicographically greatest feasible length vector. Those representatives
//! are monotone in total width because every remaining sum of finite integer
//! intervals is itself an interval. Greedy backtracking therefore reaches the
//! latest suffix position that can match before any earlier one. (The raw
//! lexicographic order of every feasible vector is not, by itself, total-width
//! order.)
//!
//! This proof deliberately does not infer universality from a whole-graph union
//! of consuming edges. Each repeated position must independently accept all 256
//! bytes. Variable-width alternation, correlated multi-byte branches, looks,
//! Unicode scalar classes, lazy repetition and a merely partial literal tail
//! all fail closed. The caller supplies the exact suffix proved by its lower
//! plan; admission requires that byte string to equal the entire HIR tail.

use regex_syntax::hir::{Class, Hir, HirKind};

const NODE_INSPECTION_WORK: u64 = 1;
const RANGE_INSPECTION_WORK: u64 = 1;
const MEMBER_INSERTION_WORK: u64 = 1;
const BITMAP_WORD_WORK: u64 = 1;
const WIDTH_ARITHMETIC_WORK: u64 = 1;
const SUFFIX_LENGTH_WORK: u64 = 1;
const SUFFIX_BYTE_WORK: u64 = 1;
const UNIVERSAL_WORDS: [u64; 4] = [u64::MAX; 4];

/// Exact source-independent language geometry proved by one inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Descriptor {
    minimum_prefix_bytes: usize,
    maximum_prefix_bytes: usize,
    minimum_match_bytes: usize,
    maximum_match_bytes: usize,
    suffix_bytes: usize,
}

impl Descriptor {
    pub(crate) const fn minimum_prefix_bytes(self) -> usize {
        self.minimum_prefix_bytes
    }

    pub(crate) const fn maximum_prefix_bytes(self) -> usize {
        self.maximum_prefix_bytes
    }

    pub(crate) const fn minimum_match_bytes(self) -> usize {
        self.minimum_match_bytes
    }

    pub(crate) const fn maximum_match_bytes(self) -> usize {
        self.maximum_match_bytes
    }

    pub(crate) const fn suffix_bytes(self) -> usize {
        self.suffix_bytes
    }
}

/// Completed optional proof and its exact cumulative planner work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Inspection {
    descriptor: Descriptor,
    planner_work: u64,
}

impl Inspection {
    pub(crate) const fn descriptor(self) -> Descriptor {
        self.descriptor
    }

    pub(crate) const fn planner_work(self) -> u64 {
        self.planner_work
    }
}

/// Transactional result of one optional structural proof.
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
struct Run {
    minimum: usize,
    maximum: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Meter {
    work: u64,
    limit: u64,
}

impl Meter {
    fn new(initial_work: u64, limit: u64) -> Result<Self, InspectionError> {
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

/// Prove one exact all-greedy `bytes{pmin,pmax} SUFFIX` HIR language.
///
/// `mandatory_suffix` must be the exact nonempty suffix independently bound to
/// the lower plan that will consume this descriptor. This analyzer allocates
/// nothing and returns the exact cumulative work completed on both admission
/// and semantic decline.
pub(crate) fn inspect(
    hir: &Hir,
    mandatory_suffix: &[u8],
    initial_work: u64,
    max_planner_work: u64,
) -> Result<InspectionOutcome, InspectionError> {
    let mut meter = Meter::new(initial_work, max_planner_work)?;
    let descriptor = inspect_inner(hir, mandatory_suffix, &mut meter)?;
    Ok(match descriptor {
        Some(descriptor) => InspectionOutcome::Eligible(Inspection {
            descriptor,
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
) -> Result<Option<Descriptor>, InspectionError> {
    let root = peel_captures(hir, meter)?;
    let HirKind::Concat(parts) = root.kind() else {
        return Ok(None);
    };
    let Some((tail, prefix)) = parts.split_last() else {
        return Ok(None);
    };
    if prefix.is_empty() || !exact_suffix(tail, mandatory_suffix, meter)? {
        return Ok(None);
    }

    let mut minimum_prefix_bytes = 0_usize;
    let mut maximum_prefix_bytes = 0_usize;
    for part in prefix {
        let Some(run) = inspect_run(part, meter)? else {
            return Ok(None);
        };
        let Some(next_minimum) =
            checked_add_width(minimum_prefix_bytes, run.minimum, meter)?
        else {
            return Ok(None);
        };
        let Some(next_maximum) =
            checked_add_width(maximum_prefix_bytes, run.maximum, meter)?
        else {
            return Ok(None);
        };
        minimum_prefix_bytes = next_minimum;
        maximum_prefix_bytes = next_maximum;
    }

    let Some(minimum_match_bytes) =
        checked_add_width(minimum_prefix_bytes, mandatory_suffix.len(), meter)?
    else {
        return Ok(None);
    };
    let Some(maximum_match_bytes) =
        checked_add_width(maximum_prefix_bytes, mandatory_suffix.len(), meter)?
    else {
        return Ok(None);
    };
    Ok(Some(Descriptor {
        minimum_prefix_bytes,
        maximum_prefix_bytes,
        minimum_match_bytes,
        maximum_match_bytes,
        suffix_bytes: mandatory_suffix.len(),
    }))
}

fn exact_suffix(
    hir: &Hir,
    mandatory_suffix: &[u8],
    meter: &mut Meter,
) -> Result<bool, InspectionError> {
    let tail = peel_captures(hir, meter)?;
    let HirKind::Literal(literal) = tail.kind() else {
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

fn inspect_run(hir: &Hir, meter: &mut Meter) -> Result<Option<Run>, InspectionError> {
    let hir = peel_captures(hir, meter)?;
    let (words, minimum, maximum) = match hir.kind() {
        HirKind::Repetition(repetition) => {
            let Some(maximum) = repetition.max else {
                return Ok(None);
            };
            if !repetition.greedy || maximum == 0 || maximum < repetition.min {
                return Ok(None);
            }
            let Ok(minimum) = usize::try_from(repetition.min) else {
                return Ok(None);
            };
            let Ok(maximum) = usize::try_from(maximum) else {
                return Ok(None);
            };
            let Some(words) = inspect_one_byte_language(&repetition.sub, meter)? else {
                return Ok(None);
            };
            (words, minimum, maximum)
        }
        _ => {
            let Some(words) = inspect_one_byte_language_peeled(hir, meter)? else {
                return Ok(None);
            };
            (words, 1, 1)
        }
    };
    if !is_universal(words, meter)? {
        return Ok(None);
    }
    Ok(Some(Run { minimum, maximum }))
}

fn inspect_one_byte_language(
    hir: &Hir,
    meter: &mut Meter,
) -> Result<Option<[u64; 4]>, InspectionError> {
    let hir = peel_captures(hir, meter)?;
    inspect_one_byte_language_peeled(hir, meter)
}

fn inspect_one_byte_language_peeled(
    hir: &Hir,
    meter: &mut Meter,
) -> Result<Option<[u64; 4]>, InspectionError> {
    match hir.kind() {
        HirKind::Class(Class::Bytes(class)) => {
            let mut words = [0_u64; 4];
            for range in class.ranges() {
                meter.charge(RANGE_INSPECTION_WORK)?;
                if range.start() > range.end() {
                    return Ok(None);
                }
                for byte in range.start()..=range.end() {
                    meter.charge(MEMBER_INSERTION_WORK)?;
                    let word = usize::from(byte >> 6);
                    let bit = u32::from(byte & 63);
                    words[word] |= 1_u64 << bit;
                }
            }
            Ok(Some(words))
        }
        HirKind::Literal(literal) if literal.0.len() == 1 => {
            meter.charge(MEMBER_INSERTION_WORK)?;
            let byte = literal.0[0];
            let word = usize::from(byte >> 6);
            let bit = u32::from(byte & 63);
            let mut words = [0_u64; 4];
            words[word] |= 1_u64 << bit;
            Ok(Some(words))
        }
        HirKind::Alternation(alternatives) if !alternatives.is_empty() => {
            let mut words = [0_u64; 4];
            for alternative in alternatives {
                let Some(branch) = inspect_one_byte_language(alternative, meter)? else {
                    return Ok(None);
                };
                for (word, branch_word) in words.iter_mut().zip(branch) {
                    meter.charge(BITMAP_WORD_WORK)?;
                    *word |= branch_word;
                }
            }
            Ok(Some(words))
        }
        HirKind::Class(Class::Unicode(_))
        | HirKind::Empty
        | HirKind::Literal(_)
        | HirKind::Look(_)
        | HirKind::Repetition(_)
        | HirKind::Capture(_)
        | HirKind::Concat(_)
        | HirKind::Alternation(_) => Ok(None),
    }
}

fn is_universal(words: [u64; 4], meter: &mut Meter) -> Result<bool, InspectionError> {
    let mut universal = true;
    for (word, expected) in words.into_iter().zip(UNIVERSAL_WORDS) {
        meter.charge(BITMAP_WORD_WORK)?;
        universal &= word == expected;
    }
    Ok(universal)
}

fn checked_add_width(
    left: usize,
    right: usize,
    meter: &mut Meter,
) -> Result<Option<usize>, InspectionError> {
    meter.charge(WIDTH_ARITHMETIC_WORK)?;
    Ok(left.checked_add(right))
}

fn peel_captures<'h>(
    mut hir: &'h Hir,
    meter: &mut Meter,
) -> Result<&'h Hir, InspectionError> {
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

    use super::{Descriptor, InspectionError, InspectionOutcome, inspect};

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

    fn eligible(pattern: &str, suffix: &[u8]) -> (Descriptor, u64) {
        let outcome = inspect(&parse_bytes(pattern), suffix, 0, u64::MAX).unwrap();
        let InspectionOutcome::Eligible(inspection) = outcome else {
            panic!("universal finite greedy corridor was refused: {pattern:?}");
        };
        (inspection.descriptor(), inspection.planner_work())
    }

    #[test]
    fn admitted_spellings_publish_exact_language_geometry() {
        for (pattern, suffix, expected) in [
            (
                r"(?s-u:.{2,16}.{2,48}XYZ)",
                b"XYZ".as_slice(),
                (4, 64, 7, 67, 3),
            ),
            (
                r"(?s-u:(?:[\x00-\x7F]|[\x80-\xFF]){2,32}.{6,96}WXYZ)",
                b"WXYZ".as_slice(),
                (8, 128, 12, 132, 4),
            ),
            (
                r"(?s-u:(?:\w|\W){0,4}Q)",
                b"Q".as_slice(),
                (0, 4, 1, 5, 1),
            ),
            (
                r"(?s-u:(.{2,3})((?:XYZ)))",
                b"XYZ".as_slice(),
                (2, 3, 5, 6, 3),
            ),
            (
                r"(?s-u:[\x00-\xFF]{2}Z)",
                b"Z".as_slice(),
                (2, 2, 3, 3, 1),
            ),
        ] {
            let (descriptor, _) = eligible(pattern, suffix);
            assert_eq!(
                (
                    descriptor.minimum_prefix_bytes(),
                    descriptor.maximum_prefix_bytes(),
                    descriptor.minimum_match_bytes(),
                    descriptor.maximum_match_bytes(),
                    descriptor.suffix_bytes(),
                ),
                expected,
                "pattern={pattern:?}",
            );
        }
    }

    #[test]
    fn every_two_range_partition_of_the_byte_universe_is_admitted() {
        for left_end in 0_u8..u8::MAX {
            let right_start = left_end.checked_add(1).expect("partition has a right half");
            let pattern = format!(
                r"(?s-u:(?:[\x00-\x{left_end:02X}]|[\x{right_start:02X}-\xFF]){{1,2}}X)",
            );
            let (descriptor, _) = eligible(&pattern, b"X");
            assert_eq!(descriptor.minimum_prefix_bytes(), 1);
            assert_eq!(descriptor.maximum_prefix_bytes(), 2);
        }
    }

    #[test]
    fn every_single_byte_hole_is_rejected() {
        for hole in 0_u8..=u8::MAX {
            let atom = match hole {
                0 => r"[\x01-\xFF]".to_owned(),
                u8::MAX => r"[\x00-\xFE]".to_owned(),
                _ => {
                    let left_end = hole.checked_sub(1).expect("nonzero hole");
                    let right_start = hole.checked_add(1).expect("nonterminal hole");
                    format!(
                        r"(?:[\x00-\x{left_end:02X}]|[\x{right_start:02X}-\xFF])",
                    )
                }
            };
            let pattern = format!(r"(?s-u:{atom}{{1,2}}X)");
            assert!(
                matches!(
                    inspect(&parse_bytes(&pattern), b"X", 0, u64::MAX).unwrap(),
                    InspectionOutcome::Ineligible { .. },
                ),
                "single-byte hole was admitted: hole={hole} pattern={pattern:?}",
            );
        }
    }

    #[test]
    fn the_entire_nonempty_literal_tail_is_bound() {
        let hir = parse_bytes(r"(?s-u:.{1,4}(XYZ))");
        assert!(matches!(
            inspect(&hir, b"XYZ", 0, u64::MAX).unwrap(),
            InspectionOutcome::Eligible(_),
        ));
        for suffix in [
            b"".as_slice(),
            b"YZ".as_slice(),
            b"WXYZ".as_slice(),
            b"XYQ".as_slice(),
        ] {
            assert!(matches!(
                inspect(&hir, suffix, 0, u64::MAX).unwrap(),
                InspectionOutcome::Ineligible { .. },
            ));
        }
    }

    #[test]
    fn priority_assertion_and_correlation_violations_fail_closed() {
        for pattern in [
            r"(?s-u:.{1,2}?X)",
            r"(?s-u:.{1,2}.{1,2}?X)",
            r"(?s-u:.{2}?X)",
            r"(?s-u:^.{1,2}X)",
            r"(?s-u:.{1,2}X$)",
            r"(?s-u:.{1,2}\bX)",
            r"(?-u:.{1,2}X)",
            r"(?s-u:[\x00-\xFE]{1,2}X)",
            r"(?s-u:a.{1,2}X)",
            r"(?s-u:.*X)",
            r"(?s-u:(?:.{1}|.{2})X)",
            r"(?s-u:(?:[\x00-\x7F]{2}|[\x80-\xFF]{2})X)",
            r"(?s-u:(?:[\x00-\x7F][\x80-\xFF]|[\x80-\xFF][\x00-\x7F])X)",
            r"(?s-u:(.{1,2}.{1,2})X)",
            r"(?s-u:.{1,2}[XY])",
            r"(?s-u:X)",
        ] {
            assert!(
                matches!(
                    inspect(&parse_bytes(pattern), b"X", 0, u64::MAX).unwrap(),
                    InspectionOutcome::Ineligible { .. },
                ),
                "invalid corridor was admitted: {pattern:?}",
            );
        }

        for pattern in [r"(?s:.{1,2}X)", r"(?s:\p{Greek}{1,2}X)"] {
            assert!(
                matches!(
                    inspect(&parse_unicode(pattern), b"X", 0, u64::MAX).unwrap(),
                    InspectionOutcome::Ineligible { .. },
                ),
                "Unicode scalar corridor was admitted: {pattern:?}",
            );
        }
    }

    #[test]
    fn planner_work_closes_at_exact_and_one_below_limits() {
        let hir = parse_bytes(
            r"(?s-u:(?:[\x00-\x7F]|[\x80-\xFF]){2,32}.{6,96}WXYZ)",
        );
        let initial_work = 19;
        let InspectionOutcome::Eligible(unlimited) =
            inspect(&hir, b"WXYZ", initial_work, u64::MAX).unwrap()
        else {
            panic!("resource fixture was refused");
        };
        let exact_work = unlimited.planner_work();
        assert!(exact_work > initial_work);
        let exact = inspect(&hir, b"WXYZ", initial_work, exact_work).unwrap();
        assert_eq!(exact.planner_work(), exact_work);
        assert_eq!(
            match exact {
                InspectionOutcome::Eligible(inspection) => inspection.descriptor(),
                InspectionOutcome::Ineligible { .. } => panic!("exact limit declined"),
            },
            unlimited.descriptor(),
        );

        let one_below = exact_work.checked_sub(1).expect("positive planner work");
        assert_eq!(
            inspect(&hir, b"WXYZ", initial_work, one_below),
            Err(InspectionError::WorkLimit {
                actual: one_below,
                needed: exact_work,
                limit: one_below,
            }),
        );
        assert_eq!(
            inspect(&hir, b"WXYZ", 2, 1),
            Err(InspectionError::WorkLimit {
                actual: 1,
                needed: 2,
                limit: 1,
            }),
        );
        assert_eq!(
            inspect(&hir, b"WXYZ", 0, 0),
            Err(InspectionError::WorkLimit {
                actual: 0,
                needed: 1,
                limit: 0,
            }),
        );
    }
}
