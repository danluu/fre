//! Late exact-shape admission for one finite greedy byte-class run between
//! two nonempty literal barriers.

use fre_kernels::{
    BoundedLiteralClassRunPlan, LiteralClassRunLiteralBuildError,
    LiteralClassRunLiteralBuildLimits, SimdDispatchContext,
};
use regex_syntax::hir::{Class, ClassBytes, Hir, HirKind};

const NODE_WORK: u64 = 1;
const ROLE_WORK: u64 = 1;
const LITERAL_BYTE_WORK: u64 = 1;
const RANGE_WORK: u64 = 1;
const MEMBER_WORK: u64 = 1;
const BOUNDARY_WORK: u64 = 1;
const ARITHMETIC_WORK: u64 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InspectionError {
    WorkLimit { needed: u64, limit: u64 },
    ArithmeticOverflow,
}

pub(crate) enum InspectionOutcome<'a> {
    Eligible(Inspection<'a>),
    Ineligible { planner_work: u64 },
}

impl InspectionOutcome<'_> {
    pub(crate) const fn planner_work(&self) -> u64 {
        match self {
            Self::Eligible(inspection) => inspection.planner_work,
            Self::Ineligible { planner_work } => *planner_work,
        }
    }
}

#[derive(Clone, Copy)]
enum InspectedClass<'a> {
    Bytes(&'a ClassBytes),
    Singleton(u8),
}

impl InspectedClass<'_> {
    fn ranges(self) -> InspectedRanges<'_> {
        InspectedRanges {
            class: self,
            index: 0,
        }
    }
}

struct InspectedRanges<'a> {
    class: InspectedClass<'a>,
    index: usize,
}

impl Iterator for InspectedRanges<'_> {
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
        self.index = self.index.checked_add(1)?;
        Some(range)
    }
}

struct ClassProof<'a> {
    source: InspectedClass<'a>,
    words: [u64; 4],
}

pub(crate) struct Inspection<'a> {
    prefix: &'a [u8],
    class: InspectedClass<'a>,
    suffix: &'a [u8],
    minimum: usize,
    maximum: usize,
    planner_work: u64,
}

impl Inspection<'_> {
    pub(crate) fn build(
        self,
        dispatch: SimdDispatchContext,
        limits: LiteralClassRunLiteralBuildLimits,
    ) -> Result<BoundedLiteralClassRunPlan, LiteralClassRunLiteralBuildError> {
        BoundedLiteralClassRunPlan::build_with_dispatch(
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

#[cold]
pub(crate) fn inspect(
    hir: &Hir,
    initial_work: u64,
    max_planner_work: u64,
) -> Result<InspectionOutcome<'_>, InspectionError> {
    let mut work = initial_work;
    let root = peel_captures(hir, &mut work, max_planner_work)?;
    let HirKind::Concat(parts) = root.kind() else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: work,
        });
    };
    charge_count(&mut work, parts.len(), ROLE_WORK, max_planner_work)?;
    let [prefix_hir, repetition_hir, suffix_hir] = parts.as_slice() else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: work,
        });
    };
    let Some(prefix) = literal(prefix_hir, &mut work, max_planner_work)? else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: work,
        });
    };
    let Some(suffix) = literal(suffix_hir, &mut work, max_planner_work)? else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: work,
        });
    };
    if prefix.is_empty() || suffix.is_empty() {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: work,
        });
    }

    let repetition_hir = peel_captures(repetition_hir, &mut work, max_planner_work)?;
    let HirKind::Repetition(repetition) = repetition_hir.kind() else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: work,
        });
    };
    charge(&mut work, ROLE_WORK, max_planner_work)?;
    let Some(maximum) = repetition.max else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: work,
        });
    };
    if !repetition.greedy || maximum < repetition.min {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: work,
        });
    }
    let minimum = usize::try_from(repetition.min)
        .map_err(|_| InspectionError::ArithmeticOverflow)?;
    let maximum =
        usize::try_from(maximum).map_err(|_| InspectionError::ArithmeticOverflow)?;
    let Some(class) = inspected_class(&repetition.sub, &mut work, max_planner_work)? else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: work,
        });
    };

    charge(&mut work, BOUNDARY_WORK, max_planner_work)?;
    if class_contains(class.words, *prefix.last().expect("nonempty prefix was checked")) {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: work,
        });
    }
    charge(&mut work, BOUNDARY_WORK, max_planner_work)?;
    if class_contains(class.words, suffix[0]) {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: work,
        });
    }

    charge(&mut work, ARITHMETIC_WORK, max_planner_work)?;
    let fixed = prefix
        .len()
        .checked_add(suffix.len())
        .ok_or(InspectionError::ArithmeticOverflow)?;
    charge(&mut work, ARITHMETIC_WORK, max_planner_work)?;
    fixed
        .checked_add(maximum)
        .ok_or(InspectionError::ArithmeticOverflow)?;

    Ok(InspectionOutcome::Eligible(Inspection {
        prefix,
        class: class.source,
        suffix,
        minimum,
        maximum,
        planner_work: work,
    }))
}

fn literal<'a>(
    hir: &'a Hir,
    work: &mut u64,
    limit: u64,
) -> Result<Option<&'a [u8]>, InspectionError> {
    let hir = peel_captures(hir, work, limit)?;
    let HirKind::Literal(literal) = hir.kind() else {
        return Ok(None);
    };
    charge_count(work, literal.0.len(), LITERAL_BYTE_WORK, limit)?;
    Ok(Some(&literal.0))
}

fn inspected_class<'a>(
    hir: &'a Hir,
    work: &mut u64,
    limit: u64,
) -> Result<Option<ClassProof<'a>>, InspectionError> {
    let hir = peel_captures(hir, work, limit)?;
    match hir.kind() {
        HirKind::Literal(literal) if literal.0.len() == 1 => {
            charge(work, LITERAL_BYTE_WORK, limit)?;
            charge(work, MEMBER_WORK, limit)?;
            let byte = literal.0[0];
            let mut words = [0; 4];
            insert(&mut words, byte);
            Ok(Some(ClassProof {
                source: InspectedClass::Singleton(byte),
                words,
            }))
        }
        HirKind::Class(Class::Bytes(class)) if !class.ranges().is_empty() => {
            let mut words = [0; 4];
            for range in class.ranges() {
                charge(work, RANGE_WORK, limit)?;
                for byte in range.start()..=range.end() {
                    charge(work, MEMBER_WORK, limit)?;
                    insert(&mut words, byte);
                }
            }
            Ok(Some(ClassProof {
                source: InspectedClass::Bytes(class),
                words,
            }))
        }
        _ => Ok(None),
    }
}

fn peel_captures<'a>(
    mut hir: &'a Hir,
    work: &mut u64,
    limit: u64,
) -> Result<&'a Hir, InspectionError> {
    loop {
        charge(work, NODE_WORK, limit)?;
        let HirKind::Capture(capture) = hir.kind() else {
            return Ok(hir);
        };
        hir = &capture.sub;
    }
}

fn insert(words: &mut [u64; 4], byte: u8) {
    words[usize::from(byte >> 6)] |= 1_u64 << u32::from(byte & 63);
}

fn class_contains(words: [u64; 4], byte: u8) -> bool {
    words[usize::from(byte >> 6)] & (1_u64 << u32::from(byte & 63)) != 0
}

fn charge_count(
    work: &mut u64,
    count: usize,
    per_item: u64,
    limit: u64,
) -> Result<(), InspectionError> {
    let count = u64::try_from(count).map_err(|_| InspectionError::ArithmeticOverflow)?;
    let additional = count
        .checked_mul(per_item)
        .ok_or(InspectionError::ArithmeticOverflow)?;
    charge(work, additional, limit)
}

fn charge(work: &mut u64, additional: u64, limit: u64) -> Result<(), InspectionError> {
    let needed = work
        .checked_add(additional)
        .ok_or(InspectionError::ArithmeticOverflow)?;
    if needed > limit {
        return Err(InspectionError::WorkLimit { needed, limit });
    }
    *work = needed;
    Ok(())
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
    fn admits_only_finite_greedy_two_barrier_runs() {
        for pattern in [r"ab[0-9]{0,8}xy", r"(ab)([0-9]{2,8})(xy)"] {
            assert!(matches!(
                inspect(&hir(pattern), 0, u64::MAX).unwrap(),
                InspectionOutcome::Eligible(_)
            ));
        }
        for pattern in [
            r"[0-9]{2,8}xy",
            r"ab[0-9]{2,8}",
            r"ab[b0-9]{2,8}xy",
            r"ab[0-9]{2,8}3y",
            r"ab[0-9]{2,8}?xy",
            r"ab[0-9]+xy",
            r"ab.{2,8}xy",
        ] {
            assert!(matches!(
                inspect(&hir(pattern), 0, u64::MAX).unwrap(),
                InspectionOutcome::Ineligible { .. }
            ));
        }
    }

    #[test]
    fn planner_work_is_cumulative_and_refuses_at_the_exact_next_charge() {
        let hir = hir(r"ab[0-9]{2,8}xy");
        let baseline = inspect(&hir, 7, u64::MAX).unwrap().planner_work();
        assert_eq!(
            inspect(&hir, 7, baseline).unwrap().planner_work(),
            baseline
        );
        assert!(matches!(
            inspect(&hir, 7, baseline - 1),
            Err(InspectionError::WorkLimit { needed, limit })
                if needed == baseline && limit == baseline - 1
        ));
    }
}
