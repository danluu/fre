//! Canonical-HIR proofs for the fixed absolute-domain aggregate route.

use fre_aggregate::CompiledRegex;
use fre_kernels::{
    FixedAbsoluteDomainBuildError, FixedAbsoluteDomainBuildLimits,
    FixedAbsoluteDomainBuildProspective, FixedAbsoluteDomainByteMask, FixedAbsoluteDomainPlan,
};
use regex_syntax::hir::{
    Class, ClassBytes, ClassBytesRange, ClassUnicode, ClassUnicodeRange, Hir, HirKind, Look,
};

use crate::aggregate::AggregateOperation;

/// Bounded structural classification before the optional selector.
/// `ProvenEligible` is deliberately limited to small canonical skeletons so a
/// one-below planner cap remains a typed U1 refusal. `Possible` may be
/// inspected, but exhaustion is then only an optional miss; it can never make
/// a formerly admitted continuation request terminal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Candidate {
    ProvenEligible,
    Possible,
    Ineligible,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CandidateInspection {
    pub(crate) candidate: Candidate,
    pub(crate) work: usize,
    pub(crate) exhausted: bool,
}

const CANDIDATE_NODE_LIMIT: usize = 16;
const CANDIDATE_PAYLOAD_LIMIT: usize = 512;
const CANDIDATE_INSPECTION_ENVELOPE: usize = 2_048;

fn candidate_add_bounded(total: &mut usize, amount: usize, limit: usize) -> bool {
    let Some(next) = total.checked_add(amount) else {
        return false;
    };
    if next > limit {
        return false;
    }
    *total = next;
    true
}

pub(crate) fn classify_candidate_with_limit(
    hir: &Hir,
    unicode: bool,
    operation: AggregateOperation,
    limit: usize,
) -> CandidateInspection {
    let mut meter = CandidateMeter { work: 0, limit };
    let candidate = classify_candidate_metered(hir, unicode, operation, &mut meter);
    CandidateInspection {
        candidate: candidate.unwrap_or(Candidate::Possible),
        work: meter.work,
        exhausted: candidate.is_err(),
    }
}

fn classify_candidate_metered(
    hir: &Hir,
    unicode: bool,
    operation: AggregateOperation,
    meter: &mut CandidateMeter,
) -> Result<Candidate, ()> {
    let Some(root) = meter.peel(hir)? else {
        return Ok(Candidate::Possible);
    };
    let HirKind::Concat(parts) = root.kind() else {
        return Ok(Candidate::Ineligible);
    };
    meter.charge(1)?;
    let Some(first_hir) = parts.first() else {
        return Ok(Candidate::Ineligible);
    };
    let Some(first) = meter.peel(first_hir)? else {
        return Ok(Candidate::Possible);
    };
    let Some(last_hir) = parts.last() else {
        return Ok(Candidate::Ineligible);
    };
    let Some(last) = meter.peel(last_hir)? else {
        return Ok(Candidate::Possible);
    };
    let starts = matches!(first.kind(), HirKind::Look(Look::Start));
    let ends = matches!(last.kind(), HirKind::Look(Look::End));
    meter.charge(1)?;
    match operation {
        AggregateOperation::Count if starts && ends => {
            classify_count_candidate(parts, unicode, meter)
        }
        AggregateOperation::SpanSum if !unicode && starts ^ ends => {
            classify_span_sum_candidate(parts, starts, meter)
        }
        AggregateOperation::Count
        | AggregateOperation::SpanSum
        | AggregateOperation::Compile
        | AggregateOperation::Spans => Ok(Candidate::Ineligible),
    }
}

fn classify_count_candidate(
    parts: &[Hir],
    unicode: bool,
    meter: &mut CandidateMeter,
) -> Result<Candidate, ()> {
    meter.charge(1)?;
    let [_start, body, _end] = parts else {
        return Ok(Candidate::Ineligible);
    };
    let Some(body) = meter.peel(body)? else {
        return Ok(Candidate::Possible);
    };
    if unicode {
        let HirKind::Repetition(repetition) = body.kind() else {
            return Ok(Candidate::Ineligible);
        };
        meter.charge(1)?;
        if repetition.max != Some(repetition.min) || repetition.min == 0 || !repetition.greedy {
            return Ok(Candidate::Ineligible);
        }
        let Some(sub) = meter.peel(&repetition.sub)? else {
            return Ok(Candidate::Possible);
        };
        meter.charge(1)?;
        if usize::try_from(repetition.min).map_or(true, |count| count > CANDIDATE_PAYLOAD_LIMIT) {
            return Ok(Candidate::Possible);
        }
        meter.charge(1)?;
        let HirKind::Class(Class::Unicode(class)) = sub.kind() else {
            return Ok(Candidate::Ineligible);
        };
        if class.ranges().is_empty() {
            return Ok(Candidate::Ineligible);
        }
        meter.charge(class.ranges().len())?;
        if class.ranges().len() > CANDIDATE_PAYLOAD_LIMIT {
            return Ok(Candidate::Possible);
        }
        return Ok(Candidate::ProvenEligible);
    }
    Ok(match body.kind() {
        HirKind::Repetition(repetition) => {
            let Some(maximum) = repetition.max else {
                return Ok(Candidate::Ineligible);
            };
            meter.charge(1)?;
            if repetition.min == 0 || maximum < repetition.min || !repetition.greedy {
                return Ok(Candidate::Ineligible);
            }
            let Some(sub) = meter.peel(&repetition.sub)? else {
                return Ok(Candidate::Possible);
            };
            meter.charge(1)?;
            if usize::try_from(maximum).map_or(true, |count| count > CANDIDATE_PAYLOAD_LIMIT) {
                return Ok(Candidate::Possible);
            }
            match sub.kind() {
                HirKind::Literal(literal) if literal.0.len() == 1 => Candidate::ProvenEligible,
                _ => Candidate::Ineligible,
            }
        }
        HirKind::Alternation(branches) if branches.len() > 1 => {
            meter.charge(1)?;
            if branches.len() > CANDIDATE_NODE_LIMIT {
                return Ok(Candidate::Possible);
            }
            let mut payload = 0_usize;
            let mut inspection = 0_usize;
            for branch in branches {
                let before = meter.work;
                let Some(branch) = meter.peel(branch)? else {
                    return Ok(Candidate::Possible);
                };
                let peel_work = meter.work.checked_sub(before).ok_or(())?;
                meter.charge(1)?;
                let HirKind::Literal(literal) = branch.kind() else {
                    return Ok(Candidate::Ineligible);
                };
                if literal.0.is_empty() {
                    return Ok(Candidate::Ineligible);
                }
                if !candidate_add_bounded(&mut payload, literal.0.len(), CANDIDATE_PAYLOAD_LIMIT)
                    || !candidate_add_bounded(
                        &mut inspection,
                        literal.0.len(),
                        CANDIDATE_INSPECTION_ENVELOPE,
                    )
                    || !candidate_add_bounded(
                        &mut inspection,
                        peel_work,
                        CANDIDATE_INSPECTION_ENVELOPE,
                    )
                {
                    return Ok(Candidate::Possible);
                }
            }
            Candidate::ProvenEligible
        }
        _ => Candidate::Ineligible,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the bounded classifier keeps each charged canonical-HIR shape decision in one audit boundary"
)]
fn classify_span_sum_candidate(
    parts: &[Hir],
    starts: bool,
    meter: &mut CandidateMeter,
) -> Result<Candidate, ()> {
    meter.charge(1)?;
    if starts {
        let [_start, prefix, alternatives] = parts else {
            return Ok(Candidate::Ineligible);
        };
        let Some(prefix) = meter.peel(prefix)? else {
            return Ok(Candidate::Possible);
        };
        meter.charge(1)?;
        let HirKind::Literal(prefix) = prefix.kind() else {
            return Ok(Candidate::Ineligible);
        };
        if prefix.0.is_empty() {
            return Ok(Candidate::Ineligible);
        }
        if prefix.0.len() > CANDIDATE_PAYLOAD_LIMIT {
            return Ok(Candidate::Possible);
        }
        let Some(alternatives) = meter.peel(alternatives)? else {
            return Ok(Candidate::Possible);
        };
        return Ok(match alternatives.kind() {
            HirKind::Class(Class::Bytes(class)) if !class.ranges().is_empty() => {
                meter.charge(class.ranges().len())?;
                let mut cardinality = 0_usize;
                for range in class.ranges() {
                    if !candidate_add_bounded(
                        &mut cardinality,
                        range.len(),
                        CANDIDATE_PAYLOAD_LIMIT,
                    ) {
                        return Ok(Candidate::Possible);
                    }
                }
                let inspection = prefix
                    .0
                    .len()
                    .checked_add(class.ranges().len())
                    .and_then(|work| work.checked_add(cardinality.checked_mul(2)?));
                if prefix
                    .0
                    .len()
                    .checked_add(cardinality)
                    .is_none_or(|payload| payload > CANDIDATE_PAYLOAD_LIMIT)
                    || inspection.is_none_or(|work| work > CANDIDATE_INSPECTION_ENVELOPE)
                {
                    return Ok(Candidate::Possible);
                }
                Candidate::ProvenEligible
            }
            HirKind::Class(Class::Unicode(class)) => {
                meter.charge(1)?;
                if !class
                    .ranges()
                    .last()
                    .is_some_and(|range| range.end().is_ascii())
                {
                    return Ok(Candidate::Ineligible);
                }
                meter.charge(class.ranges().len())?;
                let mut cardinality = 0_usize;
                for range in class.ranges() {
                    if !candidate_add_bounded(
                        &mut cardinality,
                        range.len(),
                        CANDIDATE_PAYLOAD_LIMIT,
                    ) {
                        return Ok(Candidate::Possible);
                    }
                }
                let inspection = prefix
                    .0
                    .len()
                    .checked_add(1)
                    .and_then(|work| work.checked_add(class.ranges().len()))
                    .and_then(|work| work.checked_add(cardinality.checked_mul(2)?));
                if prefix
                    .0
                    .len()
                    .checked_add(cardinality)
                    .is_none_or(|payload| payload > CANDIDATE_PAYLOAD_LIMIT)
                    || inspection.is_none_or(|work| work > CANDIDATE_INSPECTION_ENVELOPE)
                {
                    return Ok(Candidate::Possible);
                }
                Candidate::ProvenEligible
            }
            HirKind::Alternation(branches) if branches.len() > 1 => {
                meter.charge(1)?;
                if branches.len() > CANDIDATE_NODE_LIMIT {
                    return Ok(Candidate::Possible);
                }
                let mut inspection = prefix.0.len();
                for branch in branches {
                    let before = meter.work;
                    let Some(branch) = meter.peel(branch)? else {
                        return Ok(Candidate::Possible);
                    };
                    let peel_work = meter.work.checked_sub(before).ok_or(())?;
                    meter.charge(1)?;
                    if !matches!(branch.kind(), HirKind::Literal(literal) if literal.0.len() == 1) {
                        return Ok(Candidate::Ineligible);
                    }
                    if !candidate_add_bounded(
                        &mut inspection,
                        peel_work,
                        CANDIDATE_INSPECTION_ENVELOPE,
                    ) {
                        return Ok(Candidate::Possible);
                    }
                }
                if prefix
                    .0
                    .len()
                    .checked_add(branches.len())
                    .is_none_or(|payload| payload > CANDIDATE_PAYLOAD_LIMIT)
                {
                    return Ok(Candidate::Possible);
                }
                Candidate::ProvenEligible
            }
            _ => Candidate::Ineligible,
        });
    }
    if parts.len() <= 1 {
        return Ok(Candidate::Ineligible);
    }
    if let [repeat_hir, suffix_hir, _end] = parts {
        let Some(repeat_hir) = meter.peel(repeat_hir)? else {
            return Ok(Candidate::Possible);
        };
        if let HirKind::Repetition(repetition) = repeat_hir.kind() {
            meter.charge(1)?;
            if repetition.min != 0 || repetition.max.is_some() || !repetition.greedy {
                return Ok(Candidate::Ineligible);
            }
            let Some(class_hir) = meter.peel(&repetition.sub)? else {
                return Ok(Candidate::Possible);
            };
            meter.charge(1)?;
            let HirKind::Class(Class::Bytes(class)) = class_hir.kind() else {
                return Ok(Candidate::Ineligible);
            };
            if class.ranges().is_empty() {
                return Ok(Candidate::Ineligible);
            }
            meter.charge(class.ranges().len())?;
            let mut cardinality = 0_usize;
            for range in class.ranges() {
                if !candidate_add_bounded(&mut cardinality, range.len(), CANDIDATE_PAYLOAD_LIMIT) {
                    return Ok(Candidate::Possible);
                }
            }
            let Some(suffix_hir) = meter.peel(suffix_hir)? else {
                return Ok(Candidate::Possible);
            };
            meter.charge(1)?;
            let HirKind::Literal(suffix) = suffix_hir.kind() else {
                return Ok(Candidate::Ineligible);
            };
            if suffix.0.is_empty() {
                return Ok(Candidate::Ineligible);
            }
            meter.charge(suffix.0.len())?;
            if suffix.0.len() > CANDIDATE_PAYLOAD_LIMIT {
                return Ok(Candidate::Possible);
            }
            return Ok(Candidate::ProvenEligible);
        }
    }
    meter.charge(1)?;
    if parts.len() > CANDIDATE_NODE_LIMIT {
        return Ok(Candidate::Possible);
    }
    let mut positions = 0_usize;
    let mut payload = 0_usize;
    let mut inspection = 0_usize;
    let Some((_end, body)) = parts.split_last() else {
        return Ok(Candidate::Ineligible);
    };
    for part in body {
        let before = meter.work;
        let Some(part) = meter.peel(part)? else {
            return Ok(Candidate::Possible);
        };
        let peel_work = meter.work.checked_sub(before).ok_or(())?;
        match part.kind() {
            HirKind::Literal(literal) if !literal.0.is_empty() => {
                meter.charge(1)?;
                let Some(lowering) = peel_work.checked_mul(literal.0.len()) else {
                    return Ok(Candidate::Possible);
                };
                if !candidate_add_bounded(&mut positions, literal.0.len(), CANDIDATE_PAYLOAD_LIMIT)
                    || !candidate_add_bounded(
                        &mut payload,
                        literal.0.len(),
                        CANDIDATE_PAYLOAD_LIMIT,
                    )
                    || !candidate_add_bounded(
                        &mut inspection,
                        literal.0.len(),
                        CANDIDATE_INSPECTION_ENVELOPE,
                    )
                    || !candidate_add_bounded(
                        &mut inspection,
                        lowering,
                        CANDIDATE_INSPECTION_ENVELOPE,
                    )
                {
                    return Ok(Candidate::Possible);
                }
            }
            HirKind::Class(Class::Bytes(class)) if !class.ranges().is_empty() => {
                meter.charge(class.ranges().len())?;
                let mut cardinality = 0_usize;
                for range in class.ranges() {
                    if !candidate_add_bounded(
                        &mut cardinality,
                        range.len(),
                        CANDIDATE_PAYLOAD_LIMIT,
                    ) {
                        return Ok(Candidate::Possible);
                    }
                }
                if !candidate_add_bounded(&mut positions, 1, CANDIDATE_PAYLOAD_LIMIT)
                    || !candidate_add_bounded(&mut payload, cardinality, CANDIDATE_PAYLOAD_LIMIT)
                    || !candidate_add_bounded(
                        &mut inspection,
                        class.ranges().len(),
                        CANDIDATE_INSPECTION_ENVELOPE,
                    )
                    || !candidate_add_bounded(
                        &mut inspection,
                        peel_work,
                        CANDIDATE_INSPECTION_ENVELOPE,
                    )
                    || !candidate_add_bounded(
                        &mut inspection,
                        cardinality,
                        CANDIDATE_INSPECTION_ENVELOPE,
                    )
                {
                    return Ok(Candidate::Possible);
                }
            }
            _ => return Ok(Candidate::Ineligible),
        }
    }
    Ok(Candidate::ProvenEligible)
}

struct CandidateMeter {
    work: usize,
    limit: usize,
}

impl CandidateMeter {
    fn charge(&mut self, amount: usize) -> Result<(), ()> {
        let needed = self.work.checked_add(amount).ok_or(())?;
        if needed > self.limit {
            return Err(());
        }
        self.work = needed;
        Ok(())
    }

    fn peel<'a>(&mut self, mut hir: &'a Hir) -> Result<Option<&'a Hir>, ()> {
        for _ in 0..=CANDIDATE_NODE_LIMIT {
            self.charge(1)?;
            let HirKind::Capture(capture) = hir.kind() else {
                return Ok(Some(hir));
            };
            hir = &capture.sub;
        }
        Ok(None)
    }
}

pub(crate) enum Inspection<'a> {
    Eligible {
        shape: Shape<'a>,
        work: usize,
        hir_nodes: usize,
        captures: usize,
    },
    Ineligible {
        work: usize,
    },
}

pub(crate) enum Shape<'a> {
    EndMaskSequence(MaskSource<'a>),
    EndOneByteMask(FixedAbsoluteDomainByteMask),
    EndGreedyClassLiteral {
        class: FixedAbsoluteDomainByteMask,
        suffix: &'a [u8],
    },
    WholeByteRepeat {
        byte: u8,
        minimum: u32,
        maximum: u32,
    },
    WholeOrderedWords(WordSource<'a>),
    StartOrderedPrefix {
        prefix: &'a [u8],
        alternatives: AlternativeSource<'a>,
    },
    WholeScalarEnvelope {
        scalars: u32,
        class: &'a ClassUnicode,
    },
}

#[allow(
    clippy::result_large_err,
    reason = "kernel build refusals retain their complete allocation-free prospective/actual receipt"
)]
impl Shape<'_> {
    pub(crate) fn guard_prospective(
        &self,
    ) -> Result<FixedAbsoluteDomainBuildProspective, FixedAbsoluteDomainBuildError> {
        match self {
            Self::EndMaskSequence(source) => {
                FixedAbsoluteDomainPlan::end_mask_sequence_prospective(source.positions)
            }
            Self::EndOneByteMask(mask) => {
                FixedAbsoluteDomainPlan::end_one_byte_mask_prospective(*mask)
            }
            Self::EndGreedyClassLiteral { class, suffix } => {
                FixedAbsoluteDomainPlan::end_greedy_class_literal_prospective(*class, suffix.len())
            }
            Self::WholeByteRepeat {
                byte,
                minimum,
                maximum,
            } => FixedAbsoluteDomainPlan::whole_byte_repeat_prospective(*byte, *minimum, *maximum),
            Self::WholeOrderedWords(source) => {
                FixedAbsoluteDomainPlan::whole_ordered_words_prospective(
                    source.word_count,
                    source.word_bytes,
                )
            }
            Self::StartOrderedPrefix {
                prefix,
                alternatives,
            } => FixedAbsoluteDomainPlan::start_ordered_prefix_prospective(
                prefix.len(),
                alternatives.iter().len(),
            ),
            Self::WholeScalarEnvelope { scalars, class } => {
                FixedAbsoluteDomainPlan::whole_scalar_envelope_prospective(
                    *scalars,
                    class.ranges().len(),
                )
            }
        }
    }

    pub(crate) fn scalar_guard_prospective(
        &self,
    ) -> Result<Option<FixedAbsoluteDomainBuildProspective>, FixedAbsoluteDomainBuildError> {
        match self {
            Self::WholeScalarEnvelope { scalars, class } => {
                FixedAbsoluteDomainPlan::whole_scalar_envelope_prospective(
                    *scalars,
                    class.ranges().len(),
                )
                .map(Some)
            }
            _ => Ok(None),
        }
    }

    pub(crate) fn build(
        &self,
        limits: FixedAbsoluteDomainBuildLimits,
    ) -> Result<FixedAbsoluteDomainPlan, FixedAbsoluteDomainBuildError> {
        match self {
            Self::EndMaskSequence(source) => {
                FixedAbsoluteDomainPlan::build_end_mask_sequence(source.iter(), limits)
            }
            Self::EndOneByteMask(mask) => {
                FixedAbsoluteDomainPlan::build_end_one_byte_mask(*mask, limits)
            }
            Self::EndGreedyClassLiteral { class, suffix } => {
                FixedAbsoluteDomainPlan::build_end_greedy_class_literal(*class, suffix, limits)
            }
            Self::WholeByteRepeat {
                byte,
                minimum,
                maximum,
            } => {
                FixedAbsoluteDomainPlan::build_whole_byte_repeat(*byte, *minimum, *maximum, limits)
            }
            Self::WholeOrderedWords(source) => {
                FixedAbsoluteDomainPlan::build_whole_ordered_words_precounted(
                    source.word_count,
                    source.word_bytes,
                    source.iter(),
                    limits,
                )
            }
            Self::StartOrderedPrefix {
                prefix,
                alternatives,
            } => FixedAbsoluteDomainPlan::build_start_ordered_prefix(
                prefix,
                alternatives.iter(),
                limits,
            ),
            Self::WholeScalarEnvelope { scalars, class } => {
                FixedAbsoluteDomainPlan::build_whole_scalar_envelope_precounted(
                    *scalars,
                    class.ranges().len(),
                    class
                        .ranges()
                        .iter()
                        .map(|range| (u32::from(range.start()), u32::from(range.end()))),
                    limits,
                )
            }
        }
    }

    /// Exact heap-allocation census for the eagerly compiled continuation of
    /// the canonical whole-scalar envelope. This mirrors the compiler's
    /// allocation-free HIR-stack growth, state-vector growth, scalar-set
    /// ownership, retained program copy, and six certification vectors.
    pub(crate) fn scalar_residual_compile_allocations(
        &self,
        hir: &Hir,
        limit: usize,
    ) -> Result<Option<(usize, usize)>, InspectionError> {
        let Self::WholeScalarEnvelope { scalars, .. } = self else {
            return Ok(None);
        };
        let mut work = 0_usize;
        let mut stack_capacity = CompiledRegex::pinned_hir_stack_initial_capacity();
        let mut stack_allocations = 1_usize;
        census_validation_stack(
            hir,
            0,
            &mut stack_capacity,
            &mut stack_allocations,
            &mut work,
            limit,
        )?;

        let class = scalar_envelope_class(hir, &mut work, limit)?;
        charge_census(&mut work, limit, 1)?;
        let maximum_width = class
            .ranges()
            .last()
            .map_or(0, |range| range.end().len_utf8());
        if maximum_width == 0 {
            return Err(InspectionError::Overflow);
        }
        let scalar_count = usize::try_from(*scalars).map_err(|_| InspectionError::Overflow)?;
        let states = scalar_count
            .checked_mul(maximum_width)
            .and_then(|states| states.checked_add(3))
            .ok_or(InspectionError::Overflow)?;
        let mut state_capacity = 0_usize;
        let mut state_allocations = 0_usize;
        while state_capacity < states {
            charge_census(&mut work, limit, 1)?;
            let required = state_capacity
                .checked_add(1)
                .ok_or(InspectionError::Overflow)?;
            let grown = CompiledRegex::pinned_state_capacity_after_push(state_capacity, required)
                .ok_or(InspectionError::Overflow)?;
            if grown < required || grown <= state_capacity {
                return Err(InspectionError::Overflow);
            }
            state_capacity = grown;
            state_allocations = state_allocations
                .checked_add(1)
                .ok_or(InspectionError::Overflow)?;
        }
        charge_census(&mut work, limit, 1)?;
        let allocations = stack_allocations
            .checked_add(state_allocations)
            .and_then(|total| total.checked_add(scalar_count))
            // One retained-state allocation and six nonempty certification
            // vectors (outgoing, parent counts, offsets, parents, queue, order).
            .and_then(|total| total.checked_add(7))
            .ok_or(InspectionError::Overflow)?;
        Ok(Some((allocations, work)))
    }
}

fn scalar_envelope_class<'a>(
    hir: &'a Hir,
    work: &mut usize,
    limit: usize,
) -> Result<&'a ClassUnicode, InspectionError> {
    let root = peel_census(hir, work, limit)?;
    let HirKind::Concat(parts) = root.kind() else {
        return Err(InspectionError::Overflow);
    };
    charge_census(work, limit, 1)?;
    let core = parts.get(1).ok_or(InspectionError::Overflow)?;
    let body = peel_census(core, work, limit)?;
    let HirKind::Repetition(repetition) = body.kind() else {
        return Err(InspectionError::Overflow);
    };
    let sub = peel_census(&repetition.sub, work, limit)?;
    let HirKind::Class(Class::Unicode(class)) = sub.kind() else {
        return Err(InspectionError::Overflow);
    };
    Ok(class)
}

fn census_validation_stack(
    hir: &Hir,
    pending: usize,
    capacity: &mut usize,
    allocations: &mut usize,
    work: &mut usize,
    limit: usize,
) -> Result<(), InspectionError> {
    charge_census(work, limit, 1)?;
    let children: &[Hir] = match hir.kind() {
        HirKind::Capture(capture) => core::slice::from_ref(capture.sub.as_ref()),
        HirKind::Repetition(repetition) => core::slice::from_ref(repetition.sub.as_ref()),
        HirKind::Concat(children) | HirKind::Alternation(children) => children,
        HirKind::Empty | HirKind::Literal(_) | HirKind::Class(_) | HirKind::Look(_) => &[],
    };
    for index in 0..children.len() {
        charge_census(work, limit, 1)?;
        let required = pending
            .checked_add(index)
            .and_then(|length| length.checked_add(1))
            .ok_or(InspectionError::Overflow)?;
        if required > *capacity {
            let grown = CompiledRegex::pinned_hir_stack_capacity_after_push(*capacity, required)
                .ok_or(InspectionError::Overflow)?;
            if grown < required || grown <= *capacity {
                return Err(InspectionError::Overflow);
            }
            *capacity = grown;
            *allocations = allocations
                .checked_add(1)
                .ok_or(InspectionError::Overflow)?;
        }
    }
    for index in (0..children.len()).rev() {
        census_validation_stack(
            &children[index],
            pending
                .checked_add(index)
                .ok_or(InspectionError::Overflow)?,
            capacity,
            allocations,
            work,
            limit,
        )?;
    }
    Ok(())
}

fn peel_census<'a>(
    mut hir: &'a Hir,
    work: &mut usize,
    limit: usize,
) -> Result<&'a Hir, InspectionError> {
    loop {
        charge_census(work, limit, 1)?;
        let HirKind::Capture(capture) = hir.kind() else {
            return Ok(hir);
        };
        hir = &capture.sub;
    }
}

fn charge_census(work: &mut usize, limit: usize, amount: usize) -> Result<(), InspectionError> {
    let needed = work.checked_add(amount).ok_or(InspectionError::Overflow)?;
    if needed > limit {
        return Err(InspectionError::WorkLimit {
            needed,
            consumed: *work,
        });
    }
    *work = needed;
    Ok(())
}

#[derive(Clone, Copy)]
pub(crate) struct MaskSource<'a> {
    parts: &'a [Hir],
    positions: usize,
}

impl MaskSource<'_> {
    fn iter(&self) -> MaskIter<'_> {
        MaskIter {
            parts: self.parts,
            part: 0,
            literal_offset: 0,
            remaining: self.positions,
        }
    }
}

#[derive(Clone, Copy)]
struct MaskIter<'a> {
    parts: &'a [Hir],
    part: usize,
    literal_offset: usize,
    remaining: usize,
}

#[allow(
    clippy::copy_iterator,
    reason = "the small borrowed iterator is intentionally Copy so prospective and construction traverse identical sources without allocation"
)]
impl Iterator for MaskIter<'_> {
    type Item = FixedAbsoluteDomainByteMask;

    fn next(&mut self) -> Option<Self::Item> {
        if self.part < self.parts.len() {
            let hir = peel_readonly(&self.parts[self.part]);
            match hir.kind() {
                HirKind::Literal(literal) => {
                    let byte = *literal.0.get(self.literal_offset)?;
                    self.literal_offset = self.literal_offset.checked_add(1)?;
                    if self.literal_offset == literal.0.len() {
                        self.part = self.part.checked_add(1)?;
                        self.literal_offset = 0;
                    }
                    self.remaining = self.remaining.checked_sub(1)?;
                    return Some(FixedAbsoluteDomainByteMask::inclusive(byte, byte));
                }
                HirKind::Class(Class::Bytes(class)) => {
                    let mut mask = FixedAbsoluteDomainByteMask::default();
                    for range in class.ranges() {
                        mask.insert_inclusive(range.start(), range.end());
                    }
                    self.part = self.part.checked_add(1)?;
                    self.remaining = self.remaining.checked_sub(1)?;
                    return Some(mask);
                }
                _ => return None,
            }
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for MaskIter<'_> {}
impl core::iter::FusedIterator for MaskIter<'_> {}

#[derive(Clone, Copy)]
pub(crate) struct WordSource<'a> {
    branches: &'a [Hir],
    word_count: usize,
    word_bytes: usize,
}

impl WordSource<'_> {
    fn iter(&self) -> WordIter<'_> {
        WordIter {
            inner: self.branches.iter(),
        }
    }
}

#[derive(Clone)]
struct WordIter<'a> {
    inner: core::slice::Iter<'a, Hir>,
}

impl<'a> Iterator for WordIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let hir = peel_readonly(self.inner.next()?);
        let HirKind::Literal(literal) = hir.kind() else {
            return None;
        };
        Some(literal.0.as_ref())
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl ExactSizeIterator for WordIter<'_> {}
impl core::iter::FusedIterator for WordIter<'_> {}

#[derive(Clone, Copy)]
pub(crate) enum AlternativeSource<'a> {
    Class {
        class: &'a ClassBytes,
        bytes: usize,
    },
    AsciiUnicodeClass {
        class: &'a ClassUnicode,
        bytes: usize,
    },
    SingletonBranches(&'a [Hir]),
}

impl AlternativeSource<'_> {
    fn iter(&self) -> AlternativeIter<'_> {
        match *self {
            Self::Class { class, bytes } => AlternativeIter::Class {
                ranges: class.ranges(),
                range_index: 0,
                next_in_range: None,
                remaining: bytes,
            },
            Self::AsciiUnicodeClass { class, bytes } => AlternativeIter::AsciiUnicodeClass {
                ranges: class.ranges(),
                range_index: 0,
                next_in_range: None,
                remaining: bytes,
            },
            Self::SingletonBranches(branches) => AlternativeIter::SingletonBranches {
                branches: branches.iter(),
            },
        }
    }
}

#[derive(Clone)]
enum AlternativeIter<'a> {
    Class {
        ranges: &'a [ClassBytesRange],
        range_index: usize,
        next_in_range: Option<u8>,
        remaining: usize,
    },
    AsciiUnicodeClass {
        ranges: &'a [ClassUnicodeRange],
        range_index: usize,
        next_in_range: Option<char>,
        remaining: usize,
    },
    SingletonBranches {
        branches: core::slice::Iter<'a, Hir>,
    },
}

impl Iterator for AlternativeIter<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Class {
                ranges,
                range_index,
                next_in_range,
                remaining,
            } => {
                if *remaining == 0 {
                    return None;
                }
                let range = ranges.get(*range_index)?;
                let byte = next_in_range.unwrap_or_else(|| range.start());
                if byte == range.end() {
                    *range_index = range_index.checked_add(1)?;
                    *next_in_range = None;
                } else {
                    *next_in_range = byte.checked_add(1);
                }
                *remaining = remaining.checked_sub(1)?;
                Some(byte)
            }
            Self::AsciiUnicodeClass {
                ranges,
                range_index,
                next_in_range,
                remaining,
            } => {
                if *remaining == 0 {
                    return None;
                }
                let range = ranges.get(*range_index)?;
                let scalar = next_in_range.unwrap_or_else(|| range.start());
                if scalar == range.end() {
                    *range_index = range_index.checked_add(1)?;
                    *next_in_range = None;
                } else {
                    *next_in_range = char::from_u32(u32::from(scalar).checked_add(1)?);
                }
                *remaining = remaining.checked_sub(1)?;
                u8::try_from(u32::from(scalar)).ok()
            }
            Self::SingletonBranches { branches } => {
                let hir = peel_readonly(branches.next()?);
                let HirKind::Literal(literal) = hir.kind() else {
                    return None;
                };
                let [byte] = literal.0.as_ref() else {
                    return None;
                };
                Some(*byte)
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = match self {
            Self::Class { remaining, .. } | Self::AsciiUnicodeClass { remaining, .. } => *remaining,
            Self::SingletonBranches { branches } => branches.len(),
        };
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for AlternativeIter<'_> {}
impl core::iter::FusedIterator for AlternativeIter<'_> {}

pub(crate) enum InspectionError {
    WorkLimit { needed: usize, consumed: usize },
    Overflow,
}

pub(crate) fn inspect(
    hir: &Hir,
    unicode: bool,
    operation: AggregateOperation,
    limit: usize,
) -> Result<Inspection<'_>, InspectionError> {
    let mut visitor = Visitor {
        work: 0,
        limit,
        hir_nodes: 0,
        captures: 0,
    };
    let root = visitor.peel(hir)?;
    let HirKind::Concat(parts) = root.kind() else {
        return Ok(Inspection::Ineligible { work: visitor.work });
    };
    if parts.len() < 2 {
        return Ok(Inspection::Ineligible { work: visitor.work });
    }

    let shape = match (unicode, operation) {
        (false, AggregateOperation::SpanSum) => inspect_byte_span_sum(parts, &mut visitor)?,
        (false, AggregateOperation::Count) => inspect_byte_count(parts, &mut visitor)?,
        (true, AggregateOperation::Count) => inspect_scalar_count(parts, &mut visitor)?,
        _ => None,
    };
    let Some(shape) = shape else {
        return Ok(Inspection::Ineligible { work: visitor.work });
    };
    Ok(Inspection::Eligible {
        shape,
        work: visitor.work,
        hir_nodes: visitor.hir_nodes,
        captures: visitor.captures,
    })
}

fn inspect_byte_span_sum<'a>(
    parts: &'a [Hir],
    visitor: &mut Visitor,
) -> Result<Option<Shape<'a>>, InspectionError> {
    let first_start = visitor.probe_look(&parts[0], Look::Start)?;
    let last_index = parts
        .len()
        .checked_sub(1)
        .ok_or(InspectionError::Overflow)?;
    let last_end = visitor.probe_look(&parts[last_index], Look::End)?;
    if last_end && !first_start {
        let core = &parts[..last_index];
        // A failed shape probe may have traversed some nodes that the
        // incumbent mask inspector must subsequently own. Preserve all
        // charged work, but commit node/capture ownership only when this
        // route succeeds so the authenticated syntax census remains exact.
        let mut terminal_trial = *visitor;
        if let Some(shape) = inspect_end_greedy_class_literal(core, &mut terminal_trial)? {
            *visitor = terminal_trial;
            visitor.expect_look(&parts[last_index], Look::End)?;
            return Ok(Some(shape));
        }
        visitor.work = terminal_trial.work;
        let Some(positions) = visitor.inspect_masks(core)? else {
            return Ok(None);
        };
        visitor.expect_look(&parts[last_index], Look::End)?;
        let source = MaskSource {
            parts: core,
            positions,
        };
        return Ok(Some(if positions == 1 {
            Shape::EndOneByteMask(source.iter().next().ok_or(InspectionError::Overflow)?)
        } else {
            Shape::EndMaskSequence(source)
        }));
    }
    if first_start && !last_end {
        visitor.expect_look(&parts[0], Look::Start)?;
        let core = &parts[1..];
        return inspect_start_prefix(core, visitor);
    }
    Ok(None)
}

fn inspect_end_greedy_class_literal<'a>(
    core: &'a [Hir],
    visitor: &mut Visitor,
) -> Result<Option<Shape<'a>>, InspectionError> {
    let [repeat_hir, suffix_hir] = core else {
        return Ok(None);
    };
    let repeat_hir = visitor.peel(repeat_hir)?;
    let HirKind::Repetition(repetition) = repeat_hir.kind() else {
        return Ok(None);
    };
    if repetition.min != 0 || repetition.max.is_some() || !repetition.greedy {
        return Ok(None);
    }
    let class_hir = visitor.peel(&repetition.sub)?;
    let HirKind::Class(Class::Bytes(class)) = class_hir.kind() else {
        return Ok(None);
    };
    if class.ranges().is_empty() {
        return Ok(None);
    }
    visitor.charge(class.ranges().len())?;
    let mut mask = FixedAbsoluteDomainByteMask::default();
    for range in class.ranges() {
        visitor.charge(range.len())?;
        mask.insert_inclusive(range.start(), range.end());
    }
    let suffix_hir = visitor.peel(suffix_hir)?;
    let HirKind::Literal(suffix) = suffix_hir.kind() else {
        return Ok(None);
    };
    if suffix.0.is_empty() {
        return Ok(None);
    }
    visitor.charge(suffix.0.len())?;
    Ok(Some(Shape::EndGreedyClassLiteral {
        class: mask,
        suffix: suffix.0.as_ref(),
    }))
}

fn inspect_start_prefix<'a>(
    core: &'a [Hir],
    visitor: &mut Visitor,
) -> Result<Option<Shape<'a>>, InspectionError> {
    let [prefix_hir, alternatives_hir] = core else {
        return Ok(None);
    };
    let prefix_hir = visitor.peel(prefix_hir)?;
    let HirKind::Literal(literal) = prefix_hir.kind() else {
        return Ok(None);
    };
    if literal.0.is_empty() {
        return Ok(None);
    }
    visitor.charge(literal.0.len())?;

    let alternatives_hir = visitor.peel(alternatives_hir)?;
    let alternatives = match alternatives_hir.kind() {
        HirKind::Class(Class::Bytes(class)) if !class.ranges().is_empty() => {
            visitor.charge(class.ranges().len())?;
            let mut alternatives = 0_usize;
            for range in class.ranges() {
                alternatives = alternatives
                    .checked_add(range.len())
                    .ok_or(InspectionError::Overflow)?;
            }
            visitor.charge(alternatives)?;
            // Reserve the per-byte range lookup/comparison repeated by the
            // lowering iterator after selection.
            visitor.charge(alternatives)?;
            AlternativeSource::Class {
                class,
                bytes: alternatives,
            }
        }
        HirKind::Class(Class::Unicode(class)) => {
            // Canonical Unicode ranges are ordered, so the final endpoint is
            // the complete ASCII test. Reserve that comparison before
            // reading it, including the ineligible path.
            visitor.charge(1)?;
            if !class
                .ranges()
                .last()
                .is_some_and(|range| range.end().is_ascii())
            {
                return Ok(None);
            }
            visitor.charge(class.ranges().len())?;
            let mut alternatives = 0_usize;
            for range in class.ranges() {
                alternatives = alternatives
                    .checked_add(range.len())
                    .ok_or(InspectionError::Overflow)?;
            }
            visitor.charge(alternatives)?;
            visitor.charge(alternatives)?;
            AlternativeSource::AsciiUnicodeClass {
                class,
                bytes: alternatives,
            }
        }
        HirKind::Alternation(branches) if branches.len() > 1 => {
            for branch in branches {
                let work_before_peel = visitor.work;
                let branch = visitor.peel(branch)?;
                let future_peel_work = visitor
                    .work
                    .checked_sub(work_before_peel)
                    .ok_or(InspectionError::Overflow)?;
                let HirKind::Literal(literal) = branch.kind() else {
                    return Ok(None);
                };
                visitor.charge(literal.0.len())?;
                let [_] = literal.0.as_ref() else {
                    return Ok(None);
                };
                // `AlternativeIter::SingletonBranches` peels this branch once
                // more while lowering into the kernel builder.
                visitor.charge(future_peel_work)?;
            }
            AlternativeSource::SingletonBranches(branches)
        }
        _ => return Ok(None),
    };
    Ok(Some(Shape::StartOrderedPrefix {
        prefix: literal.0.as_ref(),
        alternatives,
    }))
}

fn inspect_byte_count<'a>(
    parts: &'a [Hir],
    visitor: &mut Visitor,
) -> Result<Option<Shape<'a>>, InspectionError> {
    let Some(core) = inspect_whole_anchors(parts, visitor)? else {
        return Ok(None);
    };
    if core.len() != 1 {
        return Ok(None);
    }
    let body = visitor.peel(&core[0])?;
    match body.kind() {
        HirKind::Repetition(repetition) => {
            let Some(maximum) = repetition.max else {
                return Ok(None);
            };
            if repetition.min == 0 || !repetition.greedy {
                return Ok(None);
            }
            let sub = visitor.peel(&repetition.sub)?;
            let HirKind::Literal(literal) = sub.kind() else {
                return Ok(None);
            };
            visitor.charge(literal.0.len())?;
            let [byte] = literal.0.as_ref() else {
                return Ok(None);
            };
            Ok(Some(Shape::WholeByteRepeat {
                byte: *byte,
                minimum: repetition.min,
                maximum,
            }))
        }
        HirKind::Alternation(branches) if branches.len() > 1 => {
            let mut word_bytes = 0_usize;
            for branch in branches {
                let work_before_peel = visitor.work;
                let branch = visitor.peel(branch)?;
                let future_peel_work = visitor
                    .work
                    .checked_sub(work_before_peel)
                    .ok_or(InspectionError::Overflow)?;
                let HirKind::Literal(literal) = branch.kind() else {
                    return Ok(None);
                };
                if literal.0.is_empty() {
                    return Ok(None);
                }
                visitor.charge(literal.0.len())?;
                word_bytes = word_bytes
                    .checked_add(literal.0.len())
                    .ok_or(InspectionError::Overflow)?;
                // The precounted kernel builder consumes `WordIter` exactly
                // once while copying the retained program.
                visitor.charge(future_peel_work)?;
            }
            Ok(Some(Shape::WholeOrderedWords(WordSource {
                branches,
                word_count: branches.len(),
                word_bytes,
            })))
        }
        _ => Ok(None),
    }
}

fn inspect_scalar_count<'a>(
    parts: &'a [Hir],
    visitor: &mut Visitor,
) -> Result<Option<Shape<'a>>, InspectionError> {
    let Some(core) = inspect_whole_anchors(parts, visitor)? else {
        return Ok(None);
    };
    if core.len() != 1 {
        return Ok(None);
    }
    let body = visitor.peel(&core[0])?;
    let HirKind::Repetition(repetition) = body.kind() else {
        return Ok(None);
    };
    if repetition.max != Some(repetition.min) || repetition.min == 0 || !repetition.greedy {
        return Ok(None);
    }
    let sub = visitor.peel(&repetition.sub)?;
    let HirKind::Class(Class::Unicode(class)) = sub.kind() else {
        return Ok(None);
    };
    if class.ranges().is_empty() {
        return Ok(None);
    }
    visitor.charge(class.ranges().len())?;
    Ok(Some(Shape::WholeScalarEnvelope {
        scalars: repetition.min,
        class,
    }))
}

fn inspect_whole_anchors<'a>(
    parts: &'a [Hir],
    visitor: &mut Visitor,
) -> Result<Option<&'a [Hir]>, InspectionError> {
    let last = parts
        .len()
        .checked_sub(1)
        .ok_or(InspectionError::Overflow)?;
    if !visitor.probe_look(&parts[0], Look::Start)?
        || !visitor.probe_look(&parts[last], Look::End)?
    {
        return Ok(None);
    }
    visitor.expect_look(&parts[0], Look::Start)?;
    visitor.expect_look(&parts[last], Look::End)?;
    Ok(Some(&parts[1..last]))
}

#[derive(Clone, Copy)]
struct Visitor {
    work: usize,
    limit: usize,
    hir_nodes: usize,
    captures: usize,
}

impl Visitor {
    fn charge(&mut self, amount: usize) -> Result<(), InspectionError> {
        let needed = self
            .work
            .checked_add(amount)
            .ok_or(InspectionError::Overflow)?;
        if needed > self.limit {
            return Err(InspectionError::WorkLimit {
                needed,
                consumed: self.work,
            });
        }
        self.work = needed;
        Ok(())
    }

    fn peel<'a>(&mut self, mut hir: &'a Hir) -> Result<&'a Hir, InspectionError> {
        loop {
            self.charge(1)?;
            self.hir_nodes = self
                .hir_nodes
                .checked_add(1)
                .ok_or(InspectionError::Overflow)?;
            let HirKind::Capture(capture) = hir.kind() else {
                return Ok(hir);
            };
            self.captures = self
                .captures
                .checked_add(1)
                .ok_or(InspectionError::Overflow)?;
            hir = &capture.sub;
        }
    }

    fn probe_look(&mut self, hir: &Hir, expected: Look) -> Result<bool, InspectionError> {
        let mut current = hir;
        loop {
            self.charge(1)?;
            let HirKind::Capture(capture) = current.kind() else {
                return Ok(matches!(current.kind(), HirKind::Look(actual) if *actual == expected));
            };
            current = &capture.sub;
        }
    }

    fn expect_look(&mut self, hir: &Hir, expected: Look) -> Result<(), InspectionError> {
        let hir = self.peel(hir)?;
        if matches!(hir.kind(), HirKind::Look(actual) if *actual == expected) {
            Ok(())
        } else {
            Err(InspectionError::Overflow)
        }
    }

    fn inspect_masks(&mut self, parts: &[Hir]) -> Result<Option<usize>, InspectionError> {
        if parts.is_empty() {
            return Ok(None);
        }
        let mut positions = 0_usize;
        for part in parts {
            let work_before_peel = self.work;
            let hir = self.peel(part)?;
            let future_peel_work = self
                .work
                .checked_sub(work_before_peel)
                .ok_or(InspectionError::Overflow)?;
            match hir.kind() {
                HirKind::Literal(literal) if !literal.0.is_empty() => {
                    self.charge(literal.0.len())?;
                    self.charge(
                        future_peel_work
                            .checked_mul(literal.0.len())
                            .ok_or(InspectionError::Overflow)?,
                    )?;
                    positions = positions
                        .checked_add(literal.0.len())
                        .ok_or(InspectionError::Overflow)?;
                }
                HirKind::Class(Class::Bytes(class)) if !class.ranges().is_empty() => {
                    self.charge(class.ranges().len())?;
                    let insertion_work =
                        class.ranges().iter().try_fold(0_usize, |total, range| {
                            total
                                .checked_add(range.len())
                                .ok_or(InspectionError::Overflow)
                        })?;
                    self.charge(
                        future_peel_work
                            .checked_add(insertion_work)
                            .ok_or(InspectionError::Overflow)?,
                    )?;
                    positions = positions.checked_add(1).ok_or(InspectionError::Overflow)?;
                }
                _ => return Ok(None),
            }
        }
        Ok(Some(positions))
    }
}

fn peel_readonly(mut hir: &Hir) -> &Hir {
    loop {
        let HirKind::Capture(capture) = hir.kind() else {
            return hir;
        };
        hir = &capture.sub;
    }
}
