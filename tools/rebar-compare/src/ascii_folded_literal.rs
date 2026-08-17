//! Direct Count execution for ASCII case-insensitive literal alternatives.
//!
//! Admission is based only on a small literal-only source grammar and the
//! regex flags. The retained folded trie emits candidates in source order;
//! this module performs the ordinary non-overlapping leftmost-first reduction.

use fre_kernels::{
    FoldedLiteral, FoldedLiteralTrieBuildAttempt, FoldedLiteralTrieBuildLimits,
    FoldedLiteralTriePlan, FoldedLiteralTrieScanLimits, FoldedLiteralTrieScanUpperBounds,
    FoldedScalarClass,
};

use super::{CandidateRequest, ExecutionError, FreReduction, RunLimits};

pub(super) const PLAN: &str = "aggregate-ascii-casefold-literal-alternation-v1";

const MIN_ALTERNATIVES: usize = 2;
const MAX_ALTERNATIVES: usize = 64;
const MIN_LITERAL_BYTES: usize = 2;
const MAX_SOURCE_BYTES: usize = 4_096;

#[derive(Debug)]
pub(super) struct AsciiFoldedLiteralCount {
    plan: FoldedLiteralTriePlan,
    scan: FoldedLiteralTrieScanLimits,
    haystack_len: usize,
}

impl AsciiFoldedLiteralCount {
    pub(super) fn try_build(
        patterns: &[String],
        unicode: bool,
        case_insensitive: bool,
        haystack_len: usize,
        limits: &RunLimits,
    ) -> Result<Option<Self>, ExecutionError> {
        let [pattern] = patterns else {
            return Ok(None);
        };
        if unicode || !case_insensitive {
            return Ok(None);
        }
        let Some(literals) = inspect(pattern) else {
            return Ok(None);
        };

        let scalar_positions = literals
            .iter()
            .try_fold(0_usize, |total, literal| total.checked_add(literal.len()));
        let Some(scalar_positions) = scalar_positions else {
            return Err(ExecutionError::fault(
                "ASCII folded-literal scalar-position count overflow",
            ));
        };
        let Some(equivalent_scalars) = scalar_positions.checked_mul(2) else {
            return Err(ExecutionError::fault(
                "ASCII folded-literal equivalent-scalar count overflow",
            ));
        };
        let Some(states) = scalar_positions.checked_add(1) else {
            return Err(ExecutionError::fault(
                "ASCII folded-literal state count overflow",
            ));
        };

        let owned: Vec<Vec<Vec<char>>> = literals
            .iter()
            .map(|literal| {
                literal
                    .iter()
                    .map(|&byte| {
                        if byte.is_ascii_alphabetic() {
                            vec![
                                char::from(byte.to_ascii_uppercase()),
                                char::from(byte.to_ascii_lowercase()),
                            ]
                        } else {
                            vec![char::from(byte)]
                        }
                    })
                    .collect()
            })
            .collect();
        let classes: Vec<Vec<FoldedScalarClass<'_>>> = owned
            .iter()
            .map(|literal| {
                literal
                    .iter()
                    .map(|class| FoldedScalarClass::new(class))
                    .collect()
            })
            .collect();
        let sources: Vec<FoldedLiteral<'_>> = classes
            .iter()
            .map(|literal| FoldedLiteral::new(literal))
            .collect();
        let build_limits = FoldedLiteralTrieBuildLimits {
            max_patterns: limits.patterns_per_job.min(MAX_ALTERNATIVES),
            max_scalar_positions: limits.pattern_bytes_per_job.min(MAX_SOURCE_BYTES),
            max_equivalent_scalars: limits
                .pattern_bytes_per_job
                .min(MAX_SOURCE_BYTES)
                .saturating_mul(2),
            max_states: limits
                .pattern_bytes_per_job
                .min(MAX_SOURCE_BYTES)
                .saturating_add(1),
            max_transitions: limits
                .pattern_bytes_per_job
                .min(MAX_SOURCE_BYTES)
                .saturating_mul(2),
            max_work: limits.fre_aggregate_compile_work,
            max_persistent_bytes: limits.fre_aggregate_program_bytes,
            max_peak_bytes: limits.fre_aggregate_program_bytes,
            max_allocations: 3,
        };
        if scalar_positions > build_limits.max_scalar_positions
            || equivalent_scalars > build_limits.max_equivalent_scalars
            || states > build_limits.max_states
        {
            return Err(ExecutionError::unsupported(
                "ASCII folded-literal construction exceeds the caller limits",
            ));
        }
        let attempt = FoldedLiteralTriePlan::build(&sources, build_limits).map_err(|error| {
            ExecutionError::unsupported(format!(
                "ASCII folded-literal construction refused input: {error}"
            ))
        })?;
        let FoldedLiteralTrieBuildAttempt::Admitted(plan) = attempt else {
            return Err(ExecutionError::fault(
                "literal-only ASCII fold classes unexpectedly required dense fallback",
            ));
        };
        if plan.build_accounting().root_prefilter_needles == 0 {
            return Ok(None);
        }
        let upper = plan.scan_upper_bounds(haystack_len).map_err(|error| {
            ExecutionError::fault(format!(
                "ASCII folded-literal operation preflight failed: {error}"
            ))
        })?;
        let candidate_events = u64::try_from(upper.candidate_events).map_err(|_| {
            ExecutionError::fault("ASCII folded-literal candidate bound does not fit u64")
        })?;
        if candidate_events > limits.reducer_steps {
            return Err(ExecutionError::unsupported(format!(
                "ASCII folded-literal candidates require {candidate_events} reducer steps, limit is {}",
                limits.reducer_steps
            )));
        }
        Ok(Some(Self {
            plan,
            scan: exact_scan_limits(upper),
            haystack_len,
        }))
    }

    #[inline]
    pub(super) fn count(&self, haystack: &[u8]) -> Result<u64, ExecutionError> {
        if haystack.len() != self.haystack_len {
            return Err(ExecutionError::fault(format!(
                "ASCII folded-literal haystack length {} differs from prepared {}",
                haystack.len(),
                self.haystack_len
            )));
        }
        let mut consumed_through = 0_usize;
        let mut count = 0_u64;
        let mut pending = None;
        let mut order_violation = false;
        let mut overflow = false;
        self.plan
            .scan(haystack, self.scan, |candidate| match pending {
                None => pending = Some(candidate),
                Some(best) if candidate.start() == best.start() => {
                    if candidate.pattern_index() < best.pattern_index() {
                        pending = Some(candidate);
                    }
                }
                Some(best) if candidate.start() > best.start() => {
                    if best.start() >= consumed_through {
                        let Some(next) = count.checked_add(1) else {
                            overflow = true;
                            return;
                        };
                        count = next;
                        consumed_through = best.end();
                    }
                    pending = Some(candidate);
                }
                Some(_) => order_violation = true,
            })
            .map_err(|error| {
                ExecutionError::fault(format!("ASCII folded-literal operation failed: {error}"))
            })?;
        if let Some(best) = pending
            && best.start() >= consumed_through
        {
            count = count
                .checked_add(1)
                .ok_or_else(|| ExecutionError::fault("ASCII folded-literal Count overflow"))?;
        }
        if overflow {
            return Err(ExecutionError::fault("ASCII folded-literal Count overflow"));
        }
        if order_violation {
            return Err(ExecutionError::fault(
                "ASCII folded-literal candidate order violation",
            ));
        }
        Ok(count)
    }
}

pub(super) fn try_count(
    request: CandidateRequest<'_>,
    limits: &RunLimits,
) -> Result<Option<FreReduction>, ExecutionError> {
    let Some(plan) = AsciiFoldedLiteralCount::try_build(
        request.patterns,
        request.unicode,
        request.case_insensitive,
        request.haystack.len(),
        limits,
    )?
    else {
        return Ok(None);
    };
    let actual = plan.count(request.haystack)?;
    Ok(Some(FreReduction { actual, plan: PLAN }))
}

fn exact_scan_limits(upper: FoldedLiteralTrieScanUpperBounds) -> FoldedLiteralTrieScanLimits {
    FoldedLiteralTrieScanLimits {
        max_input_bytes: upper.input_bytes,
        max_candidate_starts: upper.candidate_starts,
        max_scalar_decodes: upper.scalar_decodes,
        max_decoded_scalars: upper.decoded_scalars,
        max_invalid_bytes: upper.invalid_bytes,
        max_source_byte_reads: upper.source_byte_reads,
        max_transition_probes: upper.transition_probes,
        max_candidate_events: upper.candidate_events,
        max_work: upper.work,
        max_scratch_bytes: upper.scratch_bytes,
    }
}

fn inspect(pattern: &str) -> Option<Vec<Vec<u8>>> {
    let source = pattern.as_bytes();
    if source.len() > MAX_SOURCE_BYTES {
        return None;
    }
    let mut literals = Vec::new();
    let mut start = 0_usize;
    for (index, &byte) in source.iter().enumerate() {
        if byte == b'|' {
            push_literal(source.get(start..index)?, &mut literals)?;
            start = index.checked_add(1)?;
        } else if !is_plain_ascii_literal(byte) {
            return None;
        }
    }
    push_literal(source.get(start..)?, &mut literals)?;
    (MIN_ALTERNATIVES..=MAX_ALTERNATIVES)
        .contains(&literals.len())
        .then_some(literals)
}

fn push_literal(literal: &[u8], output: &mut Vec<Vec<u8>>) -> Option<()> {
    if literal.len() < MIN_LITERAL_BYTES || output.len() == MAX_ALTERNATIVES {
        return None;
    }
    output.push(literal.to_vec());
    Some(())
}

const fn is_plain_ascii_literal(byte: u8) -> bool {
    byte.is_ascii()
        && byte >= b' '
        && !matches!(
            byte,
            b'\\'
                | b'.'
                | b'^'
                | b'$'
                | b'*'
                | b'+'
                | b'?'
                | b'('
                | b')'
                | b'['
                | b']'
                | b'{'
                | b'}'
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CurrentFreAggregateCounterReceiptStatus, current_fre_rebar_aggregate_operation_lifecycle,
    };

    fn reference(pattern: &str, haystack: &[u8]) -> u64 {
        regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .case_insensitive(true)
            .build()
            .unwrap()
            .find_iter(haystack)
            .count()
            .try_into()
            .unwrap()
    }

    #[test]
    fn exhaustive_leftmost_first_nonoverlap_oracle() {
        let patterns = [
            "ab|aBcd|ba",
            "ab|AB|bA",
            "aa|aab|ba",
            "aab|aa|ba",
            "a-|A#|ba",
        ];
        let alphabet = [b'a', b'A', b'b', b'B', b'-', b'#', b'\n', 0xFF];
        let limits = RunLimits::default();
        let mut haystacks = vec![Vec::new()];
        for length in 0..=6 {
            for pattern in patterns {
                let source = [pattern.to_string()];
                let plan = AsciiFoldedLiteralCount::try_build(
                    &source,
                    false,
                    true,
                    haystacks.first().map_or(0, Vec::len),
                    &limits,
                );
                // Each haystack in this generation has the same byte length.
                let plan = plan.unwrap().unwrap();
                let reference = regex::bytes::RegexBuilder::new(pattern)
                    .unicode(false)
                    .case_insensitive(true)
                    .build()
                    .unwrap();
                for haystack in &haystacks {
                    assert_eq!(
                        plan.count(haystack).unwrap(),
                        u64::try_from(reference.find_iter(haystack).count()).unwrap(),
                        "pattern={pattern:?} haystack={haystack:?}"
                    );
                }
            }
            if length < 6 {
                haystacks = haystacks
                    .iter()
                    .flat_map(|prefix| {
                        alphabet.iter().map(move |&byte| {
                            let mut word = prefix.clone();
                            word.push(byte);
                            word
                        })
                    })
                    .collect();
            }
        }
    }

    #[test]
    fn structural_refusals_and_exact_reducer_bound() {
        let mut limits = RunLimits::default();
        for (pattern, unicode, case_insensitive) in [
            ("ab|cd", true, true),
            ("ab|cd", false, false),
            ("ab", false, true),
            ("a|cd", false, true),
            ("ab|", false, true),
            ("ab|c.d", false, true),
            ("(ab|cd)", false, true),
            ("ab\\|cd", false, true),
            ("é|zz", false, true),
        ] {
            assert!(
                AsciiFoldedLiteralCount::try_build(
                    &[pattern.to_string()],
                    unicode,
                    case_insensitive,
                    8,
                    &limits,
                )
                .unwrap()
                .is_none(),
                "{pattern:?}"
            );
        }
        limits.reducer_steps = 15;
        assert!(
            AsciiFoldedLiteralCount::try_build(&["ab|cd".to_string()], false, true, 8, &limits,)
                .is_err()
        );
        limits.reducer_steps = 16;
        assert!(
            AsciiFoldedLiteralCount::try_build(&["ab|cd".to_string()], false, true, 8, &limits,)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn raw_and_retained_surfaces_publish_the_structural_route() {
        let patterns = [
            "Sherlock Holmes|John Watson|Irene Adler|Inspector Lestrade|Professor Moriarty"
                .to_string(),
        ];
        let haystack = b"sherlock holmes / JOHN WATSON / john watson / x";
        let expected = reference(&patterns[0], haystack);
        let raw = try_count(
            CandidateRequest {
                job_id: "synthetic/ascii-folded-literals",
                model: "count",
                patterns: &patterns,
                haystack,
                unicode: false,
                case_insensitive: true,
            },
            &RunLimits::default(),
        )
        .unwrap()
        .unwrap();
        assert_eq!((raw.actual, raw.plan), (expected, PLAN));

        let retained = current_fre_rebar_aggregate_operation_lifecycle(
            "count",
            &patterns,
            false,
            true,
            haystack.len(),
        )
        .unwrap();
        assert_eq!(retained.plan(), PLAN);
        assert_eq!(retained.execute(haystack).unwrap(), expected);
        assert!(retained.execute(&haystack[..haystack.len() - 1]).is_err());
        let diagnostic = retained.execute_with_counters(haystack).unwrap();
        assert_eq!(diagnostic.value(), expected);
        assert_eq!(
            diagnostic.receipt_status(),
            &CurrentFreAggregateCounterReceiptStatus::DirectSelectedPlan
        );
    }
}
