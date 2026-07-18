use fre_kernels::{
    REQUIRED_INTERNAL_ANCHOR_MAX_OPTIONAL_STAGES, RequiredInternalAnchorBuildError as BuildError,
    RequiredInternalAnchorBuildLimits as BuildLimits, RequiredInternalAnchorByteClass as ByteClass,
    RequiredInternalAnchorContinuationSource as ContinuationSource,
    RequiredInternalAnchorOptionalStageSource as OptionalStageSource,
    RequiredInternalAnchorPlan as Plan,
};
use regex_syntax::hir::{Class, Hir, HirKind, Repetition};

use crate::{Error, Resource};

pub(crate) struct Inspection {
    pub(crate) plan: Option<Plan>,
    pub(crate) inspection_work: usize,
}

impl Inspection {
    const fn refused(inspection_work: usize) -> Self {
        Self {
            plan: None,
            inspection_work,
        }
    }
}

/// Inspect the canonical HIR for the first admitted verifier configuration.
///
/// This is deliberately structural: no pattern text, cache key, job name, or
/// expected result is available here. The admitted grammar is documented by
/// the kernel. A later verifier configuration can share its candidate stream
/// without weakening this proof.
pub(crate) fn inspect(
    hir: &Hir,
    max_work: usize,
    max_literal_bytes: usize,
    max_program_bytes: usize,
) -> Result<Inspection, Error> {
    let mut budget = Budget::new(max_work);
    let root = transparent(hir, &mut budget)?;
    let HirKind::Concat(parts) = root.kind() else {
        return Ok(Inspection::refused(budget.work));
    };
    if !(4..=4 + REQUIRED_INTERNAL_ANCHOR_MAX_OPTIONAL_STAGES).contains(&parts.len()) {
        return Ok(Inspection::refused(budget.work));
    }

    let Some(prefix) = one_or_more_class(&parts[0], &mut budget)? else {
        return Ok(Inspection::refused(budget.work));
    };
    let anchor = transparent(&parts[1], &mut budget)?;
    let HirKind::Literal(anchor) = anchor.kind() else {
        return Ok(Inspection::refused(budget.work));
    };
    charge(&mut budget, anchor.0.len())?;
    if anchor.0.is_empty() {
        return Ok(Inspection::refused(budget.work));
    }
    let Some(head) = one_or_more_class(&parts[2], &mut budget)? else {
        return Ok(Inspection::refused(budget.work));
    };
    let Some(tail) = one_or_more_class(&parts[3], &mut budget)? else {
        return Ok(Inspection::refused(budget.work));
    };

    let mut continuation = ContinuationSource::new(head, tail);
    for (index, optional) in parts[4..].iter().enumerate() {
        let Some(stage) = optional_stage(optional, &mut budget)? else {
            return Ok(Inspection::refused(budget.work));
        };
        continuation.optional[index] = Some(stage);
    }
    let optional_count = parts.len().checked_sub(4).ok_or(Error::InternalInvariant(
        "required internal-anchor concat lost mandatory fields",
    ))?;
    continuation.optional_count =
        u8::try_from(optional_count).map_err(|_| Error::ArithmeticOverflow {
            resource: Resource::CompileWork,
        })?;

    let build_work_upper_bound =
        Plan::build_work_upper_bound(anchor.0.len(), continuation.optional_count).map_err(
            |error| match error {
                BuildError::Overflow(_) => Error::ArithmeticOverflow {
                    resource: Resource::CompileWork,
                },
                _ => Error::InternalInvariant("required internal-anchor work derivation refused"),
            },
        )?;
    charge(&mut budget, build_work_upper_bound)?;
    let plan = build_plan(
        prefix,
        &anchor.0,
        &continuation,
        build_work_upper_bound,
        max_literal_bytes,
        max_program_bytes,
    )?;
    Ok(Inspection {
        plan,
        inspection_work: budget.work,
    })
}

fn build_plan(
    prefix: ByteClass,
    anchor: &[u8],
    continuation: &ContinuationSource,
    max_build_work: usize,
    max_literal_bytes: usize,
    max_program_bytes: usize,
) -> Result<Option<Plan>, Error> {
    let limits = BuildLimits {
        max_anchor_bytes: max_literal_bytes,
        max_build_work,
        max_persistent_bytes: max_program_bytes,
        max_peak_bytes: max_program_bytes,
        max_allocations: 1,
        max_reserves: 1,
        max_source_copies: 1,
        max_scratch_bytes: 0,
    };
    let plan = match Plan::build(prefix, anchor, *continuation, limits) {
        Ok(plan) => plan,
        Err(BuildError::AllocationFailed { additional }) => {
            return Err(Error::AllocationFailed {
                resource: Resource::ProgramBytes,
                items: additional,
            });
        }
        Err(
            BuildError::AnchorLimit { needed, limit }
            | BuildError::PersistentLimit { needed, limit }
            | BuildError::PeakLimit { needed, limit },
        ) => {
            return Err(Error::ResourceLimit {
                resource: Resource::ProgramBytes,
                required: needed,
                limit,
            });
        }
        Err(BuildError::WorkLimit { needed, limit }) => {
            return Err(Error::ResourceLimit {
                resource: Resource::CompileWork,
                required: needed,
                limit,
            });
        }
        Err(BuildError::Overflow(_)) => {
            return Err(Error::ArithmeticOverflow {
                resource: Resource::CompileWork,
            });
        }
        Err(
            BuildError::EmptyPrefix
            | BuildError::EmptyAnchor
            | BuildError::AnchorStartsInPrefix { .. }
            | BuildError::OverlappingAnchor { .. }
            | BuildError::EmptyHead
            | BuildError::EmptyTail
            | BuildError::HeadNotSubsetOfTail
            | BuildError::OptionalCount { .. }
            | BuildError::MissingOptional { .. }
            | BuildError::UnexpectedOptional { .. }
            | BuildError::DuplicateIntroducer { .. }
            | BuildError::IntroducerInPrecedingClass { .. }
            | BuildError::EmptyOptionalClass { .. }
            | BuildError::AllocationLimit { .. }
            | BuildError::ReserveLimit { .. }
            | BuildError::SourceCopyLimit { .. }
            | BuildError::ScratchLimit { .. },
        ) => return Ok(None),
        Err(BuildError::AccountingInvariant { .. }) => {
            return Err(Error::InternalInvariant(
                "required internal-anchor build accounting exceeded its envelope",
            ));
        }
        Err(_) => {
            return Err(Error::InternalInvariant(
                "unclassified required internal-anchor build refusal",
            ));
        }
    };
    Ok(Some(plan))
}

fn one_or_more_class(hir: &Hir, budget: &mut Budget) -> Result<Option<ByteClass>, Error> {
    let hir = transparent(hir, budget)?;
    let HirKind::Repetition(repetition) = hir.kind() else {
        return Ok(None);
    };
    charge(budget, 1)?;
    if repetition.min != 1 || repetition.max.is_some() || !repetition.greedy {
        return Ok(None);
    }
    byte_class(repetition, budget)
}

fn optional_stage(hir: &Hir, budget: &mut Budget) -> Result<Option<OptionalStageSource>, Error> {
    let hir = transparent(hir, budget)?;
    let HirKind::Repetition(optional) = hir.kind() else {
        return Ok(None);
    };
    charge(budget, 1)?;
    if optional.min != 0 || optional.max != Some(1) || !optional.greedy {
        return Ok(None);
    }
    let body = transparent(optional.sub.as_ref(), budget)?;
    let HirKind::Concat(parts) = body.kind() else {
        return Ok(None);
    };
    if parts.len() != 2 {
        return Ok(None);
    }
    let introducer = transparent(&parts[0], budget)?;
    let HirKind::Literal(introducer) = introducer.kind() else {
        return Ok(None);
    };
    charge(budget, introducer.0.len())?;
    let [introducer] = introducer.0.as_ref() else {
        return Ok(None);
    };
    let body = transparent(&parts[1], budget)?;
    let HirKind::Repetition(repetition) = body.kind() else {
        return Ok(None);
    };
    charge(budget, 1)?;
    if repetition.min != 0 || repetition.max.is_some() || !repetition.greedy {
        return Ok(None);
    }
    let Some(class) = byte_class(repetition, budget)? else {
        return Ok(None);
    };
    Ok(Some(OptionalStageSource {
        introducer: *introducer,
        class,
    }))
}

fn byte_class(repetition: &Repetition, budget: &mut Budget) -> Result<Option<ByteClass>, Error> {
    let hir = transparent(repetition.sub.as_ref(), budget)?;
    let mut output = ByteClass::default();
    match hir.kind() {
        HirKind::Class(Class::Bytes(class)) => {
            for range in class.ranges() {
                charge(budget, 1)?;
                output.insert_inclusive(range.start(), range.end());
            }
        }
        HirKind::Literal(literal) if literal.0.len() == 1 => {
            charge(budget, 1)?;
            output.insert_inclusive(literal.0[0], literal.0[0]);
        }
        _ => return Ok(None),
    }
    Ok((!output.is_empty()).then_some(output))
}

fn transparent<'a>(mut hir: &'a Hir, budget: &mut Budget) -> Result<&'a Hir, Error> {
    loop {
        charge(budget, 1)?;
        let HirKind::Capture(capture) = hir.kind() else {
            return Ok(hir);
        };
        hir = capture.sub.as_ref();
    }
}

struct Budget {
    work: usize,
    limit: usize,
}

impl Budget {
    const fn new(limit: usize) -> Self {
        Self { work: 0, limit }
    }
}

fn charge(budget: &mut Budget, amount: usize) -> Result<(), Error> {
    let needed = budget
        .work
        .checked_add(amount)
        .ok_or(Error::ArithmeticOverflow {
            resource: Resource::CompileWork,
        })?;
    if needed > budget.limit {
        return Err(Error::ResourceLimit {
            resource: Resource::CompileWork,
            required: needed,
            limit: budget.limit,
        });
    }
    budget.work = needed;
    Ok(())
}

#[cfg(test)]
mod tests {
    use regex_syntax::ParserBuilder;

    use crate::{
        CompileLimits, CompiledRegex, Error, OperationLimits, Resource, RustByteProfile, Strategy,
    };

    use super::inspect;

    const URI: &str = r"[\w]+://[^/\s?#]+[^\s?#]+(?:\?[^\s#]*)?(?:#[^\s]*)?";

    fn parse(pattern: &str) -> regex_syntax::hir::Hir {
        ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(pattern)
            .unwrap()
    }

    #[test]
    fn uri_configuration_is_derived_from_hir_and_retained_by_compilation() {
        let hir = parse(URI);
        let inspected = inspect(&hir, 1 << 20, 1 << 20, 1 << 20).unwrap();
        let plan = inspected.plan.as_ref().expect("required-anchor plan");
        assert_eq!(plan.anchor(), b"://");
        assert_eq!(plan.build_accounting().optional_stages, 2);

        let compiled = CompiledRegex::from_hir(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        let accounting = compiled.compile_accounting();
        assert_eq!(accounting.required_internal_anchors, 1);
        assert_eq!(accounting.required_internal_anchor_bytes, 3);
        assert_eq!(accounting.required_internal_anchor_optional_stages, 2);
        assert!(accounting.required_internal_anchor_build_work > 0);
        assert!(
            accounting.required_internal_anchor_build_work
                <= accounting.required_internal_anchor_build_work_upper_bound
        );
    }

    #[test]
    fn anchored_count_matches_pinned_bytes_semantics_on_priority_adversaries() {
        for (pattern, haystack) in [
            (URI, b"://a/b".as_slice()),
            (URI, b"x://a".as_slice()),
            (URI, b"x://a/".as_slice()),
            (URI, b"bad://x good://a/b?q=x#f\xFF".as_slice()),
            (URI, b"x://a/b://c/d y://a/b".as_slice()),
            (URI, b"x://a/b\r\ny://c/d\n\tz://e/f".as_slice()),
            (URI, b"\xFFx://a/\xFE?q=\xFD#\xFC y://c/d".as_slice()),
            (URI, b"x://a/one?two?three#four#five".as_slice()),
            (r"a+Xb+[ab]+", b"aXbaaaXba".as_slice()),
            (r"a+Xb+[ab]+", b"aXc aXbba".as_slice()),
        ] {
            let hir = parse(pattern);
            let compiled = CompiledRegex::from_hir(
                &hir,
                RustByteProfile::PINNED_1_12_4,
                CompileLimits::default(),
            )
            .unwrap();
            assert_eq!(compiled.compile_accounting().required_internal_anchors, 1);
            let actual = compiled
                .count_value(
                    haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    OperationLimits::default(),
                )
                .unwrap();
            let expected = regex::bytes::RegexBuilder::new(pattern)
                .unicode(false)
                .build()
                .unwrap()
                .find_iter(haystack)
                .count();
            assert_eq!(
                actual, expected,
                "pattern={pattern:?}, haystack={haystack:?}"
            );
        }
    }

    #[test]
    fn uri_count_uses_only_the_authenticated_operation_range() {
        let compiled = CompiledRegex::from_hir(
            &parse(URI),
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        let haystack = b"outside://x/a | x://a/b?q=x#f y://c/d | z://e/f";
        let range = 16..43;
        let actual = compiled
            .count_value(
                haystack,
                range.clone(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        let expected = regex::bytes::RegexBuilder::new(URI)
            .unicode(false)
            .build()
            .unwrap()
            .find_iter(&haystack[range])
            .count();
        assert_eq!(actual, expected);
    }

    #[test]
    fn optional_or_bordered_anchor_shapes_remain_on_the_general_route() {
        for pattern in [r"a+(?:X)?b+[ab]+", r"a+aba+b+[ab]+", r"a+X(?:b+|c+)"] {
            let compiled = CompiledRegex::from_hir(
                &parse(pattern),
                RustByteProfile::PINNED_1_12_4,
                CompileLimits::default(),
            )
            .unwrap();
            assert_eq!(compiled.compile_accounting().required_internal_anchors, 0);
        }
    }

    #[test]
    fn rejected_inspections_retain_hir_and_kernel_attempt_work() {
        let bordered = parse(r"x+(aba)b+[ab]+");
        let inspected = inspect(&bordered, 1 << 20, 1 << 20, 1 << 20).unwrap();
        assert!(inspected.plan.is_none());
        let kernel_upper = fre_kernels::RequiredInternalAnchorPlan::build_work_upper_bound(3, 0)
            .expect("kernel upper bound");
        assert!(inspected.inspection_work > kernel_upper);

        let non_shape = inspect(&parse(r"a+"), 1 << 20, 1 << 20, 1 << 20).unwrap();
        assert!(non_shape.plan.is_none());
        assert!(non_shape.inspection_work > 0);
        assert!(non_shape.inspection_work < inspected.inspection_work);
    }

    #[test]
    fn operation_resources_are_prospective_exact_and_one_below() {
        let compiled = CompiledRegex::from_hir(
            &parse(URI),
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        let haystack = b"://://://";
        let plan = compiled.required_internal_anchor.as_ref().unwrap();
        let upper = plan.count_upper_bounds(haystack.len()).unwrap();
        let exact = OperationLimits {
            max_boundaries: haystack.len() + 1,
            max_table_cells: 0,
            max_random_access_bytes: upper.random_access_bytes,
            max_scratch_bytes: upper.scratch_bytes,
            max_log_bytes: 0,
            max_sequential_bytes: upper.sequential_bytes,
            max_match_events: upper.candidate_visits,
            max_output_matches: usize::try_from(upper.count).unwrap(),
            max_output_bytes: 0,
            max_span_sum: 0,
            max_peak_bytes: upper.peak_bytes,
            max_work: upper.work,
        };
        let admitted = compiled
            .admit_count(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                exact,
            )
            .unwrap();
        assert_eq!(admitted.value(), 0);
        assert_eq!(admitted.accounting().required_anchor_candidates, 3);
        assert!(admitted.accounting().work < admitted.certificate().work_bound);
        assert_eq!(
            admitted.accounting().random_access_bytes_read,
            admitted.accounting().required_anchor_prefix_steps
        );
        assert!(admitted.accounting().work <= admitted.certificate().work_bound);
        assert_eq!(admitted.certificate().work_bound, upper.work);
        assert_eq!(
            admitted.certificate().random_access_bytes,
            upper.random_access_bytes
        );
        assert_eq!(
            admitted.certificate().sequential_bytes_bound,
            upper.sequential_bytes
        );

        for (resource, limits) in [
            (
                Resource::Boundaries,
                OperationLimits {
                    max_boundaries: exact.max_boundaries - 1,
                    ..exact
                },
            ),
            (
                Resource::MatchEvents,
                OperationLimits {
                    max_match_events: exact.max_match_events - 1,
                    ..exact
                },
            ),
            (
                Resource::OutputMatches,
                OperationLimits {
                    max_output_matches: exact.max_output_matches - 1,
                    ..exact
                },
            ),
            (
                Resource::RandomAccessBytes,
                OperationLimits {
                    max_random_access_bytes: exact.max_random_access_bytes - 1,
                    ..exact
                },
            ),
            (
                Resource::SequentialBytes,
                OperationLimits {
                    max_sequential_bytes: exact.max_sequential_bytes - 1,
                    ..exact
                },
            ),
            (
                Resource::PeakBytes,
                OperationLimits {
                    max_peak_bytes: exact.max_peak_bytes - 1,
                    ..exact
                },
            ),
            (
                Resource::ExecutionWork,
                OperationLimits {
                    max_work: exact.max_work - 1,
                    ..exact
                },
            ),
        ] {
            assert!(matches!(
                compiled.admit_count(
                    haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    limits,
                ),
                Err(Error::ResourceLimit { resource: got, .. }) if got == resource
            ));
        }
        assert_eq!(upper.allocations, 0);
        assert_eq!(upper.scratch_bytes, 0);
    }
}
