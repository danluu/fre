use crate::{
    AbiVersion, AggregateBuildError, AggregateExecuteError, AggregateExecutionLimits,
    AggregateOperation, AggregateOutput, AnchorFlags, Block, BlockId, BlockOp, BuildError,
    ByteClass, CheckedSearchWindow, Count, DataBlob, ExecuteError, ExecutionLimits, InvalidProgram,
    MAX_EXACT_AGGREGATE_LITERAL_BYTES, MatchSpan, OutputKind, RawProgram, ResourceKind,
    SearchWindow, SemanticsVersion, Span, SpanSum, ValidateError, ValidateLimits,
    build_class_suffix, build_exact_aggregate, build_exact_literal, exact_aggregate_upper_bounds,
};

#[test]
fn exact_aggregate_exhaustive_nonoverlap_and_empty_parity() {
    let literals = words(b"ab", 3);
    let haystacks = words(b"ab", 6);
    let mut comparisons = 0_u64;
    for literal in &literals {
        let count = build_exact_aggregate::<Count>(literal, ValidateLimits::default())
            .expect("bounded count program");
        let span_sum = build_exact_aggregate::<SpanSum>(literal, ValidateLimits::default())
            .expect("bounded span-sum program");
        assert_ne!(count.cache_identity(), span_sum.cache_identity());
        for haystack in &haystacks {
            let expected = direct_exact_aggregate(haystack, literal);
            let actual_count = count
                .execute(haystack, AggregateExecutionLimits::unlimited())
                .expect("count oracle");
            let actual_span = span_sum
                .execute(haystack, AggregateExecutionLimits::unlimited())
                .expect("span-sum oracle");
            assert_eq!(*actual_count.output(), expected.0);
            assert_eq!(*actual_span.output(), expected.1);
            assert!(actual_count.work() <= actual_count.upper_bounds().work);
            assert!(actual_span.work() <= actual_span.upper_bounds().work);
            comparisons = comparisons.checked_add(2).expect("bounded corpus");
        }
    }
    assert_eq!(comparisons, 3_810);

    let arbitrary = build_exact_aggregate::<Count>(&[0, 255], ValidateLimits::default())
        .expect("arbitrary-byte literal");
    assert_eq!(
        arbitrary
            .execute(
                &[0, 255, 0, 0, 255, 0, 255],
                AggregateExecutionLimits::unlimited()
            )
            .expect("arbitrary-byte aggregate")
            .into_output(),
        3
    );
}

#[test]
fn exact_aggregate_empty_and_post_match_progress_are_directed() {
    for length in 0..=64 {
        let haystack = vec![0xff; length];
        let count =
            build_exact_aggregate::<Count>(b"", ValidateLimits::default()).expect("empty count");
        let span = build_exact_aggregate::<SpanSum>(b"", ValidateLimits::default())
            .expect("empty span sum");
        assert_eq!(
            count
                .execute(&haystack, AggregateExecutionLimits::unlimited())
                .expect("empty count oracle")
                .into_output(),
            u64::try_from(length.checked_add(1).expect("small")).expect("small")
        );
        assert_eq!(
            span.execute(&haystack, AggregateExecutionLimits::unlimited())
                .expect("empty span oracle")
                .into_output(),
            0
        );
    }

    for (literal, haystack, expected) in [
        (b"aa".as_slice(), b"aaaaa".as_slice(), (2, 4)),
        (b"aba".as_slice(), b"abababa".as_slice(), (2, 6)),
        (b"a".as_slice(), b"aaaaa".as_slice(), (5, 5)),
    ] {
        let count = build_exact_aggregate::<Count>(literal, ValidateLimits::default())
            .expect("directed count");
        let span = build_exact_aggregate::<SpanSum>(literal, ValidateLimits::default())
            .expect("directed span");
        assert_eq!(
            count
                .execute(haystack, AggregateExecutionLimits::unlimited())
                .expect("directed count oracle")
                .into_output(),
            expected.0
        );
        assert_eq!(
            span.execute(haystack, AggregateExecutionLimits::unlimited())
                .expect("directed span oracle")
                .into_output(),
            expected.1
        );
    }
}

#[test]
fn exact_aggregate_bounds_accept_exact_and_refuse_one_below() {
    let haystack = b"aaaaaaaaaaaaaaaa";
    for literal in [b"".as_slice(), b"aa", b"aaaaab"] {
        assert_exact_aggregate_bounds::<Count>(literal, haystack);
        assert_exact_aggregate_bounds::<SpanSum>(literal, haystack);
    }
}

#[test]
fn exact_aggregate_literal_cap_accepts_boundary_and_refuses_next() {
    let boundary = vec![b'x'; MAX_EXACT_AGGREGATE_LITERAL_BYTES];
    build_exact_aggregate::<Count>(&boundary, ValidateLimits::default())
        .expect("exact cap accepted");
    let required = MAX_EXACT_AGGREGATE_LITERAL_BYTES
        .checked_add(1)
        .expect("small cap");
    let too_wide = vec![b'x'; required];
    assert!(matches!(
        build_exact_aggregate::<Count>(&too_wide, ValidateLimits::default()),
        Err(AggregateBuildError::LiteralLengthLimit {
            limit: MAX_EXACT_AGGREGATE_LITERAL_BYTES,
            required
        }) if required == too_wide.len()
    ));
}

#[test]
fn exact_aggregate_synthetic_overflow_boundaries_are_checked() {
    let safe_max = usize::try_from(isize::MAX).expect("usize represents isize::MAX");
    let empty = exact_aggregate_upper_bounds(safe_max, 0, AggregateOutput::Count)
        .expect("largest safe slice empty count fits");
    assert_eq!(
        empty.count,
        u64::try_from(safe_max).expect("64-bit admitted target") + 1
    );
    assert!(matches!(
        exact_aggregate_upper_bounds(usize::MAX, 0, AggregateOutput::Count),
        Err(AggregateExecuteError::ArithmeticOverflow { .. })
    ));

    let width = MAX_EXACT_AGGREGATE_LITERAL_BYTES;
    let mut low = 0_usize;
    let mut high = safe_max;
    while low < high {
        let distance = high.checked_sub(low).expect("ordered bounds");
        let middle = low
            .checked_add(distance / 2)
            .and_then(|value| value.checked_add(distance % 2))
            .expect("midpoint fits");
        if exact_aggregate_upper_bounds(middle, width, AggregateOutput::Count).is_ok() {
            low = middle;
        } else {
            high = middle.checked_sub(1).expect("positive failing midpoint");
        }
    }
    let upper = exact_aggregate_upper_bounds(low, width, AggregateOutput::Count)
        .expect("largest fitting work envelope");
    let candidates = u128::try_from(upper.candidate_positions).expect("usize fits u128");
    let reducer = u128::try_from(upper.reducer_steps).expect("usize fits u128");
    let independently_computed = candidates
        .checked_mul(u128::try_from(width + 1).expect("small width"))
        .and_then(|work| work.checked_add(reducer))
        .expect("u128 envelope");
    assert_eq!(independently_computed, u128::from(upper.work));
    let successor = low.checked_add(1).expect("boundary below safe slice max");
    assert!(matches!(
        exact_aggregate_upper_bounds(successor, width, AggregateOutput::Count),
        Err(AggregateExecuteError::ArithmeticOverflow { .. })
    ));
}

#[test]
fn exact_literal_exhaustive_direct_parity() {
    let literals = words(b"ab", 3);
    let haystacks = words(b"ab", 5);
    let mut comparisons = 0_u64;
    for literal in &literals {
        for anchors in anchors() {
            let program = build_exact_literal::<Span>(literal, anchors, ValidateLimits::default())
                .expect("eligible exact literal");
            for haystack in &haystacks {
                for window in windows(haystack.len()) {
                    let report = program
                        .execute(haystack, window, ExecutionLimits::unlimited())
                        .expect("bounded oracle execution");
                    let expected = direct_literal(haystack, window, literal, anchors);
                    assert_eq!(
                        *report.output(),
                        expected,
                        "literal={literal:?} haystack={haystack:?} window={window:?} anchors={anchors:?}"
                    );
                    let bound = program
                        .conservative_work_bound(window.end() - window.start())
                        .expect("small work bound");
                    assert!(report.work() <= bound);
                    comparisons = comparisons.checked_add(1).expect("small test corpus");
                }
            }
        }
    }
    assert_eq!(comparisons, 61_380);
}

#[test]
fn class_suffix_exhaustive_direct_parity() {
    let classes = [ByteClass::from_bytes(b"a"), ByteClass::from_bytes(b"ab")];
    let suffixes: [&[u8]; 3] = [b"X", b"XY", b"Xa"];
    let haystacks = words(b"abXY", 5);
    let mut comparisons = 0_u64;
    for class in classes {
        for suffix in suffixes {
            for anchors in anchors() {
                let program =
                    build_class_suffix::<Span>(class, suffix, anchors, ValidateLimits::default())
                        .expect("disjoint suffix delimiter");
                for haystack in &haystacks {
                    for window in windows(haystack.len()) {
                        let report = program
                            .execute(haystack, window, ExecutionLimits::unlimited())
                            .expect("bounded oracle execution");
                        let expected =
                            direct_class_suffix(haystack, window, class, suffix, anchors);
                        assert_eq!(
                            *report.output(),
                            expected,
                            "class={class:?} suffix={suffix:?} haystack={haystack:?} window={window:?} anchors={anchors:?}"
                        );
                        let bound = program
                            .conservative_work_bound(window.end() - window.start())
                            .expect("small work bound");
                        assert!(report.work() <= bound);
                        comparisons = comparisons.checked_add(1).expect("small test corpus");
                    }
                }
            }
        }
    }
    assert_eq!(comparisons, 626_232);
}

#[test]
fn forced_kernels_match_independent_k0_floor() {
    use fre_automata::{SearchLimits, SearchWindow as K0Window, Span as K0Span};
    use fre_lower::{LowerLimits, OperationSemantics, lower_hir};

    let cases = [
        ("ab", false, false, false),
        (r"\Aab", true, false, false),
        (r"ab\z", false, true, false),
        (r"\Aab\z", true, true, false),
        ("[ab]+X", false, false, true),
        (r"\A[ab]+X", true, false, true),
        (r"[ab]+X\z", false, true, true),
        (r"\A[ab]+X\z", true, true, true),
    ];
    let haystacks = words(b"abXY", 4);
    let mut comparisons = 0_u64;
    for (pattern, anchored_start, anchored_end, class_suffix) in cases {
        let hir = regex_syntax::ParserBuilder::new()
            .utf8(false)
            .unicode(false)
            .build()
            .parse(pattern)
            .expect("fixed byte pattern");
        let lowered = lower_hir(
            &hir,
            OperationSemantics::CaptureFree,
            LowerLimits::default(),
        )
        .expect("K0-supported pattern");
        let k0 = lowered.automaton().prepare::<K0Span>();
        let anchors = AnchorFlags {
            start: anchored_start,
            end: anchored_end,
        };
        let program = if class_suffix {
            build_class_suffix::<Span>(
                ByteClass::from_bytes(b"ab"),
                b"X",
                anchors,
                ValidateLimits::default(),
            )
            .unwrap()
        } else {
            build_exact_literal::<Span>(b"ab", anchors, ValidateLimits::default()).unwrap()
        };
        for haystack in &haystacks {
            for window in windows(haystack.len()) {
                let actual = program
                    .execute(haystack, window, ExecutionLimits::unlimited())
                    .unwrap()
                    .into_output();
                let expected = k0
                    .search_window(
                        haystack,
                        K0Window::new(window.start(), window.end()),
                        SearchLimits::unlimited(),
                    )
                    .unwrap()
                    .into_output()
                    .map(|span| MatchSpan::new(span.start(), span.end()));
                assert_eq!(
                    actual, expected,
                    "pattern={pattern:?} haystack={haystack:?} window={window:?}"
                );
                comparisons = comparisons.checked_add(1).expect("small test corpus");
            }
        }
    }
    assert_eq!(comparisons, 36_712);
}

#[test]
fn output_contract_is_bound_in_type_and_identity() {
    let limits = ValidateLimits::default();
    let span = build_exact_literal::<crate::Span>(b"needle", AnchorFlags::default(), limits)
        .expect("span kernel");
    let end = build_exact_literal::<crate::SelectedEnd>(b"needle", AnchorFlags::default(), limits)
        .expect("end kernel");
    let exists = build_exact_literal::<crate::Exists>(b"needle", AnchorFlags::default(), limits)
        .expect("exists kernel");
    let window = SearchWindow::new(0, 8);
    assert_eq!(
        span.execute(b"xxneedle", window, ExecutionLimits::unlimited())
            .unwrap()
            .into_output(),
        Some(MatchSpan::new(2, 8))
    );
    assert_eq!(
        end.execute(b"xxneedle", window, ExecutionLimits::unlimited())
            .unwrap()
            .into_output(),
        Some(8)
    );
    assert!(
        exists
            .execute(b"xxneedle", window, ExecutionLimits::unlimited())
            .unwrap()
            .into_output()
    );
    assert_ne!(span.cache_identity(), end.cache_identity());
    assert_ne!(span.cache_identity(), exists.cache_identity());

    let error = span
        .raw()
        .clone()
        .validate::<crate::Exists>(limits)
        .unwrap_err();
    assert_eq!(
        error,
        ValidateError::Invalid(InvalidProgram::OutputContract)
    );
}

#[test]
fn serialization_and_cache_identity_are_deterministic() {
    let first = build_class_suffix::<Span>(
        ByteClass::from_bytes(b"abc"),
        b"XYZ",
        AnchorFlags {
            start: true,
            end: false,
        },
        ValidateLimits::default(),
    )
    .unwrap();
    let second = build_class_suffix::<Span>(
        ByteClass::from_bytes(b"cba"),
        b"XYZ",
        AnchorFlags {
            start: true,
            end: false,
        },
        ValidateLimits::default(),
    )
    .unwrap();
    assert_eq!(first.serialized(), second.serialized());
    assert_eq!(first.cache_identity(), second.cache_identity());
    assert_eq!(
        first.cache_identity().to_string(),
        "6b763fbe44321319a268bbec7f8d6c5ac2306bfcb272e2e96cae22235bb23b93"
    );
    assert_eq!(
        first.serialized().as_bytes().len(),
        first.stats().serialized_bytes()
    );
    assert_eq!(
        first.serialized().retained_capacity_bytes(),
        first.stats().serialized_capacity_bytes()
    );
    assert_eq!(first.stats().serialized_bytes(), 121);
    assert_eq!(first.stats().estimated_code_bytes(), 640);
    assert_eq!(&first.serialized().as_bytes()[..8], b"FREKIR\0\x01");

    let changed_anchor = build_class_suffix::<Span>(
        ByteClass::from_bytes(b"abc"),
        b"XYZ",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .unwrap();
    assert_ne!(first.cache_identity(), changed_anchor.cache_identity());
}

#[test]
fn resource_accounting_v2_binds_work_capacity_and_phase_equations() {
    let literal = b"abcdefgh";
    let program =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("accounted exact literal");
    let stats = program.stats();
    let resources = stats.resources();
    assert_eq!(resources.version(), crate::ResourceAccounting::VERSION);
    assert_eq!(resources.allocation_requests(), 4);
    assert_eq!(resources.planning_work(), 10);
    let requested_raw = literal
        .len()
        .checked_add(stats.blocks() * core::mem::size_of::<Block>())
        .and_then(|bytes| bytes.checked_add(stats.data_blobs() * core::mem::size_of::<DataBlob>()))
        .unwrap();
    assert_eq!(
        resources.initialization_work(),
        u64::try_from(requested_raw + stats.serialized_bytes() + 128).unwrap()
    );
    assert_eq!(
        resources.copy_work(),
        u64::try_from(literal.len() + stats.serialized_bytes() + 96).unwrap()
    );
    assert_eq!(resources.hash_invocations(), 1);
    assert_eq!(
        resources.hash_work(),
        u64::try_from(stats.serialized_bytes()).unwrap()
    );
    assert!(resources.validation_work() <= resources.validation_work_upper_bound());
    assert_eq!(
        resources.construction_work(),
        resources.planning_work()
            + resources.initialization_work()
            + resources.copy_work()
            + resources.hash_work()
            + resources.validation_work_upper_bound()
    );
    assert_eq!(resources.raw_allocation_request_bytes(), requested_raw);
    assert_eq!(resources.literal_allocation_request_bytes(), literal.len());
    assert_eq!(
        resources.block_allocation_request_bytes(),
        stats.blocks() * core::mem::size_of::<Block>()
    );
    assert_eq!(
        resources.data_table_allocation_request_bytes(),
        stats.data_blobs() * core::mem::size_of::<DataBlob>()
    );
    assert_eq!(
        resources.serialized_allocation_request_bytes(),
        stats.serialized_bytes()
    );
    assert_eq!(
        resources.allocation_request_bytes(),
        requested_raw + stats.serialized_bytes()
    );
    assert!(resources.raw_program_capacity_bytes() >= requested_raw);
    assert_eq!(
        resources.raw_program_capacity_bytes(),
        resources.literal_capacity_bytes()
            + resources.block_capacity_bytes()
            + resources.data_table_capacity_bytes()
    );
    assert!(resources.serialized_capacity_bytes() >= stats.serialized_bytes());
    assert!(
        resources.validation_phase_peak_bytes()
            >= resources.raw_program_capacity_bytes() + resources.validation_scratch_bytes()
    );
    assert!(
        resources.serialization_phase_peak_bytes()
            >= resources.raw_program_capacity_bytes() + resources.serialized_capacity_bytes()
    );
    assert!(resources.identity_phase_peak_bytes() > resources.retained_program_bytes());

    let class = dimension_census_class();
    assert_eq!(class.stats().resources().planning_work(), 23);

    let aggregate = build_exact_aggregate::<Count>(b"abc", ValidateLimits::default())
        .expect("accounted exact aggregate");
    let aggregate_resources = aggregate.construction_resources();
    assert_eq!(aggregate_resources.hash_invocations(), 2);
    let serialized = u64::try_from(3_usize + 53).unwrap();
    let aggregate_domain = u64::try_from(b"FREKAGG\0\x01".len() + 1).unwrap();
    assert_eq!(
        aggregate_resources.hash_work(),
        serialized + serialized + aggregate_domain
    );
}

#[test]
fn aggregate_second_hash_and_retained_peaks_accept_exact_and_refuse_one_below() {
    let literal = b"aggregate";
    let baseline = build_exact_aggregate::<Count>(literal, ValidateLimits::default())
        .expect("aggregate resource baseline");
    let resources = baseline.construction_resources();
    assert_eq!(resources.hash_invocations(), 2);
    let serialized = u64::try_from(literal.len() + 53).expect("small serialization");
    let aggregate_domain =
        u64::try_from(b"FREKAGG\0\x01".len() + 1).expect("small identity domain");
    assert_eq!(
        resources.hash_work(),
        serialized + serialized + aggregate_domain
    );
    let requested_raw = 4_usize
        .checked_mul(core::mem::size_of::<Block>())
        .and_then(|bytes| bytes.checked_add(literal.len()))
        .and_then(|bytes| bytes.checked_add(core::mem::size_of::<DataBlob>()))
        .expect("small fixed shape");
    let two_hash_initialization = 2_u64.checked_mul(128).expect("small fixed initialization");
    let two_hash_copy = 2_u64.checked_mul(96).expect("small fixed copy");
    let expected_initialization = u64::try_from(requested_raw)
        .ok()
        .and_then(|work| work.checked_add(serialized))
        .and_then(|work| work.checked_add(two_hash_initialization))
        .expect("small initialization envelope");
    let expected_copy = u64::try_from(literal.len())
        .ok()
        .and_then(|work| work.checked_add(serialized))
        .and_then(|work| work.checked_add(two_hash_copy))
        .expect("small copy envelope");
    assert_eq!(resources.initialization_work(), expected_initialization);
    assert_eq!(resources.copy_work(), expected_copy);

    let exact = ValidateLimits {
        max_construction_work: resources.construction_work(),
        max_identity_phase_bytes: u64::try_from(resources.identity_phase_peak_bytes())
            .expect("small peak"),
        max_retained_program_bytes: u64::try_from(resources.retained_program_bytes())
            .expect("small retained state"),
        ..ValidateLimits::default()
    };
    let replay = build_exact_aggregate::<Count>(literal, exact)
        .expect("aggregate accepts exact construction and peak limits");
    assert_eq!(replay.cache_identity(), baseline.cache_identity());
    assert_eq!(replay.construction_resources(), resources);

    for (expected, required, limits) in [
        (
            ResourceKind::ConstructionWork,
            resources.construction_work(),
            ValidateLimits {
                max_construction_work: resources.construction_work() - 1,
                ..ValidateLimits::default()
            },
        ),
        (
            ResourceKind::IdentityPhaseBytes,
            u64::try_from(resources.identity_phase_peak_bytes()).expect("small peak"),
            ValidateLimits {
                max_identity_phase_bytes: u64::try_from(resources.identity_phase_peak_bytes() - 1)
                    .expect("nonzero peak"),
                ..ValidateLimits::default()
            },
        ),
        (
            ResourceKind::RetainedProgramBytes,
            u64::try_from(resources.retained_program_bytes()).expect("small retained state"),
            ValidateLimits {
                max_retained_program_bytes: u64::try_from(resources.retained_program_bytes() - 1)
                    .expect("nonzero retained state"),
                ..ValidateLimits::default()
            },
        ),
    ] {
        let error = build_exact_aggregate::<Count>(literal, limits)
            .expect_err("one-below aggregate construction limit refuses");
        assert!(
            matches!(
                error,
                AggregateBuildError::Search(BuildError::Validate(
                    ValidateError::ResourceLimit {
                        resource,
                        required: actual,
                        ..
                    }
                )) if resource == expected && actual == required
            ),
            "expected {expected:?}={required}, got {error:?}"
        );
    }
}

#[test]
fn class_suffix_phase_peaks_accept_exact_and_refuse_one_below() {
    let class = ByteClass::from_bytes(b"abc");
    let suffix = b"XYZ";
    let baseline = build_class_suffix::<Span>(
        class,
        suffix,
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("class-suffix resource baseline");
    let resources = baseline.stats().resources();
    let exact = ValidateLimits {
        max_construction_work: resources.construction_work(),
        max_validation_phase_bytes: u64::try_from(resources.validation_phase_peak_bytes())
            .expect("small validation peak"),
        max_serialization_phase_bytes: u64::try_from(resources.serialization_phase_peak_bytes())
            .expect("small serialization peak"),
        max_identity_phase_bytes: u64::try_from(resources.identity_phase_peak_bytes())
            .expect("small identity peak"),
        max_retained_program_bytes: u64::try_from(resources.retained_program_bytes())
            .expect("small retained state"),
        ..ValidateLimits::default()
    };
    let replay = build_class_suffix::<Span>(class, suffix, AnchorFlags::default(), exact)
        .expect("class suffix accepts exact construction and phase limits");
    assert_eq!(replay.cache_identity(), baseline.cache_identity());
    assert_eq!(replay.stats().resources(), resources);

    for (expected, required, limits) in [
        (
            ResourceKind::ConstructionWork,
            resources.construction_work(),
            ValidateLimits {
                max_construction_work: resources.construction_work() - 1,
                ..ValidateLimits::default()
            },
        ),
        (
            ResourceKind::ValidationPhaseBytes,
            u64::try_from(resources.validation_phase_peak_bytes()).expect("small validation peak"),
            ValidateLimits {
                max_validation_phase_bytes: u64::try_from(
                    resources.validation_phase_peak_bytes() - 1,
                )
                .expect("nonzero validation peak"),
                ..ValidateLimits::default()
            },
        ),
        (
            ResourceKind::SerializationPhaseBytes,
            u64::try_from(resources.serialization_phase_peak_bytes())
                .expect("small serialization peak"),
            ValidateLimits {
                max_serialization_phase_bytes: u64::try_from(
                    resources.serialization_phase_peak_bytes() - 1,
                )
                .expect("nonzero serialization peak"),
                ..ValidateLimits::default()
            },
        ),
        (
            ResourceKind::IdentityPhaseBytes,
            u64::try_from(resources.identity_phase_peak_bytes()).expect("small identity peak"),
            ValidateLimits {
                max_identity_phase_bytes: u64::try_from(resources.identity_phase_peak_bytes() - 1)
                    .expect("nonzero identity peak"),
                ..ValidateLimits::default()
            },
        ),
        (
            ResourceKind::RetainedProgramBytes,
            u64::try_from(resources.retained_program_bytes()).expect("small retained state"),
            ValidateLimits {
                max_retained_program_bytes: u64::try_from(resources.retained_program_bytes() - 1)
                    .expect("nonzero retained state"),
                ..ValidateLimits::default()
            },
        ),
    ] {
        let error = build_class_suffix::<Span>(class, suffix, AnchorFlags::default(), limits)
            .expect_err("one-below class-suffix construction limit refuses");
        assert!(
            matches!(
                error,
                BuildError::Validate(ValidateError::ResourceLimit {
                    resource,
                    required: actual,
                    ..
                }) if resource == expected && actual == required
            ),
            "expected {expected:?}={required}, got {error:?}"
        );
    }
}

fn dimension_census_class() -> crate::ValidatedProgram<Span> {
    build_class_suffix::<Span>(
        ByteClass::from_bytes(b"a"),
        b"X",
        AnchorFlags {
            start: true,
            end: false,
        },
        ValidateLimits::default(),
    )
    .expect("class-suffix census")
}

#[test]
fn dimension_census_preserves_shape_stats_and_identity() {
    for length in [0_usize, 1, 15, 16, 17] {
        let literal = vec![b'x'; length];
        let program = build_exact_literal::<Span>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("exact literal census");
        let stats = program.stats();
        let padded = length.checked_add(15).expect("small length") & !15;
        assert_eq!(stats.data_bytes(), length);
        assert_eq!(
            stats.serialized_bytes(),
            53_usize.checked_add(length).expect("small length")
        );
        assert_eq!(
            stats.estimated_code_bytes(),
            240_usize.checked_add(padded).expect("small length")
        );
        assert_eq!(
            stats.work_factor(),
            u64::try_from(length).expect("small length") + 8
        );
        assert_eq!(stats.validation_work(), 27);
        assert!(stats.validation_work() <= stats.resources().validation_work_upper_bound());
        assert_eq!(
            program.serialized().as_bytes().len(),
            stats.serialized_bytes()
        );
    }
    assert_eq!(
        build_exact_literal::<Span>(
            b"abcdefgh",
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("validation-work golden literal")
        .stats()
        .validation_work(),
        27
    );

    let class = dimension_census_class();
    let stats = class.stats();
    assert_eq!(stats.data_bytes(), 33);
    assert_eq!(stats.serialized_bytes(), 119);
    assert_eq!(stats.estimated_code_bytes(), 640);
    assert_eq!(stats.work_factor(), 9);
    assert_eq!(stats.validation_work(), 69);
    assert!(stats.validation_work() <= stats.resources().validation_work_upper_bound());

    let mut reordered = class.raw().clone();
    reordered.data.swap(0, 1);
    for block in &mut reordered.blocks {
        match &mut block.op {
            BlockOp::ScanClassStart { class, .. } | BlockOp::ExtendClassRun { class, .. } => {
                *class = crate::DataId(1);
            }
            BlockOp::ConfirmSuffix { suffix, .. } => *suffix = crate::DataId(0),
            _ => {}
        }
    }
    let reordered = reordered
        .validate::<Span>(ValidateLimits::default())
        .expect("reordered data with rebound ids");
    let reordered_stats = reordered.stats();
    assert_eq!(reordered_stats.blocks(), stats.blocks());
    assert_eq!(reordered_stats.instructions(), stats.instructions());
    assert_eq!(reordered_stats.data_blobs(), stats.data_blobs());
    assert_eq!(reordered_stats.data_bytes(), stats.data_bytes());
    assert_eq!(reordered_stats.serialized_bytes(), stats.serialized_bytes());
    assert_eq!(
        reordered_stats.estimated_code_bytes(),
        stats.estimated_code_bytes()
    );
    assert_eq!(reordered_stats.work_factor(), stats.work_factor());
    assert_eq!(
        reordered_stats.resources().allocation_request_bytes(),
        reordered_stats.serialized_bytes()
    );
    assert_eq!(reordered_stats.resources().allocation_requests(), 1);
    assert_ne!(reordered.cache_identity(), class.cache_identity());
}

#[test]
fn dimension_census_exact_limits_replay() {
    let class = dimension_census_class();
    let stats = class.stats();
    let exact = ValidateLimits {
        max_blocks: u64::try_from(stats.blocks()).expect("small count"),
        max_instructions: u64::try_from(stats.instructions()).expect("small count"),
        max_data_blobs: u64::try_from(stats.data_blobs()).expect("small count"),
        max_data_bytes: u64::try_from(stats.data_bytes()).expect("small count"),
        max_serialized_bytes: u64::try_from(stats.serialized_bytes()).expect("small count"),
        max_estimated_code_bytes: u64::try_from(stats.estimated_code_bytes()).expect("small count"),
        max_validation_work: stats.resources().validation_work_upper_bound(),
        max_work_factor: stats.work_factor(),
        ..ValidateLimits::default()
    };
    let replay = class
        .raw()
        .clone()
        .validate::<Span>(exact)
        .expect("all exact census limits");
    assert_same_program_dimensions(replay.stats(), stats);
}

#[test]
fn dimension_census_preserves_limit_precedence() {
    let class = dimension_census_class();
    let stats = class.stats();
    let cases = [
        (
            ResourceKind::ValidationWork,
            ValidateLimits {
                max_validation_work: 4,
                max_data_bytes: 0,
                max_serialized_bytes: 0,
                max_estimated_code_bytes: 0,
                max_work_factor: 0,
                ..ValidateLimits::default()
            },
        ),
        (
            ResourceKind::DataBytes,
            ValidateLimits {
                max_data_bytes: 32,
                max_serialized_bytes: 0,
                max_estimated_code_bytes: 0,
                max_work_factor: 0,
                ..ValidateLimits::default()
            },
        ),
        (
            ResourceKind::SerializedBytes,
            ValidateLimits {
                max_serialized_bytes: 118,
                max_estimated_code_bytes: 0,
                max_work_factor: 0,
                ..ValidateLimits::default()
            },
        ),
        (
            ResourceKind::EstimatedCodeBytes,
            ValidateLimits {
                max_estimated_code_bytes: 639,
                max_work_factor: 0,
                ..ValidateLimits::default()
            },
        ),
        (
            ResourceKind::WorkFactor,
            ValidateLimits {
                max_work_factor: 8,
                ..ValidateLimits::default()
            },
        ),
        (
            ResourceKind::ValidationWork,
            ValidateLimits {
                max_data_bytes: u64::try_from(stats.data_bytes()).expect("small count"),
                max_serialized_bytes: u64::try_from(stats.serialized_bytes()).expect("small count"),
                max_estimated_code_bytes: u64::try_from(stats.estimated_code_bytes())
                    .expect("small count"),
                max_work_factor: stats.work_factor(),
                max_validation_work: stats.validation_work() - 1,
                ..ValidateLimits::default()
            },
        ),
    ];
    for (expected, limits) in cases {
        let error = class.raw().clone().validate::<Span>(limits).unwrap_err();
        assert!(
            matches!(
                error,
                ValidateError::ResourceLimit {
                    resource,
                    ..
                } if resource == expected
            ),
            "expected {expected:?}, got {error:?}"
        );
    }
}

#[test]
fn adversarial_headers_targets_flow_and_data_are_rejected() {
    let valid =
        build_exact_literal::<Span>(b"abc", AnchorFlags::default(), ValidateLimits::default())
            .unwrap();

    assert_invalid(
        mutate(valid.raw(), |raw| raw.schema_version = 99),
        InvalidProgram::SchemaVersion { actual: 99 },
    );
    assert_invalid(
        mutate(valid.raw(), |raw| raw.semantics = SemanticsVersion(99)),
        InvalidProgram::SemanticsVersion { actual: 99 },
    );
    assert_invalid(
        mutate(valid.raw(), |raw| raw.abi = AbiVersion(99)),
        InvalidProgram::AbiVersion { actual: 99 },
    );
    assert_invalid(
        mutate(valid.raw(), |raw| {
            raw.blocks[0].op = BlockOp::Entry { next: BlockId(99) };
        }),
        InvalidProgram::BlockTargetOutOfRange {
            block: 0,
            target: 99,
        },
    );
    assert_invalid(
        mutate(valid.raw(), |raw| {
            raw.blocks[0].op = BlockOp::Entry { next: BlockId(2) };
        }),
        InvalidProgram::FlowStateMismatch { block: 2 },
    );
    assert_invalid(
        mutate(valid.raw(), |raw| {
            raw.data[0] = DataBlob::ByteClass(ByteClass::from_bytes(b"a"));
        }),
        InvalidProgram::WrongDataKind { block: 1, data: 0 },
    );
    assert_invalid(
        mutate(valid.raw(), |raw| {
            raw.blocks.push(Block {
                op: BlockOp::ReturnNone,
            });
        }),
        InvalidProgram::UnreachableBlock { block: 4 },
    );
}

#[test]
fn validator_is_total_over_deterministic_malformed_corpus() {
    let mut random = DeterministicRandom(0xd1ff_3e57_5eed_1234);
    for case in 0..65_536 {
        let raw = random_raw(&mut random);
        let result = std::panic::catch_unwind(|| raw.validate::<Span>(ValidateLimits::default()));
        assert!(
            result.is_ok(),
            "validator panicked on malformed case {case}"
        );
    }
}

#[test]
fn unsafe_class_suffix_shapes_are_rejected() {
    let empty_class = build_class_suffix::<Span>(
        ByteClass::empty(),
        b"X",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .unwrap_err();
    assert_eq!(
        empty_class,
        BuildError::Validate(ValidateError::Invalid(InvalidProgram::EmptyClass {
            data: 0
        }))
    );

    let empty_suffix = build_class_suffix::<Span>(
        ByteClass::from_bytes(b"a"),
        b"",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .unwrap_err();
    assert_eq!(
        empty_suffix,
        BuildError::Validate(ValidateError::Invalid(InvalidProgram::EmptySuffix {
            data: 1
        }))
    );

    let overlap = build_class_suffix::<Span>(
        ByteClass::from_bytes(b"a"),
        b"ab",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .unwrap_err();
    assert_eq!(
        overlap,
        BuildError::Validate(ValidateError::Invalid(
            InvalidProgram::SuffixOverlapsClass {
                class: 0,
                suffix: 1
            }
        ))
    );

    let valid = build_class_suffix::<Span>(
        ByteClass::from_bytes(b"a"),
        b"X",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .unwrap();
    let malformed = mutate(valid.raw(), |raw| {
        raw.blocks[2].op = BlockOp::ExtendClassRun {
            class: crate::DataId(0),
            next: BlockId(2),
        };
    });
    assert!(matches!(
        malformed.validate::<Span>(ValidateLimits::default()),
        Err(ValidateError::Invalid(
            InvalidProgram::UnreachableBlock { .. }
                | InvalidProgram::InvalidCycle { .. }
                | InvalidProgram::NonCanonicalTopology { .. }
        ))
    ));
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one table-driven audit keeps every public resource boundary together"
)]
fn every_declared_resource_boundary_refuses_cleanly() {
    let built = build_exact_literal::<Span>(
        b"abcdefgh",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .unwrap();
    let baseline = built
        .raw()
        .clone()
        .validate::<Span>(ValidateLimits::default())
        .expect("raw-validation accounting baseline");
    let stats = baseline.stats();
    let resources = stats.resources();

    let cases = [
        (
            ResourceKind::Blocks,
            ValidateLimits {
                max_blocks: 3,
                ..ValidateLimits::default()
            },
        ),
        (
            ResourceKind::DataBlobs,
            ValidateLimits {
                max_data_blobs: 0,
                ..ValidateLimits::default()
            },
        ),
        (
            ResourceKind::Instructions,
            ValidateLimits {
                max_instructions: 3,
                ..ValidateLimits::default()
            },
        ),
        (
            ResourceKind::DataBytes,
            ValidateLimits {
                max_data_bytes: 7,
                ..ValidateLimits::default()
            },
        ),
        (
            ResourceKind::SerializedBytes,
            ValidateLimits {
                max_serialized_bytes: u64::try_from(stats.serialized_bytes() - 1).unwrap(),
                ..ValidateLimits::default()
            },
        ),
        (
            ResourceKind::SerializedCapacityBytes,
            ValidateLimits {
                max_serialized_capacity_bytes: u64::try_from(
                    resources.serialized_capacity_bytes() - 1,
                )
                .unwrap(),
                ..ValidateLimits::default()
            },
        ),
        (
            ResourceKind::ConstructionAllocationBytes,
            ValidateLimits {
                max_construction_allocation_bytes: u64::try_from(
                    resources.allocation_request_bytes() - 1,
                )
                .unwrap(),
                ..ValidateLimits::default()
            },
        ),
        (
            ResourceKind::RawProgramCapacityBytes,
            ValidateLimits {
                max_raw_program_capacity_bytes: u64::try_from(
                    resources.raw_program_capacity_bytes() - 1,
                )
                .unwrap(),
                ..ValidateLimits::default()
            },
        ),
        (
            ResourceKind::EstimatedCodeBytes,
            ValidateLimits {
                max_estimated_code_bytes: u64::try_from(stats.estimated_code_bytes() - 1).unwrap(),
                ..ValidateLimits::default()
            },
        ),
        (
            ResourceKind::ValidationWork,
            ValidateLimits {
                max_validation_work: resources.validation_work_upper_bound() - 1,
                ..ValidateLimits::default()
            },
        ),
        (
            ResourceKind::ConstructionWork,
            ValidateLimits {
                max_construction_work: resources.construction_work() - 1,
                ..ValidateLimits::default()
            },
        ),
        (
            ResourceKind::ValidationScratchBytes,
            ValidateLimits {
                max_validation_scratch_bytes: 1,
                ..ValidateLimits::default()
            },
        ),
        (
            ResourceKind::ValidationPhaseBytes,
            ValidateLimits {
                max_validation_phase_bytes: u64::try_from(
                    resources.validation_phase_peak_bytes() - 1,
                )
                .unwrap(),
                ..ValidateLimits::default()
            },
        ),
        (
            ResourceKind::SerializationPhaseBytes,
            ValidateLimits {
                max_serialization_phase_bytes: u64::try_from(
                    resources.serialization_phase_peak_bytes() - 1,
                )
                .unwrap(),
                ..ValidateLimits::default()
            },
        ),
        (
            ResourceKind::IdentityPhaseBytes,
            ValidateLimits {
                max_identity_phase_bytes: u64::try_from(resources.identity_phase_peak_bytes() - 1)
                    .unwrap(),
                ..ValidateLimits::default()
            },
        ),
        (
            ResourceKind::RetainedProgramBytes,
            ValidateLimits {
                max_retained_program_bytes: u64::try_from(resources.retained_program_bytes() - 1)
                    .unwrap(),
                ..ValidateLimits::default()
            },
        ),
        (
            ResourceKind::WorkFactor,
            ValidateLimits {
                max_work_factor: stats.work_factor() - 1,
                ..ValidateLimits::default()
            },
        ),
    ];
    for (resource, limits) in cases {
        let error = baseline.raw().clone().validate::<Span>(limits).unwrap_err();
        assert!(
            matches!(
                error,
                ValidateError::ResourceLimit {
                    resource: actual,
                    ..
                } if actual == resource
            ),
            "expected {resource:?}, got {error:?}"
        );
    }
}

#[test]
fn fixed_shape_prospective_refuses_before_owned_construction() {
    let baseline = build_exact_literal::<Span>(
        b"abcdefgh",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("accounting baseline");
    let resources = baseline.stats().resources();
    for (expected, limits) in [
        (
            ResourceKind::ConstructionAllocationBytes,
            ValidateLimits {
                max_construction_allocation_bytes: u64::try_from(
                    resources.allocation_request_bytes() - 1,
                )
                .unwrap(),
                ..ValidateLimits::default()
            },
        ),
        (
            ResourceKind::ConstructionWork,
            ValidateLimits {
                max_construction_work: resources.construction_work() - 1,
                ..ValidateLimits::default()
            },
        ),
        (
            ResourceKind::ValidationScratchBytes,
            ValidateLimits {
                max_validation_scratch_bytes: u64::try_from(
                    resources.validation_scratch_bytes() - 1,
                )
                .unwrap(),
                ..ValidateLimits::default()
            },
        ),
    ] {
        let error = build_exact_literal::<Span>(b"abcdefgh", AnchorFlags::default(), limits)
            .expect_err("one-below prospective bound refuses");
        assert!(
            matches!(
                error,
                BuildError::Validate(ValidateError::ResourceLimit {
                    resource,
                    ..
                }) if resource == expected
            ),
            "expected {expected:?}, got {error:?}"
        );
    }
}

#[test]
fn raw_metadata_planning_is_admitted_before_adversarial_pair_planning() {
    let program = build_exact_literal::<Span>(
        b"abcdefgh",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("raw planning baseline");
    let mut raw = program.raw().clone();
    for byte in 1_u8..16 {
        raw.data.push(DataBlob::Bytes(vec![byte; 256]));
    }
    let planning_work =
        crate::validate::raw_metadata_planning_work_for_test(raw.blocks.len(), raw.data.len())
            .expect("hard-bounded planning envelope");
    assert_eq!(planning_work, 280);

    for limit in [0, planning_work - 1] {
        crate::validate::reset_pair_planning_steps();
        let error = raw
            .clone()
            .validate::<Span>(ValidateLimits {
                max_construction_work: limit,
                ..ValidateLimits::default()
            })
            .expect_err("planning must be admitted before pair traversal");
        assert!(matches!(
            error,
            ValidateError::ResourceLimit {
                resource: ResourceKind::ConstructionWork,
                ..
            }
        ));
        assert_eq!(
            crate::validate::pair_planning_steps(),
            0,
            "pair planner ran before its construction-work envelope was admitted"
        );
    }

    crate::validate::reset_pair_planning_steps();
    let error = raw
        .validate::<Span>(ValidateLimits {
            max_construction_work: planning_work,
            ..ValidateLimits::default()
        })
        .expect_err("planning alone cannot cover complete construction");
    assert!(matches!(
        error,
        ValidateError::ResourceLimit {
            resource: ResourceKind::ConstructionWork,
            ..
        }
    ));
    assert_eq!(crate::validate::pair_planning_steps(), 120);
}

#[test]
fn raw_validation_accounts_allocator_excess_before_serialization() {
    let program = build_exact_literal::<Span>(
        b"abcdefgh",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("raw capacity baseline");
    let mut raw = program.raw().clone();
    raw.blocks
        .try_reserve_exact(16)
        .expect("small test-only excess capacity");
    assert!(raw.blocks.capacity() > raw.blocks.len());
    raw.data
        .try_reserve_exact(8)
        .expect("small test-only excess capacity");
    assert!(raw.data.capacity() > raw.data.len());
    let DataBlob::Bytes(literal) = &mut raw.data[0] else {
        panic!("exact literal program stores literal bytes");
    };
    literal
        .try_reserve_exact(32)
        .expect("small test-only literal excess capacity");
    assert!(literal.capacity() > literal.len());
    let observed = raw
        .blocks
        .capacity()
        .checked_mul(core::mem::size_of::<Block>())
        .and_then(|bytes| {
            raw.data
                .capacity()
                .checked_mul(core::mem::size_of::<DataBlob>())
                .and_then(|data| bytes.checked_add(data))
        })
        .and_then(|bytes| match &raw.data[0] {
            DataBlob::Bytes(literal) => bytes.checked_add(literal.capacity()),
            DataBlob::ByteClass(_) => None,
        })
        .expect("small observed capacity");
    let error = raw
        .validate::<Span>(ValidateLimits {
            max_raw_program_capacity_bytes: u64::try_from(observed - 1).unwrap(),
            ..ValidateLimits::default()
        })
        .expect_err("observed allocator excess is authoritative");
    assert!(matches!(
        error,
        ValidateError::ResourceLimit {
            resource: ResourceKind::RawProgramCapacityBytes,
            required,
            ..
        } if required == u64::try_from(observed).unwrap()
    ));
}

#[test]
fn inclusive_resource_limits_accept_exact_boundaries() {
    let built = build_exact_literal::<Span>(
        b"abcdefgh",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .unwrap();
    let baseline = built
        .raw()
        .clone()
        .validate::<Span>(ValidateLimits::default())
        .expect("raw-validation accounting baseline");
    let stats = baseline.stats();
    let resources = stats.resources();
    let exact = ValidateLimits {
        max_blocks: u64::try_from(stats.blocks()).unwrap(),
        max_instructions: u64::try_from(stats.instructions()).unwrap(),
        max_data_blobs: u64::try_from(stats.data_blobs()).unwrap(),
        max_data_bytes: u64::try_from(stats.data_bytes()).unwrap(),
        max_serialized_bytes: u64::try_from(stats.serialized_bytes()).unwrap(),
        max_serialized_capacity_bytes: u64::try_from(resources.serialized_capacity_bytes())
            .unwrap(),
        max_construction_allocation_bytes: u64::try_from(resources.allocation_request_bytes())
            .unwrap(),
        max_raw_program_capacity_bytes: u64::try_from(resources.raw_program_capacity_bytes())
            .unwrap(),
        max_estimated_code_bytes: u64::try_from(stats.estimated_code_bytes()).unwrap(),
        max_validation_work: resources.validation_work_upper_bound(),
        max_construction_work: resources.construction_work(),
        max_validation_scratch_bytes: u64::try_from(resources.validation_scratch_bytes()).unwrap(),
        max_validation_phase_bytes: u64::try_from(resources.validation_phase_peak_bytes()).unwrap(),
        max_serialization_phase_bytes: u64::try_from(resources.serialization_phase_peak_bytes())
            .unwrap(),
        max_identity_phase_bytes: u64::try_from(resources.identity_phase_peak_bytes()).unwrap(),
        max_retained_program_bytes: u64::try_from(resources.retained_program_bytes()).unwrap(),
        max_work_factor: stats.work_factor(),
    };
    let replay = baseline
        .raw()
        .clone()
        .validate::<Span>(exact)
        .expect("all inclusive limits accept their exact boundary");
    assert_same_program_dimensions(replay.stats(), stats);
}

#[test]
fn execution_budget_and_invalid_windows_are_checked() {
    let program =
        build_exact_literal::<Span>(b"aaab", AnchorFlags::default(), ValidateLimits::default())
            .unwrap();
    let haystack = b"aaaaaaaaaaaaaaaa";
    let window = SearchWindow::new(0, haystack.len());
    let work = program
        .execute(haystack, window, ExecutionLimits::unlimited())
        .unwrap()
        .work();
    let error = program
        .execute(haystack, window, ExecutionLimits { max_work: work - 1 })
        .unwrap_err();
    assert_eq!(
        error,
        ExecuteError::WorkLimitExceeded {
            limit: work - 1,
            consumed: work - 1
        }
    );
    assert!(matches!(
        program.execute(
            haystack,
            SearchWindow::new(7, 6),
            ExecutionLimits::unlimited()
        ),
        Err(ExecuteError::InvalidWindow { .. })
    ));
    assert!(matches!(
        program.execute(
            haystack,
            SearchWindow::new(0, haystack.len() + 1),
            ExecutionLimits::unlimited()
        ),
        Err(ExecuteError::InvalidWindow { .. })
    ));
}

#[test]
fn checked_window_binds_exact_haystack_and_range() {
    let haystack = b"0123456789";
    let window = SearchWindow::new(2, 8);
    let checked = CheckedSearchWindow::new(haystack, window).expect("valid checked window");
    assert_eq!(checked.haystack(), haystack);
    assert_eq!(checked.window(), window);
    assert_eq!(checked.searched_bytes(), 6);
    assert!(CheckedSearchWindow::new(haystack, SearchWindow::new(8, 2)).is_none());
    assert!(CheckedSearchWindow::new(haystack, SearchWindow::new(2, 11)).is_none());
}

#[test]
fn charged_work_scales_linearly_for_fixed_patterns() {
    let literal = build_exact_literal::<Span>(
        b"aaaaaaaX",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .unwrap();
    let class = build_class_suffix::<Span>(
        ByteClass::from_bytes(b"a"),
        b"X",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .unwrap();
    let mut previous_literal = None;
    let mut previous_class = None;
    for length in [64_usize, 128, 256, 512, 1_024] {
        let literal_haystack = vec![b'a'; length];
        let class_haystack = alternating(length);
        let literal_work = literal
            .execute(
                &literal_haystack,
                SearchWindow::new(0, length),
                ExecutionLimits::unlimited(),
            )
            .unwrap()
            .work();
        let class_work = class
            .execute(
                &class_haystack,
                SearchWindow::new(0, length),
                ExecutionLimits::unlimited(),
            )
            .unwrap()
            .work();
        assert!(
            literal_work
                <= literal
                    .conservative_work_bound(length)
                    .expect("bounded length")
        );
        assert!(
            class_work
                <= class
                    .conservative_work_bound(length)
                    .expect("bounded length")
        );
        if let Some(previous) = previous_literal {
            assert!(literal_work <= previous * 3);
        }
        if let Some(previous) = previous_class {
            assert!(class_work <= previous * 3);
        }
        previous_literal = Some(literal_work);
        previous_class = Some(class_work);
    }
}

fn mutate(raw: &RawProgram, change: impl FnOnce(&mut RawProgram)) -> RawProgram {
    let mut raw = raw.clone();
    change(&mut raw);
    raw
}

fn assert_same_program_dimensions(left: crate::ProgramStats, right: crate::ProgramStats) {
    assert_eq!(left.blocks(), right.blocks());
    assert_eq!(left.instructions(), right.instructions());
    assert_eq!(left.data_blobs(), right.data_blobs());
    assert_eq!(left.data_bytes(), right.data_bytes());
    assert_eq!(left.serialized_bytes(), right.serialized_bytes());
    assert_eq!(left.estimated_code_bytes(), right.estimated_code_bytes());
    assert_eq!(left.work_factor(), right.work_factor());
}

fn assert_invalid(raw: RawProgram, expected: InvalidProgram) {
    assert_eq!(
        raw.validate::<Span>(ValidateLimits::default()).unwrap_err(),
        ValidateError::Invalid(expected)
    );
}

fn anchors() -> [AnchorFlags; 4] {
    [
        AnchorFlags::default(),
        AnchorFlags {
            start: true,
            end: false,
        },
        AnchorFlags {
            start: false,
            end: true,
        },
        AnchorFlags {
            start: true,
            end: true,
        },
    ]
}

#[allow(
    clippy::too_many_lines,
    reason = "one helper audits every exact/one-below aggregate ceiling together"
)]
fn assert_exact_aggregate_bounds<A: AggregateOperation>(literal: &[u8], haystack: &[u8]) {
    let program =
        build_exact_aggregate::<A>(literal, ValidateLimits::default()).expect("aggregate program");
    let upper = program
        .upper_bounds(haystack.len())
        .expect("aggregate bounds");
    let output = match A::OUTPUT {
        AggregateOutput::Count => upper.count,
        AggregateOutput::SpanSum => upper.span_sum,
    };
    let exact = AggregateExecutionLimits {
        max_haystack_bytes: upper.haystack_bytes,
        max_literal_bytes: upper.literal_bytes,
        max_candidate_positions: upper.candidate_positions,
        max_work: upper.work,
        max_match_events: upper.match_events,
        max_output: output,
        max_reducer_steps: upper.reducer_steps,
        max_scratch_bytes: upper.scratch_bytes,
        max_native_invocations: upper.native_invocations,
    };
    program
        .execute(haystack, exact)
        .expect("exact aggregate bounds succeed");
    for (limits, expected) in [
        (
            AggregateExecutionLimits {
                max_work: upper.work.checked_sub(1).expect("nonzero work"),
                ..exact
            },
            "work",
        ),
        (
            AggregateExecutionLimits {
                max_match_events: upper
                    .match_events
                    .checked_sub(1)
                    .expect("nonzero event bound"),
                ..exact
            },
            "events",
        ),
        (
            AggregateExecutionLimits {
                max_reducer_steps: upper
                    .reducer_steps
                    .checked_sub(1)
                    .expect("nonzero step bound"),
                ..exact
            },
            "steps",
        ),
    ] {
        let error = program
            .execute(haystack, limits)
            .expect_err("one-below aggregate bound refuses");
        assert!(
            matches!(
                (&error, expected),
                (AggregateExecuteError::WorkLimit { .. }, "work")
                    | (AggregateExecuteError::MatchEventsLimit { .. }, "events")
                    | (AggregateExecuteError::ReducerStepsLimit { .. }, "steps")
            ),
            "wrong {expected} error: {error:?}"
        );
    }
    if output != 0 {
        let error = program
            .execute(
                haystack,
                AggregateExecutionLimits {
                    max_output: output.checked_sub(1).expect("nonzero output"),
                    ..exact
                },
            )
            .expect_err("one-below output bound refuses");
        assert!(matches!(error, AggregateExecuteError::OutputLimit { .. }));
    }
    for (needed, limits, expected) in [
        (
            upper.haystack_bytes,
            AggregateExecutionLimits {
                max_haystack_bytes: upper.haystack_bytes.saturating_sub(1),
                ..exact
            },
            "haystack",
        ),
        (
            upper.literal_bytes,
            AggregateExecutionLimits {
                max_literal_bytes: upper.literal_bytes.saturating_sub(1),
                ..exact
            },
            "literal",
        ),
        (
            upper.candidate_positions,
            AggregateExecutionLimits {
                max_candidate_positions: upper.candidate_positions.saturating_sub(1),
                ..exact
            },
            "candidates",
        ),
    ] {
        if needed == 0 {
            program
                .execute(haystack, limits)
                .expect("zero resource ceiling accepts zero need");
            continue;
        }
        let error = program
            .execute(haystack, limits)
            .expect_err("positive resource one-below refuses");
        assert!(
            matches!(
                (&error, expected),
                (AggregateExecuteError::HaystackBytesLimit { .. }, "haystack")
                    | (AggregateExecuteError::LiteralBytesLimit { .. }, "literal")
                    | (
                        AggregateExecuteError::CandidatePositionsLimit { .. },
                        "candidates"
                    )
            ),
            "wrong {expected} error: {error:?}"
        );
    }
    let error = program
        .execute(
            haystack,
            AggregateExecutionLimits {
                max_native_invocations: upper
                    .native_invocations
                    .checked_sub(1)
                    .expect("positive invocation bound"),
                ..exact
            },
        )
        .expect_err("one below invocation bound refuses");
    assert!(matches!(
        error,
        AggregateExecuteError::NativeInvocationsLimit { .. }
    ));
}

fn direct_exact_aggregate(haystack: &[u8], literal: &[u8]) -> (u64, u64) {
    if literal.is_empty() {
        return (
            u64::try_from(haystack.len().checked_add(1).expect("small corpus")).expect("small"),
            0,
        );
    }
    let mut cursor = 0_usize;
    let mut count = 0_u64;
    while let Some(end) = cursor.checked_add(literal.len()) {
        if end > haystack.len() {
            break;
        }
        if haystack.get(cursor..end) == Some(literal) {
            count = count.checked_add(1).expect("small corpus");
            cursor = end;
        } else {
            cursor = cursor.checked_add(1).expect("small corpus");
        }
    }
    let width = u64::try_from(literal.len()).expect("small corpus");
    (count, count.checked_mul(width).expect("small corpus"))
}

fn words(alphabet: &[u8], max_length: usize) -> Vec<Vec<u8>> {
    let mut all = vec![Vec::new()];
    let mut frontier = vec![Vec::new()];
    for _ in 0..max_length {
        let mut next = Vec::new();
        for prefix in &frontier {
            for byte in alphabet {
                let mut word = prefix.clone();
                word.push(*byte);
                next.push(word.clone());
                all.push(word);
            }
        }
        frontier = next;
    }
    all
}

fn windows(length: usize) -> Vec<SearchWindow> {
    let mut windows = Vec::new();
    for start in 0..=length {
        for end in start..=length {
            windows.push(SearchWindow::new(start, end));
        }
    }
    windows
}

fn direct_literal(
    haystack: &[u8],
    window: SearchWindow,
    literal: &[u8],
    anchors: AnchorFlags,
) -> Option<MatchSpan> {
    for start in window.start()..=window.end() {
        if anchors.start && start != 0 {
            continue;
        }
        let Some(end) = start.checked_add(literal.len()) else {
            continue;
        };
        if end > window.end() || (anchors.end && end != haystack.len()) {
            continue;
        }
        if haystack.get(start..end) == Some(literal) {
            return Some(MatchSpan::new(start, end));
        }
    }
    None
}

fn direct_class_suffix(
    haystack: &[u8],
    window: SearchWindow,
    class: ByteClass,
    suffix: &[u8],
    anchors: AnchorFlags,
) -> Option<MatchSpan> {
    let mut start = window.start();
    while start < window.end() {
        if anchors.start && start != 0 {
            return None;
        }
        if !class.contains(haystack[start]) {
            start = start.checked_add(1).expect("bounded test index");
            continue;
        }
        let mut run_end = start.checked_add(1).expect("bounded test index");
        while run_end < window.end() && class.contains(haystack[run_end]) {
            run_end = run_end.checked_add(1).expect("bounded test index");
        }
        let end = run_end.checked_add(suffix.len())?;
        if end <= window.end()
            && (!anchors.end || end == haystack.len())
            && haystack.get(run_end..end) == Some(suffix)
        {
            return Some(MatchSpan::new(start, end));
        }
        start = run_end;
    }
    None
}

fn alternating(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| if index % 2 == 0 { b'a' } else { b'Y' })
        .collect()
}

struct DeterministicRandom(u64);

impl DeterministicRandom {
    fn next(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        u32::try_from(self.0 >> 32).expect("upper half fits u32")
    }

    fn below(&mut self, bound: u32) -> u32 {
        self.next()
            .checked_rem(bound)
            .expect("all bounds are nonzero")
    }
}

fn random_raw(random: &mut DeterministicRandom) -> RawProgram {
    let block_count = usize::try_from(random.below(17)).expect("small count");
    let data_count = usize::try_from(random.below(17)).expect("small count");
    let mut blocks = Vec::with_capacity(block_count);
    for _ in 0..block_count {
        let first = BlockId(random.below(17));
        let second = BlockId(random.below(17));
        let data = crate::DataId(random.below(9));
        let op = match random.below(8) {
            0 => BlockOp::Entry { next: first },
            1 => BlockOp::ScanLiteral {
                needle: data,
                anchors: AnchorFlags {
                    start: random.below(2) != 0,
                    end: random.below(2) != 0,
                },
                matched: first,
                exhausted: second,
            },
            2 => BlockOp::ScanClassStart {
                class: data,
                anchored_start: random.below(2) != 0,
                run: first,
                exhausted: second,
            },
            3 => BlockOp::ExtendClassRun {
                class: data,
                next: first,
            },
            4 => BlockOp::ConfirmSuffix {
                suffix: data,
                anchored_end: random.below(2) != 0,
                matched: first,
                rejected: second,
            },
            5 => BlockOp::AdvanceAfterReject { next: first },
            6 => BlockOp::ReturnFound,
            _ => BlockOp::ReturnNone,
        };
        blocks.push(Block { op });
    }
    let mut data = Vec::with_capacity(data_count);
    for _ in 0..data_count {
        if random.below(2) == 0 {
            let length = usize::try_from(random.below(6)).expect("small length");
            let mut bytes = Vec::with_capacity(length);
            for _ in 0..length {
                bytes.push(random.next().to_le_bytes()[0]);
            }
            data.push(DataBlob::Bytes(bytes));
        } else {
            let bytes = random.next().to_le_bytes();
            data.push(DataBlob::ByteClass(ByteClass::from_bytes(&bytes)));
        }
    }
    RawProgram {
        schema_version: RawProgram::SCHEMA_VERSION,
        semantics: SemanticsVersion::CURRENT,
        abi: AbiVersion::CURRENT,
        output: OutputKind::Span,
        entry: BlockId(random.below(17)),
        blocks,
        data,
    }
}
