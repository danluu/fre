use fre_kernel_ir::{Count, ExactAggregateProgram, ValidateLimits, build_exact_aggregate};

use super::*;

fn program(literal: &[u8]) -> ExactAggregateProgram<Count> {
    build_exact_aggregate::<Count>(literal, ValidateLimits::default())
        .expect("bounded exact Count program")
}

fn optimize(literal: &[u8]) -> OptimizedCountV3 {
    optimize_count_v3(
        &program(literal),
        CountV3TuningClass::GenericAarch64,
        CountV3OptimizerLimits::default(),
    )
    .expect("bounded Count-v3 optimization")
}

#[test]
fn selection_and_every_identity_are_deterministic() {
    let left_program = program(b"header: x-fre-request-id");
    let right_program = program(b"header: x-fre-request-id");
    let left = optimize_count_v3(
        &left_program,
        CountV3TuningClass::NeoverseV2V3,
        CountV3OptimizerLimits::default(),
    )
    .expect("first optimization");
    let right = optimize_count_v3(
        &right_program,
        CountV3TuningClass::NeoverseV2V3,
        CountV3OptimizerLimits::default(),
    )
    .expect("second optimization");
    assert_eq!(left, right);
    assert!(left.receipt().authenticates());
    assert_eq!(
        encode_count_recipe_v3(left.recipe()),
        encode_count_recipe_v3(right.recipe())
    );
    let receipt_bytes = encode_count_v3_optimizer_receipt(left.receipt());
    assert_eq!(
        &receipt_bytes[COUNT_V3_OPTIMIZER_RECEIPT_CANONICAL_BYTES - 32..],
        left.receipt().identity().as_bytes()
    );
    validate_count_recipe_v3(&left_program, left.recipe()).expect("sealed recipe");
}

#[test]
fn explicit_isa_plans_are_sealed_before_recipe_identity() {
    let program = program(b"target-aware-recipe");
    let optimize_for = |required_isa| {
        optimize_count_v3_for_isa(
            &program,
            CountV3TuningClass::NeoverseV2V3,
            required_isa,
            CountV3OptimizerLimits::default(),
        )
        .expect("target-aware optimization")
    };
    let neon = optimize_for(CountV3RequiredIsa::Aarch64Neon128);
    let sve = optimize_for(CountV3RequiredIsa::Aarch64SveVl16);
    let sve2 = optimize_for(CountV3RequiredIsa::Aarch64Sve2Vl16);

    for (optimized, required_isa, register_plan) in [
        (
            &neon,
            CountV3RequiredIsa::Aarch64Neon128,
            CountV3RegisterPlanId::Aarch64NeonV1,
        ),
        (
            &sve,
            CountV3RequiredIsa::Aarch64SveVl16,
            CountV3RegisterPlanId::Aarch64SveVl16V1,
        ),
        (
            &sve2,
            CountV3RequiredIsa::Aarch64Sve2Vl16,
            CountV3RegisterPlanId::Aarch64Sve2Vl16V1,
        ),
    ] {
        assert_eq!(optimized.recipe().required_isa(), required_isa);
        assert_eq!(optimized.recipe().register_plan_id(), register_plan);
        validate_count_recipe_v3(&program, optimized.recipe()).expect("sealed target recipe");
        assert_eq!(
            decode_count_recipe_v3(&program, &encode_count_recipe_v3(optimized.recipe()))
                .expect("target-aware canonical decode"),
            *optimized.recipe()
        );
    }

    assert_ne!(neon.recipe().identity(), sve.recipe().identity());
    assert_ne!(sve.recipe().identity(), sve2.recipe().identity());
    assert_ne!(neon.receipt().identity(), sve.receipt().identity());
    assert_ne!(sve.receipt().identity(), sve2.receipt().identity());
}

#[test]
fn sve_costs_follow_the_shared_lowering_instead_of_strategy_labels() {
    let literal = b"target-aware-recipe";
    let mut work = Work::default();
    let analysis = analyze_literal(literal, &mut work).expect("literal analysis");
    let filters = [0, u8::try_from(literal.len() - 1).expect("bounded literal")];

    let sve_incumbent = estimate_costs(
        literal,
        analysis.facts,
        &analysis.multiplicity,
        CountV3RequiredIsa::Aarch64SveVl16,
        CountV3Strategy::Incumbent,
        &filters,
    )
    .expect("SVE incumbent costs");
    let sve_endpoint = estimate_costs(
        literal,
        analysis.facts,
        &analysis.multiplicity,
        CountV3RequiredIsa::Aarch64SveVl16,
        CountV3Strategy::EndpointDense,
        &filters,
    )
    .expect("SVE endpoint costs");
    assert_eq!(sve_incumbent, sve_endpoint);

    let neon_incumbent = estimate_costs(
        literal,
        analysis.facts,
        &analysis.multiplicity,
        CountV3RequiredIsa::Aarch64Neon128,
        CountV3Strategy::Incumbent,
        &filters,
    )
    .expect("NEON incumbent costs");
    let neon_endpoint = estimate_costs(
        literal,
        analysis.facts,
        &analysis.multiplicity,
        CountV3RequiredIsa::Aarch64Neon128,
        CountV3Strategy::EndpointDense,
        &filters,
    )
    .expect("NEON endpoint costs");
    assert_ne!(neon_incumbent, neon_endpoint);

    let sve2_endpoint = estimate_costs(
        literal,
        analysis.facts,
        &analysis.multiplicity,
        CountV3RequiredIsa::Aarch64Sve2Vl16,
        CountV3Strategy::EndpointDense,
        &filters,
    )
    .expect("SVE2 endpoint costs");
    assert!(sve2_endpoint.sparse > sve_endpoint.sparse);
    assert!(sve2_endpoint.dense > sve_endpoint.dense);
}

#[test]
fn periodic_portfolio_competes_over_every_bounded_filter_prefix() {
    let literal = b"abababab";
    let mut work = Work::default();
    let analysis = analyze_literal(literal, &mut work).expect("periodic literal analysis");
    let frontier = build_column_frontier(literal, &analysis, &mut work).expect("periodic frontier");
    let expected = count_portfolio(
        literal,
        analysis.facts,
        &analysis.multiplicity,
        &frontier,
        &mut work,
    )
    .expect("periodic portfolio count");
    let candidates = build_portfolio(
        literal,
        analysis.facts,
        &analysis.multiplicity,
        &frontier,
        CountV3RequiredIsa::Aarch64Neon128,
        expected,
        &mut work,
    )
    .expect("periodic portfolio");
    let periodic_filter_counts = candidates
        .iter()
        .filter(|candidate| candidate.strategy == CountV3Strategy::PeriodicRun)
        .map(|candidate| candidate.filter_count)
        .collect::<Vec<_>>();
    assert_eq!(periodic_filter_counts, vec![2, 3, 4]);
}

#[test]
fn canonical_inspection_and_decode_are_strict() {
    let source_program = program(b"0123456789abcdef");
    let optimized = optimize_count_v3(
        &source_program,
        CountV3TuningClass::AppleMSeries,
        CountV3OptimizerLimits::default(),
    )
    .expect("optimization");
    let canonical = encode_count_recipe_v3(optimized.recipe());
    let inspected = inspect_count_recipe_v3(&canonical).expect("canonical inspection");
    assert_eq!(
        inspected.program_identity(),
        source_program.cache_identity().as_bytes()
    );
    assert_eq!(inspected.identity(), optimized.recipe().identity());
    assert_eq!(
        decode_count_recipe_v3(&source_program, &canonical).expect("strict decode"),
        *optimized.recipe()
    );
    let other_program = program(b"fedcba9876543210");
    assert_eq!(
        decode_count_recipe_v3(&other_program, &canonical),
        Err(CountV3RecipeDecodeError::ProgramIdentity)
    );

    let mut noncanonical = canonical;
    noncanonical[200] = 1;
    assert_eq!(
        inspect_count_recipe_v3(&noncanonical),
        Err(CountV3RecipeDecodeError::NonCanonicalPadding)
    );
    let mut corrupt_identity = canonical;
    corrupt_identity[255] ^= 1;
    assert_eq!(
        inspect_count_recipe_v3(&corrupt_identity),
        Err(CountV3RecipeDecodeError::RecipeIdentity)
    );
}

#[test]
fn canonical_optimizer_receipt_inspection_is_strict_and_allocation_free() {
    let optimized = optimize(b"receipt-inspection");
    let canonical = encode_count_v3_optimizer_receipt(optimized.receipt());
    let inspected =
        inspect_count_v3_optimizer_receipt(&canonical).expect("canonical optimizer receipt");
    assert_eq!(
        inspected.program_identity(),
        optimized.receipt().program_identity().as_bytes()
    );
    assert_eq!(
        inspected.recipe_identity(),
        optimized.receipt().recipe_identity()
    );
    assert_eq!(inspected.tuning_class(), optimized.receipt().tuning_class());
    assert_eq!(inspected.resources(), optimized.receipt().resources());
    assert_eq!(
        inspected.chosen_ordinal(),
        optimized.receipt().chosen_ordinal()
    );
    assert_eq!(
        inspected.minimax_regret(),
        optimized.receipt().minimax_regret()
    );
    assert_eq!(inspected.identity(), optimized.receipt().identity());

    let mut padding = canonical;
    padding[13] = 1;
    assert_eq!(
        inspect_count_v3_optimizer_receipt(&padding),
        Err(CountV3OptimizerReceiptDecodeError::NonCanonicalPadding)
    );
    let mut resource = canonical;
    resource[128] ^= 1;
    assert_eq!(
        inspect_count_v3_optimizer_receipt(&resource),
        Err(CountV3OptimizerReceiptDecodeError::InvalidResources)
    );
    let mut identity = canonical;
    identity[191] ^= 1;
    assert_eq!(
        inspect_count_v3_optimizer_receipt(&identity),
        Err(CountV3OptimizerReceiptDecodeError::ReceiptIdentity)
    );
}

#[test]
fn literal_facts_use_kmp_minimum_period_and_self_overlap() {
    let optimized = optimize(b"abababab");
    let facts = optimized.facts();
    assert_eq!(facts.literal_bytes(), 8);
    assert_eq!(facts.distinct_bytes(), 2);
    assert_eq!(facts.minimum_period(), 2);
    assert_eq!(facts.self_overlap_bytes(), 6);
    assert_eq!(facts.full_period_repetitions(), 4);
    assert!(facts.is_periodic());
    assert_eq!(optimized.recipe().strategy(), CountV3Strategy::PeriodicRun);
    assert_eq!(optimized.recipe().periodic_stride(), 2);

    let partial = optimize(b"abcab");
    assert_eq!(partial.facts().minimum_period(), 3);
    assert_eq!(partial.facts().self_overlap_bytes(), 2);
    assert!(partial.facts().is_periodic());
}

#[test]
fn primary_filter_rank_is_pattern_only_and_encoding_structural() {
    for literal in ["абабаб".as_bytes(), "中文中文".as_bytes()] {
        let optimized = optimize(literal);
        assert_eq!(optimized.recipe().strategy(), CountV3Strategy::PeriodicRun);
        let primary = literal[usize::from(optimized.recipe().filter_offsets()[0])];
        assert!(
            (0x80..=0xbf).contains(&primary),
            "UTF-8 continuation should precede a repeated lead byte"
        );

        let mut work = Work::default();
        let analysis = analyze_literal(literal, &mut work).unwrap();
        assert!(
            optimized
                .recipe()
                .filter_offsets()
                .windows(2)
                .all(|pair| column_rank(literal, &analysis.multiplicity, pair[0])
                    <= column_rank(literal, &analysis.multiplicity, pair[1]))
        );
        validate_count_recipe_v3(&program(literal), optimized.recipe()).unwrap();
    }

    let english = b"eta";
    let mut work = Work::default();
    let analysis = analyze_literal(english, &mut work).unwrap();
    let e = column_rank(english, &analysis.multiplicity, 0);
    let t = column_rank(english, &analysis.multiplicity, 1);
    let a = column_rank(english, &analysis.multiplicity, 2);
    assert_eq!((e.0, e.1), (t.0, t.1));
    assert_eq!((t.0, t.1), (a.0, a.1));
    let mut reversed = [2, 1, 0];
    canonicalize_filter_order(
        english,
        &analysis.multiplicity,
        CountV3Strategy::SparseRareColumns,
        &mut reversed,
    );
    assert_eq!(reversed, [0, 1, 2]);

    let endpoint_literal = "a中".as_bytes();
    let mut work = Work::default();
    let endpoint_analysis = analyze_literal(endpoint_literal, &mut work).unwrap();
    let endpoints = ranked_endpoint_pair(endpoint_literal, &endpoint_analysis.multiplicity);
    assert_eq!(
        endpoints,
        [u8::try_from(endpoint_literal.len() - 1).unwrap(), 0,]
    );
}

#[test]
fn short_non_overlapping_literals_select_direct_exact_masks() {
    for literal in [&b"ab"[..], &b"abc"[..], &b"abcd"[..]] {
        let optimized = optimize(literal);
        assert_eq!(
            optimized.recipe().strategy(),
            CountV3Strategy::DirectExactMask
        );
        assert_eq!(
            optimized.recipe().schedule_id(),
            CountV3ScheduleId::DirectExactMaskV1
        );
        assert_eq!(
            optimized.recipe().filter_offsets(),
            &[0, 1, 2, 3][..literal.len()]
        );
        assert_eq!(
            optimized.facts().minimum_period(),
            u8::try_from(literal.len()).unwrap()
        );
    }

    assert_ne!(
        optimize(b"aaa").recipe().strategy(),
        CountV3Strategy::DirectExactMask
    );
}

#[test]
fn binary_literals_are_not_text_normalized() {
    let literal = [
        0x00, 0xff, 0x80, 0x00, 0x7f, 0x01, 0xfe, 0x80, 0x11, 0xee, 0x22, 0xdd,
    ];
    let program = program(&literal);
    let optimized = optimize_count_v3(
        &program,
        CountV3TuningClass::GenericAarch64,
        CountV3OptimizerLimits::default(),
    )
    .expect("binary optimization");
    assert_eq!(optimized.facts().distinct_bytes(), 10);
    assert_eq!(optimized.facts().maximum_multiplicity(), 2);
    assert_eq!(optimized.recipe().match_stride(), literal.len() as u8);
    validate_count_recipe_v3(&program, optimized.recipe()).expect("binary recipe validation");
}

#[test]
fn optimization_is_pattern_only_and_has_no_haystack_channel() {
    let literal = b"same-pattern-only";
    let first = optimize(literal);
    let second = optimize(literal);
    assert_eq!(first, second);
    assert_eq!(first.receipt().resources(), second.receipt().resources());
    assert_eq!(
        first.recipe().literal_identity(),
        second.recipe().literal_identity()
    );
}

#[test]
fn recipe_literal_identity_is_explicitly_domain_separated() {
    let literal = b"literal-identity";
    let optimized = optimize(literal);
    let plain_sha256: [u8; 32] = Sha256::digest(literal).into();
    assert_eq!(
        optimized.recipe().literal_identity(),
        &compute_count_v3_literal_identity(literal)
    );
    assert_ne!(optimized.recipe().literal_identity(), &plain_sha256);
}

#[test]
fn width_and_portfolio_are_hard_bounded() {
    let literal = *b"0123456789abcdefghijklmnopqrstuv";
    let program = program(&literal);
    let mut limits = CountV3OptimizerLimits::default();
    limits.max_literal_bytes = COUNT_V3_MAX_LITERAL_BYTES - 1;
    assert_eq!(
        optimize_count_v3(&program, CountV3TuningClass::GenericAarch64, limits),
        Err(CountV3OptimizeError::LiteralBytes {
            limit: COUNT_V3_MAX_LITERAL_BYTES - 1,
            required: COUNT_V3_MAX_LITERAL_BYTES,
        })
    );

    let successful = optimize_count_v3(
        &program,
        CountV3TuningClass::GenericAarch64,
        CountV3OptimizerLimits::default(),
    )
    .expect("maximum-width optimization");
    assert!(
        successful.receipt().resources().portfolio_recipes <= COUNT_V3_HARD_MAX_PORTFOLIO_RECIPES
    );
    assert_eq!(
        successful.receipt().resources().candidate_columns,
        COUNT_V3_MAX_LITERAL_BYTES
    );
}

#[test]
fn every_reported_limit_refuses_at_success_minus_one() {
    let program = program(b"four-distinct-filter-columns");
    let successful = optimize_count_v3(
        &program,
        CountV3TuningClass::GenericAarch64,
        CountV3OptimizerLimits::default(),
    )
    .expect("resource baseline");
    let resources = successful.receipt().resources();

    let mut limits = CountV3OptimizerLimits::default();
    limits.max_candidate_columns = resources.candidate_columns - 1;
    assert_eq!(
        optimize_count_v3(&program, CountV3TuningClass::GenericAarch64, limits),
        Err(CountV3OptimizeError::CandidateColumns {
            limit: resources.candidate_columns - 1,
            required: resources.candidate_columns,
        })
    );

    let mut limits = CountV3OptimizerLimits::default();
    limits.max_portfolio_recipes = resources.portfolio_recipes - 1;
    assert_eq!(
        optimize_count_v3(&program, CountV3TuningClass::GenericAarch64, limits),
        Err(CountV3OptimizeError::PortfolioRecipes {
            limit: resources.portfolio_recipes - 1,
            required: resources.portfolio_recipes,
        })
    );

    let mut limits = CountV3OptimizerLimits::default();
    limits.max_scratch_bytes = resources.scratch_bytes - 1;
    assert_eq!(
        optimize_count_v3(&program, CountV3TuningClass::GenericAarch64, limits),
        Err(CountV3OptimizeError::ScratchBytes {
            limit: resources.scratch_bytes - 1,
            required: resources.scratch_bytes,
        })
    );

    let mut limits = CountV3OptimizerLimits::default();
    limits.max_analysis_work = resources.analysis_work - 1;
    assert_eq!(
        optimize_count_v3(&program, CountV3TuningClass::GenericAarch64, limits),
        Err(CountV3OptimizeError::AnalysisWork {
            limit: resources.analysis_work - 1,
            required: resources.analysis_work,
        })
    );

    let mut limits = CountV3OptimizerLimits::default();
    limits.max_retained_bytes = resources.retained_bytes - 1;
    assert_eq!(
        optimize_count_v3(&program, CountV3TuningClass::GenericAarch64, limits),
        Err(CountV3OptimizeError::RetainedBytes {
            limit: resources.retained_bytes - 1,
            required: resources.retained_bytes,
        })
    );

    let mut limits = CountV3OptimizerLimits::default();
    limits.max_identity_bytes_hashed = resources.identity_bytes_hashed - 1;
    assert_eq!(
        optimize_count_v3(&program, CountV3TuningClass::GenericAarch64, limits),
        Err(CountV3OptimizeError::IdentityBytesHashed {
            limit: resources.identity_bytes_hashed - 1,
            required: resources.identity_bytes_hashed,
        })
    );

    let mut limits = CountV3OptimizerLimits::default();
    limits.max_allocation_requests = 0;
    assert_eq!(
        optimize_count_v3(&program, CountV3TuningClass::GenericAarch64, limits),
        Err(CountV3OptimizeError::AllocationRequests {
            limit: 0,
            required: 1,
        })
    );
}

#[test]
fn selected_recipe_has_exact_permutation_and_group_partition() {
    for literal in [
        &b"x"[..],
        &b"abcdefghijklmno"[..],
        &b"0123456789abcdefghijklmnopqrstuv"[..],
    ] {
        let optimized = optimize(literal);
        let recipe = optimized.recipe();
        assert_eq!(recipe.confirmation_order().len(), literal.len());
        let mut offsets = recipe.confirmation_order().to_vec();
        offsets.sort_unstable();
        assert_eq!(
            offsets,
            (0..literal.len())
                .map(|offset| offset as u8)
                .collect::<Vec<_>>()
        );
        let covered = recipe
            .sparse_group_blocks()
            .iter()
            .map(|group| usize::from(group.len()))
            .sum::<usize>();
        assert_eq!(covered, literal.len());
        assert_eq!(recipe.match_stride(), literal.len() as u8);
    }
}
