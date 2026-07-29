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
fn canonical_inspection_and_decode_are_strict() {
    let program = program(b"0123456789abcdef");
    let optimized = optimize_count_v3(
        &program,
        CountV3TuningClass::AppleMSeries,
        CountV3OptimizerLimits::default(),
    )
    .expect("optimization");
    let canonical = encode_count_recipe_v3(optimized.recipe());
    let inspected = inspect_count_recipe_v3(&canonical).expect("canonical inspection");
    assert_eq!(
        inspected.program_identity(),
        program.cache_identity().as_bytes()
    );
    assert_eq!(inspected.identity(), optimized.recipe().identity());
    assert_eq!(
        decode_count_recipe_v3(&program, &canonical).expect("strict decode"),
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
