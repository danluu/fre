#![forbid(unsafe_code)]

use core::mem::size_of;
use std::sync::Arc;

use fre::{
    AggregateBuildAccounting, AggregateBuildLimits, AggregateBuildReport, AggregateBuilder,
    AggregateCacheIdentity, AggregateConstructionActual, AggregateConstructionAttemptError,
    AggregateConstructionEffect, AggregateConstructionPrepublicationFallback,
    AggregateConstructionStage, AggregateConstructionStageDisposition,
    AggregateConstructionTerminal, AggregateConstructionTransition, AggregateOperation,
    AggregatePlanKind, AggregatePlanSelection, AggregateRunLimits, AggregateStrategy, RustProfile,
};

fn builder(pattern: &str) -> AggregateBuilder {
    AggregateBuilder::new(pattern).profile(RustProfile::rebar_1_12_4())
}

const GRAPHEME_SCALAR_DFA_PATTERN: &str = r"(?x)
\p{gcb=CR} \p{gcb=LF}
|
\p{gcb=Control}
|
\p{gcb=Prepend}*
(
  (
    (\p{gcb=L}* (\p{gcb=V}+ | \p{gcb=LV} \p{gcb=V}* | \p{gcb=LVT}) \p{gcb=T}*)
    |
    \p{gcb=L}+
    |
    \p{gcb=T}+
  )
  |
  \p{gcb=RI} \p{gcb=RI}
  |
  \p{Extended_Pictographic} (\p{gcb=Extend}* \p{gcb=ZWJ} \p{Extended_Pictographic})*
  |
  [^\p{gcb=Control} \p{gcb=CR} \p{gcb=LF}]
)
[\p{gcb=Extend} \p{gcb=ZWJ} \p{gcb=SpacingMark}]*
|
\p{Any}
";

fn assert_success_receipt(report: &AggregateBuildReport) {
    assert!(report.has_closed_construction_attempt());
    let receipt = report
        .construction_attempt_receipt()
        .expect("successful construction lost its receipt");
    let plan = receipt
        .published_plan
        .as_ref()
        .expect("successful construction lost its published plan");
    assert!(receipt.closes(&receipt.identity, Some(plan)));
    assert_eq!(receipt.terminal, AggregateConstructionTerminal::Success);
    assert_eq!(receipt.published_stage, Some(plan.stage()));

    let prospective = receipt
        .prospective
        .expect("successful construction must publish P before effects");
    assert!(prospective.contains(receipt.actual));

    let terminal = receipt
        .ledger
        .get(
            receipt
                .ledger
                .len()
                .checked_sub(1)
                .expect("empty success ledger"),
        )
        .expect("success ledger lost its terminal entry");
    assert_eq!(
        receipt
            .ledger
            .iter()
            .filter(|entry| {
                entry.disposition == AggregateConstructionStageDisposition::Published
            })
            .count(),
        1,
        "success must publish exactly one selected-success effect"
    );
    assert_eq!(terminal.stage, plan.stage());
    assert_eq!(
        terminal.disposition,
        AggregateConstructionStageDisposition::Published
    );
    assert_eq!(
        terminal.transition,
        AggregateConstructionTransition::Published
    );
    assert_ne!(
        terminal.effect,
        AggregateConstructionEffect::default(),
        "publication must retain the selected route's exact success effect"
    );
    assert_eq!(terminal.actual, receipt.actual);
}

fn assert_cache_receipt(report: &AggregateBuildReport, cache: &AggregateCacheIdentity) {
    assert!(cache.has_closed_construction_attempt());
    assert_eq!(
        cache.construction_attempt_receipt(),
        report.construction_attempt_receipt()
    );
}

fn assert_failure_receipt(
    error: &AggregateConstructionAttemptError,
    expected_stage: AggregateConstructionStage,
    expects_prospective: bool,
    expects_nonzero_actual: bool,
) {
    assert!(error.closes());
    let receipt = error.receipt();
    assert!(receipt.closes(&receipt.identity, None));
    assert_eq!(receipt.terminal, AggregateConstructionTerminal::Failure);
    assert_eq!(receipt.published_stage, None);
    assert_eq!(receipt.published_plan, None);

    if let Some(prospective) = receipt.prospective {
        assert!(expects_prospective);
        assert!(prospective.contains(receipt.actual));
    } else {
        assert!(!expects_prospective);
        assert_eq!(receipt.actual, AggregateConstructionActual::default());
    }
    if expects_nonzero_actual {
        assert_ne!(receipt.actual, AggregateConstructionActual::default());
    }

    let terminal = receipt
        .ledger
        .get(
            receipt
                .ledger
                .len()
                .checked_sub(1)
                .expect("empty failure ledger"),
        )
        .expect("failure ledger lost its terminal entry");
    assert_eq!(terminal.stage, expected_stage);
    assert_eq!(
        terminal.disposition,
        AggregateConstructionStageDisposition::HardTerminal
    );
    assert_eq!(
        terminal.transition,
        AggregateConstructionTransition::HardTerminal
    );
}

fn construction_entry(
    report: &AggregateBuildReport,
    stage: AggregateConstructionStage,
) -> &fre::AggregateConstructionLedgerEntry {
    report
        .construction_attempt_receipt()
        .expect("report lost its construction receipt")
        .ledger
        .iter()
        .find(|entry| entry.stage == stage)
        .unwrap_or_else(|| panic!("construction ledger did not visit {stage:?}"))
}

fn assert_typed_fallback(
    report: &AggregateBuildReport,
    stage: AggregateConstructionStage,
    fallback: AggregateConstructionPrepublicationFallback,
    transition: AggregateConstructionTransition,
) {
    let entry = construction_entry(report, stage);
    assert_eq!(
        entry.disposition,
        AggregateConstructionStageDisposition::SoftResourceRefused
    );
    assert_eq!(entry.fallback, fallback);
    assert_eq!(entry.transition, transition);
    assert!(entry.effect.work > 0 || entry.effect.released_persistent_bytes > 0);
}

fn toggle_strategy(strategy: AggregateStrategy) -> AggregateStrategy {
    match strategy {
        AggregateStrategy::FullTable => AggregateStrategy::ReverseSequentialRows,
        AggregateStrategy::ReverseSequentialRows => AggregateStrategy::FullTable,
    }
}

fn assert_public_report_mutations_are_rejected(report: &AggregateBuildReport) {
    let mut changed = report.clone();
    changed.operation = match report.operation {
        AggregateOperation::Count => AggregateOperation::SpanSum,
        _ => AggregateOperation::Count,
    };
    assert!(!changed.has_closed_construction_attempt());

    let mut changed = report.clone();
    changed.selection = match report.selection {
        AggregatePlanSelection::Auto => AggregatePlanSelection::ForceContinuation,
        _ => AggregatePlanSelection::Auto,
    };
    assert!(!changed.has_closed_construction_attempt());

    let mut changed = report.clone();
    changed.requested_strategy = toggle_strategy(report.requested_strategy);
    assert!(!changed.has_closed_construction_attempt());

    let mut changed = report.clone();
    changed.build_limits.max_literal_planner_work = changed
        .build_limits
        .max_literal_planner_work
        .checked_add(1)
        .expect("default planner limit has room for a mutation");
    assert!(!changed.has_closed_construction_attempt());

    let mut changed = report.clone();
    changed.plan = match report.plan {
        AggregatePlanKind::ContinuationProgram => AggregatePlanKind::ExactLiteral,
        _ => AggregatePlanKind::ContinuationProgram,
    };
    assert!(!changed.has_closed_construction_attempt());

    let mut changed = report.clone();
    changed.continuation_strategy = match report.continuation_strategy {
        Some(strategy) => Some(toggle_strategy(strategy)),
        None => Some(AggregateStrategy::FullTable),
    };
    assert!(!changed.has_closed_construction_attempt());
}

#[test]
fn representative_successes_close_report_cache_and_publication_receipts() {
    let direct = builder("needle")
        .unicode(false)
        .build_count_attempt()
        .expect("representative direct construction");
    let direct_report = direct.build_report();
    assert_eq!(direct_report.plan, AggregatePlanKind::ExactLiteral);
    assert_success_receipt(direct_report);
    assert_cache_receipt(
        direct_report,
        &direct.cache_identity(AggregateRunLimits::default()),
    );
    assert_public_report_mutations_are_rejected(direct_report);

    let continuation = builder("needle")
        .unicode(false)
        .plan_selection(AggregatePlanSelection::ForceContinuation)
        .strategy(AggregateStrategy::FullTable)
        .build_count_attempt()
        .expect("representative continuation construction");
    let continuation_report = continuation.build_report();
    assert_eq!(
        continuation_report.plan,
        AggregatePlanKind::ContinuationProgram
    );
    assert_eq!(
        continuation_report.continuation_strategy,
        Some(AggregateStrategy::FullTable)
    );
    assert_success_receipt(continuation_report);
    assert_cache_receipt(
        continuation_report,
        &continuation.cache_identity(AggregateRunLimits::default()),
    );
    assert_public_report_mutations_are_rejected(continuation_report);
}

#[test]
fn fixed_domain_success_closes_both_construction_boundaries() {
    let fixed = builder(r"^a{2,5}$")
        .unicode(false)
        .build_count_attempt()
        .expect("representative fixed-domain construction");
    let report = fixed.build_report();
    assert_eq!(report.plan, AggregatePlanKind::FixedAbsoluteDomain);
    assert_success_receipt(report);
    assert!(report.has_closed_fixed_absolute_domain_identity());
    assert_cache_receipt(report, &fixed.cache_identity(AggregateRunLimits::default()));
}

#[test]
fn terminal_receipts_distinguish_pre_p_pre_syntax_syntax_and_post_syntax() {
    let overflowing = AggregateBuildLimits {
        max_literal_planner_work: usize::MAX,
        ..AggregateBuildLimits::default()
    };
    let pre_p = builder("needle")
        .limits(overflowing)
        .build_count_attempt()
        .expect_err("overflowing input-derived P must terminate before P publication");
    assert_failure_receipt(
        &pre_p,
        AggregateConstructionStage::PreSyntaxForceExactLiteralSpans,
        false,
        false,
    );
    assert!(pre_p.syntax_attempt_receipt().is_none());

    let pre_syntax = builder("(")
        .plan_selection(AggregatePlanSelection::ForceExactLiteral)
        .build_spans_attempt()
        .expect_err("forced exact spans must terminate before syntax");
    assert_failure_receipt(
        &pre_syntax,
        AggregateConstructionStage::PreSyntaxForceExactLiteralSpans,
        false,
        false,
    );
    assert!(pre_syntax.syntax_attempt_receipt().is_none());

    let syntax = builder("(")
        .build_count_attempt()
        .expect_err("invalid syntax must retain a construction terminal");
    assert_failure_receipt(
        &syntax,
        AggregateConstructionStage::SyntaxParseAdmission,
        true,
        false,
    );
    assert!(syntax.syntax_attempt_receipt().is_some());

    let planner_limits = AggregateBuildLimits {
        max_literal_planner_work: 0,
        ..AggregateBuildLimits::default()
    };
    let post_syntax = builder("needle")
        .unicode(false)
        .limits(planner_limits)
        .plan_selection(AggregatePlanSelection::ForceExactLiteral)
        .build_count_attempt()
        .expect_err("zero exact-planner budget must terminate after syntax");
    assert_failure_receipt(
        &post_syntax,
        AggregateConstructionStage::ExactLiteral,
        true,
        true,
    );
    assert!(post_syntax.syntax_attempt_receipt().is_some());
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one owner-lifecycle test keeps source, syntax, terminal, and publication byte deltas adjacent"
)]
fn source_and_cache_owner_handles_are_charged_exactly() {
    let source_allocation = fre_syntax::ParseRequest::attempt_source_owner_allocation_bytes();
    let source_handle = fre_syntax::ParseRequest::attempt_source_owner_handle_bytes();
    let cache_handle = size_of::<Arc<fre_syntax::CacheKey>>();

    let invalid = builder("(")
        .build_count_attempt()
        .expect_err("invalid syntax fixture");
    let invalid_receipt = invalid.receipt();
    let invalid_source = invalid_receipt
        .ledger
        .get(0)
        .expect("invalid syntax source-owner entry");
    assert_eq!(
        invalid_source.effect,
        AggregateConstructionEffect {
            work: 0,
            allocations: 1,
            allocated_bytes: source_allocation,
            copied_bytes: 2 * source_handle,
            initialized_bytes: source_allocation + 2 * source_handle,
            retained_persistent_bytes: source_allocation + 2 * source_handle,
            released_persistent_bytes: 0,
            co_live_bytes: source_allocation + 2 * source_handle,
        }
    );
    let invalid_syntax = invalid_receipt
        .ledger
        .get(1)
        .expect("invalid syntax receipt entry");
    assert_eq!(
        invalid_syntax.effect,
        AggregateConstructionEffect {
            work: invalid
                .syntax_attempt_receipt()
                .expect("invalid syntax nested receipt")
                .actual
                .observed_work,
            allocations: 0,
            allocated_bytes: 0,
            copied_bytes: source_handle,
            initialized_bytes: source_handle,
            retained_persistent_bytes: source_handle,
            released_persistent_bytes: 0,
            co_live_bytes: source_handle,
        }
    );
    assert_eq!(
        invalid_syntax.actual.live_persistent_bytes,
        source_allocation + 3 * source_handle
    );
    assert_eq!(
        invalid_syntax.actual.high_water_bytes,
        source_allocation + 3 * source_handle
    );

    let exact = builder("needle")
        .unicode(false)
        .build_count_attempt()
        .expect("exact owner-accounting fixture");
    let exact_receipt = exact
        .build_report()
        .construction_attempt_receipt()
        .expect("exact construction receipt");
    let exact_source = exact_receipt
        .ledger
        .get(0)
        .expect("exact source-owner entry");
    assert_eq!(exact_source.effect, invalid_source.effect);
    let exact_syntax = exact_receipt.ledger.get(1).expect("exact syntax entry");
    assert_eq!(exact_syntax.effect.allocations, 1);
    assert_eq!(
        exact_syntax.effect.copied_bytes,
        source_handle + 2 * cache_handle
    );
    assert_eq!(
        exact_syntax.effect.initialized_bytes,
        exact_syntax.effect.allocated_bytes + source_handle + 2 * cache_handle
    );
    assert_eq!(
        exact_syntax.effect.retained_persistent_bytes,
        exact_syntax.effect.initialized_bytes
    );
    assert_eq!(exact_syntax.effect.released_persistent_bytes, source_handle);
    assert_eq!(
        exact_syntax.effect.co_live_bytes,
        exact_syntax.effect.retained_persistent_bytes - source_handle
    );
    assert_eq!(
        exact_syntax.actual.live_persistent_bytes,
        source_allocation
            + exact_syntax.effect.allocated_bytes
            + 2 * source_handle
            + 2 * cache_handle
    );
    assert_eq!(
        exact_syntax.actual.high_water_bytes,
        exact_source
            .actual
            .high_water_bytes
            .max(exact_source.actual.live_persistent_bytes + exact_syntax.effect.co_live_bytes)
    );
    let exact_terminal = exact_receipt
        .ledger
        .get(exact_receipt.ledger.len() - 1)
        .expect("exact publication entry");
    assert_eq!(
        exact_terminal.effect.released_persistent_bytes, cache_handle,
        "publication must release the failure-recovery CacheKey owner"
    );

    let planner_limits = AggregateBuildLimits {
        max_literal_planner_work: 0,
        ..AggregateBuildLimits::default()
    };
    let post_syntax = builder("needle")
        .unicode(false)
        .limits(planner_limits)
        .plan_selection(AggregatePlanSelection::ForceExactLiteral)
        .build_count_attempt()
        .expect_err("post-syntax owner-accounting fixture");
    let post_syntax_receipt = post_syntax.receipt();
    let post_syntax_terminal = post_syntax_receipt
        .ledger
        .get(post_syntax_receipt.ledger.len() - 1)
        .expect("post-syntax terminal");
    assert_eq!(
        post_syntax_terminal.effect.released_persistent_bytes,
        cache_handle
    );
    assert_eq!(
        post_syntax_receipt.actual.live_persistent_bytes,
        source_allocation + exact_syntax.effect.allocated_bytes + 2 * source_handle + cache_handle
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the direct-route matrix stays together so every selected stage is visibly covered once"
)]
fn direct_route_families_publish_one_exact_selected_success_effect() {
    let cases = [
        (
            "needle",
            false,
            false,
            AggregatePlanKind::ExactLiteral,
            AggregateConstructionStage::ExactLiteral,
        ),
        (
            r"\pL",
            true,
            false,
            AggregatePlanKind::UnicodeScalarClass,
            AggregateConstructionStage::UnicodeScalar,
        ),
        (
            r"\b\w{12,}\b",
            true,
            false,
            AggregatePlanKind::WordRun,
            AggregateConstructionStage::WordRun,
        ),
        (
            r"(?m)^Sherlock Holmes|Sherlock Holmes$",
            false,
            false,
            AggregatePlanKind::LiteralAssertions,
            AggregateConstructionStage::LiteralAssertions,
        ),
        (
            r#"["'][^"']{0,30}[?!.]["']"#,
            false,
            false,
            AggregatePlanKind::BlockingDelimiter,
            AggregateConstructionStage::BlockingDelimiter,
        ),
        (
            r"\b\w+\s+Holmes\s+\w+\b",
            false,
            false,
            AggregatePlanKind::TokenPhrase,
            AggregateConstructionStage::TokenPhrase,
        ),
        (
            r"[a-q][^u-z]{3}x",
            false,
            false,
            AggregatePlanKind::FixedClassSandwich,
            AggregateConstructionStage::FixedClassSandwich,
        ),
        (
            GRAPHEME_SCALAR_DFA_PATTERN,
            true,
            false,
            AggregatePlanKind::GraphemeScalarDfa,
            AggregateConstructionStage::GraphemeScalarDfa,
        ),
        (
            r"(?:[A-Z][a-z]+\s*){10,100}",
            false,
            false,
            AggregatePlanKind::BoundedClassSequence,
            AggregateConstructionStage::BoundedClassSequence,
        ),
        (
            r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9])",
            false,
            false,
            AggregatePlanKind::BoundedSeparatedFields,
            AggregateConstructionStage::BoundedSeparatedFields,
        ),
        (
            r"Huck[a-zA-Z]+|Saw[a-zA-Z]+",
            false,
            false,
            AggregatePlanKind::PrefixClassAlternation,
            AggregateConstructionStage::PrefixClassAlternation,
        ),
        (
            r"Holmes.{0,25}Watson|Watson.{0,25}Holmes",
            false,
            false,
            AggregatePlanKind::BoundedLiteralPair,
            AggregateConstructionStage::BoundedLiteralPair,
        ),
        (
            r"Sherlock\s+Holmes",
            false,
            false,
            AggregatePlanKind::LiteralClassRunLiteral,
            AggregateConstructionStage::LiteralClassRunLiteral,
        ),
        (
            r"\s[A-Za-z]{0,12}ing\s",
            false,
            false,
            AggregatePlanKind::BoundedContext,
            AggregateConstructionStage::BoundedAffix,
        ),
        (
            r"[a-z]{2}\s+[\s\S]{0,2}R[\s\S]{0,2}\s+[a-z]{2}",
            false,
            false,
            AggregatePlanKind::BoundedContext,
            AggregateConstructionStage::BoundedContext,
        ),
        (
            r"(?P<word>cat|dog|mouse)",
            false,
            false,
            AggregatePlanKind::PackedFiniteLiteral,
            AggregateConstructionStage::PackedFinite,
        ),
        (
            r"(?P<word>a|cat|dog|mouse)",
            false,
            false,
            AggregatePlanKind::FiniteLiteralDfa,
            AggregateConstructionStage::DenseFinite,
        ),
        (
            r"\b(?:as|break|Self|ab|ba)\b",
            false,
            false,
            AggregatePlanKind::GuardedAsciiWordDictionary,
            AggregateConstructionStage::GeneralFiniteExtraction,
        ),
        (
            "Sherlock Holmes",
            false,
            true,
            AggregatePlanKind::FixedPredicateWord64,
            AggregateConstructionStage::FixedPredicateWord64,
        ),
    ];

    for (pattern, unicode, case_insensitive, expected_plan, expected_stage) in cases {
        let regex = builder(pattern)
            .unicode(unicode)
            .case_insensitive(case_insensitive)
            .build_count_attempt()
            .unwrap_or_else(|error| panic!("route fixture {pattern:?}: {error}"));
        let report = regex.build_report();
        assert_eq!(report.plan, expected_plan, "pattern={pattern:?}");
        assert_success_receipt(report);
        assert_eq!(
            report
                .construction_attempt_receipt()
                .expect("route receipt")
                .published_stage,
            Some(expected_stage),
            "pattern={pattern:?}"
        );
    }

    let sparse_words = (0..32)
        .map(|index| format!("p{index:03}雪"))
        .collect::<Vec<_>>();
    let sparse_pattern = format!("(?:{})", sparse_words.join("|"));
    let mut sparse_limits = AggregateBuildLimits::default();
    sparse_limits.finite_literal.max_dfa_cells = sparse_words.iter().map(String::len).sum();
    let sparse = builder(&sparse_pattern)
        .unicode(true)
        .limits(sparse_limits)
        .build_count_attempt()
        .expect("sparse finite fixture");
    assert_eq!(
        sparse.build_report().plan,
        AggregatePlanKind::FiniteLiteralDfa
    );
    assert_success_receipt(sparse.build_report());
    assert_eq!(
        sparse
            .build_report()
            .construction_attempt_receipt()
            .expect("sparse receipt")
            .published_stage,
        Some(AggregateConstructionStage::SparseFiniteRoot)
    );
}

fn assert_complete_policy_skip_ledger(report: &AggregateBuildReport) {
    let receipt = report
        .construction_attempt_receipt()
        .expect("policy build lost its transaction");
    assert_eq!(
        receipt.ledger.len(),
        AggregateConstructionStage::ORDER.len()
    );
    for (index, entry) in receipt.ledger.iter().enumerate() {
        assert_eq!(entry.stage, AggregateConstructionStage::ORDER[index]);
        let expected = if index < 2 {
            AggregateConstructionStageDisposition::Completed
        } else if entry.stage == AggregateConstructionStage::Continuation {
            AggregateConstructionStageDisposition::Published
        } else {
            AggregateConstructionStageDisposition::PolicySkipped
        };
        assert_eq!(entry.disposition, expected, "stage={:?}", entry.stage);
        if expected == AggregateConstructionStageDisposition::PolicySkipped {
            assert_eq!(entry.effect, AggregateConstructionEffect::default());
        }
    }
}

#[test]
fn forced_continuation_and_spans_pin_full_order_as_policy_skips() {
    {
        let forced = builder("needle")
            .unicode(false)
            .plan_selection(AggregatePlanSelection::ForceContinuation)
            .build_count_attempt()
            .expect("forced continuation");
        assert_success_receipt(forced.build_report());
        assert_complete_policy_skip_ledger(forced.build_report());
    }

    let spans = builder(r"a.*b")
        .unicode(false)
        .build_spans_attempt()
        .expect("spans continuation");
    assert_success_receipt(spans.build_report());
    assert_complete_policy_skip_ledger(spans.build_report());
}

#[test]
fn unicode_scalar_cursor_count_transaction_retains_exact_attempt_effects() {
    let pattern = r"\p{Greek}+";
    let baseline = builder(pattern)
        .build_count_attempt()
        .expect("cursor Count baseline");
    assert_success_receipt(baseline.build_report());
    let AggregateBuildAccounting::UnicodeScalarCursorCount(build) =
        baseline.build_report().build
    else {
        panic!("positive scalar Count retained another build owner")
    };
    let success = construction_entry(
        baseline.build_report(),
        AggregateConstructionStage::UnicodeScalar,
    );
    assert_eq!(
        success.effect.work,
        u64::try_from(
            baseline
                .build_report()
                .unicode_scalar_planner_work
                .checked_add(build.work)
                .and_then(|work| work.checked_add(1))
                .expect("cursor inspection plus build work fits")
        )
        .unwrap()
    );
    assert!(success.effect.retained_persistent_bytes >= build.persistent_bytes);
    assert!(success.effect.initialized_bytes >= build.persistent_bytes);
    assert!(success.effect.co_live_bytes >= build.peak_bytes);

    assert!(build.scalar.persistent_bytes < build.persistent_bytes);
    let mut limits = AggregateBuildLimits::default();
    limits.unicode_scalar.max_persistent_bytes = build.persistent_bytes - 1;
    let refusal = builder(pattern)
        .limits(limits)
        .build_count_attempt()
        .expect_err("one-below cursor wrapper persistent budget");
    assert_failure_receipt(
        &refusal,
        AggregateConstructionStage::UnicodeScalar,
        true,
        true,
    );
    assert!(matches!(
        refusal.source(),
        fre::AggregateBuildError::UnicodeScalarBuild {
            source: fre::UnicodeScalarAggregateBuildError::PersistentLimit { needed, limit },
            ..
        } if *needed == build.persistent_bytes && *limit == build.persistent_bytes - 1
    ));
    let terminal = refusal
        .receipt()
        .ledger
        .get(refusal.receipt().ledger.len() - 1)
        .expect("cursor refusal terminal");
    assert_eq!(terminal.stage, AggregateConstructionStage::UnicodeScalar);
    assert_eq!(
        terminal.effect.work,
        u64::try_from(
            baseline
                .build_report()
                .unicode_scalar_planner_work
                .checked_add(build.work)
                .expect("cursor refusal work fits")
        )
        .unwrap()
    );
    assert!(terminal.effect.allocations > 0);
    assert!(terminal.effect.allocated_bytes > 0);
    assert!(terminal.effect.initialized_bytes >= build.scalar.persistent_bytes);
    assert_eq!(terminal.effect.retained_persistent_bytes, 0);
    let syntax = refusal
        .receipt()
        .ledger
        .iter()
        .find(|entry| entry.stage == AggregateConstructionStage::SyntaxParseAdmission)
        .expect("cursor refusal syntax completion");
    assert_eq!(
        terminal.actual.live_persistent_bytes,
        syntax.actual.live_persistent_bytes - size_of::<Arc<fre_syntax::CacheKey>>()
    );
    assert!(terminal.effect.co_live_bytes >= build.scalar.persistent_bytes);
}

#[test]
fn unicode_scalar_cursor_count_broad_fallback_retains_exact_attempt_effects() {
    let pattern = r"\p{L}{8,13}";
    let baseline = builder(pattern)
        .build_count_attempt()
        .expect("broad scalar Count baseline");
    assert_success_receipt(baseline.build_report());
    let AggregateBuildAccounting::UnicodeScalar(build) = baseline.build_report().build else {
        panic!("broad scalar Count retained a cursor wrapper")
    };
    let success = construction_entry(
        baseline.build_report(),
        AggregateConstructionStage::UnicodeScalar,
    );
    assert_eq!(
        success.effect.work,
        u64::try_from(
            baseline
                .build_report()
                .unicode_scalar_planner_work
                .checked_add(build.work)
                .and_then(|work| work.checked_add(1))
                .expect("fallback inspection plus build work fits")
        )
        .unwrap()
    );
    assert!(success.effect.retained_persistent_bytes >= build.persistent_bytes);
    assert!(success.effect.initialized_bytes >= build.persistent_bytes);
    assert!(success.effect.co_live_bytes >= build.persistent_bytes);

    let mut exact_limits = AggregateBuildLimits::default();
    exact_limits.unicode_scalar.max_build_work = build.work;
    exact_limits.unicode_scalar.max_persistent_bytes = build.persistent_bytes;
    exact_limits.unicode_scalar.max_peak_bytes = build.peak_bytes;
    let exact = builder(pattern)
        .limits(exact_limits)
        .build_count_attempt()
        .expect("exact broad scalar work, persistent, and peak quotas");
    assert_eq!(
        exact.build_report().build,
        AggregateBuildAccounting::UnicodeScalar(build)
    );

    let mut limits = AggregateBuildLimits::default();
    limits.unicode_scalar.max_build_work = build.work - 1;
    let refusal = builder(pattern)
        .limits(limits)
        .build_count_attempt()
        .expect_err("one-below broad scalar routing work");
    assert_failure_receipt(
        &refusal,
        AggregateConstructionStage::UnicodeScalar,
        true,
        true,
    );
    assert!(matches!(
        refusal.source(),
        fre::AggregateBuildError::UnicodeScalarBuild {
            source: fre::UnicodeScalarAggregateBuildError::WorkLimit { needed, limit },
            ..
        } if *needed == build.work && *limit == build.work - 1
    ));
    let terminal = refusal
        .receipt()
        .ledger
        .get(refusal.receipt().ledger.len() - 1)
        .expect("fallback refusal terminal");
    assert_eq!(terminal.stage, AggregateConstructionStage::UnicodeScalar);
    assert_eq!(
        terminal.effect.work,
        u64::try_from(
            baseline
                .build_report()
                .unicode_scalar_planner_work
                .checked_add(build.work)
                .expect("fallback refusal work fits")
        )
        .unwrap()
    );
    assert!(terminal.effect.allocations > 0);
    assert!(terminal.effect.allocated_bytes > 0);
    assert!(terminal.effect.initialized_bytes >= build.persistent_bytes);
    assert_eq!(terminal.effect.retained_persistent_bytes, 0);
    let syntax = refusal
        .receipt()
        .ledger
        .iter()
        .find(|entry| entry.stage == AggregateConstructionStage::SyntaxParseAdmission)
        .expect("fallback refusal syntax completion");
    assert_eq!(
        terminal.actual.live_persistent_bytes,
        syntax.actual.live_persistent_bytes - size_of::<Arc<fre_syntax::CacheKey>>()
    );
    assert!(terminal.effect.co_live_bytes >= build.persistent_bytes);
}

#[test]
fn real_semantic_ineligibility_is_charged_and_ordered() {
    let regex = builder(r"a.*b")
        .unicode(false)
        .build_count_attempt()
        .expect("representative continuation");
    let report = regex.build_report();
    assert_eq!(report.plan, AggregatePlanKind::ContinuationProgram);
    assert_success_receipt(report);
    let receipt = report
        .construction_attempt_receipt()
        .expect("semantic receipt");
    let mut semantic_count = 0;
    let mut prior_ordinal = None;
    for entry in receipt.ledger.iter() {
        if let Some(prior) = prior_ordinal {
            assert!(entry.stage.ordinal() > prior);
        }
        prior_ordinal = Some(entry.stage.ordinal());
        if entry.disposition == AggregateConstructionStageDisposition::SemanticIneligible {
            semantic_count += 1;
            assert!(entry.effect.work > 0, "stage={:?}", entry.stage);
        }
    }
    assert!(semantic_count >= 10);
    for stage in [
        AggregateConstructionStage::ExactLiteral,
        AggregateConstructionStage::WordRun,
        AggregateConstructionStage::BlockingDelimiter,
        AggregateConstructionStage::FixedAbsolute,
        AggregateConstructionStage::GeneralFiniteExtraction,
    ] {
        assert_eq!(
            construction_entry(report, stage).disposition,
            AggregateConstructionStageDisposition::SemanticIneligible
        );
    }
}

#[test]
fn post_p_refusals_preserve_partial_a_and_prefail_the_next_effect() {
    let baseline = builder("needle")
        .unicode(false)
        .build_count_attempt()
        .expect("exact baseline");
    let AggregateBuildAccounting::ExactLiteral(build) = baseline.build_report().build else {
        panic!("exact fixture selected another route");
    };
    assert!(build.persistent_bytes > 0);

    let planner_limits = AggregateBuildLimits {
        max_literal_planner_work: 0,
        ..AggregateBuildLimits::default()
    };
    let planner_error = builder("needle")
        .unicode(false)
        .limits(planner_limits)
        .plan_selection(AggregatePlanSelection::ForceExactLiteral)
        .build_count_attempt()
        .expect_err("zero planner budget");
    let planner_receipt = planner_error.receipt();
    let planner_p = planner_receipt.prospective.expect("post-P planner refusal");
    assert!(planner_p.contains(planner_receipt.actual));
    let syntax = planner_receipt
        .ledger
        .iter()
        .find(|entry| entry.stage == AggregateConstructionStage::SyntaxParseAdmission)
        .expect("syntax completion");
    let terminal = planner_receipt
        .ledger
        .iter()
        .find(|entry| entry.stage == AggregateConstructionStage::ExactLiteral)
        .expect("literal terminal");
    let cache_owner_bytes = size_of::<Arc<fre_syntax::CacheKey>>();
    assert_eq!(
        terminal.effect,
        AggregateConstructionEffect {
            released_persistent_bytes: cache_owner_bytes,
            ..AggregateConstructionEffect::default()
        }
    );
    assert_eq!(
        terminal.actual,
        AggregateConstructionActual {
            live_persistent_bytes: syntax.actual.live_persistent_bytes - cache_owner_bytes,
            ..syntax.actual
        }
    );

    let mut build_limits = AggregateBuildLimits::default();
    build_limits.exact_literal.max_persistent_bytes = build.persistent_bytes - 1;
    let build_error = builder("needle")
        .unicode(false)
        .limits(build_limits)
        .plan_selection(AggregatePlanSelection::ForceExactLiteral)
        .build_count_attempt()
        .expect_err("one-below persistent build budget");
    let build_receipt = build_error.receipt();
    let build_p = build_receipt.prospective.expect("post-P build refusal");
    assert!(build_p.contains(build_receipt.actual));
    let syntax = build_receipt
        .ledger
        .iter()
        .find(|entry| entry.stage == AggregateConstructionStage::SyntaxParseAdmission)
        .expect("syntax completion");
    let terminal = build_receipt
        .ledger
        .iter()
        .find(|entry| entry.stage == AggregateConstructionStage::ExactLiteral)
        .expect("literal terminal");
    assert!(terminal.effect.work > 0);
    assert_eq!(terminal.effect.allocations, 0);
    assert_eq!(terminal.effect.allocated_bytes, 0);
    assert_eq!(terminal.effect.retained_persistent_bytes, 0);
    assert_eq!(terminal.actual.allocations, syntax.actual.allocations);
    assert_eq!(
        terminal.actual.allocated_bytes,
        syntax.actual.allocated_bytes
    );
    assert_eq!(
        terminal.actual.live_persistent_bytes,
        syntax.actual.live_persistent_bytes - cache_owner_bytes
    );
    assert!(terminal.actual.work > syntax.actual.work);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one fallback matrix keeps every typed edge and its cumulative abandoned effects adjacent"
)]
fn typed_fallbacks_preserve_distinct_edges_and_abandoned_actuals() {
    std::thread::Builder::new()
        .name("typed-fallback-ledger-matrix".to_owned())
        .stack_size(8 * 1024 * 1024)
        .spawn(typed_fallbacks_preserve_distinct_edges_and_abandoned_actuals_inner)
        .expect("spawn typed fallback ledger matrix")
        .join()
        .expect("typed fallback ledger matrix");
}

fn typed_fallbacks_preserve_distinct_edges_and_abandoned_actuals_inner() {
    let fixed_optional_limits = AggregateBuildLimits {
        max_fixed_absolute_planner_work: 1,
        ..AggregateBuildLimits::default()
    };
    let fixed_optional = builder(r"^a{2,5}$")
        .unicode(false)
        .limits(fixed_optional_limits)
        .build_count_attempt()
        .expect("optional fixed refusal must continue");
    assert_typed_fallback(
        fixed_optional.build_report(),
        AggregateConstructionStage::FixedAbsolute,
        AggregateConstructionPrepublicationFallback::FixedAbsoluteOptionalInspectionResource,
        AggregateConstructionTransition::FixedAbsoluteToSparseFiniteRoot,
    );

    let mut dense_limits = AggregateBuildLimits::default();
    dense_limits.finite_literal.max_trie_states = 1;
    let dense_off = builder(r"(?P<word>a|cat|dog|mouse)")
        .unicode(false)
        .limits(dense_limits)
        .build_count_attempt()
        .expect("Unicode-off dense fallback");
    assert_typed_fallback(
        dense_off.build_report(),
        AggregateConstructionStage::DenseFinite,
        AggregateConstructionPrepublicationFallback::DenseFiniteBuildResourceToFixedPredicateWord64,
        AggregateConstructionTransition::DenseFiniteToFixedPredicateWord64,
    );
    let dense_on = builder(r"(?P<word>a|cat|dog|mouse)")
        .unicode(true)
        .limits(dense_limits)
        .build_count_attempt()
        .expect("Unicode-on dense fallback");
    assert_typed_fallback(
        dense_on.build_report(),
        AggregateConstructionStage::DenseFinite,
        AggregateConstructionPrepublicationFallback::DenseFiniteBuildResourceToContinuation,
        AggregateConstructionTransition::DenseFiniteToContinuation,
    );
    for report in [dense_off.build_report(), dense_on.build_report()] {
        let extraction =
            construction_entry(report, AggregateConstructionStage::GeneralFiniteExtraction);
        let dense = construction_entry(report, AggregateConstructionStage::DenseFinite);
        assert_eq!(
            dense.abandonment.work,
            extraction
                .effect
                .work
                .checked_add(dense.effect.work)
                .expect("dense branch work fits")
        );
        assert_eq!(
            dense.abandonment.allocations,
            extraction
                .effect
                .allocations
                .checked_add(dense.effect.allocations)
                .expect("dense branch allocations fit")
        );
        assert_eq!(
            dense.abandonment.bytes,
            extraction
                .effect
                .allocated_bytes
                .checked_add(dense.effect.allocated_bytes)
                .expect("dense branch capacity bytes fit"),
            "dense fallback must retain cumulative allocated capacity, not only live bytes"
        );
    }

    let sparse_words = (0..32)
        .map(|index| format!("p{index:03}雪"))
        .collect::<Vec<_>>();
    let sparse_pattern = format!("(?:{})", sparse_words.join("|"));
    let mut sparse_limits = AggregateBuildLimits::default();
    sparse_limits.finite_literal.max_dfa_cells = sparse_words.iter().map(String::len).sum();
    let sparse_baseline = builder(&sparse_pattern)
        .unicode(true)
        .limits(sparse_limits)
        .build_count_attempt()
        .expect("sparse baseline");
    let AggregateBuildAccounting::SparseFiniteLiteral(sparse_build) =
        sparse_baseline.build_report().build
    else {
        panic!("sparse baseline selected another route");
    };
    sparse_limits.finite_literal.max_build_work = sparse_build
        .build_work
        .checked_sub(1)
        .expect("sparse fixture has positive construction work");
    let sparse_refusal = builder(&sparse_pattern)
        .unicode(true)
        .limits(sparse_limits)
        .build_count_attempt()
        .expect("sparse work refusal must continue");
    assert_typed_fallback(
        sparse_refusal.build_report(),
        AggregateConstructionStage::SparseFiniteRoot,
        AggregateConstructionPrepublicationFallback::SparseFiniteBuildResource,
        AggregateConstructionTransition::SparseFiniteToContinuation,
    );
    let sparse = construction_entry(
        sparse_refusal.build_report(),
        AggregateConstructionStage::SparseFiniteRoot,
    );
    assert!(sparse.effect.allocations > 0);
    assert_eq!(sparse.abandonment.work, sparse.effect.work);
    assert_eq!(sparse.abandonment.allocations, sparse.effect.allocations);
    assert_eq!(
        sparse.abandonment.bytes, sparse.effect.allocated_bytes,
        "sparse fallback must retain cumulative allocated capacity, not only live bytes"
    );

    let mut guarded_limits = AggregateBuildLimits::default();
    guarded_limits.finite_literal.max_identity_bytes = 0;
    let guarded = builder(r"\b(?:as|break|Self|ab|ba)\b")
        .unicode(false)
        .limits(guarded_limits)
        .build_count_attempt()
        .expect("guarded dictionary fallback");
    assert_typed_fallback(
        guarded.build_report(),
        AggregateConstructionStage::GeneralFiniteExtraction,
        AggregateConstructionPrepublicationFallback::GuardedFiniteDictionaryResource,
        AggregateConstructionTransition::GuardedFiniteToContinuation,
    );

    let mut predicate_limits = AggregateBuildLimits::default();
    predicate_limits.finite_literal.max_patterns = 0;
    let predicate = builder("Sherlock Holmes")
        .unicode(false)
        .case_insensitive(true)
        .limits(predicate_limits)
        .build_count_attempt()
        .expect("fixed-predicate fallback");
    let report = predicate.build_report();
    let too_large = construction_entry(report, AggregateConstructionStage::GeneralFiniteExtraction);
    assert_eq!(
        too_large.disposition,
        AggregateConstructionStageDisposition::SemanticIneligible
    );
    assert_eq!(
        too_large.fallback,
        AggregateConstructionPrepublicationFallback::TooLargeFixedSequenceToFixedPredicateWord64
    );
    assert_eq!(
        too_large.transition,
        AggregateConstructionTransition::TooLargeFixedSequenceToFixedPredicateWord64
    );
    assert_typed_fallback(
        report,
        AggregateConstructionStage::FixedPredicateWord64,
        AggregateConstructionPrepublicationFallback::FixedPredicateWord64BuildResource,
        AggregateConstructionTransition::FixedPredicateWord64ToContinuation,
    );
    let receipt = report
        .construction_attempt_receipt()
        .expect("fallback receipt");
    let predicate_refusal =
        construction_entry(report, AggregateConstructionStage::FixedPredicateWord64);
    assert!(
        receipt.actual.abandoned_work
            >= too_large
                .effect
                .work
                .checked_add(predicate_refusal.effect.work)
                .expect("fixture work fits")
    );
    assert!(receipt.actual.abandoned_allocations > 0);
    assert!(receipt.actual.abandoned_bytes > 0);
    assert_success_receipt(report);
}

#[test]
fn dense_publication_accounts_for_release_before_selected_owner_retention() {
    let regex = builder(r"(?P<word>a|cat|dog|mouse)")
        .unicode(false)
        .build_count_attempt()
        .expect("dense finite success");
    let report = regex.build_report();
    assert_eq!(report.plan, AggregatePlanKind::FiniteLiteralDfa);
    assert_success_receipt(report);
    let receipt = report
        .construction_attempt_receipt()
        .expect("dense receipt");
    let terminal = receipt
        .ledger
        .get(receipt.ledger.len() - 1)
        .expect("dense terminal");
    let before = receipt
        .ledger
        .get(receipt.ledger.len() - 2)
        .expect("finite extraction");
    assert_eq!(terminal.stage, AggregateConstructionStage::DenseFinite);
    assert!(terminal.effect.released_persistent_bytes > 0);
    assert!(terminal.effect.retained_persistent_bytes > 0);
    let after_release = before
        .actual
        .live_persistent_bytes
        .checked_sub(terminal.effect.released_persistent_bytes)
        .expect("dense publication release is bounded");
    assert_eq!(
        terminal.actual.live_persistent_bytes,
        after_release
            .checked_add(terminal.effect.retained_persistent_bytes)
            .expect("dense retained owner fits")
    );
    assert_eq!(
        terminal.actual.high_water_bytes,
        before.actual.high_water_bytes.max(
            before
                .actual
                .live_persistent_bytes
                .checked_add(terminal.effect.co_live_bytes)
                .expect("dense co-live peak fits")
        )
    );
}
