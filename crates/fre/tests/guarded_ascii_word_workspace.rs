use fre::{
    AggregateBuilder, AggregateCountWorkspace, AggregatePlanKind, AggregateRunLimits,
    OrderedLiteralAggregateReduceLimits, RustProfile,
};

fn guarded(pattern: &str) -> fre::AggregateCountRegex {
    let regex = AggregateBuilder::new(pattern)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(false)
        .case_insensitive(false)
        .build_count()
        .unwrap();
    assert_eq!(
        regex.build_report().plan,
        AggregatePlanKind::GuardedAsciiWordDictionary
    );
    regex
}

#[test]
fn guarded_ascii_word_count_workspace_preserves_reuse_and_refusals() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            let first = guarded(r"\b(?:as|break|Self|ab|ba)\b");
            let second = guarded(r"\b(?:if|else|while|return|struct)\b");
            let default_limits = AggregateRunLimits::default();
            let mut workspace = AggregateCountWorkspace::new();

            assert_eq!(
                first
                    .count_value_with_workspace(
                        b"as break xas Self",
                        default_limits,
                        &mut workspace,
                    )
                    .unwrap(),
                3
            );
            assert_eq!(
                first
                    .count_value_with_workspace(b"nothing", default_limits, &mut workspace)
                    .unwrap(),
                0
            );
            assert_eq!(
                second
                    .count_value_with_workspace(
                        b"return iffy struct",
                        default_limits,
                        &mut workspace,
                    )
                    .unwrap(),
                2
            );

            let refusal_limits = AggregateRunLimits {
                finite_literal: OrderedLiteralAggregateReduceLimits {
                    max_total_work: 0,
                    ..OrderedLiteralAggregateReduceLimits::default()
                },
                ..default_limits
            };
            let ordinary_error = first.count_value(b"as", refusal_limits).unwrap_err();
            let workspace_error = first
                .count_value_with_workspace(b"as", refusal_limits, &mut workspace)
                .unwrap_err();
            assert_eq!(workspace_error, ordinary_error);

            assert_eq!(
                first
                    .count_value_with_workspace(b"as", default_limits, &mut workspace)
                    .unwrap(),
                1
            );
        })
        .unwrap()
        .join()
        .unwrap();
}
