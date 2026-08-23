use fre_aot_regex::{
    CompileMode, DeterminizeLimits, MatchResult, OrderedManyAotCompileDecline,
    OrderedManyAotCompileDisposition, OrderedManyAotCompileError, OrderedManyAotCompileLimits,
    OrderedManyAotCompileRequest, OrderedManyPatternId, OrderedManyRow, PreparedAggregateExports,
    PreparedAggregateStrategy, SearchWindow, SlowAotLimits, Target, compile_ordered_many_aot,
    compile_ordered_many_aot_reported,
};
use regex_automata::meta::Regex as MetaRegex;

fn rows(patterns: &[&str], ids: &[u32]) -> Vec<OrderedManyRow> {
    assert_eq!(patterns.len(), ids.len());
    patterns
        .iter()
        .zip(ids)
        .map(|(&pattern, &id)| OrderedManyRow::new(OrderedManyPatternId::new(id), pattern))
        .collect()
}

fn oracle(patterns: &[&str], haystack: &[u8]) -> Vec<(usize, usize)> {
    MetaRegex::builder()
        .configure(MetaRegex::config().utf8_empty(false))
        .syntax(
            regex_automata::util::syntax::Config::new()
                .utf8(false)
                .unicode(true),
        )
        .build_many(patterns)
        .expect("ordered build-many oracle")
        .find_iter(haystack)
        .map(|matched| (matched.start(), matched.end()))
        .collect()
}

fn semantic_spans(
    artifact: &fre_aot_regex::OrderedManyAotArtifact,
    haystack: &[u8],
) -> Vec<(usize, usize)> {
    let compiled = artifact.compiled();
    let mut workspace = compiled.prepare_workspace().expect("shared workspace");
    let mut cursor = 0usize;
    let mut suppress_empty_at = None;
    let mut spans = Vec::new();
    while cursor <= haystack.len() {
        let MatchResult::Span(found) = compiled
            .search_with_workspace(
                haystack,
                SearchWindow::new(cursor, haystack.len()),
                &mut workspace,
            )
            .expect("shared search")
        else {
            panic!("ordered-many AOT lost its Span contract");
        };
        let Some((start, end)) = found else {
            break;
        };
        if start == end && suppress_empty_at == Some(start) {
            if start == haystack.len() {
                break;
            }
            cursor = start + 1;
            continue;
        }
        spans.push((start, end));
        if start == end {
            if start == haystack.len() {
                break;
            }
            cursor = start + 1;
        } else {
            suppress_empty_at = Some(end);
            cursor = end;
        }
    }
    spans
}

fn byte_strings(max_len: usize) -> Vec<Vec<u8>> {
    let alphabet = [b'a', b'b', 0xff];
    let mut all = vec![Vec::new()];
    let mut frontier = vec![Vec::new()];
    for _ in 0..max_len {
        let mut next = Vec::new();
        for prefix in &frontier {
            for &byte in &alphabet {
                let mut value = prefix.clone();
                value.push(byte);
                all.push(value.clone());
                next.push(value);
            }
        }
        frontier = next;
    }
    all
}

#[test]
fn one_shared_native_reducer_matches_ordered_build_many_exhaustively() {
    let pattern_sets: &[&[&str]] = &[
        &["ab", "a"],
        &["a", "ab"],
        &["a+", "a"],
        &["a+?", "a"],
        &["a", "a", "ab"],
        &[r"(?P<same>a)", r"(?P<same>b)"],
        &["", "a"],
        &["a", ""],
    ];
    let haystacks = byte_strings(3);
    for patterns in pattern_sets {
        let ids = (0..patterns.len())
            .map(|ordinal| if ordinal % 2 == 0 { 91 } else { 7 })
            .collect::<Vec<_>>();
        let artifact = compile_ordered_many_aot(
            OrderedManyAotCompileRequest::new(rows(patterns, &ids), Target::x86_64_linux())
                .mode(CompileMode::Fast),
            PreparedAggregateExports::COUNT,
            SlowAotLimits::default(),
        )
        .unwrap_or_else(|error| panic!("shared native ordered-many reducer {patterns:?}: {error}"));
        assert_eq!(patterns.len(), artifact.receipt().rows);
        assert!(matches!(
            artifact.receipt().aggregate_strategy,
            PreparedAggregateStrategy::NativeFused
                | PreparedAggregateStrategy::NativeOrderedNfaFused
        ));
        assert!(
            artifact
                .compiled()
                .module()
                .prepared_count_symbol()
                .is_some()
        );
        assert_eq!(
            1,
            artifact
                .compiled()
                .module()
                .prepared_count_symbol()
                .into_iter()
                .count(),
        );
        for haystack in &haystacks {
            assert_eq!(
                oracle(patterns, haystack),
                semantic_spans(&artifact, haystack),
                "patterns={patterns:?} haystack={haystack:?}",
            );
        }
    }
}

#[test]
fn optimizing_count_and_span_sum_share_one_authenticated_source_identity() {
    let patterns = [r"\bfoo+\b", r"bar|baz", r"(?P<x>quux)"];
    let ids = [100, 7, 100];
    let exports = PreparedAggregateExports::COUNT.union(PreparedAggregateExports::SPAN_SUM);
    let artifact = compile_ordered_many_aot(
        OrderedManyAotCompileRequest::new(rows(&patterns, &ids), Target::aarch64_macos())
            .mode(CompileMode::Optimizing),
        exports,
        SlowAotLimits::default(),
    )
    .expect("optimizing shared reducer");
    assert_eq!(exports, artifact.receipt().exports);
    assert!(matches!(
        artifact.receipt().aggregate_strategy,
        PreparedAggregateStrategy::NativeFused | PreparedAggregateStrategy::NativeOrderedNfaFused
    ));
    assert!(
        artifact
            .compiled()
            .module()
            .prepared_count_symbol()
            .is_some()
    );
    assert!(
        artifact
            .compiled()
            .module()
            .prepared_span_sum_symbol()
            .is_some()
    );
    assert_eq!(
        artifact.receipt().program_sha256,
        artifact.compiled().receipt().program_sha256,
    );
    assert_eq!(
        artifact.receipt().object_sha256,
        artifact.compiled().receipt().object_sha256,
    );

    let reordered = compile_ordered_many_aot(
        OrderedManyAotCompileRequest::new(
            rows(&[patterns[1], patterns[0], patterns[2]], &[7, 100, 100]),
            Target::aarch64_macos(),
        )
        .mode(CompileMode::Optimizing),
        exports,
        SlowAotLimits::default(),
    )
    .expect("reordered shared reducer");
    assert_ne!(
        artifact.receipt().ordered_sources_sha256,
        reordered.receipt().ordered_sources_sha256,
    );

    let changed_ids = compile_ordered_many_aot(
        OrderedManyAotCompileRequest::new(rows(&patterns, &[100, 8, 100]), Target::aarch64_macos())
            .mode(CompileMode::Optimizing),
        exports,
        SlowAotLimits::default(),
    )
    .expect("ID-changed shared reducer");
    assert_ne!(
        artifact.receipt().ordered_sources_sha256,
        changed_ids.receipt().ordered_sources_sha256,
    );
    assert_eq!(
        artifact.receipt().program_sha256,
        changed_ids.receipt().program_sha256,
        "caller IDs bind the source receipt but cannot change matching semantics",
    );
}

#[test]
fn full_ordinary_optimizer_keeps_helper_free_native_fused_ahead_of_v15() {
    let patterns = ["ab", "a", "b+"];
    let ids = [0, 1, 2];
    let mut limits = OrderedManyAotCompileLimits::default();
    limits.compile.determinize = DeterminizeLimits {
        max_states: 0,
        max_transitions: 0,
        max_work: 0,
    };
    let request = || {
        OrderedManyAotCompileRequest::new(rows(&patterns, &ids), Target::x86_64_linux())
            .mode(CompileMode::Optimizing)
            .limits(limits)
    };
    let ordinary = compile_ordered_many_aot(
        request(),
        PreparedAggregateExports::COUNT,
        SlowAotLimits::default(),
    )
    .expect("full ordinary ordered-many incumbent");
    assert_eq!(
        ordinary.receipt().aggregate_strategy,
        PreparedAggregateStrategy::NativeFused,
    );
    assert_eq!(ordinary.compiled().module().required_prepare_capabilities(), 0);
    assert!(
        ordinary
            .compiled()
            .module()
            .required_runtime_symbols()
            .next()
            .is_none(),
    );

}

#[test]
fn shared_aot_limits_and_export_surface_fail_closed() {
    let request = || {
        OrderedManyAotCompileRequest::new(rows(&["a", "b"], &[0, 1]), Target::x86_64_linux())
            .mode(CompileMode::Fast)
    };
    assert!(matches!(
        compile_ordered_many_aot(
            request(),
            PreparedAggregateExports::GREP_COUNT,
            SlowAotLimits::default(),
        ),
        Err(OrderedManyAotCompileError::UnsupportedExports { .. })
    ));

    let v15_request = || {
        OrderedManyAotCompileRequest::new(
            rows(&[r"(?-u:[\x00-\xFF])\bfoo\b"], &[0]),
            Target::x86_64_linux(),
        )
        .mode(CompileMode::Fast)
    };
    let v15 = compile_ordered_many_aot(
        v15_request(),
        PreparedAggregateExports::COUNT,
        SlowAotLimits::default(),
    )
    .expect("ordered-NFA V15 resource fixture");
    assert_eq!(
        v15.receipt().aggregate_strategy,
        PreparedAggregateStrategy::NativeOrderedNfaFused,
    );

    let mut slow = SlowAotLimits::default();
    slow.max_native_data_bytes = 0;
    let capped_v15 = compile_ordered_many_aot_reported(
        v15_request(),
        PreparedAggregateExports::COUNT,
        slow,
    );
    assert!(matches!(
        &capped_v15,
        Ok(OrderedManyAotCompileDisposition::Declined(
            OrderedManyAotCompileDecline::NativeDataBytes { limit, .. }
        )) if *limit == 0
    ), "unexpected capped V15 disposition: {capped_v15:?}");

    let mut object_limits = OrderedManyAotCompileLimits::default();
    let object_limit = v15.compiled().receipt().data_bytes;
    assert!(object_limit < v15.compiled().object().len());
    object_limits.compile.max_object_bytes = object_limit;
    let object_capped_v15 = compile_ordered_many_aot_reported(
        v15_request().limits(object_limits),
        PreparedAggregateExports::COUNT,
        SlowAotLimits::default(),
    );
    assert!(matches!(
        &object_capped_v15,
        Ok(OrderedManyAotCompileDisposition::Declined(
            OrderedManyAotCompileDecline::ObjectBytes { limit, .. }
        )) if *limit == object_limit
    ), "unexpected object-capped V15 disposition: {object_capped_v15:?}");

    let mut limits = OrderedManyAotCompileLimits::default();
    limits.max_rows = 1;
    assert!(matches!(
        compile_ordered_many_aot(
            request().limits(limits),
            PreparedAggregateExports::COUNT,
            SlowAotLimits::default(),
        ),
        Err(OrderedManyAotCompileError::Planning(
            fre_aot_regex::OrderedManyCompileError::RowsLimit {
                needed: 2,
                limit: 1,
            }
        ))
    ));

    let mut limits = OrderedManyAotCompileLimits::default();
    limits.max_pattern_bytes = 1;
    assert!(matches!(
        compile_ordered_many_aot(
            request().limits(limits),
            PreparedAggregateExports::COUNT,
            SlowAotLimits::default(),
        ),
        Err(OrderedManyAotCompileError::Planning(
            fre_aot_regex::OrderedManyCompileError::PatternBytesLimit {
                row: 1,
                needed: 2,
                limit: 1,
                ..
            }
        ))
    ));
}
