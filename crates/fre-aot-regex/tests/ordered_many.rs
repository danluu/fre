use fre_aot_regex::{
    CompileError, CompileMode, CompileResource, OrderedManyCompileError, OrderedManyCompileLimits,
    OrderedManyCompileRequest, OrderedManyFallbackReason, OrderedManyMatch, OrderedManyPatternId,
    OrderedManyRow, OrderedManyRunError, OrderedManySessionLimits, OrderedManyStrategy,
    compile_ordered_many,
};
use fre_syntax::{RustConstructor, RustProfile};
use regex_automata::meta::Regex as MetaRegex;

fn profile_size_limit(profile: &RustProfile) -> Option<usize> {
    match profile.constructor {
        RustConstructor::RegexBuilder { size_limit, .. }
        | RustConstructor::RegexSetBuilder { size_limit, .. } => {
            Some(usize::try_from(size_limit).unwrap())
        }
        RustConstructor::RebarMeta { .. } => None,
    }
}

fn one_row_request() -> OrderedManyCompileRequest {
    OrderedManyCompileRequest::new(vec![OrderedManyRow::new(OrderedManyPatternId::new(7), "a")])
}

#[test]
fn native_per_row_size_limit_is_synchronized_and_last_setter_wins() {
    const HIGH_LEVEL_DEFAULT: usize = 10 * 1_048_576;
    let default_request = one_row_request();
    assert_eq!(
        HIGH_LEVEL_DEFAULT,
        default_request.limits.max_program_bytes_per_row
    );
    assert_eq!(
        Some(HIGH_LEVEL_DEFAULT),
        profile_size_limit(&default_request.profile)
    );

    let mut limits = OrderedManyCompileLimits::default();
    limits.max_program_bytes_per_row = 12_345;
    let limits_last = one_row_request().size_limit(7).limits(limits);
    assert_eq!(12_345, limits_last.limits.max_program_bytes_per_row);
    assert_eq!(Some(12_345), profile_size_limit(&limits_last.profile));

    let size_last = one_row_request().limits(limits).size_limit(7);
    assert_eq!(7, size_last.limits.max_program_bytes_per_row);
    assert_eq!(Some(7), profile_size_limit(&size_last.profile));

    let rebar = one_row_request()
        .size_limit(7)
        .profile(RustProfile::rebar_1_12_4());
    assert_eq!(
        OrderedManyCompileLimits::default().max_program_bytes_per_row,
        rebar.limits.max_program_bytes_per_row
    );
    assert_eq!(None, profile_size_limit(&rebar.profile));
}

#[test]
fn per_row_limits_do_not_rewrite_a_set_constructor_identity() {
    let profile = RustProfile::regex_set_1_12_4();
    let profile_limit = profile_size_limit(&profile);
    let mut limits = OrderedManyCompileLimits::default();
    limits.max_program_bytes_per_row = 12_345;

    let request = one_row_request().profile(profile).limits(limits);
    assert_eq!(12_345, request.limits.max_program_bytes_per_row);
    assert_eq!(profile_limit, profile_size_limit(&request.profile));
    assert!(matches!(
        request.profile.constructor,
        RustConstructor::RegexSetBuilder { .. }
    ));
}

#[test]
fn size_limit_is_the_exact_per_row_program_boundary() {
    let measured = compile_ordered_many(
        one_row_request()
            .size_limit(usize::MAX)
            .mode(CompileMode::Fast),
    )
    .expect("measure one native row");
    let needed = measured.stats().serialized_program_bytes;
    assert!(needed > 0);

    let exact = compile_ordered_many(one_row_request().size_limit(needed).mode(CompileMode::Fast))
        .expect("the exact per-row native boundary is inclusive");
    assert_eq!(needed, exact.stats().serialized_program_bytes);

    assert!(matches!(
        compile_ordered_many(
            one_row_request()
                .size_limit(needed - 1)
                .mode(CompileMode::Fast)
        ),
        Err(OrderedManyCompileError::Row {
            row: 0,
            pattern_id,
            source: CompileError::Resource {
                resource: CompileResource::ProgramBytes,
                required,
                limit,
            },
        }) if pattern_id == OrderedManyPatternId::new(7)
            && required == needed
            && limit == needed - 1
    ));
}

#[test]
fn direct_request_cannot_bypass_the_profile_native_program_limit() {
    let mut request = one_row_request().size_limit(0);
    request.limits.max_program_bytes_per_row = usize::MAX;
    assert!(matches!(
        compile_ordered_many(request),
        Err(OrderedManyCompileError::Row {
            row: 0,
            pattern_id,
            source: CompileError::Resource {
                resource: CompileResource::ProgramBytes,
                limit: 0,
                required,
            },
        }) if pattern_id == OrderedManyPatternId::new(7) && required > 0
    ));
}

fn compile_rows(
    patterns: &[&str],
    ids: &[u32],
    force_fallback: bool,
) -> fre_aot_regex::OrderedManyProgram {
    assert_eq!(patterns.len(), ids.len());
    let rows = patterns
        .iter()
        .zip(ids)
        .map(|(&pattern, &id)| OrderedManyRow::new(OrderedManyPatternId::new(id), pattern))
        .collect();
    let mut limits = OrderedManyCompileLimits::default();
    if force_fallback {
        limits.tagged.max_patterns = 0;
    }
    compile_ordered_many(
        OrderedManyCompileRequest::new(rows)
            .mode(CompileMode::Fast)
            .limits(limits),
    )
    .expect("ordered-many program")
}

fn execute(
    program: &fre_aot_regex::OrderedManyProgram,
    haystack: &[u8],
) -> Vec<(u32, u32, usize, usize)> {
    let mut session = program
        .prepare_session(haystack.len(), OrderedManySessionLimits::unlimited())
        .expect("ordered-many session");
    let capacity = haystack.len().checked_add(1).expect("test haystack bound");
    let mut output = vec![OrderedManyMatch::default(); capacity];
    let report = session.fill(haystack, &mut output).expect("fill");
    assert!(!report.truncated());
    assert_eq!(report.selected(), report.written());
    output[..report.written()]
        .iter()
        .map(|matched| {
            (
                matched.source_ordinal(),
                matched.pattern_id().get(),
                matched.start(),
                matched.end(),
            )
        })
        .collect()
}

fn upstream_regex(patterns: &[&str]) -> MetaRegex {
    MetaRegex::builder()
        .configure(MetaRegex::config().utf8_empty(false))
        .syntax(
            regex_automata::util::syntax::Config::new()
                .utf8(false)
                .unicode(true),
        )
        .build_many(patterns)
        .expect("upstream ordered-many oracle")
}

fn upstream(regex: &MetaRegex, ids: &[u32], haystack: &[u8]) -> Vec<(u32, u32, usize, usize)> {
    regex
        .find_iter(haystack)
        .map(|matched| {
            let ordinal = matched.pattern().as_usize();
            (
                u32::try_from(ordinal).unwrap(),
                ids[ordinal],
                matched.start(),
                matched.end(),
            )
        })
        .collect()
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
fn tagged_and_forced_fallback_match_upstream_ordered_many_exhaustively() {
    let pattern_sets: &[&[&str]] = &[
        &["ab", "a"],
        &["a", "ab"],
        &["", "a"],
        &["a", ""],
        &[r"\Aab", "."],
        &["a+", "a"],
        &["a+?", "a"],
        &["a", "a", "ab"],
    ];
    let haystacks = byte_strings(3);
    for patterns in pattern_sets {
        // Deliberately duplicate and reorder payload IDs. Only source ordinal
        // may determine matching priority.
        let ids = (0..patterns.len())
            .map(|ordinal| if ordinal % 2 == 0 { 91 } else { 7 })
            .collect::<Vec<_>>();
        let tagged = compile_rows(patterns, &ids, false);
        let fallback = compile_rows(patterns, &ids, true);
        let oracle = upstream_regex(patterns);
        assert_eq!(OrderedManyStrategy::TaggedMany, tagged.strategy());
        assert_eq!(OrderedManyStrategy::SemanticFallback, fallback.strategy());
        assert!(matches!(
            fallback.fallback_reason(),
            Some(OrderedManyFallbackReason::TaggedBuild(_))
        ));
        for haystack in &haystacks {
            let expected = upstream(&oracle, &ids, haystack);
            assert_eq!(
                expected,
                execute(&tagged, haystack),
                "tagged {patterns:?}/{haystack:?}"
            );
            assert_eq!(
                expected,
                execute(&fallback, haystack),
                "fallback {patterns:?}/{haystack:?}"
            );
        }
    }
}

#[test]
fn zero_rows_succeed_without_touching_the_output_buffer() {
    let program = compile_ordered_many(OrderedManyCompileRequest::new(Vec::new())).unwrap();
    assert!(program.is_empty());
    assert_eq!(OrderedManyStrategy::Empty, program.strategy());
    assert_eq!(0, program.stats().rows);
    let mut session = program
        .prepare_session(3, OrderedManySessionLimits::default())
        .unwrap();
    let sentinel = OrderedManyMatch::default();
    let mut output = [sentinel; 2];
    let report = session.fill(b"abc", &mut output).unwrap();
    assert_eq!(0, report.selected());
    assert_eq!(0, report.written());
    assert!(!report.truncated());
    assert_eq!([sentinel; 2], output);
}

#[test]
fn fallback_fill_reports_exact_truncation_and_terminal_partial_mutation() {
    let program = compile_rows(&["a"], &[42], true);
    let mut session = program
        .prepare_session(3, OrderedManySessionLimits::unlimited())
        .unwrap();
    let mut output = [OrderedManyMatch::default(); 1];
    let report = session.fill(b"aaa", &mut output).unwrap();
    assert_eq!(3, report.selected());
    assert_eq!(1, report.written());
    assert!(report.truncated());
    assert_eq!(
        (0, 42, 0, 1),
        (
            output[0].source_ordinal(),
            output[0].pattern_id().get(),
            output[0].start(),
            output[0].end(),
        )
    );

    let mut limits = OrderedManySessionLimits::unlimited();
    limits.max_match_events = 1;
    let mut limited = program.prepare_session(2, limits).unwrap();
    let sentinel = OrderedManyMatch::default();
    let mut partial = [sentinel; 2];
    assert!(matches!(
        limited.fill(b"aa", &mut partial),
        Err(OrderedManyRunError::MatchEventLimit {
            needed: 2,
            limit: 1
        })
    ));
    assert_eq!(42, partial[0].pattern_id().get());
    assert_eq!((0, 1), (partial[0].start(), partial[0].end()));
    assert_eq!(sentinel, partial[1]);
}

#[test]
fn source_length_mismatch_is_rejected_before_buffer_mutation() {
    let program = compile_rows(&["a"], &[3], false);
    let mut session = program
        .prepare_session(1, OrderedManySessionLimits::unlimited())
        .unwrap();
    let sentinel = OrderedManyMatch::default();
    let mut output = [sentinel];
    assert!(matches!(
        session.fill(b"aa", &mut output),
        Err(OrderedManyRunError::SourceLength {
            expected: 1,
            actual: 2
        })
    ));
    assert_eq!([sentinel], output);
}

#[test]
fn row_compile_errors_retain_source_ordinal_and_pattern_id() {
    let error = compile_ordered_many(OrderedManyCompileRequest::new(vec![
        OrderedManyRow::new(OrderedManyPatternId::new(9), "a"),
        OrderedManyRow::new(OrderedManyPatternId::new(77), "("),
    ]))
    .unwrap_err();
    assert!(matches!(
        error,
        OrderedManyCompileError::Row {
            row: 1,
            pattern_id,
            source: CompileError::Syntax(_),
        } if pattern_id == OrderedManyPatternId::new(77)
    ));
}

#[test]
fn more_than_128_rows_retain_exact_source_order_fallback() {
    let rows = (0..129)
        .map(|row| {
            OrderedManyRow::new(
                OrderedManyPatternId::new(if row == 0 { 500 } else { 1 }),
                "a",
            )
        })
        .collect();
    let program =
        compile_ordered_many(OrderedManyCompileRequest::new(rows).mode(CompileMode::Fast)).unwrap();
    assert_eq!(OrderedManyStrategy::SemanticFallback, program.strategy());
    assert!(matches!(
        program.fallback_reason(),
        Some(OrderedManyFallbackReason::TaggedOwnerLimit {
            needed: 129,
            limit: 128
        })
    ));
    assert_eq!(vec![(0, 500, 0, 1)], execute(&program, b"a"));
}

#[test]
fn nullable_repetition_tagged_refusal_keeps_semantic_fallback() {
    let patterns = [r"(?-u:(?:a?)*)", "a"];
    let ids = [60, 2];
    let program = compile_rows(&patterns, &ids, false);
    assert_eq!(OrderedManyStrategy::SemanticFallback, program.strategy());
    assert!(matches!(
        program.fallback_reason(),
        Some(OrderedManyFallbackReason::TaggedBuild(
            fre_automata::TaggedManyBuildError::ZeroWidthCycle { pattern: 0 }
        ))
    ));
    let oracle = upstream_regex(&patterns);
    for haystack in byte_strings(2) {
        assert_eq!(
            upstream(&oracle, &ids, &haystack),
            execute(&program, &haystack),
            "{haystack:?}"
        );
    }
}
