use fre_aot_regex::{
    CompileMode, DeterminizeLimits, EntryAbi, MatchResult, OrderedManyAotCompileDecline,
    OrderedManyAotCompileDisposition, OrderedManyAotCompileError, OrderedManyAotCompileLimits,
    OrderedManyAotCompileRequest, OrderedManyPatternId, OrderedManyRow, OutputContract,
    PREPARED_CAPABILITY_ORDERED_NFA_V15, PreparedAggregateExports, PreparedAggregateStrategy,
    SearchWindow, SlowAotLimits, Target, compile_ordered_many_aot,
    compile_ordered_many_aot_reported,
};
use regex_automata::meta::Regex as MetaRegex;
use sha2::{Digest, Sha256};

fn rows(patterns: &[&str], ids: &[u32]) -> Vec<OrderedManyRow> {
    assert_eq!(patterns.len(), ids.len());
    patterns
        .iter()
        .zip(ids)
        .map(|(&pattern, &id)| OrderedManyRow::new(OrderedManyPatternId::new(id), pattern))
        .collect()
}

#[test]
fn shared_grep_count_uses_one_closed_ordered_automaton_cross_isa() {
    let patterns = ["foo", "bar+", "(?:quux|xyz)"];
    let ids = [91, 7, 91];
    for target in [Target::x86_64_linux(), Target::aarch64_linux()] {
        let artifact = compile_ordered_many_aot(
            OrderedManyAotCompileRequest::new(rows(&patterns, &ids), target)
                .mode(CompileMode::Optimizing),
            PreparedAggregateExports::GREP_COUNT,
            SlowAotLimits::default(),
        )
        .expect("shared GrepCount native reducer");
        let compiled = artifact.compiled();
        let module = compiled.module();
        assert_eq!(compiled.receipt().output, OutputContract::Span);
        assert_eq!(
            artifact.receipt().aggregate_strategy,
            PreparedAggregateStrategy::NativeFused,
        );
        assert_eq!(
            module.prepared_aggregate_exports(),
            PreparedAggregateExports::GREP_COUNT,
        );
        assert!(module.prepared_grep_count_symbol().is_some());
        assert_eq!(module.prepared_count_symbol(), None);
        assert_eq!(module.prepared_span_sum_symbol(), None);
        assert!(module.required_runtime_symbols().next().is_none());
        assert!(!compiled.receipt().runtime_helper_required);
        assert_eq!(artifact.receipt().rows, patterns.len());
        assert_eq!(
            oracle(&patterns, b"nope foo barrr xyz"),
            semantic_spans(&artifact, b"nope foo barrr xyz"),
        );
    }
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
fn optimizing_exact_rows_can_select_one_ordered_finite_native_scan() {
    let mut rows = Vec::new();
    for byte in 0_u8..65 {
        let mut pattern = String::from("(?-u:");
        for _ in 0..8 {
            pattern.push_str(&format!("\\x{byte:02x}"));
        }
        if byte == 64 {
            pattern.push_str("\\x40");
        }
        pattern.push(')');
        rows.push(OrderedManyRow::new(
            OrderedManyPatternId::new(u32::from(byte)),
            pattern,
        ));
    }
    let artifact = compile_ordered_many_aot(
        OrderedManyAotCompileRequest::new(rows, Target::x86_64_linux())
            .mode(CompileMode::Optimizing),
        PreparedAggregateExports::COUNT,
        SlowAotLimits::default(),
    )
    .expect("shared exact finite native reducer");

    assert!(
        artifact
            .compiled()
            .receipt()
            .ordered_finite_language_aot
            .is_some(),
        "correlated variable-width exact rows should select one finite-language scan",
    );
    assert_eq!(
        PreparedAggregateStrategy::NativeFused,
        artifact.receipt().aggregate_strategy,
    );
    assert!(
        artifact
            .compiled()
            .module()
            .required_runtime_symbols()
            .next()
            .is_none(),
    );
}

fn escaped_exact_pattern(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut pattern = String::from("(?-u:");
    for byte in bytes {
        write!(&mut pattern, "\\x{byte:02x}").expect("write escaped byte");
    }
    pattern.push(')');
    pattern
}

fn escaped_exact_alternation(literals: &[Vec<u8>]) -> String {
    use std::fmt::Write as _;

    let mut pattern = String::from("(?-u:(?:");
    for (index, literal) in literals.iter().enumerate() {
        if index != 0 {
            pattern.push('|');
        }
        for byte in literal {
            write!(&mut pattern, "\\x{byte:02x}").expect("write escaped alternative byte");
        }
    }
    pattern.push_str("))");
    pattern
}

fn generated_outlier_run_literals(count: usize, width: usize, outliers: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|ordinal| {
            let byte = u8::try_from((ordinal * 73 + 19) % 251).expect("outlier byte");
            let extra = usize::from(ordinal >= count.saturating_sub(outliers));
            vec![byte; width + extra]
        })
        .collect()
}

fn generated_radix_literals(count: usize, width: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|ordinal| {
            let mut bytes = Vec::with_capacity(width);
            bytes.push(u8::try_from(ordinal % 251).expect("radix low byte"));
            bytes.push(u8::try_from((ordinal / 251) % 251).expect("radix high byte"));
            let mut state = u64::try_from(ordinal)
                .expect("radix ordinal")
                .wrapping_add(0x6a09_e667_f3bc_c909);
            while bytes.len() < width {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                bytes.push(state.to_le_bytes()[bytes.len() % 8]);
            }
            bytes
        })
        .collect()
}

fn one_pattern_per_literal(literals: &[Vec<u8>]) -> Vec<String> {
    literals
        .iter()
        .map(|literal| escaped_exact_pattern(literal))
        .collect()
}

struct GeneratedExactFixture {
    name: &'static str,
    patterns: Vec<String>,
    literals: Vec<Vec<u8>>,
    selects_finite: bool,
}

fn generated_semantic_haystacks(literals: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut haystacks = vec![Vec::new(), b"public unrelated control".to_vec()];
    for index in [0, literals.len() / 2, literals.len() - 1] {
        let literal = &literals[index];
        let mut wrapped = vec![0xff, 0xfe];
        wrapped.extend_from_slice(literal);
        wrapped.extend_from_slice(&[0xfe, 0xff]);
        haystacks.push(wrapped);

        let mut near_miss = literal.clone();
        let middle = near_miss.len() / 2;
        near_miss[middle] ^= 0x80;
        haystacks.push(near_miss);
    }
    let mut dense = Vec::new();
    for literal in literals {
        dense.extend_from_slice(literal);
        dense.extend_from_slice(&[0xff, 0xfe]);
    }
    haystacks.push(dense);
    haystacks
}

#[test]
fn generated_exact_finite_diversity_preserves_route_object_and_semantics() {
    let outlier33 = generated_outlier_run_literals(33, 8, 1);
    let nested65 = generated_outlier_run_literals(65, 8, 1);
    let priority_base = generated_outlier_run_literals(65, 8, 0);
    let first_byte = priority_base[0][0];
    let short = vec![first_byte; 8];
    let long = vec![first_byte; 9];
    let mut short_first_literals = vec![short.clone(), long.clone()];
    short_first_literals.extend(priority_base.iter().skip(1).cloned());
    let mut long_first_literals = vec![long, short];
    long_first_literals.extend(priority_base.iter().skip(1).cloned());
    let radix17 = generated_radix_literals(17, 13);
    let fixtures = [
        GeneratedExactFixture {
            name: "flat-33",
            patterns: one_pattern_per_literal(&outlier33),
            literals: outlier33,
            selects_finite: true,
        },
        GeneratedExactFixture {
            name: "nested-13x5",
            patterns: nested65
                .chunks_exact(5)
                .map(escaped_exact_alternation)
                .collect(),
            literals: nested65,
            selects_finite: true,
        },
        GeneratedExactFixture {
            name: "short-prefix-first",
            patterns: std::iter::once(escaped_exact_alternation(&short_first_literals[..2]))
                .chain(
                    short_first_literals[2..]
                        .iter()
                        .map(|literal| escaped_exact_pattern(literal)),
                )
                .collect(),
            literals: short_first_literals,
            selects_finite: true,
        },
        GeneratedExactFixture {
            name: "long-prefix-first",
            patterns: std::iter::once(escaped_exact_alternation(&long_first_literals[..2]))
                .chain(
                    long_first_literals[2..]
                        .iter()
                        .map(|literal| escaped_exact_pattern(literal)),
                )
                .collect(),
            literals: long_first_literals,
            selects_finite: true,
        },
        GeneratedExactFixture {
            name: "radix-17-incumbent-control",
            patterns: one_pattern_per_literal(&radix17),
            literals: radix17,
            selects_finite: false,
        },
    ];
    let mut short_first_hashes = None;
    let mut long_first_hashes = None;
    for fixture in fixtures {
        let pattern_refs = fixture
            .patterns
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let source_rows = fixture
            .patterns
            .iter()
            .enumerate()
            .map(|(ordinal, pattern)| {
                let id = u32::try_from(ordinal)
                    .expect("generated row ordinal")
                    .checked_mul(17)
                    .and_then(|id| id.checked_add(3))
                    .expect("generated row ID");
                OrderedManyRow::new(OrderedManyPatternId::new(id), pattern.clone())
            })
            .collect();
        let artifact = compile_ordered_many_aot(
            OrderedManyAotCompileRequest::new(source_rows, Target::aarch64_macos())
                .mode(CompileMode::Optimizing),
            PreparedAggregateExports::COUNT,
            SlowAotLimits::default(),
        )
        .unwrap_or_else(|error| panic!("generated fixture {}: {error}", fixture.name));
        let compiled = artifact.compiled();
        assert_eq!(
            PreparedAggregateStrategy::NativeFused,
            artifact.receipt().aggregate_strategy,
            "fixture {}",
            fixture.name,
        );
        assert!(
            compiled
                .module()
                .required_runtime_symbols()
                .next()
                .is_none()
        );
        assert!(!compiled.object().is_empty());
        let object_sha256: [u8; 32] = Sha256::digest(compiled.object()).into();
        assert_eq!(compiled.receipt().object_sha256, object_sha256);
        assert_eq!(artifact.receipt().object_sha256, object_sha256);

        let finite = compiled.receipt().ordered_finite_language_aot;
        assert_eq!(
            finite.is_some(),
            fixture.selects_finite,
            "fixture {} selected the wrong optimizer route",
            fixture.name,
        );
        if let Some(report) = finite {
            assert_eq!(
                usize::try_from(report.source_count).expect("finite source count"),
                fixture.literals.len(),
            );
            assert_eq!(
                report.source_bytes,
                fixture.literals.iter().map(Vec::len).sum::<usize>(),
            );
            assert_eq!(
                usize::try_from(report.maximum_width).expect("finite maximum width"),
                fixture.literals.iter().map(Vec::len).max().unwrap(),
            );
        }
        for haystack in generated_semantic_haystacks(&fixture.literals) {
            assert_eq!(
                oracle(&pattern_refs, &haystack),
                semantic_spans(&artifact, &haystack),
                "fixture={} haystack={haystack:?}",
                fixture.name,
            );
        }

        let hashes = (compiled.receipt().program_sha256, object_sha256);
        match fixture.name {
            "short-prefix-first" => short_first_hashes = Some(hashes),
            "long-prefix-first" => long_first_hashes = Some(hashes),
            _ => {}
        }
    }
    assert_ne!(short_first_hashes.unwrap(), long_first_hashes.unwrap());
}

#[test]
fn finite_proof_refusals_retain_the_full_shared_incumbent() {
    for patterns in [["", "a"], ["[a-z]{3}", "x"]] {
        let artifact = compile_ordered_many_aot(
            OrderedManyAotCompileRequest::new(rows(&patterns, &[0, 1]), Target::x86_64_linux())
                .mode(CompileMode::Optimizing),
            PreparedAggregateExports::COUNT,
            SlowAotLimits::default(),
        )
        .unwrap_or_else(|error| panic!("finite proof refusal {patterns:?}: {error}"));
        assert!(
            artifact
                .compiled()
                .receipt()
                .ordered_finite_language_aot
                .is_none(),
        );
        assert!(matches!(
            artifact.receipt().aggregate_strategy,
            PreparedAggregateStrategy::NativeFused
                | PreparedAggregateStrategy::NativeOrderedNfaFused
        ));
    }
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
fn shared_v15_scalar_operation_is_closed_for_all_scalar_exports_cross_isa() {
    for target in [Target::x86_64_linux(), Target::aarch64_linux()] {
        for export in [
            PreparedAggregateExports::COUNT,
            PreparedAggregateExports::SPAN_SUM,
            PreparedAggregateExports::GREP_COUNT,
        ] {
            let artifact = compile_ordered_many_aot(
                OrderedManyAotCompileRequest::new(
                    rows(&[r"(?-u:[\x00-\xFF])\bfoo\b"], &[0]),
                    target,
                )
                .mode(CompileMode::Fast),
                export,
                SlowAotLimits::default(),
            )
            .expect("shared Ordered-NFA scalar operation");
            let compiled = artifact.compiled();
            let module = compiled.module();
            assert_eq!(
                artifact.receipt().aggregate_strategy,
                PreparedAggregateStrategy::NativeOrderedNfaFused,
            );
            assert_eq!(compiled.receipt().entry_abi, EntryAbi::PreparedScalarReduceV1);
            assert_eq!(
                compiled.receipt().required_prepare_capabilities,
                PREPARED_CAPABILITY_ORDERED_NFA_V15,
            );
            assert!(!compiled.receipt().runtime_helper_required);
            assert_eq!(module.prepared_bulk_strategy(), None);
            assert_eq!(module.prepared_entry_symbol(), None);
            assert_eq!(module.prepared_span_fill_symbol(), None);
            assert!(module.required_runtime_symbols().next().is_none());
            let reducer = match export {
                PreparedAggregateExports::COUNT => module.prepared_count_symbol(),
                PreparedAggregateExports::SPAN_SUM => module.prepared_span_sum_symbol(),
                PreparedAggregateExports::GREP_COUNT => module.prepared_grep_count_symbol(),
                _ => unreachable!("test requests one scalar export"),
            };
            assert_eq!(reducer, Some(module.entry_symbol()));
        }
    }
}

#[test]
fn shared_aot_limits_and_unsupported_export_surfaces_fail_closed() {
    let request = || {
        OrderedManyAotCompileRequest::new(rows(&["a", "b"], &[0, 1]), Target::x86_64_linux())
            .mode(CompileMode::Fast)
    };
    assert!(matches!(
        compile_ordered_many_aot(
            request(),
            PreparedAggregateExports::NONE,
            SlowAotLimits::default(),
        ),
        Err(OrderedManyAotCompileError::UnsupportedExports { .. })
    ));
    assert!(matches!(
        compile_ordered_many_aot(
            request(),
            PreparedAggregateExports::COUNT.union(PreparedAggregateExports::GREP_COUNT),
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
    assert_eq!(
        v15.compiled().receipt().entry_abi,
        EntryAbi::PreparedScalarReduceV1,
    );
    assert_eq!(v15.compiled().module().prepared_bulk_strategy(), None);
    assert!(v15
        .compiled()
        .module()
        .required_runtime_symbols()
        .next()
        .is_none());

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
