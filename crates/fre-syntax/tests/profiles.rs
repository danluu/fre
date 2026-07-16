use std::collections::{BTreeSet, HashSet};

use fre_syntax::{
    AdmissionPolicy, AdmissionStatus, CanonicalPattern, CompatibilityProfile, ErrorCategory,
    PackageIdentity, ParseRequest, QuotaBounded, Re2CapabilityStatus, Re2Encoding, Re2Options,
    Re2Profile, Re2Surface, ResourceKind, RustConstructor, RustMatchKind, RustProfile,
    SafetyEnvelope, StrictAdmission, SyntaxQuotas, UnicodeVersion, UpstreamRevision, parse,
    re2_surface_inventory,
};

fn re2_literal_profile() -> CompatibilityProfile {
    let mut profile = Re2Profile::default();
    profile.options.literal = true;
    CompatibilityProfile::Re2(profile)
}

#[test]
fn pinned_defaults_are_explicit() {
    let RustProfile {
        regex,
        regex_automata,
        regex_syntax,
        unicode,
        constructor,
        options,
    } = RustProfile::default();
    assert_eq!(regex, PackageIdentity::REGEX_1_12_4);
    assert_eq!(regex_automata, PackageIdentity::REGEX_AUTOMATA_0_4_14);
    assert_eq!(regex_syntax, PackageIdentity::REGEX_SYNTAX_0_8_11);
    assert_eq!(regex.version.to_string(), "1.12.4");
    assert_eq!(regex_automata.version.to_string(), "0.4.14");
    assert_eq!(regex_syntax.version.to_string(), "0.8.11");
    assert_eq!(
        regex.checksum,
        "f1292b7759ae1cb9ec195452d1390a074f0cd8541ab7a5a8c31cd6db45d4a6ba"
    );
    assert_eq!(
        regex_automata.checksum,
        "6e1dd4122fc1595e8162618945476892eefca7b88c52820e74af6262213cae8f"
    );
    assert_eq!(
        regex_syntax.checksum,
        "d6f6ff9a378485b298a5286656da665ba74413d36db0979633275d2e708145d4"
    );
    assert_eq!(
        regex.vcs_revision.commit(),
        "7b96fdc9d5fe6a0cb4efe30e6689b050493fc1e1"
    );
    assert_eq!(
        regex_automata.vcs_revision.commit(),
        "5e195de266e203441b2c8001d6ebefab1161a59e"
    );
    assert_eq!(
        regex_syntax.vcs_revision.commit(),
        "140167995737fa11dfe11b8af8b9aa143b790b4e"
    );
    assert_eq!(unicode, UnicodeVersion::RUST_16_0_0);
    assert!(options.unicode);
    assert_eq!(options.nest_limit, 250);
    assert_eq!(
        constructor,
        RustConstructor::RegexBuilder {
            size_limit: 10 * (1 << 20),
            dfa_size_limit: 2 * (1 << 20),
            text_syntax_utf8: true,
            bytes_syntax_utf8: false,
            text_utf8_empty: true,
            bytes_utf8_empty: false,
            match_kind: RustMatchKind::LeftmostFirst,
        }
    );

    assert_eq!(
        RustProfile::regex_set_1_12_4().constructor,
        RustConstructor::RegexSetBuilder {
            size_limit: 10 * (1 << 20),
            dfa_size_limit: 2 * (1 << 20),
            text_syntax_utf8: true,
            bytes_syntax_utf8: false,
            text_utf8_empty: true,
            bytes_utf8_empty: false,
            match_kind: RustMatchKind::LeftmostFirst,
        }
    );

    assert!(matches!(
        RustProfile::rebar_1_12_4().constructor,
        RustConstructor::RebarMeta {
            rebar_revision: UpstreamRevision::Rebar463d00f,
            regex_default_features: true,
            regex_logging: true,
            regex_perf_dfa_full: true,
            regex_automata_default_features: true,
            syntax_utf8: false,
            utf8_empty: false,
            match_kind: RustMatchKind::LeftmostFirst,
            build_many_ordered: true,
            thompson_nfa_size_limit: 104_857_600,
            admission_status: AdmissionStatus::UpstreamOraclePending,
        }
    ));

    let re2 = Re2Profile::default();
    assert_eq!(re2.revision, UpstreamRevision::Re2_972a15c);
    assert_eq!(re2.unicode, UnicodeVersion::RE2_15_1_0);
    assert_eq!(re2.options.max_mem, 8 << 20);
    assert!(re2.options.log_errors);
    assert!(re2.options.case_sensitive);
    assert!(!re2.options.posix_syntax);
}

#[test]
fn high_level_and_rebar_profiles_share_syntax_but_not_cache_identity() {
    let high_level = parse(ParseRequest::rust(
        "(?i:ab[c-e])",
        CompatibilityProfile::RustBytes(RustProfile::regex_1_12_4()),
    ))
    .expect("high-level profile parses");
    let rebar = parse(ParseRequest::rust(
        "(?i:ab[c-e])",
        CompatibilityProfile::RustBytes(RustProfile::rebar_1_12_4()),
    ))
    .expect("Rebar profile parses");
    assert_eq!(high_level.summary, rebar.summary);
    assert_ne!(high_level.key, rebar.key);
    let CanonicalPattern::Rust(high_level) = high_level.pattern else {
        panic!("Rust request returned another syntax family")
    };
    let CanonicalPattern::Rust(rebar) = rebar.pattern else {
        panic!("Rust request returned another syntax family")
    };
    assert_eq!(high_level.hir, rebar.hir);
}

#[test]
fn forged_rebar_admission_stamp_is_rejected() {
    let mut forged = RustProfile::rebar_1_12_4();
    let RustConstructor::RebarMeta {
        admission_status, ..
    } = &mut forged.constructor
    else {
        panic!("Rebar profile did not use the Rebar constructor")
    };
    *admission_status = AdmissionStatus::QuotaChecked;

    let error = parse(ParseRequest::rust(
        "a",
        CompatibilityProfile::RustBytes(forged),
    ))
    .expect_err("a forged Rebar admission stamp must be rejected");
    assert_eq!(error.category, ErrorCategory::InvalidConfiguration);
}

#[test]
fn rebar_profile_rejects_every_runner_fixed_option_override() {
    type Mutation = fn(&mut RustProfile);
    let cases: [(&str, &str, Mutation); 8] = [
        ("multi_line", "a", |profile| {
            profile.options.multi_line = true;
        }),
        ("dot_matches_new_line", "a", |profile| {
            profile.options.dot_matches_new_line = true;
        }),
        ("crlf", "a", |profile| profile.options.crlf = true),
        ("line_terminator", "a", |profile| {
            profile.options.line_terminator = b'\r';
        }),
        ("swap_greed", "a+", |profile| {
            profile.options.swap_greed = true;
        }),
        ("ignore_whitespace", "a b", |profile| {
            profile.options.ignore_whitespace = true;
        }),
        ("octal", "a", |profile| profile.options.octal = true),
        ("nest_limit", "a", |profile| {
            profile.options.nest_limit += 1;
        }),
    ];

    for (name, pattern, mutate) in cases {
        let mut profile = RustProfile::rebar_1_12_4();
        mutate(&mut profile);
        let error = parse(ParseRequest::rust(
            pattern,
            CompatibilityProfile::RustBytes(profile),
        ))
        .expect_err(name);
        assert_eq!(
            error.category,
            ErrorCategory::InvalidConfiguration,
            "{name}"
        );
    }
}

#[test]
fn rebar_profile_allows_only_job_options_to_vary() {
    for (unicode, case_insensitive) in [(false, false), (true, true)] {
        let mut profile = RustProfile::rebar_1_12_4();
        profile.options.unicode = unicode;
        profile.options.case_insensitive = case_insensitive;
        let expected_profile = CompatibilityProfile::RustBytes(profile.clone());
        let record = parse(ParseRequest::rust("a", expected_profile.clone()))
            .expect("Rebar job-controlled options must remain configurable");

        assert_eq!(record.key.profile, expected_profile);
        assert_eq!(
            record.admission_status,
            AdmissionStatus::UpstreamOraclePending
        );
        let CompatibilityProfile::RustBytes(accepted) = record.key.profile else {
            panic!("Rebar profile changed syntax family")
        };
        assert_eq!(accepted.options.unicode, unicode);
        assert_eq!(accepted.options.case_insensitive, case_insensitive);
    }
}

#[test]
fn high_level_line_terminator_validation_is_pattern_sensitive() {
    let mut profile = RustProfile::regex_1_12_4();
    profile.options.line_terminator = 0x80;
    let profile = CompatibilityProfile::RustText(profile);

    parse(ParseRequest::rust("a", profile.clone()))
        .expect("a literal does not expose a non-ASCII line terminator to Unicode matching");
    let error = parse(ParseRequest::rust(".", profile))
        .expect_err("a Unicode dot cannot exclude a non-ASCII byte line terminator");
    assert_eq!(error.category, ErrorCategory::UpstreamRustSyntax);
}

#[test]
fn bytes_local_unicode_flags_control_line_terminator_validity() {
    let mut profile = RustProfile::regex_1_12_4();
    profile.options.line_terminator = 0x80;
    let profile = CompatibilityProfile::RustBytes(profile);

    parse(ParseRequest::rust("(?-u:.)", profile.clone()))
        .expect("a byte-mode dot can use a non-ASCII line terminator");
    let error = parse(ParseRequest::rust("(?u:.)", profile))
        .expect_err("a locally Unicode dot must reject a non-ASCII byte line terminator");
    assert_eq!(error.category, ErrorCategory::UpstreamRustSyntax);
}

#[test]
fn cache_keys_separate_facade_options_policy_and_safety() {
    let text =
        parse(ParseRequest::rust("abc", CompatibilityProfile::rust_text())).expect("text parses");
    let bytes = parse(ParseRequest::rust(
        "abc",
        CompatibilityProfile::rust_bytes(),
    ))
    .expect("bytes parses");
    assert_ne!(text.key, bytes.key);

    let mut configured = RustProfile::default();
    configured.options.case_insensitive = true;
    let configured = parse(ParseRequest::rust(
        "abc",
        CompatibilityProfile::RustText(configured),
    ))
    .expect("configured profile parses");
    assert_ne!(text.key, configured.key);

    let quota = parse(
        ParseRequest::rust("abc", CompatibilityProfile::rust_text())
            .with_admission(AdmissionPolicy::Quota(QuotaBounded::default())),
    )
    .expect("quota parse succeeds");
    assert_ne!(text.key, quota.key);
    assert_eq!(
        text.admission_status,
        AdmissionStatus::UpstreamOraclePending
    );
    assert_eq!(quota.admission_status, AdmissionStatus::QuotaChecked);

    let different_safety = parse(
        ParseRequest::rust("abc", CompatibilityProfile::rust_text()).with_safety_envelope(
            SafetyEnvelope {
                max_parse_work: SafetyEnvelope::default().max_parse_work - 1,
                ..SafetyEnvelope::default()
            },
        ),
    )
    .expect("larger-than-needed safety envelope succeeds");
    assert_ne!(text.key, different_safety.key);
}

#[test]
fn every_re2_option_bit_is_identity() {
    let base = Re2Options::default();
    let mut variants = Vec::new();
    macro_rules! variant {
        ($field:ident, $value:expr) => {{
            let mut value = base.clone();
            value.$field = $value;
            variants.push(value);
        }};
    }
    variant!(max_mem, base.max_mem + 1);
    variant!(encoding, Re2Encoding::Latin1);
    variant!(posix_syntax, !base.posix_syntax);
    variant!(longest_match, !base.longest_match);
    variant!(log_errors, !base.log_errors);
    variant!(literal, !base.literal);
    variant!(never_nl, !base.never_nl);
    variant!(dot_nl, !base.dot_nl);
    variant!(never_capture, !base.never_capture);
    variant!(case_sensitive, !base.case_sensitive);
    variant!(perl_classes, !base.perl_classes);
    variant!(word_boundary, !base.word_boundary);
    variant!(one_line, !base.one_line);

    assert_eq!(variants.len(), 13);
    assert!(variants.iter().all(|variant| variant != &base));
    let distinct: HashSet<_> = variants.into_iter().collect();
    assert_eq!(distinct.len(), 13);
}

#[test]
fn rust_text_and_bytes_keep_different_utf8_contracts() {
    let pattern = r"(?-u:\xFF)";
    let text_error = parse(ParseRequest::rust(
        pattern,
        CompatibilityProfile::rust_text(),
    ))
    .expect_err("text cannot permit an invalid UTF-8 consuming expression");
    assert_eq!(text_error.category, ErrorCategory::UpstreamRustSyntax);

    let bytes = parse(ParseRequest::rust(
        pattern,
        CompatibilityProfile::rust_bytes(),
    ))
    .expect("bytes profile permits scoped raw-byte matching");
    assert!(!bytes.summary.guarantees_valid_utf8_nonempty);

    let invalid_source = parse(ParseRequest::re2(
        vec![0xFF],
        CompatibilityProfile::rust_bytes(),
    ))
    .expect_err("the Rust pattern language itself is UTF-8 text");
    assert_eq!(
        invalid_source.category,
        ErrorCategory::InvalidPatternEncoding
    );
}

#[test]
fn strict_and_quota_resource_failures_are_never_relabelled() {
    let quota = AdmissionPolicy::Quota(QuotaBounded {
        syntax: SyntaxQuotas {
            max_pattern_bytes: 2,
            ..SyntaxQuotas::default()
        },
    });
    let quota_error =
        parse(ParseRequest::rust("abc", CompatibilityProfile::rust_text()).with_admission(quota))
            .expect_err("quota is deliberately small");
    assert!(matches!(
        quota_error.category,
        ErrorCategory::FreResourceLimit {
            resource: ResourceKind::PatternBytes,
            limit: 2,
            observed: 3,
        }
    ));

    let strict_error = parse(
        ParseRequest::rust("abc", CompatibilityProfile::rust_text())
            .with_admission(AdmissionPolicy::Strict(StrictAdmission))
            .with_safety_envelope(SafetyEnvelope {
                max_pattern_bytes: 2,
                ..SafetyEnvelope::default()
            }),
    )
    .expect_err("hard safety envelope is deliberately small");
    assert!(matches!(
        strict_error.category,
        ErrorCategory::StrictQualificationFailure {
            resource: ResourceKind::PatternBytes,
            limit: 2,
            observed: 3,
        }
    ));
}

#[test]
fn iterative_traversal_has_independent_node_work_and_nesting_limits() {
    let nesting = AdmissionPolicy::Quota(QuotaBounded {
        syntax: SyntaxQuotas {
            max_nesting: 0,
            ..SyntaxQuotas::default()
        },
    });
    let error =
        parse(ParseRequest::rust("(a)", CompatibilityProfile::rust_text()).with_admission(nesting))
            .expect_err("capture produces a child HIR node");
    assert!(matches!(
        error.category,
        ErrorCategory::FreResourceLimit {
            resource: ResourceKind::Nesting,
            ..
        }
    ));

    let nodes = AdmissionPolicy::Quota(QuotaBounded {
        syntax: SyntaxQuotas {
            max_hir_nodes: 1,
            ..SyntaxQuotas::default()
        },
    });
    let error =
        parse(ParseRequest::rust("(a)", CompatibilityProfile::rust_text()).with_admission(nodes))
            .expect_err("capture plus child exceeds one HIR node");
    assert!(matches!(
        error.category,
        ErrorCategory::FreResourceLimit {
            resource: ResourceKind::HirNodes,
            ..
        }
    ));

    let work = AdmissionPolicy::Quota(QuotaBounded {
        syntax: SyntaxQuotas {
            max_parse_work: 1,
            ..SyntaxQuotas::default()
        },
    });
    let error =
        parse(ParseRequest::rust("abcdef", CompatibilityProfile::rust_text()).with_admission(work))
            .expect_err("literal accounting exceeds one work unit");
    assert!(matches!(
        error.category,
        ErrorCategory::FreResourceLimit {
            resource: ResourceKind::ParseWork,
            ..
        }
    ));
}

#[test]
fn rust_repeat_bounds_are_retained_symbolically() {
    let record = parse(ParseRequest::rust(
        "a{1001}",
        CompatibilityProfile::rust_text(),
    ))
    .expect("Rust accepts this repeat bound");
    assert_eq!(record.summary.repetitions, 1);
    assert_eq!(record.summary.largest_finite_repeat, Some(1001));
}

#[test]
fn re2_literal_mode_distinguishes_utf8_and_latin1() {
    let utf8_error = parse(ParseRequest::re2(vec![0xFF], re2_literal_profile()))
        .expect_err("RE2 UTF-8 mode validates pattern bytes");
    assert_eq!(utf8_error.category, ErrorCategory::InvalidPatternEncoding);

    let mut latin1 = Re2Profile::default();
    latin1.options.literal = true;
    latin1.options.encoding = Re2Encoding::Latin1;
    let record = parse(ParseRequest::re2(
        vec![0xFF, b'{', b'1', b'0', b'0', b'1', b'}'],
        CompatibilityProfile::Re2(latin1),
    ))
    .expect("Latin-1 literal mode preserves all bytes and treats braces literally");
    assert_eq!(record.summary.literal_bytes, 7);
    assert!(!record.summary.guarantees_valid_utf8_nonempty);
}

#[test]
fn re2_direct_parser_preserves_ast_diagnostics_and_syntax_modes() {
    let perl = CompatibilityProfile::re2();
    let oversized = parse(ParseRequest::re2(b"a{1001}".to_vec(), perl.clone()))
        .expect_err("RE2 rejects a repeat bound above 1000");
    assert_eq!(
        oversized.category,
        ErrorCategory::Re2Syntax {
            code: 10,
            argument_bytes: b"{1001}".to_vec(),
        }
    );
    assert_eq!(oversized.span.expect("repeat span").start, 1);

    for pattern in [r"a{1000}", r"a\{1001}", r"[a{1001}]", r"\Q{1001}\E"] {
        let record = parse(ParseRequest::re2(pattern.as_bytes().to_vec(), perl.clone()))
            .expect("direct Perl parser accepts the pattern");
        let CanonicalPattern::Re2(parsed) = record.pattern else {
            panic!("general RE2 syntax must retain a direct AST")
        };
        assert_eq!(parsed.ast.pattern.as_ref(), pattern.as_bytes());
    }

    let mut posix = Re2Profile::default();
    posix.options.posix_syntax = true;
    let record = parse(ParseRequest::re2(
        b"abc".to_vec(),
        CompatibilityProfile::Re2(posix),
    ))
    .expect("direct POSIX parser accepts a literal");
    let CanonicalPattern::Re2(parsed) = record.pattern else {
        panic!("POSIX syntax must retain a direct AST")
    };
    assert_eq!(
        parsed.ast.options.syntax,
        fre_syntax::re2_syntax::SyntaxMode::Posix
    );
    assert_eq!(record.summary.literal_bytes, 3);
}

#[test]
fn re2_parser_limits_map_to_profile_aware_admission_errors() {
    let request = ParseRequest::re2(b"(a)".to_vec(), CompatibilityProfile::re2()).with_admission(
        AdmissionPolicy::Quota(QuotaBounded {
            syntax: SyntaxQuotas {
                max_hir_nodes: 1,
                ..SyntaxQuotas::default()
            },
        }),
    );
    let error = parse(request).expect_err("capture and child exceed one AST node");
    assert!(matches!(
        error.category,
        ErrorCategory::FreResourceLimit {
            resource: ResourceKind::HirNodes,
            limit: 1,
            observed: 2,
        }
    ));
}

#[test]
fn re2_surface_inventory_is_complete_unique_and_honest() {
    let inventory = re2_surface_inventory();
    let surfaces: BTreeSet<_> = inventory.iter().map(|item| item.surface).collect();
    assert_eq!(surfaces.len(), inventory.len());
    assert_eq!(inventory.len(), 10);
    assert!(inventory.iter().any(|item| {
        item.surface == Re2Surface::LiteralMode && item.status == Re2CapabilityStatus::Implemented
    }));
    assert!(inventory.iter().any(|item| {
        item.surface == Re2Surface::PerlSyntaxParser
            && item.status == Re2CapabilityStatus::OracleCheckedSlice
    }));
    assert!(inventory.iter().any(|item| {
        item.surface == Re2Surface::CountedRepeatPreflight
            && item.status == Re2CapabilityStatus::OracleCheckedSlice
    }));
}

#[test]
fn error_categories_do_not_depend_on_message_parsing() {
    let syntax = parse(ParseRequest::rust("(", CompatibilityProfile::rust_text()))
        .expect_err("unclosed group is invalid");
    assert_eq!(syntax.category, ErrorCategory::UpstreamRustSyntax);
    assert!(!syntax.message.is_empty());

    let mut invalid = RustProfile::default();
    invalid.options.line_terminator = 0xFF;
    let config = parse(ParseRequest::rust(
        ".",
        CompatibilityProfile::RustText(invalid),
    ))
    .expect_err("Unicode dot rejects a non-ASCII byte line terminator");
    assert_eq!(config.category, ErrorCategory::UpstreamRustSyntax);

    let unstamped = RustProfile {
        unicode: UnicodeVersion {
            major: 15,
            minor: 0,
            patch: 0,
        },
        ..RustProfile::default()
    };
    let stamp = parse(ParseRequest::rust(
        ".",
        CompatibilityProfile::RustText(unstamped),
    ))
    .expect_err("an unimplemented version stamp cannot borrow current semantics");
    assert_eq!(stamp.category, ErrorCategory::InvalidConfiguration);

    let mut mismatched_receipt = RustProfile::rebar_1_12_4();
    mismatched_receipt.regex.checksum = "mismatched";
    let stamp = parse(ParseRequest::rust(
        ".",
        CompatibilityProfile::RustBytes(mismatched_receipt),
    ))
    .expect_err("a mismatched component receipt cannot borrow current semantics");
    assert_eq!(stamp.category, ErrorCategory::InvalidConfiguration);
}
