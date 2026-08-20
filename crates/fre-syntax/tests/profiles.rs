use std::collections::{BTreeSet, HashSet};

use fre_syntax::{
    AdmissionPolicy, AdmissionStatus, CanonicalPattern, CompatibilityProfile, ErrorCategory,
    PackageIdentity, ParseRequest, QuotaBounded, Re2CapabilityStatus, Re2Encoding, Re2Options,
    Re2Profile, Re2Surface, ResourceKind, RustAstOptions, RustConstructor, RustMatchKind,
    RustProfile, RustUnicodeFeatures, SafetyEnvelope, StrictAdmission, SyntaxQuotas,
    UnicodeVersion, UpstreamRevision, parse, parse_rust_ast, parse_rust_ast_with_options,
    re2_surface_inventory,
};

const GENCAT_ALIASES: &[&str] = include!("../src/unicode_gencat_aliases.in");
const SCRIPT_ALIASES: &[&str] = include!("../src/unicode_script_aliases.in");
const SEGMENT_ALIASES: &[(&[&str], &[&str])] = include!("../src/unicode_segment_aliases.in");

#[test]
fn syntax_manifest_has_no_shadow_regex_automata_dependency() {
    const MANIFEST: &str = include_str!("../Cargo.toml");
    assert!(
        !MANIFEST.lines().any(|line| {
            line.split_once('=')
                .is_some_and(|(name, _)| name.trim() == "regex-automata")
        }),
        "fre-syntax must not construct a shadow regex-automata meta matcher"
    );
}

fn re2_literal_profile() -> CompatibilityProfile {
    let mut profile = Re2Profile::default();
    profile.options.literal = true;
    CompatibilityProfile::Re2(profile)
}

fn parse_rust_text_set_patterns(
    patterns: &[&str],
    profile: RustProfile,
) -> Result<(), (usize, fre_syntax::ParseError)> {
    for (index, pattern) in patterns.iter().enumerate() {
        parse(ParseRequest::rust(
            *pattern,
            CompatibilityProfile::RustText(profile.clone()),
        ))
        .map_err(|error| (index, error))?;
    }
    Ok(())
}

#[test]
fn pinned_defaults_are_explicit() {
    let RustProfile {
        regex,
        regex_automata,
        regex_syntax,
        unicode,
        unicode_features,
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
    assert_eq!(unicode_features, RustUnicodeFeatures::ALL);
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
            admission_status: AdmissionStatus::StrictChecked,
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
fn rust_ast_parse_reserves_work_before_parser_execution() {
    let profile = CompatibilityProfile::RustText(RustProfile::regex_1_12_4());
    let pattern = r"\\\.\+\*\?\(\)\|\[\]\{\}\^\$\#\&\-\~";
    let baseline = parse_rust_ast(ParseRequest::rust(pattern, profile.clone()))
        .expect("strict AST conformance parse");
    assert_eq!(baseline.reserved_ast_nodes, 74);
    assert_eq!(baseline.reserved_max_nesting, 37);
    assert_eq!(baseline.reserved_parser_stack, 37);
    assert_eq!(baseline.reserved_parse_work, 18_944);

    let mut quotas = SyntaxQuotas {
        max_hir_nodes: baseline.reserved_ast_nodes,
        max_nesting: baseline.reserved_max_nesting,
        max_traversal_stack: baseline.reserved_parser_stack,
        max_parse_work: baseline.reserved_parse_work,
        ..SyntaxQuotas::default()
    };
    parse_rust_ast(
        ParseRequest::rust(pattern, profile.clone())
            .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
    )
    .expect("exact prospective AST limits must pass");

    quotas.max_parse_work = baseline.reserved_parse_work - 1;
    let error = parse_rust_ast(
        ParseRequest::rust(pattern, profile.clone())
            .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
    )
    .expect_err("one below prospective AST work must fail before parsing");
    assert_eq!(
        error.category,
        ErrorCategory::FreResourceLimit {
            resource: ResourceKind::ParseWork,
            limit: baseline.reserved_parse_work - 1,
            observed: baseline.reserved_parse_work,
        }
    );

    quotas.max_parse_work = baseline.reserved_parse_work;
    quotas.max_hir_nodes = baseline.reserved_ast_nodes - 1;
    let error = parse_rust_ast(
        ParseRequest::rust(pattern, profile)
            .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
    )
    .expect_err("one below prospective AST nodes must fail before parsing");
    assert_eq!(
        error.category,
        ErrorCategory::FreResourceLimit {
            resource: ResourceKind::HirNodes,
            limit: baseline.reserved_ast_nodes - 1,
            observed: baseline.reserved_ast_nodes,
        }
    );
}

#[test]
fn rust_ast_empty_min_range_is_explicit_and_resource_bounded() {
    use regex_syntax::ast::{Ast, RepetitionKind, RepetitionRange};

    let profile = CompatibilityProfile::RustText(RustProfile::regex_1_12_4());
    let pattern = r"a{,9}";
    let default_error = parse_rust_ast(ParseRequest::rust(pattern, profile.clone()))
        .expect_err("default AST parsing rejects an omitted lower bound");
    assert_eq!(default_error.category, ErrorCategory::UpstreamRustSyntax);

    let ast_options = RustAstOptions {
        empty_min_range: true,
    };
    let baseline =
        parse_rust_ast_with_options(ParseRequest::rust(pattern, profile.clone()), ast_options)
            .expect("explicit AST-only option accepts an omitted lower bound");
    assert_eq!(baseline.ast_options, ast_options);
    assert!(matches!(
        baseline.ast,
        Ast::Repetition(ref repetition)
            if repetition.op.kind
                == RepetitionKind::Range(RepetitionRange::Bounded(0, 9))
    ));

    let same_ast = parse_rust_ast_with_options(
        ParseRequest::rust("a{5}", profile.clone()),
        RustAstOptions::default(),
    )
    .expect("default identity parses an ordinary counted repetition");
    let distinct_identity =
        parse_rust_ast_with_options(ParseRequest::rust("a{5}", profile.clone()), ast_options)
            .expect("AST-only identity also parses an ordinary counted repetition");
    assert_eq!(same_ast.ast, distinct_identity.ast);
    assert_ne!(same_ast, distinct_identity);

    let mut quotas = SyntaxQuotas {
        max_hir_nodes: baseline.reserved_ast_nodes,
        max_nesting: baseline.reserved_max_nesting,
        max_traversal_stack: baseline.reserved_parser_stack,
        max_parse_work: baseline.reserved_parse_work,
        ..SyntaxQuotas::default()
    };
    parse_rust_ast_with_options(
        ParseRequest::rust(pattern, profile.clone())
            .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
        ast_options,
    )
    .expect("exact prospective AST limits pass with AST-only options");

    quotas.max_parse_work = baseline.reserved_parse_work - 1;
    let error = parse_rust_ast_with_options(
        ParseRequest::rust(pattern, profile)
            .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
        ast_options,
    )
    .expect_err("one below prospective AST work fails before option-enabled parsing");
    assert_eq!(
        error.category,
        ErrorCategory::FreResourceLimit {
            resource: ResourceKind::ParseWork,
            limit: baseline.reserved_parse_work - 1,
            observed: baseline.reserved_parse_work,
        }
    );
}

#[test]
fn rust_ast_retains_exact_comment_side_channel() {
    let pattern = "(?x)\n# first\nfoo # second\nbar";
    let profile = CompatibilityProfile::RustText(RustProfile::regex_1_12_4());
    let expected = regex_syntax::ast::parse::Parser::new()
        .parse_with_comments(pattern)
        .expect("pinned parser accepts comment probe");
    let observed = parse_rust_ast(ParseRequest::rust(pattern, profile))
        .expect("FRE AST adapter accepts comment probe");

    assert_eq!(observed.ast, expected.ast);
    assert_eq!(observed.comments, expected.comments);
    assert_eq!(observed.comments.len(), 2);
    assert_eq!(observed.comments[0].comment, " first");
    assert_eq!(observed.comments[1].comment, " second");

    let plain = parse_rust_ast(ParseRequest::rust(
        "foo#bar",
        CompatibilityProfile::RustText(RustProfile::regex_1_12_4()),
    ))
    .expect("a hash is literal when whitespace mode is disabled");
    assert!(plain.comments.is_empty());
}

#[test]
fn rust_ast_node_reservation_covers_synthetic_empty_alternation_nodes() {
    use regex_syntax::ast::Ast;

    let profile = CompatibilityProfile::RustText(RustProfile::regex_1_12_4());
    for (pattern, reserved_nodes) in [("", 2), ("|", 4), ("||", 6), ("|a", 6), ("a|", 6)] {
        let baseline = parse_rust_ast(ParseRequest::rust(pattern, profile.clone()))
            .expect("empty alternation must parse under the prospective reservation");
        assert_eq!(baseline.reserved_ast_nodes, reserved_nodes);
        if pattern == "|" {
            let Ast::Alternation(alternation) = &baseline.ast else {
                panic!("sole alternation must produce an Alternation AST");
            };
            assert_eq!(alternation.asts.len(), 2);
            assert!(
                alternation
                    .asts
                    .iter()
                    .all(|ast| matches!(ast, Ast::Empty(_)))
            );
        }

        let mut quotas = SyntaxQuotas {
            max_hir_nodes: reserved_nodes,
            max_nesting: baseline.reserved_max_nesting,
            max_traversal_stack: baseline.reserved_parser_stack,
            max_parse_work: baseline.reserved_parse_work,
            ..SyntaxQuotas::default()
        };
        parse_rust_ast(
            ParseRequest::rust(pattern, profile.clone())
                .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
        )
        .expect("exact prospective AST-node limit must pass");

        quotas.max_hir_nodes = reserved_nodes - 1;
        let error = parse_rust_ast(
            ParseRequest::rust(pattern, profile.clone())
                .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
        )
        .expect_err("one below prospective AST-node limit must fail before parsing");
        assert_eq!(
            error.category,
            ErrorCategory::FreResourceLimit {
                resource: ResourceKind::HirNodes,
                limit: reserved_nodes - 1,
                observed: reserved_nodes,
            }
        );
    }
}

#[test]
fn partial_unicode_feature_profiles_enforce_positive_and_negative_availability() {
    let witnesses = [
        r"\p{Age:6.0}",
        r"\p{Alphabetic}",
        r"(?i:\u{03B4})",
        r"\pL",
        r"\w",
        r"\p{Greek}",
        r"\p{Grapheme_Cluster_Break=Extend}",
    ];

    let mut none = RustProfile::regex_1_12_4();
    none.unicode_features = RustUnicodeFeatures::NONE;
    parse(ParseRequest::rust(
        "ascii",
        CompatibilityProfile::RustText(none.clone()),
    ))
    .expect("profiles with no Unicode tables still accept table-free syntax");
    for pattern in witnesses {
        let error = parse(ParseRequest::rust(
            pattern,
            CompatibilityProfile::RustText(none.clone()),
        ))
        .expect_err("a no-table profile must reject every Unicode data family");
        assert_eq!(
            error.category,
            ErrorCategory::UpstreamRustSyntax,
            "{pattern}"
        );
    }

    let full = RustProfile::regex_1_12_4();
    for pattern in witnesses {
        parse(ParseRequest::rust(
            pattern,
            CompatibilityProfile::RustText(full.clone()),
        ))
        .unwrap_or_else(|error| panic!("all-table profile rejected {pattern}: {error:?}"));
    }
}

#[test]
fn unicode_age_profile_accepts_only_age_named_value_properties() {
    let mut age = RustProfile::regex_1_12_4();
    age.unicode_features = RustUnicodeFeatures::AGE;
    for pattern in [
        r"\p{Age:6.0}",
        r"\P{age=V6_0}",
        r"\p{A_g-e = 6.0}",
        r"\p{IsAge=6.0}",
        r"\p{A💥ge=6.0}",
    ] {
        parse(ParseRequest::rust(
            pattern,
            CompatibilityProfile::RustText(age.clone()),
        ))
        .unwrap_or_else(|error| panic!("unicode-age alias {pattern}: {error:?}"));
    }
    for pattern in [
        r"\p{Age}",
        r"\p{Ageish=6.0}",
        r"\p{Age=definitely-invalid}",
        r"\p{Age=Unassigned}",
        r"\p{Alphabetic}",
        r"\p{gc=Letter}",
        r"\p{sc=Greek}",
        r"\p{gcb=Extend}",
        r"\w",
        r"(?i:\p{Age=6.0})",
    ] {
        parse(ParseRequest::rust(
            pattern,
            CompatibilityProfile::RustText(age.clone()),
        ))
        .expect_err("unicode-age must not borrow another data family");
    }
}

#[test]
fn unicode_bool_profile_accepts_only_binary_property_data() {
    let mut boolean = RustProfile::regex_1_12_4();
    boolean.unicode_features = RustUnicodeFeatures::BOOL;
    for pattern in [
        r"\p{Alphabetic}",
        r"\P{alpha}",
        r"\p{Is_A-lphabetic}",
        r"\p{A💥lpha}",
        r"\p{Other_Default_Ignorable_Code_Point}",
        r"[\p{Uppercase}&&\p{Alphabetic}]",
        r"\s",
        r"\S",
    ] {
        parse(ParseRequest::rust(
            pattern,
            CompatibilityProfile::RustText(boolean.clone()),
        ))
        .unwrap_or_else(|error| panic!("unicode-bool alias {pattern}: {error:?}"));
    }
    for pattern in [
        r"\p{Age=6.0}",
        r"(?i:\p{Alphabetic})",
        r"(?i:[\p{Alphabetic}])",
        r"(?i:[\s])",
        r"\pL",
        r"\d",
        r"\w",
        r"\b",
        r"\p{Greek}",
        r"\p{Grapheme_Cluster_Break=Extend}",
        r"\p{Alphabetic=Yes}",
        r"\p{Alphabeticish}",
        r"\p{InCB}",
        r"\p{cf}",
        r"\p{sc}",
        r"\p{lc}",
    ] {
        parse(ParseRequest::rust(
            pattern,
            CompatibilityProfile::RustText(boolean.clone()),
        ))
        .expect_err("unicode-bool must not borrow another data family");
    }
}

#[test]
fn unicode_case_profile_accepts_only_unicode_simple_case_folding() {
    let mut case = RustProfile::regex_1_12_4();
    case.unicode_features = RustUnicodeFeatures::CASE;
    let case_profile = CompatibilityProfile::RustText(case.clone());
    let full_profile = CompatibilityProfile::rust_text();

    // These cover literals with and without mappings, multi-member simple
    // folds, bracket/range folding, negation and all flag-scope transitions.
    for pattern in [
        r"(?i:a)",
        r"(?i:\u{03B4})",
        r"(?i:k)",
        r"(?i:\u{212A})",
        r"(?i:s)",
        r"(?i:\u{017F})",
        r"(?i:\u{03A3})",
        r"(?i:\u{03C2})",
        r"(?i:\u{1F600})",
        r"(?i:[a-z])",
        r"(?i:[^\u{03B4}])",
        r"(?i:[a-z&&[^q]])",
        r"(?i)(?-u:a)(?u:\u{03B4})",
        r"(?i:(?-i:\u{03B4})a)",
    ] {
        let partial = parse(ParseRequest::rust(pattern, case_profile.clone()))
            .unwrap_or_else(|error| panic!("unicode-case rejected {pattern}: {error:?}"));
        let full = parse(ParseRequest::rust(pattern, full_profile.clone()))
            .unwrap_or_else(|error| panic!("all-table profile rejected {pattern}: {error:?}"));
        let CanonicalPattern::Rust(partial) = partial.pattern else {
            panic!("Rust request returned another syntax family")
        };
        let CanonicalPattern::Rust(full) = full.pattern else {
            panic!("Rust request returned another syntax family")
        };
        assert_eq!(partial.hir, full.hir, "case-folded HIR for {pattern}");
    }

    // Case folding has no property aliases of its own. Every independently
    // feature-gated Unicode family remains unavailable, including when `i`
    // would otherwise ask to case-fold the resulting class.
    for pattern in [
        r"\p{Age=6.0}",
        r"\p{Alphabetic}",
        r"\pL",
        r"\w",
        r"\b",
        r"\p{Greek}",
        r"\p{Grapheme_Cluster_Break=Extend}",
        r"(?i:\p{Age=6.0})",
        r"(?i:[\w])",
    ] {
        let error = parse(ParseRequest::rust(pattern, case_profile.clone()))
            .expect_err("unicode-case must not borrow another data family");
        assert_eq!(
            error.category,
            ErrorCategory::UpstreamRustSyntax,
            "{pattern}"
        );
    }

    for pattern in [r"(?i)", r"(?i:.)", r"(?i:^$)", r"(?i-u:a)", r"(?-u:\w)"] {
        parse(ParseRequest::rust(pattern, case_profile.clone()))
            .unwrap_or_else(|error| panic!("table-free case scope {pattern}: {error:?}"));
    }

    let mut builder_case = case.clone();
    builder_case.options.case_insensitive = true;
    let mut builder_full = RustProfile::regex_1_12_4();
    builder_full.options.case_insensitive = true;
    for pattern in ["a", "Σ", "[a-z]"] {
        let partial = parse(ParseRequest::rust(
            pattern,
            CompatibilityProfile::RustText(builder_case.clone()),
        ))
        .expect("unicode-case builder option parses");
        let full = parse(ParseRequest::rust(
            pattern,
            CompatibilityProfile::RustText(builder_full.clone()),
        ))
        .expect("all-table builder option parses");
        let (CanonicalPattern::Rust(partial), CanonicalPattern::Rust(full)) =
            (partial.pattern, full.pattern)
        else {
            panic!("Rust request returned another syntax family")
        };
        assert_eq!(
            partial.hir, full.hir,
            "builder case-folded HIR for {pattern}"
        );
    }

    let mut case_set = RustProfile::regex_set_1_12_4();
    case_set.unicode_features = RustUnicodeFeatures::CASE;
    parse_rust_text_set_patterns(&[r"(?i:a)", r"(?i:\u{03B4})"], case_set.clone())
        .expect("unicode-case set patterns parse");
    let (index, error) =
        parse_rust_text_set_patterns(&[r"(?i:a)", r"\p{Alphabetic}"], case_set)
            .expect_err("unicode-case set cannot borrow unicode-bool");
    assert_eq!(index, 1);
    assert_eq!(error.category, ErrorCategory::UpstreamRustSyntax);
}

#[test]
fn unicode_gencat_profile_accepts_only_materialized_general_categories() {
    assert_eq!(GENCAT_ALIASES.len(), 81);
    assert!(GENCAT_ALIASES.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(
        GENCAT_ALIASES.iter().map(|alias| alias.len()).max(),
        Some(20)
    );

    let mut gencat = RustProfile::regex_1_12_4();
    gencat.unicode_features = RustUnicodeFeatures::GENCAT;
    let gencat_profile = CompatibilityProfile::RustText(gencat.clone());
    let full_profile = CompatibilityProfile::rust_text();

    // Authenticate every direct normalized alias against the all-table HIR.
    // This includes the cf/sc/lc property-name collisions and the synthetic
    // Any/ASCII/Assigned classes.
    for alias in GENCAT_ALIASES {
        let pattern = format!(r"\p{{{alias}}}");
        let partial = parse(ParseRequest::rust(&pattern, gencat_profile.clone()))
            .unwrap_or_else(|error| panic!("unicode-gencat alias {pattern}: {error:?}"));
        let full = parse(ParseRequest::rust(&pattern, full_profile.clone()))
            .unwrap_or_else(|error| panic!("all-table alias {pattern}: {error:?}"));
        let (CanonicalPattern::Rust(partial), CanonicalPattern::Rust(full)) =
            (partial.pattern, full.pattern)
        else {
            panic!("Rust request returned another syntax family")
        };
        assert_eq!(partial.hir, full.hir, "general-category HIR for {pattern}");
    }

    for pattern in [
        r"\pL",
        r"\pz",
        r"\P{Separator}",
        r"\p{se PaRa ToR}",
        r"\p{IsCf}",
        r"\p{gc:Lu}",
        r"\p{General_Category=Uppercase_Letter}",
        r"\p{Is_G-C=Letter}",
        r"\P{gc!=Separator}",
        r"\p{Any}",
        r"\P{Any}",
        r"\p{Assigned}",
        r"\p{ASCII}",
        r"\d",
        r"\D",
        r"(?i:\d)",
        r"[\pL&&\P{Lu}]",
        r"[\d--\p{ASCII}]",
    ] {
        let partial = parse(ParseRequest::rust(pattern, gencat_profile.clone()))
            .unwrap_or_else(|error| panic!("unicode-gencat rejected {pattern}: {error:?}"));
        let full = parse(ParseRequest::rust(pattern, full_profile.clone()))
            .unwrap_or_else(|error| panic!("all-table profile rejected {pattern}: {error:?}"));
        let (CanonicalPattern::Rust(partial), CanonicalPattern::Rust(full)) =
            (partial.pattern, full.pattern)
        else {
            panic!("Rust request returned another syntax family")
        };
        assert_eq!(partial.hir, full.hir, "general-category HIR for {pattern}");
    }

    for pattern in [
        r"\p{Age=6.0}",
        r"\p{Alphabetic}",
        r"(?i:\pL)",
        r"\s",
        r"\w",
        r"\b",
        r"\p{Greek}",
        r"\p{Grapheme_Cluster_Break=Extend}",
        r"\p{cs}",
        r"\p{Surrogate}",
        r"\p{IsC}",
        r"\p{gc}",
        r"\p{gc=definitely-invalid}",
        r"\p{Script=Letter}",
    ] {
        let error = parse(ParseRequest::rust(pattern, gencat_profile.clone()))
            .expect_err("unicode-gencat must not borrow another or unmaterialized family");
        assert_eq!(
            error.category,
            ErrorCategory::UpstreamRustSyntax,
            "{pattern}"
        );
    }

    let mut gencat_set = RustProfile::regex_set_1_12_4();
    gencat_set.unicode_features = RustUnicodeFeatures::GENCAT;
    parse_rust_text_set_patterns(&[r"\pL", r"\p{gc=Nd}", r"\d"], gencat_set.clone())
        .expect("unicode-gencat set patterns parse");
    let (index, error) =
        parse_rust_text_set_patterns(&[r"\pL", r"\p{Alphabetic}"], gencat_set)
            .expect_err("unicode-gencat set cannot borrow unicode-bool");
    assert_eq!(index, 1);
    assert_eq!(error.category, ErrorCategory::UpstreamRustSyntax);
}

#[test]
fn unicode_perl_profile_accepts_only_singleton_perl_data() {
    let mut perl = RustProfile::regex_1_12_4();
    perl.unicode_features = RustUnicodeFeatures::PERL;
    let perl_profile = CompatibilityProfile::RustText(perl.clone());
    let full_profile = CompatibilityProfile::rust_text();

    // The singleton feature owns the three direct tables, every Unicode
    // boundary look kind and only the White_Space/Decimal_Number named-query
    // aliases that regex-syntax routes back to those same tables.
    for pattern in [
        r"\d",
        r"\D",
        r"\s",
        r"\S",
        r"\w",
        r"\W",
        r"\b",
        r"\B",
        r"\b{start}",
        r"\b{end}",
        r"\b{start-half}",
        r"\b{end-half}",
        r"\<",
        r"\>",
        r"\p{White_Space}",
        r"\p{IsWhite_Space}",
        r"\p{wspace}",
        r"\p{Nd}",
        r"\p{IsDigit}",
        r"\p{gc=Nd}",
        r"\p{Is_G-C=D_e-cimal Number}",
        r"[\w&&[\s&&\d]]",
        r"(?i:\d\s\w)",
    ] {
        let partial = parse(ParseRequest::rust(pattern, perl_profile.clone()))
            .unwrap_or_else(|error| panic!("unicode-perl rejected {pattern}: {error:?}"));
        let full = parse(ParseRequest::rust(pattern, full_profile.clone()))
            .unwrap_or_else(|error| panic!("all-table profile rejected {pattern}: {error:?}"));
        let (CanonicalPattern::Rust(partial), CanonicalPattern::Rust(full)) =
            (partial.pattern, full.pattern)
        else {
            panic!("Rust request returned another syntax family")
        };
        assert_eq!(partial.hir, full.hir, "unicode-perl HIR for {pattern}");
    }

    for pattern in [
        r"\p{Age=6.0}",
        r"\p{Alphabetic}",
        r"(?i:a)",
        r"\pL",
        r"\p{Letter}",
        r"\p{gc=Number}",
        r"\p{White_Space=Yes}",
        r"(?i:\p{Nd})",
        r"(?i:[\w])",
        r"\p{Greek}",
        r"\p{Grapheme_Cluster_Break=Extend}",
    ] {
        let error = parse(ParseRequest::rust(pattern, perl_profile.clone()))
            .expect_err("unicode-perl must not borrow another Unicode family");
        assert_eq!(
            error.category,
            ErrorCategory::UpstreamRustSyntax,
            "{pattern}"
        );
    }

    let mut perl_set = RustProfile::regex_set_1_12_4();
    perl_set.unicode_features = RustUnicodeFeatures::PERL;
    parse_rust_text_set_patterns(&[r"\b\w+\b", r"\p{gc=Nd}+", r"\s+"], perl_set.clone())
        .expect("unicode-perl set patterns parse");
    let (index, error) =
        parse_rust_text_set_patterns(&[r"\w+", r"\p{Alphabetic}"], perl_set)
            .expect_err("unicode-perl set cannot borrow unicode-bool");
    assert_eq!(index, 1);
    assert_eq!(error.category, ErrorCategory::UpstreamRustSyntax);
}

#[test]
fn unicode_script_profile_accepts_only_singleton_script_data() {
    assert_eq!(SCRIPT_ALIASES.len(), 338);
    assert!(SCRIPT_ALIASES.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(
        SCRIPT_ALIASES.iter().map(|alias| alias.len()).max(),
        Some(21)
    );

    let mut script = RustProfile::regex_1_12_4();
    script.unicode_features = RustUnicodeFeatures::SCRIPT;
    let script_profile = CompatibilityProfile::RustText(script.clone());
    let full_profile = CompatibilityProfile::rust_text();

    for pattern in [
        r"\p{Greek}",
        r"\p{IsGreek}",
        r"\p{grek}",
        r"\P{Common}",
        r"\p{Script=Greek}",
        r"\p{Is_S-c r i p t=G_r-e e k}",
        r"\p{sc=Grek}",
        r"\p{Script_Extensions=Hiragana}",
        r"\p{Is_S-c x=H_i-r a}",
        r"\p{scx=Kana}",
        r"[\p{sc=Greek}&&[\p{scx=Common}--\p{Latin}]]",
    ] {
        let partial = parse(ParseRequest::rust(pattern, script_profile.clone()))
            .unwrap_or_else(|error| panic!("unicode-script rejected {pattern}: {error:?}"));
        let full = parse(ParseRequest::rust(pattern, full_profile.clone()))
            .unwrap_or_else(|error| panic!("all-table profile rejected {pattern}: {error:?}"));
        let (CanonicalPattern::Rust(partial), CanonicalPattern::Rust(full)) =
            (partial.pattern, full.pattern)
        else {
            panic!("Rust request returned another syntax family")
        };
        assert_eq!(partial.hir, full.hir, "unicode-script HIR for {pattern}");
    }

    for pattern in [
        r"\p{Age=6.0}",
        r"\p{Alphabetic}",
        r"(?i:a)",
        r"\pL",
        r"\p{gc=Letter}",
        r"\d",
        r"\s",
        r"\w",
        r"\b",
        r"\p{Grapheme_Cluster_Break=Extend}",
        r"\p{sc}",
        r"\p{Script}",
        r"\p{Script=Letter}",
        r"\p{scx=definitely-invalid}",
        r"(?i:\p{Greek})",
    ] {
        let error = parse(ParseRequest::rust(pattern, script_profile.clone()))
            .expect_err("unicode-script must not borrow another or invalid Unicode family");
        assert_eq!(
            error.category,
            ErrorCategory::UpstreamRustSyntax,
            "{pattern}"
        );
    }

    let mut script_set = RustProfile::regex_set_1_12_4();
    script_set.unicode_features = RustUnicodeFeatures::SCRIPT;
    parse_rust_text_set_patterns(&[r"\p{Greek}+", r"\p{scx=Latin}+"], script_set.clone())
        .expect("unicode-script set patterns parse");
    let (index, error) =
        parse_rust_text_set_patterns(&[r"\p{Greek}+", r"\p{gcb=Extend}"], script_set)
            .expect_err("unicode-script set cannot borrow unicode-segment");
    assert_eq!(index, 1);
    assert_eq!(error.category, ErrorCategory::UpstreamRustSyntax);
}

#[test]
fn unicode_segment_alias_inventory_is_exact_and_sorted() {
    assert_eq!(SEGMENT_ALIASES.len(), 3);
    assert_eq!(SEGMENT_ALIASES[0].0, ["gcb", "graphemeclusterbreak"]);
    assert_eq!(SEGMENT_ALIASES[1].0, ["sb", "sentencebreak"]);
    assert_eq!(SEGMENT_ALIASES[2].0, ["wb", "wordbreak"]);
    assert_eq!(SEGMENT_ALIASES[0].1.len(), 18);
    assert_eq!(SEGMENT_ALIASES[1].1.len(), 25);
    assert_eq!(SEGMENT_ALIASES[2].1.len(), 31);
    for &(names, values) in SEGMENT_ALIASES {
        assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(values.windows(2).all(|pair| pair[0] < pair[1]));
    }
    assert_eq!(
        SEGMENT_ALIASES
            .iter()
            .flat_map(|(names, values)| names.iter().chain(values.iter()))
            .map(|alias| alias.len())
            .max(),
        Some(20)
    );
}

#[test]
fn unicode_segment_profile_accepts_only_singleton_segmentation_data() {
    let mut segment = RustProfile::regex_1_12_4();
    segment.unicode_features = RustUnicodeFeatures::SEGMENT;
    let segment_profile = CompatibilityProfile::RustText(segment.clone());
    let full_profile = CompatibilityProfile::rust_text();

    for pattern in [
        r"\p{Grapheme_Cluster_Break=Extend}",
        r"\p{gcb=EX}",
        r"\P{Is_G-c b=Regional_Indicator}",
        r"\p{Sentence_Break=Lower}",
        r"\p{sb=AT}",
        r"\p{Word_Break=ALetter}",
        r"\p{wb=ExtendNumLet}",
        r"[\p{gcb=Extend}&&[\p{sb=Lower}--\p{wb=ALetter}]]",
    ] {
        let partial = parse(ParseRequest::rust(pattern, segment_profile.clone()))
            .unwrap_or_else(|error| panic!("unicode-segment rejected {pattern}: {error:?}"));
        let full = parse(ParseRequest::rust(pattern, full_profile.clone()))
            .unwrap_or_else(|error| panic!("all-table profile rejected {pattern}: {error:?}"));
        let (CanonicalPattern::Rust(partial), CanonicalPattern::Rust(full)) =
            (partial.pattern, full.pattern)
        else {
            panic!("Rust request returned another syntax family")
        };
        assert_eq!(partial.hir, full.hir, "unicode-segment HIR for {pattern}");
    }

    for &(names, values) in SEGMENT_ALIASES {
        for &name in names {
            for &value in values {
                let pattern = format!(r"\p{{{name}={value}}}");
                let partial = parse(ParseRequest::rust(&pattern, segment_profile.clone()))
                    .unwrap_or_else(|error| {
                        panic!("unicode-segment rejected {pattern}: {error:?}")
                    });
                let full = parse(ParseRequest::rust(&pattern, full_profile.clone()))
                    .unwrap_or_else(|error| {
                        panic!("all-table profile rejected {pattern}: {error:?}")
                    });
                let (CanonicalPattern::Rust(partial), CanonicalPattern::Rust(full)) =
                    (partial.pattern, full.pattern)
                else {
                    panic!("Rust request returned another syntax family")
                };
                assert_eq!(partial.hir, full.hir, "unicode-segment HIR for {pattern}");
            }
        }
    }

    for pattern in [
        r"\p{Age=6.0}",
        r"\p{Alphabetic}",
        r"(?i:a)",
        r"\pL",
        r"\d",
        r"\s",
        r"\w",
        r"\b",
        r"\p{Greek}",
        r"\p{Extend}",
        r"\p{gcb}",
        r"\p{gcb=Other}",
        r"\p{gcb=E_Base}",
        r"\p{sb=Other}",
        r"\p{wb=E_Base}",
        r"\p{gcb=definitely-invalid}",
        r"(?i:\p{gcb=Extend})",
    ] {
        let error = parse(ParseRequest::rust(pattern, segment_profile.clone()))
            .expect_err("unicode-segment must not borrow another or invalid Unicode family");
        assert_eq!(
            error.category,
            ErrorCategory::UpstreamRustSyntax,
            "{pattern}"
        );
    }

    let mut segment_set = RustProfile::regex_set_1_12_4();
    segment_set.unicode_features = RustUnicodeFeatures::SEGMENT;
    parse_rust_text_set_patterns(
        &[r"\p{gcb=Extend}+", r"\p{wb=ALetter}+"],
        segment_set.clone(),
    )
    .expect("unicode-segment set patterns parse");
    let (index, error) =
        parse_rust_text_set_patterns(&[r"\p{gcb=Extend}+", r"\p{Greek}"], segment_set)
            .expect_err("unicode-segment set cannot borrow unicode-script");
    assert_eq!(index, 1);
    assert_eq!(error.category, ErrorCategory::UpstreamRustSyntax);
}

#[test]
fn unicode_feature_availability_participates_in_cache_and_rebar_identity() {
    let mut none = RustProfile::regex_1_12_4();
    none.unicode_features = RustUnicodeFeatures::NONE;
    let partial = parse(ParseRequest::rust(
        "ascii",
        CompatibilityProfile::RustText(none),
    ))
    .expect("table-free syntax under partial profile");
    let full = parse(ParseRequest::rust(
        "ascii",
        CompatibilityProfile::rust_text(),
    ))
    .expect("table-free syntax under full profile");
    assert_ne!(partial.key, full.key);

    let mut age = RustProfile::regex_1_12_4();
    age.unicode_features = RustUnicodeFeatures::AGE;
    let age = parse(ParseRequest::rust(
        "ascii",
        CompatibilityProfile::RustText(age),
    ))
    .expect("table-free syntax under age profile");
    assert_ne!(partial.key, age.key);
    assert_ne!(age.key, full.key);

    let mut boolean = RustProfile::regex_1_12_4();
    boolean.unicode_features = RustUnicodeFeatures::BOOL;
    let boolean = parse(ParseRequest::rust(
        "ascii",
        CompatibilityProfile::RustText(boolean),
    ))
    .expect("table-free syntax under bool profile");
    assert_ne!(partial.key, boolean.key);
    assert_ne!(age.key, boolean.key);
    assert_ne!(boolean.key, full.key);

    let mut case = RustProfile::regex_1_12_4();
    case.unicode_features = RustUnicodeFeatures::CASE;
    let case = parse(ParseRequest::rust(
        "ascii",
        CompatibilityProfile::RustText(case),
    ))
    .expect("table-free syntax under case profile");
    assert_ne!(partial.key, case.key);
    assert_ne!(age.key, case.key);
    assert_ne!(boolean.key, case.key);
    assert_ne!(case.key, full.key);

    let mut gencat = RustProfile::regex_1_12_4();
    gencat.unicode_features = RustUnicodeFeatures::GENCAT;
    let gencat = parse(ParseRequest::rust(
        "ascii",
        CompatibilityProfile::RustText(gencat),
    ))
    .expect("table-free syntax under gencat profile");
    assert_ne!(partial.key, gencat.key);
    assert_ne!(age.key, gencat.key);
    assert_ne!(boolean.key, gencat.key);
    assert_ne!(case.key, gencat.key);
    assert_ne!(gencat.key, full.key);

    let mut perl = RustProfile::regex_1_12_4();
    perl.unicode_features = RustUnicodeFeatures::PERL;
    let perl = parse(ParseRequest::rust(
        "ascii",
        CompatibilityProfile::RustText(perl),
    ))
    .expect("table-free syntax under perl profile");
    assert_ne!(partial.key, perl.key);
    assert_ne!(age.key, perl.key);
    assert_ne!(boolean.key, perl.key);
    assert_ne!(case.key, perl.key);
    assert_ne!(gencat.key, perl.key);
    assert_ne!(perl.key, full.key);

    let mut script = RustProfile::regex_1_12_4();
    script.unicode_features = RustUnicodeFeatures::SCRIPT;
    let script = parse(ParseRequest::rust(
        "ascii",
        CompatibilityProfile::RustText(script),
    ))
    .expect("table-free syntax under script profile");
    assert_ne!(partial.key, script.key);
    assert_ne!(age.key, script.key);
    assert_ne!(boolean.key, script.key);
    assert_ne!(case.key, script.key);
    assert_ne!(gencat.key, script.key);
    assert_ne!(perl.key, script.key);
    assert_ne!(script.key, full.key);

    let mut forged_rebar = RustProfile::rebar_1_12_4();
    forged_rebar.unicode_features = RustUnicodeFeatures::NONE;
    let error = parse(ParseRequest::rust(
        "ascii",
        CompatibilityProfile::RustBytes(forged_rebar),
    ))
    .expect_err("Rebar's default-feature receipt requires all Unicode tables");
    assert_eq!(error.category, ErrorCategory::InvalidConfiguration);
}

#[test]
fn unicode_segment_availability_has_distinct_cache_identity() {
    let mut segment = RustProfile::regex_1_12_4();
    segment.unicode_features = RustUnicodeFeatures::SEGMENT;
    let segment = parse(ParseRequest::rust(
        "ascii",
        CompatibilityProfile::RustText(segment),
    ))
    .expect("table-free syntax under segment profile");
    for features in [
        RustUnicodeFeatures::NONE,
        RustUnicodeFeatures::AGE,
        RustUnicodeFeatures::BOOL,
        RustUnicodeFeatures::CASE,
        RustUnicodeFeatures::GENCAT,
        RustUnicodeFeatures::PERL,
        RustUnicodeFeatures::SCRIPT,
        RustUnicodeFeatures::ALL,
    ] {
        let mut other = RustProfile::regex_1_12_4();
        other.unicode_features = features;
        let other = parse(ParseRequest::rust(
            "ascii",
            CompatibilityProfile::RustText(other),
        ))
        .expect("table-free syntax under another Unicode profile");
        assert_ne!(segment.key, other.key);
    }
}

#[test]
fn partial_unicode_profiles_cover_aliases_overlaps_nested_classes_and_sets() {
    let full = RustProfile::regex_1_12_4();
    for pattern in [
        r"[\p{Alphabetic}\s]",
        r"[\p{sc=Greek}\p{scx=Latin}]",
        r"\p{gcb=Extend}",
        r"\b\d\s\w\b",
    ] {
        parse(ParseRequest::rust(
            pattern,
            CompatibilityProfile::RustText(full.clone()),
        ))
        .unwrap_or_else(|error| panic!("all-table nested pattern {pattern}: {error:?}"));
    }

    let mut none_set = RustProfile::regex_set_1_12_4();
    none_set.unicode_features = RustUnicodeFeatures::NONE;
    let (index, error) =
        parse_rust_text_set_patterns(&["literal", r"\p{Greek}"], none_set)
            .expect_err("set parsing must enforce constituent feature availability");
    assert_eq!(index, 1);
    assert_eq!(error.category, ErrorCategory::UpstreamRustSyntax);
}

#[test]
fn partial_unicode_profiles_follow_active_unicode_and_case_flag_scope() {
    let mut none = RustProfile::regex_1_12_4();
    none.unicode_features = RustUnicodeFeatures::NONE;
    for pattern in [
        r"(?i)",
        r"(?i:.)",
        r"(?i:^$)",
        r"(?i-u:a)",
        r"(?-u:\d\s\w\b)",
    ] {
        parse(ParseRequest::rust(
            pattern,
            CompatibilityProfile::RustText(none.clone()),
        ))
        .unwrap_or_else(|error| panic!("table-free scoped pattern {pattern}: {error:?}"));
    }
    parse(ParseRequest::rust(
        r"(?i)(?-u:a)(?-i:\u{03B4})",
        CompatibilityProfile::RustText(none.clone()),
    ))
    .expect("group-local i/u changes restore in traversal order");
    parse(ParseRequest::rust(
        r"(?i:a)",
        CompatibilityProfile::RustText(none),
    ))
    .expect_err("an i+u literal requires Unicode case data");
}

#[test]
fn partial_unicode_analysis_obeys_exact_parse_work_limit() {
    let mut profile = RustProfile::regex_1_12_4();
    profile.unicode_features = RustUnicodeFeatures::NONE;
    let compatibility = CompatibilityProfile::RustText(profile);
    let pattern = r"(?-u:[a-z]+)|(?-u:\d+)";
    let baseline = parse(ParseRequest::rust(pattern, compatibility.clone()))
        .expect("baseline partial analysis");
    let exact = baseline.summary.parse_work;
    assert!(exact > 0);

    let mut quotas = SyntaxQuotas {
        max_parse_work: exact,
        ..SyntaxQuotas::default()
    };
    parse(
        ParseRequest::rust(pattern, compatibility.clone())
            .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
    )
    .expect("exact availability-analysis work limit must pass");

    quotas.max_parse_work = exact - 1;
    let error = parse(
        ParseRequest::rust(pattern, compatibility)
            .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
    )
    .expect_err("one below availability-analysis work must fail");
    assert!(matches!(
        error.category,
        ErrorCategory::FreResourceLimit {
            resource: ResourceKind::ParseWork,
            limit,
            ..
        } if limit == exact - 1
    ));
}

#[test]
fn unicode_age_name_analysis_obeys_exact_parse_work_limit() {
    let mut profile = RustProfile::regex_1_12_4();
    profile.unicode_features = RustUnicodeFeatures::AGE;
    let compatibility = CompatibilityProfile::RustText(profile);
    let short = parse(ParseRequest::rust(r"\p{Age=6.0}", compatibility.clone()))
        .expect("short unicode-age property");
    let pattern = r"\p{A_g-e=6.0}";
    let baseline = parse(ParseRequest::rust(pattern, compatibility.clone()))
        .expect("normalized unicode-age property");
    assert_eq!(baseline.summary.parse_work - short.summary.parse_work, 4);
    let exact = baseline.summary.parse_work;

    let mut quotas = SyntaxQuotas {
        max_parse_work: exact,
        ..SyntaxQuotas::default()
    };
    parse(
        ParseRequest::rust(pattern, compatibility.clone())
            .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
    )
    .expect("exact Unicode property-name analysis limit must pass");

    quotas.max_parse_work = exact - 1;
    let error = parse(
        ParseRequest::rust(pattern, compatibility)
            .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
    )
    .expect_err("one below Unicode property-name analysis must fail");
    assert!(matches!(
        error.category,
        ErrorCategory::FreResourceLimit {
            resource: ResourceKind::ParseWork,
            limit,
            ..
        } if limit == exact - 1
    ));
}

#[test]
fn unicode_bool_alias_analysis_obeys_exact_parse_work_limit() {
    let mut profile = RustProfile::regex_1_12_4();
    profile.unicode_features = RustUnicodeFeatures::BOOL;
    let compatibility = CompatibilityProfile::RustText(profile);
    for pattern in [
        r"\p{Other_Default_Ignorable_Code_Point}",
        r"\p{IsAlphabetic}",
    ] {
        let baseline = parse(ParseRequest::rust(pattern, compatibility.clone()))
            .expect("authenticated unicode-bool alias");
        let exact = baseline.summary.parse_work;

        let mut quotas = SyntaxQuotas {
            max_parse_work: exact,
            ..SyntaxQuotas::default()
        };
        parse(
            ParseRequest::rust(pattern, compatibility.clone())
                .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
        )
        .expect("exact Unicode bool alias-analysis limit must pass");

        quotas.max_parse_work = exact - 1;
        let error = parse(
            ParseRequest::rust(pattern, compatibility.clone())
                .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
        )
        .expect_err("one below Unicode bool alias-analysis work must fail");
        assert!(matches!(
            error.category,
            ErrorCategory::FreResourceLimit {
                resource: ResourceKind::ParseWork,
                limit,
                ..
            } if limit == exact - 1
        ));
    }
}

#[test]
fn unicode_case_analysis_obeys_exact_parse_work_limit() {
    let mut profile = RustProfile::regex_1_12_4();
    profile.unicode_features = RustUnicodeFeatures::CASE;
    let compatibility = CompatibilityProfile::RustText(profile);
    let pattern = r"(?i:[A-Z\u{03A3}\u{212A}])|(?i-u:[a-z])|(?-i:\u{03B4})";
    let baseline = parse(ParseRequest::rust(pattern, compatibility.clone()))
        .expect("baseline unicode-case analysis");
    let exact = baseline.summary.parse_work;
    assert!(exact > u64::try_from(pattern.len()).expect("pattern length fits u64"));

    let mut quotas = SyntaxQuotas {
        max_parse_work: exact,
        ..SyntaxQuotas::default()
    };
    let exact_record = parse(
        ParseRequest::rust(pattern, compatibility.clone())
            .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
    )
    .expect("exact Unicode case classifier work limit must pass");
    assert_eq!(exact_record.summary.parse_work, exact);

    quotas.max_parse_work = exact - 1;
    let error = parse(
        ParseRequest::rust(pattern, compatibility)
            .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
    )
    .expect_err("one below Unicode case classifier work must fail");
    assert!(matches!(
        error.category,
        ErrorCategory::FreResourceLimit {
            resource: ResourceKind::ParseWork,
            limit,
            ..
        } if limit == exact - 1
    ));
}

#[test]
fn unicode_case_wide_range_work_is_reserved_before_translation() {
    let mut profile = RustProfile::regex_1_12_4();
    profile.unicode_features = RustUnicodeFeatures::CASE;
    let compatibility = CompatibilityProfile::RustText(profile);
    let pattern = r"(?i:[\u{0}-\u{10FFFF}])";
    let baseline = parse(ParseRequest::rust(pattern, compatibility.clone()))
        .expect("wide Unicode case-fold range is within the hard safety envelope");
    let exact = baseline.summary.parse_work;
    assert!(
        exact > 20_000_000,
        "wide table traversal must be precharged"
    );

    let mut quotas = SyntaxQuotas {
        max_parse_work: exact,
        ..SyntaxQuotas::default()
    };
    parse(
        ParseRequest::rust(pattern, compatibility.clone())
            .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
    )
    .expect("exact wide-range case-fold work limit must pass");

    quotas.max_parse_work = exact - 1;
    let error = parse(
        ParseRequest::rust(pattern, compatibility)
            .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
    )
    .expect_err("one below wide-range case-fold work must fail before translation");
    assert!(matches!(
        error.category,
        ErrorCategory::FreResourceLimit {
            resource: ResourceKind::ParseWork,
            limit,
            ..
        } if limit == exact - 1
    ));
}

#[test]
fn unicode_case_auxiliary_stack_has_an_exact_prospective_limit() {
    const EXPECTED_MAX_STACK: u64 = 5;

    let mut profile = RustProfile::regex_1_12_4();
    profile.unicode_features = RustUnicodeFeatures::CASE;
    let compatibility = CompatibilityProfile::RustText(profile);
    let pattern = r"(?i:[a&&[b&&[c&&[d&&e]]]])";

    // Each binary node pushes lhs then rhs, so LIFO traversal retains one lhs
    // while descending the right-nested operand. The root reaches 2 pending
    // nodes, and the three nested binary nodes raise that to 3, 4 and exactly
    // 5. Bracket wrapper nodes replace themselves and do not raise the peak.

    let exact_quotas = SyntaxQuotas {
        max_parse_work: 60_000_000,
        max_traversal_stack: EXPECTED_MAX_STACK,
        ..SyntaxQuotas::default()
    };
    parse(
        ParseRequest::rust(pattern, compatibility.clone()).with_admission(AdmissionPolicy::Quota(
            QuotaBounded {
                syntax: exact_quotas,
            },
        )),
    )
    .expect("exact auxiliary traversal-stack limit must pass");

    let below_quotas = SyntaxQuotas {
        max_traversal_stack: EXPECTED_MAX_STACK - 1,
        ..exact_quotas
    };
    let error = parse(ParseRequest::rust(pattern, compatibility).with_admission(
        AdmissionPolicy::Quota(QuotaBounded {
            syntax: below_quotas,
        }),
    ))
    .expect_err("one below auxiliary traversal-stack limit must fail prospectively");
    assert!(matches!(
        error.category,
        ErrorCategory::FreResourceLimit {
            resource: ResourceKind::TraversalStack,
            limit,
            observed,
        } if limit == EXPECTED_MAX_STACK - 1 && observed == EXPECTED_MAX_STACK
    ));
}

#[test]
fn unicode_gencat_classifier_and_table_work_obey_exact_parse_limit() {
    let mut profile = RustProfile::regex_1_12_4();
    profile.unicode_features = RustUnicodeFeatures::GENCAT;
    let compatibility = CompatibilityProfile::RustText(profile);
    let pattern = r"\P{G_e-n e r a l _ Category != Connector_Punctuation}";
    let baseline = parse(ParseRequest::rust(pattern, compatibility.clone()))
        .expect("normalized unicode-gencat named-value query");
    let exact = baseline.summary.parse_work;
    assert!(
        exact > 10_000,
        "table search, class allocation and canonicalization must be precharged"
    );

    let mut quotas = SyntaxQuotas {
        max_parse_work: exact,
        ..SyntaxQuotas::default()
    };
    let exact_record = parse(
        ParseRequest::rust(pattern, compatibility.clone())
            .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
    )
    .expect("exact general-category classifier/table limit must pass");
    assert_eq!(exact_record.summary.parse_work, exact);

    quotas.max_parse_work = exact - 1;
    let error = parse(
        ParseRequest::rust(pattern, compatibility)
            .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
    )
    .expect_err("one below general-category classifier/table limit must fail");
    assert!(matches!(
        error.category,
        ErrorCategory::FreResourceLimit {
            resource: ResourceKind::ParseWork,
            limit,
            ..
        } if limit == exact - 1
    ));
}

#[test]
fn unicode_gencat_nested_set_dedup_work_is_prospectively_bounded() {
    let mut profile = RustProfile::regex_1_12_4();
    profile.unicode_features = RustUnicodeFeatures::GENCAT;
    let compatibility = CompatibilityProfile::RustText(profile);
    let pattern = r"[[\p{Other}]~~[\p{Letter}--[\p{Mark}&&\p{Number}]]]";
    let baseline = parse(ParseRequest::rust(pattern, compatibility.clone()))
        .expect("nested general-category set operations");
    let exact = baseline.summary.parse_work;
    assert!(
        exact > 1_000_000,
        "nested allocation, sort and dedup work must be precharged"
    );

    let mut quotas = SyntaxQuotas {
        max_parse_work: exact,
        ..SyntaxQuotas::default()
    };
    parse(
        ParseRequest::rust(pattern, compatibility.clone())
            .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
    )
    .expect("exact nested general-category set-work limit must pass");

    quotas.max_parse_work = exact - 1;
    let error = parse(
        ParseRequest::rust(pattern, compatibility)
            .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
    )
    .expect_err("one below nested set-work limit must fail before translation");
    assert!(matches!(
        error.category,
        ErrorCategory::FreResourceLimit {
            resource: ResourceKind::ParseWork,
            limit,
            ..
        } if limit == exact - 1
    ));
}

#[test]
fn unicode_gencat_analysis_stack_has_a_hand_derived_exact_limit() {
    const EXPECTED_MAX_STACK: u64 = 5;

    let mut profile = RustProfile::regex_1_12_4();
    profile.unicode_features = RustUnicodeFeatures::GENCAT;
    let compatibility = CompatibilityProfile::RustText(profile);
    let pattern = r"[\pL&&[\pN&&[\pM&&[\pS&&\pZ]]]]";

    // Each binary node pushes lhs and then rhs. LIFO traversal retains one
    // lhs while descending the right-nested operand: the root peaks at two
    // pending nodes and the next three binary nodes raise the peak to exactly
    // three, four and five. Bracket wrappers replace their pending item.
    let exact_quotas = SyntaxQuotas {
        max_parse_work: 64_000_000,
        max_traversal_stack: EXPECTED_MAX_STACK,
        ..SyntaxQuotas::default()
    };
    parse(
        ParseRequest::rust(pattern, compatibility.clone()).with_admission(AdmissionPolicy::Quota(
            QuotaBounded {
                syntax: exact_quotas,
            },
        )),
    )
    .expect("exact general-category analysis stack must pass");

    let below_quotas = SyntaxQuotas {
        max_traversal_stack: EXPECTED_MAX_STACK - 1,
        ..exact_quotas
    };
    let error = parse(ParseRequest::rust(pattern, compatibility).with_admission(
        AdmissionPolicy::Quota(QuotaBounded {
            syntax: below_quotas,
        }),
    ))
    .expect_err("one below general-category analysis stack must fail prospectively");
    assert!(matches!(
        error.category,
        ErrorCategory::FreResourceLimit {
            resource: ResourceKind::TraversalStack,
            limit,
            observed,
        } if limit == EXPECTED_MAX_STACK - 1 && observed == EXPECTED_MAX_STACK
    ));
}

#[test]
fn unicode_perl_classifier_and_table_work_obey_exact_parse_limit() {
    let mut profile = RustProfile::regex_1_12_4();
    profile.unicode_features = RustUnicodeFeatures::PERL;
    let compatibility = CompatibilityProfile::RustText(profile);
    let pattern = r"\P{Is_G-e n e r a l _ Category != D_e-cimal Number}";
    let baseline = parse(ParseRequest::rust(pattern, compatibility.clone()))
        .expect("normalized unicode-perl Decimal_Number query");
    let exact = baseline.summary.parse_work;
    assert!(
        exact > 2_000,
        "property search, class allocation and negation must be precharged"
    );

    let mut quotas = SyntaxQuotas {
        max_parse_work: exact,
        ..SyntaxQuotas::default()
    };
    let exact_record = parse(
        ParseRequest::rust(pattern, compatibility.clone())
            .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
    )
    .expect("exact unicode-perl classifier/table limit must pass");
    assert_eq!(exact_record.summary.parse_work, exact);

    quotas.max_parse_work = exact - 1;
    let error = parse(
        ParseRequest::rust(pattern, compatibility)
            .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
    )
    .expect_err("one below unicode-perl classifier/table limit must fail");
    assert!(matches!(
        error.category,
        ErrorCategory::FreResourceLimit {
            resource: ResourceKind::ParseWork,
            limit,
            ..
        } if limit == exact - 1
    ));
}

#[test]
fn unicode_perl_nested_set_work_is_prospectively_bounded() {
    let mut profile = RustProfile::regex_1_12_4();
    profile.unicode_features = RustUnicodeFeatures::PERL;
    let compatibility = CompatibilityProfile::RustText(profile);
    let pattern = r"[[\W~~\w]--[[\S&&\s]~~[\D&&\d]]]";
    let baseline = parse(ParseRequest::rust(pattern, compatibility.clone()))
        .expect("nested unicode-perl set operations");
    let exact = baseline.summary.parse_work;
    assert!(
        exact > 1_000_000,
        "nested Perl-table allocation, set and dedup work must be precharged"
    );

    let mut quotas = SyntaxQuotas {
        max_parse_work: exact,
        ..SyntaxQuotas::default()
    };
    parse(
        ParseRequest::rust(pattern, compatibility.clone())
            .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
    )
    .expect("exact nested unicode-perl set-work limit must pass");

    quotas.max_parse_work = exact - 1;
    let error = parse(
        ParseRequest::rust(pattern, compatibility)
            .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
    )
    .expect_err("one below nested unicode-perl set-work limit must fail prospectively");
    assert!(matches!(
        error.category,
        ErrorCategory::FreResourceLimit {
            resource: ResourceKind::ParseWork,
            limit,
            ..
        } if limit == exact - 1
    ));
}

#[test]
fn unicode_perl_analysis_stack_has_a_hand_derived_exact_limit() {
    const EXPECTED_MAX_STACK: u64 = 5;

    let mut profile = RustProfile::regex_1_12_4();
    profile.unicode_features = RustUnicodeFeatures::PERL;
    let compatibility = CompatibilityProfile::RustText(profile);
    let pattern = r"[\w&&[\s&&[\d&&[\W&&\D]]]]";

    let exact_quotas = SyntaxQuotas {
        max_parse_work: 64_000_000,
        max_traversal_stack: EXPECTED_MAX_STACK,
        ..SyntaxQuotas::default()
    };
    parse(
        ParseRequest::rust(pattern, compatibility.clone()).with_admission(AdmissionPolicy::Quota(
            QuotaBounded {
                syntax: exact_quotas,
            },
        )),
    )
    .expect("exact unicode-perl analysis stack must pass");

    let below_quotas = SyntaxQuotas {
        max_traversal_stack: EXPECTED_MAX_STACK - 1,
        ..exact_quotas
    };
    let error = parse(ParseRequest::rust(pattern, compatibility).with_admission(
        AdmissionPolicy::Quota(QuotaBounded {
            syntax: below_quotas,
        }),
    ))
    .expect_err("one below unicode-perl analysis stack must fail prospectively");
    assert!(matches!(
        error.category,
        ErrorCategory::FreResourceLimit {
            resource: ResourceKind::TraversalStack,
            limit,
            observed,
        } if limit == EXPECTED_MAX_STACK - 1 && observed == EXPECTED_MAX_STACK
    ));
}

#[test]
fn unicode_script_classifier_and_table_work_obey_exact_parse_limit() {
    let mut profile = RustProfile::regex_1_12_4();
    profile.unicode_features = RustUnicodeFeatures::SCRIPT;
    let compatibility = CompatibilityProfile::RustText(profile);
    let pattern = r"\P{Is_S-c r i p t _ Extensions=K_a-t a k-a n a}";
    let baseline = parse(ParseRequest::rust(pattern, compatibility.clone()))
        .expect("normalized unicode-script named-value query");
    let exact = baseline.summary.parse_work;
    assert!(
        exact > 5_000,
        "alias search, property lookup, table allocation and negation must be precharged"
    );

    let mut quotas = SyntaxQuotas {
        max_parse_work: exact,
        ..SyntaxQuotas::default()
    };
    let exact_record = parse(
        ParseRequest::rust(pattern, compatibility.clone())
            .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
    )
    .expect("exact unicode-script classifier/table limit must pass");
    assert_eq!(exact_record.summary.parse_work, exact);

    quotas.max_parse_work = exact - 1;
    let error = parse(
        ParseRequest::rust(pattern, compatibility)
            .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
    )
    .expect_err("one below unicode-script classifier/table limit must fail");
    assert!(matches!(
        error.category,
        ErrorCategory::FreResourceLimit {
            resource: ResourceKind::ParseWork,
            limit,
            ..
        } if limit == exact - 1
    ));
}

#[test]
fn unicode_script_nested_set_work_is_prospectively_bounded() {
    let mut profile = RustProfile::regex_1_12_4();
    profile.unicode_features = RustUnicodeFeatures::SCRIPT;
    let compatibility = CompatibilityProfile::RustText(profile);
    let pattern = r"[[\p{Common}~~\p{Greek}]--[\p{scx=Latin}&&[\p{scx=Arabic}~~\p{Inherited}]]]";
    let baseline = parse(ParseRequest::rust(pattern, compatibility.clone()))
        .expect("nested unicode-script set operations");
    let exact = baseline.summary.parse_work;
    assert!(
        exact > 500_000,
        "nested script-table allocation, set and dedup work must be precharged"
    );

    let mut quotas = SyntaxQuotas {
        max_parse_work: exact,
        ..SyntaxQuotas::default()
    };
    parse(
        ParseRequest::rust(pattern, compatibility.clone())
            .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
    )
    .expect("exact nested unicode-script set-work limit must pass");

    quotas.max_parse_work = exact - 1;
    let error = parse(
        ParseRequest::rust(pattern, compatibility)
            .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
    )
    .expect_err("one below nested unicode-script set-work limit must fail prospectively");
    assert!(matches!(
        error.category,
        ErrorCategory::FreResourceLimit {
            resource: ResourceKind::ParseWork,
            limit,
            ..
        } if limit == exact - 1
    ));
}

#[test]
fn unicode_script_analysis_stack_has_a_hand_derived_exact_limit() {
    const EXPECTED_MAX_STACK: u64 = 5;

    let mut profile = RustProfile::regex_1_12_4();
    profile.unicode_features = RustUnicodeFeatures::SCRIPT;
    let compatibility = CompatibilityProfile::RustText(profile);
    let pattern = r"[\p{Greek}&&[\p{Latin}&&[\p{Arabic}&&[\p{Han}&&\p{Common}]]]]";

    let exact_quotas = SyntaxQuotas {
        max_parse_work: 64_000_000,
        max_traversal_stack: EXPECTED_MAX_STACK,
        ..SyntaxQuotas::default()
    };
    parse(
        ParseRequest::rust(pattern, compatibility.clone()).with_admission(AdmissionPolicy::Quota(
            QuotaBounded {
                syntax: exact_quotas,
            },
        )),
    )
    .expect("exact unicode-script analysis stack must pass");

    let below_quotas = SyntaxQuotas {
        max_traversal_stack: EXPECTED_MAX_STACK - 1,
        ..exact_quotas
    };
    let error = parse(ParseRequest::rust(pattern, compatibility).with_admission(
        AdmissionPolicy::Quota(QuotaBounded {
            syntax: below_quotas,
        }),
    ))
    .expect_err("one below unicode-script analysis stack must fail prospectively");
    assert!(matches!(
        error.category,
        ErrorCategory::FreResourceLimit {
            resource: ResourceKind::TraversalStack,
            limit,
            observed,
        } if limit == EXPECTED_MAX_STACK - 1 && observed == EXPECTED_MAX_STACK
    ));
}

#[test]
fn unicode_segment_classifier_and_table_work_obey_exact_parse_limit() {
    let mut profile = RustProfile::regex_1_12_4();
    profile.unicode_features = RustUnicodeFeatures::SEGMENT;
    let compatibility = CompatibilityProfile::RustText(profile);
    let pattern = r"\P{Is_G-r a p h e m e _ Cluster _ Break=Regional _ Indicator}";
    let baseline = parse(ParseRequest::rust(pattern, compatibility.clone()))
        .expect("normalized unicode-segment named-value query");
    let exact = baseline.summary.parse_work;
    assert!(
        exact > 5_000,
        "property/value lookup, table allocation and negation must be precharged"
    );

    let mut quotas = SyntaxQuotas {
        max_parse_work: exact,
        ..SyntaxQuotas::default()
    };
    let exact_record = parse(
        ParseRequest::rust(pattern, compatibility.clone())
            .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
    )
    .expect("exact unicode-segment classifier/table limit must pass");
    assert_eq!(exact_record.summary.parse_work, exact);

    quotas.max_parse_work = exact - 1;
    let error = parse(
        ParseRequest::rust(pattern, compatibility)
            .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
    )
    .expect_err("one below unicode-segment classifier/table limit must fail");
    assert!(matches!(
        error.category,
        ErrorCategory::FreResourceLimit {
            resource: ResourceKind::ParseWork,
            limit,
            ..
        } if limit == exact - 1
    ));
}

#[test]
fn unicode_segment_nested_set_work_is_prospectively_bounded() {
    let mut profile = RustProfile::regex_1_12_4();
    profile.unicode_features = RustUnicodeFeatures::SEGMENT;
    let compatibility = CompatibilityProfile::RustText(profile);
    let pattern =
        r"[[\p{gcb=LV}~~\p{sb=Lower}]--[\p{wb=ALetter}&&[\p{gcb=Extend}~~\p{wb=Numeric}]]]";
    let baseline = parse(ParseRequest::rust(pattern, compatibility.clone()))
        .expect("nested unicode-segment set operations");
    let exact = baseline.summary.parse_work;
    assert!(
        exact > 500_000,
        "nested segment-table allocation, set and dedup work must be precharged"
    );

    let mut quotas = SyntaxQuotas {
        max_parse_work: exact,
        ..SyntaxQuotas::default()
    };
    parse(
        ParseRequest::rust(pattern, compatibility.clone())
            .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
    )
    .expect("exact nested unicode-segment set-work limit must pass");

    quotas.max_parse_work = exact - 1;
    let error = parse(
        ParseRequest::rust(pattern, compatibility)
            .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
    )
    .expect_err("one below nested unicode-segment set-work limit must fail prospectively");
    assert!(matches!(
        error.category,
        ErrorCategory::FreResourceLimit {
            resource: ResourceKind::ParseWork,
            limit,
            ..
        } if limit == exact - 1
    ));
}

#[test]
fn unicode_segment_analysis_stack_has_a_hand_derived_exact_limit() {
    const EXPECTED_MAX_STACK: u64 = 5;

    let mut profile = RustProfile::regex_1_12_4();
    profile.unicode_features = RustUnicodeFeatures::SEGMENT;
    let compatibility = CompatibilityProfile::RustText(profile);
    let pattern =
        r"[\p{gcb=Extend}&&[\p{sb=Lower}&&[\p{wb=ALetter}&&[\p{gcb=LV}&&\p{wb=Numeric}]]]]";

    let exact_quotas = SyntaxQuotas {
        max_parse_work: 64_000_000,
        max_traversal_stack: EXPECTED_MAX_STACK,
        ..SyntaxQuotas::default()
    };
    parse(
        ParseRequest::rust(pattern, compatibility.clone()).with_admission(AdmissionPolicy::Quota(
            QuotaBounded {
                syntax: exact_quotas,
            },
        )),
    )
    .expect("exact unicode-segment analysis stack must pass");

    let below_quotas = SyntaxQuotas {
        max_traversal_stack: EXPECTED_MAX_STACK - 1,
        ..exact_quotas
    };
    let error = parse(ParseRequest::rust(pattern, compatibility).with_admission(
        AdmissionPolicy::Quota(QuotaBounded {
            syntax: below_quotas,
        }),
    ))
    .expect_err("one below unicode-segment analysis stack must fail prospectively");
    assert!(matches!(
        error.category,
        ErrorCategory::FreResourceLimit {
            resource: ResourceKind::TraversalStack,
            limit,
            observed,
        } if limit == EXPECTED_MAX_STACK - 1 && observed == EXPECTED_MAX_STACK
    ));
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
            AdmissionStatus::StrictChecked
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
        AdmissionStatus::StrictChecked
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
