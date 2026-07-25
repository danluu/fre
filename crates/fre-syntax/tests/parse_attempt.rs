use core::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

use fre_syntax::{
    AdmissionPolicy, CompatibilityProfile, ErrorCategory, ParseAttemptActual, ParseAttemptTerminal,
    ParseRequest, QuotaBounded, ResourceKind, RustProfile, RustUnicodeFeatures, SyntaxQuotas,
    parse, parse_attempt, parse_rust_ast,
};

fn semantic_hash<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

#[test]
fn success_moves_the_exact_source_allocation_into_the_cache_key() {
    let mut source = String::with_capacity(64);
    source.push_str("a+");
    let request = ParseRequest::rust(
        source,
        CompatibilityProfile::RustText(RustProfile::regex_1_12_4()),
    );
    let source_pointer = request.pattern().as_bytes().as_ptr();
    let source_capacity = request.pattern().capacity_bytes();

    let attempt = parse_attempt(request).expect("receipt-bearing parse");
    assert!(attempt.closes());
    assert_eq!(attempt.receipt().terminal, ParseAttemptTerminal::Success);
    assert_eq!(
        attempt.record().key.pattern.as_bytes().as_ptr(),
        source_pointer
    );
    assert_eq!(
        attempt.record().key.pattern.capacity_bytes(),
        source_capacity
    );
    let prospective = attempt.receipt().prospective.expect("published P");
    let actual = attempt.receipt().actual;
    assert_eq!(actual.source_admission_checks, 1);
    assert_eq!(actual.configuration_checks, 1);
    assert_eq!(actual.opaque_parser_invocations, 1);
    assert_eq!(
        prospective.source_bytes + actual.observed_work,
        attempt.record().summary.parse_work
    );
    assert!(prospective.contains(actual));

    let legacy = parse(ParseRequest::rust(
        "a+",
        CompatibilityProfile::RustText(RustProfile::regex_1_12_4()),
    ))
    .expect("legacy parse API");
    assert_eq!(legacy.summary, attempt.record().summary);
    assert_eq!(
        legacy.key.pattern.as_bytes(),
        attempt.record().key.pattern.as_bytes()
    );
}

#[test]
fn syntax_error_retains_the_exact_request_without_post_failure_cloning() {
    let mut source = String::with_capacity(64);
    source.push('(');
    let request = ParseRequest::rust(
        source,
        CompatibilityProfile::RustText(RustProfile::regex_1_12_4()),
    );
    let source_pointer = request.pattern().as_bytes().as_ptr();
    let source_capacity = request.pattern().capacity_bytes();

    let error = parse_attempt(request).expect_err("unclosed group must fail");
    assert!(error.closes());
    assert_eq!(
        error.request().pattern().as_bytes().as_ptr(),
        source_pointer
    );
    assert_eq!(error.request().pattern().capacity_bytes(), source_capacity);
    assert_eq!(error.source().category, ErrorCategory::UpstreamRustSyntax);
    assert_eq!(error.receipt().terminal, ParseAttemptTerminal::Failure);
    let actual = error.receipt().actual;
    assert_eq!(actual.source_admission_checks, 1);
    assert_eq!(actual.configuration_checks, 1);
    assert_eq!(actual.opaque_parser_invocations, 1);
    assert_eq!(actual.observed_work, 0);
    assert!(
        error
            .receipt()
            .prospective
            .expect("published P")
            .contains(actual)
    );

    let diagnostic_pointer = error.source().message.as_ptr();
    let (request, source, receipt) = error.into_parts();
    assert_eq!(request.pattern().as_bytes().as_ptr(), source_pointer);
    assert_eq!(source.message.as_ptr(), diagnostic_pointer);
    assert_eq!(receipt.actual, actual);
}

#[test]
fn same_length_terminal_receipts_do_not_authenticate_another_source_owner() {
    let profile = CompatibilityProfile::RustText(RustProfile::regex_1_12_4());
    let mut first_request = ParseRequest::rust("(", profile.clone());
    let mut second_request = ParseRequest::rust("[", profile);
    assert!(
        first_request
            .bind_attempt_source_owner()
            .is_some_and(|bytes| bytes > 0)
    );
    assert!(
        second_request
            .bind_attempt_source_owner()
            .is_some_and(|bytes| bytes > 0)
    );
    let first = parse_attempt(first_request).expect_err("first invalid source");
    let second = parse_attempt(second_request).expect_err("second invalid source");
    assert!(first.closes());
    assert!(second.closes());
    assert!(first.receipt().identity.has_stable_source_owner());
    assert!(second.receipt().identity.has_stable_source_owner());
    assert_ne!(first.receipt().identity, second.receipt().identity);
    assert_eq!(
        first.request().pattern().as_bytes().len(),
        second.request().pattern().as_bytes().len()
    );
    assert!(!first.receipt().authenticates_request(second.request()));
    assert!(!second.receipt().authenticates_request(first.request()));
}

#[test]
fn bound_owner_is_single_allocation_and_survives_clones_and_request_to_key_move() {
    let profile = CompatibilityProfile::RustText(RustProfile::regex_1_12_4());
    let mut source = String::with_capacity(64);
    source.push_str("a+");
    let mut request = ParseRequest::rust(source, profile);
    let source_pointer = request.pattern().as_bytes().as_ptr();
    let unbound_identity = request.attempt_identity();
    let logical_bytes = request
        .bind_attempt_source_owner()
        .expect("first binding allocates the stable owner");
    assert_eq!(
        logical_bytes,
        ParseRequest::attempt_source_owner_allocation_bytes()
    );
    assert_eq!(logical_bytes, core::mem::size_of::<[usize; 2]>());
    assert_eq!(request.bind_attempt_source_owner(), None);

    let identity = request.attempt_identity();
    assert_ne!(identity, unbound_identity);
    assert!(!unbound_identity.authenticates_request(&request));
    let identity_clone = identity.clone();
    assert!(identity.has_stable_source_owner());
    assert_eq!(identity_clone, identity);
    assert!(identity_clone.authenticates_request(&request));

    let attempt = parse_attempt(request).expect("bound request parses");
    assert!(attempt.closes());
    assert_eq!(
        attempt.record().key.pattern.as_bytes().as_ptr(),
        source_pointer
    );
    assert_eq!(attempt.receipt().identity, identity);
    assert!(identity_clone.authenticates_key(&attempt.record().key));

    let receipt_clone = attempt.receipt().clone();
    assert!(receipt_clone.identity.has_stable_source_owner());
    assert!(
        receipt_clone
            .identity
            .authenticates_key(&attempt.record().key)
    );

    let semantically_equal_key_clone = attempt.record().key.clone();
    assert_eq!(semantically_equal_key_clone, attempt.record().key);
    assert!(!identity.authenticates_key(&semantically_equal_key_clone));
}

#[test]
fn bound_owner_moves_through_legacy_ast_and_re2_success_paths() {
    let mut ast_request = ParseRequest::rust(
        "a+",
        CompatibilityProfile::RustText(RustProfile::regex_1_12_4()),
    );
    ast_request
        .bind_attempt_source_owner()
        .expect("bind AST request");
    let ast_identity = ast_request.attempt_identity();
    let ast = parse_rust_ast(ast_request).expect("AST request parses");
    assert!(ast_identity.authenticates_key(&ast.key));

    let mut re2_request = ParseRequest::re2(b"a+".to_vec(), CompatibilityProfile::re2());
    re2_request
        .bind_attempt_source_owner()
        .expect("bind RE2 request");
    let re2_identity = re2_request.attempt_identity();
    let re2 = parse(re2_request).expect("RE2 request parses");
    assert!(re2_identity.authenticates_key(&re2.key));
}

#[test]
fn stable_owner_is_not_part_of_request_or_cache_key_semantic_identity() {
    let profile = CompatibilityProfile::RustText(RustProfile::regex_1_12_4());
    let unbound = ParseRequest::rust("same", profile.clone());
    let mut first = unbound.clone();
    let mut second = unbound.clone();
    first
        .bind_attempt_source_owner()
        .expect("bind first independent owner");
    second
        .bind_attempt_source_owner()
        .expect("bind second independent owner");

    assert_eq!(first, second);
    assert_eq!(first.cmp(&second), core::cmp::Ordering::Equal);
    assert_eq!(semantic_hash(&first), semantic_hash(&second));

    let first_identity = first.attempt_identity();
    let second_identity = second.attempt_identity();
    assert_ne!(first_identity, second_identity);
    assert!(!first_identity.authenticates_request(&second));
    assert!(!second_identity.authenticates_request(&first));

    let first_attempt = parse_attempt(first).expect("first bound request parses");
    let second_attempt = parse_attempt(second).expect("second bound request parses");
    assert_eq!(first_attempt.record().key, second_attempt.record().key);
    assert_eq!(
        first_attempt.record().key.cmp(&second_attempt.record().key),
        core::cmp::Ordering::Equal
    );
    assert_eq!(
        semantic_hash(&first_attempt.record().key),
        semantic_hash(&second_attempt.record().key)
    );
    assert!(!first_identity.authenticates_key(&second_attempt.record().key));
    assert!(!second_identity.authenticates_key(&first_attempt.record().key));
}

#[test]
fn same_length_bound_receipt_splice_and_public_identity_mutation_are_rejected() {
    let profile = CompatibilityProfile::RustText(RustProfile::regex_1_12_4());
    let mut first_request = ParseRequest::rust("ab", profile.clone());
    let mut second_request = ParseRequest::rust("cd", profile);
    first_request
        .bind_attempt_source_owner()
        .expect("bind first owner");
    second_request
        .bind_attempt_source_owner()
        .expect("bind second owner");
    let first = parse_attempt(first_request).expect("first request parses");
    let second = parse_attempt(second_request).expect("second request parses");

    let mut spliced = first.receipt().clone();
    spliced.identity = second.receipt().identity.clone();
    assert!(spliced.authenticates_canonical());
    assert!(!spliced.identity.authenticates_key(&first.record().key));

    let mut mutated = first.receipt().clone();
    mutated.identity.algorithm_version = mutated
        .identity
        .algorithm_version
        .checked_add(1)
        .expect("version mutation fits");
    assert!(!mutated.authenticates_canonical());
    assert!(!mutated.identity.authenticates_key(&first.record().key));
}

#[test]
fn public_p_a_and_terminal_mutations_cannot_reauthenticate_a_closed_receipt() {
    let attempt = parse_attempt(ParseRequest::rust(
        "a+",
        CompatibilityProfile::RustText(RustProfile::regex_1_12_4()),
    ))
    .expect("baseline request parses");
    assert!(attempt.closes());

    let mut prospective_mutation = attempt.receipt().clone();
    let prospective = prospective_mutation
        .prospective
        .as_mut()
        .expect("Rust attempt publishes P");
    prospective.max_observed_work = prospective
        .max_observed_work
        .checked_add(1)
        .expect("test mutation fits");
    assert!(!prospective_mutation.authenticates_canonical());

    let mut actual_mutation = attempt.receipt().clone();
    actual_mutation.actual.source_admission_checks = 0;
    assert!(
        actual_mutation
            .prospective
            .expect("Rust attempt publishes P")
            .contains(actual_mutation.actual)
    );
    assert!(!actual_mutation.authenticates_canonical());

    let mut terminal_mutation = attempt.receipt().clone();
    terminal_mutation.terminal = ParseAttemptTerminal::Failure;
    assert!(!terminal_mutation.authenticates_canonical());
}

#[test]
fn source_refusal_publishes_p_but_commits_no_actual_effect() {
    let quotas = SyntaxQuotas {
        max_pattern_bytes: 0,
        ..SyntaxQuotas::default()
    };
    let request = ParseRequest::rust(
        "x",
        CompatibilityProfile::RustText(RustProfile::regex_1_12_4()),
    )
    .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas }));
    let source_pointer = request.pattern().as_bytes().as_ptr();

    let error = parse_attempt(request).expect_err("one byte exceeds zero-byte quota");
    assert!(error.closes());
    assert_eq!(
        error.request().pattern().as_bytes().as_ptr(),
        source_pointer
    );
    assert!(error.receipt().prospective.is_some());
    assert_eq!(error.receipt().actual, ParseAttemptActual::default());
    assert!(matches!(
        error.source().category,
        ErrorCategory::FreResourceLimit {
            resource: ResourceKind::PatternBytes,
            ..
        }
    ));
}

#[test]
fn restricted_unicode_failure_retains_partial_observed_work() {
    let mut profile = RustProfile::regex_1_12_4();
    profile.unicode_features = RustUnicodeFeatures::NONE;
    let request = ParseRequest::rust(r"\p{Greek}", CompatibilityProfile::RustText(profile));

    let error = parse_attempt(request).expect_err("Greek data is unavailable");
    assert!(error.closes());
    assert_eq!(error.source().category, ErrorCategory::UpstreamRustSyntax);
    let actual = error.receipt().actual;
    assert_eq!(actual.source_admission_checks, 1);
    assert_eq!(actual.configuration_checks, 1);
    assert_eq!(actual.opaque_parser_invocations, 1);
    assert!(actual.availability_work > 0);
    assert_eq!(actual.observed_work, actual.availability_work);
    assert_eq!(actual.hir_summary_work, 0);
    assert!(
        error
            .receipt()
            .prospective
            .expect("published P")
            .contains(actual)
    );
}

#[test]
fn one_below_work_refusal_retains_bounded_partial_actual() {
    let mut profile = RustProfile::regex_1_12_4();
    profile.unicode_features = RustUnicodeFeatures::NONE;
    let compatibility = CompatibilityProfile::RustText(profile);
    let pattern = r"(?-u:[a-z]+)|(?-u:\d+)";
    let baseline = parse_attempt(ParseRequest::rust(pattern, compatibility.clone()))
        .expect("baseline attempt");
    let exact = baseline.record().summary.parse_work;
    assert!(exact > u64::try_from(pattern.len()).expect("length fits"));

    let quotas = SyntaxQuotas {
        max_parse_work: exact - 1,
        ..SyntaxQuotas::default()
    };
    let error = parse_attempt(
        ParseRequest::rust(pattern, compatibility)
            .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
    )
    .expect_err("one-below work quota");
    assert!(error.closes());
    let prospective = error.receipt().prospective.expect("published P");
    let actual = error.receipt().actual;
    assert!(actual.observed_work > 0);
    assert!(prospective.contains(actual));
    assert!(matches!(
        error.source().category,
        ErrorCategory::FreResourceLimit {
            resource: ResourceKind::ParseWork,
            ..
        }
    ));
}

#[test]
fn kind_work_refusal_retains_the_admitted_node_visit_and_no_kind_effect() {
    let compatibility = CompatibilityProfile::RustText(RustProfile::regex_1_12_4());
    for pattern in ["abc", "[abc]"] {
        let source_work = u64::try_from(pattern.len()).expect("source length fits");
        let quotas = SyntaxQuotas {
            max_parse_work: source_work + 1,
            ..SyntaxQuotas::default()
        };
        let error = parse_attempt(
            ParseRequest::rust(pattern, compatibility.clone())
                .with_admission(AdmissionPolicy::Quota(QuotaBounded { syntax: quotas })),
        )
        .expect_err("kind work exceeds the one-node allowance");
        assert!(error.closes());
        let actual = error.receipt().actual;
        assert_eq!(actual.hir_nodes, 1, "{pattern}");
        assert_eq!(actual.hir_summary_work, 1, "{pattern}");
        assert_eq!(actual.observed_work, 1, "{pattern}");
        assert_eq!(actual.literal_bytes, 0, "{pattern}");
        assert_eq!(actual.class_ranges, 0, "{pattern}");
        assert_eq!(actual.max_depth, 0, "{pattern}");
        assert_eq!(actual.traversal_stack_peak, 1, "{pattern}");
        assert!(
            error
                .receipt()
                .prospective
                .expect("published P")
                .contains(actual),
            "{pattern}"
        );
        assert!(
            matches!(
                error.source().category,
                ErrorCategory::FreResourceLimit {
                    resource: ResourceKind::ParseWork,
                    ..
                }
            ),
            "{pattern}"
        );
    }
}

#[test]
fn re2_attempt_fails_before_p_and_p_none_requires_zero_actual() {
    let request = ParseRequest::re2(b"a".to_vec(), CompatibilityProfile::re2());
    let source_pointer = request.pattern().as_bytes().as_ptr();
    let error = parse_attempt(request).expect_err("attempt API is Rust-only");
    assert!(error.closes());
    assert_eq!(
        error.request().pattern().as_bytes().as_ptr(),
        source_pointer
    );
    assert!(error.receipt().prospective.is_none());
    assert_eq!(error.receipt().actual, ParseAttemptActual::default());

    let mut forged = error.receipt().clone();
    forged.actual.source_admission_checks = 1;
    assert!(!forged.authenticates_canonical());
}
