use fre::{
    AggregateBuildError, AggregateBuilder, AggregateExactLiteralSemantics, AggregateOperation,
    AggregatePlanKind, AggregatePlanSelection, LiteralAggregateOperation, RustProfile,
};

fn semantic_binding_bytes(regex: &fre::AggregateCountRegex) -> [u8; 32] {
    let candidate = regex
        .exact_literal_aot_candidate()
        .expect("expected authenticated exact-literal count candidate");
    *candidate.semantic_binding_identity().as_bytes()
}

#[test]
fn exact_count_candidate_exposes_only_authenticated_immutable_inputs() {
    let regex = AggregateBuilder::new("needle")
        .unicode(false)
        .build_count()
        .unwrap();
    assert_eq!(regex.build_report().plan, AggregatePlanKind::ExactLiteral);

    let candidate = regex.exact_literal_aot_candidate().unwrap();
    assert_eq!(candidate.literal(), b"needle");
    assert_eq!(candidate.operation(), AggregateOperation::Count);
    assert_eq!(
        candidate.semantics(),
        AggregateExactLiteralSemantics::UnicodeOffByteBoundaries
    );
    assert!(!candidate.profile().options.unicode);
    assert_eq!(candidate.plan_identity().semantics, candidate.semantics());
    assert_eq!(
        candidate.plan_identity().kernel.operation,
        LiteralAggregateOperation::Count
    );
    assert_eq!(
        candidate.build_accounting().needle_bytes,
        candidate.literal().len()
    );
    assert_eq!(candidate.semantic_binding_identity().as_bytes().len(), 32);
}

#[test]
fn escaped_source_reuses_selected_literal_but_changes_source_binding() {
    let plain = AggregateBuilder::new("needle")
        .unicode(false)
        .build_count()
        .unwrap();
    let escaped = AggregateBuilder::new(r"\x6e\x65\x65\x64\x6c\x65")
        .unicode(false)
        .build_count()
        .unwrap();
    let repeated = AggregateBuilder::new(r"\x6e\x65\x65\x64\x6c\x65")
        .unicode(false)
        .build_count()
        .unwrap();

    assert_eq!(
        plain.exact_literal_aot_candidate().unwrap().literal(),
        escaped.exact_literal_aot_candidate().unwrap().literal()
    );
    assert_ne!(
        semantic_binding_bytes(&plain),
        semantic_binding_bytes(&escaped)
    );
    assert_eq!(
        semantic_binding_bytes(&escaped),
        semantic_binding_bytes(&repeated)
    );
}

#[test]
fn non_exact_and_forced_refusal_never_publish_candidates() {
    let non_exact = AggregateBuilder::new("[a-z]+")
        .unicode(false)
        .build_count()
        .unwrap();
    assert_ne!(
        non_exact.build_report().plan,
        AggregatePlanKind::ExactLiteral
    );
    assert!(non_exact.exact_literal_aot_candidate().is_none());

    let refusal = AggregateBuilder::new("[a-z]+")
        .unicode(false)
        .plan_selection(AggregatePlanSelection::ForceExactLiteral)
        .build_count()
        .unwrap_err();
    assert!(matches!(
        refusal,
        AggregateBuildError::ExactLiteralIneligible { .. }
    ));
}

#[test]
fn complete_profile_and_selection_are_binding_sensitive() {
    let default_profile = RustProfile::default();
    let rebar_profile = RustProfile::rebar_1_12_4();
    let default = AggregateBuilder::new("needle")
        .profile(default_profile.clone())
        .build_count()
        .unwrap();
    let rebar = AggregateBuilder::new("needle")
        .profile(rebar_profile.clone())
        .build_count()
        .unwrap();
    let forced = AggregateBuilder::new("needle")
        .profile(default_profile.clone())
        .plan_selection(AggregatePlanSelection::ForceExactLiteral)
        .build_count()
        .unwrap();

    assert_eq!(
        default.exact_literal_aot_candidate().unwrap().profile(),
        &default_profile
    );
    assert_eq!(
        rebar.exact_literal_aot_candidate().unwrap().profile(),
        &rebar_profile
    );
    assert_ne!(
        semantic_binding_bytes(&default),
        semantic_binding_bytes(&rebar)
    );
    assert_ne!(
        semantic_binding_bytes(&default),
        semantic_binding_bytes(&forced)
    );
}
