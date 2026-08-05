use fre::{AggregatePlanIdentity, AggregatePlanKind};
use rebar_compare::{
    CandidateAdapter, CurrentFreAdapter, current_fre_rebar_aggregate_builder,
    current_fre_rebar_aggregate_compile_lifecycle, current_fre_rebar_aggregate_operation_lifecycle,
    current_fre_rebar_validate_aggregate_identity,
};
use regex::bytes::RegexBuilder;
use sha2::{Digest, Sha256};

const ASSERTED_PATTERN: &str = r"\b\w+\s+Holmes\s+\w+\b";
const ASSERTED_PATTERN_SHA256: &str =
    "0704ded7fbd59d6eb343f82f9551b310ae8d33aa5592ba806b2725ac4f1bb9ad";
const UNASSERTED_PATTERN: &str = r"\w+\s+Holmes\s+\w+";
const UNASSERTED_PATTERN_SHA256: &str =
    "b529539ea7718c8fdfd31b0505e3722f2284c5cd2cbb04384c267a1b0fefecb0";
const COMPILE_PLAN: &str = "compile-aggregate-token-phrase-v2";
const OPERATION_PLAN: &str = "aggregate-token-phrase-v2";

fn local_fixture() -> Vec<u8> {
    b"Sherlock Holmes wat--A Holmes B; C X Holmes Y; Mycroft  Holmes \t too\xff".to_vec()
}

#[test]
fn exact_rebar_shapes_use_token_phrase() {
    for (row, pattern, pattern_sha256, asserted) in [
        (
            "unicode/word/around-holmes-english@rust/regex",
            ASSERTED_PATTERN,
            ASSERTED_PATTERN_SHA256,
            true,
        ),
        (
            "imported/sherlock/before-after-holmes@rust/regex",
            UNASSERTED_PATTERN,
            UNASSERTED_PATTERN_SHA256,
            false,
        ),
    ] {
        assert_eq!(
            format!("{:x}", Sha256::digest(pattern.as_bytes())),
            pattern_sha256
        );
        let haystack = local_fixture();
        let oracle = RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .expect("pinned Rust regex accepts exact token-phrase row");
        let spans: Vec<_> = oracle.find_iter(&haystack).collect();
        let expected_span_sum = spans
            .iter()
            .map(|matched| matched.end() - matched.start())
            .sum::<usize>();

        let lifecycle = current_fre_rebar_aggregate_operation_lifecycle(
            "count-spans",
            &[pattern.to_owned()],
            false,
            false,
            haystack.len(),
        )
        .expect("exact token-phrase operation lifecycle");
        assert_eq!(lifecycle.plan(), OPERATION_PLAN, "{row}");
        assert_eq!(
            lifecycle.execute(&haystack).unwrap(),
            u64::try_from(expected_span_sum).unwrap(),
            "{row}"
        );
        assert_eq!(
            lifecycle.execute(&haystack).unwrap(),
            u64::try_from(expected_span_sum).unwrap(),
            "{row}"
        );

        let compile = current_fre_rebar_aggregate_compile_lifecycle(
            &[pattern.to_owned()],
            false,
            false,
            haystack.len(),
        )
        .expect("exact token-phrase compile lifecycle");
        let artifact = compile
            .construct()
            .expect("exact token-phrase construction");
        assert_eq!(artifact.plan(&compile).unwrap(), COMPILE_PLAN);
        assert_eq!(
            artifact.verify(&compile, &haystack).unwrap(),
            u64::try_from(spans.len()).unwrap()
        );

        let regex = current_fre_rebar_aggregate_builder(pattern, false, false)
            .build_span_sum()
            .expect("exact token-phrase facade plan");
        assert_eq!(regex.build_report().plan, AggregatePlanKind::TokenPhrase);
        assert_eq!(regex.build_report().schema_version, 48);
        let AggregatePlanIdentity::TokenPhrase(identity) = regex.build_report().plan_identity
        else {
            panic!("exact token-phrase row selected another identity");
        };
        assert_eq!(identity.kernel.outer_word_assertions, asserted);
        current_fre_rebar_validate_aggregate_identity(regex.build_report(), false, "count-spans")
            .expect("typed token-phrase identity");
    }
}

#[test]
fn adapter_identity_names_the_new_operation_owned_leaf() {
    let identity = CurrentFreAdapter.identity();
    assert!(identity.adapter.contains("token-phrase-v2"));
    assert!(identity.identity.contains("token-phrase-v2"));
    assert!(identity.availability.contains("token-phrase"));
}

#[test]
fn adapter_limits_close_literal_anchor_and_impossible_width_routes() {
    let mut anchor_haystack = vec![b'-'; 4_096];
    anchor_haystack.extend_from_slice(b"--left Holmes right--");
    anchor_haystack.resize(8_192, b'-');
    let anchor_oracle = RegexBuilder::new(ASSERTED_PATTERN)
        .unicode(false)
        .build()
        .unwrap()
        .find_iter(&anchor_haystack)
        .map(|matched| matched.len())
        .sum::<usize>();
    let anchor = current_fre_rebar_aggregate_operation_lifecycle(
        "count-spans",
        &[ASSERTED_PATTERN.to_owned()],
        false,
        false,
        anchor_haystack.len(),
    )
    .expect("literal-anchor lifecycle");
    assert_eq!(anchor.plan(), OPERATION_PLAN);
    assert_eq!(
        anchor.execute(&anchor_haystack).unwrap(),
        u64::try_from(anchor_oracle).unwrap()
    );

    let literal = "H".repeat(256);
    let pattern = format!(r"\b\w+\s+{literal}\s+\w+\b");
    let impossible_haystack = vec![b'H'; 128];
    let impossible = current_fre_rebar_aggregate_operation_lifecycle(
        "count",
        &[pattern],
        false,
        false,
        impossible_haystack.len(),
    )
    .expect("impossible-width lifecycle");
    assert_eq!(impossible.plan(), OPERATION_PLAN);
    assert_eq!(impossible.execute(&impossible_haystack).unwrap(), 0);
}

#[test]
#[ignore = "requires the separately authenticated Rebar Sherlock corpus"]
fn authenticated_rebar_sherlock_corpus_returns_2593() {
    let path = std::env::var_os("FRE_TOKEN_PHRASE_SHERLOCK_HAYSTACK")
        .expect("set FRE_TOKEN_PHRASE_SHERLOCK_HAYSTACK");
    let haystack = std::fs::read(path).expect("read authenticated Sherlock corpus");
    assert_eq!(haystack.len(), 594_933);
    assert_eq!(
        format!("{:x}", Sha256::digest(&haystack)),
        "242ec73a70f0a03dcbe007e32038e7deeaee004aaec9a09a07fa322743440fa8"
    );
    let lifecycle = current_fre_rebar_aggregate_operation_lifecycle(
        "count-spans",
        &[UNASSERTED_PATTERN.to_owned()],
        false,
        false,
        haystack.len(),
    )
    .expect("authenticated Sherlock token-phrase lifecycle");
    assert_eq!(lifecycle.plan(), OPERATION_PLAN);
    assert_eq!(lifecycle.execute(&haystack).unwrap(), 2_593);
}

#[test]
#[ignore = "requires the separately authenticated Rebar OpenSubtitles English corpus"]
fn authenticated_rebar_opensubtitles_corpus_returns_27() {
    let path =
        std::env::var_os("FRE_TOKEN_PHRASE_EN_HAYSTACK").expect("set FRE_TOKEN_PHRASE_EN_HAYSTACK");
    let haystack = std::fs::read(path).expect("read authenticated OpenSubtitles corpus");
    assert_eq!(haystack.len(), 613_357);
    assert_eq!(
        format!("{:x}", Sha256::digest(&haystack)),
        "07ff024bdc05f6c2b4bc0b5b768a332a18a616261fcbd16b41e953df1c7fa7ff"
    );
    let lifecycle = current_fre_rebar_aggregate_operation_lifecycle(
        "count-spans",
        &[ASSERTED_PATTERN.to_owned()],
        false,
        false,
        haystack.len(),
    )
    .expect("authenticated OpenSubtitles token-phrase lifecycle");
    assert_eq!(lifecycle.plan(), OPERATION_PLAN);
    assert_eq!(lifecycle.execute(&haystack).unwrap(), 27);
}
