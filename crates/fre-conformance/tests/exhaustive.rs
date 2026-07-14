use fre_conformance::{
    Agreement, ConformanceCase, GeneratedCorpus, GeneratorLimits, Harness, HarnessLimits, Outcome,
    generate_small_exhaustive,
};

fn corpus() -> GeneratedCorpus {
    match generate_small_exhaustive(0x4652_452d_5345_4544, GeneratorLimits::default()) {
        Outcome::Value(corpus) => corpus,
        outcome => panic!("corpus generation refused unexpectedly: {outcome:?}"),
    }
}

#[test]
fn finite_small_grammar_is_exhaustively_equal() {
    let corpus = corpus();
    assert!(!corpus.truncated);
    assert_eq!(corpus.patterns.len(), corpus.planned_patterns);
    assert_eq!(corpus.haystacks.len(), corpus.planned_haystacks);

    let harness = Harness::new(HarnessLimits::default());
    let mut ordinal = 0_u64;
    for (pattern_index, pattern) in corpus.patterns.iter().enumerate() {
        for (haystack_index, haystack) in corpus.haystacks.iter().enumerate() {
            let case = ConformanceCase::full(
                format!("generated-{pattern_index}-{haystack_index}"),
                corpus.seed,
                ordinal,
                pattern.clone(),
                haystack.clone(),
            );
            let record = harness.compare(&case);
            assert_eq!(
                record.agreement,
                Agreement::Equal,
                "pattern={pattern:?}, haystack={haystack:?}, record={record:?}"
            );
            ordinal = ordinal.checked_add(1).expect("bounded generated cases");
        }
    }
    assert_eq!(ordinal, 2_976);
}

#[test]
fn generation_caps_are_visible_not_silent() {
    let generated = generate_small_exhaustive(
        1,
        GeneratorLimits {
            max_patterns: 3,
            max_haystacks: 2,
            max_haystack_len: 4,
            max_comparisons: 4,
        },
    );
    let Outcome::Value(corpus) = generated else {
        panic!("small capped corpus should be representable");
    };
    assert!(corpus.truncated);
    assert!(corpus.patterns.len() * corpus.haystacks.len() <= 4);
}
