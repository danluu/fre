use fre::{AggregateManyBuildLimits, AggregateManyBuilder, AggregateManyRunLimits, RustProfile};
use regex::bytes::RegexBuilder;

struct Family {
    label: &'static str,
    patterns: &'static [&'static str],
    haystacks: &'static [&'static [u8]],
}

fn patterns(source: &[&str]) -> Vec<String> {
    source
        .iter()
        .map(|pattern| (*pattern).to_string())
        .collect()
}

fn spans(regex: &fre::AggregateManySpansRegex, haystack: &[u8]) -> Vec<(usize, usize)> {
    regex
        .spans(haystack, AggregateManyRunLimits::unlimited())
        .unwrap()
        .iter()
        .map(|matched| (matched.start(), matched.end()))
        .collect()
}

#[test]
fn ascii_word_shadow_is_a_parameterized_opt_in_theorem() {
    let families = [
        Family {
            label: "language keywords before identifiers",
            patterns: &[
                r"(\bif\b)",
                r"(\belse\b)",
                r"(\bwhile\b)",
                r"([a-z_][a-z0-9_]*)",
            ],
            haystacks: &[b"if value9 else _tail while 7zip", b"x iffy while_ else"],
        },
        Family {
            label: "uppercase protocol atoms before symbols",
            patterns: &[r"(\bYES\b)", r"(\bNO\b)", r"([A-Z][A-Z_]*)"],
            haystacks: &[b"YES MAYBE NO X_Y yes", b"NOPE YES _NO NO"],
        },
        Family {
            label: "hex sentinels before hex words",
            patterns: &[r"(\bBEEF\b)", r"(\bFACE\b)", r"([A-F][A-F0-9]*)"],
            haystacks: &[b"BEEF FACE C0DE cafe 0BAD", b"A F00 BEEFY FACE"],
        },
    ];

    for family in families {
        let sources = patterns(family.patterns);
        let generic = AggregateManyBuilder::new(&sources)
            .profile(RustProfile::rebar_1_12_4())
            .unicode(false)
            .build_spans()
            .unwrap_or_else(|error| panic!("{} generic build: {error}", family.label));
        let proof = generic
            .build_report()
            .ascii_word_shadow
            .unwrap_or_else(|| panic!("{} did not select the generic theorem", family.label));
        assert!(proof.shadowed_patterns >= 1, "{}", family.label);

        let mut quarantined_limits = AggregateManyBuildLimits::default();
        quarantined_limits
            .continuation
            .allow_workload_specific_intrinsics = false;
        let quarantined = AggregateManyBuilder::new(&sources)
            .profile(RustProfile::rebar_1_12_4())
            .unicode(false)
            .limits(quarantined_limits)
            .build_spans()
            .unwrap_or_else(|error| panic!("{} quarantined build: {error}", family.label));
        assert!(
            quarantined.build_report().ascii_word_shadow.is_none(),
            "{}",
            family.label
        );

        let alternation = family.patterns.join("|");
        let oracle = RegexBuilder::new(&alternation)
            .unicode(false)
            .build()
            .unwrap_or_else(|error| panic!("{} oracle: {error}", family.label));
        for &haystack in family.haystacks {
            let expected = oracle
                .find_iter(haystack)
                .map(|matched| (matched.start(), matched.end()))
                .collect::<Vec<_>>();
            assert_eq!(spans(&generic, haystack), expected, "{}", family.label);
            assert_eq!(
                spans(&quarantined, haystack),
                expected,
                "{} quarantined",
                family.label
            );
        }
    }
}
