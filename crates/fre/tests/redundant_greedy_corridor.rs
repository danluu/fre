use fre::{
    AggregateBuilder, AggregateRunLimits, PortableBuilder, PortableFindIterRunLimits, RustProfile,
    SearchSessionLimits,
};
use regex::bytes::RegexBuilder;

const PATTERNS: [&str; 4] = [".*=.*", ".*.*=.*", "(?:.*.*=.*)", ".*.*:.*"];

fn portable_builder(pattern: &str) -> PortableBuilder {
    PortableBuilder::new(pattern).profile(RustProfile::rebar_1_12_4())
}

fn expected_spans(oracle: &regex::bytes::Regex, haystack: &[u8]) -> Vec<(usize, usize)> {
    oracle
        .find_iter(haystack)
        .map(|matched| (matched.start(), matched.end()))
        .collect()
}

fn with_large_stack(test: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .name("redundant-greedy-corridor".to_owned())
        .stack_size(32 * 1024 * 1024)
        .spawn(test)
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn redundant_greedy_corridor_spellings_match_oracle_exhaustively() {
    with_large_stack(|| {
        let alphabet = [b'x', b'=', b':', b'\n', 0, 0xFF];
        let mut haystack = Vec::new();

        for pattern in PATTERNS {
            let regex = portable_builder(pattern).unicode(false).build().unwrap();
            let oracle = RegexBuilder::new(pattern).unicode(false).build().unwrap();
            let mut session = regex
                .search_session(SearchSessionLimits::unlimited())
                .unwrap();

            for len in 0..=4 {
                let cases = alphabet.len().pow(u32::try_from(len).unwrap());
                for mut encoded in 0..cases {
                    haystack.clear();
                    for _ in 0..len {
                        haystack.push(alphabet[encoded % alphabet.len()]);
                        encoded /= alphabet.len();
                    }

                    let expected = expected_spans(&oracle, &haystack);
                    let actual: Vec<_> = session
                        .find_iter_value(&haystack, PortableFindIterRunLimits::unlimited())
                        .map(|result| {
                            let matched = result.unwrap();
                            (matched.start(), matched.end())
                        })
                        .collect();
                    assert_eq!(
                        expected, actual,
                        "pattern={pattern:?}, haystack={haystack:?}"
                    );
                }
            }
        }
    });
}

#[test]
fn redundant_greedy_corridor_materialized_spans_match_oracle() {
    with_large_stack(|| {
        let haystacks: &[&[u8]] = &[
            b"",
            b"none",
            b"=first\nnone\nleft=right\nlast=",
            b":first\nnone\nleft:right\nlast:",
            b"a=b:c\n::\n==\n",
            b"\xff=\0:\n=:\xff",
        ];

        for pattern in PATTERNS {
            let regex = AggregateBuilder::new(pattern)
                .profile(RustProfile::rebar_1_12_4())
                .unicode(false)
                .build_spans()
                .unwrap();
            let oracle = RegexBuilder::new(pattern).unicode(false).build().unwrap();

            for &haystack in haystacks {
                let expected = expected_spans(&oracle, haystack);
                let spans = regex
                    .spans(haystack, AggregateRunLimits::default())
                    .unwrap();
                let actual: Vec<_> = spans
                    .iter()
                    .map(|matched| (matched.start(), matched.end()))
                    .collect();
                assert_eq!(
                    expected, actual,
                    "pattern={pattern:?}, haystack={haystack:?}"
                );
            }
        }
    });
}
