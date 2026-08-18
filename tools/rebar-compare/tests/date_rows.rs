use std::fs;

use bstr::ByteSlice;
use rebar_compare::{
    CURRENT_FRE_REBAR_COMPLETE_SPANS_LARGE_CONTINUATION_PLAN,
    CURRENT_FRE_REBAR_COMPLETE_SPANS_PLAN_PREFIX, current_fre_rebar_complete_spans_regex,
    current_fre_rebar_complete_spans_regex_for_haystack,
};
use sha2::{Digest, Sha256};

const BASE: &str = "c852de243e39ea3495918809741e619f74c356f6";
const PATTERN_SHA256: &str = "97cd171850089efa20adec84678649a72ccf0d75170baaff15a5219042b0e46d";
const HAYSTACK_SHA256: &str = "e27b1bdbd4242ac5b62fc2f80205ca693298cecae7be04242c78aa96f1f1d5e9";

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn date_input() -> (String, Vec<u8>) {
    let root = std::env::var("FRE_EXACT_REBAR_CHECKOUT").expect("exact Rebar checkout");
    let pattern_source = fs::read(format!("{root}/benchmarks/regexes/wild/date.txt"))
        .expect("authenticated Date pattern source");
    assert_eq!(
        sha256(&pattern_source),
        "0d223554e54ce6bfb34bbb3aa510a4a0941a3856882c64b0d971cc6b10f893bf"
    );
    let pattern = std::str::from_utf8(&pattern_source)
        .expect("Date pattern is UTF-8")
        .trim_end_matches(['\r', '\n'])
        .to_string();
    assert_eq!(pattern.len(), 6_348);
    assert_eq!(sha256(pattern.as_bytes()), PATTERN_SHA256);

    let full = fs::read(format!(
        "{root}/benchmarks/haystacks/rust-src-tools-3b0d4813.txt"
    ))
    .expect("authenticated Date source haystack");
    assert_eq!(
        sha256(&full),
        "7d43cc8dfd053b083b809bd7ce7d4a074f2fd24a6b7ec38908b3966f3324fa36"
    );
    let haystack = bstr::concat(full.lines_with_terminator().take(200_000).skip(190_000));
    assert_eq!(haystack.len(), 268_796);
    assert_eq!(sha256(&haystack), HAYSTACK_SHA256);
    (pattern, haystack)
}

fn assert_exact_fixture_uses_formal_large_continuation_sweep(
    unicode: bool,
    row_id: &str,
    expected: u64,
) {
    let (pattern, haystack) = date_input();
    let incumbent = current_fre_rebar_complete_spans_regex(pattern.clone(), unicode, true)
        .expect("Date lifecycle construction");
    assert_eq!(
        incumbent.plan(),
        format!("{CURRENT_FRE_REBAR_COMPLETE_SPANS_PLAN_PREFIX}-k0-k0")
    );
    let regex =
        current_fre_rebar_complete_spans_regex_for_haystack(pattern, unicode, true, haystack.len())
            .expect("formal Date lifecycle construction");
    assert_eq!(
        regex.plan(),
        format!(
            "{CURRENT_FRE_REBAR_COMPLETE_SPANS_LARGE_CONTINUATION_PLAN}-formal-large-continuation-raw-span-sweep-v1"
        )
    );
    let mut session = regex.session(haystack.len()).expect("Date session");
    let actual = session.execute(&haystack).expect("Date execution");
    assert_eq!(actual, expected, "unexpected {row_id} result");
    println!(
        "date-row-pass base={BASE} row={row_id} pattern_sha256={PATTERN_SHA256} haystack_sha256={HAYSTACK_SHA256} actual={actual}"
    );
}

#[test]
#[ignore = "requires the separately authenticated exact Rebar fixture"]
fn curated_03_date_ascii_exact_current_canary() {
    std::thread::Builder::new()
        .name("exact-date-ascii-canary".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            assert_exact_fixture_uses_formal_large_continuation_sweep(
                false,
                "curated/03-date/ascii@rust/regex",
                111_817,
            );
        })
        .expect("spawn exact Date ASCII canary")
        .join()
        .expect("exact Date ASCII canary");
}

#[test]
#[ignore = "requires the separately authenticated exact Rebar fixture"]
fn curated_03_date_unicode_exact_current_canary() {
    std::thread::Builder::new()
        .name("exact-date-unicode-canary".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            assert_exact_fixture_uses_formal_large_continuation_sweep(
                true,
                "curated/03-date/unicode@rust/regex",
                111_841,
            );
        })
        .expect("spawn exact Date Unicode canary")
        .join()
        .expect("exact Date Unicode canary");
}
