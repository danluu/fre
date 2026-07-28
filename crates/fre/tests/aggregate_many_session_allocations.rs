#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{AggregateManyBuilder, AggregateManyCaptureRunLimits, AggregateStrategy, RustProfile};
use regex_automata::{Input, meta::Regex as MetaRegex};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn reference_capture_count(patterns: &[String], haystack: &[u8]) -> u64 {
    let regex = MetaRegex::builder()
        .configure(MetaRegex::config().utf8_empty(false))
        .syntax(
            regex_automata::util::syntax::Config::new()
                .utf8(false)
                .unicode(false),
        )
        .build_many(patterns)
        .unwrap();
    let mut input = Input::new(haystack);
    let mut captures = regex.create_captures();
    let mut count = 0_u64;
    loop {
        regex.search_captures(&input, &mut captures);
        let Some(matched) = captures.get_match() else {
            break;
        };
        count = count
            .checked_add(u64::try_from(captures.iter().flatten().count()).unwrap())
            .unwrap();
        input.set_start(matched.end());
    }
    count
}

#[test]
fn aggregate_many_byte_cover_session_has_zero_steady_allocator_activity() {
    let patterns = vec![
        r"(\balways_comb\b)".to_owned(),
        r"([A-Za-z_][A-Za-z0-9_]*)".to_owned(),
        r"(\r\n|\r|\n)".to_owned(),
        r"(.)".to_owned(),
    ];
    let regex = AggregateManyBuilder::new(&patterns)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(false)
        .strategy(AggregateStrategy::ReverseSequentialRows)
        .build_capture_count()
        .unwrap();
    let sources: [&[u8]; 3] = [b"always_comb!", b"alpha_\xff beta", b"\xff\xfe !?\tvalue!"];
    let expected = sources
        .iter()
        .map(|source| reference_capture_count(&patterns, source))
        .collect::<Vec<_>>();
    let limits = AggregateManyCaptureRunLimits::unlimited();
    let mut session = regex
        .prepare_cached_count_session(sources[0].len(), limits)
        .unwrap()
        .expect("proved byte-cover session");

    regex
        .count_captures_value_with_session(&mut session, sources[0], limits)
        .unwrap();
    let region = Region::new(GLOBAL);
    for (index, source) in sources.into_iter().cycle().take(18).enumerate() {
        let actual = regex
            .count_captures_value_with_session(&mut session, source, limits)
            .unwrap();
        assert_eq!(expected[index % expected.len()], actual);
    }
    assert_eq!(Stats::default(), region.change());
}
