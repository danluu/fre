//! Development-only release smoke comparison for the ordered literal-set DFA.

use std::hint::black_box;
use std::time::Instant;

use aho_corasick::packed::Searcher;
use fre_kernels::{LiteralSetBuildLimits, LiteralSetPlan, LiteralSetSearchLimits};

const ITERATIONS: usize = 2_000;
const PATTERNS: &[&[u8]] = &[b"foobar", b"foobaz", b"fooquux"];

fn main() {
    let mut haystack = b"foo-no-match/".repeat(4_000);
    haystack.extend_from_slice(b"foobaz");
    let plan = LiteralSetPlan::new(PATTERNS, LiteralSetBuildLimits::default()).unwrap();
    let packed = Searcher::new(PATTERNS).expect("SIMD packed searcher available on this target");
    let upstream = regex::bytes::RegexBuilder::new("foobar|foobaz|fooquux")
        .unicode(false)
        .build()
        .unwrap();
    let expected = upstream
        .find(&haystack)
        .map(|matched| (matched.start(), matched.end()));
    let actual = plan
        .find(&haystack, LiteralSetSearchLimits::unlimited())
        .unwrap()
        .0;
    assert_eq!(actual, expected);

    for _ in 0..20 {
        black_box(
            plan.find(black_box(&haystack), LiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
        );
        black_box(upstream.find(black_box(&haystack)));
        black_box(packed.find(black_box(&haystack)));
    }
    let plan_start = Instant::now();
    let mut plan_checksum = 0_usize;
    for _ in 0..ITERATIONS {
        plan_checksum = plan_checksum.wrapping_add(
            plan.find(black_box(&haystack), LiteralSetSearchLimits::unlimited())
                .unwrap()
                .0
                .map_or(0, |matched| matched.1),
        );
    }
    let plan_elapsed = plan_start.elapsed().as_nanos();
    let upstream_start = Instant::now();
    let mut upstream_checksum = 0_usize;
    for _ in 0..ITERATIONS {
        upstream_checksum = upstream_checksum.wrapping_add(
            upstream
                .find(black_box(&haystack))
                .map_or(0, |matched| matched.end()),
        );
    }
    let upstream_elapsed = upstream_start.elapsed().as_nanos();
    let packed_start = Instant::now();
    let mut packed_checksum = 0_usize;
    for _ in 0..ITERATIONS {
        packed_checksum = packed_checksum.wrapping_add(
            packed
                .find(black_box(&haystack))
                .map_or(0, |matched| matched.end()),
        );
    }
    let packed_elapsed = packed_start.elapsed().as_nanos();
    assert_eq!(plan_checksum, upstream_checksum);
    assert_eq!(packed_checksum, upstream_checksum);
    let denominator = u128::try_from(ITERATIONS).unwrap();
    println!("engine,iterations,elapsed_ns,ns_per_iteration,checksum");
    println!(
        "fre-literal-set-dfa,{ITERATIONS},{plan_elapsed},{},{}",
        plan_elapsed.checked_div(denominator).unwrap(),
        plan_checksum
    );
    println!(
        "rust-regex-1.12.4,{ITERATIONS},{upstream_elapsed},{},{}",
        upstream_elapsed.checked_div(denominator).unwrap(),
        upstream_checksum
    );
    println!(
        "aho-packed-teddy,{ITERATIONS},{packed_elapsed},{},{}",
        packed_elapsed.checked_div(denominator).unwrap(),
        packed_checksum
    );
    let build = plan.build_accounting();
    println!(
        "build,patterns={},pattern_bytes={},work_upper={},build_bytes_upper={},persistent_bytes={}",
        build.patterns,
        build.pattern_bytes,
        build.build_work_upper_bound,
        build.build_bytes_upper_bound,
        build.persistent_bytes
    );
}
