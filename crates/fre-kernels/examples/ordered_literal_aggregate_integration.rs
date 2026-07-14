#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_precision_loss,
    clippy::too_many_lines,
    clippy::type_complexity,
    reason = "standalone measurement driver uses checked fixtures and reports floating-point ns/iteration"
)]

use std::fmt::Write as _;
use std::hint::black_box;
use std::time::Instant;

use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind, packed::Searcher};
use fre_kernels::{
    OrderedLiteralAggregateBuildLimits, OrderedLiteralAggregateReduceLimits,
    OrderedLiteralCountPlan, OrderedLiteralSpanSumPlan, PackedOrderedLiteralAggregateBuildLimits,
    PackedOrderedLiteralAggregateReduceLimits, PackedOrderedLiteralCountPlan,
    PackedOrderedLiteralSpanSumPlan,
};
use regex::bytes::{Regex, RegexBuilder};

const REBAR_PATTERN: &[&[u8]] = &[
    b"Sherlock Holmes",
    b"John Watson",
    b"Irene Adler",
    b"Inspector Lestrade",
    b"Professor Moriarty",
];

struct Fixture {
    patterns: Vec<Vec<u8>>,
    haystack: Vec<u8>,
}

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 6 {
        eprintln!("usage: ordered_literal_aggregate_integration ENGINE CASE OP SIZE ITERS");
        std::process::exit(2);
    }
    let engine = &args[1];
    let case = &args[2];
    let operation = &args[3];
    let size = args[4].parse::<usize>().unwrap();
    let iterations = args[5].parse::<u64>().unwrap();
    let fixture = fixture(case, size);
    let oracle = regex(&fixture.patterns);
    let expected_count = u64::try_from(oracle.find_iter(&fixture.haystack).count()).unwrap();
    let expected_span = oracle
        .find_iter(&fixture.haystack)
        .map(|matched| u64::try_from(matched.end() - matched.start()).unwrap())
        .sum::<u64>();
    let expected = match operation.as_str() {
        "count" => expected_count,
        "span-sum" => expected_span,
        _ => panic!("unknown operation {operation}"),
    };

    let runner: Box<dyn Fn(&[u8]) -> u64> = match engine.as_str() {
        "reverse" => match operation.as_str() {
            "count" => {
                let plan = OrderedLiteralCountPlan::build(
                    &fixture.patterns,
                    OrderedLiteralAggregateBuildLimits::unlimited(),
                )
                .unwrap();
                Box::new(move |haystack| {
                    plan.count(haystack, OrderedLiteralAggregateReduceLimits::unlimited())
                        .unwrap()
                        .count
                })
            }
            "span-sum" => {
                let plan = OrderedLiteralSpanSumPlan::build(
                    &fixture.patterns,
                    OrderedLiteralAggregateBuildLimits::unlimited(),
                )
                .unwrap();
                Box::new(move |haystack| {
                    plan.span_sum(haystack, OrderedLiteralAggregateReduceLimits::unlimited())
                        .unwrap()
                        .span_sum
                })
            }
            _ => unreachable!(),
        },
        "rust" => match operation.as_str() {
            "count" => {
                Box::new(move |haystack| u64::try_from(oracle.find_iter(haystack).count()).unwrap())
            }
            "span-sum" => Box::new(move |haystack| {
                oracle
                    .find_iter(haystack)
                    .map(|matched| u64::try_from(matched.end() - matched.start()).unwrap())
                    .sum()
            }),
            _ => unreachable!(),
        },
        "ac" => {
            let searcher = AhoCorasick::builder()
                .kind(Some(AhoCorasickKind::DFA))
                .match_kind(MatchKind::LeftmostFirst)
                .build(fixture.patterns.iter().map(Vec::as_slice))
                .unwrap();
            match operation.as_str() {
                "count" => Box::new(move |haystack| {
                    u64::try_from(searcher.find_iter(haystack).count()).unwrap()
                }),
                "span-sum" => Box::new(move |haystack| {
                    searcher
                        .find_iter(haystack)
                        .map(|matched| u64::try_from(matched.end() - matched.start()).unwrap())
                        .sum()
                }),
                _ => unreachable!(),
            }
        }
        "packed" => {
            let searcher = Searcher::new(fixture.patterns.iter().map(Vec::as_slice))
                .expect("packed strategy unsupported for this fixture");
            match operation.as_str() {
                "count" => Box::new(move |haystack| {
                    u64::try_from(searcher.find_iter(haystack).count()).unwrap()
                }),
                "span-sum" => Box::new(move |haystack| {
                    searcher
                        .find_iter(haystack)
                        .map(|matched| u64::try_from(matched.end() - matched.start()).unwrap())
                        .sum()
                }),
                _ => unreachable!(),
            }
        }
        "packed-plan" => match operation.as_str() {
            "count" => {
                let plan = PackedOrderedLiteralCountPlan::build(
                    &fixture.patterns,
                    PackedOrderedLiteralAggregateBuildLimits::unlimited(),
                )
                .unwrap();
                Box::new(move |haystack| {
                    plan.count(
                        haystack,
                        PackedOrderedLiteralAggregateReduceLimits::unlimited(),
                    )
                    .unwrap()
                    .count
                })
            }
            "span-sum" => {
                let plan = PackedOrderedLiteralSpanSumPlan::build(
                    &fixture.patterns,
                    PackedOrderedLiteralAggregateBuildLimits::unlimited(),
                )
                .unwrap();
                Box::new(move |haystack| {
                    plan.span_sum(
                        haystack,
                        PackedOrderedLiteralAggregateReduceLimits::unlimited(),
                    )
                    .unwrap()
                    .span_sum
                })
            }
            _ => unreachable!(),
        },
        _ => panic!("unknown engine {engine}"),
    };
    assert_eq!(runner(&fixture.haystack), expected);
    for _ in 0..5 {
        black_box(runner(black_box(&fixture.haystack)));
    }
    let start = Instant::now();
    let mut checksum = 0_u64;
    for iteration in 0..iterations {
        let value = runner(black_box(&fixture.haystack));
        checksum = checksum
            .rotate_left(7)
            .wrapping_add(value)
            .wrapping_add(iteration);
    }
    let elapsed = start.elapsed().as_nanos();
    println!(
        "{engine},{case},{operation},{},{iterations},{elapsed},{:.3},{checksum},{expected}",
        fixture.haystack.len(),
        elapsed as f64 / iterations as f64,
    );
}

fn regex(patterns: &[Vec<u8>]) -> Regex {
    let mut source = String::from("(?:");
    for (index, pattern) in patterns.iter().enumerate() {
        if index != 0 {
            source.push('|');
        }
        for &byte in pattern {
            write!(&mut source, "\\x{byte:02X}").unwrap();
        }
    }
    source.push(')');
    RegexBuilder::new(&source).unicode(false).build().unwrap()
}

fn fixture(case: &str, size: usize) -> Fixture {
    match case {
        "rebar-sherlock" => {
            let checkout =
                std::env::var("REBAR_CHECKOUT").unwrap_or_else(|_| String::from("/tmp/rebar-fre"));
            let path = format!("{checkout}/benchmarks/haystacks/opensubtitles/en-sampled.txt");
            Fixture {
                patterns: REBAR_PATTERN
                    .iter()
                    .map(|pattern| pattern.to_vec())
                    .collect(),
                haystack: std::fs::read(path).unwrap(),
            }
        }
        "sparse" => {
            let mut haystack = vec![0x80; size];
            let patterns = vec![
                b"\xFF\x00needle".to_vec(),
                b"rare-two".to_vec(),
                b"third\xFE".to_vec(),
            ];
            if size >= 64 {
                let first = size / 3;
                let second = size * 2 / 3;
                haystack[first..first + patterns[0].len()].copy_from_slice(&patterns[0]);
                haystack[second..second + patterns[2].len()].copy_from_slice(&patterns[2]);
            }
            Fixture { patterns, haystack }
        }
        "dense" => Fixture {
            patterns: vec![b"ab".to_vec(), b"b".to_vec(), b"c".to_vec()],
            haystack: (0..size).map(|index| b"abc"[index % 3]).collect(),
        },
        "prefix" => {
            let mut first = vec![b'a'; 31];
            first.push(b'b');
            Fixture {
                patterns: vec![first, b"a".to_vec(), b"aa".to_vec()],
                haystack: vec![b'a'; size],
            }
        }
        "empty" => Fixture {
            patterns: vec![b"a".to_vec(), Vec::new(), b"bb".to_vec()],
            haystack: vec![b'b'; size],
        },
        "adversarial" => {
            let width = size.clamp(2, 1_024) / 2;
            let mut first = vec![b'a'; width];
            first.push(b'b');
            Fixture {
                patterns: vec![first, b"a".to_vec()],
                haystack: vec![b'a'; size],
            }
        }
        "joint-adversarial" => {
            let width = size.max(2) / 2;
            let mut first = vec![b'a'; width];
            first.push(b'b');
            Fixture {
                patterns: vec![first, b"a".to_vec()],
                haystack: vec![b'a'; size],
            }
        }
        _ => panic!("unknown fixture {case}"),
    }
}
