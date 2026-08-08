//! Release-mode smoke evidence for production required-literal routing.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "fixed-size measurement loops and checksum wrapping are controlled"
)]

use std::{hint::black_box, time::Instant};

use fre::{PlanKind, PlanSelection, PortableBuilder, SearchLimits};

const ITERATIONS: usize = 300;

struct Case {
    name: &'static str,
    pattern: &'static str,
    force: bool,
    haystack: Vec<u8>,
}

fn main() {
    println!(
        "case,route,plan,pattern_bytes,haystack_bytes,sample,engine,iterations,elapsed_ns,ns_per_iteration,match_start,match_end"
    );
    for case in cases() {
        measure(&case);
    }
}

fn cases() -> Vec<Case> {
    let mut late = b"0123456789".repeat(5_000);
    late.extend_from_slice(b"alphabeticZ");
    let mut positive = vec![b'a'; 65_535];
    positive.push(b'Z');
    let negative = vec![b'a'; 65_536];
    let mut candidates = Vec::with_capacity(65_536);
    for _ in 0..32_768 {
        candidates.extend_from_slice(b"!Z");
    }
    let mut multibyte = vec![b'x'; 65_533];
    multibyte.extend_from_slice(b"END");
    vec![
        Case {
            name: "late-short-run",
            pattern: "[a-z]+Z",
            force: false,
            haystack: late,
        },
        Case {
            name: "positive-class-run",
            pattern: "[a-z]+Z",
            force: false,
            haystack: positive.clone(),
        },
        Case {
            name: "negative-no-suffix",
            pattern: "[a-z]+Z",
            force: false,
            haystack: negative,
        },
        Case {
            name: "adversarial-candidates",
            pattern: "[a-z]+Z",
            force: false,
            haystack: candidates,
        },
        Case {
            name: "multibyte-suffix",
            pattern: "[a-z]+END",
            force: false,
            haystack: multibyte,
        },
        Case {
            name: "absolute-start",
            pattern: r"\A[a-z]+Z",
            force: false,
            haystack: positive.clone(),
        },
        Case {
            name: "absolute-end",
            pattern: r"[a-z]+Z\z",
            force: false,
            haystack: positive.clone(),
        },
        Case {
            name: "absolute-both-auto",
            pattern: r"\A[a-z]+Z\z",
            force: false,
            haystack: positive.clone(),
        },
        Case {
            name: "absolute-both-forced",
            pattern: r"\A[a-z]+Z\z",
            force: true,
            haystack: positive,
        },
    ]
}

fn measure(case: &Case) {
    let mut builder = PortableBuilder::new(case.pattern).unicode(false);
    if case.force {
        builder = builder.plan_selection(PlanSelection::ForceRequiredLiteral);
    }
    let fre = builder.build().unwrap();
    let upstream = regex::bytes::RegexBuilder::new(case.pattern)
        .unicode(false)
        .build()
        .unwrap();
    let expected = upstream
        .find(&case.haystack)
        .map(|matched| (matched.start(), matched.end()));
    let actual = fre
        .find(&case.haystack, SearchLimits::unlimited())
        .unwrap()
        .0
        .map(|matched| (matched.start(), matched.end()));
    assert_eq!(actual, expected);
    for _ in 0..10 {
        black_box(
            fre.find(black_box(&case.haystack), SearchLimits::unlimited())
                .unwrap()
                .0,
        );
        black_box(upstream.find(black_box(&case.haystack)));
    }
    for sample in 0..7 {
        let started = Instant::now();
        for _ in 0..ITERATIONS {
            black_box(
                fre.find(black_box(&case.haystack), SearchLimits::unlimited())
                    .unwrap()
                    .0,
            );
        }
        emit(
            case,
            fre.build_report().plan,
            sample,
            "fre-facade",
            started.elapsed().as_nanos(),
            actual,
        );

        let started = Instant::now();
        for _ in 0..ITERATIONS {
            black_box(upstream.find(black_box(&case.haystack)));
        }
        emit(
            case,
            fre.build_report().plan,
            sample,
            "rust-regex-1.12.4",
            started.elapsed().as_nanos(),
            expected,
        );
    }
}

fn emit(
    case: &Case,
    plan: PlanKind,
    sample: usize,
    engine: &str,
    elapsed_ns: u128,
    matched: Option<(usize, usize)>,
) {
    let route = if case.force { "forced" } else { "auto" };
    let plan = match plan {
        PlanKind::ExactLiteral => "exact-literal",
        PlanKind::PackedLiteralSet => "packed-literal-set",
        PlanKind::LiteralSetDfa => "literal-set-dfa",
        PlanKind::RequiredLiteral => "required-literal-v1",
        PlanKind::LiteralClassRunLiteral => "literal-class-run-literal-v1",
        PlanKind::ReverseInner => "reverse-inner-v1",
        PlanKind::PrefixClassAlternation => "prefix-class-alternation-v1",
        PlanKind::ForwardAnchored => "anchored-class-suffix-forward-v1",
        PlanKind::K0 => "k0",
        PlanKind::UnicodeFoldedLiteral => "unicode-folded-literal-first-start-v1",
        PlanKind::UnicodeWordRun => "unicode-word-run-linear-v1",
        PlanKind::PureByteClassRepeat => "pure-byte-class-repeat-v1",
        PlanKind::BoundedByteClassSequence => "bounded-byte-class-sequence-search-v2",
        PlanKind::FixedPredicateWord64 => "fixed-predicate-word64-first-match-v1",
        PlanKind::UnicodeScalarRun => "unicode-scalar-run-search-v1",
        PlanKind::LineDomainByteAtoms => "line-domain-byte-atoms-search-v3",
    };
    let per_iteration = elapsed_ns / u128::try_from(ITERATIONS).unwrap();
    let (start, end) = matched.map_or((String::new(), String::new()), |(start, end)| {
        (start.to_string(), end.to_string())
    });
    println!(
        "{},{route},{plan},{},{},{sample},{engine},{ITERATIONS},{elapsed_ns},{per_iteration},{start},{end}",
        case.name,
        case.pattern.len(),
        case.haystack.len()
    );
}
