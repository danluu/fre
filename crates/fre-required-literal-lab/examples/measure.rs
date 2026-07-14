//! Reproducible release-mode smoke measurements for the laboratory plan.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "measurement loop counters and elapsed-time division use tiny controlled values"
)]

use std::{hint::black_box, time::Instant};

use fre_required_literal_lab::{
    Anchors, BuildLimits, ByteClass, RequiredLiteralPlan, SearchLimits,
};
use regex::bytes::{Regex, RegexBuilder};

#[derive(Clone, Debug)]
struct Case {
    name: &'static str,
    class: ByteClass,
    suffix: Vec<u8>,
    anchors: Anchors,
    haystack: Vec<u8>,
}

fn main() {
    println!(
        "category,case,pattern_bytes,haystack_bytes,engine,phase,iterations,median_ns_per_op,work_upper_bound,match_start,match_end"
    );
    let cases = performance_cases();
    for case in &cases {
        measure_case("performance", case);
    }
    for size in [1_024_usize, 4_096, 16_384, 65_536, 262_144] {
        let suffix = vec![b'Z'];
        let case = positive_case("fixed_pattern", size, suffix);
        measure_case("scaling_fixed_pattern", &case);
    }
    for suffix_len in [1_usize, 4, 16, 64, 256] {
        let suffix = unbordered_suffix(suffix_len);
        let case = positive_case("fixed_haystack", 65_536, suffix);
        measure_case("scaling_fixed_haystack", &case);
    }
    for (suffix_len, haystack_len) in [
        (1_usize, 1_024_usize),
        (4, 4_096),
        (16, 16_384),
        (64, 65_536),
        (256, 262_144),
    ] {
        let suffix = unbordered_suffix(suffix_len);
        let case = positive_case("joint", haystack_len, suffix);
        measure_case("scaling_joint", &case);
    }
}

fn performance_cases() -> Vec<Case> {
    let class = ByteClass::inclusive(b'a', b'z');
    let mut positive = vec![b'a'; 65_535];
    positive.push(b'Z');
    let negative = vec![b'a'; 65_536];
    let mut candidates = Vec::with_capacity(65_536);
    for _ in 0..32_768 {
        candidates.extend_from_slice(b"!Z");
    }
    let suffix = b"END".to_vec();
    let mut non_rebar = vec![b'x'; 65_533];
    non_rebar.extend_from_slice(&suffix);
    vec![
        Case {
            name: "positive_class_run",
            class,
            suffix: vec![b'Z'],
            anchors: Anchors::default(),
            haystack: positive.clone(),
        },
        Case {
            name: "negative_no_suffix",
            class,
            suffix: vec![b'Z'],
            anchors: Anchors::default(),
            haystack: negative,
        },
        Case {
            name: "adversarial_many_candidates",
            class,
            suffix: vec![b'Z'],
            anchors: Anchors::default(),
            haystack: candidates,
        },
        Case {
            name: "non_rebar_multibyte_suffix",
            class,
            suffix,
            anchors: Anchors::default(),
            haystack: non_rebar,
        },
        Case {
            name: "absolute_both_anchors",
            class,
            suffix: vec![b'Z'],
            anchors: Anchors {
                start: true,
                end: true,
            },
            haystack: positive,
        },
    ]
}

fn positive_case(name: &'static str, haystack_len: usize, suffix: Vec<u8>) -> Case {
    let prefix_len = haystack_len.saturating_sub(suffix.len());
    let mut haystack = vec![b'a'; prefix_len];
    haystack.extend_from_slice(&suffix);
    Case {
        name,
        class: ByteClass::inclusive(b'a', b'z'),
        suffix,
        anchors: Anchors::default(),
        haystack,
    }
}

fn unbordered_suffix(len: usize) -> Vec<u8> {
    let mut suffix = vec![b'Q'; len];
    if let Some(first) = suffix.first_mut() {
        *first = b'Z';
    }
    suffix
}

fn measure_case(category: &str, case: &Case) {
    let plan = RequiredLiteralPlan::build(
        case.class,
        &case.suffix,
        case.anchors,
        BuildLimits::default(),
    )
    .unwrap();
    let regex_pattern = pattern(&case.suffix, case.anchors);
    let regex = compile_regex(&regex_pattern);
    let (found, accounting) = plan
        .find(&case.haystack, SearchLimits::unlimited())
        .unwrap();
    let expected = regex.find(&case.haystack);
    assert_eq!(
        found.map(|matched| (matched.start(), matched.end())),
        expected.map(|matched| (matched.start(), matched.end()))
    );
    let iterations = if case.haystack.len() <= 4_096 {
        2_000
    } else if case.haystack.len() <= 65_536 {
        300
    } else {
        80
    };
    let plan_hot = median_ns(iterations, || {
        black_box(
            plan.find(black_box(&case.haystack), SearchLimits::unlimited())
                .unwrap()
                .0,
        );
    });
    let regex_hot = median_ns(iterations, || {
        black_box(regex.find(black_box(&case.haystack)));
    });
    emit(
        category,
        case,
        "fre-required-literal",
        "hot_find",
        iterations,
        plan_hot,
        accounting.work_upper_bound,
        found.map(|matched| (matched.start(), matched.end())),
    );
    emit(
        category,
        case,
        "rust-regex-1.12.4-rebar-config",
        "hot_find",
        iterations,
        regex_hot,
        0,
        expected.map(|matched| (matched.start(), matched.end())),
    );

    if category != "performance" {
        return;
    }
    let cold_iterations = 50;
    let plan_cold = median_ns(cold_iterations, || {
        black_box(
            RequiredLiteralPlan::build(
                black_box(case.class),
                black_box(&case.suffix),
                black_box(case.anchors),
                BuildLimits::default(),
            )
            .unwrap(),
        );
    });
    let regex_cold = median_ns(cold_iterations, || {
        black_box(compile_regex(black_box(&regex_pattern)));
    });
    emit(
        category,
        case,
        "fre-required-literal",
        "cold_kernel_build",
        cold_iterations,
        plan_cold,
        plan.build_accounting().work_upper_bound,
        found.map(|matched| (matched.start(), matched.end())),
    );
    emit(
        category,
        case,
        "rust-regex-1.12.4-rebar-config",
        "cold_full_compile",
        cold_iterations,
        regex_cold,
        0,
        expected.map(|matched| (matched.start(), matched.end())),
    );
}

#[allow(
    clippy::too_many_arguments,
    reason = "each CSV column is intentionally explicit in this evidence emitter"
)]
fn emit(
    category: &str,
    case: &Case,
    engine: &str,
    phase: &str,
    iterations: usize,
    median_ns: u128,
    work_upper_bound: u64,
    matched: Option<(usize, usize)>,
) {
    let (start, end) = matched.map_or((String::new(), String::new()), |(start, end)| {
        (start.to_string(), end.to_string())
    });
    println!(
        "{category},{},{},{},{engine},{phase},{iterations},{median_ns},{work_upper_bound},{start},{end}",
        case.name,
        case.suffix.len(),
        case.haystack.len()
    );
}

fn median_ns(mut iterations: usize, mut run: impl FnMut()) -> u128 {
    iterations = iterations.max(1);
    for _ in 0..iterations {
        run();
    }
    let mut samples = [0_u128; 7];
    for sample in &mut samples {
        let start = Instant::now();
        for _ in 0..iterations {
            run();
        }
        *sample = start.elapsed().as_nanos() / u128::try_from(iterations).unwrap();
    }
    samples.sort_unstable();
    samples[samples.len() / 2]
}

fn compile_regex(pattern: &str) -> Regex {
    RegexBuilder::new(pattern).unicode(false).build().unwrap()
}

fn pattern(suffix: &[u8], anchors: Anchors) -> String {
    use std::fmt::Write as _;

    let mut pattern = String::from("(?-u:");
    if anchors.start {
        pattern.push_str(r"\A");
    }
    pattern.push_str("[a-z]+");
    for &byte in suffix {
        write!(pattern, r"\x{byte:02X}").unwrap();
    }
    if anchors.end {
        pattern.push_str(r"\z");
    }
    pattern.push(')');
    pattern
}
