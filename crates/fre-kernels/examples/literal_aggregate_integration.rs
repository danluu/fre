//! Release driver for complete exact-literal reducers.

use std::{
    env, fmt::Write as _, fs, hint::black_box, path::PathBuf, process::ExitCode, time::Instant,
};

use fre_kernels::{
    LiteralAggregateBuildLimits, LiteralAggregatePlan, LiteralAggregateReduceLimits,
};
use regex::bytes::{Regex, RegexBuilder};

#[derive(Clone, Copy)]
enum Operation {
    Count,
    SpanSum,
}

impl Operation {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "count" => Some(Self::Count),
            "span-sum" => Some(Self::SpanSum),
            _ => None,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Count => "count",
            Self::SpanSum => "span-sum",
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let engine = args
        .next()
        .ok_or("usage: ENGINE CASE OPERATION SIZE ITERATIONS")?;
    let case = args.next().ok_or("missing CASE")?;
    let operation = Operation::parse(&args.next().ok_or("missing OPERATION")?)
        .ok_or("OPERATION must be count or span-sum")?;
    let requested_size = args
        .next()
        .ok_or("missing SIZE")?
        .parse::<usize>()
        .map_err(|error| format!("invalid SIZE: {error}"))?;
    let iterations = args
        .next()
        .ok_or("missing ITERATIONS")?
        .parse::<u64>()
        .map_err(|error| format!("invalid ITERATIONS: {error}"))?;
    if iterations == 0 || args.next().is_some() {
        return Err("ITERATIONS must be positive and no extra arguments are accepted".into());
    }

    let fixture = fixture(&case, requested_size)?;
    let aggregate =
        LiteralAggregatePlan::build(&fixture.needle, LiteralAggregateBuildLimits::unlimited())
            .map_err(|error| error.to_string())?;
    let rust = rust_regex(&fixture.needle)?;
    let oracle_count = u64::try_from(rust.find_iter(&fixture.haystack).count())
        .map_err(|_| "oracle count does not fit u64")?;
    let oracle_span_sum = oracle_count
        .checked_mul(u64::try_from(fixture.needle.len()).map_err(|_| "needle does not fit u64")?)
        .ok_or("oracle span sum overflow")?;
    if let Some(expected_count) = fixture.expected_count
        && oracle_count != expected_count
    {
        return Err(format!(
            "authenticated fixture expected {expected_count} matches, observed {oracle_count}"
        ));
    }
    let aggregate_count = aggregate
        .count(&fixture.haystack, LiteralAggregateReduceLimits::unlimited())
        .map_err(|error| error.to_string())?
        .count;
    let aggregate_span_sum = aggregate
        .span_sum(&fixture.haystack, LiteralAggregateReduceLimits::unlimited())
        .map_err(|error| error.to_string())?
        .span_sum;
    if aggregate_count != oracle_count || aggregate_span_sum != oracle_span_sum {
        return Err(format!(
            "pre-timing mismatch: aggregate ({aggregate_count}, {aggregate_span_sum}), oracle ({oracle_count}, {oracle_span_sum})"
        ));
    }

    let expected = match operation {
        Operation::Count => oracle_count,
        Operation::SpanSum => oracle_span_sum,
    };
    let (elapsed, checksum, plan) = match engine.as_str() {
        "aggregate" => time_aggregate(&aggregate, &fixture.haystack, operation, iterations)?,
        "rust" => time_rust(&rust, &fixture.haystack, operation, iterations)?,
        _ => return Err(format!("unknown ENGINE {engine:?}")),
    };
    let total_ns = elapsed.as_nanos();
    let ns_per_iteration_milli = total_ns
        .checked_mul(1_000)
        .ok_or("nanosecond scaling overflow")?
        .checked_div(u128::from(iterations))
        .ok_or("iteration division failed")?;
    println!(
        "{engine},{case},{},{},{iterations},{total_ns},{}.{:03},{checksum},{expected},{plan}",
        operation.name(),
        fixture.haystack.len(),
        ns_per_iteration_milli / 1_000,
        ns_per_iteration_milli % 1_000,
    );
    Ok(())
}

struct Fixture {
    needle: Vec<u8>,
    haystack: Vec<u8>,
    expected_count: Option<u64>,
}

fn fixture(case: &str, requested_size: usize) -> Result<Fixture, String> {
    let make_cycle = |bytes: &[u8], size: usize| -> Vec<u8> {
        bytes.iter().copied().cycle().take(size).collect()
    };
    match case {
        "positive" => {
            let needle = b"Sherlock Holmes".to_vec();
            let size = requested_size.max(needle.len());
            let mut haystack = vec![b'x'; size];
            let mut position = 997_usize;
            loop {
                let Some(end) = position.checked_add(needle.len()) else {
                    break;
                };
                if end > size {
                    break;
                }
                haystack[position..end].copy_from_slice(&needle);
                position = position
                    .checked_add(4_096)
                    .ok_or("fixture stride overflow")?;
            }
            let final_start = size
                .checked_sub(needle.len())
                .ok_or("positive size underflow")?;
            haystack[final_start..].copy_from_slice(&needle);
            Ok(Fixture {
                needle,
                haystack,
                expected_count: None,
            })
        }
        "negative" => Ok(Fixture {
            needle: b"Sherlock Holmes".to_vec(),
            haystack: vec![b'x'; requested_size],
            expected_count: Some(0),
        }),
        "dense" => Ok(Fixture {
            needle: b"a".to_vec(),
            haystack: vec![b'a'; requested_size],
            expected_count: Some(u64::try_from(requested_size).unwrap_or(u64::MAX)),
        }),
        "overlapping" => Ok(Fixture {
            needle: b"aba".to_vec(),
            haystack: make_cycle(b"ababa", requested_size),
            expected_count: None,
        }),
        "empty" => Ok(Fixture {
            needle: Vec::new(),
            haystack: make_cycle(b"\xFFa\x80\0", requested_size),
            expected_count: u64::try_from(requested_size)
                .ok()
                .and_then(|size| size.checked_add(1)),
        }),
        "short-positive" => {
            let needle = b"ab".to_vec();
            let size = requested_size.max(needle.len());
            let mut haystack = vec![b'x'; size];
            let start = size
                .checked_sub(needle.len())
                .ok_or("short size underflow")?;
            haystack[start..].copy_from_slice(&needle);
            Ok(Fixture {
                needle,
                haystack,
                expected_count: Some(1),
            })
        }
        "rebar-sherlock" => {
            let checkout = env::var_os("REBAR_CHECKOUT")
                .map_or_else(|| PathBuf::from("/tmp/rebar-fre"), PathBuf::from);
            let path = checkout.join("benchmarks/haystacks/opensubtitles/en-sampled.txt");
            let haystack = fs::read(&path)
                .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
            if haystack.len() != 899_232 {
                return Err(format!(
                    "authenticated Sherlock haystack length is {}, expected 899232",
                    haystack.len()
                ));
            }
            Ok(Fixture {
                needle: b"Sherlock Holmes".to_vec(),
                haystack,
                expected_count: Some(513),
            })
        }
        _ => Err(format!("unknown CASE {case:?}")),
    }
}

fn rust_regex(needle: &[u8]) -> Result<Regex, String> {
    let mut pattern = String::new();
    for &byte in needle {
        write!(&mut pattern, "\\x{byte:02X}").map_err(|error| error.to_string())?;
    }
    RegexBuilder::new(&pattern)
        .unicode(false)
        .build()
        .map_err(|error| error.to_string())
}

fn time_aggregate(
    plan: &LiteralAggregatePlan,
    haystack: &[u8],
    operation: Operation,
    iterations: u64,
) -> Result<(std::time::Duration, u64, &'static str), String> {
    let start = Instant::now();
    let mut checksum = 0_u64;
    for iteration in 0..iterations {
        let value = match operation {
            Operation::Count => {
                plan.count(
                    black_box(haystack),
                    LiteralAggregateReduceLimits::unlimited(),
                )
                .map_err(|error| error.to_string())?
                .count
            }
            Operation::SpanSum => {
                plan.span_sum(
                    black_box(haystack),
                    LiteralAggregateReduceLimits::unlimited(),
                )
                .map_err(|error| error.to_string())?
                .span_sum
            }
        };
        checksum = accumulate(checksum, black_box(value), iteration);
    }
    Ok((
        start.elapsed(),
        checksum,
        "exact-literal-aggregate.memmem-find-iter.v1",
    ))
}

fn time_rust(
    regex: &Regex,
    haystack: &[u8],
    operation: Operation,
    iterations: u64,
) -> Result<(std::time::Duration, u64, &'static str), String> {
    let start = Instant::now();
    let mut checksum = 0_u64;
    for iteration in 0..iterations {
        let value = match operation {
            Operation::Count => u64::try_from(regex.find_iter(black_box(haystack)).count())
                .map_err(|_| "Rust count does not fit u64")?,
            Operation::SpanSum => {
                let mut total = 0_u64;
                for matched in regex.find_iter(black_box(haystack)) {
                    let length = u64::try_from(matched.len())
                        .map_err(|_| "Rust match length does not fit u64")?;
                    total = total.checked_add(length).ok_or("Rust span sum overflow")?;
                }
                total
            }
        };
        checksum = accumulate(checksum, black_box(value), iteration);
    }
    Ok((start.elapsed(), checksum, "rust-regex-1.12.4"))
}

const fn accumulate(checksum: u64, value: u64, iteration: u64) -> u64 {
    checksum
        .rotate_left(1)
        .wrapping_add(value)
        .wrapping_add(iteration)
}
