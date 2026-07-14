//! Bounded release driver for the distinct forward-anchored candidate.

use std::{env, hint::black_box, process::ExitCode, time::Instant};

use fre::{PlanKind, PlanSelection, PortableBuilder, SearchLimits};

#[derive(Clone, Copy)]
enum Operation {
    Build,
    Exists,
    End,
    Span,
}

impl Operation {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "build" => Some(Self::Build),
            "exists" => Some(Self::Exists),
            "end" => Some(Self::End),
            "span" => Some(Self::Span),
            _ => None,
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
        .ok_or("OPERATION must be build, exists, end, or span")?;
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
    let (elapsed, checksum, plan) = if matches!(operation, Operation::Build) {
        time_build(&engine, &fixture.pattern, iterations)?
    } else {
        time_search(&engine, &fixture, operation, iterations)?
    };
    let total_ns = elapsed.as_nanos();
    let ns_per_iteration_milli = total_ns
        .checked_mul(1_000)
        .ok_or("nanosecond scaling overflow")?
        .checked_div(u128::from(iterations))
        .ok_or("iteration division failed")?;
    let ns_whole = ns_per_iteration_milli / 1_000;
    let ns_fraction = ns_per_iteration_milli % 1_000;
    println!(
        "{engine},{case},{},{},{iterations},{total_ns},{ns_whole}.{ns_fraction:03},{checksum},{plan}",
        operation_name(operation),
        fixture.haystack.len(),
    );
    Ok(())
}

struct Fixture {
    pattern: String,
    haystack: Vec<u8>,
}

fn fixture(case: &str, requested_size: usize) -> Result<Fixture, String> {
    let make_prefix = |bytes: &[u8], length: usize| -> Vec<u8> {
        bytes.iter().copied().cycle().take(length).collect()
    };
    let fixture = match case {
        "range-start-positive" => {
            let size = requested_size.max(2);
            let prefix = size.checked_sub(1).ok_or("positive prefix underflow")?;
            let mut haystack = vec![b'a'; prefix];
            haystack.push(b'Z');
            Fixture {
                pattern: r"\A[a-z]+Z".into(),
                haystack,
            }
        }
        "range-both-positive" => {
            let size = requested_size.max(2);
            let prefix = size.checked_sub(1).ok_or("positive prefix underflow")?;
            let mut haystack = vec![b'a'; prefix];
            haystack.push(b'Z');
            Fixture {
                pattern: r"\A[a-z]+Z\z".into(),
                haystack,
            }
        }
        "range-start-no-boundary" => {
            let size = requested_size.max(2);
            let prefix = size.checked_sub(1).ok_or("mismatch prefix underflow")?;
            let mut haystack = vec![b'a'; prefix];
            haystack.push(b'Q');
            Fixture {
                pattern: r"\A[a-z]+Z".into(),
                haystack,
            }
        }
        "range-start-boundary-mismatch" => {
            let size = requested_size.max(2);
            let prefix = size.checked_sub(1).ok_or("mismatch prefix underflow")?;
            let mut haystack = vec![b'a'; prefix];
            haystack.push(b'!');
            Fixture {
                pattern: r"\A[a-z]+Z".into(),
                haystack,
            }
        }
        "range-both-trailing-byte" => {
            let size = requested_size.max(3);
            let prefix = size.checked_sub(2).ok_or("trailing prefix underflow")?;
            let mut haystack = vec![b'a'; prefix];
            haystack.extend_from_slice(b"Z!");
            Fixture {
                pattern: r"\A[a-z]+Z\z".into(),
                haystack,
            }
        }
        "range-prefix-mismatch" => {
            let size = requested_size.max(2);
            let mut haystack = vec![b'a'; size];
            haystack[0] = b'!';
            Fixture {
                pattern: r"\A[a-z]+Z".into(),
                haystack,
            }
        }
        "bordered-generalization" => {
            let size = requested_size.max(4);
            let prefix = size.checked_sub(3).ok_or("bordered prefix underflow")?;
            let mut haystack = vec![b'b'; prefix];
            haystack.extend_from_slice(b"aba");
            Fixture {
                pattern: r"\Ab+aba".into(),
                haystack,
            }
        }
        "bitset-generalization" => {
            let size = requested_size.max(2);
            let prefix = size.checked_sub(1).ok_or("bitset prefix underflow")?;
            let mut haystack = make_prefix(b"aceg", prefix);
            haystack.push(b'Z');
            Fixture {
                pattern: r"\A[aceg]+Z".into(),
                haystack,
            }
        }
        "bitset-suffix-absent" => Fixture {
            pattern: r"\A[aceg]+Z".into(),
            haystack: make_prefix(b"aceg", requested_size),
        },
        "bitset-suffix-near-front" => {
            let size = requested_size.max(5);
            let mut haystack = make_prefix(b"aceg", size);
            haystack[4] = b'Z';
            Fixture {
                pattern: r"\A[aceg]+Z".into(),
                haystack,
            }
        }
        "bitset-early-outsider" => {
            let size = requested_size.max(3);
            let mut haystack = make_prefix(b"aceg", size);
            haystack[1] = b'!';
            haystack[size - 1] = b'Z';
            Fixture {
                pattern: r"\A[aceg]+Z".into(),
                haystack,
            }
        }
        "triple-generalization" => {
            let size = requested_size.max(2);
            let prefix = size.checked_sub(1).ok_or("triple prefix underflow")?;
            let mut haystack = make_prefix(b"ace", prefix);
            haystack.push(b'Z');
            Fixture {
                pattern: r"\A[ace]+Z".into(),
                haystack,
            }
        }
        "five-member-generalization" => {
            let size = requested_size.max(2);
            let prefix = size.checked_sub(1).ok_or("five-member prefix underflow")?;
            let mut haystack = make_prefix(b"acegi", prefix);
            haystack.push(b'Z');
            Fixture {
                pattern: r"\A[acegi]+Z".into(),
                haystack,
            }
        }
        "whitespace-generalization" => {
            let size = requested_size.max(4);
            let prefix = size.checked_sub(3).ok_or("whitespace prefix underflow")?;
            let mut haystack = make_prefix(b" \t", prefix);
            haystack.extend_from_slice(b"END");
            Fixture {
                pattern: r"\A[ \t]+END".into(),
                haystack,
            }
        }
        "whitespace-suffix-absent" => Fixture {
            pattern: r"\A[ \t]+END".into(),
            haystack: make_prefix(b" \t", requested_size),
        },
        _ => return Err(format!("unknown CASE {case:?}")),
    };
    Ok(fixture)
}

fn time_build(
    engine: &str,
    pattern: &str,
    iterations: u64,
) -> Result<(std::time::Duration, u64, &'static str), String> {
    let start = Instant::now();
    let mut checksum = 0_u64;
    let mut selected = "rust-regex";
    for iteration in 0..iterations {
        if engine == "rust" {
            let regex = regex::bytes::RegexBuilder::new(black_box(pattern))
                .unicode(false)
                .build()
                .map_err(|error| error.to_string())?;
            let value = u64::try_from(black_box(regex.as_str().len())).unwrap_or(u64::MAX);
            checksum = accumulate(checksum, value, iteration);
        } else {
            let regex = build_fre(engine, black_box(pattern))?;
            selected = plan_name(regex.build_report().plan);
            let value = u64::from(plan_tag(black_box(regex.build_report().plan)));
            checksum = accumulate(checksum, value, iteration);
        }
    }
    Ok((start.elapsed(), checksum, selected))
}

fn time_search(
    engine: &str,
    fixture: &Fixture,
    operation: Operation,
    iterations: u64,
) -> Result<(std::time::Duration, u64, &'static str), String> {
    if engine == "rust" {
        let regex = regex::bytes::RegexBuilder::new(&fixture.pattern)
            .unicode(false)
            .build()
            .map_err(|error| error.to_string())?;
        let start = Instant::now();
        let mut checksum = 0_u64;
        for iteration in 0..iterations {
            let value = match operation {
                Operation::Exists => u64::from(regex.is_match(black_box(&fixture.haystack))),
                Operation::End => regex
                    .find(black_box(&fixture.haystack))
                    .map_or(0, |matched| {
                        u64::try_from(matched.end()).unwrap_or(u64::MAX)
                    }),
                Operation::Span => regex
                    .find(black_box(&fixture.haystack))
                    .map_or(0, |matched| {
                        u64::try_from(matched.start().wrapping_add(matched.end()))
                            .unwrap_or(u64::MAX)
                    }),
                Operation::Build => unreachable!(),
            };
            checksum = accumulate(checksum, value, iteration);
        }
        return Ok((start.elapsed(), checksum, "rust-regex"));
    }

    let regex = build_fre(engine, &fixture.pattern)?;
    let plan = plan_name(regex.build_report().plan);
    let start = Instant::now();
    let mut checksum = 0_u64;
    for iteration in 0..iterations {
        let value = match operation {
            Operation::Exists => u64::from(
                regex
                    .is_match(black_box(&fixture.haystack), SearchLimits::unlimited())
                    .map_err(|error| error.to_string())?
                    .0,
            ),
            Operation::End => regex
                .selected_end(black_box(&fixture.haystack), SearchLimits::unlimited())
                .map_err(|error| error.to_string())?
                .0
                .map_or(0, |end| u64::try_from(end).unwrap_or(u64::MAX)),
            Operation::Span => regex
                .find(black_box(&fixture.haystack), SearchLimits::unlimited())
                .map_err(|error| error.to_string())?
                .0
                .map_or(0, |matched| {
                    u64::try_from(matched.start().wrapping_add(matched.end())).unwrap_or(u64::MAX)
                }),
            Operation::Build => unreachable!(),
        };
        checksum = accumulate(checksum, value, iteration);
    }
    Ok((start.elapsed(), checksum, plan))
}

fn build_fre(engine: &str, pattern: &str) -> Result<fre::PortableRegex, String> {
    let selection = match engine {
        "forward" => PlanSelection::ForceForwardAnchored,
        "required" => PlanSelection::ForceRequiredLiteral,
        "k0" => PlanSelection::ForceK0,
        "current" => PlanSelection::Auto,
        _ => return Err(format!("unknown ENGINE {engine:?}")),
    };
    PortableBuilder::new(pattern)
        .unicode(false)
        .plan_selection(selection)
        .build()
        .map_err(|error| error.to_string())
}

const fn operation_name(operation: Operation) -> &'static str {
    match operation {
        Operation::Build => "build",
        Operation::Exists => "exists",
        Operation::End => "end",
        Operation::Span => "span",
    }
}

const fn plan_tag(plan: PlanKind) -> u8 {
    match plan {
        PlanKind::ExactLiteral => 1,
        PlanKind::PackedLiteralSet => 2,
        PlanKind::LiteralSetDfa => 3,
        PlanKind::RequiredLiteral => 4,
        PlanKind::ForwardAnchored => 5,
        PlanKind::K0 => 6,
    }
}

const fn plan_name(plan: PlanKind) -> &'static str {
    match plan {
        PlanKind::ExactLiteral => "exact-literal",
        PlanKind::PackedLiteralSet => "packed-literal-set",
        PlanKind::LiteralSetDfa => "literal-set-dfa",
        PlanKind::RequiredLiteral => "required-literal-v1",
        PlanKind::ForwardAnchored => "anchored-class-suffix.forward.v1",
        PlanKind::K0 => "k0",
    }
}

const fn accumulate(checksum: u64, value: u64, iteration: u64) -> u64 {
    checksum
        .rotate_left(1)
        .wrapping_add(value)
        .wrapping_add(iteration)
}
