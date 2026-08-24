#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::too_many_lines,
    reason = "the public benchmark uses checked input bounds and one explicit wrapping checksum"
)]
#![allow(
    unsafe_code,
    reason = "the benchmark exercises the published raw Count and exclusive-handle ABIs"
)]

use std::{env, hint::black_box, process::ExitCode, time::Instant};

use fre::{AggregateBuilder, AggregateRunLimits};
use fre_aot_regex_runtime::{
    FreAotRegexExclusiveCountV1, FreAotRegexExclusiveHandleV1,
    fre_aot_regex_runtime_destroy_exclusive_v1, fre_aot_regex_runtime_prepare_exclusive_v1,
};
use serde_json::json;
use sha2::{Digest, Sha256};

#[path = "../public_shapes.rs"]
mod public_shapes;

const SCHEMA: &str = "fre-aot-direct-count-public-v1";
const SENTINEL: u64 = 0xa17e_d00d_6c3b_2915;
const CHECKSUM_MIX: u64 = 0x9e37_79b9_7f4a_7c15;
const MAX_HAYSTACK_BYTES: usize = 16 * 1024 * 1024;
const MAX_ITERATIONS: u64 = 10_000_000_000;

#[derive(Clone, Copy, Debug)]
struct PublicRoute {
    api: &'static str,
    mode: &'static str,
    output: &'static str,
    aggregate: &'static str,
    implementation: &'static str,
    target: &'static str,
    features: &'static str,
    engine: &'static str,
    reason: &'static str,
}

#[derive(Clone, Copy, Debug)]
struct PublicSpec {
    width: usize,
    literal: &'static str,
    program: fn() -> *const u8,
    program_len: usize,
    entry: FreAotRegexExclusiveCountV1,
    route: PublicRoute,
}

include!(concat!(env!("OUT_DIR"), "/registry.rs"));

#[derive(Clone, Copy, Debug)]
enum Scenario {
    Negative,
    Early,
    Late,
    Dense,
    Overlap,
}

impl Scenario {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "negative" => Ok(Self::Negative),
            "early" => Ok(Self::Early),
            "late" => Ok(Self::Late),
            "dense" => Ok(Self::Dense),
            "overlap" => Ok(Self::Overlap),
            _ => Err(format!(
                "unknown scenario {value:?}; expected negative, early, late, dense, or overlap",
            )),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Negative => "negative",
            Self::Early => "early",
            Self::Late => "late",
            Self::Dense => "dense",
            Self::Overlap => "overlap",
        }
    }
}

#[derive(Debug)]
struct Config {
    scenario: Scenario,
    width: usize,
    bytes: usize,
    iterations: u64,
}

impl Config {
    fn parse() -> Result<Self, String> {
        let mut args = env::args().skip(1);
        let scenario = Scenario::parse(&next(&mut args, "scenario")?)?;
        let width = parse_usize(&next(&mut args, "width")?, "width")?;
        let bytes = parse_usize(&next(&mut args, "bytes")?, "bytes")?;
        let iterations = next(&mut args, "iterations")?
            .parse::<u64>()
            .map_err(|_| "iterations must be an integer".to_owned())?;
        if let Some(extra) = args.next() {
            return Err(format!("unexpected argument {extra:?}"));
        }
        if public_shapes::literal_for_width(width).is_none() {
            return Err(format!(
                "width must be one of {:?}",
                public_shapes::WIDTHS,
            ));
        }
        if bytes < width {
            return Err("bytes must be at least width".to_owned());
        }
        if bytes > MAX_HAYSTACK_BYTES {
            return Err(format!("bytes exceeds public cap {MAX_HAYSTACK_BYTES}"));
        }
        if iterations == 0 || iterations > MAX_ITERATIONS {
            return Err(format!(
                "iterations must be in 1..={MAX_ITERATIONS}",
            ));
        }
        Ok(Self {
            scenario,
            width,
            bytes,
            iterations,
        })
    }
}

fn next(args: &mut impl Iterator<Item = String>, name: &str) -> Result<String, String> {
    args.next().ok_or_else(|| {
        format!(
            "missing {name}; usage: fre-aot-direct-count-benchmark SCENARIO WIDTH BYTES ITERATIONS",
        )
    })
}

fn parse_usize(value: &str, name: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|_| format!("{name} must be an integer"))
}

fn main() -> ExitCode {
    match Config::parse().and_then(run) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run(config: Config) -> Result<(), String> {
    let spec = PUBLIC_SPECS
        .iter()
        .find(|spec| spec.width == config.width)
        .ok_or_else(|| "generated registry lost requested width".to_owned())?;
    if spec.literal != public_shapes::literal_for_width(config.width).unwrap_or_default() {
        return Err("generated registry literal disagrees with public shape table".to_owned());
    }
    let haystack = make_haystack(config.scenario, spec.literal.as_bytes(), config.bytes)?;
    let expected = scalar_nonoverlap_count(&haystack, spec.literal.as_bytes())?;

    let fre_count = AggregateBuilder::new(spec.literal)
        .build_count()
        .map_err(|error| format!("build ordinary FRE Count diagnostic: {error}"))?;
    let fre_plan = format!("{:?}", fre_count.build_report().plan);
    let fre_value = fre_count
        .count_value(&haystack, AggregateRunLimits::default())
        .map_err(|error| format!("run ordinary FRE Count diagnostic: {error}"))?;
    if fre_value != expected {
        return Err(format!(
            "ordinary FRE Count diagnostic mismatch: expected {expected}, got {fre_value}",
        ));
    }

    let prepared = Prepared::new(spec)?;
    let preflight = prepared.count(spec.entry, &haystack)?;
    if preflight != expected {
        return Err(format!(
            "native Count preflight mismatch: expected {expected}, got {preflight}",
        ));
    }

    let entry = black_box(spec.entry);
    let haystack = black_box(haystack);
    let started = Instant::now();
    let mut checksum = 0_u64;
    let mut status_or = 0_u32;
    let mut wrong_or = 0_u32;
    for iteration in 0..config.iterations {
        let mut value = SENTINEL;
        // SAFETY: `prepared` exclusively owns the live handle, `haystack` is
        // readable for its complete length, and `value` is aligned writable
        // storage disjoint from both inputs.
        let status = unsafe {
            entry(
                prepared.handle,
                haystack.as_ptr(),
                haystack.len(),
                &mut value,
            )
        };
        status_or |= status;
        wrong_or |= u32::from(value != expected);
        checksum = checksum
            .rotate_left(7)
            .wrapping_add(value ^ iteration.wrapping_mul(CHECKSUM_MIX));
    }
    let elapsed_ns = u64::try_from(started.elapsed().as_nanos())
        .map_err(|_| "elapsed duration does not fit u64 nanoseconds".to_owned())?;
    if status_or != 0 || wrong_or != 0 {
        return Err(format!(
            "timed native Count failed: status_or={status_or}, wrong_or={wrong_or}",
        ));
    }
    prepared.finish()?;

    let haystack_sha256 = hex_digest(&haystack);
    let result_sha256 = result_digest(&config, expected, checksum);
    let output = json!({
        "schema": SCHEMA,
        "status": "ok",
        "scenario": config.scenario.name(),
        "width": config.width,
        "bytes": config.bytes,
        "iterations": config.iterations,
        "elapsed_ns": elapsed_ns,
        "count": expected,
        "checksum": format!("{checksum:016x}"),
        "haystack_sha256": haystack_sha256,
        "result_sha256": result_sha256,
        "route": {
            "api": spec.route.api,
            "mode": spec.route.mode,
            "output": spec.route.output,
            "aggregate": spec.route.aggregate,
            "implementation": spec.route.implementation,
            "target": spec.route.target,
            "features": spec.route.features,
            "engine": spec.route.engine,
            "reason": spec.route.reason,
        },
        "non_aot": {
            "count": fre_value,
            "plan": fre_plan,
        },
    });
    println!(
        "{}",
        serde_json::to_string(&output).map_err(|error| error.to_string())?,
    );
    Ok(())
}

#[derive(Debug)]
struct Prepared {
    handle: FreAotRegexExclusiveHandleV1,
}

impl Prepared {
    fn new(spec: &PublicSpec) -> Result<Self, String> {
        let mut handle = FreAotRegexExclusiveHandleV1::INVALID;
        // SAFETY: the linked program symbol is readable for the exact length
        // authenticated by the compiler module, and `handle` is aligned,
        // writable, and disjoint.
        let status = unsafe {
            fre_aot_regex_runtime_prepare_exclusive_v1(
                (spec.program)(),
                spec.program_len,
                &mut handle,
            )
        };
        if status != 0 || handle.is_invalid() {
            return Err(format!(
                "prepare exclusive Count handle failed with status {status}",
            ));
        }
        Ok(Self { handle })
    }

    fn count(&self, entry: FreAotRegexExclusiveCountV1, haystack: &[u8]) -> Result<u64, String> {
        let mut value = SENTINEL;
        // SAFETY: `self` exclusively owns a live handle and the slice/output
        // pointers meet the published Count ABI.
        let status = unsafe {
            entry(
                self.handle,
                haystack.as_ptr(),
                haystack.len(),
                &mut value,
            )
        };
        if status != 0 {
            return Err(format!("native Count returned status {status}"));
        }
        Ok(value)
    }

    fn finish(mut self) -> Result<(), String> {
        let handle = std::mem::replace(
            &mut self.handle,
            FreAotRegexExclusiveHandleV1::INVALID,
        );
        // SAFETY: `handle` is the live exclusively owned value, no call is in
        // flight, and replacing it prevents reuse or double destruction.
        let status = unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) };
        if status == 0 {
            Ok(())
        } else {
            Err(format!("destroy exclusive Count handle failed with status {status}"))
        }
    }
}

impl Drop for Prepared {
    fn drop(&mut self) {
        if self.handle.is_invalid() {
            return;
        }
        let handle = std::mem::replace(
            &mut self.handle,
            FreAotRegexExclusiveHandleV1::INVALID,
        );
        // SAFETY: a non-finished `Prepared` still exclusively owns this live
        // handle and no native call can overlap its drop.
        let _ = unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) };
    }
}

fn make_haystack(scenario: Scenario, literal: &[u8], bytes: usize) -> Result<Vec<u8>, String> {
    let mut haystack = vec![b'~'; bytes];
    match scenario {
        Scenario::Negative => {}
        Scenario::Early => haystack[..literal.len()].copy_from_slice(literal),
        Scenario::Late => haystack[bytes - literal.len()..].copy_from_slice(literal),
        Scenario::Dense if literal.len() == 1 => {
            for (index, byte) in haystack.iter_mut().enumerate() {
                *byte = if index.is_multiple_of(2) {
                    literal[0]
                } else {
                    b'!'
                };
            }
        }
        Scenario::Dense => {
            for (index, byte) in haystack.iter_mut().enumerate() {
                let within = index % literal.len();
                *byte = if within + 1 == literal.len() {
                    b'!'
                } else {
                    literal[within]
                };
            }
        }
        Scenario::Overlap => {
            let period = public_shapes::primitive_period(literal);
            for (index, byte) in haystack.iter_mut().enumerate() {
                *byte = literal[index % period];
            }
        }
    }
    if haystack.iter().any(|byte| *byte == 0) {
        return Err("public haystack unexpectedly contains NUL".to_owned());
    }
    Ok(haystack)
}

fn scalar_nonoverlap_count(haystack: &[u8], literal: &[u8]) -> Result<u64, String> {
    if literal.is_empty() {
        return Err("public literal must be nonempty".to_owned());
    }
    let mut offset = 0_usize;
    let mut count = 0_u64;
    while offset
        .checked_add(literal.len())
        .is_some_and(|end| end <= haystack.len())
    {
        if haystack[offset..offset + literal.len()] == *literal {
            count = count
                .checked_add(1)
                .ok_or_else(|| "scalar Count overflow".to_owned())?;
            offset = offset
                .checked_add(literal.len())
                .ok_or_else(|| "scalar successor overflow".to_owned())?;
        } else {
            offset = offset
                .checked_add(1)
                .ok_or_else(|| "scalar successor overflow".to_owned())?;
        }
    }
    Ok(count)
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn result_digest(config: &Config, count: u64, checksum: u64) -> String {
    let mut digest = Sha256::new();
    digest.update(b"fre-aot-direct-count-public-result/v1\0");
    digest.update(config.scenario.name().as_bytes());
    digest.update([0]);
    digest.update(u64::try_from(config.width).unwrap_or(u64::MAX).to_le_bytes());
    digest.update(u64::try_from(config.bytes).unwrap_or(u64::MAX).to_le_bytes());
    digest.update(config.iterations.to_le_bytes());
    digest.update(count.to_le_bytes());
    digest.update(checksum.to_le_bytes());
    hex_digest(&digest.finalize())
}
