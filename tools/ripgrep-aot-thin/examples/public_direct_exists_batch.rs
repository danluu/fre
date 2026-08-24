//! Public, deterministic timing endpoint for the direct Exists-batch route.

use std::collections::BTreeSet;
use std::env;
use std::hint::black_box;
use std::process::ExitCode;
use std::time::Instant;

use fre_ripgrep_aot_thin::{AotMatcher, AotMode, AotOutput, EXISTS_BATCH_CAPACITY};

const PATTERN: &str = "FRE_PUBLIC_BATCH_NEEDLE_7f4a9c2d";
const DECOY: &[u8] = b"FRE_PUBLIC_BATCH_NEEDLE_7f4a9c2x";
const MIN_HAYSTACK_BYTES: usize = 64;
const MAX_HAYSTACK_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
enum Scenario {
    Negative,
    Early,
    Late,
    DenseDecoy,
}

impl Scenario {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "negative" => Ok(Self::Negative),
            "early" => Ok(Self::Early),
            "late" => Ok(Self::Late),
            "dense-decoy" => Ok(Self::DenseDecoy),
            _ => Err(format!(
                "unknown scenario {value:?}; expected negative, early, late, or dense-decoy"
            )),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Negative => "negative",
            Self::Early => "early",
            Self::Late => "late",
            Self::DenseDecoy => "dense-decoy",
        }
    }

    const fn expected_match(self) -> bool {
        matches!(self, Self::Early | Self::Late)
    }
}

#[derive(Debug)]
struct Arguments {
    scenario: Scenario,
    batch: usize,
    bytes: usize,
    iterations: usize,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("public direct Exists-batch benchmark: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let arguments = parse_arguments()?;
    let owned_haystacks = make_haystacks(&arguments)?;
    let distinct = owned_haystacks
        .iter()
        .map(Vec::as_slice)
        .collect::<BTreeSet<_>>();
    if distinct.len() != arguments.batch {
        return Err("generated haystacks are not pairwise distinct".to_owned());
    }
    let haystacks = owned_haystacks
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();

    let mut scalar = AotMatcher::new(AotMode::Optimizing, AotOutput::Exists, PATTERN, false)?;
    let expected = haystacks
        .iter()
        .map(|haystack| scalar.is_match(haystack))
        .collect::<Result<Vec<_>, _>>()?;
    let expected_value = arguments.scenario.expected_match();
    if expected.iter().any(|&matched| matched != expected_value) {
        return Err(format!(
            "scalar preflight disagrees with generated scenario semantics: expected {expected_value}"
        ));
    }

    let mut matcher = AotMatcher::new(AotMode::Optimizing, AotOutput::Exists, PATTERN, false)?;
    let route = matcher.description();
    let mut outcomes = expected.iter().map(|value| !value).collect::<Vec<_>>();
    matcher.is_match_batch(&haystacks, &mut outcomes)?;
    if outcomes != expected {
        return Err("batch preflight disagrees with scalar is_match output".to_owned());
    }

    let started = Instant::now();
    for _ in 0..arguments.iterations {
        matcher.is_match_batch(&haystacks, &mut outcomes)?;
    }
    let elapsed = started.elapsed();
    black_box(&outcomes);
    if outcomes != expected {
        return Err("final timed batch disagrees with scalar preflight".to_owned());
    }

    let input_digest = digest_haystacks(&haystacks);
    let result_digest = digest_result(input_digest, arguments.iterations, &outcomes);
    let matches_per_batch = outcomes.iter().filter(|&&value| value).count();
    let total_bytes = arguments
        .bytes
        .checked_mul(arguments.batch)
        .ok_or_else(|| "total haystack byte count overflow".to_owned())?;
    println!(
        "{{\"schema\":\"fre-public-direct-exists-batch-v1\",\"status\":\"ok\",\"scenario\":\"{}\",\"batch\":{},\"bytes_per_haystack\":{},\"total_bytes\":{},\"iterations\":{},\"elapsed_ns\":{},\"matches_per_batch\":{},\"input_digest\":\"{input_digest:016x}\",\"result_digest\":\"{result_digest:016x}\",\"route\":{}}}",
        arguments.scenario.name(),
        arguments.batch,
        arguments.bytes,
        total_bytes,
        arguments.iterations,
        elapsed.as_nanos(),
        matches_per_batch,
        json_string(route),
    );
    Ok(())
}

fn parse_arguments() -> Result<Arguments, String> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 4 {
        return Err(
            "usage: public_direct_exists_batch SCENARIO BATCH BYTES ITERATIONS".to_owned(),
        );
    }
    let scenario = Scenario::parse(&arguments[0])?;
    let batch = parse_usize("batch", &arguments[1])?;
    let bytes = parse_usize("bytes", &arguments[2])?;
    let iterations = parse_usize("iterations", &arguments[3])?;
    if !(1..=EXISTS_BATCH_CAPACITY).contains(&batch) {
        return Err(format!(
            "batch must be in 1..={EXISTS_BATCH_CAPACITY}, got {batch}"
        ));
    }
    if !(MIN_HAYSTACK_BYTES..=MAX_HAYSTACK_BYTES).contains(&bytes) {
        return Err(format!(
            "bytes must be in {MIN_HAYSTACK_BYTES}..={MAX_HAYSTACK_BYTES}, got {bytes}"
        ));
    }
    if iterations == 0 {
        return Err("iterations must be nonzero".to_owned());
    }
    Ok(Arguments {
        scenario,
        batch,
        bytes,
        iterations,
    })
}

fn parse_usize(name: &str, value: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|error| format!("invalid {name} {value:?}: {error}"))
}

fn make_haystacks(arguments: &Arguments) -> Result<Vec<Vec<u8>>, String> {
    let needle = PATTERN.as_bytes();
    if arguments.bytes < needle.len() + 3 {
        return Err("haystack is too short for the public literal and uniqueness tag".to_owned());
    }
    (0..arguments.batch)
        .map(|index| {
            let mut haystack = match arguments.scenario {
                Scenario::Negative => vec![b'N'; arguments.bytes],
                Scenario::Early => {
                    let mut bytes = vec![b'E'; arguments.bytes];
                    bytes[..needle.len()].copy_from_slice(needle);
                    bytes
                }
                Scenario::Late => {
                    let mut bytes = vec![b'L'; arguments.bytes];
                    let start = bytes.len() - needle.len();
                    bytes[start..].copy_from_slice(needle);
                    bytes
                }
                Scenario::DenseDecoy => (0..arguments.bytes)
                    .map(|offset| DECOY[offset % DECOY.len()])
                    .collect(),
            };
            let index = u8::try_from(index)
                .map_err(|_| "batch index does not fit the public uniqueness tag".to_owned())?;
            let tag = [b'Q', b'0' + index / 10, b'0' + index % 10];
            match arguments.scenario {
                Scenario::Late => haystack[..tag.len()].copy_from_slice(&tag),
                Scenario::Negative | Scenario::Early | Scenario::DenseDecoy => {
                    let start = haystack.len() - tag.len();
                    haystack[start..].copy_from_slice(&tag);
                }
            }
            Ok(haystack)
        })
        .collect()
}

fn digest_haystacks(haystacks: &[&[u8]]) -> u64 {
    let mut digest = 0xcbf2_9ce4_8422_2325_u64;
    for haystack in haystacks {
        let len = u64::try_from(haystack.len()).unwrap_or(u64::MAX);
        digest = digest_bytes(digest, &len.to_le_bytes());
        digest = digest_bytes(digest, haystack);
    }
    digest
}

fn digest_result(mut digest: u64, iterations: usize, matched: &[bool]) -> u64 {
    let iterations = u64::try_from(iterations).unwrap_or(u64::MAX);
    digest = digest_bytes(digest, &iterations.to_le_bytes());
    for &value in matched {
        digest = digest_bytes(digest, &[u8::from(value)]);
    }
    digest
}

fn digest_bytes(mut digest: u64, bytes: &[u8]) -> u64 {
    for &byte in bytes {
        digest ^= u64::from(byte);
        digest = digest.wrapping_mul(0x0000_0100_0000_01b3);
    }
    digest
}

fn json_string(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len() + 2);
    encoded.push('"');
    for character in value.chars() {
        match character {
            '"' => encoded.push_str("\\\""),
            '\\' => encoded.push_str("\\\\"),
            '\n' => encoded.push_str("\\n"),
            '\r' => encoded.push_str("\\r"),
            '\t' => encoded.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                write!(&mut encoded, "\\u{:04x}", u32::from(character))
                    .expect("String writes cannot fail");
            }
            character => encoded.push(character),
        }
    }
    encoded.push('"');
    encoded
}
