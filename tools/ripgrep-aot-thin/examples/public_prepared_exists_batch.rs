//! Public generated timing endpoint for the prepared Exists-batch loop.

use std::env;
use std::hint::black_box;
use std::process::ExitCode;
use std::time::Instant;

use fre_ripgrep_aot_thin::{AotHaystack, AotMatcher, AotMode, AotOutput, EXISTS_BATCH_CAPACITY};
use sha2::{Digest, Sha256};

const PATTERN: &str = "FRE_PUBLIC_BATCH_NEEDLE_7f4a9c2d";
const DECOY: &[u8] = b"FRE_PUBLIC_BATCH_NEEDLE_7f4a9c2x";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("public prepared Exists-batch benchmark: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 4 {
        return Err(
            "usage: public_prepared_exists_batch SCENARIO BATCH BYTES ITERATIONS".to_owned(),
        );
    }
    let scenario = arguments[0].as_str();
    if !matches!(scenario, "negative" | "early" | "late" | "dense-decoy") {
        return Err(format!("unknown scenario {scenario:?}"));
    }
    let parse = |index: usize| {
        arguments[index]
            .parse::<usize>()
            .map_err(|error| error.to_string())
    };
    let batch = parse(1)?;
    let bytes = parse(2)?;
    let iterations = parse(3)?;
    if !matches!(batch, 1 | 8 | 64) || batch > EXISTS_BATCH_CAPACITY {
        return Err("batch must be 1, 8, or 64".to_owned());
    }
    if !matches!(bytes, 64 | 4096 | 65536) || iterations == 0 {
        return Err("bytes must be 64, 4096, or 65536; iterations must be nonzero".to_owned());
    }

    let needle = PATTERN.as_bytes();
    let mut owned = Vec::with_capacity(batch);
    let mut input_digest = Sha256::new();
    for index in 0..batch {
        let mut haystack = match scenario {
            "dense-decoy" => (0..bytes)
                .map(|offset| DECOY[offset % DECOY.len()])
                .collect(),
            _ => vec![b'z'; bytes],
        };
        match scenario {
            "early" => haystack[..needle.len()].copy_from_slice(needle),
            "late" => haystack[bytes - needle.len()..].copy_from_slice(needle),
            _ => {}
        }
        // Distinct buffers and contents; the tag never overlaps an inserted match.
        let tag = format!("Q{index:02}");
        let tag_start = if scenario == "late" {
            0
        } else {
            bytes - tag.len()
        };
        haystack[tag_start..tag_start + tag.len()].copy_from_slice(tag.as_bytes());
        input_digest.update((haystack.len() as u64).to_le_bytes());
        input_digest.update(&haystack);
        owned.push(haystack);
    }
    let expected = owned
        .iter()
        .map(|haystack| {
            haystack
                .windows(needle.len())
                .any(|window| window == needle)
        })
        .collect::<Vec<_>>();
    if expected
        .iter()
        .any(|&value| value != matches!(scenario, "early" | "late"))
    {
        return Err("generated fixture disagrees with exact literal oracle".to_owned());
    }
    let descriptors = owned
        .iter()
        .map(|haystack| AotHaystack::from(haystack.as_slice()))
        .collect::<Vec<_>>();
    let mut scalar = AotMatcher::new(AotMode::Fast, AotOutput::Exists, PATTERN, false)?;
    let mut matcher = AotMatcher::new(AotMode::Fast, AotOutput::Exists, PATTERN, false)?;
    for required in [
        "route=compiled-prepared",
        "api=exists-batch-v1",
        "bulk=native-frozen-loop",
    ] {
        if !matcher
            .description()
            .split(',')
            .any(|field| field == required)
        {
            return Err(format!("unexpected route {}", matcher.description()));
        }
    }
    for (haystack, &oracle) in owned.iter().zip(&expected) {
        if scalar.is_match(haystack)? != oracle {
            return Err("scalar result disagrees with exact literal oracle".to_owned());
        }
    }
    let mut matched = expected.iter().map(|value| !value).collect::<Vec<_>>();
    matcher.is_match_descriptor_batch(&descriptors, &mut matched)?;
    if matched != expected {
        return Err("prepared batch disagrees with scalar and exact literal oracle".to_owned());
    }

    let started = Instant::now();
    for _ in 0..iterations {
        matcher.is_match_descriptor_batch(black_box(&descriptors), black_box(&mut matched))?;
    }
    let elapsed_ns = started.elapsed().as_nanos();
    black_box(&matched);
    if matched != expected {
        return Err("final result disagrees with exact literal oracle".to_owned());
    }
    let input_sha256 = format!("{:x}", input_digest.finalize());
    let matches_per_batch = matched.iter().filter(|&&value| value).count();
    // Compiler route fields contain only printable ASCII, so Debug string escaping is JSON-compatible.
    if !matcher
        .description()
        .bytes()
        .all(|byte| (0x20..=0x7e).contains(&byte))
    {
        return Err("non-ASCII route receipt".to_owned());
    }
    println!(
        "{{\"schema\":\"fre-public-prepared-exists-batch-v1\",\"status\":\"ok\",\"scenario\":{scenario:?},\"batch\":{batch},\"bytes_per_haystack\":{bytes},\"iterations\":{iterations},\"elapsed_ns\":{elapsed_ns},\"matches_per_batch\":{matches_per_batch},\"input_sha256\":{input_sha256:?},\"route\":{:?}}}",
        matcher.description()
    );
    Ok(())
}
