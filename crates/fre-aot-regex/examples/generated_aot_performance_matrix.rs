//! Generated-only steady-state performance matrix for the general AOT compiler.
//!
//! The matrix is derived entirely from structural regex graphs and deterministic
//! synthetic haystacks. It does not accept a corpus path or inspect external
//! benchmark data. The axes are:
//!
//! - six literal, class, range, sparse-class, and branching prefix shapes;
//! - no match, or a match at the start, middle, or end;
//! - candidate-start densities of 0, approximately 1/256, 1/32, 1/4, and dense;
//! - 32-byte, 4-KiB, and 64-KiB search windows; and
//! - four independently generated haystack rotations per matrix cell.
//!
//! Each graph is compiled once in `Fast` mode and once in `Optimizing` mode.
//! Fast mode is timed through a reusable portable workspace. The optimizing
//! object is linked into a generated C harness and timed through its direct
//! native entry point. Before any timed loop, both portable programs and every
//! native entry are checked for identical status/start/end results on all four
//! rotations. Trials are warmed, and TSV output reports minimum and median
//! absolute latency and throughput. No speedup ratio is printed. The native
//! harness also reports a non-inlined no-op call with the same C ABI, making
//! timer/call floors visible for short windows.
//! Throughput is explicitly labeled nominal-window throughput because an early
//! match can return without inspecting the remainder of the window.
//! No-op rows report latency only and use `-` for throughput because they do
//! not inspect the nominal window bytes.
//!
//! Run the complete matrix on the current supported host:
//!
//! ```text
//! cargo run --release -p fre-aot-regex \
//!   --example generated_aot_performance_matrix
//! ```
//!
//! Select CPU facts only when the current CPU and OS context supports them:
//!
//! ```text
//! cargo run --release -p fre-aot-regex \
//!   --example generated_aot_performance_matrix -- \
//!   --features avx2 --trials 9 --bytes-per-trial 8388608
//! ```
//!
//! A bounded smoke run still covers all three window sizes:
//!
//! ```text
//! cargo run -p fre-aot-regex \
//!   --example generated_aot_performance_matrix -- --smoke
//! ```
//!
//! The default minimum of 16,384 searches per trial prevents start matches
//! from falling below timer resolution even when the nominal window is large.
//! `--min-searches 4` is useful only for fast semantic-validation sweeps; its
//! timing output is intentionally not performance evidence.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_precision_loss,
    clippy::too_many_lines,
    reason = "this generated benchmark keeps its Rust/C matrix protocol together"
)]

use std::{
    env,
    ffi::OsString,
    fmt::Write as _,
    fs,
    hint::black_box,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
    time::Instant,
};

use fre_aot_regex::{
    Architecture, CompileMode, CompileRequest, CompiledRegex, CpuFeature, EngineKind, FeatureSet,
    MatchResult, OperatingSystem, OutputContract, SearchWindow, Target, compile,
};

const ROTATIONS: usize = 4;
const WINDOW_SIZES: [usize; 3] = [32, 4 * 1024, 64 * 1024];
const SAFE_BYTES: &[u8] = b"~!@#%&*+=:;?";
const CHECKSUM_MIX: u64 = 0x9e37_79b9_7f4a_7c15;
const START_MIX: u64 = 0xd1b5_4a32_d192_ed03;
const END_MIX: u64 = 0x94d0_49bb_1331_11eb;
const ITERATION_MIX: u64 = 0xbf58_476d_1ce4_e5b9;
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn usage() -> &'static str {
    "generated_aot_performance_matrix - generated structural AOT matrix

USAGE:
  cargo run --release -p fre-aot-regex \
    --example generated_aot_performance_matrix -- [OPTIONS]

OPTIONS:
  --trials N             Warmed timing trials per matrix cell. Default: 7.
  --warmup-rounds N      Four-search rotations before each measurement kind.
                         Default: 32.
  --bytes-per-trial N    Approximate searched bytes per trial. Default: 4194304.
  --min-searches N       Minimum calls per trial, independent of nominal bytes.
                         Rounded up to a multiple of four. Default: 16384.
  --features LIST        Comma-separated host CPU facts: sse2, avx2, avx512f,
                         avx512bw, avx512vl, asimd, sve, sve2. Default: none.
  --smoke                Bounded timer-floor matrix: two graph shapes, start
                         matches, two densities, three sizes, three trials, and
                         65536 bytes per trial unless those values were set.
  -h, --help             Show this text.

OUTPUT:
  TSV records. portable_fast rows time the reusable Fast workspace. native and
  noop_abi rows come from the linked C harness. Values are absolute; no speedup
  ratio is claimed. noop_abi throughput is `-` because it scans no bytes. All
  patterns and haystacks are deterministic and generated."
}

#[derive(Clone, Copy, Debug)]
struct Config {
    trials: usize,
    warmup_rounds: usize,
    bytes_per_trial: usize,
    min_searches: usize,
    target: Target,
    target_name: &'static str,
    smoke: bool,
}

#[derive(Debug, Default)]
struct PartialConfig {
    trials: Option<usize>,
    warmup_rounds: Option<usize>,
    bytes_per_trial: Option<usize>,
    min_searches: Option<usize>,
    features: Option<FeatureSet>,
    smoke: bool,
}

impl Config {
    fn parse() -> Result<Option<Self>, String> {
        let mut partial = PartialConfig::default();
        let mut arguments = env::args_os().skip(1);
        while let Some(argument) = arguments.next() {
            match argument.to_str() {
                Some("-h" | "--help") => return Ok(None),
                Some("--smoke") => partial.smoke = true,
                Some("--trials") => {
                    partial.trials = Some(parse_next(&mut arguments, "--trials")?);
                }
                Some("--warmup-rounds") => {
                    partial.warmup_rounds = Some(parse_next(&mut arguments, "--warmup-rounds")?);
                }
                Some("--bytes-per-trial") => {
                    partial.bytes_per_trial =
                        Some(parse_next(&mut arguments, "--bytes-per-trial")?);
                }
                Some("--min-searches") => {
                    partial.min_searches = Some(parse_next(&mut arguments, "--min-searches")?);
                }
                Some("--features") => {
                    let value = next_utf8(&mut arguments, "--features")?;
                    partial.features = Some(parse_features(&value)?);
                }
                Some(value) => return Err(format!("unknown argument {value:?}\n\n{}", usage())),
                None => return Err(format!("arguments must be valid UTF-8\n\n{}", usage())),
            }
        }

        let trials = partial.trials.unwrap_or(if partial.smoke { 3 } else { 7 });
        let warmup_rounds = partial
            .warmup_rounds
            .unwrap_or(if partial.smoke { 2 } else { 32 });
        let bytes_per_trial = partial.bytes_per_trial.unwrap_or(if partial.smoke {
            65_536
        } else {
            4 * 1024 * 1024
        });
        let min_searches = partial.min_searches.unwrap_or(16_384);
        if trials < 3 {
            return Err("--trials must be at least 3".to_owned());
        }
        if warmup_rounds == 0 {
            return Err("--warmup-rounds must be greater than zero".to_owned());
        }
        if bytes_per_trial < 32 {
            return Err("--bytes-per-trial must be at least 32".to_owned());
        }
        if min_searches == 0 {
            return Err("--min-searches must be greater than zero".to_owned());
        }

        let (mut target, target_name) = host_target()?;
        if let Some(features) = partial.features {
            target = target
                .with_features(features)
                .map_err(|error| format!("invalid host feature set: {error}"))?;
        }
        Ok(Some(Self {
            trials,
            warmup_rounds,
            bytes_per_trial,
            min_searches,
            target,
            target_name,
            smoke: partial.smoke,
        }))
    }
}

fn next_utf8(arguments: &mut impl Iterator<Item = OsString>, flag: &str) -> Result<String, String> {
    arguments
        .next()
        .ok_or_else(|| format!("{flag} requires a value"))?
        .into_string()
        .map_err(|_| format!("{flag} requires a UTF-8 value"))
}

fn parse_next(arguments: &mut impl Iterator<Item = OsString>, flag: &str) -> Result<usize, String> {
    next_utf8(arguments, flag)?
        .parse()
        .map_err(|_| format!("{flag} requires a valid non-negative integer"))
}

fn parse_features(value: &str) -> Result<FeatureSet, String> {
    if value.is_empty() || value == "none" {
        return Ok(FeatureSet::EMPTY);
    }
    let mut features = FeatureSet::EMPTY;
    for name in value.split(',') {
        let feature = match name {
            "sse2" => CpuFeature::X86Sse2,
            "avx2" => CpuFeature::X86Avx2,
            "avx512f" => CpuFeature::X86Avx512F,
            "avx512bw" => CpuFeature::X86Avx512Bw,
            "avx512vl" => CpuFeature::X86Avx512Vl,
            "asimd" => CpuFeature::Aarch64Asimd,
            "sve" => CpuFeature::Aarch64Sve,
            "sve2" => CpuFeature::Aarch64Sve2,
            _ => return Err(format!("unknown CPU feature {name:?}\n\n{}", usage())),
        };
        features = features.with(feature);
    }
    Ok(features)
}

fn host_target() -> Result<(Target, &'static str), String> {
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Ok((Target::x86_64_linux(), "linux-x86_64"))
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        Ok((Target::aarch64_linux(), "linux-aarch64"))
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        Ok((Target::x86_64_macos(), "macos-x86_64"))
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Ok((Target::aarch64_macos(), "macos-aarch64"))
    } else {
        Err("this example requires an x86-64/AArch64 Linux/macOS host".to_owned())
    }
}

#[derive(Clone, Copy, Debug)]
struct GraphShape {
    name: &'static str,
    class_shape: &'static str,
    pattern: &'static str,
    fixture: &'static [u8],
    candidates: &'static [u8],
}

const GRAPH_SHAPES: [GraphShape; 6] = [
    GraphShape {
        name: "literal_depth_3",
        class_shape: "singleton_literal",
        pattern: "aQZ",
        fixture: b"aQZ",
        candidates: b"a",
    },
    GraphShape {
        name: "literal_depth_6",
        class_shape: "deep_literal",
        pattern: "abcdQZ",
        fixture: b"abcdQZ",
        candidates: b"a",
    },
    GraphShape {
        name: "small_class",
        class_shape: "small_contiguous_class",
        pattern: "[a-c]QZ",
        fixture: b"bQZ",
        candidates: b"abc",
    },
    GraphShape {
        name: "range_pair",
        class_shape: "two_contiguous_classes",
        pattern: "[a-f][0-3]QZ",
        fixture: b"d2QZ",
        candidates: b"abcdef",
    },
    GraphShape {
        name: "sparse_pair",
        class_shape: "two_sparse_classes",
        pattern: "[acegik][02468]QZ",
        fixture: b"g6QZ",
        candidates: b"acegik",
    },
    GraphShape {
        name: "branching_pair",
        class_shape: "alternating_prefix_branches",
        pattern: "(?:ab|cd|ef)QZ",
        fixture: b"cdQZ",
        candidates: b"ace",
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MatchPosition {
    None,
    Start,
    Middle,
    End,
}

impl MatchPosition {
    const ALL: [Self; 4] = [Self::None, Self::Start, Self::Middle, Self::End];

    const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Start => "start",
            Self::Middle => "middle",
            Self::End => "end",
        }
    }

    const fn c_value(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Start => 1,
            Self::Middle => 2,
            Self::End => 3,
        }
    }

    fn offset(self, haystack_len: usize, fixture_len: usize) -> Option<usize> {
        match self {
            Self::None => None,
            Self::Start => Some(0),
            Self::Middle => Some((haystack_len - fixture_len) / 2),
            Self::End => Some(haystack_len - fixture_len),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct CandidateDensity {
    name: &'static str,
    stride: usize,
}

const CANDIDATE_DENSITIES: [CandidateDensity; 5] = [
    CandidateDensity {
        name: "zero",
        stride: 0,
    },
    CandidateDensity {
        name: "1_per_256",
        stride: 256,
    },
    CandidateDensity {
        name: "1_per_32",
        stride: 32,
    },
    CandidateDensity {
        name: "1_per_4",
        stride: 4,
    },
    CandidateDensity {
        name: "dense",
        stride: 1,
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AbiResult {
    status: u32,
    start: usize,
    end: usize,
}

impl AbiResult {
    fn from_match(result: MatchResult) -> Self {
        match result {
            MatchResult::Span(Some((start, end))) => Self {
                status: 1,
                start,
                end,
            },
            MatchResult::Span(None) => Self {
                status: 0,
                start: 0,
                end: 0,
            },
            other => panic!("the matrix requested Span but received {other:?}"),
        }
    }
}

fn generated_haystack(
    shape_index: usize,
    shape: GraphShape,
    haystack_len: usize,
    density: CandidateDensity,
    position: MatchPosition,
    rotation: usize,
) -> Vec<u8> {
    let mut haystack = Vec::with_capacity(haystack_len);
    for index in 0..haystack_len {
        let safe_index = index
            .wrapping_mul(13)
            .wrapping_add(rotation.wrapping_mul(7))
            .wrapping_add(shape_index.wrapping_mul(11))
            % SAFE_BYTES.len();
        haystack.push(SAFE_BYTES[safe_index]);
    }
    if density.stride != 0 {
        let phase = rotation
            .wrapping_mul(17)
            .wrapping_add(shape_index.wrapping_mul(23))
            % density.stride;
        let mut index = phase;
        while index < haystack_len {
            let candidate_index = (index / density.stride)
                .wrapping_add(rotation)
                .wrapping_add(shape_index)
                % shape.candidates.len();
            haystack[index] = shape.candidates[candidate_index];
            index = index.saturating_add(density.stride);
        }
    }
    if let Some(offset) = position.offset(haystack_len, shape.fixture.len()) {
        haystack[offset..offset + shape.fixture.len()].copy_from_slice(shape.fixture);
    }
    haystack
}

fn checksum_step(checksum: u64, result: AbiResult, iteration: u64) -> u64 {
    let start = u64::try_from(result.start).expect("supported targets use at most 64-bit size_t");
    let end = u64::try_from(result.end).expect("supported targets use at most 64-bit size_t");
    let value = u64::from(result.status)
        .wrapping_add(1)
        .wrapping_mul(CHECKSUM_MIX)
        ^ start.wrapping_add(START_MIX).rotate_left(17)
        ^ end.wrapping_add(END_MIX).rotate_left(41);
    checksum.rotate_left(7) ^ value ^ iteration.wrapping_mul(ITERATION_MIX)
}

fn byte_fingerprint(bytes: &[u8]) -> u64 {
    bytes.iter().fold(FNV_OFFSET, |fingerprint, &byte| {
        (fingerprint ^ u64::from(byte)).wrapping_mul(FNV_PRIME)
    })
}

fn searches_per_trial(config: Config, haystack_len: usize) -> usize {
    let quotient = config.bytes_per_trial.div_ceil(haystack_len);
    let at_least_one_rotation = quotient.max(config.min_searches).max(ROTATIONS);
    at_least_one_rotation.div_ceil(ROTATIONS) * ROTATIONS
}

#[derive(Clone, Debug)]
struct NativeScenario {
    case_name: String,
    shape_index: usize,
    size: usize,
    density: CandidateDensity,
    position: MatchPosition,
    searches: usize,
    expected: [AbiResult; ROTATIONS],
    haystack_fingerprints: [u64; ROTATIONS],
}

#[derive(Debug)]
struct CompiledShape {
    shape: GraphShape,
    fast: CompiledRegex,
    optimizing: CompiledRegex,
}

fn compile_shapes(config: Config) -> Result<Vec<CompiledShape>, String> {
    let shape_count = if config.smoke { 2 } else { GRAPH_SHAPES.len() };
    GRAPH_SHAPES[..shape_count]
        .iter()
        .copied()
        .map(|shape| {
            let fast = compile(
                CompileRequest::new(shape.pattern, config.target)
                    .mode(CompileMode::Fast)
                    .output(OutputContract::Span),
            )
            .map_err(|error| format!("{} Fast compilation failed: {error}", shape.name))?;
            let optimizing = compile(
                CompileRequest::new(shape.pattern, config.target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
            )
            .map_err(|error| format!("{} Optimizing compilation failed: {error}", shape.name))?;
            if optimizing.receipt().engine != EngineKind::OrderedDfa
                || optimizing.module().required_runtime_symbol().is_some()
            {
                return Err(format!(
                    "{} did not compile to a direct native ordered DFA",
                    shape.name
                ));
            }
            Ok(CompiledShape {
                shape,
                fast,
                optimizing,
            })
        })
        .collect()
}

fn median(samples: &[u128]) -> u128 {
    let middle = samples.len() / 2;
    if samples.len().is_multiple_of(2) {
        samples[middle - 1].saturating_add(samples[middle]) / 2
    } else {
        samples[middle]
    }
}

fn matrix_positions(config: Config) -> &'static [MatchPosition] {
    if config.smoke {
        &[MatchPosition::Start]
    } else {
        &MatchPosition::ALL
    }
}

fn matrix_densities(config: Config) -> &'static [CandidateDensity] {
    if config.smoke {
        &[CANDIDATE_DENSITIES[0], CANDIDATE_DENSITIES[2]]
    } else {
        &CANDIDATE_DENSITIES
    }
}

fn measure_portable_matrix(
    config: Config,
    compiled_shapes: &[CompiledShape],
) -> Result<Vec<NativeScenario>, String> {
    println!(
        "#portable_matrix\tkind\tcase\tgraph_shape\tclass_shape\tpattern\ttarget\tfeature_bits\tprefix_graph_bytes\tprefix_selective_positions\tprefix_filter_bytes\twindow_bytes\tmatch_position\tcandidate_density\trotations\tsearches_per_trial\ttrials\twarmup_rounds\tmin_elapsed_ns\tmedian_elapsed_ns\tmin_ns_per_search\tmedian_ns_per_search\tnominal_window_throughput_at_min_mib_s\tnominal_window_throughput_at_median_mib_s\tchecksum\tstatus"
    );
    let mut native_scenarios = Vec::new();
    for (shape_index, compiled) in compiled_shapes.iter().enumerate() {
        let shape = compiled.shape;
        let mut fast_workspace = compiled
            .fast
            .program()
            .prepare_workspace()
            .map_err(|error| format!("{} Fast workspace failed: {error}", shape.name))?;
        let mut optimizing_workspace = compiled
            .optimizing
            .program()
            .prepare_workspace()
            .map_err(|error| format!("{} Optimizing workspace failed: {error}", shape.name))?;
        for &size in &WINDOW_SIZES {
            for &position in matrix_positions(config) {
                for &density in matrix_densities(config) {
                    let haystacks: [Vec<u8>; ROTATIONS] = std::array::from_fn(|rotation| {
                        generated_haystack(shape_index, shape, size, density, position, rotation)
                    });
                    let mut expected = [AbiResult {
                        status: 0,
                        start: 0,
                        end: 0,
                    }; ROTATIONS];
                    let haystack_fingerprints =
                        std::array::from_fn(|rotation| byte_fingerprint(&haystacks[rotation]));
                    for (rotation, haystack) in haystacks.iter().enumerate() {
                        let window = SearchWindow::new(0, haystack.len());
                        let fast = compiled
                            .fast
                            .program()
                            .search_with_workspace(haystack, window, &mut fast_workspace)
                            .map_err(|error| {
                                format!("{} Fast validation failed: {error}", shape.name)
                            })?;
                        let optimizing = compiled
                            .optimizing
                            .program()
                            .search_with_workspace(haystack, window, &mut optimizing_workspace)
                            .map_err(|error| {
                                format!("{} Optimizing validation failed: {error}", shape.name)
                            })?;
                        let fast = AbiResult::from_match(fast);
                        let optimizing = AbiResult::from_match(optimizing);
                        if fast != optimizing {
                            return Err(format!(
                                "{} disagreed before timing at size {size}, position {}, density {}, rotation {rotation}: Fast {fast:?}, Optimizing {optimizing:?}",
                                shape.name,
                                position.name(),
                                density.name,
                            ));
                        }
                        let generator_expected = position.offset(size, shape.fixture.len()).map_or(
                            AbiResult {
                                status: 0,
                                start: 0,
                                end: 0,
                            },
                            |start| AbiResult {
                                status: 1,
                                start,
                                end: start + shape.fixture.len(),
                            },
                        );
                        if fast != generator_expected {
                            return Err(format!(
                                "{} generated an unintended match at size {size}, position {}, density {}, rotation {rotation}: got {fast:?}, expected {generator_expected:?}",
                                shape.name,
                                position.name(),
                                density.name,
                            ));
                        }
                        expected[rotation] = fast;
                    }

                    for warmup in 0..config.warmup_rounds * ROTATIONS {
                        let haystack = &haystacks[warmup % ROTATIONS];
                        black_box(
                            compiled
                                .fast
                                .program()
                                .search_with_workspace(
                                    black_box(haystack),
                                    SearchWindow::new(0, haystack.len()),
                                    &mut fast_workspace,
                                )
                                .map_err(|error| {
                                    format!("{} Fast warmup failed: {error}", shape.name)
                                })?,
                        );
                    }

                    let searches = searches_per_trial(config, size);
                    let expected_checksum = (0..searches).fold(0_u64, |checksum, iteration| {
                        checksum_step(
                            checksum,
                            expected[iteration % ROTATIONS],
                            u64::try_from(iteration).expect("search count fits u64"),
                        )
                    });
                    let mut elapsed_samples = Vec::with_capacity(config.trials);
                    let mut observed_checksum = 0_u64;
                    for _ in 0..config.trials {
                        let mut checksum = 0_u64;
                        let before = Instant::now();
                        for iteration in 0..searches {
                            let haystack = &haystacks[iteration % ROTATIONS];
                            let result = compiled
                                .fast
                                .program()
                                .search_with_workspace(
                                    black_box(haystack),
                                    SearchWindow::new(0, haystack.len()),
                                    &mut fast_workspace,
                                )
                                .map_err(|error| {
                                    format!("{} Fast timed search failed: {error}", shape.name)
                                })?;
                            checksum = checksum_step(
                                checksum,
                                AbiResult::from_match(result),
                                u64::try_from(iteration).expect("search count fits u64"),
                            );
                        }
                        elapsed_samples.push(before.elapsed().as_nanos());
                        if checksum != expected_checksum {
                            return Err(format!(
                                "{} Fast timed checksum changed for size {size}, position {}, density {}",
                                shape.name,
                                position.name(),
                                density.name,
                            ));
                        }
                        observed_checksum = checksum;
                        black_box(checksum);
                    }
                    elapsed_samples.sort_unstable();
                    let minimum = elapsed_samples[0];
                    let median = median(&elapsed_samples);
                    let bytes = size as f64 * searches as f64;
                    let min_ns_per_search = minimum as f64 / searches as f64;
                    let median_ns_per_search = median as f64 / searches as f64;
                    let min_mib_s =
                        bytes * 1_000_000_000.0 / minimum.max(1) as f64 / (1024.0 * 1024.0);
                    let median_mib_s =
                        bytes * 1_000_000_000.0 / median.max(1) as f64 / (1024.0 * 1024.0);
                    let case_name = format!(
                        "{}_{}_{}_{}",
                        shape.name,
                        size,
                        position.name(),
                        density.name
                    );
                    let prefix = compiled.optimizing.receipt().anchored_prefix;
                    println!(
                        "portable_matrix\tportable_fast\t{case_name}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{}\tok",
                        shape.name,
                        shape.class_shape,
                        shape.pattern,
                        config.target_name,
                        config.target.features.bits(),
                        prefix.guaranteed_bytes,
                        prefix.selective_positions,
                        compiled.optimizing.receipt().anchored_prefix_filter_bytes,
                        size,
                        position.name(),
                        density.name,
                        ROTATIONS,
                        searches,
                        config.trials,
                        config.warmup_rounds,
                        minimum,
                        median,
                        min_ns_per_search,
                        median_ns_per_search,
                        min_mib_s,
                        median_mib_s,
                        observed_checksum,
                    );
                    native_scenarios.push(NativeScenario {
                        case_name,
                        shape_index,
                        size,
                        density,
                        position,
                        searches,
                        expected,
                        haystack_fingerprints,
                    });
                }
            }
        }
    }
    Ok(native_scenarios)
}

fn c_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn c_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            character if character.is_ascii_graphic() || character == ' ' => {
                escaped.push(character);
            }
            character => {
                for byte in character.to_string().bytes() {
                    write!(&mut escaped, "\\x{byte:02x}").expect("writing to a String cannot fail");
                }
            }
        }
    }
    escaped
}

fn build_c_harness(
    config: Config,
    compiled_shapes: &[CompiledShape],
    scenarios: &[NativeScenario],
) -> String {
    let mut source = String::from(
        "#define _POSIX_C_SOURCE 200809L\n\
         #include <inttypes.h>\n\
         #include <stddef.h>\n\
         #include <stdint.h>\n\
         #include <stdio.h>\n\
         #include <stdlib.h>\n\
         #include <string.h>\n\
         #include <time.h>\n\n\
         #define ROTATIONS 4U\n\
         #if defined(__GNUC__) || defined(__clang__)\n\
         #define NOINLINE __attribute__((noinline))\n\
         #else\n\
         #define NOINLINE\n\
         #endif\n\n\
         typedef uint32_t (*entry_fn)(const unsigned char *, size_t, size_t,\n\
                                      size_t, size_t *);\n\
         typedef struct {\n\
           const char *name;\n\
           entry_fn entry;\n\
           const unsigned char *fixture;\n\
           size_t fixture_len;\n\
           const unsigned char *candidates;\n\
           size_t candidate_len;\n\
         } shape_spec;\n\
         typedef struct {\n\
           const char *name;\n\
           size_t shape;\n\
           size_t length;\n\
           size_t stride;\n\
           unsigned position;\n\
           uint64_t searches;\n\
           uint32_t status[ROTATIONS];\n\
           size_t start[ROTATIONS];\n\
           size_t end[ROTATIONS];\n\
           uint64_t fingerprint[ROTATIONS];\n\
         } scenario_spec;\n\n",
    );
    for (index, compiled) in compiled_shapes.iter().enumerate() {
        let symbol = compiled.optimizing.module().entry_symbol();
        writeln!(
            &mut source,
            "extern uint32_t {symbol}(const unsigned char *, size_t, size_t, size_t, size_t *);"
        )
        .expect("writing to a String cannot fail");
        writeln!(
            &mut source,
            "static const unsigned char fixture_{index}[] = {{{}}};",
            c_bytes(compiled.shape.fixture)
        )
        .expect("writing to a String cannot fail");
        writeln!(
            &mut source,
            "static const unsigned char candidates_{index}[] = {{{}}};",
            c_bytes(compiled.shape.candidates)
        )
        .expect("writing to a String cannot fail");
    }
    source.push_str("\nstatic const shape_spec shapes[] = {\n");
    for (index, compiled) in compiled_shapes.iter().enumerate() {
        writeln!(
            &mut source,
            "  {{\"{}\", {}, fixture_{index}, sizeof(fixture_{index}), candidates_{index}, sizeof(candidates_{index})}},",
            c_string(compiled.shape.name),
            compiled.optimizing.module().entry_symbol(),
        )
        .expect("writing to a String cannot fail");
    }
    source.push_str("};\n\nstatic const scenario_spec scenarios[] = {\n");
    for scenario in scenarios {
        let statuses = scenario
            .expected
            .iter()
            .map(|result| result.status.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let starts = scenario
            .expected
            .iter()
            .map(|result| result.start.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let ends = scenario
            .expected
            .iter()
            .map(|result| result.end.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let fingerprints = scenario
            .haystack_fingerprints
            .iter()
            .map(|fingerprint| format!("UINT64_C({fingerprint})"))
            .collect::<Vec<_>>()
            .join(",");
        writeln!(
            &mut source,
            "  {{\"{}\", {}, {}, {}, {}, UINT64_C({}), {{{statuses}}}, {{{starts}}}, {{{ends}}}, {{{fingerprints}}}}},",
            c_string(&scenario.case_name),
            scenario.shape_index,
            scenario.size,
            scenario.density.stride,
            scenario.position.c_value(),
            scenario.searches,
        )
        .expect("writing to a String cannot fail");
    }
    writeln!(
        &mut source,
        "}};\n\n\
         static const unsigned char safe_bytes[] = {{{}}};\n\
         static volatile uint64_t benchmark_sink;\n\n\
         static uint64_t rotate_left(uint64_t value, unsigned count) {{\n\
           return (value << count) | (value >> (64U - count));\n\
         }}\n\
         static uint64_t checksum_step(uint64_t checksum, uint32_t status,\n\
                                       size_t start, size_t end, uint64_t iteration) {{\n\
           uint64_t value = ((uint64_t)status + UINT64_C(1)) * UINT64_C(0x9e3779b97f4a7c15);\n\
           value ^= rotate_left((uint64_t)start + UINT64_C(0xd1b54a32d192ed03), 17U);\n\
           value ^= rotate_left((uint64_t)end + UINT64_C(0x94d049bb133111eb), 41U);\n\
           return rotate_left(checksum, 7U) ^ value ^\n\
                  iteration * UINT64_C(0xbf58476d1ce4e5b9);\n\
         }}\n\
         static uint64_t byte_fingerprint(const unsigned char *bytes, size_t length) {{\n\
           uint64_t fingerprint = UINT64_C(0xcbf29ce484222325);\n\
           for (size_t index = 0; index < length; ++index) {{\n\
             fingerprint = (fingerprint ^ (uint64_t)bytes[index]) *\n\
                           UINT64_C(0x00000100000001b3);\n\
           }}\n\
           return fingerprint;\n\
         }}\n\
         static uint64_t now_ns(void) {{\n\
           struct timespec value;\n\
           if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) {{\n\
             perror(\"clock_gettime\"); exit(90);\n\
           }}\n\
           return (uint64_t)value.tv_sec * UINT64_C(1000000000) +\n\
                  (uint64_t)value.tv_nsec;\n\
         }}\n\
         static int compare_u64(const void *left, const void *right) {{\n\
           uint64_t a = *(const uint64_t *)left;\n\
           uint64_t b = *(const uint64_t *)right;\n\
           return (a > b) - (a < b);\n\
         }}\n\
         static double median_u64(const uint64_t *sorted, size_t count) {{\n\
           size_t middle = count / 2U;\n\
           if ((count & 1U) != 0U) return (double)sorted[middle];\n\
           return ((double)sorted[middle - 1U] + (double)sorted[middle]) / 2.0;\n\
         }}\n\n",
        c_bytes(SAFE_BYTES),
    )
    .expect("writing to a String cannot fail");
    source.push_str(
        "static void generate_haystack(unsigned char *haystack, const scenario_spec *scenario,\n\
                                      size_t rotation) {\n\
           const shape_spec *shape = &shapes[scenario->shape];\n\
           for (size_t index = 0; index < scenario->length; ++index) {\n\
             size_t safe_index = (index * 13U + rotation * 7U + scenario->shape * 11U) %\n\
                                 sizeof(safe_bytes);\n\
             haystack[index] = safe_bytes[safe_index];\n\
           }\n\
           if (scenario->stride != 0U) {\n\
             size_t phase = (rotation * 17U + scenario->shape * 23U) % scenario->stride;\n\
             for (size_t index = phase; index < scenario->length; index += scenario->stride) {\n\
               size_t candidate = (index / scenario->stride + rotation + scenario->shape) %\n\
                                  shape->candidate_len;\n\
               haystack[index] = shape->candidates[candidate];\n\
             }\n\
           }\n\
           if (scenario->position != 0U) {\n\
             size_t offset = 0U;\n\
             if (scenario->position == 2U) {\n\
               offset = (scenario->length - shape->fixture_len) / 2U;\n\
             } else if (scenario->position == 3U) {\n\
               offset = scenario->length - shape->fixture_len;\n\
             }\n\
             memcpy(haystack + offset, shape->fixture, shape->fixture_len);\n\
           }\n\
         }\n\n\
         static NOINLINE uint32_t noop_entry(const unsigned char *haystack, size_t length,\n\
                                              size_t start, size_t end, size_t *result) {\n\
           uintptr_t address = (uintptr_t)haystack;\n\
           result[0] = start ^ (size_t)(address & 1U);\n\
           result[1] = end ^ (length & 1U);\n\
           return (uint32_t)((address ^ length ^ start ^ end) & 1U);\n\
         }\n\n",
    );
    writeln!(
        &mut source,
        "static int measure_one(const scenario_spec *scenario, const char *kind,\n\
                                entry_fn entry, int validate) {{\n\
           const size_t trials = {trials}U;\n\
           const size_t warmup_rounds = {warmup}U;\n\
           unsigned char *storage = malloc(scenario->length * ROTATIONS);\n\
           uint64_t *samples = malloc(trials * sizeof(*samples));\n\
           if (storage == NULL || samples == NULL) {{\n\
             fprintf(stderr, \"native harness allocation failed for %s\\n\", scenario->name);\n\
             free(samples); free(storage); return 80;\n\
           }}\n\
           for (size_t rotation = 0; rotation < ROTATIONS; ++rotation) {{\n\
             generate_haystack(storage + rotation * scenario->length, scenario, rotation);\n\
           }}\n\
           size_t result[2] = {{SIZE_MAX, SIZE_MAX}};\n\
           if (validate) {{\n\
             for (size_t rotation = 0; rotation < ROTATIONS; ++rotation) {{\n\
               uint64_t fingerprint = byte_fingerprint(\n\
                   storage + rotation * scenario->length, scenario->length);\n\
               if (fingerprint != scenario->fingerprint[rotation]) {{\n\
                 fprintf(stderr,\n\
                         \"generated haystack fingerprint mismatch for %s rotation %zu\\n\",\n\
                         scenario->name, rotation);\n\
                 free(samples); free(storage); return 69;\n\
               }}\n\
               uint32_t status = entry(storage + rotation * scenario->length,\n\
                                       scenario->length, 0U, scenario->length, result);\n\
               if (status != scenario->status[rotation] ||\n\
                   result[0] != scenario->start[rotation] ||\n\
                   result[1] != scenario->end[rotation]) {{\n\
                 fprintf(stderr,\n\
                         \"native semantic mismatch for %s rotation %zu: got %u/%zu/%zu expected %u/%zu/%zu\\n\",\n\
                         scenario->name, rotation, status, result[0], result[1],\n\
                         scenario->status[rotation], scenario->start[rotation],\n\
                         scenario->end[rotation]);\n\
                 free(samples); free(storage); return 70;\n\
               }}\n\
             }}\n\
           }}\n\
           for (size_t round = 0; round < warmup_rounds; ++round) {{\n\
             for (size_t rotation = 0; rotation < ROTATIONS; ++rotation) {{\n\
               uint32_t status = entry(storage + rotation * scenario->length,\n\
                                       scenario->length, 0U, scenario->length, result);\n\
               benchmark_sink ^= checksum_step(benchmark_sink, status, result[0], result[1],\n\
                                               (uint64_t)(round * ROTATIONS + rotation));\n\
             }}\n\
           }}\n\
           uint64_t measured_searches = scenario->searches;\n\
           if (!validate && measured_searches < UINT64_C(262144)) {{\n\
             measured_searches = UINT64_C(262144);\n\
           }}\n\
           uint64_t last_checksum = 0;\n\
           for (size_t trial = 0; trial < trials; ++trial) {{\n\
             uint64_t checksum = 0;\n\
             uint64_t before = now_ns();\n\
             for (uint64_t iteration = 0; iteration < measured_searches; ++iteration) {{\n\
               size_t rotation = ((size_t)iteration + trial) % ROTATIONS;\n\
               uint32_t status = entry(storage + rotation * scenario->length,\n\
                                       scenario->length, 0U, scenario->length, result);\n\
               checksum = checksum_step(checksum, status, result[0], result[1], iteration);\n\
             }}\n\
             samples[trial] = now_ns() - before;\n\
             if (validate) {{\n\
               uint64_t expected_checksum = 0;\n\
               for (uint64_t iteration = 0; iteration < measured_searches; ++iteration) {{\n\
                 size_t rotation = ((size_t)iteration + trial) % ROTATIONS;\n\
                 expected_checksum = checksum_step(expected_checksum,\n\
                                                   scenario->status[rotation],\n\
                                                   scenario->start[rotation],\n\
                                                   scenario->end[rotation], iteration);\n\
               }}\n\
               if (checksum != expected_checksum) {{\n\
                 fprintf(stderr, \"native timed checksum mismatch for %s\\n\", scenario->name);\n\
                 free(samples); free(storage); return 71;\n\
               }}\n\
             }}\n\
             last_checksum = checksum;\n\
             benchmark_sink ^= checksum;\n\
           }}\n\
           qsort(samples, trials, sizeof(*samples), compare_u64);\n\
           uint64_t minimum = samples[0];\n\
           double med = median_u64(samples, trials);\n\
           double bytes = (double)scenario->length * (double)measured_searches;\n\
           double minimum_ns_per_search = (double)minimum / (double)measured_searches;\n\
           double median_ns_per_search = med / (double)measured_searches;\n\
           double minimum_mib_s = bytes * 1000000000.0 /\n\
                                  (double)(minimum == 0U ? 1U : minimum) / 1048576.0;\n\
           double median_mib_s = bytes * 1000000000.0 /\n\
                                 (med < 1.0 ? 1.0 : med) / 1048576.0;\n\
           char minimum_throughput[64];\n\
           char median_throughput[64];\n\
           if (validate) {{\n\
             snprintf(minimum_throughput, sizeof(minimum_throughput), \"%.3f\", minimum_mib_s);\n\
             snprintf(median_throughput, sizeof(median_throughput), \"%.3f\", median_mib_s);\n\
           }} else {{\n\
             strcpy(minimum_throughput, \"-\");\n\
             strcpy(median_throughput, \"-\");\n\
           }}\n\
           const char *position_names[] = {{\"none\", \"start\", \"middle\", \"end\"}};\n\
           const char *density = scenario->stride == 0U ? \"zero\" :\n\
                                 scenario->stride == 256U ? \"1_per_256\" :\n\
                                 scenario->stride == 32U ? \"1_per_32\" :\n\
                                 scenario->stride == 4U ? \"1_per_4\" : \"dense\";\n\
           printf(\"native_matrix\\t%s\\t%s\\t%s\\t%s\\t%s\\t0x%\" PRIx64\n\
                  \"\\t%zu\\t%s\\t%s\\t%u\\t%\" PRIu64 \"\\t%zu\\t%zu\"\n\
                  \"\\t%\" PRIu64 \"\\t%.1f\\t%.3f\\t%.3f\\t%s\\t%s\"\n\
                  \"\\t%\" PRIu64 \"\\tok\\n\",\n\
                  kind, scenario->name, shapes[scenario->shape].name,\n\
                  \"{target_name}\", \"{feature_bits}\", UINT64_C({feature_bits}),\n\
                  scenario->length, position_names[scenario->position], density, ROTATIONS,\n\
                  measured_searches, trials, warmup_rounds, minimum, med,\n\
                  minimum_ns_per_search, median_ns_per_search,\n\
                  minimum_throughput, median_throughput, last_checksum);\n\
           free(samples); free(storage); return 0;\n\
         }}\n\n",
        trials = config.trials,
        warmup = config.warmup_rounds,
        target_name = config.target_name,
        feature_bits = config.target.features.bits(),
    )
    .expect("writing to a String cannot fail");
    source.push_str(
        "int main(void) {\n\
           puts(\"#native_matrix\\tkind\\tcase\\tgraph_shape\\ttarget\\tfeature_bits_text\\tfeature_bits\\twindow_bytes\\tmatch_position\\tcandidate_density\\trotations\\tsearches_per_trial\\ttrials\\twarmup_rounds\\tmin_elapsed_ns\\tmedian_elapsed_ns\\tmin_ns_per_search\\tmedian_ns_per_search\\tnominal_window_throughput_at_min_mib_s\\tnominal_window_throughput_at_median_mib_s\\tchecksum\\tstatus\");\n\
           const size_t count = sizeof(scenarios) / sizeof(scenarios[0]);\n\
           for (size_t index = 0; index < count; ++index) {\n\
             int status = measure_one(&scenarios[index], \"native\", shapes[scenarios[index].shape].entry, 1);\n\
             if (status != 0) return status;\n\
             status = measure_one(&scenarios[index], \"noop_abi\", noop_entry, 0);\n\
             if (status != 0) return status;\n\
           }\n\
           return 0;\n\
         }\n",
    );
    source
}

fn temporary_directory() -> Result<PathBuf, String> {
    for suffix in 0_u32..100 {
        let candidate = env::temp_dir().join(format!(
            "fre-generated-aot-performance-matrix-{}-{suffix}",
            std::process::id()
        ));
        match fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(format!(
                    "could not create temporary directory {}: {error}",
                    candidate.display()
                ));
            }
        }
    }
    Err("could not allocate a unique temporary native directory".to_owned())
}

fn compile_native_harness(
    directory: &Path,
    config: Config,
    compiled_shapes: &[CompiledShape],
    scenarios: &[NativeScenario],
) -> Result<PathBuf, String> {
    let harness_path = directory.join("matrix.c");
    fs::write(
        &harness_path,
        build_c_harness(config, compiled_shapes, scenarios),
    )
    .map_err(|error| format!("could not write generated C harness: {error}"))?;
    let mut object_paths = Vec::with_capacity(compiled_shapes.len());
    for (index, compiled) in compiled_shapes.iter().enumerate() {
        let path = directory.join(format!("shape_{index}.o"));
        fs::write(&path, compiled.optimizing.object())
            .map_err(|error| format!("could not write {}: {error}", path.display()))?;
        object_paths.push(path);
    }
    let executable = directory.join("matrix-native");
    let configured = env::var_os("CC");
    let compiler = configured.clone().unwrap_or_else(|| OsString::from("cc"));
    let mut command = Command::new(&compiler);
    command
        .arg("-O3")
        .arg("-std=c11")
        .arg(&harness_path)
        .args(&object_paths)
        .arg("-o")
        .arg(&executable);
    let output = match command.output() {
        Ok(output) => output,
        Err(error) if configured.is_none() => Command::new("clang")
            .arg("-O3")
            .arg("-std=c11")
            .arg(&harness_path)
            .args(&object_paths)
            .arg("-o")
            .arg(&executable)
            .output()
            .map_err(|fallback| {
                format!("could not invoke cc ({error}) or clang ({fallback}) for native harness")
            })?,
        Err(error) => {
            return Err(format!(
                "could not invoke C compiler {}: {error}",
                compiler.to_string_lossy()
            ));
        }
    };
    if !output.status.success() {
        return Err(format!(
            "native harness compilation failed:\n{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(executable)
}

fn clean_temporary_directory(directory: &Path, shape_count: usize) {
    let _ = fs::remove_file(directory.join("matrix.c"));
    let _ = fs::remove_file(directory.join("matrix-native"));
    for index in 0..shape_count {
        let _ = fs::remove_file(directory.join(format!("shape_{index}.o")));
    }
    let _ = fs::remove_dir(directory);
}

fn execute_native_harness(
    executable: &Path,
    directory: &Path,
    scenario_count: usize,
) -> Result<(), String> {
    let output = Command::new(executable)
        .current_dir(directory)
        .output()
        .map_err(|error| format!("could not execute generated native harness: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "native harness failed with {}:\n{}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|error| format!("native harness emitted non-UTF-8 output: {error}"))?;
    let mut native_rows = 0_usize;
    let mut noop_rows = 0_usize;
    for line in stdout.lines() {
        if line.starts_with('#') {
            println!("{line}");
            continue;
        }
        let columns = line.split('\t').collect::<Vec<_>>();
        if columns.len() != 22 || columns[0] != "native_matrix" || columns[21] != "ok" {
            return Err(format!("malformed native matrix row: {line}"));
        }
        match columns[1] {
            "native" => native_rows += 1,
            "noop_abi" => noop_rows += 1,
            _ => return Err(format!("unknown native matrix row kind: {line}")),
        }
        println!("{line}");
    }
    if native_rows != scenario_count || noop_rows != scenario_count {
        return Err(format!(
            "native harness emitted {native_rows} native and {noop_rows} no-op rows; expected {scenario_count} each"
        ));
    }
    Ok(())
}

fn run(config: Config) -> Result<(), String> {
    let architecture = match config.target.architecture {
        Architecture::X86_64 => "x86_64",
        Architecture::Aarch64 => "aarch64",
    };
    let operating_system = match config.target.operating_system {
        OperatingSystem::Linux => "linux",
        OperatingSystem::Macos => "macos",
    };
    eprintln!(
        "generated matrix: {architecture}-{operating_system}, feature_bits={:#x}, trials={}, bytes_per_trial={}, min_searches={}, smoke={}",
        config.target.features.bits(),
        config.trials,
        config.bytes_per_trial,
        config.min_searches,
        config.smoke,
    );
    let compiled_shapes = compile_shapes(config)?;
    let scenarios = measure_portable_matrix(config, &compiled_shapes)?;
    let directory = temporary_directory()?;
    let result = (|| {
        let executable = compile_native_harness(&directory, config, &compiled_shapes, &scenarios)?;
        execute_native_harness(&executable, &directory, scenarios.len())
    })();
    clean_temporary_directory(&directory, compiled_shapes.len());
    result
}

fn main() -> ExitCode {
    match Config::parse() {
        Ok(None) => {
            println!("{}", usage());
            ExitCode::SUCCESS
        }
        Ok(Some(config)) => match run(config) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("error: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
