//! Generated, holdout-independent comparison of general optimizing AOT search
//! against the workspace-pinned upstream `regex` crate.
//!
//! The complete matrix has 24 distinct patterns: two each for literals,
//! classes (including a full-byte first class), concatenation, alternation,
//! greedy, lazy, bounded, and nullable repetition, Unicode, line assertions,
//! word assertions, and forced determinization-resource fallback. One pattern
//! in every family uses `find`/Span and the other uses `is_match`/Exists. It
//! crosses two runtime-derived seeds with four window sizes (through 8 MiB),
//! four match positions, five candidate densities (including near misses),
//! and four deterministic rotations: 3,840 cells total.
//!
//! Every rotation is compared with the upstream engine and the portable AOT
//! semantic program before timing. The linked native harness validates the
//! same fingerprints and results again. Runtime-backed assertion and resource
//! fallback objects are prepared once for dependency/lifecycle validation.
//! Timed calls always enter generated code: the exclusive prepared entry when
//! one was published, otherwise the module's ordinary generated entry.
//! Compilation, object linking, and preparation are excluded from all
//! measurements.
//!
//! Run on a supported x86-64 or `AArch64` Linux/macOS host:
//!
//! ```text
//! cargo run --release -p fre-aot-regex \
//!   --example generated_aot_upstream_comparison -- --features asimd
//! ```
//!
//! Use `--smoke` for semantic and harness validation of all 48 seeded pattern
//! instances over one generated cell apiece. This benchmark accepts no corpus
//! path.
//!
//! `--grammar` selects a separate out-of-sample diagnostic: two seeds generate
//! 72 capture-free byte regexes from nine structural grammar families, then a
//! bounded 1,296-cell call-overhead/throughput matrix is validated and timed.
//!
//! `--nested-grammar` is a broader recursive diagnostic. Two printed root
//! seeds generate 96 unique byte-regex ASTs from twelve structural families.
//! Their depth, branches, atoms, ranges, repetition bounds, greediness, and
//! witnesses all come from the grammar RNG. Its four rotations use
//! punctuation-safe, weighted text/whitespace, code-like, and full-byte seeded
//! backgrounds. One in four shapes ends in an unconstrained byte, so required
//! terminal-byte acceleration cannot cover the whole suite. With both default
//! roots and one deterministically assigned output contract per source, the
//! matrix has 4,608 cells. Selecting one root reduces that assigned-contract
//! matrix to 2,304 cells; `--output-matrix` triples it to 6,912 cells per root
//! (13,824 for both default roots). Each matrix crosses 64 byte, 4 KiB, and
//! 64 KiB windows with none/start/middle/end witness placement and
//! zero/sparse/near-miss/dense candidate input. The upstream engine is the
//! result oracle and the portable FRE program is checked against it before any
//! native timing.
//!
//! `--output-matrix` removes output-contract confounding for qualification by
//! compiling every generated source as Span, Exists, and SelectedEnd. The
//! default single deterministically assigned contract remains unchanged for
//! development runs and backwards-compatible output cardinality.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_precision_loss,
    clippy::too_many_lines,
    reason = "the generated benchmark keeps its Rust/C validation protocol together"
)]

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::{OsStr, OsString},
    fmt::Write as _,
    fs,
    hint::black_box,
    io::{BufRead as _, BufReader, Read as _, Write as _},
    path::{Path, PathBuf},
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitCode, Stdio},
    time::Instant,
};

use fre_aot_regex::{
    Architecture, CompileLimitsV1, CompileMode, CompileRequest, CompiledRegex, CpuFeature,
    DeterminizationStage, EngineKind, EngineSelectionReason, FeatureSet, MatchResult,
    OperatingSystem, OutputContract, PartialDfaStats, SearchWindow, SlowAotLimits,
    StartAccelerator, Target, compile_with_slow_aot_limits,
};
use regex::bytes::Regex;

const ROTATIONS: usize = 4;
const WINDOW_SIZES: [usize; 4] = [64, 4 * 1024, 64 * 1024, 8 * 1024 * 1024];
const SAFE_BYTES: &[u8] = b"~!@#%&*+=:;?";
const ENGLISHISH_BYTES: &[u8] = b"          eeeeeeeeeeeetttttttttaaaaaaaaaooooooooiiiiiiiinnnnnnnsssssshhhhhhrrrrrrddddllluuummccffyywwggppbbvvkkxjqz\n\n\t.,'";
const CODEISH_BYTES: &[u8] =
    b"fn main value index self usize match if else return struct impl let mut pub const Result Option 0123456789_(){}[];,.=+-*/<>!&| \n\t";
const CHECKSUM_MIX: u64 = 0x9e37_79b9_7f4a_7c15;
const START_MIX: u64 = 0xd1b5_4a32_d192_ed03;
const END_MIX: u64 = 0x94d0_49bb_1331_11eb;
const ITERATION_MIX: u64 = 0xbf58_476d_1ce4_e5b9;
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
const PATTERN_SEEDS: [u64; 2] = [0x243f_6a88_85a3_08d2, 0x1319_8a2e_0370_7345];
const UPSTREAM_REGEX_VERSION: &str = "1.13.1";
// Keep the diagnostic setup transaction identical to the exclusive runtime.
// These limits affect only optional immutable setup state, never semantics or
// timed execution.
const FROZEN_DYNAMIC_SIDECAR_MAX_K0_BYTES: usize = 512 * 1024;
const FROZEN_DYNAMIC_SIDECAR_MAX_PACKED_BYTES: usize = 512 * 1024;

fn usage() -> &'static str {
    "generated_aot_upstream_comparison - generated general-AOT comparison

USAGE:
  cargo run --release -p fre-aot-regex \\
    --example generated_aot_upstream_comparison -- [OPTIONS]

OPTIONS:
  --trials N             Timed trials per cell. Default: 5 (minimum: 3).
  --warmup-rounds N      Four-search warmup rotations. Default: 8.
  --bytes-per-trial N    Minimum nominal bytes per trial. Default: 262144.
  --min-searches N       Initial minimum calls per trial. Default: 1.
  --min-trial-ns N       Each engine doubles its batch until a pilot reaches
                         this duration. Default: 5000000.
  --family NAME          Measure only this structural family.
  --pattern-name NAME    Measure only this generated pattern name.
  --route NAME           Measure only direct_dfa, direct_context_dfa,
                         direct_context_fallback, direct_resource_fallback,
                         prepared_runtime_assertion,
                         ordinary_runtime_assertion,
                         ordinary_runtime_resource_fallback, or
                         prepared_runtime_resource_fallback, or
                         slow_partial_resource_fallback. Authenticated
                         complete retained tables may use the self-contained
                         direct_resource_fallback route. A published prepared
                         optimizing entry owns the prepared route even when
                         no stable partial-row statistics exist; runtime-dependent
                         generated entries without that prepared entry use the
                         ordinary route.
  --measurement-order O  Timed engine order: upstream-native (default) or
                         native-upstream. All build/link/runtime preparation
                         completes before either timed phase.
  --output-matrix        Compile every generated regex source under Span,
                         Exists, and SelectedEnd. By default each source keeps
                         its single deterministically assigned contract.
  --force-resource-fallback
                         Set the ordinary DFA state budget to zero for every
                         generated source. Contextual sources retain their
                         separate assertion fallback route. This is a generic
                         fallback diagnostic, not a pattern allowlist.
  --force-retained-resource-fallback
                        Probe each source structurally, then force a canonical
                        decline that preserves nonempty DFA rows when the
                        graph supports them. The separate slow-AOT pass is
                        bounded off so it cannot replace the retained ordinary
                        rows. Incomplete rows publish a native prepared entry
                        when eligible; authenticated complete rows may publish
                        a self-contained direct entry. Keeps excluded exact-
                        product and contextual diagnostic rows.
  --force-slow-partial-resource-fallback
                        Set the semantic DFA state budget to zero, probe the
                        complete slow-AOT graph, then derive a deterministic
                        slow state limit that retains a genuine incomplete
                        forward prefix. Shapes without an interior prefix stay
                        truthfully classified as exclusions. Select only the
                        admitted rows with --route slow_partial_resource_fallback.
  --seed N               Measure one generated seed (decimal or 0x-prefixed).
                         Both grammar modes accept any new root seed.
  --grammar              Use the separate seeded grammar-generated diagnostic
                         suite instead of the fixed-family matrix.
  --nested-grammar       Use the recursive seeded AST diagnostic: 96 patterns,
                         12 families, and 4,608 cells in the default two-root,
                         assigned-contract matrix. One root has 2,304 cells;
                         --output-matrix triples either cardinality.
  --features LIST        Comma-separated host facts: sse2,avx2,avx512f,
                         avx512bw,avx512vl,asimd,sve,sve2. Default: none.
  --smoke                Keep all patterns but use one 64-byte/start/zero cell.
  -h, --help             Show this text.

OUTPUT:
  Joined TSV rows with absolute upstream/native latency and speedup. Upstream
  Regex values and native AOT objects are reused. Compilation, linking, and
  prepared-runtime setup are outside timing. All inputs are generated."
}

#[derive(Clone, Debug)]
struct Config {
    trials: usize,
    warmup_rounds: usize,
    bytes_per_trial: usize,
    min_searches: usize,
    min_trial_ns: usize,
    target: Target,
    target_name: &'static str,
    smoke: bool,
    family_filter: Option<String>,
    pattern_filter: Option<String>,
    route_filter: Option<String>,
    measurement_order: MeasurementOrder,
    output_matrix: bool,
    force_resource_fallback: bool,
    force_retained_resource_fallback: bool,
    force_slow_partial_resource_fallback: bool,
    seed_filter: Option<u64>,
    grammar: bool,
    nested_grammar: bool,
}

#[derive(Debug, Default)]
struct PartialConfig {
    trials: Option<usize>,
    warmup_rounds: Option<usize>,
    bytes_per_trial: Option<usize>,
    min_searches: Option<usize>,
    min_trial_ns: Option<usize>,
    features: Option<FeatureSet>,
    smoke: bool,
    family_filter: Option<String>,
    pattern_filter: Option<String>,
    route_filter: Option<String>,
    measurement_order: Option<MeasurementOrder>,
    output_matrix: bool,
    force_resource_fallback: bool,
    force_retained_resource_fallback: bool,
    force_slow_partial_resource_fallback: bool,
    seed_filter: Option<u64>,
    grammar: bool,
    nested_grammar: bool,
}

impl Config {
    fn parse() -> Result<Option<Self>, String> {
        let mut partial = PartialConfig::default();
        let mut arguments = env::args_os().skip(1);
        while let Some(argument) = arguments.next() {
            match argument.to_str() {
                Some("-h" | "--help") => return Ok(None),
                Some("--smoke") => partial.smoke = true,
                Some("--output-matrix") => partial.output_matrix = true,
                Some("--force-resource-fallback") => partial.force_resource_fallback = true,
                Some("--force-retained-resource-fallback") => {
                    partial.force_retained_resource_fallback = true;
                }
                Some("--force-slow-partial-resource-fallback") => {
                    partial.force_slow_partial_resource_fallback = true;
                }
                Some("--grammar") => partial.grammar = true,
                Some("--nested-grammar") => partial.nested_grammar = true,
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
                Some("--min-trial-ns") => {
                    partial.min_trial_ns = Some(parse_next(&mut arguments, "--min-trial-ns")?);
                }
                Some("--family") => {
                    partial.family_filter = Some(next_utf8(&mut arguments, "--family")?);
                }
                Some("--pattern-name") => {
                    partial.pattern_filter = Some(next_utf8(&mut arguments, "--pattern-name")?);
                }
                Some("--route") => {
                    partial.route_filter = Some(next_utf8(&mut arguments, "--route")?);
                }
                Some("--measurement-order") => {
                    partial.measurement_order = Some(parse_measurement_order(&next_utf8(
                        &mut arguments,
                        "--measurement-order",
                    )?)?);
                }
                Some("--seed") => {
                    partial.seed_filter = Some(parse_seed(&next_utf8(&mut arguments, "--seed")?)?);
                }
                Some("--features") => {
                    partial.features =
                        Some(parse_features(&next_utf8(&mut arguments, "--features")?)?);
                }
                Some(value) => return Err(format!("unknown argument {value:?}\n\n{}", usage())),
                None => return Err(format!("arguments must be valid UTF-8\n\n{}", usage())),
            }
        }
        let trials = partial.trials.unwrap_or(if partial.smoke { 3 } else { 5 });
        let warmup_rounds = partial
            .warmup_rounds
            .unwrap_or(if partial.smoke { 2 } else { 8 });
        let bytes_per_trial =
            partial
                .bytes_per_trial
                .unwrap_or(if partial.smoke { 4_096 } else { 262_144 });
        let min_searches = partial.min_searches.unwrap_or(1);
        let min_trial_ns =
            partial
                .min_trial_ns
                .unwrap_or(if partial.smoke { 100_000 } else { 5_000_000 });
        if trials < 3 {
            return Err("--trials must be at least 3".to_owned());
        }
        if partial.grammar && partial.nested_grammar {
            return Err("--grammar and --nested-grammar are mutually exclusive".to_owned());
        }
        forced_fallback_mode(
            partial.force_resource_fallback,
            partial.force_retained_resource_fallback,
            partial.force_slow_partial_resource_fallback,
        )?;
        if warmup_rounds == 0 || bytes_per_trial == 0 || min_searches == 0 || min_trial_ns == 0 {
            return Err(
                "warmup rounds, bytes per trial, searches, and trial duration must be non-zero"
                    .to_owned(),
            );
        }
        if let Some(route) = partial.route_filter.as_deref() && !is_known_route(route) {
            return Err(format!("unknown native route {route:?}\n\n{}", usage()));
        }
        let (mut target, target_name) = host_target()?;
        if let Some(features) = partial.features {
            target = target
                .with_features(features)
                .map_err(|error| format!("invalid host feature set: {error}"))?;
        }
        validate_host_features(target.features)?;
        Ok(Some(Self {
            trials,
            warmup_rounds,
            bytes_per_trial,
            min_searches,
            min_trial_ns,
            target,
            target_name,
            smoke: partial.smoke,
            family_filter: partial.family_filter,
            pattern_filter: partial.pattern_filter,
            route_filter: partial.route_filter,
            measurement_order: partial.measurement_order.unwrap_or_default(),
            output_matrix: partial.output_matrix,
            force_resource_fallback: partial.force_resource_fallback,
            force_retained_resource_fallback: partial.force_retained_resource_fallback,
            force_slow_partial_resource_fallback: partial
                .force_slow_partial_resource_fallback,
            seed_filter: partial.seed_filter,
            grammar: partial.grammar,
            nested_grammar: partial.nested_grammar,
        }))
    }
}

fn is_known_route(route: &str) -> bool {
    matches!(
        route,
        "direct_dfa"
            | "direct_context_dfa"
            | "direct_context_fallback"
            | "direct_resource_fallback"
            | "prepared_runtime_assertion"
            | "ordinary_runtime_assertion"
            | "ordinary_runtime_resource_fallback"
            | "prepared_runtime_resource_fallback"
            | "slow_partial_resource_fallback"
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ForcedFallbackMode {
    None,
    ZeroRows,
    RetainedRows,
    SlowPartial,
}

impl ForcedFallbackMode {
    const fn slow_aot_policy(self) -> &'static str {
        match self {
            Self::None => "default",
            Self::ZeroRows => "disabled_for_zero_rows",
            Self::RetainedRows => "disabled_for_retained_rows",
            Self::SlowPartial => "derived_incomplete_forward_prefix",
        }
    }
}

fn forced_fallback_mode(
    zero_rows: bool,
    retained_rows: bool,
    slow_partial: bool,
) -> Result<ForcedFallbackMode, String> {
    match (zero_rows, retained_rows, slow_partial) {
        (false, false, false) => Ok(ForcedFallbackMode::None),
        (true, false, false) => Ok(ForcedFallbackMode::ZeroRows),
        (false, true, false) => Ok(ForcedFallbackMode::RetainedRows),
        (false, false, true) => Ok(ForcedFallbackMode::SlowPartial),
        _ => Err(
            "--force-resource-fallback, --force-retained-resource-fallback, and \
             --force-slow-partial-resource-fallback are mutually exclusive"
                .to_owned(),
        ),
    }
}

impl Config {
    fn forced_fallback_mode(&self) -> ForcedFallbackMode {
        forced_fallback_mode(
            self.force_resource_fallback,
            self.force_retained_resource_fallback,
            self.force_slow_partial_resource_fallback,
        )
        .expect("parsed force modes remain mutually exclusive")
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum MeasurementOrder {
    #[default]
    UpstreamNative,
    NativeUpstream,
}

impl MeasurementOrder {
    const fn name(self) -> &'static str {
        match self {
            Self::UpstreamNative => "upstream-native",
            Self::NativeUpstream => "native-upstream",
        }
    }
}

fn parse_measurement_order(value: &str) -> Result<MeasurementOrder, String> {
    match value {
        "upstream-native" => Ok(MeasurementOrder::UpstreamNative),
        "native-upstream" => Ok(MeasurementOrder::NativeUpstream),
        _ => Err(format!(
            "--measurement-order must be upstream-native or native-upstream, got {value:?}"
        )),
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
        .map_err(|_| format!("{flag} requires a non-negative integer"))
}

fn parse_seed(value: &str) -> Result<u64, String> {
    let parsed = value
        .strip_prefix("0x")
        .map_or_else(|| value.parse::<u64>(), |hex| u64::from_str_radix(hex, 16));
    parsed.map_err(|_| format!("--seed requires a decimal or 0x-prefixed u64, got {value:?}"))
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

fn feature_requested(features: FeatureSet, feature: CpuFeature) -> bool {
    features.contains(FeatureSet::EMPTY.with(feature))
}

#[cfg(target_arch = "x86_64")]
fn validate_host_features(features: FeatureSet) -> Result<(), String> {
    let checks = [
        (
            CpuFeature::X86Sse2,
            "sse2",
            std::arch::is_x86_feature_detected!("sse2"),
        ),
        (
            CpuFeature::X86Avx2,
            "avx2",
            std::arch::is_x86_feature_detected!("avx2"),
        ),
        (
            CpuFeature::X86Avx512F,
            "avx512f",
            std::arch::is_x86_feature_detected!("avx512f"),
        ),
        (
            CpuFeature::X86Avx512Bw,
            "avx512bw",
            std::arch::is_x86_feature_detected!("avx512bw"),
        ),
        (
            CpuFeature::X86Avx512Vl,
            "avx512vl",
            std::arch::is_x86_feature_detected!("avx512vl"),
        ),
    ];
    for (feature, name, available) in checks {
        if feature_requested(features, feature) && !available {
            return Err(format!(
                "requested host CPU feature {name:?} is unavailable"
            ));
        }
    }
    Ok(())
}

#[cfg(target_arch = "aarch64")]
fn validate_host_features(features: FeatureSet) -> Result<(), String> {
    let checks = [
        (
            CpuFeature::Aarch64Asimd,
            "asimd",
            std::arch::is_aarch64_feature_detected!("neon"),
        ),
        (
            CpuFeature::Aarch64Sve,
            "sve",
            std::arch::is_aarch64_feature_detected!("sve"),
        ),
        (
            CpuFeature::Aarch64Sve2,
            "sve2",
            std::arch::is_aarch64_feature_detected!("sve2"),
        ),
    ];
    for (feature, name, available) in checks {
        if feature_requested(features, feature) && !available {
            return Err(format!(
                "requested host CPU feature {name:?} is unavailable"
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputKind {
    Span,
    Exists,
    SelectedEnd,
}

impl OutputKind {
    const MATRIX: [Self; 3] = [Self::Span, Self::Exists, Self::SelectedEnd];

    const fn contract(self) -> OutputContract {
        match self {
            Self::Span => OutputContract::Span,
            Self::Exists => OutputContract::Exists,
            Self::SelectedEnd => OutputContract::SelectedEnd,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Span => "span",
            Self::Exists => "exists",
            Self::SelectedEnd => "selected_end",
        }
    }

    const fn upstream_operation(self) -> &'static str {
        match self {
            Self::Span => "find",
            Self::Exists => "is_match",
            Self::SelectedEnd => "find_end",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct PatternSpec {
    name: &'static str,
    family: &'static str,
    pattern: &'static str,
    fixture: &'static [u8],
    candidates: &'static [u8],
    output: OutputKind,
    guard_before: Option<u8>,
    guard_after: Option<u8>,
    force_fallback: bool,
}

const PATTERNS: [PatternSpec; 24] = [
    PatternSpec {
        name: "literal_needle_span",
        family: "literal",
        pattern: "needle",
        fixture: b"needle",
        candidates: b"n",
        output: OutputKind::Span,
        guard_before: None,
        guard_after: None,
        force_fallback: false,
    },
    PatternSpec {
        name: "literal_terminal_exists",
        family: "literal",
        pattern: "terminal",
        fixture: b"terminal",
        candidates: b"t",
        output: OutputKind::Exists,
        guard_before: None,
        guard_after: None,
        force_fallback: false,
    },
    PatternSpec {
        name: "class_small_span",
        family: "class",
        pattern: "[A-F0-9_]QZ",
        fixture: b"AQZ",
        candidates: b"A0_",
        output: OutputKind::Span,
        guard_before: None,
        guard_after: None,
        force_fallback: false,
    },
    PatternSpec {
        name: "class_full_byte_exists",
        family: "class",
        pattern: r"(?-u:[\x00-\xFF])END",
        fixture: b"~END",
        candidates: b"~",
        output: OutputKind::Exists,
        guard_before: None,
        guard_after: None,
        force_fallback: false,
    },
    PatternSpec {
        name: "concat_digit_span",
        family: "concat",
        pattern: "ab[0-9]{2}Z",
        fixture: b"ab42Z",
        candidates: b"a",
        output: OutputKind::Span,
        guard_before: None,
        guard_after: None,
        force_fallback: false,
    },
    PatternSpec {
        name: "concat_class_exists",
        family: "concat",
        pattern: "xy[A-Z]tail",
        fixture: b"xyQtail",
        candidates: b"x",
        output: OutputKind::Exists,
        guard_before: None,
        guard_after: None,
        force_fallback: false,
    },
    PatternSpec {
        name: "alternation_words_span",
        family: "alternation",
        pattern: "(?:alpha|beta|gamma)Z",
        fixture: b"betaZ",
        candidates: b"abg",
        output: OutputKind::Span,
        guard_before: None,
        guard_after: None,
        force_fallback: false,
    },
    PatternSpec {
        name: "alternation_lengths_exists",
        family: "alternation",
        pattern: "(?:foo|bar|quux)END",
        fixture: b"barEND",
        candidates: b"fbq",
        output: OutputKind::Exists,
        guard_before: None,
        guard_after: None,
        force_fallback: false,
    },
    PatternSpec {
        name: "greedy_branch_span",
        family: "greedy_repetition",
        pattern: "(?:ab|c){2,6}Z",
        fixture: b"abcZ",
        candidates: b"ac",
        output: OutputKind::Span,
        guard_before: Some(b'!'),
        guard_after: None,
        force_fallback: false,
    },
    PatternSpec {
        name: "greedy_plus_exists",
        family: "greedy_repetition",
        pattern: "(?:mn|p)+R",
        fixture: b"mnpR",
        candidates: b"mp",
        output: OutputKind::Exists,
        guard_before: None,
        guard_after: None,
        force_fallback: false,
    },
    PatternSpec {
        name: "lazy_bounded_span",
        family: "lazy_repetition",
        pattern: "(?:xy|z){2,6}?Q",
        fixture: b"xyzQ",
        candidates: b"xz",
        output: OutputKind::Span,
        guard_before: Some(b'!'),
        guard_after: None,
        force_fallback: false,
    },
    PatternSpec {
        name: "lazy_plus_exists",
        family: "lazy_repetition",
        pattern: "(?:de|f)+?R",
        fixture: b"defR",
        candidates: b"df",
        output: OutputKind::Exists,
        guard_before: None,
        guard_after: None,
        force_fallback: false,
    },
    PatternSpec {
        name: "bounded_class_span",
        family: "bounded_repetition",
        pattern: "[mn]{3,5}R",
        fixture: b"mnmR",
        candidates: b"mn",
        output: OutputKind::Span,
        guard_before: Some(b'!'),
        guard_after: None,
        force_fallback: false,
    },
    PatternSpec {
        name: "bounded_concat_exists",
        family: "bounded_repetition",
        pattern: "(?:hi){2,4}J",
        fixture: b"hihiJ",
        candidates: b"h",
        output: OutputKind::Exists,
        guard_before: None,
        guard_after: None,
        force_fallback: false,
    },
    PatternSpec {
        name: "nullable_star_span",
        family: "nullable_repetition",
        pattern: "(?:uv|w)*YZ",
        fixture: b"uvYZ",
        candidates: b"uw",
        output: OutputKind::Span,
        guard_before: Some(b'!'),
        guard_after: None,
        force_fallback: false,
    },
    PatternSpec {
        name: "nullable_optional_exists",
        family: "nullable_repetition",
        pattern: "(?:ab|c)?END",
        fixture: b"abEND",
        candidates: b"ac",
        output: OutputKind::Exists,
        guard_before: None,
        guard_after: None,
        force_fallback: false,
    },
    PatternSpec {
        name: "unicode_multiscript_span",
        family: "unicode",
        pattern: "(?:Δ|東京|é){1,3}K",
        fixture: "東京éK".as_bytes(),
        candidates: &[0xce, 0xe6, 0xc3],
        output: OutputKind::Span,
        guard_before: Some(b'!'),
        guard_after: None,
        force_fallback: false,
    },
    PatternSpec {
        name: "unicode_multiscript_exists",
        family: "unicode",
        pattern: "(?:λ|大阪|ß)+Q",
        fixture: "大阪ßQ".as_bytes(),
        candidates: &[0xce, 0xe5, 0xc3],
        output: OutputKind::Exists,
        guard_before: None,
        guard_after: None,
        force_fallback: false,
    },
    PatternSpec {
        name: "line_item_span",
        family: "line_assertion",
        pattern: r"(?m)^item[0-9]{2}$",
        fixture: b"item42",
        candidates: b"i",
        output: OutputKind::Span,
        guard_before: Some(b'\n'),
        guard_after: Some(b'\n'),
        force_fallback: false,
    },
    PatternSpec {
        name: "line_warn_exists",
        family: "line_assertion",
        pattern: r"(?m)^WARN:[A-Z]+$",
        fixture: b"WARN:OK",
        candidates: b"W",
        output: OutputKind::Exists,
        guard_before: Some(b'\n'),
        guard_after: Some(b'\n'),
        force_fallback: false,
    },
    PatternSpec {
        name: "word_animals_span",
        family: "word_assertion",
        pattern: r"(?-u:\b(?:cat|dog)\b)",
        fixture: b"dog",
        candidates: b"cd",
        output: OutputKind::Span,
        guard_before: Some(b'!'),
        guard_after: Some(b'!'),
        force_fallback: false,
    },
    PatternSpec {
        name: "word_colors_exists",
        family: "word_assertion",
        pattern: r"(?-u:\b(?:red|blue)\b)",
        fixture: b"blue",
        candidates: b"rb",
        output: OutputKind::Exists,
        guard_before: Some(b'!'),
        guard_after: Some(b'!'),
        force_fallback: false,
    },
    PatternSpec {
        name: "resource_branches_span",
        family: "resource_fallback",
        pattern: "(?:ab|ac|ad)+z",
        fixture: b"abacz",
        candidates: b"a",
        output: OutputKind::Span,
        guard_before: Some(b'!'),
        guard_after: None,
        force_fallback: true,
    },
    PatternSpec {
        name: "resource_words_exists",
        family: "resource_fallback",
        pattern: "(?:foo|bar|baz){2,4}Q",
        fixture: b"foobarQ",
        candidates: b"fb",
        output: OutputKind::Exists,
        guard_before: None,
        guard_after: None,
        force_fallback: true,
    },
];

#[derive(Clone, Debug)]
struct SeededPatternSpec {
    name: String,
    base_name: String,
    family: &'static str,
    source_kind: &'static str,
    pattern: String,
    fixture: Vec<u8>,
    candidates: Vec<u8>,
    output: OutputKind,
    guard_before: Option<u8>,
    guard_after: Option<u8>,
    force_fallback: bool,
    seed: u64,
    generation_id: usize,
}

fn expand_output_matrix(specs: Vec<SeededPatternSpec>, enabled: bool) -> Vec<SeededPatternSpec> {
    if !enabled {
        return specs;
    }
    specs
        .into_iter()
        .flat_map(|spec| {
            OutputKind::MATRIX.map(move |output| {
                let mut expanded = spec.clone();
                expanded.name = format!("{}_output_{}", spec.name, output.name());
                expanded.output = output;
                expanded
            })
        })
        .collect()
}

fn shifted_ascii(byte: u8, seed: u64) -> u8 {
    let shift = (seed & 1) as u8 + 1;
    match byte {
        b'a'..=b'z' => b'a' + (byte - b'a' + shift) % 26,
        b'A'..=b'Z' => b'A' + (byte - b'A' + shift) % 26,
        b'0'..=b'9' => b'0' + (byte - b'0' + shift) % 10,
        _ => byte,
    }
}

fn instantiate_pattern(
    base_index: usize,
    base: PatternSpec,
    seed_index: usize,
    seed: u64,
) -> Result<SeededPatternSpec, String> {
    let selected = base
        .candidates
        .iter()
        .copied()
        .find(|byte| {
            byte.is_ascii_alphanumeric()
                && base.fixture.contains(byte)
                && !(*byte == b'b' && base.pattern.contains(r"\b"))
        })
        .or_else(|| {
            base.fixture
                .iter()
                .rev()
                .copied()
                .find(u8::is_ascii_alphanumeric)
        })
        .ok_or_else(|| format!("{} has no seedable literal byte", base.name))?;
    let replacement = shifted_ascii(selected, seed);
    let rewrite = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|&byte| if byte == selected { replacement } else { byte })
            .collect::<Vec<_>>()
    };
    let pattern = String::from_utf8(rewrite(base.pattern.as_bytes()))
        .map_err(|error| format!("{} seeded pattern was not UTF-8: {error}", base.name))?;
    let fixture = rewrite(base.fixture);
    let mut candidates = rewrite(base.candidates);
    if !candidates.is_empty() {
        let rotation = usize::try_from(seed % candidates.len() as u64)
            .expect("candidate rotation is bounded by a usize length");
        candidates.rotate_left(rotation);
    }
    Ok(SeededPatternSpec {
        name: format!("{}_seed_{seed:016x}", base.name),
        base_name: base.name.to_owned(),
        family: base.family,
        source_kind: "fixed_seeded",
        pattern,
        fixture,
        candidates,
        output: base.output,
        guard_before: base.guard_before,
        guard_after: base.guard_after,
        force_fallback: base.force_fallback,
        seed,
        generation_id: seed_index * PATTERNS.len() + base_index,
    })
}

const GRAMMAR_FAMILIES: [&str; 9] = [
    "grammar_concat",
    "grammar_alternation",
    "grammar_class",
    "grammar_bounded_greedy",
    "grammar_bounded_lazy",
    "grammar_unbounded_greedy",
    "grammar_unbounded_lazy",
    "grammar_nullable",
    "grammar_assertion",
];
const GRAMMAR_PATTERNS_PER_FAMILY: usize = 4;

#[derive(Clone, Copy, Debug)]
struct GrammarRng {
    state: u64,
}

impl GrammarRng {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn choose(&mut self, length: usize) -> usize {
        usize::try_from(self.next() % length as u64).expect("choice is bounded by a usize length")
    }
}

fn grammar_word(rng: &mut GrammarRng, length: usize) -> String {
    const INITIALS: &[u8] = b"bcdfghjklmnpqrstvwxyz";
    const TAILS: &[u8] = b"aeiou";
    let mut word = String::with_capacity(length);
    word.push(char::from(INITIALS[rng.choose(INITIALS.len())]));
    for _ in 1..length {
        word.push(char::from(TAILS[rng.choose(TAILS.len())]));
    }
    word
}

fn grammar_word_with_length(
    rng: &mut GrammarRng,
    minimum_length: usize,
    length_choices: usize,
) -> String {
    let length = minimum_length + rng.choose(length_choices);
    grammar_word(rng, length)
}

fn push_repeated_alternatives(fixture: &mut String, first: &str, second: &str, units: usize) {
    for unit in 0..units {
        fixture.push_str(if unit.is_multiple_of(2) {
            first
        } else {
            second
        });
    }
}

fn grammar_pattern(
    seed_index: usize,
    seed: u64,
    family_index: usize,
    ordinal: usize,
) -> SeededPatternSpec {
    let family = GRAMMAR_FAMILIES[family_index];
    let mixed_seed = seed
        ^ (family_index as u64).wrapping_mul(0xd1b5_4a32_d192_ed03)
        ^ (ordinal as u64).wrapping_mul(0x94d0_49bb_1331_11eb);
    let mut rng = GrammarRng::new(mixed_seed);
    let sentinel = char::from(b'Q' + u8::try_from(rng.choose(9)).expect("choice fits u8"));
    let (pattern, fixture, candidates, guard_before, guard_after) = match family_index {
        0 => {
            let left = grammar_word_with_length(&mut rng, 2, 3);
            let right = grammar_word_with_length(&mut rng, 2, 3);
            let low = b'A' + u8::try_from(rng.choose(16)).expect("choice fits u8");
            let high = low + 2;
            let fixture = format!("{left}{}{right}{sentinel}", char::from(low + 1));
            (
                format!(
                    "{left}[{}-{}]{right}{sentinel}",
                    char::from(low),
                    char::from(high)
                ),
                fixture,
                vec![left.as_bytes()[0]],
                None,
                None,
            )
        }
        1 => {
            let first = grammar_word_with_length(&mut rng, 2, 3);
            let mut second = grammar_word_with_length(&mut rng, 3, 3);
            let mut third = grammar_word_with_length(&mut rng, 2, 4);
            if second == first {
                second.push('a');
            }
            if third == first || third == second {
                third.push('e');
            }
            let fixture = format!("{second}{sentinel}");
            (
                format!("(?:{first}|{second}|{third}){sentinel}"),
                fixture,
                vec![
                    first.as_bytes()[0],
                    second.as_bytes()[0],
                    third.as_bytes()[0],
                ],
                None,
                None,
            )
        }
        2 => {
            let low = b'a' + u8::try_from(rng.choose(16)).expect("choice fits u8");
            let high = low + 3;
            let upper_low = b'J' + u8::try_from(rng.choose(7)).expect("choice fits u8");
            let upper_high = upper_low + 2;
            let fixture = format!(
                "{}{}{}{sentinel}",
                char::from(low + 1),
                char::from(upper_low + 1),
                char::from(upper_low + 2)
            );
            (
                format!(
                    "[{}-{}][{}-{}]{{2}}{sentinel}",
                    char::from(low),
                    char::from(high),
                    char::from(upper_low),
                    char::from(upper_high)
                ),
                fixture,
                vec![low, low + 1, high],
                None,
                None,
            )
        }
        3 | 4 => {
            let first = grammar_word(&mut rng, 2);
            let second = grammar_word(&mut rng, 1);
            let minimum = 2 + rng.choose(2);
            let maximum = minimum + 2 + rng.choose(2);
            let mut fixture = String::new();
            push_repeated_alternatives(&mut fixture, &first, &second, minimum + 1);
            fixture.push(sentinel);
            let lazy = if family_index == 4 { "?" } else { "" };
            (
                format!("(?:{first}|{second}){{{minimum},{maximum}}}{lazy}{sentinel}"),
                fixture,
                vec![first.as_bytes()[0], second.as_bytes()[0]],
                Some(b'!'),
                None,
            )
        }
        5 | 6 => {
            let first = grammar_word(&mut rng, 2);
            let second = grammar_word(&mut rng, 1);
            let mut fixture = String::new();
            push_repeated_alternatives(&mut fixture, &first, &second, 4);
            fixture.push(sentinel);
            let lazy = if family_index == 6 { "?" } else { "" };
            (
                format!("(?:{first}|{second})+{lazy}{sentinel}"),
                fixture,
                vec![first.as_bytes()[0], second.as_bytes()[0]],
                Some(b'!'),
                None,
            )
        }
        7 => {
            let optional = grammar_word(&mut rng, 3);
            let repeated = grammar_word(&mut rng, 2);
            let branch = grammar_word(&mut rng, 1);
            let fixture = format!("{optional}{repeated}{branch}{sentinel}");
            (
                format!("(?:{optional})?(?:{repeated}|{branch})*{sentinel}"),
                fixture,
                vec![
                    optional.as_bytes()[0],
                    repeated.as_bytes()[0],
                    branch.as_bytes()[0],
                ],
                Some(b'!'),
                None,
            )
        }
        8 if ordinal.is_multiple_of(2) => {
            let word = grammar_word_with_length(&mut rng, 3, 3);
            let fixture = format!("{word}42");
            (
                format!(r"(?m)^{word}[0-9]{{2}}$"),
                fixture,
                vec![word.as_bytes()[0]],
                Some(b'\n'),
                Some(b'\n'),
            )
        }
        8 => {
            let first = grammar_word_with_length(&mut rng, 4, 2);
            let mut second = grammar_word_with_length(&mut rng, 4, 2);
            if second == first {
                second.push('a');
            }
            if second.as_bytes()[0] == first.as_bytes()[0] {
                let replacement = if first.as_bytes()[0] == b'z' {
                    "q"
                } else {
                    "z"
                };
                second.replace_range(..1, replacement);
            }
            (
                format!(r"(?-u:\b(?:{first}|{second})\b)"),
                second.clone(),
                vec![first.as_bytes()[0], second.as_bytes()[0]],
                Some(b'!'),
                Some(b'!'),
            )
        }
        _ => unreachable!("grammar family index is statically bounded"),
    };
    let output = if (seed_index + family_index + ordinal).is_multiple_of(2) {
        OutputKind::Span
    } else {
        OutputKind::Exists
    };
    let name = format!("{family}_{ordinal}_seed_{seed:016x}");
    SeededPatternSpec {
        base_name: format!("{family}_{ordinal}"),
        name,
        family,
        source_kind: "grammar_generated",
        pattern,
        fixture: fixture.into_bytes(),
        candidates,
        output,
        guard_before,
        guard_after,
        force_fallback: false,
        seed,
        generation_id: 100_000
            + seed_index * GRAMMAR_FAMILIES.len() * GRAMMAR_PATTERNS_PER_FAMILY
            + family_index * GRAMMAR_PATTERNS_PER_FAMILY
            + ordinal,
    }
}

fn selected_generator_seeds(selected: Option<u64>) -> Vec<(usize, u64)> {
    selected.map_or_else(
        || PATTERN_SEEDS.iter().copied().enumerate().collect(),
        |seed| {
            vec![(
                PATTERN_SEEDS
                    .iter()
                    .position(|&built_in| built_in == seed)
                    .unwrap_or(0),
                seed,
            )]
        },
    )
}

fn grammar_patterns(config: &Config) -> Vec<SeededPatternSpec> {
    selected_generator_seeds(config.seed_filter)
        .into_iter()
        .flat_map(|(seed_index, seed)| {
            (0..GRAMMAR_FAMILIES.len()).flat_map(move |family_index| {
                (0..GRAMMAR_PATTERNS_PER_FAMILY)
                    .map(move |ordinal| grammar_pattern(seed_index, seed, family_index, ordinal))
            })
        })
        .collect()
}

const NESTED_GRAMMAR_FAMILIES: [&str; 12] = [
    "nested_concat",
    "nested_alternation",
    "nested_class_range",
    "nested_bounded_greedy",
    "nested_bounded_lazy",
    "nested_unbounded_greedy",
    "nested_unbounded_lazy",
    "nested_nullable",
    "nested_line_assertion",
    "nested_word_assertion",
    "nested_mixed_bounded",
    "nested_mixed_unbounded",
];
const NESTED_PATTERNS_PER_FAMILY: usize = 4;
const NESTED_MAX_WITNESS_BYTES: usize = 48;
const NESTED_MAX_PATTERN_BYTES: usize = 768;

#[derive(Clone, Debug)]
enum NestedExpr {
    Literal(Vec<u8>),
    ClassRange {
        low: u8,
        high: u8,
        witness: u8,
    },
    /// One unconstrained byte. A quarter of the nested corpus ends in this
    /// node so a required-terminal-byte optimizer cannot dominate the suite.
    AnyByte,
    Concat(Vec<Self>),
    Alternation {
        branches: Vec<Self>,
        witness_branch: usize,
    },
    Repeat {
        expression: Box<Self>,
        minimum: usize,
        maximum: Option<usize>,
        lazy: bool,
        witness_count: usize,
    },
}

impl NestedExpr {
    fn render_into(&self, rendered: &mut String) {
        match self {
            Self::Literal(bytes) => {
                for &byte in bytes {
                    rendered.push(char::from(byte));
                }
            }
            Self::ClassRange { low, high, .. } => {
                rendered.push('[');
                rendered.push(char::from(*low));
                rendered.push('-');
                rendered.push(char::from(*high));
                rendered.push(']');
            }
            Self::AnyByte => rendered.push_str(r"(?-u:[\x00-\xFF])"),
            Self::Concat(expressions) => {
                rendered.push_str("(?:");
                for expression in expressions {
                    expression.render_into(rendered);
                }
                rendered.push(')');
            }
            Self::Alternation { branches, .. } => {
                rendered.push_str("(?:");
                for (index, branch) in branches.iter().enumerate() {
                    if index != 0 {
                        rendered.push('|');
                    }
                    branch.render_into(rendered);
                }
                rendered.push(')');
            }
            Self::Repeat {
                expression,
                minimum,
                maximum,
                lazy,
                ..
            } => {
                rendered.push_str("(?:");
                expression.render_into(rendered);
                rendered.push(')');
                match (*minimum, *maximum) {
                    (0, None) => rendered.push('*'),
                    (1, None) => rendered.push('+'),
                    (0, Some(1)) => rendered.push('?'),
                    (minimum, Some(maximum)) if minimum == maximum => {
                        write!(rendered, "{{{minimum}}}").expect("writing to a String cannot fail");
                    }
                    (minimum, Some(maximum)) => {
                        write!(rendered, "{{{minimum},{maximum}}}")
                            .expect("writing to a String cannot fail");
                    }
                    (minimum, None) => {
                        write!(rendered, "{{{minimum},}}")
                            .expect("writing to a String cannot fail");
                    }
                }
                if *lazy {
                    rendered.push('?');
                }
            }
        }
    }

    fn render(&self) -> String {
        let mut rendered = String::new();
        self.render_into(&mut rendered);
        rendered
    }

    fn witness_into(&self, witness: &mut Vec<u8>) {
        match self {
            Self::Literal(bytes) => witness.extend_from_slice(bytes),
            Self::ClassRange { witness: byte, .. } => witness.push(*byte),
            Self::AnyByte => witness.push(b'a'),
            Self::Concat(expressions) => {
                for expression in expressions {
                    expression.witness_into(witness);
                }
            }
            Self::Alternation {
                branches,
                witness_branch,
            } => branches[*witness_branch].witness_into(witness),
            Self::Repeat {
                expression,
                witness_count,
                ..
            } => {
                for _ in 0..*witness_count {
                    expression.witness_into(witness);
                }
            }
        }
    }

    fn witness(&self) -> Vec<u8> {
        let mut witness = Vec::new();
        self.witness_into(&mut witness);
        witness
    }

    fn nullable(&self) -> bool {
        match self {
            Self::Literal(bytes) => bytes.is_empty(),
            Self::ClassRange { .. } | Self::AnyByte => false,
            Self::Concat(expressions) => expressions.iter().all(Self::nullable),
            Self::Alternation { branches, .. } => branches.iter().any(Self::nullable),
            Self::Repeat {
                expression,
                minimum,
                ..
            } => *minimum == 0 || expression.nullable(),
        }
    }

    fn first_bytes_into(&self, bytes: &mut BTreeSet<u8>) {
        match self {
            Self::Literal(literal) => {
                if let Some(&byte) = literal.first() {
                    bytes.insert(byte);
                }
            }
            Self::ClassRange { low, high, .. } => {
                bytes.extend(*low..=*high);
            }
            Self::AnyByte => bytes.extend(u8::MIN..=u8::MAX),
            Self::Concat(expressions) => {
                for expression in expressions {
                    expression.first_bytes_into(bytes);
                    if !expression.nullable() {
                        break;
                    }
                }
            }
            Self::Alternation { branches, .. } => {
                for branch in branches {
                    branch.first_bytes_into(bytes);
                }
            }
            Self::Repeat { expression, .. } => expression.first_bytes_into(bytes),
        }
    }

    fn first_bytes(&self) -> Vec<u8> {
        let mut bytes = BTreeSet::new();
        self.first_bytes_into(&mut bytes);
        bytes.into_iter().collect()
    }
}

fn nested_literal(rng: &mut GrammarRng, minimum: usize, choices: usize) -> NestedExpr {
    const ALPHABET: &[u8] = b"abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let length = minimum + rng.choose(choices);
    let bytes = (0..length)
        .map(|_| ALPHABET[rng.choose(ALPHABET.len())])
        .collect();
    NestedExpr::Literal(bytes)
}

fn nested_class(rng: &mut GrammarRng) -> NestedExpr {
    const BASES: &[(u8, usize)] = &[(b'a', 20), (b'A', 20), (b'2', 4)];
    let (base, room) = BASES[rng.choose(BASES.len())];
    let low = base + u8::try_from(rng.choose(room)).expect("class offset fits u8");
    let width = 1 + u8::try_from(rng.choose(4)).expect("class width fits u8");
    let high = low + width;
    let witness = low + u8::try_from(rng.choose(usize::from(width) + 1)).expect("choice fits u8");
    NestedExpr::ClassRange { low, high, witness }
}

fn nested_atom(rng: &mut GrammarRng) -> NestedExpr {
    if rng.choose(3) == 0 {
        nested_class(rng)
    } else {
        nested_literal(rng, 1, 3)
    }
}

fn nested_required_tail(rng: &mut GrammarRng) -> NestedExpr {
    match rng.choose(4) {
        0 => nested_literal(rng, 2, 3),
        1 => nested_class(rng),
        2 => NestedExpr::Concat(vec![nested_class(rng), nested_literal(rng, 1, 2)]),
        3 => NestedExpr::Alternation {
            branches: vec![nested_atom(rng), nested_atom(rng)],
            witness_branch: rng.choose(2),
        },
        _ => unreachable!("grammar choice is statically bounded"),
    }
}

fn nested_consuming(rng: &mut GrammarRng, expression: NestedExpr) -> NestedExpr {
    if expression.nullable() {
        NestedExpr::Concat(vec![expression, nested_atom(rng)])
    } else {
        expression
    }
}

fn nested_bounded_repeat(rng: &mut GrammarRng, expression: NestedExpr, lazy: bool) -> NestedExpr {
    let expression = nested_consuming(rng, expression);
    let minimum = 1 + rng.choose(2);
    let maximum = minimum + 1 + rng.choose(3);
    NestedExpr::Repeat {
        expression: Box::new(expression),
        minimum,
        maximum: Some(maximum),
        lazy,
        witness_count: minimum + rng.choose(maximum - minimum + 1),
    }
}

fn nested_unbounded_repeat(rng: &mut GrammarRng, expression: NestedExpr, lazy: bool) -> NestedExpr {
    let expression = nested_consuming(rng, expression);
    NestedExpr::Repeat {
        expression: Box::new(expression),
        minimum: 1,
        maximum: None,
        lazy,
        witness_count: 1 + rng.choose(3),
    }
}

fn nested_nullable_piece(rng: &mut GrammarRng, expression: NestedExpr) -> NestedExpr {
    let expression = nested_consuming(rng, expression);
    if rng.choose(2) == 0 {
        NestedExpr::Repeat {
            expression: Box::new(expression),
            minimum: 0,
            maximum: Some(1),
            lazy: rng.choose(2) == 0,
            witness_count: rng.choose(2),
        }
    } else {
        NestedExpr::Repeat {
            expression: Box::new(expression),
            minimum: 0,
            maximum: None,
            lazy: rng.choose(2) == 0,
            witness_count: rng.choose(3),
        }
    }
}

fn nested_mixed_expr(rng: &mut GrammarRng, depth: usize) -> NestedExpr {
    if depth == 0 {
        return nested_atom(rng);
    }
    let deep = nested_mixed_expr(rng, depth - 1);
    match rng.choose(6) {
        0 => NestedExpr::Concat(vec![deep, nested_atom(rng), nested_atom(rng)]),
        1 => {
            let witness_branch = rng.choose(3);
            NestedExpr::Alternation {
                branches: vec![deep, nested_atom(rng), nested_atom(rng)],
                witness_branch,
            }
        }
        2 => nested_bounded_repeat(rng, deep, false),
        3 => nested_bounded_repeat(rng, deep, true),
        4 => {
            let lazy = rng.choose(2) == 0;
            nested_unbounded_repeat(rng, deep, lazy)
        }
        5 => nested_nullable_piece(rng, deep),
        _ => unreachable!("grammar choice is statically bounded"),
    }
}

fn nested_family_expr(rng: &mut GrammarRng, family_index: usize, depth: usize) -> NestedExpr {
    let inner_depth = depth.saturating_sub(1);
    match family_index {
        0 => NestedExpr::Concat(vec![
            nested_mixed_expr(rng, inner_depth),
            nested_atom(rng),
            nested_mixed_expr(rng, inner_depth / 2),
        ]),
        1 => NestedExpr::Alternation {
            branches: vec![
                nested_mixed_expr(rng, inner_depth),
                nested_mixed_expr(rng, inner_depth / 2),
                nested_atom(rng),
            ],
            witness_branch: rng.choose(3),
        },
        2 => NestedExpr::Concat(vec![
            nested_class(rng),
            nested_mixed_expr(rng, inner_depth),
            nested_class(rng),
        ]),
        3 => {
            let inner = nested_mixed_expr(rng, inner_depth);
            nested_bounded_repeat(rng, inner, false)
        }
        4 => {
            let inner = nested_mixed_expr(rng, inner_depth);
            nested_bounded_repeat(rng, inner, true)
        }
        5 => {
            let inner = nested_mixed_expr(rng, inner_depth);
            nested_unbounded_repeat(rng, inner, false)
        }
        6 => {
            let inner = nested_mixed_expr(rng, inner_depth);
            nested_unbounded_repeat(rng, inner, true)
        }
        7 => {
            let optional_inner = nested_mixed_expr(rng, inner_depth);
            let star_inner = nested_mixed_expr(rng, inner_depth / 2);
            NestedExpr::Concat(vec![
                nested_nullable_piece(rng, optional_inner),
                nested_nullable_piece(rng, star_inner),
                nested_atom(rng),
            ])
        }
        8 | 9 => nested_mixed_expr(rng, depth),
        10 => {
            let alternation = NestedExpr::Alternation {
                branches: vec![
                    nested_mixed_expr(rng, inner_depth),
                    nested_atom(rng),
                    nested_class(rng),
                ],
                witness_branch: rng.choose(3),
            };
            let bounded_inner = nested_mixed_expr(rng, inner_depth / 2);
            let lazy = rng.choose(2) == 0;
            NestedExpr::Concat(vec![
                alternation,
                nested_bounded_repeat(rng, bounded_inner, lazy),
                nested_class(rng),
            ])
        }
        11 => {
            let repeated_inner = nested_mixed_expr(rng, inner_depth);
            let lazy = rng.choose(2) == 0;
            let left = NestedExpr::Concat(vec![
                nested_unbounded_repeat(rng, repeated_inner, lazy),
                nested_atom(rng),
            ]);
            let nullable_inner = nested_mixed_expr(rng, inner_depth / 2);
            let right = NestedExpr::Concat(vec![
                nested_nullable_piece(rng, nullable_inner),
                nested_mixed_expr(rng, inner_depth / 2),
            ]);
            NestedExpr::Alternation {
                branches: vec![left, right],
                witness_branch: rng.choose(2),
            }
        }
        _ => unreachable!("nested grammar family index is statically bounded"),
    }
}

fn nested_pattern(
    seed_index: usize,
    seed: u64,
    family_index: usize,
    ordinal: usize,
) -> Result<SeededPatternSpec, String> {
    let family = NESTED_GRAMMAR_FAMILIES[family_index];
    let depth = 2 + ordinal;
    for attempt in 0..64_usize {
        let mixed_seed = seed
            ^ (family_index as u64).wrapping_mul(0xa076_1d64_78bd_642f)
            ^ (ordinal as u64).wrapping_mul(0xe703_7ed1_a0b4_28db)
            ^ (attempt as u64).wrapping_mul(0x8ebc_6af0_9c88_c6e3);
        let mut rng = GrammarRng::new(mixed_seed);
        let core = nested_family_expr(&mut rng, family_index, depth);
        let expression = if ordinal + 1 == NESTED_PATTERNS_PER_FAMILY {
            NestedExpr::Concat(vec![core, NestedExpr::AnyByte])
        } else {
            NestedExpr::Concat(vec![core, nested_required_tail(&mut rng)])
        };
        let fixture = expression.witness();
        let body = expression.render();
        let (pattern, guard_before, guard_after) = match family_index {
            8 => (format!(r"(?m)^(?:{body})$"), Some(b'\n'), Some(b'\n')),
            9 => (format!(r"(?-u:\b(?:{body})\b)"), Some(b'!'), Some(b'!')),
            _ => (body, Some(b'!'), None),
        };
        if fixture.is_empty()
            || fixture.len() > NESTED_MAX_WITNESS_BYTES
            || pattern.len() > NESTED_MAX_PATTERN_BYTES
        {
            continue;
        }
        let candidates = expression.first_bytes();
        if candidates.is_empty() {
            continue;
        }
        let output = if (seed_index + family_index + ordinal).is_multiple_of(2) {
            OutputKind::Span
        } else {
            OutputKind::Exists
        };
        return Ok(SeededPatternSpec {
            name: format!("{family}_depth_{depth}_{ordinal}_seed_{seed:016x}"),
            base_name: format!("{family}_depth_{depth}_{ordinal}"),
            family,
            source_kind: "nested_grammar_generated",
            pattern,
            fixture,
            candidates,
            output,
            guard_before,
            guard_after,
            force_fallback: false,
            seed,
            generation_id: 200_000
                + seed_index * NESTED_GRAMMAR_FAMILIES.len() * NESTED_PATTERNS_PER_FAMILY
                + family_index * NESTED_PATTERNS_PER_FAMILY
                + ordinal,
        });
    }
    Err(format!(
        "nested grammar could not bound {family} ordinal {ordinal} for seed 0x{seed:016x}"
    ))
}

fn nested_grammar_patterns(config: &Config) -> Result<Vec<SeededPatternSpec>, String> {
    selected_generator_seeds(config.seed_filter)
        .into_iter()
        .flat_map(|(seed_index, seed)| {
            (0..NESTED_GRAMMAR_FAMILIES.len()).flat_map(move |family_index| {
                (0..NESTED_PATTERNS_PER_FAMILY)
                    .map(move |ordinal| nested_pattern(seed_index, seed, family_index, ordinal))
            })
        })
        .collect()
}

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
    near_miss: bool,
}

const DENSITIES: [CandidateDensity; 5] = [
    CandidateDensity {
        name: "zero",
        stride: 0,
        near_miss: false,
    },
    CandidateDensity {
        name: "1_per_32",
        stride: 32,
        near_miss: false,
    },
    CandidateDensity {
        name: "1_per_8",
        stride: 8,
        near_miss: false,
    },
    CandidateDensity {
        name: "near_miss_1_per_32",
        stride: 32,
        near_miss: true,
    },
    CandidateDensity {
        name: "dense",
        stride: 1,
        near_miss: false,
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AbiResult {
    status: u32,
    start: usize,
    end: usize,
}

const NO_MATCH: AbiResult = AbiResult {
    status: 0,
    start: 0,
    end: 0,
};

impl AbiResult {
    fn from_aot(result: MatchResult, output: OutputKind) -> Result<Self, String> {
        match (output, result) {
            (OutputKind::Span, MatchResult::Span(Some((start, end)))) => Ok(Self {
                status: 1,
                start,
                end,
            }),
            (OutputKind::Span, MatchResult::Span(None))
            | (OutputKind::Exists, MatchResult::Exists(false)) => Ok(NO_MATCH),
            (OutputKind::Exists, MatchResult::Exists(true)) => Ok(Self {
                status: 1,
                start: 0,
                end: 0,
            }),
            (OutputKind::SelectedEnd, MatchResult::SelectedEnd(Some(end))) => Ok(Self {
                status: 1,
                start: end,
                end,
            }),
            (OutputKind::SelectedEnd, MatchResult::SelectedEnd(None)) => Ok(NO_MATCH),
            (_, other) => Err(format!("unexpected output-contract result {other:?}")),
        }
    }
}

#[derive(Debug)]
struct CompiledShape {
    spec: SeededPatternSpec,
    upstream: Regex,
    aot: CompiledRegex,
    runtime_program: Option<(String, usize)>,
    partial_dfa: Option<PartialDfaStats>,
    prepared_capability_format: &'static str,
    fallback_artifact_kind: &'static str,
    retained_limit_derivation: &'static str,
}

impl CompiledShape {
    fn route(&self) -> &'static str {
        match self.aot.receipt().engine_selection_reason {
            EngineSelectionReason::CompleteDfa => "direct_dfa",
            EngineSelectionReason::CompleteContextDfa => "direct_context_dfa",
            EngineSelectionReason::ContextAssertions => {
                if self.aot.module().prepared_entry_symbol().is_some() {
                    "prepared_runtime_assertion"
                } else if self.runtime_program.is_some() {
                    "ordinary_runtime_assertion"
                } else {
                    "direct_context_fallback"
                }
            }
            EngineSelectionReason::DeterminizationResourceLimit => {
                if is_genuine_slow_partial(&self.aot) {
                    "slow_partial_resource_fallback"
                } else if self.aot.module().prepared_entry_symbol().is_some() {
                    "prepared_runtime_resource_fallback"
                } else if self.runtime_program.is_some() {
                    "ordinary_runtime_resource_fallback"
                } else {
                    "direct_resource_fallback"
                }
            }
            EngineSelectionReason::FastMode => "unexpected_fast_mode",
        }
    }

    fn is_compiled_primary(&self) -> bool {
        let module = self.aot.module();
        let entry = module.entry_symbol();
        module
            .symbols()
            .iter()
            .any(|symbol| symbol.name == entry && symbol.section.is_some())
    }

    fn timed_entry_scope(&self) -> &'static str {
        if self.aot.module().prepared_entry_symbol().is_some() {
            "prepared_compiled"
        } else if self.runtime_program.is_some() {
            "runtime_dependent_compiled"
        } else {
            "self_contained_compiled"
        }
    }

    fn score_scope(&self) -> &'static str {
        if is_genuine_slow_partial(&self.aot) {
            "slow_aot_partial_generated_entry"
        } else if self.aot.module().prepared_entry_symbol().is_some() {
            "prepared_compiled_all_windows"
        } else if self.runtime_program.is_some() && self.partial_dfa.is_some() {
            "runtime_dependent_partial_compiled_entry"
        } else if self.runtime_program.is_some() {
            "runtime_dependent_compiled_entry"
        } else if self.runtime_program.is_none()
            && self.partial_dfa.is_some_and(|stats| {
                stats.complete_rows != 0
                    && stats.complete_rows == stats.discovered_states
                    && stats.resume_frontiers == 0
                    && stats.resume_items == 0
            })
        {
            "retained_complete_direct_all_windows"
        } else if self.runtime_program.is_none() && self.partial_dfa.is_some() {
            "slow_aot_self_contained_all_windows"
        } else {
            "self_contained_compiled_all_windows"
        }
    }
}

fn compile_source_aot_with_slow_limits(
    pattern: &str,
    output: OutputKind,
    target: Target,
    limits: CompileLimitsV1,
    slow_aot_limits: SlowAotLimits,
) -> Result<CompiledRegex, String> {
    compile_with_slow_aot_limits(
        CompileRequest::new(pattern.to_owned(), target)
            .mode(CompileMode::Optimizing)
            .output(output.contract())
            .limits(limits),
        slow_aot_limits,
    )
    .map_err(|error| format!("AOT compilation failed: {error}"))
}

fn compile_shape_aot(
    spec: &SeededPatternSpec,
    target: Target,
    limits: CompileLimitsV1,
) -> Result<CompiledRegex, String> {
    compile_shape_aot_with_slow_limits(spec, target, limits, SlowAotLimits::default())
}

fn compile_shape_aot_with_slow_limits(
    spec: &SeededPatternSpec,
    target: Target,
    limits: CompileLimitsV1,
    slow_aot_limits: SlowAotLimits,
) -> Result<CompiledRegex, String> {
    compile_source_aot_with_slow_limits(
        &spec.pattern,
        spec.output,
        target,
        limits,
        slow_aot_limits,
    )
    .map_err(|error| format!("{} {error}", spec.name))
}

fn disabled_slow_aot_limits() -> SlowAotLimits {
    let mut limits = SlowAotLimits::default();
    limits.determinize.max_states = 0;
    limits.determinize.max_transitions = 0;
    limits.determinize.max_work = 0;
    limits.max_allocation_bytes = 0;
    limits.max_native_data_bytes = 0;
    limits
}

fn is_genuine_slow_partial(compiled: &CompiledRegex) -> bool {
    compiled.receipt().slow_aot.as_ref().is_some_and(|report| {
        report
            .determinization
            .decline
            .is_some_and(|decline| decline.stage == DeterminizationStage::ForwardSubsetConstruction)
            && report.dfa.forward_states > 0
            && report.dfa.forward_states < report.dfa.forward_states_before_minimization
    })
}

fn retained_partial_stats(compiled: &CompiledRegex) -> Result<Option<PartialDfaStats>, String> {
    compiled
        .program()
        .partial_dfa_stats()
        .map_err(|error| format!("partial-DFA statistics failed: {error}"))
}

fn has_usable_retained_rows(compiled: &CompiledRegex) -> Result<bool, String> {
    Ok(retained_partial_stats(compiled)?.is_some_and(|stats| {
        stats.complete_rows > 0 && stats.optimized_entry_supported
    }))
}

fn prepared_capability_format(compiled: &CompiledRegex) -> Result<&'static str, String> {
    if compiled.module().prepared_entry_symbol().is_none() {
        return Ok("not_prepared");
    }
    if compiled.module().required_runtime_program().is_none() {
        return Err("prepared native entry has no serialized runtime program".to_owned());
    }

    // Mirror PreparedAotRegex::from_program exactly far enough to report
    // which immutable offset-zero capability would be active before the
    // first native call. This is structural and setup-derived: it does not
    // recognize pattern names or inspect benchmark inputs.
    let program = compiled.program();
    let mut workspace = program
        .prepare_workspace()
        .map_err(|error| format!("prepared capability workspace failed: {error}"))?;
    let fully_prefilled_fallback = program
        .compiler_private_try_prefill_retained_fallback_with_workspace_receipt(&mut workspace)
        .map_err(|error| format!("prepared capability prefill failed: {error}"))?;
    let mut frozen_dynamic_rows = program
        .compiler_private_frozen_dynamic_rows_storage_v3_with_fallback_receipt(
            &mut workspace,
            fully_prefilled_fallback,
            FROZEN_DYNAMIC_SIDECAR_MAX_K0_BYTES,
            FROZEN_DYNAMIC_SIDECAR_MAX_PACKED_BYTES,
        );
    let mut frozen_header = if frozen_dynamic_rows.is_some() {
        program.compiler_private_frozen_prepared_header_v6(
            &workspace,
            None,
            frozen_dynamic_rows.as_ref(),
        )
    } else {
        program.compiler_private_frozen_prepared_header_v6(
            &workspace,
            fully_prefilled_fallback,
            None,
        )
    };
    if frozen_dynamic_rows.is_some() && !frozen_header.has_dynamic_rows() {
        frozen_dynamic_rows = None;
        frozen_header = program.compiler_private_frozen_prepared_header_v6(
            &workspace,
            fully_prefilled_fallback,
            None,
        );
    }
    if frozen_header.has_dynamic_rows() {
        if frozen_dynamic_rows.is_none() {
            return Err("active compact header lost its immutable owner".to_owned());
        }
        Ok("active_immutable_compact_v3_v14")
    } else if frozen_header.is_active() {
        Ok("active_immutable_retained_v1")
    } else {
        Ok("prepared_no_immutable_capability")
    }
}

fn is_self_contained_native_shape(compiled: &CompiledRegex) -> bool {
    let module = compiled.module();
    if module.required_runtime_program().is_some()
        || module.prepared_entry_symbol().is_some()
        || module.required_runtime_symbol().is_some()
        || module.required_prepared_runtime_symbol().is_some()
        || module.required_prepared_fallback_runtime_symbol().is_some()
        || module.required_prepared_admission_runtime_symbol().is_some()
        || module.required_prepared_preflight_runtime_symbol().is_some()
        || module
            .required_prepared_dynamic_rows_deopt_runtime_symbol()
            .is_some()
        || module
            .required_prepared_dynamic_rows_continue_runtime_symbol()
            .is_some()
        || module
            .required_prepared_dynamic_rows_span_recovery_runtime_symbol()
            .is_some()
        || module
            .required_prepared_dynamic_rows_loop_scan_runtime_symbol()
            .is_some()
        || module.required_prepared_span_recovery_runtime_symbol().is_some()
        || compiled.receipt().runtime_helper_required
    {
        return false;
    }
    let has_unresolved = module
        .symbols()
        .iter()
        .any(|symbol| symbol.section.is_none());
    // The runtime static library is linked below and owns every public
    // adapter ABI. Treat any unresolved symbol structurally as a runtime
    // dependency so a newer partial-resume helper remains benchmarkable
    // without teaching this example its private symbol name.
    !has_unresolved
}

fn compile_retained_resource_probe(
    spec: &SeededPatternSpec,
    target: Target,
) -> Result<(CompiledRegex, &'static str), String> {
    compile_retained_resource_probe_with_limits(spec, target, CompileLimitsV1::default())
}

fn compile_retained_resource_probe_with_limits(
    spec: &SeededPatternSpec,
    target: Target,
    probe_limits: CompileLimitsV1,
) -> Result<(CompiledRegex, &'static str), String> {
    let probe = compile_shape_aot(spec, target, probe_limits)?;
    let bounded_probe = compile_shape_aot_with_slow_limits(
        spec,
        target,
        probe_limits,
        disabled_slow_aot_limits(),
    )?;
    if probe.receipt().context_determinization.is_some() {
        return Ok((bounded_probe, "excluded_contextual"));
    }
    if retained_partial_stats(&probe)?.is_some_and(|stats| stats.complete_rows > 0) {
        if has_usable_retained_rows(&bounded_probe)? {
            return Ok((bounded_probe, "natural_decline_slow_disabled"));
        }
        return Ok((bounded_probe, "excluded_unusable_natural_retained_rows"));
    }
    let Some(dfa) = probe.receipt().dfa else {
        return Ok((bounded_probe, "excluded_non_dfa_probe"));
    };

    if let Some(max_states) = dfa.forward_states_before_minimization.checked_sub(1)
        && max_states > 0
    {
        let mut limits = probe_limits;
        limits.determinize.max_states = max_states;
        let state_limited = compile_shape_aot_with_slow_limits(
            spec,
            target,
            limits,
            disabled_slow_aot_limits(),
        )?;
        if has_usable_retained_rows(&state_limited)? {
            return Ok((state_limited, "forward_state_limit"));
        }
    }

    let Some(max_work) = dfa.build_work.checked_sub(1) else {
        return Ok((bounded_probe, "excluded_zero_build_work"));
    };
    let mut limits = probe_limits;
    limits.determinize.max_work = max_work;
    let work_limited = compile_shape_aot_with_slow_limits(
        spec,
        target,
        limits,
        disabled_slow_aot_limits(),
    )?;
    if has_usable_retained_rows(&work_limited)? {
        Ok((work_limited, "final_work_limit"))
    } else {
        Ok((work_limited, "excluded_no_usable_retained_rows"))
    }
}

fn compile_slow_partial_resource_probe(
    pattern: &str,
    output: OutputKind,
    target: Target,
) -> Result<(CompiledRegex, &'static str), String> {
    let mut semantic_limits = CompileLimitsV1::default();
    semantic_limits.determinize.max_states = 0;
    let full_probe = compile_source_aot_with_slow_limits(
        pattern,
        output,
        target,
        semantic_limits,
        SlowAotLimits::default(),
    )?;
    if full_probe.receipt().context_determinization.is_some() {
        return Ok((full_probe, "excluded_contextual"));
    }
    if full_probe.receipt().engine_selection_reason
        != EngineSelectionReason::DeterminizationResourceLimit
    {
        return Ok((full_probe, "excluded_non_resource_fallback"));
    }
    let (full_decline, full_forward_states) = {
        let Some(report) = full_probe.receipt().slow_aot.as_ref() else {
            let exact_product = full_probe.program().has_nfa_exact_product();
            return Ok((
                full_probe,
                if exact_product {
                    "excluded_exact_product"
                } else {
                    "excluded_no_complete_slow_probe"
                },
            ));
        };
        (
            report.determinization.decline,
            report.dfa.forward_states_before_minimization,
        )
    };
    if is_genuine_slow_partial(&full_probe) {
        return Ok((full_probe, "slow_natural_resource_limit"));
    }
    if full_decline.is_some() {
        return Ok((full_probe, "excluded_no_complete_slow_probe"));
    }
    if full_forward_states <= 1 {
        return Ok((full_probe, "excluded_no_interior_slow_state_limit"));
    }

    let primary_limit = full_forward_states - 1;
    let candidate_limits = std::iter::once(primary_limit).chain(
        (1..full_forward_states).filter(move |&max_states| max_states != primary_limit),
    );
    for max_states in candidate_limits {
        let mut slow_limits = SlowAotLimits::default();
        slow_limits.determinize.max_states = max_states;
        let candidate = compile_source_aot_with_slow_limits(
            pattern,
            output,
            target,
            semantic_limits,
            slow_limits,
        )?;
        if is_genuine_slow_partial(&candidate) {
            return Ok((
                candidate,
                if max_states == primary_limit {
                    "slow_forward_state_limit"
                } else {
                    "slow_forward_state_search"
                },
            ));
        }
    }
    Ok((full_probe, "excluded_no_genuine_slow_partial"))
}

fn compile_shapes(config: &Config) -> Result<Vec<CompiledShape>, String> {
    let seeded = if config.nested_grammar {
        nested_grammar_patterns(config)?
    } else if config.grammar {
        grammar_patterns(config)
    } else {
        PATTERN_SEEDS
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, seed)| config.seed_filter.is_none_or(|selected| selected == *seed))
            .flat_map(|(seed_index, seed)| {
                PATTERNS
                    .iter()
                    .copied()
                    .enumerate()
                    .map(move |(base_index, base)| {
                        instantiate_pattern(base_index, base, seed_index, seed)
                    })
            })
            .collect::<Result<Vec<_>, String>>()?
    };
    if (config.grammar || config.nested_grammar)
        && seeded
            .iter()
            .map(|spec| spec.pattern.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            != seeded.len()
    {
        return Err("seeded grammar generation produced a duplicate regex".to_owned());
    }
    let seeded = expand_output_matrix(seeded, config.output_matrix);
    let mut shapes = seeded
        .into_iter()
        .filter(|spec| {
            config
                .family_filter
                .as_deref()
                .is_none_or(|family| spec.family == family)
                && config
                    .pattern_filter
                    .as_deref()
                    .is_none_or(|name| spec.base_name == name || spec.name == name)
        })
        .map(|spec| {
            let forced_mode = config.forced_fallback_mode();
            let force_runtime_fallback = spec.force_fallback
                || matches!(
                    forced_mode,
                    ForcedFallbackMode::ZeroRows | ForcedFallbackMode::SlowPartial
                );
            let upstream = Regex::new(&spec.pattern)
                .map_err(|error| format!("{} upstream compilation failed: {error}", spec.name))?;
            let (aot, retained_limit_derivation) =
                match forced_mode {
                    ForcedFallbackMode::RetainedRows => {
                        compile_retained_resource_probe(&spec, config.target)?
                    }
                    ForcedFallbackMode::SlowPartial => {
                        compile_slow_partial_resource_probe(
                            &spec.pattern,
                            spec.output,
                            config.target,
                        )
                        .map_err(|error| format!("{} {error}", spec.name))?
                    }
                    ForcedFallbackMode::None | ForcedFallbackMode::ZeroRows => {
                        let mut limits = CompileLimitsV1::default();
                        if force_runtime_fallback {
                            limits.determinize.max_states = 0;
                        }
                        let aot = if force_runtime_fallback {
                            compile_shape_aot_with_slow_limits(
                                &spec,
                                config.target,
                                limits,
                                disabled_slow_aot_limits(),
                            )?
                        } else {
                            compile_shape_aot(&spec, config.target, limits)?
                        };
                        (
                            aot,
                            if force_runtime_fallback {
                                "zero_state_slow_disabled"
                            } else {
                                "not_requested"
                            },
                        )
                    }
                };
            let has_context_assertions = aot.receipt().context_determinization.is_some();
            let force_ordinary_fallback = spec.force_fallback
                || forced_mode == ForcedFallbackMode::ZeroRows && !has_context_assertions;
            let witness_upstream = upstream_search(&upstream, spec.output, &spec.fixture);
            let witness_aot = AbiResult::from_aot(
                aot.search(&spec.fixture, SearchWindow::full(&spec.fixture))
                    .map_err(|error| {
                        format!("{} portable witness validation failed: {error}", spec.name)
                    })?,
                spec.output,
            )?;
            if witness_upstream.status == 0 || witness_upstream != witness_aot {
                return Err(format!(
                    "{} generated witness failed: upstream {witness_upstream:?}, AOT {witness_aot:?}",
                    spec.name
                ));
            }
            let reason = aot.receipt().engine_selection_reason;
            if force_ordinary_fallback
                && reason != EngineSelectionReason::DeterminizationResourceLimit
            {
                return Err(format!(
                    "{} did not take forced resource fallback: {reason:?}",
                    spec.name
                ));
            }
            if has_context_assertions
                && !matches!(
                    reason,
                    EngineSelectionReason::CompleteContextDfa
                        | EngineSelectionReason::ContextAssertions
                )
            {
                return Err(format!(
                    "{} did not take the contextual compiler route: {reason:?}",
                    spec.name
                ));
            }
            let runtime_program = aot
                .module()
                .required_runtime_program()
                .map(|(symbol, bytes)| (symbol.to_owned(), bytes));
            let partial_dfa = retained_partial_stats(&aot)?;
            let exact_product = aot.program().has_nfa_exact_product();
            let structurally_runtime_backed =
                reason == EngineSelectionReason::DeterminizationResourceLimit;
            if runtime_program.is_some()
                && !spec.force_fallback
                && forced_mode == ForcedFallbackMode::None
                && !has_context_assertions
                && !structurally_runtime_backed
            {
                return Err(format!(
                    "{} unexpectedly retained a runtime program",
                    spec.name
                ));
            }
            let self_contained_engine = is_self_contained_native_shape(&aot);
            if force_ordinary_fallback && runtime_program.is_none() && !self_contained_engine {
                return Err(format!(
                    "{} forced resource fallback has neither a runtime program nor a self-contained native entry",
                    spec.name
                ));
            }
            if runtime_program.is_none()
                && (aot.module().required_runtime_symbol().is_some() || !self_contained_engine)
            {
                return Err(format!(
                    "{} did not compile to a self-contained native engine",
                    spec.name
                ));
            }
            let prepared_entry_published = aot.module().prepared_entry_symbol().is_some();
            if prepared_entry_published && runtime_program.is_none() {
                return Err(format!(
                    "{} published a prepared native entry without its serialized runtime program",
                    spec.name
                ));
            }
            let entry_symbol = aot.module().entry_symbol();
            if !aot
                .module()
                .symbols()
                .iter()
                .any(|symbol| symbol.name == entry_symbol && symbol.section.is_some())
            {
                return Err(format!(
                    "{} emitted no defined generated entry for timed execution",
                    spec.name
                ));
            }
            let prepared_capability_format = prepared_capability_format(&aot)
                .map_err(|error| format!("{} {error}", spec.name))?;
            let fallback_artifact_kind = if is_genuine_slow_partial(&aot) {
                "slow_aot_partial"
            } else if partial_dfa.is_some() {
                "retained_partial"
            } else if exact_product {
                "exact_product"
            } else if has_context_assertions {
                "contextual"
            } else if aot
                .module()
                .required_prepared_dynamic_rows_deopt_runtime_symbol()
                .is_some()
            {
                "dynamic_rows"
            } else if aot.receipt().engine == EngineKind::OrderedNfa {
                "plain_nfa"
            } else {
                "direct"
            };
            if config.force_retained_resource_fallback
                && !retained_limit_derivation.starts_with("excluded_")
                && let Some(stats) = partial_dfa
                && (reason != EngineSelectionReason::DeterminizationResourceLimit
                    || aot.receipt().engine != EngineKind::OrderedNfa
                    || runtime_program.is_none() && !self_contained_engine
                    || stats.complete_rows == 0
                    || !stats.optimized_entry_supported)
            {
                return Err(format!(
                    "{} retained-row probe produced an inconsistent artifact: reason={reason:?}, engine={:?}, runtime={}, prepared_entry_published={prepared_entry_published}, stats={stats:?}",
                    spec.name,
                    aot.receipt().engine,
                    runtime_program.is_some(),
                ));
            }
            if forced_mode == ForcedFallbackMode::SlowPartial
                && !retained_limit_derivation.starts_with("excluded_")
                && !is_genuine_slow_partial(&aot)
            {
                return Err(format!(
                    "{} derived slow-partial row failed its public receipt admission criteria",
                    spec.name
                ));
            }
            Ok(CompiledShape {
                spec,
                upstream,
                aot,
                runtime_program,
                partial_dfa,
                prepared_capability_format,
                fallback_artifact_kind,
                retained_limit_derivation,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    if let Some(route) = config.route_filter.as_deref() {
        shapes.retain(|shape| shape.route() == route);
        if route == "prepared_runtime_resource_fallback"
            && shapes
                .iter()
                .any(|shape| {
                    shape.aot.module().prepared_entry_symbol().is_none()
                        || shape.runtime_program.is_none()
                })
        {
            return Err(
                "prepared runtime route selected an artifact without its native entry and serialized program"
                    .to_owned(),
            );
        }
        if route == "slow_partial_resource_fallback"
            && shapes.iter().any(|shape| !is_genuine_slow_partial(&shape.aot))
        {
            return Err(
                "slow-partial route selected an artifact without a genuine incomplete forward prefix"
                    .to_owned(),
            );
        }
    }
    if shapes.is_empty() {
        return Err("the requested filters selected no generated patterns".to_owned());
    }
    if config.seed_filter.is_none()
        && shapes
            .iter()
            .map(|shape| shape.spec.seed)
            .collect::<BTreeSet<_>>()
            .len()
            < 2
    {
        return Err(
            "the default benchmark requires at least two distinct printed seeds".to_owned(),
        );
    }
    Ok(shapes)
}

fn seed_component(seed: u64, shift: u32) -> usize {
    usize::try_from((seed >> shift) & 0xffff).expect("supported hosts have at least 32-bit usize")
}

fn nested_distribution_hash(seed: u64, generation_id: usize, index: usize, rotation: usize) -> u64 {
    let mut value = seed
        ^ (generation_id as u64).wrapping_mul(0xa076_1d64_78bd_642f)
        ^ (index as u64).wrapping_mul(0xe703_7ed1_a0b4_28db)
        ^ (rotation as u64).wrapping_mul(0x8ebc_6af0_9c88_c6e3);
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn nested_background_byte(spec: &SeededPatternSpec, index: usize, rotation: usize) -> u8 {
    let value = nested_distribution_hash(spec.seed, spec.generation_id, index, rotation);
    match rotation % ROTATIONS {
        0 => {
            let safe_index = index
                .wrapping_mul(13 + seed_component(spec.seed, 8) % 16)
                .wrapping_add(rotation.wrapping_mul(7 + seed_component(spec.seed, 24) % 16))
                .wrapping_add(
                    spec.generation_id
                        .wrapping_mul(11 + seed_component(spec.seed, 40) % 16),
                )
                .wrapping_add(seed_component(spec.seed, 0))
                % SAFE_BYTES.len();
            SAFE_BYTES[safe_index]
        }
        1 => {
            let index = usize::try_from(
                value
                    % u64::try_from(ENGLISHISH_BYTES.len())
                        .expect("static Englishish alphabet length fits u64"),
            )
            .expect("reduced Englishish alphabet index fits usize");
            ENGLISHISH_BYTES[index]
        }
        2 => {
            let index = usize::try_from(
                value
                    % u64::try_from(CODEISH_BYTES.len())
                        .expect("static code alphabet length fits u64"),
            )
            .expect("reduced code alphabet index fits usize");
            CODEISH_BYTES[index]
        }
        3 => u8::try_from(value & u64::from(u8::MAX))
            .expect("masked full-byte background value fits u8"),
        _ => unreachable!("rotation is reduced modulo the static rotation count"),
    }
}

fn generated_haystack(
    generation_id: usize,
    spec: &SeededPatternSpec,
    haystack_len: usize,
    density: CandidateDensity,
    position: MatchPosition,
    rotation: usize,
) -> Vec<u8> {
    let mut haystack = Vec::with_capacity(haystack_len);
    for index in 0..haystack_len {
        if spec.source_kind == "nested_grammar_generated" {
            haystack.push(nested_background_byte(spec, index, rotation));
        } else {
            let safe_index = index
                .wrapping_mul(13 + seed_component(spec.seed, 8) % 16)
                .wrapping_add(rotation.wrapping_mul(7 + seed_component(spec.seed, 24) % 16))
                .wrapping_add(generation_id.wrapping_mul(11 + seed_component(spec.seed, 40) % 16))
                .wrapping_add(seed_component(spec.seed, 0))
                % SAFE_BYTES.len();
            haystack.push(SAFE_BYTES[safe_index]);
        }
    }
    if density.near_miss {
        let phase = rotation
            .wrapping_mul(17 + seed_component(spec.seed, 4) % 16)
            .wrapping_add(generation_id.wrapping_mul(23 + seed_component(spec.seed, 20) % 16))
            .wrapping_add(seed_component(spec.seed, 16))
            % density.stride;
        let mut index = phase;
        while index + spec.fixture.len() <= haystack_len {
            haystack[index..index + spec.fixture.len()].copy_from_slice(&spec.fixture);
            haystack[index + spec.fixture.len() - 1] =
                SAFE_BYTES[(index + rotation + seed_component(spec.seed, 48)) % SAFE_BYTES.len()];
            index = index.saturating_add(density.stride);
        }
    } else if density.stride != 0 {
        let phase = rotation
            .wrapping_mul(17 + seed_component(spec.seed, 4) % 16)
            .wrapping_add(generation_id.wrapping_mul(23 + seed_component(spec.seed, 20) % 16))
            .wrapping_add(seed_component(spec.seed, 16))
            % density.stride;
        let mut index = phase;
        while index < haystack_len {
            let candidate_index = (index / density.stride)
                .wrapping_add(rotation)
                .wrapping_add(generation_id)
                .wrapping_add(seed_component(spec.seed, 32))
                % spec.candidates.len();
            haystack[index] = spec.candidates[candidate_index];
            index = index.saturating_add(density.stride);
        }
    }
    if let Some(offset) = position.offset(haystack_len, spec.fixture.len()) {
        haystack[offset..offset + spec.fixture.len()].copy_from_slice(&spec.fixture);
        if offset > 0
            && let Some(guard) = spec.guard_before
        {
            haystack[offset - 1] = guard;
        }
        let after = offset + spec.fixture.len();
        if after < haystack_len
            && let Some(guard) = spec.guard_after
        {
            haystack[after] = guard;
        }
    }
    haystack
}

fn upstream_search(regex: &Regex, output: OutputKind, haystack: &[u8]) -> AbiResult {
    match output {
        OutputKind::Span => regex.find(haystack).map_or(NO_MATCH, |matched| AbiResult {
            status: 1,
            start: matched.start(),
            end: matched.end(),
        }),
        OutputKind::Exists => AbiResult {
            status: u32::from(regex.is_match(haystack)),
            start: 0,
            end: 0,
        },
        OutputKind::SelectedEnd => regex.find(haystack).map_or(NO_MATCH, |matched| {
            let end = matched.end();
            AbiResult {
                status: 1,
                start: end,
                end,
            }
        }),
    }
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

fn searches_per_trial(config: &Config, haystack_len: usize) -> usize {
    let requested = config.bytes_per_trial.div_ceil(haystack_len);
    requested.max(config.min_searches)
}

#[derive(Clone, Debug)]
struct Scenario {
    case_name: String,
    shape_index: usize,
    size: usize,
    density: CandidateDensity,
    position: MatchPosition,
    searches: usize,
    expected: [AbiResult; ROTATIONS],
    fingerprints: [u64; ROTATIONS],
}

fn sizes(config: &Config) -> &'static [usize] {
    if config.smoke {
        &WINDOW_SIZES[..1]
    } else if config.nested_grammar {
        &[64, 4 * 1024, 64 * 1024]
    } else if config.grammar {
        &[64, 64 * 1024]
    } else {
        &WINDOW_SIZES
    }
}

fn positions(config: &Config) -> &'static [MatchPosition] {
    if config.smoke {
        &[MatchPosition::Start]
    } else if config.nested_grammar {
        &MatchPosition::ALL
    } else if config.grammar {
        &[
            MatchPosition::None,
            MatchPosition::Start,
            MatchPosition::End,
        ]
    } else {
        &MatchPosition::ALL
    }
}

fn densities(config: &Config) -> &'static [CandidateDensity] {
    if config.smoke {
        &DENSITIES[..1]
    } else if config.nested_grammar {
        &[DENSITIES[0], DENSITIES[1], DENSITIES[3], DENSITIES[4]]
    } else if config.grammar {
        &[DENSITIES[0], DENSITIES[2], DENSITIES[3]]
    } else {
        &DENSITIES
    }
}

fn generator_expected(spec: &SeededPatternSpec, size: usize, position: MatchPosition) -> AbiResult {
    position
        .offset(size, spec.fixture.len())
        .map_or(NO_MATCH, |start| match spec.output {
            OutputKind::Span => AbiResult {
                status: 1,
                start,
                end: start + spec.fixture.len(),
            },
            OutputKind::Exists => AbiResult {
                status: 1,
                start: 0,
                end: 0,
            },
            OutputKind::SelectedEnd => {
                let end = start + spec.fixture.len();
                AbiResult {
                    status: 1,
                    start: end,
                    end,
                }
            }
        })
}

fn generated_insertion_is_valid(
    nested_grammar: bool,
    output_matrix: bool,
    position: MatchPosition,
    upstream: AbiResult,
    intended: AbiResult,
) -> bool {
    upstream == intended
        || if nested_grammar {
            position == MatchPosition::None || upstream.status != 0
        } else {
            output_matrix
                && position != MatchPosition::None
                && upstream.status != 0
                && upstream.start <= intended.start
                && upstream.end >= intended.end
        }
}

fn build_scenarios(config: &Config, shapes: &[CompiledShape]) -> Result<Vec<Scenario>, String> {
    let mut scenarios = Vec::new();
    for (shape_index, shape) in shapes.iter().enumerate() {
        for &size in sizes(config) {
            for &position in positions(config) {
                for &density in densities(config) {
                    let haystacks: [Vec<u8>; ROTATIONS] = std::array::from_fn(|rotation| {
                        generated_haystack(
                            shape.spec.generation_id,
                            &shape.spec,
                            size,
                            density,
                            position,
                            rotation,
                        )
                    });
                    let intended = generator_expected(&shape.spec, size, position);
                    let mut expected = [NO_MATCH; ROTATIONS];
                    for (rotation, haystack) in haystacks.iter().enumerate() {
                        let upstream =
                            upstream_search(&shape.upstream, shape.spec.output, haystack);
                        let aot = AbiResult::from_aot(
                            shape
                                .aot
                                .search(haystack, SearchWindow::full(haystack))
                                .map_err(|error| {
                                    format!(
                                        "{} portable validation failed: {error}",
                                        shape.spec.name
                                    )
                                })?,
                            shape.spec.output,
                        )?;
                        if upstream != aot
                            || !generated_insertion_is_valid(
                                config.nested_grammar,
                                config.output_matrix,
                                position,
                                upstream,
                                intended,
                            )
                        {
                            return Err(format!(
                                "{} validation failed for {size}/{}/{}/rotation {rotation}: upstream oracle {upstream:?}, AOT {aot:?}, generated insertion {intended:?}",
                                shape.spec.name,
                                position.name(),
                                density.name,
                            ));
                        }
                        expected[rotation] = upstream;
                    }
                    let fingerprints =
                        std::array::from_fn(|rotation| byte_fingerprint(&haystacks[rotation]));
                    scenarios.push(Scenario {
                        case_name: format!(
                            "{}_{}_{}_{}",
                            shape.spec.name,
                            size,
                            position.name(),
                            density.name
                        ),
                        shape_index,
                        size,
                        density,
                        position,
                        searches: searches_per_trial(config, size),
                        expected,
                        fingerprints,
                    });
                }
            }
        }
    }
    Ok(scenarios)
}

#[derive(Clone, Copy, Debug)]
struct Measurement {
    searches: usize,
    min_elapsed_ns: f64,
    median_elapsed_ns: f64,
    min_ns_per_search: f64,
    median_ns_per_search: f64,
    checksum: u64,
}

fn expected_checksum(scenario: &Scenario, searches: usize, trial: usize) -> u64 {
    (0..searches).fold(0_u64, |checksum, iteration| {
        checksum_step(
            checksum,
            scenario.expected[(iteration + trial) % ROTATIONS],
            iteration as u64,
        )
    })
}

fn upstream_batch(
    shape: &CompiledShape,
    haystacks: &[Vec<u8>; ROTATIONS],
    searches: usize,
    trial: usize,
) -> (u128, u64) {
    let mut checksum = 0_u64;
    let before = Instant::now();
    for iteration in 0..searches {
        let rotation = (iteration + trial) % ROTATIONS;
        let result = upstream_search(
            &shape.upstream,
            shape.spec.output,
            black_box(&haystacks[rotation]),
        );
        checksum = checksum_step(checksum, result, iteration as u64);
    }
    (before.elapsed().as_nanos(), checksum)
}

fn median(samples: &[u128]) -> f64 {
    let middle = samples.len() / 2;
    if samples.len().is_multiple_of(2) {
        f64::midpoint(samples[middle - 1] as f64, samples[middle] as f64)
    } else {
        samples[middle] as f64
    }
}

fn measure_upstream(
    config: &Config,
    shapes: &[CompiledShape],
    scenarios: &[Scenario],
) -> Result<BTreeMap<String, Measurement>, String> {
    let mut measurements = BTreeMap::new();
    for scenario in scenarios {
        let shape = &shapes[scenario.shape_index];
        let haystacks: [Vec<u8>; ROTATIONS] = std::array::from_fn(|rotation| {
            generated_haystack(
                shape.spec.generation_id,
                &shape.spec,
                scenario.size,
                scenario.density,
                scenario.position,
                rotation,
            )
        });
        for round in 0..config.warmup_rounds * ROTATIONS {
            black_box(upstream_search(
                &shape.upstream,
                shape.spec.output,
                black_box(&haystacks[round % ROTATIONS]),
            ));
        }
        let mut searches = scenario.searches;
        loop {
            let (elapsed, checksum) = upstream_batch(shape, &haystacks, searches, 0);
            if checksum != expected_checksum(scenario, searches, 0) {
                return Err(format!(
                    "{} upstream calibration checksum changed",
                    scenario.case_name
                ));
            }
            black_box(checksum);
            if elapsed >= config.min_trial_ns as u128 {
                break;
            }
            searches = searches
                .checked_mul(2)
                .ok_or_else(|| format!("{} upstream calibration overflow", scenario.case_name))?;
        }
        let (samples, last_checksum) = loop {
            let mut samples = Vec::with_capacity(config.trials);
            let mut last_checksum = 0;
            for trial in 0..config.trials {
                let (elapsed, checksum) = upstream_batch(shape, &haystacks, searches, trial);
                samples.push(elapsed);
                if checksum != expected_checksum(scenario, searches, trial) {
                    return Err(format!(
                        "{} upstream timed checksum changed",
                        scenario.case_name
                    ));
                }
                last_checksum = checksum;
                black_box(checksum);
            }
            samples.sort_unstable();
            if samples[0] >= config.min_trial_ns as u128 {
                break (samples, last_checksum);
            }
            searches = searches.checked_mul(2).ok_or_else(|| {
                format!("{} upstream retry calibration overflow", scenario.case_name)
            })?;
        };
        let minimum = samples[0] as f64;
        let med = median(&samples);
        measurements.insert(
            scenario.case_name.clone(),
            Measurement {
                searches,
                min_elapsed_ns: minimum,
                median_elapsed_ns: med,
                min_ns_per_search: minimum / searches as f64,
                median_ns_per_search: med / searches as f64,
                checksum: last_checksum,
            },
        );
    }
    Ok(measurements)
}

fn measure_in_order<Upstream, Native, Error>(
    order: MeasurementOrder,
    upstream: impl FnOnce() -> Result<Upstream, Error>,
    native: impl FnOnce() -> Result<Native, Error>,
) -> Result<(Upstream, Native), Error> {
    match order {
        MeasurementOrder::UpstreamNative => {
            let upstream = upstream()?;
            let native = native()?;
            Ok((upstream, native))
        }
        MeasurementOrder::NativeUpstream => {
            let native = native()?;
            let upstream = upstream()?;
            Ok((upstream, native))
        }
    }
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
                    write!(&mut escaped, "\\x{byte:02x}").expect("String writes cannot fail");
                }
            }
        }
    }
    escaped
}

fn option_byte(value: Option<u8>) -> i16 {
    value.map_or(-1, i16::from)
}

fn build_c_harness(config: &Config, shapes: &[CompiledShape], scenarios: &[Scenario]) -> String {
    let mut source = String::from(
        "#define _POSIX_C_SOURCE 200809L\n\
         #include <inttypes.h>\n\
         #include <stddef.h>\n\
         #include <stdint.h>\n\
         #include <stdio.h>\n\
         #include <stdlib.h>\n\
         #include <string.h>\n\
         #include <time.h>\n\n\
         #define ROTATIONS 4U\n\n\
         typedef void *exclusive_handle;\n\
         typedef uint32_t (*entry_fn)(const unsigned char *, size_t, size_t, size_t, size_t *);\n\
         typedef uint32_t (*exclusive_entry_fn)(exclusive_handle, const unsigned char *, size_t, size_t, size_t, size_t *);\n\
         extern uint32_t fre_aot_regex_runtime_prepare_exclusive_v1(const unsigned char *, size_t, exclusive_handle *);\n\
         extern uint32_t fre_aot_regex_runtime_destroy_exclusive_v1(exclusive_handle);\n\n\
         typedef struct {\n\
           const char *name; entry_fn direct; exclusive_entry_fn prepared_direct;\n\
           const unsigned char *program; size_t program_len;\n\
           exclusive_handle prepared; const unsigned char *fixture; size_t fixture_len;\n\
           const unsigned char *candidates; size_t candidate_len; int guard_before; int guard_after;\n\
           uint64_t seed; size_t generation_id; unsigned nested_distribution;\n\
         } shape_spec;\n\
         typedef struct {\n\
           const char *name; size_t shape; size_t length; size_t stride; unsigned near_miss; unsigned position;\n\
           uint64_t searches; uint32_t status[ROTATIONS]; size_t start[ROTATIONS];\n\
           size_t end[ROTATIONS]; uint64_t fingerprint[ROTATIONS];\n\
         } scenario_spec;\n\n",
    );
    for (index, shape) in shapes.iter().enumerate() {
        let entry = shape.aot.module().entry_symbol();
        writeln!(
            &mut source,
            "extern uint32_t {entry}(const unsigned char *, size_t, size_t, size_t, size_t *);"
        )
        .unwrap();
        if let Some(prepared_entry) = shape.aot.module().prepared_entry_symbol() {
            writeln!(
                &mut source,
                "extern uint32_t {prepared_entry}(exclusive_handle, const unsigned char *, size_t, size_t, size_t, size_t *);"
            )
            .unwrap();
        }
        if let Some((symbol, _)) = &shape.runtime_program {
            writeln!(&mut source, "extern const unsigned char {symbol}[];").unwrap();
        }
        writeln!(
            &mut source,
            "static const unsigned char fixture_{index}[] = {{{}}};",
            c_bytes(&shape.spec.fixture)
        )
        .unwrap();
        writeln!(
            &mut source,
            "static const unsigned char candidates_{index}[] = {{{}}};",
            c_bytes(&shape.spec.candidates)
        )
        .unwrap();
    }
    source.push_str("\nstatic shape_spec shapes[] = {\n");
    for (index, shape) in shapes.iter().enumerate() {
        let prepared_entry = shape.aot.module().prepared_entry_symbol();
        let direct = shape.aot.module().entry_symbol();
        let prepared_direct = prepared_entry.unwrap_or("NULL");
        let (program, program_len) = shape
            .runtime_program
            .as_ref()
            .map_or(("NULL", 0), |(symbol, bytes)| (symbol.as_str(), *bytes));
        writeln!(
            &mut source,
            "  {{\"{}\", {direct}, {prepared_direct}, {program}, {program_len}, 0, fixture_{index}, sizeof(fixture_{index}), candidates_{index}, sizeof(candidates_{index}), {}, {}, UINT64_C({}), {}, {}}},",
            c_string(&shape.spec.name), option_byte(shape.spec.guard_before), option_byte(shape.spec.guard_after),
            shape.spec.seed, shape.spec.generation_id,
            u8::from(shape.spec.source_kind == "nested_grammar_generated"),
        ).unwrap();
    }
    source.push_str("};\n\nstatic const scenario_spec scenarios[] = {\n");
    for scenario in scenarios {
        let statuses = scenario
            .expected
            .iter()
            .map(|value| value.status.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let starts = scenario
            .expected
            .iter()
            .map(|value| value.start.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let ends = scenario
            .expected
            .iter()
            .map(|value| value.end.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let fingerprints = scenario
            .fingerprints
            .iter()
            .map(|value| format!("UINT64_C({value})"))
            .collect::<Vec<_>>()
            .join(",");
        writeln!(
            &mut source,
            "  {{\"{}\", {}, {}, {}, {}, {}, UINT64_C({}), {{{statuses}}}, {{{starts}}}, {{{ends}}}, {{{fingerprints}}}}},",
            c_string(&scenario.case_name), scenario.shape_index, scenario.size, scenario.density.stride,
            u8::from(scenario.density.near_miss), scenario.position.c_value(), scenario.searches,
        ).unwrap();
    }
    writeln!(
        &mut source,
        "}};\n\n\
         static const unsigned char safe_bytes[] = {{{}}};\n\
         static const unsigned char englishish_bytes[] = {{{}}};\n\
         static const unsigned char codeish_bytes[] = {{{}}};\n\
         static volatile uint64_t benchmark_sink;\n\n\
         static uint64_t rotate_left(uint64_t value, unsigned count) {{\n\
           return (value << count) | (value >> (64U - count));\n\
         }}\n\
         static uint64_t checksum_step(uint64_t checksum, uint32_t status, size_t start, size_t end, uint64_t iteration) {{\n\
           uint64_t value = ((uint64_t)status + UINT64_C(1)) * UINT64_C(0x9e3779b97f4a7c15);\n\
           value ^= rotate_left((uint64_t)start + UINT64_C(0xd1b54a32d192ed03), 17U);\n\
           value ^= rotate_left((uint64_t)end + UINT64_C(0x94d049bb133111eb), 41U);\n\
           return rotate_left(checksum, 7U) ^ value ^ iteration * UINT64_C(0xbf58476d1ce4e5b9);\n\
         }}\n\
         static uint64_t byte_fingerprint(const unsigned char *bytes, size_t length) {{\n\
           uint64_t value = UINT64_C(0xcbf29ce484222325);\n\
           for (size_t index = 0; index < length; ++index)\n\
             value = (value ^ (uint64_t)bytes[index]) * UINT64_C(0x00000100000001b3);\n\
           return value;\n\
         }}\n\
         static uint64_t now_ns(void) {{\n\
           struct timespec value;\n\
           if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) {{ perror(\"clock_gettime\"); exit(90); }}\n\
           return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;\n\
         }}\n\
         static int compare_u64(const void *left, const void *right) {{\n\
           uint64_t a = *(const uint64_t *)left, b = *(const uint64_t *)right; return (a > b) - (a < b);\n\
         }}\n\
         static double median_u64(const uint64_t *values, size_t count) {{\n\
           size_t middle = count / 2U;\n\
           return (count & 1U) ? (double)values[middle] : ((double)values[middle - 1U] + (double)values[middle]) / 2.0;\n\
         }}\n\
         static size_t seed_component(uint64_t seed, unsigned shift) {{\n\
           return (size_t)((seed >> shift) & UINT64_C(0xffff));\n\
         }}\n\
         static uint64_t nested_distribution_hash(const shape_spec *shape, size_t index, size_t rotation) {{\n\
           uint64_t value = shape->seed\n\
               ^ (uint64_t)shape->generation_id * UINT64_C(0xa0761d6478bd642f)\n\
               ^ (uint64_t)index * UINT64_C(0xe7037ed1a0b428db)\n\
               ^ (uint64_t)rotation * UINT64_C(0x8ebc6af09c88c6e3);\n\
           value += UINT64_C(0x9e3779b97f4a7c15);\n\
           value = (value ^ (value >> 30U)) * UINT64_C(0xbf58476d1ce4e5b9);\n\
           value = (value ^ (value >> 27U)) * UINT64_C(0x94d049bb133111eb);\n\
           return value ^ (value >> 31U);\n\
         }}\n\n",
        c_bytes(SAFE_BYTES),
        c_bytes(ENGLISHISH_BYTES),
        c_bytes(CODEISH_BYTES),
    ).unwrap();
    source.push_str(
         "static void generate_haystack(unsigned char *haystack, const scenario_spec *scenario, size_t rotation) {\n\
           shape_spec *shape = &shapes[scenario->shape];\n\
           for (size_t index = 0; index < scenario->length; ++index) {\n\
             if (shape->nested_distribution != 0U) {\n\
               uint64_t value = nested_distribution_hash(shape, index, rotation);\n\
               switch (rotation % ROTATIONS) {\n\
                 case 0U: {\n\
                   size_t safe_index = (index * (13U + seed_component(shape->seed, 8U) % 16U) +\n\
                       rotation * (7U + seed_component(shape->seed, 24U) % 16U) +\n\
                       shape->generation_id * (11U + seed_component(shape->seed, 40U) % 16U) +\n\
                       seed_component(shape->seed, 0U)) % sizeof(safe_bytes);\n\
                   haystack[index] = safe_bytes[safe_index];\n\
                   break;\n\
                 }\n\
                 case 1U: haystack[index] = englishish_bytes[(size_t)value % sizeof(englishish_bytes)]; break;\n\
                 case 2U: haystack[index] = codeish_bytes[(size_t)value % sizeof(codeish_bytes)]; break;\n\
                 default: haystack[index] = (unsigned char)value; break;\n\
               }\n\
             } else {\n\
               size_t safe_index = (index * (13U + seed_component(shape->seed, 8U) % 16U) +\n\
                   rotation * (7U + seed_component(shape->seed, 24U) % 16U) +\n\
                   shape->generation_id * (11U + seed_component(shape->seed, 40U) % 16U) +\n\
                   seed_component(shape->seed, 0U)) % sizeof(safe_bytes);\n\
               haystack[index] = safe_bytes[safe_index];\n\
             }\n\
           }\n\
           if (scenario->near_miss != 0U) {\n\
             size_t phase = (rotation * (17U + seed_component(shape->seed, 4U) % 16U) +\n\
                 shape->generation_id * (23U + seed_component(shape->seed, 20U) % 16U) +\n\
                 seed_component(shape->seed, 16U)) % scenario->stride;\n\
             for (size_t index = phase; index <= scenario->length - shape->fixture_len; index += scenario->stride) {\n\
               memcpy(haystack + index, shape->fixture, shape->fixture_len);\n\
               haystack[index + shape->fixture_len - 1U] =\n\
                   safe_bytes[(index + rotation + seed_component(shape->seed, 48U)) % sizeof(safe_bytes)];\n\
             }\n\
           } else if (scenario->stride != 0U) {\n\
             size_t phase = (rotation * (17U + seed_component(shape->seed, 4U) % 16U) +\n\
                 shape->generation_id * (23U + seed_component(shape->seed, 20U) % 16U) +\n\
                 seed_component(shape->seed, 16U)) % scenario->stride;\n\
             for (size_t index = phase; index < scenario->length; index += scenario->stride) {\n\
               size_t candidate = (index / scenario->stride + rotation + shape->generation_id +\n\
                   seed_component(shape->seed, 32U)) % shape->candidate_len;\n\
               haystack[index] = shape->candidates[candidate];\n\
             }\n\
           }\n\
           if (scenario->position != 0U) {\n\
             size_t offset = scenario->position == 2U ? (scenario->length - shape->fixture_len) / 2U :\n\
                             scenario->position == 3U ? scenario->length - shape->fixture_len : 0U;\n\
             memcpy(haystack + offset, shape->fixture, shape->fixture_len);\n\
             if (offset > 0U && shape->guard_before >= 0) haystack[offset - 1U] = (unsigned char)shape->guard_before;\n\
             if (offset + shape->fixture_len < scenario->length && shape->guard_after >= 0)\n\
               haystack[offset + shape->fixture_len] = (unsigned char)shape->guard_after;\n\
           }\n\
         }\n\n\
         static uint32_t invoke(shape_spec *shape, const unsigned char *haystack, size_t length, size_t *result) {\n\
           if (shape->prepared_direct != NULL)\n\
             return shape->prepared_direct(shape->prepared, haystack, length, 0U, length, result);\n\
           return shape->direct(haystack, length, 0U, length, result);\n\
         }\n\n"
    );
    writeln!(
        &mut source,
        "static int measure_one(const scenario_spec *scenario) {{\n\
           const size_t trials = {trials}U, warmup_rounds = {warmup}U;\n\
           const uint64_t min_trial_ns = UINT64_C({min_trial_ns});\n\
           shape_spec *shape = &shapes[scenario->shape];\n\
           unsigned char *storage = malloc(scenario->length * ROTATIONS);\n\
           uint64_t *samples = malloc(trials * sizeof(*samples));\n\
           if (storage == NULL || samples == NULL) {{ free(samples); free(storage); return 80; }}\n\
           for (size_t rotation = 0; rotation < ROTATIONS; ++rotation)\n\
             generate_haystack(storage + rotation * scenario->length, scenario, rotation);\n\
           for (size_t rotation = 0; rotation < ROTATIONS; ++rotation) {{\n\
             unsigned char *haystack = storage + rotation * scenario->length;\n\
             if (byte_fingerprint(haystack, scenario->length) != scenario->fingerprint[rotation]) {{\n\
               fprintf(stderr, \"native fingerprint mismatch: %s/%zu\\n\", scenario->name, rotation); return 69;\n\
             }}\n\
             size_t result[2] = {{SIZE_MAX, SIZE_MAX}};\n\
             uint32_t status = invoke(shape, haystack, scenario->length, result);\n\
             if (status != scenario->status[rotation] || result[0] != scenario->start[rotation] || result[1] != scenario->end[rotation]) {{\n\
               fprintf(stderr, \"native result mismatch: %s/%zu got %u/%zu/%zu expected %u/%zu/%zu\\n\",\n\
                       scenario->name, rotation, status, result[0], result[1], scenario->status[rotation],\n\
                       scenario->start[rotation], scenario->end[rotation]); return 70;\n\
             }}\n\
           }}\n\
           size_t result[2] = {{0, 0}};\n\
           for (size_t round = 0; round < warmup_rounds; ++round)\n\
             for (size_t rotation = 0; rotation < ROTATIONS; ++rotation) {{\n\
               uint32_t status = invoke(shape, storage + rotation * scenario->length, scenario->length, result);\n\
               benchmark_sink ^= checksum_step(benchmark_sink, status, result[0], result[1], round * ROTATIONS + rotation);\n\
             }}\n\
           uint64_t measured_searches = scenario->searches;\n\
           for (;;) {{\n\
             uint64_t checksum = 0, before = now_ns();\n\
             for (uint64_t iteration = 0; iteration < measured_searches; ++iteration) {{\n\
               size_t rotation = (size_t)iteration % ROTATIONS;\n\
               uint32_t status = invoke(shape, storage + rotation * scenario->length, scenario->length, result);\n\
               checksum = checksum_step(checksum, status, result[0], result[1], iteration);\n\
             }}\n\
             uint64_t elapsed = now_ns() - before, expected = 0;\n\
             for (uint64_t iteration = 0; iteration < measured_searches; ++iteration) {{\n\
               size_t rotation = (size_t)iteration % ROTATIONS;\n\
               expected = checksum_step(expected, scenario->status[rotation], scenario->start[rotation], scenario->end[rotation], iteration);\n\
             }}\n\
             if (checksum != expected) {{ fprintf(stderr, \"native calibration checksum mismatch: %s\\n\", scenario->name); return 71; }}\n\
             benchmark_sink ^= checksum;\n\
             if (elapsed >= min_trial_ns) break;\n\
             if (measured_searches > UINT64_MAX / UINT64_C(2)) return 74;\n\
             measured_searches *= UINT64_C(2);\n\
           }}\n\
         measure_trials: ;\n\
           uint64_t last_checksum = 0;\n\
           for (size_t trial = 0; trial < trials; ++trial) {{\n\
             uint64_t checksum = 0, before = now_ns();\n\
             for (uint64_t iteration = 0; iteration < measured_searches; ++iteration) {{\n\
               size_t rotation = ((size_t)iteration + trial) % ROTATIONS;\n\
               uint32_t status = invoke(shape, storage + rotation * scenario->length, scenario->length, result);\n\
               checksum = checksum_step(checksum, status, result[0], result[1], iteration);\n\
             }}\n\
             samples[trial] = now_ns() - before;\n\
             uint64_t expected = 0;\n\
             for (uint64_t iteration = 0; iteration < measured_searches; ++iteration) {{\n\
               size_t rotation = ((size_t)iteration + trial) % ROTATIONS;\n\
               expected = checksum_step(expected, scenario->status[rotation], scenario->start[rotation], scenario->end[rotation], iteration);\n\
             }}\n\
             if (checksum != expected) {{ fprintf(stderr, \"native checksum mismatch: %s\\n\", scenario->name); return 71; }}\n\
             benchmark_sink ^= checksum; last_checksum = checksum;\n\
           }}\n\
           qsort(samples, trials, sizeof(*samples), compare_u64);\n\
           if (samples[0] < min_trial_ns) {{\n\
             if (measured_searches > UINT64_MAX / UINT64_C(2)) return 75;\n\
             measured_searches *= UINT64_C(2); goto measure_trials;\n\
           }}\n\
           double minimum = (double)samples[0], med = median_u64(samples, trials);\n\
           printf(\"native\\t%s\\t%\" PRIu64 \"\\t%.1f\\t%.1f\\t%.6f\\t%.6f\\t%\" PRIu64 \"\\tok\\n\",\n\
                  scenario->name, measured_searches, minimum, med, minimum / (double)measured_searches,\n\
                  med / (double)measured_searches, last_checksum);\n\
           free(samples); free(storage); return 0;\n\
         }}\n\n\
         int main(void) {{\n\
           const size_t shape_count = sizeof(shapes) / sizeof(shapes[0]);\n\
           for (size_t index = 0; index < shape_count; ++index) {{\n\
             if (shapes[index].program != NULL) {{\n\
               uint32_t status = fre_aot_regex_runtime_prepare_exclusive_v1(shapes[index].program, shapes[index].program_len, &shapes[index].prepared);\n\
               if (status != 0U) {{ fprintf(stderr, \"prepare failed for %s: %u\\n\", shapes[index].name, status); return 72; }}\n\
             }}\n\
           }}\n\
           if (fputs(\"ready\\n\", stdout) == EOF || fflush(stdout) != 0) return 76;\n\
           if (getchar() == EOF) return 77;\n\
           const size_t count = sizeof(scenarios) / sizeof(scenarios[0]);\n\
           for (size_t index = 0; index < count; ++index) {{ int status = measure_one(&scenarios[index]); if (status != 0) return status; }}\n\
           for (size_t index = 0; index < shape_count; ++index) {{\n\
             if (shapes[index].program != NULL && fre_aot_regex_runtime_destroy_exclusive_v1(shapes[index].prepared) != 0U) return 73;\n\
           }}\n\
           return 0;\n\
         }}\n",
        trials = config.trials,
        warmup = config.warmup_rounds,
        min_trial_ns = config.min_trial_ns,
    ).unwrap();
    source
}

#[derive(Debug)]
struct ScratchDirectory(PathBuf);

impl ScratchDirectory {
    fn create() -> Result<Self, String> {
        for suffix in 0_u32..100 {
            let path = env::temp_dir().join(format!(
                "fre-generated-aot-upstream-{}-{suffix}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(format!("could not create {}: {error}", path.display())),
            }
        }
        Err("could not allocate a unique temporary directory".to_owned())
    }
}

impl Drop for ScratchDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug)]
struct RuntimeLink {
    archive: PathBuf,
    native_libraries: Vec<OsString>,
}

fn build_runtime_staticlib() -> Result<RuntimeLink, String> {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| "could not resolve workspace root".to_owned())?;
    let manifest = workspace.join("Cargo.toml");
    let target_dir =
        env::var_os("CARGO_TARGET_DIR").map_or_else(|| workspace.join("target"), PathBuf::from);
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let output = Command::new(cargo)
        .arg("rustc")
        .arg("--locked")
        .arg("--release")
        .arg("-p")
        .arg("fre-aot-regex-runtime")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--target-dir")
        .arg(&target_dir)
        .arg("--")
        .arg("--print")
        .arg("native-static-libs")
        .output()
        .map_err(|error| format!("could not build runtime static library: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "runtime static-library build failed:\n{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ));
    }
    let diagnostics = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let libraries = diagnostics
        .lines()
        .filter_map(|line| {
            line.split_once("native-static-libs:")
                .map(|(_, value)| value)
        })
        .flat_map(str::split_whitespace)
        .map(OsString::from)
        .collect::<Vec<_>>();
    if libraries.is_empty() {
        return Err("cargo did not report the runtime's native static libraries".to_owned());
    }
    let archive_name = if cfg!(target_os = "windows") {
        "fre_aot_regex_runtime.lib"
    } else {
        "libfre_aot_regex_runtime.a"
    };
    let archive = target_dir.join("release").join(archive_name);
    if !archive.is_file() {
        return Err(format!(
            "runtime archive was not created at {}",
            archive.display()
        ));
    }
    Ok(RuntimeLink {
        archive,
        native_libraries: libraries,
    })
}

fn compile_native_harness(
    directory: &Path,
    config: &Config,
    shapes: &[CompiledShape],
    scenarios: &[Scenario],
    runtime: &RuntimeLink,
) -> Result<PathBuf, String> {
    let harness = directory.join("comparison.c");
    fs::write(&harness, build_c_harness(config, shapes, scenarios))
        .map_err(|error| format!("could not write native harness: {error}"))?;
    let mut objects = Vec::with_capacity(shapes.len());
    for (index, shape) in shapes.iter().enumerate() {
        let path = directory.join(format!("shape_{index}.o"));
        fs::write(&path, shape.aot.object())
            .map_err(|error| format!("could not write {}: {error}", path.display()))?;
        objects.push(path);
    }
    let executable = directory.join("comparison-native");
    let configured = env::var_os("CC");
    let compiler = configured.clone().unwrap_or_else(|| OsString::from("cc"));
    let invoke = |compiler: &OsStr| {
        let mut command = Command::new(compiler);
        command
            .arg("-O3")
            .arg("-std=c11")
            .arg(&harness)
            .args(&objects)
            .arg(&runtime.archive)
            .args(&runtime.native_libraries)
            .arg("-o")
            .arg(&executable)
            .output()
    };
    let output = match invoke(&compiler) {
        Ok(output) => output,
        Err(first) if configured.is_none() => invoke(OsStr::new("clang"))
            .map_err(|second| format!("could not invoke cc ({first}) or clang ({second})"))?,
        Err(error) => return Err(format!("could not invoke C compiler: {error}")),
    };
    if !output.status.success() {
        return Err(format!(
            "native harness compilation failed:\n{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ));
    }
    Ok(executable)
}

#[derive(Debug)]
struct PreparedNativeHarness {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    stderr: Option<ChildStderr>,
    finished: bool,
}

impl Drop for PreparedNativeHarness {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn prepare_native_harness(
    executable: &Path,
    directory: &Path,
) -> Result<PreparedNativeHarness, String> {
    let mut child = Command::new(executable)
        .current_dir(directory)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("could not start native harness: {error}"))?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| "native harness did not expose stdin".to_owned())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "native harness did not expose stdout".to_owned())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "native harness did not expose stderr".to_owned())?;
    let mut prepared = PreparedNativeHarness {
        child,
        stdin: Some(stdin),
        stdout: BufReader::new(stdout),
        stderr: Some(stderr),
        finished: false,
    };
    let mut ready = String::new();
    prepared
        .stdout
        .read_line(&mut ready)
        .map_err(|error| format!("could not read native preparation handshake: {error}"))?;
    if ready != "ready\n" {
        return Err(format!(
            "native harness did not complete preparation; first output was {ready:?}"
        ));
    }
    Ok(prepared)
}

fn execute_native_harness(
    mut prepared: PreparedNativeHarness,
    expected_rows: usize,
) -> Result<BTreeMap<String, Measurement>, String> {
    let mut stdin = prepared
        .stdin
        .take()
        .ok_or_else(|| "native harness start signal was already sent".to_owned())?;
    stdin
        .write_all(b"measure\n")
        .and_then(|()| stdin.flush())
        .map_err(|error| format!("could not start native measurement: {error}"))?;
    drop(stdin);
    let mut stdout = String::new();
    prepared
        .stdout
        .read_to_string(&mut stdout)
        .map_err(|error| format!("could not read native harness output: {error}"))?;
    let mut stderr = Vec::new();
    prepared
        .stderr
        .take()
        .expect("prepared native harness retains stderr")
        .read_to_end(&mut stderr)
        .map_err(|error| format!("could not read native harness diagnostics: {error}"))?;
    let status = prepared
        .child
        .wait()
        .map_err(|error| format!("could not wait for native harness: {error}"))?;
    prepared.finished = true;
    if !status.success() {
        return Err(format!(
            "native harness failed with {status}:\n{stdout}{}",
            String::from_utf8_lossy(&stderr),
        ));
    }
    let mut measurements = BTreeMap::new();
    for line in stdout.lines() {
        let columns = line.split('\t').collect::<Vec<_>>();
        if columns.len() != 9 || columns[0] != "native" || columns[8] != "ok" {
            return Err(format!("malformed native row: {line}"));
        }
        let parse_float = |column: usize| {
            columns[column]
                .parse::<f64>()
                .map_err(|error| format!("malformed native number in {line}: {error}"))
        };
        let searches = columns[2]
            .parse::<usize>()
            .map_err(|error| format!("malformed native searches in {line}: {error}"))?;
        let checksum = columns[7]
            .parse::<u64>()
            .map_err(|error| format!("malformed native checksum in {line}: {error}"))?;
        let previous = measurements.insert(
            columns[1].to_owned(),
            Measurement {
                searches,
                min_elapsed_ns: parse_float(3)?,
                median_elapsed_ns: parse_float(4)?,
                min_ns_per_search: parse_float(5)?,
                median_ns_per_search: parse_float(6)?,
                checksum,
            },
        );
        if previous.is_some() {
            return Err(format!("duplicate native row for {}", columns[1]));
        }
    }
    if measurements.len() != expected_rows {
        return Err(format!(
            "native harness returned {} rows; expected {expected_rows}",
            measurements.len()
        ));
    }
    Ok(measurements)
}

const fn engine_name(engine: EngineKind) -> &'static str {
    match engine {
        EngineKind::OrderedNfa => "ordered_nfa",
        EngineKind::OrderedDfa => "ordered_dfa",
        EngineKind::OrderedContextDfa => "ordered_context_dfa",
    }
}

const fn reason_name(reason: EngineSelectionReason) -> &'static str {
    match reason {
        EngineSelectionReason::FastMode => "fast_mode",
        EngineSelectionReason::CompleteDfa => "complete_dfa",
        EngineSelectionReason::CompleteContextDfa => "complete_context_dfa",
        EngineSelectionReason::ContextAssertions => "context_assertions",
        EngineSelectionReason::DeterminizationResourceLimit => "determinization_resource_limit",
    }
}

const fn accelerator_name(accelerator: StartAccelerator) -> &'static str {
    match accelerator {
        StartAccelerator::None => "none",
        StartAccelerator::Scalar => "scalar",
        StartAccelerator::X86Sse2 => "x86_sse2",
        StartAccelerator::X86Avx2 => "x86_avx2",
        StartAccelerator::X86Avx512Bw => "x86_avx512bw",
        StartAccelerator::Aarch64Asimd => "aarch64_asimd",
        StartAccelerator::Aarch64Sve => "aarch64_sve",
        StartAccelerator::Aarch64Sve2 => "aarch64_sve2",
    }
}

/// Classify the actual SVE scanner mix in the emitted object rather than the
/// maximum `StartAccelerator` receipt. Contextual objects can contain an SVE2
/// exact-set scanner and a base-SVE range scanner on independent paths, while
/// the receipt intentionally reports only the strongest accelerator present.
fn aarch64_sve_code_profile(compiled: &CompiledRegex) -> &'static str {
    if compiled.module().target().architecture != Architecture::Aarch64 {
        return "not_aarch64";
    }

    // These instruction families differ outside their three register fields.
    // Masking those fields recognizes every allocation without consulting the
    // regex source or benchmark family.
    const REGISTER_FIELDS: u32 = (0x1f << 16) | (0x1f << 5) | 0x1f;
    const OPCODE_MASK: u32 = !REGISTER_FIELDS;
    const SVE_CMPEQ_B: u32 = 0x2400_a000;
    const SVE_CMPHS_B: u32 = 0x2400_0000;
    const SVE2_MATCH_B: u32 = 0x4520_8000;

    let mut base_exact = false;
    let mut base_range = false;
    let mut sve2_exact = false;
    for section in compiled
        .module()
        .sections()
        .iter()
        .filter(|section| section.name == ".text")
    {
        for instruction in section.bytes().chunks_exact(4) {
            let word = u32::from_le_bytes(
                instruction
                    .try_into()
                    .expect("four-byte AArch64 instruction chunk"),
            );
            let opcode = word & OPCODE_MASK;
            base_exact |= opcode == SVE_CMPEQ_B;
            base_range |= opcode == SVE_CMPHS_B;
            sve2_exact |= opcode == SVE2_MATCH_B;
        }
    }
    match (base_exact, base_range, sve2_exact) {
        (false, false, false) => "none",
        (true, false, false) => "base_sve_exact_only",
        (false, true, false) => "base_sve_range_only",
        (false, false, true) => "sve2_exact_only",
        (false, true, true) => "mixed_sve2_exact_base_sve_range",
        (true, false, true) => "mixed_sve2_exact_base_sve_exact",
        (true, true, false) => "mixed_base_sve_exact_range",
        (true, true, true) => "mixed_sve2_exact_base_sve_exact_range",
    }
}

fn print_joined_rows(
    config: &Config,
    shapes: &[CompiledShape],
    scenarios: &[Scenario],
    upstream: &BTreeMap<String, Measurement>,
    native: &BTreeMap<String, Measurement>,
) -> Result<(), String> {
    println!(
        "comparison\tcase\tpattern_name\tfamily\tseed\tsource_kind\tpattern\toutput\tupstream_operation\tnative_route\tengine\tselection_reason\ttarget\tfeature_bits\tstart_accelerator\taarch64_sve_code_profile\tprefix_graph_bytes\tprefix_selective_positions\tprefix_filter_bytes\twindow_bytes\tmatch_position\tcandidate_density\trotations\tinitial_searches\tmin_trial_ns\ttrials\twarmup_rounds\tupstream_searches_per_trial\tupstream_min_elapsed_ns\tupstream_median_elapsed_ns\tupstream_min_ns_per_search\tupstream_median_ns_per_search\tnative_searches_per_trial\tnative_min_elapsed_ns\tnative_median_elapsed_ns\tnative_min_ns_per_search\tnative_median_ns_per_search\tspeedup_at_min\tspeedup_at_median\tupstream_checksum\tnative_checksum\tstatus"
    );
    let mut aggregates: BTreeMap<(String, String), Vec<f64>> = BTreeMap::new();
    let mut family_regimes: BTreeMap<(String, String), Vec<f64>> = BTreeMap::new();
    for scenario in scenarios {
        let shape = &shapes[scenario.shape_index];
        let upstream = upstream
            .get(&scenario.case_name)
            .ok_or_else(|| format!("missing upstream row for {}", scenario.case_name))?;
        let native = native
            .get(&scenario.case_name)
            .ok_or_else(|| format!("missing native row for {}", scenario.case_name))?;
        let speedup_at_min = upstream.min_ns_per_search / native.min_ns_per_search;
        let speedup_at_median = upstream.median_ns_per_search / native.median_ns_per_search;
        if !speedup_at_min.is_finite()
            || speedup_at_min <= 0.0
            || !speedup_at_median.is_finite()
            || speedup_at_median <= 0.0
        {
            return Err(format!(
                "{} produced a non-positive or non-finite speedup",
                scenario.case_name
            ));
        }
        let receipt = shape.aot.receipt();
        let regime = if scenario.size == 64 {
            "call_overhead_64b"
        } else if scenario.size >= 64 * 1024 {
            "throughput_ge_64kib"
        } else {
            "middle_4kib"
        };
        let compiled_primary = shape.is_compiled_primary();
        let groups = [
            ("all".to_owned(), "all".to_owned()),
            (
                "scope".to_owned(),
                if compiled_primary {
                    "compiled_primary"
                } else {
                    "runtime_resilience"
                }
                .to_owned(),
            ),
            ("route".to_owned(), shape.route().to_owned()),
            (
                "native_entry_scope".to_owned(),
                shape.timed_entry_scope().to_owned(),
            ),
            ("family".to_owned(), shape.spec.family.to_owned()),
            ("seed".to_owned(), format!("0x{:016x}", shape.spec.seed)),
            ("source_kind".to_owned(), shape.spec.source_kind.to_owned()),
            ("regime".to_owned(), regime.to_owned()),
            ("output".to_owned(), shape.spec.output.name().to_owned()),
            ("window_bytes".to_owned(), scenario.size.to_string()),
            (
                "match_position".to_owned(),
                scenario.position.name().to_owned(),
            ),
            (
                "candidate_density".to_owned(),
                scenario.density.name.to_owned(),
            ),
            (
                "start_accelerator".to_owned(),
                accelerator_name(receipt.start_accelerator).to_owned(),
            ),
        ];
        for group in groups {
            aggregates.entry(group).or_default().push(speedup_at_median);
        }
        if compiled_primary {
            for selected_regime in ["all", regime] {
                family_regimes
                    .entry((selected_regime.to_owned(), shape.spec.family.to_owned()))
                    .or_default()
                    .push(speedup_at_median);
            }
        }
        println!(
            "comparison\t{}\t{}\t{}\t0x{:016x}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t0x{:x}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.1}\t{:.1}\t{:.6}\t{:.6}\t{}\t{:.1}\t{:.1}\t{:.6}\t{:.6}\t{:.6}\t{:.6}\t{}\t{}\tok",
            scenario.case_name,
            shape.spec.base_name,
            shape.spec.family,
            shape.spec.seed,
            shape.spec.source_kind,
            shape.spec.pattern,
            shape.spec.output.name(),
            shape.spec.output.upstream_operation(),
            shape.route(),
            engine_name(receipt.engine),
            reason_name(receipt.engine_selection_reason),
            config.target_name,
            config.target.features.bits(),
            accelerator_name(receipt.start_accelerator),
            aarch64_sve_code_profile(&shape.aot),
            receipt.anchored_prefix.guaranteed_bytes,
            receipt.anchored_prefix.selective_positions,
            receipt.anchored_prefix_filter_bytes,
            scenario.size,
            scenario.position.name(),
            scenario.density.name,
            ROTATIONS,
            scenario.searches,
            config.min_trial_ns,
            config.trials,
            config.warmup_rounds,
            upstream.searches,
            upstream.min_elapsed_ns,
            upstream.median_elapsed_ns,
            upstream.min_ns_per_search,
            upstream.median_ns_per_search,
            native.searches,
            native.min_elapsed_ns,
            native.median_elapsed_ns,
            native.min_ns_per_search,
            native.median_ns_per_search,
            speedup_at_min,
            speedup_at_median,
            upstream.checksum,
            native.checksum,
        );
    }
    println!("#aggregate\tgroup\tvalue\tmetric\tcells\tgeomean\tp10\tp50\tp90\twins\tstatus");
    for ((group, value), mut samples) in aggregates {
        samples.sort_by(f64::total_cmp);
        let count = samples.len();
        let quantile = |percent: usize| samples[(count - 1) * percent / 100];
        let geometric_mean =
            (samples.iter().map(|sample| sample.ln()).sum::<f64>() / count as f64).exp();
        let wins = samples.iter().filter(|&&sample| sample > 1.0).count();
        println!(
            "aggregate\t{group}\t{value}\tmedian_ns_per_search_speedup\t{count}\t{geometric_mean:.6}\t{:.6}\t{:.6}\t{:.6}\t{wins}\tok",
            quantile(10),
            quantile(50),
            quantile(90),
        );
    }
    let mut equal_family: BTreeMap<String, (usize, Vec<f64>)> = BTreeMap::new();
    for ((regime, _family), samples) in family_regimes {
        let family_geomean =
            (samples.iter().map(|sample| sample.ln()).sum::<f64>() / samples.len() as f64).exp();
        let entry = equal_family.entry(regime).or_default();
        entry.0 += samples.len();
        entry.1.push(family_geomean);
    }
    println!(
        "#equal_family_aggregate\tregime\tfamilies\tcells\tgeomean_of_family_geomeans\tp10_family_geomean\tp50_family_geomean\tp90_family_geomean\tscope\tstatus"
    );
    for (regime, (cells, mut family_geomeans)) in equal_family {
        family_geomeans.sort_by(f64::total_cmp);
        let families = family_geomeans.len();
        let quantile = |percent: usize| family_geomeans[(families - 1) * percent / 100];
        let equal_weight_geomean = (family_geomeans
            .iter()
            .map(|sample| sample.ln())
            .sum::<f64>()
            / families as f64)
            .exp();
        println!(
            "equal_family_aggregate\t{regime}\t{families}\t{cells}\t{equal_weight_geomean:.6}\t{:.6}\t{:.6}\t{:.6}\tcompiled_primary\tok",
            quantile(10),
            quantile(50),
            quantile(90),
        );
    }
    Ok(())
}

fn command_version(program: &OsStr, argument: &str) -> String {
    Command::new(program)
        .arg(argument)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| {
            let stdout = String::from_utf8(output.stdout).ok()?;
            stdout.lines().next().map(str::to_owned)
        })
        .unwrap_or_else(|| "unavailable".to_owned())
        .replace(['\t', '\r', '\n'], " ")
}

fn print_partial_dfa_metadata(shapes: &[CompiledShape]) {
    println!(
        "#partial_dfa\tpattern\tfamily\tseed\toutput\tartifact_kind\tscore_scope\tlimit_derivation\truntime_program\tprepared_entry_published\tprepared_entry_symbol\tprepared_capability_format\tcomplete_rows\tdiscovered_states\tresume_frontiers\tresume_items\toptimized_entry_supported\tmin_input_bytes\trequested_max_states\trequested_max_transitions\trequested_max_work\teffective_max_states\teffective_max_transitions\teffective_max_work\tdecline_stage\tdecline_resource\twork_completed\tstates_completed\ttransitions_completed\texact_product\tstatus"
    );
    for shape in shapes {
        let report = &shape.aot.receipt().determinization;
        let requested = report.requested_limits;
        let effective = report.effective_limits;
        let decline = report.decline;
        let partial = shape.partial_dfa;
        let number = |value: Option<u64>| {
            value.map_or_else(|| "na".to_owned(), |value| value.to_string())
        };
        let decline_stage = decline.map_or_else(
            || "none".to_owned(),
            |decline| format!("{:?}", decline.stage),
        );
        let decline_resource = decline.map_or_else(
            || "none".to_owned(),
            |decline| format!("{:?}", decline.resource).replace(' ', ""),
        );
        let fields = [
            "partial_dfa".to_owned(),
            shape.spec.name.clone(),
            shape.spec.family.to_owned(),
            format!("0x{:016x}", shape.spec.seed),
            shape.spec.output.name().to_owned(),
            shape.fallback_artifact_kind.to_owned(),
            shape.score_scope().to_owned(),
            shape.retained_limit_derivation.to_owned(),
            shape.runtime_program.is_some().to_string(),
            shape
                .aot
                .module()
                .prepared_entry_symbol()
                .is_some()
                .to_string(),
            shape
                .aot
                .module()
                .prepared_entry_symbol()
                .unwrap_or("none")
                .to_owned(),
            shape.prepared_capability_format.to_owned(),
            number(partial.map(|stats| stats.complete_rows as u64)),
            number(partial.map(|stats| stats.discovered_states as u64)),
            number(partial.map(|stats| stats.resume_frontiers as u64)),
            number(partial.map(|stats| stats.resume_items as u64)),
            partial.map_or_else(|| "na".to_owned(), |stats| {
                stats.optimized_entry_supported.to_string()
            }),
            number(partial.map(|stats| stats.min_input_bytes as u64)),
            requested.max_states.to_string(),
            requested.max_transitions.to_string(),
            requested.max_work.to_string(),
            effective.max_states.to_string(),
            effective.max_transitions.to_string(),
            effective.max_work.to_string(),
            decline_stage,
            decline_resource,
            report.work_completed.to_string(),
            report.states_completed.to_string(),
            report.transitions_completed.to_string(),
            shape.aot.program().has_nfa_exact_product().to_string(),
            "ok".to_owned(),
        ];
        println!("{}", fields.join("\t"));
    }

    // Keep the established partial-DFA row schema stable for existing matrix
    // consumers. Slow-AOT provenance is an additive comment-prefixed table.
    println!(
        "#slow_aot_header\tpattern\tfamily\tseed\toutput\tlimit_derivation\tpresent\tpartial_admitted\trequested_max_states\teffective_max_states\tcomplete_rows\tforward_states_before_minimization\tdecline_stage\tdecline_resource\twork_completed\truntime_helper_symbols\tstatus"
    );
    for shape in shapes {
        let slow = shape.aot.receipt().slow_aot.as_ref();
        let slow_decline = slow.and_then(|report| report.determinization.decline);
        let number = |value: Option<u64>| {
            value.map_or_else(|| "na".to_owned(), |value| value.to_string())
        };
        let runtime_helper_symbols = shape
            .aot
            .module()
            .symbols()
            .iter()
            .filter(|symbol| symbol.section.is_none())
            .map(|symbol| symbol.name.as_str())
            .collect::<Vec<_>>()
            .join(",");
        let fields = [
            "#slow_aot".to_owned(),
            shape.spec.name.clone(),
            shape.spec.family.to_owned(),
            format!("0x{:016x}", shape.spec.seed),
            shape.spec.output.name().to_owned(),
            shape.retained_limit_derivation.to_owned(),
            slow.is_some().to_string(),
            is_genuine_slow_partial(&shape.aot).to_string(),
            number(slow.map(|report| report.requested_limits.determinize.max_states as u64)),
            number(slow.map(|report| report.determinization.effective_limits.max_states as u64)),
            number(slow.map(|report| report.dfa.forward_states as u64)),
            number(
                slow.map(|report| report.dfa.forward_states_before_minimization as u64),
            ),
            slow_decline.map_or_else(
                || "none".to_owned(),
                |decline| format!("{:?}", decline.stage),
            ),
            slow_decline.map_or_else(
                || "none".to_owned(),
                |decline| format!("{:?}", decline.resource).replace(' ', ""),
            ),
            number(slow.map(|report| report.determinization.work_completed)),
            if runtime_helper_symbols.is_empty() {
                "none".to_owned()
            } else {
                runtime_helper_symbols
            },
            "ok".to_owned(),
        ];
        println!("{}", fields.join("\t"));
    }
}

fn print_environment(config: &Config, shapes: &[CompiledShape], scenario_count: usize) {
    let compiler = env::var_os("CC").unwrap_or_else(|| OsString::from("cc"));
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
    let seeds = shapes
        .iter()
        .map(|shape| format!("0x{:016x}", shape.spec.seed))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(",");
    let requested_features = [
        (CpuFeature::X86Sse2, "sse2"),
        (CpuFeature::X86Avx2, "avx2"),
        (CpuFeature::X86Avx512F, "avx512f"),
        (CpuFeature::X86Avx512Bw, "avx512bw"),
        (CpuFeature::X86Avx512Vl, "avx512vl"),
        (CpuFeature::Aarch64Asimd, "asimd"),
        (CpuFeature::Aarch64Sve, "sve"),
        (CpuFeature::Aarch64Sve2, "sve2"),
    ]
    .into_iter()
    .filter_map(|(feature, name)| {
        feature_requested(config.target.features, feature).then_some(name)
    })
    .collect::<Vec<_>>()
    .join(",");
    println!("#environment\tkey\tvalue");
    println!(
        "environment\tbenchmark_mode\t{}",
        if config.nested_grammar {
            "nested_grammar_generated_out_of_sample"
        } else if config.grammar {
            "grammar_generated_out_of_sample"
        } else {
            "fixed_structural_matrix"
        }
    );
    if config.nested_grammar {
        println!("environment\tgenerator\trecursive_byte_regex_ast_v1");
        println!(
            "environment\tfull_grammar_dimensions\troot_seeds=2,families=12,patterns_per_family=4,patterns=96"
        );
        println!("environment\tbaseline_assigned_full_matrix_cells\t4608");
        // Retain the established key for metadata consumers, but report the
        // configured run rather than the two-root assigned-contract baseline.
        println!("environment\tfull_matrix_cells\t{scenario_count}");
        println!("environment\twindow_bytes\t64,4096,65536");
        println!("environment\tmatch_positions\tnone,start,middle,end");
        println!(
            "environment\trotation_backgrounds\tpunctuation_safe,weighted_englishish,code_alphanumeric,full_byte_prng"
        );
        println!("environment\tcandidate_densities\tzero,1_per_32,near_miss_1_per_32,dense");
        println!(
            "environment\tsemantic_validation\tregex_{UPSTREAM_REGEX_VERSION}_oracle_vs_portable_fre_then_linked_native"
        );
        println!(
            "environment\taggregation_scope\tevery_timed_row_enters_generated_code;native_entry_scope_distinguishes_self_contained_prepared_and_runtime_dependent"
        );
    }
    println!("environment\ttarget\t{}", config.target_name);
    println!(
        "environment\trequested_features\t{}",
        if requested_features.is_empty() {
            "none"
        } else {
            &requested_features
        }
    );
    println!(
        "environment\tfeature_bits\t0x{:x}",
        config.target.features.bits()
    );
    println!("environment\thost_feature_validation\tpassed");
    println!("environment\tregex_version\t{UPSTREAM_REGEX_VERSION}");
    println!("environment\tregex_features\tdefault,perf-dfa-full (logging disabled)");
    println!(
        "environment\trustc\t{}",
        command_version(&rustc, "--version")
    );
    println!(
        "environment\tc_compiler\t{}",
        command_version(&compiler, "--version")
    );
    println!(
        "environment\thost_kernel\t{}",
        command_version(OsStr::new("uname"), "-a")
    );
    println!("environment\tnative_harness_flags\t-O3 -std=c11");
    println!(
        "environment\tmeasurement_order\t{}",
        config.measurement_order.name()
    );
    println!(
        "environment\toutput_matrix\t{}",
        if config.output_matrix {
            "span_exists_selected_end_v1"
        } else {
            "assigned_v1"
        }
    );
    println!(
        "environment\tforce_resource_fallback\t{}",
        config.force_resource_fallback
    );
    println!(
        "environment\tforce_retained_resource_fallback\t{}",
        config.force_retained_resource_fallback
    );
    println!(
        "environment\tforce_slow_partial_resource_fallback\t{}",
        config.force_slow_partial_resource_fallback
    );
    println!(
        "environment\tslow_aot_policy\t{}",
        config.forced_fallback_mode().slow_aot_policy()
    );
    let artifact_counts = shapes.iter().fold(BTreeMap::new(), |mut counts, shape| {
        *counts.entry(shape.fallback_artifact_kind).or_insert(0_usize) += 1;
        counts
    });
    println!(
        "environment\tfallback_artifact_counts\t{}",
        artifact_counts
            .into_iter()
            .map(|(kind, count)| format!("{kind}={count}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    let derivation_counts = shapes.iter().fold(BTreeMap::new(), |mut counts, shape| {
        *counts
            .entry(shape.retained_limit_derivation)
            .or_insert(0_usize) += 1;
        counts
    });
    println!(
        "environment\tfallback_limit_derivation_counts\t{}",
        derivation_counts
            .into_iter()
            .map(|(kind, count)| format!("{kind}={count}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    println!("environment\tseeds\t{seeds}");
    println!("environment\tcompiled_patterns\t{}", shapes.len());
    println!("environment\tscenarios\t{scenario_count}");
    println!(
        "environment\tavailable_parallelism\t{}",
        std::thread::available_parallelism().map_or(0, usize::from)
    );
}

fn run(config: &Config) -> Result<(), String> {
    let architecture = match config.target.architecture {
        Architecture::X86_64 => "x86_64",
        Architecture::Aarch64 => "aarch64",
    };
    let operating_system = match config.target.operating_system {
        OperatingSystem::Linux => "linux",
        OperatingSystem::Macos => "macos",
    };
    let shapes = compile_shapes(config)?;
    eprintln!(
        "generated comparison: {architecture}-{operating_system}, patterns={}, cells={}, feature_bits={:#x}, trials={}, bytes_per_trial={}, min_searches={}, min_trial_ns={}, smoke={}, grammar={}, nested_grammar={}, output_matrix={}, force_resource_fallback={}, force_retained_resource_fallback={}, force_slow_partial_resource_fallback={}, slow_aot_policy={}, family_filter={}, pattern_filter={}, route_filter={}, measurement_order={}, seed_filter={}",
        shapes.len(),
        shapes.len() * sizes(config).len() * positions(config).len() * densities(config).len(),
        config.target.features.bits(),
        config.trials,
        config.bytes_per_trial,
        config.min_searches,
        config.min_trial_ns,
        config.smoke,
        config.grammar,
        config.nested_grammar,
        config.output_matrix,
        config.force_resource_fallback,
        config.force_retained_resource_fallback,
        config.force_slow_partial_resource_fallback,
        config.forced_fallback_mode().slow_aot_policy(),
        config.family_filter.as_deref().unwrap_or("all"),
        config.pattern_filter.as_deref().unwrap_or("all"),
        config.route_filter.as_deref().unwrap_or("all"),
        config.measurement_order.name(),
        config
            .seed_filter
            .map_or_else(|| "all".to_owned(), |seed| format!("0x{seed:016x}")),
    );
    let scenarios = build_scenarios(config, &shapes)?;
    let runtime = build_runtime_staticlib()?;
    let scratch = ScratchDirectory::create()?;
    let executable = compile_native_harness(&scratch.0, config, &shapes, &scenarios, &runtime)?;
    let prepared_native = prepare_native_harness(&executable, &scratch.0)?;
    print_environment(config, &shapes, scenarios.len());
    print_partial_dfa_metadata(&shapes);
    let (upstream, native) = measure_in_order(
        config.measurement_order,
        || measure_upstream(config, &shapes, &scenarios),
        || execute_native_harness(prepared_native, scenarios.len()),
    )?;
    print_joined_rows(config, &shapes, &scenarios, &upstream, &native)?;
    eprintln!("validated and measured {} generated cells", scenarios.len());
    Ok(())
}

fn main() -> ExitCode {
    match Config::parse() {
        Ok(None) => {
            println!("{}", usage());
            ExitCode::SUCCESS
        }
        Ok(Some(config)) => match run(&config) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use fre_aot_regex::compile;

    const UNSEEN_TEST_SEED: u64 = 0x510e_527f_ade6_82d1;

    fn flat_grammar_config(seed_filter: Option<u64>) -> Config {
        Config {
            trials: 3,
            warmup_rounds: 1,
            bytes_per_trial: 64,
            min_searches: 1,
            min_trial_ns: 1,
            target: Target::x86_64_linux(),
            target_name: "linux-x86_64",
            smoke: true,
            family_filter: None,
            pattern_filter: None,
            route_filter: None,
            measurement_order: MeasurementOrder::default(),
            output_matrix: false,
            force_resource_fallback: false,
            force_retained_resource_fallback: false,
            force_slow_partial_resource_fallback: false,
            seed_filter,
            grammar: true,
            nested_grammar: false,
        }
    }

    fn generated_grammar_config(
        nested: bool,
        seed_filter: Option<u64>,
        output_matrix: bool,
    ) -> Config {
        let mut config = flat_grammar_config(seed_filter);
        config.smoke = false;
        config.output_matrix = output_matrix;
        config.grammar = !nested;
        config.nested_grammar = nested;
        config
    }

    fn renamed_test_spec(pattern: &str, output: OutputKind, name: &str) -> SeededPatternSpec {
        let mut spec = grammar_patterns(&flat_grammar_config(Some(UNSEEN_TEST_SEED)))
            .into_iter()
            .next()
            .expect("generated test shape");
        spec.name = name.to_owned();
        spec.base_name = name.to_owned();
        spec.family = "structural_test";
        spec.pattern = pattern.to_owned();
        spec.fixture = b"AqqZ".to_vec();
        spec.candidates = b"A".to_vec();
        spec.output = output;
        spec.force_fallback = false;
        spec
    }

    fn compiled_test_shape(
        spec: SeededPatternSpec,
        aot: CompiledRegex,
        fallback_artifact_kind: &'static str,
        limit_derivation: &'static str,
    ) -> CompiledShape {
        let runtime_program = aot
            .module()
            .required_runtime_program()
            .map(|(symbol, bytes)| (symbol.to_owned(), bytes));
        let partial_dfa = retained_partial_stats(&aot).expect("test partial statistics");
        let prepared_capability_format =
            prepared_capability_format(&aot).expect("test prepared capability");
        CompiledShape {
            upstream: Regex::new(&spec.pattern).expect("test upstream regex"),
            spec,
            aot,
            runtime_program,
            partial_dfa,
            prepared_capability_format,
            fallback_artifact_kind,
            retained_limit_derivation: limit_derivation,
        }
    }

    fn generated_matrix_cardinality(config: &Config) -> (usize, usize) {
        let sources = if config.nested_grammar {
            nested_grammar_patterns(config).unwrap()
        } else {
            grammar_patterns(config)
        };
        let compiled_patterns = expand_output_matrix(sources, config.output_matrix).len();
        let scenarios = compiled_patterns
            * sizes(config).len()
            * positions(config).len()
            * densities(config).len();
        (compiled_patterns, scenarios)
    }

    #[test]
    fn generator_seed_selection_preserves_defaults_and_accepts_unseen_roots() {
        assert_eq!(
            selected_generator_seeds(None),
            vec![(0, PATTERN_SEEDS[0]), (1, PATTERN_SEEDS[1])]
        );
        assert_eq!(
            selected_generator_seeds(Some(PATTERN_SEEDS[1])),
            vec![(1, PATTERN_SEEDS[1])]
        );
        assert_eq!(
            selected_generator_seeds(Some(UNSEEN_TEST_SEED)),
            vec![(0, UNSEEN_TEST_SEED)]
        );
    }

    #[test]
    fn measurement_order_parser_scheduler_and_preparation_handshake_are_exact() {
        use std::cell::RefCell;

        assert_eq!(
            parse_measurement_order("upstream-native"),
            Ok(MeasurementOrder::UpstreamNative)
        );
        assert_eq!(
            parse_measurement_order("native-upstream"),
            Ok(MeasurementOrder::NativeUpstream)
        );
        assert!(parse_measurement_order("alternating").is_err());
        assert_eq!(
            MeasurementOrder::default(),
            MeasurementOrder::UpstreamNative
        );

        for (order, expected) in [
            (MeasurementOrder::UpstreamNative, vec!["upstream", "native"]),
            (MeasurementOrder::NativeUpstream, vec!["native", "upstream"]),
        ] {
            let events = RefCell::new(Vec::new());
            let measured = measure_in_order(
                order,
                || {
                    events.borrow_mut().push("upstream");
                    Ok::<_, ()>(11)
                },
                || {
                    events.borrow_mut().push("native");
                    Ok::<_, ()>(7)
                },
            )
            .unwrap();
            assert_eq!(measured, (11, 7));
            assert_eq!(events.into_inner(), expected);
        }

        let source = build_c_harness(&flat_grammar_config(None), &[], &[]);
        let prepare = source
            .find("fre_aot_regex_runtime_prepare_exclusive_v1(shapes[index].program")
            .expect("runtime preparation call");
        let ready = source.find("fputs(\"ready\\n\"").expect("ready handshake");
        let wait = source.find("getchar() == EOF").expect("measurement gate");
        let measure = source
            .find("measure_one(&scenarios[index])")
            .expect("native timed phase");
        assert!(prepare < ready && ready < wait && wait < measure);
    }

    #[test]
    fn forced_fallback_modes_and_new_routes_are_closed_and_mutually_exclusive() {
        assert_eq!(
            forced_fallback_mode(false, false, false),
            Ok(ForcedFallbackMode::None)
        );
        assert_eq!(
            forced_fallback_mode(true, false, false),
            Ok(ForcedFallbackMode::ZeroRows)
        );
        assert_eq!(
            forced_fallback_mode(false, true, false),
            Ok(ForcedFallbackMode::RetainedRows)
        );
        assert_eq!(
            forced_fallback_mode(false, false, true),
            Ok(ForcedFallbackMode::SlowPartial)
        );
        for flags in [
            (true, true, false),
            (true, false, true),
            (false, true, true),
            (true, true, true),
        ] {
            assert!(forced_fallback_mode(flags.0, flags.1, flags.2).is_err());
        }

        for route in [
            "prepared_runtime_assertion",
            "ordinary_runtime_assertion",
            "direct_context_fallback",
            "slow_partial_resource_fallback",
        ] {
            assert!(is_known_route(route));
        }
        assert!(!is_known_route("prepared_by_pattern_name"));

        let disabled = disabled_slow_aot_limits();
        assert_eq!(disabled.determinize.max_states, 0);
        assert_eq!(disabled.determinize.max_transitions, 0);
        assert_eq!(disabled.determinize.max_work, 0);
        assert_eq!(disabled.max_allocation_bytes, 0);
        assert_eq!(disabled.max_native_data_bytes, 0);
    }

    #[test]
    fn zero_and_natural_retained_force_modes_disable_slow_aot_at_final_compile() {
        let target = Target::x86_64_linux();

        let mut config = flat_grammar_config(Some(UNSEEN_TEST_SEED));
        let selected_name = grammar_patterns(&config)[0].name.clone();
        config.pattern_filter = Some(selected_name);
        config.force_resource_fallback = true;
        let zero_rows = compile_shapes(&config).expect("forced zero-row shape");
        assert_eq!(zero_rows.len(), 1);
        assert!(zero_rows[0].aot.receipt().slow_aot.is_none());
        assert_eq!(
            zero_rows[0]
                .aot
                .receipt()
                .determinization
                .requested_limits
                .max_states,
            0
        );
        assert_eq!(
            zero_rows[0].retained_limit_derivation,
            "zero_state_slow_disabled"
        );

        let spec = renamed_test_spec(
            "a+Q|[b-c][a-b]{1,5}(?:x+|y+)|a*",
            OutputKind::SelectedEnd,
            "natural_retained_renamed",
        );
        let mut probe_limits = CompileLimitsV1::default();
        probe_limits.determinize.max_states = 8;
        let (retained, derivation) = compile_retained_resource_probe_with_limits(
            &spec,
            target,
            probe_limits,
        )
        .expect("natural retained structural probe");
        assert_eq!(derivation, "natural_decline_slow_disabled");
        assert!(retained.receipt().slow_aot.is_none());
        let stats = retained_partial_stats(&retained)
            .expect("retained statistics")
            .expect("nonempty natural retained rows");
        assert!(stats.complete_rows > 0);
    }

    #[test]
    fn slow_partial_derivation_is_structural_and_times_the_generated_entry() {
        const PATTERN: &str = "A(?-u:[^Z])*Z|(?:ab|cd){2,8}";
        let target = Target::x86_64_linux();
        let derive_without_name: fn(
            &str,
            OutputKind,
            Target,
        ) -> Result<(CompiledRegex, &'static str), String> = compile_slow_partial_resource_probe;
        let (aot, derivation) = derive_without_name(PATTERN, OutputKind::SelectedEnd, target)
            .expect("derive genuine slow partial from source structure");
        assert!(matches!(
            derivation,
            "slow_forward_state_limit"
                | "slow_forward_state_search"
                | "slow_natural_resource_limit"
        ));
        assert!(is_genuine_slow_partial(&aot));
        let slow = aot.receipt().slow_aot.as_ref().expect("slow report");
        assert_eq!(
            slow
                .determinization
                .decline
                .expect("slow decline")
                .stage,
            DeterminizationStage::ForwardSubsetConstruction
        );
        assert!(slow.dfa.forward_states > 0);
        assert!(slow.dfa.forward_states < slow.dfa.forward_states_before_minimization);
        assert_eq!(aot.receipt().determinization.requested_limits.max_states, 0);

        let entry = aot.module().entry_symbol().to_owned();
        let (runtime_symbol, runtime_bytes) = aot
            .module()
            .required_runtime_program()
            .map(|(symbol, bytes)| (symbol.to_owned(), bytes))
            .expect("current whole-search slow-partial wrapper program");
        assert!(aot.module().prepared_entry_symbol().is_none());
        let shape = compiled_test_shape(
            renamed_test_spec(PATTERN, OutputKind::SelectedEnd, "arbitrary_renamed_source"),
            aot,
            "slow_aot_partial",
            derivation,
        );
        assert_eq!(shape.route(), "slow_partial_resource_fallback");
        assert_eq!(shape.score_scope(), "slow_aot_partial_generated_entry");
        assert!(shape.is_compiled_primary());

        let source = build_c_harness(&flat_grammar_config(None), &[shape], &[]);
        assert!(source.contains(&format!(
            "extern uint32_t {entry}(const unsigned char *"
        )));
        assert!(source.contains(&format!(
            "{{\"arbitrary_renamed_source\", {entry}, NULL, {runtime_symbol}, {runtime_bytes}, 0"
        )));
        assert!(source.contains("return shape->direct(haystack, length, 0U, length, result);"));
    }

    #[test]
    fn slow_context_completion_uses_the_direct_context_fallback_route() {
        const PATTERN: &str = r"(?-u:\b)abc(?-u:\b)";
        let (aot, derivation) = compile_slow_partial_resource_probe(
            PATTERN,
            OutputKind::Span,
            Target::x86_64_linux(),
        )
        .expect("truthful excluded slow-context fallback");
        assert_eq!(derivation, "excluded_contextual");
        assert!(!is_genuine_slow_partial(&aot));
        assert_eq!(
            aot.receipt().engine_selection_reason,
            EngineSelectionReason::ContextAssertions
        );
        assert!(aot.receipt().slow_context_aot.is_some());
        assert!(aot.module().prepared_entry_symbol().is_none());
        assert!(aot.module().required_runtime_program().is_none());
        let entry = aot.module().entry_symbol().to_owned();
        let shape = compiled_test_shape(
            renamed_test_spec(PATTERN, OutputKind::Span, "renamed_context_source"),
            aot,
            "contextual",
            derivation,
        );
        assert_eq!(shape.route(), "direct_context_fallback");
        assert_eq!(shape.timed_entry_scope(), "self_contained_compiled");

        let source = build_c_harness(&flat_grammar_config(None), &[shape], &[]);
        assert!(source.contains(&format!(
            "{{\"renamed_context_source\", {entry}, NULL, NULL, 0, 0"
        )));
        assert!(source.contains("return shape->direct(haystack, length, 0U, length, result);"));
    }

    #[test]
    fn direct_resource_fallback_is_classified_from_the_emitted_object_abi() {
        let target = Target::x86_64_linux();
        let mut limits = CompileLimitsV1::default();
        limits.determinize.max_states = 0;
        let aot = compile(
            CompileRequest::new("[ab]x", target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span)
                .limits(limits),
        )
        .expect("compile exact-product resource fallback");
        assert_eq!(aot.receipt().engine, EngineKind::OrderedNfa);
        assert!(aot.program().has_nfa_exact_product());
        assert!(aot.module().required_runtime_program().is_none());
        assert!(aot.module().required_runtime_symbol().is_none());
        assert!(is_self_contained_native_shape(&aot));

        let shape = CompiledShape {
            spec: grammar_patterns(&flat_grammar_config(Some(UNSEEN_TEST_SEED)))
                .into_iter()
                .next()
                .expect("grammar shape"),
            upstream: Regex::new("[ab]x").unwrap(),
            aot,
            runtime_program: None,
            partial_dfa: None,
            prepared_capability_format: "not_prepared",
            fallback_artifact_kind: "exact_product",
            retained_limit_derivation: "legacy_zero_state",
        };
        assert_eq!(shape.route(), "direct_resource_fallback");
        assert!(shape.is_compiled_primary());
    }

    #[test]
    fn zero_row_variable_span_prepared_entry_is_embedded_and_scored_as_compiled() {
        let target = Target::x86_64_linux();
        let pattern = "(?:ab|ac)+z";
        let mut limits = CompileLimitsV1::default();
        limits.determinize.max_states = 0;
        let slow_limits = fre_aot_regex::SlowAotLimits {
            determinize: fre_aot_regex::DeterminizeLimits {
                max_states: 0,
                ..fre_aot_regex::DeterminizeLimits::default()
            },
            max_native_data_bytes: 0,
            ..fre_aot_regex::SlowAotLimits::default()
        };
        let aot = fre_aot_regex::compile_with_slow_aot_limits(
            CompileRequest::new(pattern, target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span)
                .limits(limits),
            slow_limits,
        )
        .expect("compile optimizing zero-row variable Span");
        assert_eq!(
            aot.receipt().engine_selection_reason,
            EngineSelectionReason::DeterminizationResourceLimit
        );
        assert!(retained_partial_stats(&aot).unwrap().is_none());
        let prepared_entry = aot
            .module()
            .prepared_entry_symbol()
            .expect("general dynamic-row prepared entry")
            .to_owned();
        let entry = aot.module().entry_symbol().to_owned();
        let (runtime_symbol, runtime_bytes) = aot
            .module()
            .required_runtime_program()
            .map(|(symbol, bytes)| (symbol.to_owned(), bytes))
            .expect("prepared entry serialized program");
        let runtime_program = Some((runtime_symbol.clone(), runtime_bytes));
        assert_eq!(
            prepared_capability_format(&aot).unwrap(),
            "active_immutable_compact_v3_v14"
        );

        let fixture = b"abz";
        let upstream = Regex::new(pattern).unwrap();
        let upstream_result = upstream_search(&upstream, OutputKind::Span, fixture);
        let portable_result = AbiResult::from_aot(
            aot.search(fixture, SearchWindow::full(fixture)).unwrap(),
            OutputKind::Span,
        )
        .unwrap();
        assert_eq!(portable_result, upstream_result);

        let mut spec = grammar_patterns(&flat_grammar_config(Some(UNSEEN_TEST_SEED)))
            .into_iter()
            .next()
            .expect("grammar shape");
        spec.name = "zero_row_variable_span".to_owned();
        spec.base_name = spec.name.clone();
        spec.family = "resource_fallback";
        spec.pattern = pattern.to_owned();
        spec.fixture = fixture.to_vec();
        spec.candidates = b"a".to_vec();
        spec.output = OutputKind::Span;
        spec.force_fallback = true;
        let shape = CompiledShape {
            spec,
            upstream,
            aot,
            runtime_program,
            partial_dfa: None,
            prepared_capability_format: "active_immutable_compact_v3_v14",
            fallback_artifact_kind: "dynamic_rows",
            retained_limit_derivation: "legacy_zero_state",
        };
        assert_eq!(shape.route(), "prepared_runtime_resource_fallback");
        assert!(shape.is_compiled_primary());
        assert_eq!(shape.score_scope(), "prepared_compiled_all_windows");

        let source = build_c_harness(&flat_grammar_config(None), &[shape], &[]);
        assert!(source.contains(&format!(
            "extern uint32_t {prepared_entry}(exclusive_handle"
        )));
        assert!(source.contains(&format!("extern const unsigned char {runtime_symbol}[];")));
        assert!(source.contains(&format!(
            "{{\"zero_row_variable_span\", {entry}, {prepared_entry}, {runtime_symbol}, {runtime_bytes}, 0"
        )));
    }

    #[test]
    fn runtime_backed_nonprepared_shape_times_the_generated_entry() {
        let target = Target::x86_64_linux();
        let pattern = r"a{0}";
        let mut limits = CompileLimitsV1::default();
        limits.determinize.max_states = 0;
        let aot = fre_aot_regex::compile_with_slow_aot_limits(
            CompileRequest::new(pattern, target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span)
                .limits(limits),
            fre_aot_regex::SlowAotLimits {
                max_allocation_bytes: 0,
                max_native_data_bytes: 0,
                ..fre_aot_regex::SlowAotLimits::default()
            },
        )
        .expect("compile runtime-backed nonprepared fixture");
        assert_eq!(
            aot.receipt().engine_selection_reason,
            EngineSelectionReason::DeterminizationResourceLimit
        );
        assert!(retained_partial_stats(&aot).unwrap().is_none());
        assert!(aot.module().prepared_entry_symbol().is_none());
        assert!(!is_self_contained_native_shape(&aot));
        let entry = aot.module().entry_symbol().to_owned();
        let (runtime_symbol, runtime_bytes) = aot
            .module()
            .required_runtime_program()
            .map(|(symbol, bytes)| (symbol.to_owned(), bytes))
            .expect("runtime adapter serialized program");

        let fixture = b"x";
        let upstream = Regex::new(pattern).unwrap();
        let upstream_result = upstream_search(&upstream, OutputKind::Span, fixture);
        let portable_result = AbiResult::from_aot(
            aot.search(fixture, SearchWindow::full(fixture)).unwrap(),
            OutputKind::Span,
        )
        .unwrap();
        assert_eq!(portable_result, upstream_result);

        let mut spec = grammar_patterns(&flat_grammar_config(Some(UNSEEN_TEST_SEED)))
            .into_iter()
            .next()
            .expect("grammar shape");
        spec.name = "runtime_backed_nonprepared".to_owned();
        spec.base_name = spec.name.clone();
        spec.family = "resource_fallback";
        spec.pattern = pattern.to_owned();
        spec.fixture = fixture.to_vec();
        spec.candidates = b"x".to_vec();
        spec.output = OutputKind::Span;
        spec.force_fallback = true;
        let shape = CompiledShape {
            spec,
            upstream,
            aot,
            runtime_program: Some((runtime_symbol.clone(), runtime_bytes)),
            partial_dfa: None,
            prepared_capability_format: "not_prepared",
            fallback_artifact_kind: "plain_nfa",
            retained_limit_derivation: "legacy_zero_state",
        };
        assert_eq!(shape.route(), "ordinary_runtime_resource_fallback");
        assert!(shape.is_compiled_primary());
        assert_eq!(shape.timed_entry_scope(), "runtime_dependent_compiled");
        assert_eq!(shape.score_scope(), "runtime_dependent_compiled_entry");

        let source = build_c_harness(&flat_grammar_config(None), &[shape], &[]);
        assert!(source.contains(&format!(
            "{{\"runtime_backed_nonprepared\", {entry}, NULL, {runtime_symbol}, {runtime_bytes}, 0"
        )));
        assert!(source.contains("return shape->direct(haystack, length, 0U, length, result);"));
        assert!(!source.contains("fre_aot_regex_runtime_search_exclusive_v1"));
    }

    #[test]
    fn complete_retained_direct_resource_fallback_is_self_contained() {
        let target = Target::aarch64_macos()
            .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
            .unwrap();
        let pattern = "(?:ab|c){3,6}Z";
        let complete = compile(
            CompileRequest::new(pattern, target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::SelectedEnd),
        )
        .expect("compile complete DFA probe");
        let mut limits = CompileLimitsV1::default();
        limits.determinize.max_work = complete
            .receipt()
            .dfa
            .expect("complete DFA statistics")
            .build_work
            .checked_sub(1)
            .expect("nonzero DFA work");
        let retained = compile(
            CompileRequest::new(pattern, target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::SelectedEnd)
                .limits(limits),
        )
        .expect("compile complete retained fallback");
        let partial = retained_partial_stats(&retained)
            .unwrap()
            .expect("retained-row statistics");

        assert_eq!(retained.receipt().engine, EngineKind::OrderedNfa);
        assert_eq!(
            retained.receipt().engine_selection_reason,
            EngineSelectionReason::DeterminizationResourceLimit
        );
        assert!(!retained.program().has_nfa_exact_product());
        assert!(retained.module().required_runtime_program().is_none());
        assert!(retained.module().required_runtime_symbol().is_none());
        assert!(!retained.receipt().runtime_helper_required);
        assert_eq!(partial.complete_rows, partial.discovered_states);
        assert_eq!(partial.resume_frontiers, 0);
        assert_eq!(partial.resume_items, 0);
        assert!(partial.optimized_entry_supported);
        assert!(is_self_contained_native_shape(&retained));
    }

    #[test]
    fn retained_resource_routes_track_the_published_prepared_symbol() {
        let prepared_limits = CompileLimitsV1 {
            determinize: fre_aot_regex::DeterminizeLimits {
                max_states: 8,
                ..fre_aot_regex::DeterminizeLimits::default()
            },
            ..CompileLimitsV1::default()
        };
        let base_spec = grammar_patterns(&flat_grammar_config(Some(UNSEEN_TEST_SEED)))
            .into_iter()
            .next()
            .expect("grammar shape");
        let pattern = "a+Q|[b-c][a-b]{1,5}(?:x+|y+)|a*";
        for (bound_slow_native, expected_route, prepared, runtime_backed) in [
            (
                true,
                "prepared_runtime_resource_fallback",
                true,
                true,
            ),
            (false, "direct_resource_fallback", false, false),
        ] {
            let request = CompileRequest::new(pattern, Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::SelectedEnd)
                .limits(prepared_limits);
            let aot = if bound_slow_native {
                fre_aot_regex::compile_with_slow_aot_limits(
                    request,
                    fre_aot_regex::SlowAotLimits {
                        max_native_data_bytes: 0,
                        ..fre_aot_regex::SlowAotLimits::default()
                    },
                )
            } else {
                compile(request)
            }
            .expect("compile retained route fixture");
            let runtime_program = aot
                .module()
                .required_runtime_program()
                .map(|(symbol, bytes)| (symbol.to_owned(), bytes));
            let partial_dfa = retained_partial_stats(&aot).unwrap();
            assert_eq!(runtime_program.is_some(), runtime_backed, "{pattern:?}");
            let partial_stats = partial_dfa.expect("incomplete retained semantic rows");
            assert!(partial_stats.complete_rows > 0);
            assert!(partial_stats.complete_rows < partial_stats.discovered_states);
            assert_eq!(aot.module().prepared_entry_symbol().is_some(), prepared);
            assert_eq!(
                is_self_contained_native_shape(&aot),
                !runtime_backed,
                "{pattern:?}"
            );

            let mut spec = base_spec.clone();
            spec.pattern = pattern.to_owned();
            spec.output = OutputKind::SelectedEnd;
            let shape = CompiledShape {
                spec,
                upstream: Regex::new(pattern).unwrap(),
                prepared_capability_format: prepared_capability_format(&aot).unwrap(),
                aot,
                runtime_program,
                partial_dfa,
                fallback_artifact_kind: "retained_partial",
                retained_limit_derivation: "forward_state_limit",
            };
            assert_eq!(shape.route(), expected_route);
            assert_eq!(
                shape.score_scope(),
                if prepared {
                    "prepared_compiled_all_windows"
                } else {
                    "slow_aot_self_contained_all_windows"
                }
            );
        }
    }

    #[test]
    fn flat_grammar_generates_a_complete_unique_suite_from_an_unseen_root() {
        let config = flat_grammar_config(Some(UNSEEN_TEST_SEED));
        let patterns = grammar_patterns(&config);
        assert_eq!(
            patterns.len(),
            GRAMMAR_FAMILIES.len() * GRAMMAR_PATTERNS_PER_FAMILY
        );
        assert!(patterns.iter().all(|pattern| {
            pattern.seed == UNSEEN_TEST_SEED && pattern.source_kind == "grammar_generated"
        }));
        assert_eq!(
            patterns
                .iter()
                .map(|pattern| pattern.family)
                .collect::<BTreeSet<_>>()
                .len(),
            GRAMMAR_FAMILIES.len()
        );
        assert_eq!(
            patterns
                .iter()
                .map(|pattern| pattern.pattern.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            patterns.len()
        );
        assert_eq!(
            patterns
                .iter()
                .map(|pattern| pattern.pattern.clone())
                .collect::<Vec<_>>(),
            grammar_patterns(&config)
                .into_iter()
                .map(|pattern| pattern.pattern)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn output_matrix_is_an_exact_contract_cross_product_and_default_is_unchanged() {
        assert!(usage().contains("--output-matrix"));
        let original = grammar_patterns(&flat_grammar_config(Some(UNSEEN_TEST_SEED)))
            .into_iter()
            .take(2)
            .collect::<Vec<_>>();
        let assigned = expand_output_matrix(original.clone(), false);
        assert_eq!(assigned.len(), original.len());
        for (actual, expected) in assigned.iter().zip(&original) {
            assert_eq!(actual.name, expected.name);
            assert_eq!(actual.pattern, expected.pattern);
            assert_eq!(actual.output, expected.output);
        }

        let matrix = expand_output_matrix(original.clone(), true);
        assert_eq!(matrix.len(), original.len() * OutputKind::MATRIX.len());
        for (source, contracts) in original.iter().zip(matrix.chunks_exact(3)) {
            assert_eq!(
                contracts.iter().map(|spec| spec.output).collect::<Vec<_>>(),
                OutputKind::MATRIX
            );
            for contract in contracts {
                assert_eq!(contract.base_name, source.base_name);
                assert_eq!(contract.family, source.family);
                assert_eq!(contract.pattern, source.pattern);
                assert_eq!(contract.fixture, source.fixture);
                assert_eq!(contract.candidates, source.candidates);
                assert_eq!(contract.seed, source.seed);
                assert_eq!(contract.generation_id, source.generation_id);
                assert!(contract.name.ends_with(contract.output.name()));
            }
        }
        assert_eq!(
            matrix
                .iter()
                .map(|spec| &spec.name)
                .collect::<BTreeSet<_>>()
                .len(),
            matrix.len()
        );

        let oracle = Regex::new("(?:ab|a)").unwrap();
        assert_eq!(
            upstream_search(&oracle, OutputKind::SelectedEnd, b"ab"),
            AbiResult {
                status: 1,
                start: 2,
                end: 2,
            }
        );
        assert_eq!(
            AbiResult::from_aot(MatchResult::SelectedEnd(Some(2)), OutputKind::SelectedEnd),
            Ok(AbiResult {
                status: 1,
                start: 2,
                end: 2,
            })
        );
    }

    #[test]
    fn generated_full_matrix_cardinalities_cover_roots_and_output_contract_modes() {
        let cases = [
            // Flat grammar: 36 sources/root and 2 x 3 x 3 scenario dimensions.
            (false, true, false, 36, 648),
            (false, true, true, 108, 1_944),
            (false, false, false, 72, 1_296),
            (false, false, true, 216, 3_888),
            // Nested grammar: 48 sources/root and 3 x 4 x 4 dimensions.
            (true, true, false, 48, 2_304),
            (true, true, true, 144, 6_912),
            (true, false, false, 96, 4_608),
            (true, false, true, 288, 13_824),
        ];
        for (nested, one_root, output_matrix, expected_patterns, expected_scenarios) in cases {
            let seed_filter = one_root.then_some(UNSEEN_TEST_SEED);
            let config = generated_grammar_config(nested, seed_filter, output_matrix);
            assert_eq!(
                generated_matrix_cardinality(&config),
                (expected_patterns, expected_scenarios),
                "nested={nested}, one_root={one_root}, output_matrix={output_matrix}"
            );
        }
    }

    #[test]
    fn output_matrix_contracts_compile_with_unique_entries_and_match_the_oracle() {
        let pattern = "(?:ab|a)";
        let haystack = b"xxabyy";
        let oracle = Regex::new(pattern).unwrap();
        let mut entries = BTreeSet::new();
        for output in OutputKind::MATRIX {
            let compiled = compile(
                CompileRequest::new(pattern, Target::x86_64_linux())
                    .mode(CompileMode::Optimizing)
                    .output(output.contract()),
            )
            .unwrap();
            assert_eq!(
                AbiResult::from_aot(
                    compiled
                        .search(haystack, SearchWindow::full(haystack))
                        .unwrap(),
                    output,
                )
                .unwrap(),
                upstream_search(&oracle, output, haystack)
            );
            assert!(entries.insert(compiled.module().entry_symbol().to_owned()));
        }
        assert_eq!(entries.len(), OutputKind::MATRIX.len());
    }

    #[test]
    fn sve_code_profile_distinguishes_exact_range_and_mixed_objects() {
        let target = Target::aarch64_linux()
            .with_features(FeatureSet::of(CpuFeature::Aarch64Sve).with(CpuFeature::Aarch64Sve2))
            .unwrap();
        let profile = |pattern| {
            let compiled = compile(
                CompileRequest::new(pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
            )
            .unwrap();
            aarch64_sve_code_profile(&compiled)
        };

        assert_eq!(profile(r"(?-u:\b)(?s:.)*Z"), "sve2_exact_only");
        assert_eq!(profile(r"[a-z]+"), "base_sve_range_only");
        assert_eq!(
            profile(r"(?-u:\b)[a-z]+Z(?s:.)*?"),
            "mixed_sve2_exact_base_sve_range"
        );
        let asimd_mixed = compile(
            CompileRequest::new(
                r"(?-u:\b)[a-z]+Z(?s:.)*?",
                Target::aarch64_linux()
                    .with_features(
                        FeatureSet::of(CpuFeature::Aarch64Asimd)
                            .with(CpuFeature::Aarch64Sve)
                            .with(CpuFeature::Aarch64Sve2),
                    )
                    .unwrap(),
            )
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span),
        )
        .unwrap();
        assert_eq!(
            aarch64_sve_code_profile(&asimd_mixed),
            "mixed_sve2_exact_base_sve_range"
        );
        assert_eq!(
            aarch64_sve_code_profile(
                &compile(
                    CompileRequest::new("z", Target::x86_64_linux())
                        .mode(CompileMode::Optimizing)
                        .output(OutputContract::Span),
                )
                .unwrap()
            ),
            "not_aarch64"
        );
    }

    #[test]
    fn generated_insertion_validation_separates_nested_and_output_matrix_semantics() {
        let fixed_intended = AbiResult {
            status: 1,
            start: 30,
            end: 34,
        };
        let fixed_extension = AbiResult {
            status: 1,
            start: 29,
            end: 34,
        };
        assert!(generated_insertion_is_valid(
            false,
            false,
            MatchPosition::Middle,
            fixed_intended,
            fixed_intended,
        ));
        assert!(generated_insertion_is_valid(
            false,
            true,
            MatchPosition::Middle,
            fixed_extension,
            fixed_intended,
        ));
        assert!(!generated_insertion_is_valid(
            false,
            true,
            MatchPosition::Middle,
            AbiResult {
                status: 1,
                start: 5,
                end: 10,
            },
            fixed_intended,
        ));

        let nested_intended = AbiResult {
            status: 1,
            start: 0,
            end: 20,
        };
        assert!(generated_insertion_is_valid(
            true,
            true,
            MatchPosition::Start,
            AbiResult {
                status: 1,
                start: 0,
                end: 16,
            },
            nested_intended,
        ));
        assert!(generated_insertion_is_valid(
            true,
            true,
            MatchPosition::None,
            fixed_extension,
            NO_MATCH,
        ));
        assert!(!generated_insertion_is_valid(
            false,
            true,
            MatchPosition::Middle,
            NO_MATCH,
            fixed_intended,
        ));
        assert!(!generated_insertion_is_valid(
            false,
            true,
            MatchPosition::None,
            fixed_extension,
            NO_MATCH,
        ));
    }

    #[test]
    fn upstream_oracle_and_fre_choose_the_true_leftmost_nested_match() {
        // regex 1.12.4's reverse suffix/inner optimization incorrectly skipped
        // this first match. Keep the structural regression here so benchmark
        // qualification cannot silently use that broken offset oracle again.
        let pattern = r"(?:(?:(?:(?:(?:(?:(?:dR)*4Q))+?)+Gy))+(?-u:[\x00-\xFF]))";
        let haystack = b"&~+@:dR4QdR4QGydR4QdR4QGydR4QdR4!dR4QdR4QGydR4QdR4QGydR4QdR4QGya";
        let expected = AbiResult {
            status: 1,
            start: 5,
            end: 26,
        };
        let oracle = Regex::new(pattern).unwrap();
        assert_eq!(
            upstream_search(&oracle, OutputKind::Span, haystack),
            expected
        );

        let compiled = compile(
            CompileRequest::new(pattern, Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
        )
        .unwrap();
        assert_eq!(
            AbiResult::from_aot(
                compiled
                    .search(haystack, SearchWindow::full(haystack))
                    .unwrap(),
                OutputKind::Span,
            )
            .unwrap(),
            expected
        );
    }
}
