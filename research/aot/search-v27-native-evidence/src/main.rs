#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::enum_variant_names,
    clippy::too_many_lines,
    unsafe_code,
    reason = "the bounded evidence harness keeps timing arithmetic and its static AAPCS64 call boundary explicit"
)]

use std::{
    collections::BTreeSet,
    error::Error,
    fs,
    hint::black_box,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use fre::{PortableBuilder, PortableRegex, SearchLimits, SearchWindow};
use fre_jit_aarch64::NativeResult;
use serde::Serialize;

type DynError = Box<dyn Error>;
type EntryFunction = unsafe extern "C" fn(*const u8, usize, usize, usize, *mut NativeResult) -> u64;

const SCHEMA: &str = "fre.aot.search-v27-native-evidence.v1";
const RANDOM_SEMANTIC_CASES_PER_FAMILY: usize = 12;
const DEFAULT_SAMPLE_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_SAMPLES: usize = 5;
const DEFAULT_WINDOW_BYTES: [usize; 2] = [65_536, 1_048_576];
const WINDOW_START: usize = 37;
const CHECKSUM_SEED: u64 = 0x243f_6a88_85a3_08d3;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Topology {
    Uniform,
    Periodic,
    Clustered,
    PhaseUnique,
}

impl Topology {
    const fn name(self) -> &'static str {
        match self {
            Self::Uniform => "uniform",
            Self::Periodic => "periodic",
            Self::Clustered => "clustered",
            Self::PhaseUnique => "phase-unique",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Graph {
    V8Fallback,
    V17Fast,
    V25Fast,
}

impl Graph {
    const fn name(self) -> &'static str {
        match self {
            Self::V8Fallback => "v8-fallback",
            Self::V17Fast => "v17-fast",
            Self::V25Fast => "v25-fast",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Output {
    Exists,
    SelectedEnd,
    Span,
}

impl Output {
    const ALL: [Self; 3] = [Self::Exists, Self::SelectedEnd, Self::Span];

    const fn index(self) -> usize {
        match self {
            Self::Exists => 0,
            Self::SelectedEnd => 1,
            Self::Span => 2,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Exists => "exists",
            Self::SelectedEnd => "selected-end",
            Self::Span => "span",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Outcome {
    NoMatch,
    EarlyMatch,
    LateMatch,
}

impl Outcome {
    const ALL: [Self; 3] = [Self::NoMatch, Self::EarlyMatch, Self::LateMatch];

    const fn name(self) -> &'static str {
        match self {
            Self::NoMatch => "no-match",
            Self::EarlyMatch => "early-match",
            Self::LateMatch => "late-match",
        }
    }

    const fn ordinal(self) -> u64 {
        match self {
            Self::NoMatch => 0,
            Self::EarlyMatch => 1,
            Self::LateMatch => 2,
        }
    }
}

#[derive(Clone, Copy)]
struct CandidateFamily {
    width: usize,
    topology: Topology,
    graph: Graph,
    literal: &'static [u8],
    entries: [EntryFunction; 3],
}

include!(concat!(env!("OUT_DIR"), "/generated.rs"));

#[derive(Debug)]
struct Fixture {
    haystack: Vec<u8>,
    window: SearchWindow,
    expected: Option<(usize, usize)>,
}

#[derive(Clone, Debug, Serialize)]
struct TimingRow {
    width: usize,
    topology: Topology,
    graph: Graph,
    output: Output,
    outcome: Outcome,
    window_bytes: usize,
    iterations: usize,
    native_ns_per_call: f64,
    portable_ns_per_call: f64,
    portable_over_native: f64,
    native_gib_per_second: f64,
    portable_gib_per_second: f64,
    checksum: u64,
}

#[derive(Clone, Debug, Serialize)]
struct GroupSummary {
    group: String,
    cells: usize,
    geomean_portable_over_native: f64,
    p05_portable_over_native: f64,
    median_portable_over_native: f64,
    p95_portable_over_native: f64,
    cells_over_1_20: usize,
    cells_below_1_00: usize,
}

#[derive(Debug, Serialize)]
struct Evidence {
    schema: &'static str,
    source_commit: String,
    corpus_sha256: &'static str,
    host: Host,
    configuration: Configuration,
    semantics: Semantics,
    overall: GroupSummary,
    summaries: Vec<GroupSummary>,
    rows: Vec<TimingRow>,
}

#[derive(Debug, Serialize)]
struct Host {
    os: String,
    arch: String,
    identifier: String,
}

#[derive(Debug, Serialize)]
struct Configuration {
    widths: String,
    topologies: Vec<&'static str>,
    outputs: Vec<&'static str>,
    outcomes: Vec<&'static str>,
    window_bytes: Vec<usize>,
    samples: usize,
    target_bytes_per_sample: usize,
    comparator: &'static str,
    candidate: &'static str,
}

#[derive(Debug, Serialize)]
struct Semantics {
    deterministic_cells_checked: usize,
    randomized_unseen_cases_checked: usize,
    mismatches: usize,
}

#[derive(Debug)]
struct Options {
    output: PathBuf,
    host: String,
    samples: usize,
    sample_bytes: usize,
    windows: Vec<usize>,
}

fn main() -> Result<(), DynError> {
    let options = options()?;
    let families = candidate_families();
    require(families.len() == 32 * 4, "candidate family count changed")?;
    validate_families(&families)?;

    let mut randomized_checked = 0;
    for (ordinal, family) in families.iter().enumerate() {
        let portable = portable_for(family.literal)?;
        for case in 0..RANDOM_SEMANTIC_CASES_PER_FAMILY {
            let seed = splitmix64(
                u64::try_from(ordinal)?
                    .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                    .wrapping_add(u64::try_from(case)?),
            );
            let minimum = family
                .width
                .checked_add(1)
                .ok_or("semantic width overflow")?;
            let span = usize::try_from(seed % 16_321)?
                .checked_add(minimum)
                .ok_or("semantic span overflow")?;
            let outcome = Outcome::ALL[usize::try_from((seed >> 32) % 3)?];
            let fixture = make_fixture(family.literal, span, outcome, seed)?;
            for output in Output::ALL {
                verify(family.entries[output.index()], output, &portable, &fixture)?;
                randomized_checked += 1;
            }
        }
    }

    let mut rows = Vec::with_capacity(
        families.len() * Output::ALL.len() * Outcome::ALL.len() * options.windows.len(),
    );
    let mut deterministic_checked = 0;
    for (ordinal, family) in families.iter().enumerate() {
        let portable = portable_for(family.literal)?;
        for &window_bytes in &options.windows {
            for outcome in Outcome::ALL {
                let seed = splitmix64(
                    u64::try_from(ordinal)?
                        .wrapping_mul(0xd6e8_feb8_6659_fd93)
                        .wrapping_add(u64::try_from(window_bytes)?)
                        .wrapping_add(outcome.ordinal()),
                );
                let fixture = make_fixture(family.literal, window_bytes, outcome, seed)?;
                for output in Output::ALL {
                    let entry = family.entries[output.index()];
                    verify(entry, output, &portable, &fixture)?;
                    deterministic_checked += 1;
                    rows.push(measure_cell(
                        family,
                        entry,
                        output,
                        outcome,
                        &portable,
                        &fixture,
                        options.samples,
                        options.sample_bytes,
                    )?);
                }
            }
        }
    }

    let overall = summarize("overall".to_owned(), &rows);
    let mut summaries = Vec::new();
    add_group_summaries(&mut summaries, &rows);
    let evidence = Evidence {
        schema: SCHEMA,
        source_commit: source_commit(),
        corpus_sha256: CORPUS_SHA256,
        host: Host {
            os: std::env::consts::OS.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
            identifier: options.host,
        },
        configuration: Configuration {
            widths: "1..=32".to_owned(),
            topologies: vec!["uniform", "periodic", "clustered", "phase-unique"],
            outputs: vec!["exists", "selected-end", "span"],
            outcomes: vec!["no-match", "early-match", "late-match"],
            window_bytes: options.windows,
            samples: options.samples,
            target_bytes_per_sample: options.sample_bytes,
            comparator: "current PortableRegex value API built from identical source",
            candidate: "statically linked V27/tag40 AAPCS64 machine image",
        },
        semantics: Semantics {
            deterministic_cells_checked: deterministic_checked,
            randomized_unseen_cases_checked: randomized_checked,
            mismatches: 0,
        },
        overall,
        summaries,
        rows,
    };
    let encoded = serde_json::to_vec_pretty(&evidence)?;
    fs::write(&options.output, encoded)?;
    print_summary(&evidence, &options.output);
    Ok(())
}

fn validate_families(families: &[CandidateFamily]) -> Result<(), DynError> {
    let mut seen = BTreeSet::new();
    for family in families {
        require(
            family.width == family.literal.len() && (1..=32).contains(&family.width),
            "candidate width changed",
        )?;
        require(
            seen.insert((family.width, family.topology)),
            "duplicate candidate family",
        )?;
        if family.width < 6 {
            require(
                family.graph == Graph::V8Fallback,
                "short V27 graph must use fallback",
            )?;
        }
    }
    Ok(())
}

fn portable_for(literal: &[u8]) -> Result<PortableRegex, DynError> {
    let source = canonical_exact_source(literal);
    let portable = PortableBuilder::new(&source).build()?;
    let candidate = portable
        .exact_literal_search_aot_candidate()
        .ok_or("source did not retain exact-literal plan")?;
    require(candidate.source() == source, "source identity changed")?;
    require(candidate.literal() == literal, "literal identity changed")?;
    Ok(portable)
}

fn make_fixture(
    literal: &[u8],
    window_bytes: usize,
    outcome: Outcome,
    salt: u64,
) -> Result<Fixture, DynError> {
    require(
        window_bytes >= literal.len(),
        "window is narrower than literal",
    )?;
    let window_start = WINDOW_START + usize::try_from(salt & 15)?;
    let window_end = window_start
        .checked_add(window_bytes)
        .ok_or("fixture window overflow")?;
    let extent = window_end
        .checked_add(literal.len())
        .and_then(|value| value.checked_add(64))
        .ok_or("fixture extent overflow")?;
    let avoid = (0_u8..=u8::MAX)
        .find(|byte| !literal.contains(byte))
        .ok_or("literal unexpectedly contains all byte values")?;
    let mut near_miss = literal.to_vec();
    let mismatch = usize::try_from((salt >> 8) % u64::try_from(literal.len())?)?;
    near_miss[mismatch] = avoid;
    let mut tile = near_miss;
    tile.push(avoid);
    let mut haystack = vec![avoid; extent];
    for (offset, byte) in haystack[window_start..window_end].iter_mut().enumerate() {
        *byte = tile[offset % tile.len()];
    }

    let selected_start = match outcome {
        Outcome::NoMatch => None,
        Outcome::EarlyMatch => Some(
            window_start
                .checked_add(literal.len())
                .and_then(|value| value.checked_add(17))
                .filter(|start| start.checked_add(literal.len()) <= Some(window_end))
                .unwrap_or(window_start),
        ),
        Outcome::LateMatch => Some(
            window_end
                .checked_sub(literal.len())
                .ok_or("late match underflow")?,
        ),
    };
    if let Some(start) = selected_start {
        let guard_start = start.saturating_sub(literal.len()).max(window_start);
        let end = start
            .checked_add(literal.len())
            .ok_or("match end overflow")?;
        let guard_end = end
            .checked_add(literal.len())
            .unwrap_or(haystack.len())
            .min(window_end);
        haystack[guard_start..guard_end].fill(avoid);
        haystack[start..end].copy_from_slice(literal);
    }
    let expected = scalar_find(&haystack, literal, window_start, window_end);
    match outcome {
        Outcome::NoMatch => require(expected.is_none(), "no-match fixture contains a match")?,
        Outcome::EarlyMatch | Outcome::LateMatch => require(
            expected.map(|value| value.0) == selected_start,
            "fixture selected match moved",
        )?,
    }
    Ok(Fixture {
        haystack,
        window: SearchWindow::new(window_start, window_end),
        expected,
    })
}

fn scalar_find(
    haystack: &[u8],
    literal: &[u8],
    start: usize,
    end: usize,
) -> Option<(usize, usize)> {
    haystack[start..end]
        .windows(literal.len())
        .position(|candidate| candidate == literal)
        .map(|offset| {
            let match_start = start + offset;
            (match_start, match_start + literal.len())
        })
}

fn verify(
    entry: EntryFunction,
    output: Output,
    portable: &PortableRegex,
    fixture: &Fixture,
) -> Result<(), DynError> {
    let expected = project_expected(output, fixture.expected);
    let native = call_native(entry, output, &fixture.haystack, fixture.window);
    let portable = call_portable(portable, output, &fixture.haystack, fixture.window)?;
    if native != expected {
        return Err(format!(
            "native result disagrees with scalar oracle: output={output:?} window={}..{} expected={expected:#x} actual={native:#x} scalar={:?}",
            fixture.window.start(),
            fixture.window.end(),
            fixture.expected
        )
        .into());
    }
    if portable != expected {
        return Err(format!(
            "portable result disagrees with scalar oracle: output={output:?} window={}..{} expected={expected:#x} actual={portable:#x} scalar={:?}",
            fixture.window.start(),
            fixture.window.end(),
            fixture.expected
        )
        .into());
    }
    Ok(())
}

fn project_expected(output: Output, found: Option<(usize, usize)>) -> u64 {
    match output {
        Output::Exists => u64::from(found.is_some()),
        Output::SelectedEnd => found.map_or(u64::MAX, |(_, end)| usize_u64(end)),
        Output::Span => found.map_or(u64::MAX, |(start, end)| {
            usize_u64(start).rotate_left(29) ^ usize_u64(end)
        }),
    }
}

#[inline]
fn call_native(entry: EntryFunction, output: Output, haystack: &[u8], window: SearchWindow) -> u64 {
    let mut slot = NativeResult {
        start: usize::MAX,
        end: usize::MAX,
    };
    // SAFETY: build.rs independently audits each exact V27 image before
    // packaging it into this process's executable text. The typed descriptor
    // retains the matching output contract; all five AAPCS64 arguments remain
    // live and correctly aligned for the complete leaf call.
    let status = unsafe {
        entry(
            haystack.as_ptr(),
            haystack.len(),
            window.start(),
            window.end(),
            &raw mut slot,
        )
    };
    match (status, output) {
        (0, Output::Exists) => 0,
        (0, Output::SelectedEnd | Output::Span) => u64::MAX,
        (1, Output::Exists) => 1,
        (1, Output::SelectedEnd) => usize_u64(slot.end),
        (1, Output::Span) => usize_u64(slot.start).rotate_left(29) ^ usize_u64(slot.end),
        _ => u64::MAX - 1,
    }
}

#[inline]
fn call_portable(
    portable: &PortableRegex,
    output: Output,
    haystack: &[u8],
    window: SearchWindow,
) -> Result<u64, DynError> {
    Ok(match output {
        Output::Exists => u64::from(portable.is_match_window_value(
            haystack,
            window,
            SearchLimits::unlimited(),
        )?),
        Output::SelectedEnd => portable
            .find_window_value(haystack, window, SearchLimits::unlimited())?
            .map_or(u64::MAX, |matched| usize_u64(matched.end())),
        Output::Span => portable
            .find_window_value(haystack, window, SearchLimits::unlimited())?
            .map_or(u64::MAX, |matched| {
                usize_u64(matched.start()).rotate_left(29) ^ usize_u64(matched.end())
            }),
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "each timing coordinate is carried explicitly into its evidence row"
)]
fn measure_cell(
    family: &CandidateFamily,
    entry: EntryFunction,
    output: Output,
    outcome: Outcome,
    portable: &PortableRegex,
    fixture: &Fixture,
    samples: usize,
    sample_bytes: usize,
) -> Result<TimingRow, DynError> {
    let window_bytes = fixture
        .window
        .end()
        .checked_sub(fixture.window.start())
        .ok_or("window underflow")?;
    let iterations = if outcome == Outcome::EarlyMatch {
        sample_bytes
            .checked_div(64)
            .unwrap_or(1)
            .clamp(16_384, 1_048_576)
    } else {
        sample_bytes.checked_div(window_bytes).unwrap_or(1).max(4)
    };
    for _ in 0..3 {
        black_box(call_native(
            entry,
            output,
            &fixture.haystack,
            fixture.window,
        ));
        black_box(call_portable(
            portable,
            output,
            &fixture.haystack,
            fixture.window,
        )?);
    }

    let mut native_samples = Vec::with_capacity(samples);
    let mut portable_samples = Vec::with_capacity(samples);
    let mut checksum = CHECKSUM_SEED;
    for sample in 0..samples {
        if sample % 2 == 0 {
            let (native, native_checksum) = time_native(entry, output, fixture, iterations);
            let (portable_elapsed, portable_checksum) =
                time_portable(portable, output, fixture, iterations)?;
            native_samples.push(native);
            portable_samples.push(portable_elapsed);
            checksum ^= native_checksum.rotate_left(7) ^ portable_checksum.rotate_left(23);
        } else {
            let (portable_elapsed, portable_checksum) =
                time_portable(portable, output, fixture, iterations)?;
            let (native, native_checksum) = time_native(entry, output, fixture, iterations);
            portable_samples.push(portable_elapsed);
            native_samples.push(native);
            checksum ^= native_checksum.rotate_left(11) ^ portable_checksum.rotate_left(31);
        }
    }
    let iterations_f64 = f64::from(u32::try_from(iterations).expect("bounded iterations"));
    let native_ns = median_duration(&mut native_samples).as_secs_f64() * 1e9 / iterations_f64;
    let portable_ns = median_duration(&mut portable_samples).as_secs_f64() * 1e9 / iterations_f64;
    let gib = f64::from(u32::try_from(window_bytes).expect("bounded evidence window"))
        / (1024.0 * 1024.0 * 1024.0);
    Ok(TimingRow {
        width: family.width,
        topology: family.topology,
        graph: family.graph,
        output,
        outcome,
        window_bytes,
        iterations,
        native_ns_per_call: native_ns,
        portable_ns_per_call: portable_ns,
        portable_over_native: portable_ns / native_ns,
        native_gib_per_second: gib / (native_ns / 1e9),
        portable_gib_per_second: gib / (portable_ns / 1e9),
        checksum,
    })
}

fn time_native(
    entry: EntryFunction,
    output: Output,
    fixture: &Fixture,
    iterations: usize,
) -> (Duration, u64) {
    let mut checksum = CHECKSUM_SEED;
    let started = Instant::now();
    for iteration in 0..iterations {
        let value = call_native(
            black_box(entry),
            output,
            black_box(&fixture.haystack),
            black_box(fixture.window),
        );
        checksum = checksum.rotate_left(5) ^ value ^ u64::try_from(iteration).unwrap_or(u64::MAX);
    }
    let elapsed = started.elapsed();
    black_box(checksum);
    (elapsed, checksum)
}

fn time_portable(
    portable: &PortableRegex,
    output: Output,
    fixture: &Fixture,
    iterations: usize,
) -> Result<(Duration, u64), DynError> {
    let mut checksum = CHECKSUM_SEED;
    let started = Instant::now();
    for iteration in 0..iterations {
        let value = call_portable(
            black_box(portable),
            output,
            black_box(&fixture.haystack),
            black_box(fixture.window),
        )?;
        checksum = checksum.rotate_left(5) ^ value ^ u64::try_from(iteration).unwrap_or(u64::MAX);
    }
    let elapsed = started.elapsed();
    black_box(checksum);
    Ok((elapsed, checksum))
}

fn median_duration(samples: &mut [Duration]) -> Duration {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

fn add_group_summaries(summaries: &mut Vec<GroupSummary>, rows: &[TimingRow]) {
    for output in Output::ALL {
        let selected = rows
            .iter()
            .filter(|row| row.output == output)
            .cloned()
            .collect::<Vec<_>>();
        summaries.push(summarize(format!("output={}", output.name()), &selected));
    }
    for topology in [
        Topology::Uniform,
        Topology::Periodic,
        Topology::Clustered,
        Topology::PhaseUnique,
    ] {
        let selected = rows
            .iter()
            .filter(|row| row.topology == topology)
            .cloned()
            .collect::<Vec<_>>();
        summaries.push(summarize(
            format!("topology={}", topology.name()),
            &selected,
        ));
    }
    for graph in [Graph::V8Fallback, Graph::V17Fast, Graph::V25Fast] {
        let selected = rows
            .iter()
            .filter(|row| row.graph == graph)
            .cloned()
            .collect::<Vec<_>>();
        summaries.push(summarize(format!("graph={}", graph.name()), &selected));
    }
    for outcome in Outcome::ALL {
        let selected = rows
            .iter()
            .filter(|row| row.outcome == outcome)
            .cloned()
            .collect::<Vec<_>>();
        summaries.push(summarize(format!("outcome={}", outcome.name()), &selected));
    }
    let width_bands = [(1, 5), (6, 8), (9, 16), (17, 32)];
    for (minimum, maximum) in width_bands {
        let selected = rows
            .iter()
            .filter(|row| (minimum..=maximum).contains(&row.width))
            .cloned()
            .collect::<Vec<_>>();
        summaries.push(summarize(format!("width={minimum}..={maximum}"), &selected));
    }
    let mut windows = rows.iter().map(|row| row.window_bytes).collect::<Vec<_>>();
    windows.sort_unstable();
    windows.dedup();
    for window in windows {
        let selected = rows
            .iter()
            .filter(|row| row.window_bytes == window)
            .cloned()
            .collect::<Vec<_>>();
        summaries.push(summarize(format!("window={window}"), &selected));
    }
}

fn summarize(group: String, rows: &[TimingRow]) -> GroupSummary {
    let mut ratios = rows
        .iter()
        .map(|row| row.portable_over_native)
        .collect::<Vec<_>>();
    ratios.sort_by(f64::total_cmp);
    let logarithmic_sum = ratios.iter().map(|ratio| ratio.ln()).sum::<f64>();
    GroupSummary {
        group,
        cells: ratios.len(),
        geomean_portable_over_native: (logarithmic_sum
            / f64::from(u32::try_from(ratios.len()).expect("bounded evidence rows")))
        .exp(),
        p05_portable_over_native: percentile(&ratios, 5),
        median_portable_over_native: percentile(&ratios, 50),
        p95_portable_over_native: percentile(&ratios, 95),
        cells_over_1_20: ratios.iter().filter(|ratio| **ratio >= 1.2).count(),
        cells_below_1_00: ratios.iter().filter(|ratio| **ratio < 1.0).count(),
    }
}

fn percentile(sorted: &[f64], percentile: usize) -> f64 {
    let index = sorted
        .len()
        .saturating_sub(1)
        .checked_mul(percentile)
        .unwrap_or(0)
        / 100;
    sorted[index]
}

fn print_summary(evidence: &Evidence, output: &Path) {
    println!(
        "semantics: deterministic={} randomized={} mismatches={}",
        evidence.semantics.deterministic_cells_checked,
        evidence.semantics.randomized_unseen_cases_checked,
        evidence.semantics.mismatches
    );
    println!(
        "overall: cells={} geomean={:.3}x p05={:.3}x median={:.3}x p95={:.3}x >=1.20x={}/{} regressions={}",
        evidence.overall.cells,
        evidence.overall.geomean_portable_over_native,
        evidence.overall.p05_portable_over_native,
        evidence.overall.median_portable_over_native,
        evidence.overall.p95_portable_over_native,
        evidence.overall.cells_over_1_20,
        evidence.overall.cells,
        evidence.overall.cells_below_1_00,
    );
    for summary in &evidence.summaries {
        println!(
            "{}: cells={} geomean={:.3}x p05={:.3}x >=1.20x={}/{} regressions={}",
            summary.group,
            summary.cells,
            summary.geomean_portable_over_native,
            summary.p05_portable_over_native,
            summary.cells_over_1_20,
            summary.cells,
            summary.cells_below_1_00,
        );
    }
    println!("wrote {}", output.display());
}

fn options() -> Result<Options, DynError> {
    let mut output = None;
    let mut host = None;
    let mut samples = DEFAULT_SAMPLES;
    let mut sample_bytes = DEFAULT_SAMPLE_BYTES;
    let mut windows = DEFAULT_WINDOW_BYTES.to_vec();
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--output" => output = arguments.next().map(PathBuf::from),
            "--host" => host = arguments.next(),
            "--samples" => {
                samples = arguments.next().ok_or("missing --samples value")?.parse()?;
            }
            "--sample-bytes" => {
                sample_bytes = arguments
                    .next()
                    .ok_or("missing --sample-bytes value")?
                    .parse()?;
            }
            "--windows" => {
                windows = arguments
                    .next()
                    .ok_or("missing --windows value")?
                    .split(',')
                    .map(str::parse)
                    .collect::<Result<Vec<_>, _>>()?;
            }
            _ => return Err(format!("unknown argument: {argument}").into()),
        }
    }
    require(
        samples >= 3 && samples % 2 == 1,
        "samples must be odd and >= 3",
    )?;
    require(
        sample_bytes >= 1 << 20,
        "sample bytes must be at least 1 MiB",
    )?;
    require(
        !windows.is_empty() && windows.iter().all(|window| *window >= 65_536),
        "all timing windows must be at least 64 KiB",
    )?;
    Ok(Options {
        output: output.ok_or("--output PATH is required")?,
        host: host.unwrap_or_else(|| "unspecified-aarch64-host".to_owned()),
        samples,
        sample_bytes,
        windows,
    })
}

fn canonical_exact_source(literal: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut source = String::with_capacity(6 + literal.len() * 4);
    source.push_str("(?-u:");
    for byte in literal {
        write!(source, "\\x{byte:02x}").expect("source byte");
    }
    source.push(')');
    source
}

fn source_commit() -> String {
    option_env!("FRE_SOURCE_COMMIT")
        .unwrap_or("0cc270a46122d905d0f652c737f7413c8b696fa6")
        .to_owned()
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn usize_u64(value: usize) -> u64 {
    u64::try_from(value).expect("AArch64 usize always fits u64")
}

fn require(condition: bool, message: &str) -> Result<(), DynError> {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned().into())
    }
}
