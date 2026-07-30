use std::{
    error::Error,
    hint::black_box,
    io::{self, BufWriter, Write as _},
    time::Instant,
};

use fre_jit_aarch64::{EmitLimits, SearchBackendPolicy, emit_audited_with_backend};
use fre_jit_runtime::{PublicationLimits, PublishedKernelThreadSession, publish_audited};
use fre_kernel_ir::{
    AnchorFlags, CheckedSearchWindow, MatchSpan, SearchWindow as NativeWindow, Span,
    ValidateLimits, build_exact_literal,
};
use fre_kernels::{
    LiteralBuildLimits, LiteralPlan, LiteralSearchLimits, Window as PortableWindow,
    preflight_checked_literal_window,
};

type DynError = Box<dyn Error>;

const SCREEN_SEEDS: [u64; 2] = [0xa551_0001_7e23_914d, 0xf117_0002_3c84_d6a9];
const HELDOUT_SEEDS: [u64; 2] = [0x8d19_74b2_c63e_50af, 0xd3a5_2f91_6c48_b7e0];
const WIDTHS: [usize; 11] = [1, 2, 3, 4, 5, 6, 8, 12, 16, 24, 32];
const SCREEN_SIZES: [usize; 7] = [257, 1_021, 4_093, 16_381, 65_521, 262_139, 1_048_573];
const HELDOUT_SIZES: [usize; 3] = [4_093, 65_521, 1_048_573];
const SCREEN_ALIGNMENTS: [u8; 4] = [0, 1, 7, 15];
const HELDOUT_ALIGNMENTS: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const HEADER: &str = "schema,phase,seed,width,shape,size,scenario,alignment,window_start,window_end,repetition,order,engine,iterations,total_ns,ns_per_iter,checksum,semantic";
const SCHEMA: &str = "fre-search-v8-broad-deploy-v1";
const CHECKSUM_SEED: u64 = 0x243f_6a88_85a3_08d3;
const MAX_CALIBRATION_ITERATIONS: usize = 1 << 30;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Screen,
    Heldout,
    Confirm,
}

impl Phase {
    fn parse(value: &str) -> Result<Self, DynError> {
        match value {
            "screen" => Ok(Self::Screen),
            "heldout" => Ok(Self::Heldout),
            "confirm" => Ok(Self::Confirm),
            _ => Err(invalid("PHASE must be screen, heldout, or confirm").into()),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Screen => "screen",
            Self::Heldout => "heldout",
            Self::Confirm => "confirm",
        }
    }

    const fn seeds(self) -> &'static [u64] {
        match self {
            Self::Screen => &SCREEN_SEEDS,
            Self::Heldout | Self::Confirm => &HELDOUT_SEEDS,
        }
    }

    const fn sizes(self) -> &'static [usize] {
        match self {
            Self::Screen => &SCREEN_SIZES,
            Self::Heldout | Self::Confirm => &HELDOUT_SIZES,
        }
    }

    const fn alignments(self) -> &'static [u8] {
        match self {
            Self::Screen => &SCREEN_ALIGNMENTS,
            Self::Heldout | Self::Confirm => &HELDOUT_ALIGNMENTS,
        }
    }

    const fn repetitions(self) -> usize {
        match self {
            Self::Screen => 3,
            Self::Heldout => 7,
            Self::Confirm => 12,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Shape {
    Entropy,
    Repeated,
    Periodic,
    Binary,
}

impl Shape {
    const ALL: [Self; 4] = [Self::Entropy, Self::Repeated, Self::Periodic, Self::Binary];

    const fn name(self) -> &'static str {
        match self {
            Self::Entropy => "entropy",
            Self::Repeated => "repeated",
            Self::Periodic => "periodic",
            Self::Binary => "binary",
        }
    }

    const fn tag(self) -> u64 {
        match self {
            Self::Entropy => 0x13,
            Self::Repeated => 0x29,
            Self::Periodic => 0x47,
            Self::Binary => 0x71,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scenario {
    AbsentEntropy,
    AbsentFiller,
    Early,
    Middle,
    Tail,
    Dense,
    FirstByteDenseAbsent,
    NearMissTail,
    BinaryTail,
    WindowAbsent,
    WindowTail,
    AlignmentTail(u8),
}

impl Scenario {
    const BASE: [Self; 11] = [
        Self::AbsentEntropy,
        Self::AbsentFiller,
        Self::Early,
        Self::Middle,
        Self::Tail,
        Self::Dense,
        Self::FirstByteDenseAbsent,
        Self::NearMissTail,
        Self::BinaryTail,
        Self::WindowAbsent,
        Self::WindowTail,
    ];

    fn name(self) -> String {
        match self {
            Self::AbsentEntropy => "absent-entropy".to_owned(),
            Self::AbsentFiller => "absent-filler".to_owned(),
            Self::Early => "early".to_owned(),
            Self::Middle => "middle".to_owned(),
            Self::Tail => "tail".to_owned(),
            Self::Dense => "dense".to_owned(),
            Self::FirstByteDenseAbsent => "first-byte-dense-absent".to_owned(),
            Self::NearMissTail => "near-miss-tail".to_owned(),
            Self::BinaryTail => "binary-tail".to_owned(),
            Self::WindowAbsent => "window-absent".to_owned(),
            Self::WindowTail => "window-tail".to_owned(),
            Self::AlignmentTail(residue) => format!("alignment-tail-{residue}"),
        }
    }

    const fn tag(self) -> u64 {
        match self {
            Self::AbsentEntropy => 0x101,
            Self::AbsentFiller => 0x103,
            Self::Early => 0x107,
            Self::Middle => 0x10d,
            Self::Tail => 0x11f,
            Self::Dense => 0x137,
            Self::FirstByteDenseAbsent => 0x151,
            Self::NearMissTail => 0x16d,
            Self::BinaryTail => 0x181,
            Self::WindowAbsent => 0x1a7,
            Self::WindowTail => 0x1c3,
            Self::AlignmentTail(residue) => 0x200 + residue as u64,
        }
    }

    const fn alignment(self) -> u8 {
        match self {
            Self::AlignmentTail(residue) => residue,
            _ => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Engine {
    Native,
    Portable,
}

impl Engine {
    const fn name(self) -> &'static str {
        match self {
            Self::Native => "native-v8-aot-code",
            Self::Portable => "portable-memmem",
        }
    }
}

#[derive(Debug)]
struct Fixture {
    storage: Vec<u8>,
    start: usize,
    len: usize,
    window_start: usize,
    window_end: usize,
}

impl Fixture {
    fn bytes(&self) -> &[u8] {
        &self.storage[self.start..self.start + self.len]
    }
}

#[derive(Clone, Copy, Debug)]
struct Measurement {
    total_ns: u64,
    checksum: u64,
    semantic: u64,
}

fn main() -> Result<(), DynError> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let [phase, shard, shards, target_ms] = arguments.as_slice() else {
        return Err(invalid("usage: PHASE SHARD SHARDS TARGET_MILLISECONDS").into());
    };
    let phase = Phase::parse(phase)?;
    let shard = canonical_usize(shard, "SHARD")?;
    let shards = canonical_usize(shards, "SHARDS")?;
    let target_ms = canonical_usize(target_ms, "TARGET_MILLISECONDS")?;
    require(
        shards > 0 && shard < shards,
        "SHARD must be less than nonzero SHARDS",
    )?;
    require(
        (1..=1_000).contains(&target_ms),
        "target milliseconds outside 1..=1000",
    )?;
    let target_ns = u64::try_from(target_ms)?
        .checked_mul(1_000_000)
        .ok_or_else(|| invalid("target nanoseconds overflow"))?;

    let stdout = io::stdout();
    let mut output = BufWriter::new(stdout.lock());
    writeln!(output, "{HEADER}")?;
    let mut ordinal = 0_usize;
    for &seed in phase.seeds() {
        for &width in &WIDTHS {
            for shape in Shape::ALL {
                let literal = make_literal(seed, width, shape);
                for &size in phase.sizes() {
                    for scenario in scenarios(phase) {
                        let selected = ordinal % shards == shard;
                        ordinal = ordinal
                            .checked_add(1)
                            .ok_or_else(|| invalid("case ordinal overflow"))?;
                        if !selected {
                            continue;
                        }
                        run_case(
                            &mut output,
                            phase,
                            seed,
                            shape,
                            size,
                            scenario,
                            &literal,
                            target_ns,
                        )?;
                    }
                }
            }
        }
    }
    output.flush()?;
    Ok(())
}

fn scenarios(phase: Phase) -> Vec<Scenario> {
    let mut scenarios = Vec::with_capacity(Scenario::BASE.len() + phase.alignments().len());
    scenarios.extend_from_slice(&Scenario::BASE);
    scenarios.extend(
        phase
            .alignments()
            .iter()
            .copied()
            .map(Scenario::AlignmentTail),
    );
    scenarios
}

#[allow(clippy::too_many_arguments)]
fn run_case(
    output: &mut impl io::Write,
    phase: Phase,
    seed: u64,
    shape: Shape,
    size: usize,
    scenario: Scenario,
    literal: &[u8],
    target_ns: u64,
) -> Result<(), DynError> {
    let fixture = make_fixture(seed, size, scenario, literal)?;
    let bytes = fixture.bytes();
    let portable_window = PortableWindow::new(fixture.window_start, fixture.window_end);
    let native_window = NativeWindow::new(fixture.window_start, fixture.window_end);
    let portable = LiteralPlan::new(literal, LiteralBuildLimits::default())?;
    let program =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())?;
    let image = emit_audited_with_backend(
        &program,
        SearchBackendPolicy::AsimdV8,
        EmitLimits::default(),
    )?;
    let kernel = publish_audited::<Span>(&image, PublicationLimits::default())?;
    let session = kernel.begin_current_thread_session()?;

    let expected = encode_portable(
        portable
            .find_window(bytes, portable_window, LiteralSearchLimits::unlimited())?
            .0,
    );
    let actual = invoke_native(&session, bytes, native_window, literal.len())?;
    require(
        expected == actual,
        "native/portable semantic mismatch before timing",
    )?;

    for _ in 0..3 {
        black_box(invoke_portable(&portable, bytes, portable_window)?);
        black_box(invoke_native(
            &session,
            bytes,
            native_window,
            literal.len(),
        )?);
    }
    let iterations = calibrate(
        &portable,
        &session,
        bytes,
        portable_window,
        native_window,
        literal.len(),
        target_ns,
        expected,
    )?;
    let scenario_name = scenario.name();
    for repetition in 0..phase.repetitions() {
        let order = if repetition % 2 == 0 {
            [Engine::Native, Engine::Portable]
        } else {
            [Engine::Portable, Engine::Native]
        };
        let order_name = format!("{}+{}", order[0].name(), order[1].name());
        for engine in order {
            let measurement = match engine {
                Engine::Native => measure(iterations, expected, || {
                    invoke_native(&session, bytes, native_window, literal.len())
                })?,
                Engine::Portable => measure(iterations, expected, || {
                    invoke_portable(&portable, bytes, portable_window)
                })?,
            };
            let ns_per_iter = measurement.total_ns as f64 / iterations as f64;
            writeln!(
                output,
                "{SCHEMA},{},{seed:016x},{},{},{size},{scenario_name},{},{},{},{repetition},{order_name},{},{iterations},{},{ns_per_iter:.6},{:016x},{:016x}",
                phase.name(),
                literal.len(),
                shape.name(),
                scenario.alignment(),
                fixture.window_start,
                fixture.window_end,
                engine.name(),
                measurement.total_ns,
                measurement.checksum,
                measurement.semantic,
            )?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn calibrate(
    portable: &LiteralPlan,
    session: &PublishedKernelThreadSession<'_, Span>,
    haystack: &[u8],
    portable_window: PortableWindow,
    native_window: NativeWindow,
    literal_bytes: usize,
    target_ns: u64,
    expected: u64,
) -> Result<usize, DynError> {
    let mut iterations = 1_usize;
    loop {
        let native = measure(iterations, expected, || {
            invoke_native(session, haystack, native_window, literal_bytes)
        })?;
        let portable_measurement = measure(iterations, expected, || {
            invoke_portable(portable, haystack, portable_window)
        })?;
        let faster_ns = native.total_ns.min(portable_measurement.total_ns).max(1);
        if faster_ns >= target_ns / 4 || iterations == MAX_CALIBRATION_ITERATIONS {
            let scale = target_ns
                .checked_add(faster_ns - 1)
                .ok_or_else(|| invalid("calibration rounding overflow"))?
                / faster_ns;
            let scale = usize::try_from(scale.max(1))?;
            return Ok(iterations
                .checked_mul(scale)
                .unwrap_or(MAX_CALIBRATION_ITERATIONS)
                .min(MAX_CALIBRATION_ITERATIONS));
        }
        iterations = iterations
            .checked_mul(8)
            .unwrap_or(MAX_CALIBRATION_ITERATIONS)
            .min(MAX_CALIBRATION_ITERATIONS);
    }
}

fn measure(
    iterations: usize,
    expected: u64,
    mut invoke: impl FnMut() -> Result<u64, DynError>,
) -> Result<Measurement, DynError> {
    let started = Instant::now();
    let mut checksum = CHECKSUM_SEED;
    let mut semantic = u64::MAX;
    for ordinal in 0..iterations {
        semantic = black_box(invoke()?);
        require(semantic == expected, "timed semantic mismatch")?;
        checksum = fold_checksum(checksum, ordinal, semantic);
    }
    let total_ns = u64::try_from(started.elapsed().as_nanos())?;
    Ok(Measurement {
        total_ns,
        checksum: black_box(checksum),
        semantic,
    })
}

fn invoke_native(
    session: &PublishedKernelThreadSession<'_, Span>,
    haystack: &[u8],
    window: NativeWindow,
    literal_bytes: usize,
) -> Result<u64, DynError> {
    let checked = CheckedSearchWindow::new(black_box(haystack), window)
        .ok_or_else(|| invalid("native window rejected"))?;
    preflight_checked_literal_window(literal_bytes, checked, LiteralSearchLimits::unlimited())?;
    Ok(encode_native(session.search_checked(checked)?))
}

fn invoke_portable(
    portable: &LiteralPlan,
    haystack: &[u8],
    window: PortableWindow,
) -> Result<u64, DynError> {
    Ok(encode_portable(
        portable
            .find_window(
                black_box(haystack),
                window,
                LiteralSearchLimits::unlimited(),
            )?
            .0,
    ))
}

fn encode_native(matched: Option<MatchSpan>) -> u64 {
    matched.map_or(0, |span| encode_span(span.start(), span.end()))
}

fn encode_portable(matched: Option<(usize, usize)>) -> u64 {
    matched.map_or(0, |(start, end)| encode_span(start, end))
}

fn encode_span(start: usize, end: usize) -> u64 {
    let start = u64::try_from(start).expect("benchmark span start fits u64");
    let end = u64::try_from(end).expect("benchmark span end fits u64");
    start.rotate_left(17) ^ end.rotate_left(41) ^ 1
}

fn fold_checksum(checksum: u64, ordinal: usize, semantic: u64) -> u64 {
    let ordinal = u64::try_from(ordinal).expect("benchmark ordinal fits u64");
    (checksum ^ semantic ^ ordinal.wrapping_mul(0x9e37_79b9_7f4a_7c15))
        .rotate_left(13)
        .wrapping_mul(0xbf58_476d_1ce4_e5b9)
        .wrapping_add(0x94d0_49bb_1331_11eb)
}

fn make_literal(seed: u64, width: usize, shape: Shape) -> Vec<u8> {
    let mut state = seed ^ shape.tag().wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let mut literal = Vec::with_capacity(width);
    for index in 0..width {
        let byte = match shape {
            Shape::Entropy => splitmix64(&mut state).to_le_bytes()[index & 7],
            Shape::Repeated => (seed ^ 0x5a).to_le_bytes()[0],
            Shape::Periodic => {
                let pair = [
                    (seed ^ 0x35).to_le_bytes()[0],
                    (seed ^ 0xc7).to_le_bytes()[1],
                ];
                pair[index & 1]
            }
            Shape::Binary => {
                const BINARY: [u8; 8] = [0x00, 0xff, 0x80, 0x7f, 0x01, 0xfe, 0x55, 0xaa];
                BINARY[(index + usize::from(seed.to_le_bytes()[0] & 7)) & 7]
            }
        };
        literal.push(byte);
    }
    literal
}

fn make_fixture(
    seed: u64,
    len: usize,
    scenario: Scenario,
    literal: &[u8],
) -> Result<Fixture, DynError> {
    require(
        !literal.is_empty() && literal.len() <= len,
        "invalid fixture literal width",
    )?;
    let mut storage = vec![
        0_u8;
        len.checked_add(64)
            .ok_or_else(|| invalid("fixture extent"))?
    ];
    let base = storage.as_ptr().addr() & 15;
    let alignment = usize::from(scenario.alignment());
    let start = alignment.wrapping_add(16).wrapping_sub(base) & 15;
    let haystack = &mut storage[start..start + len];
    let avoid = (0_u16..=255)
        .map(|value| u8::try_from(value).expect("bounded byte"))
        .find(|byte| !literal.contains(byte))
        .ok_or_else(|| invalid("literal unexpectedly contains every byte"))?;
    let maximum = len - literal.len();
    let mut window_start = 0_usize;
    let mut window_end = len;
    let mut state = seed
        ^ u64::try_from(len)?
        ^ scenario.tag().wrapping_mul(0xd6e8_feb8_6659_fd93)
        ^ u64::try_from(literal.len())?.rotate_left(29);

    match scenario {
        Scenario::AbsentEntropy => {
            fill_entropy(haystack, &mut state);
            scrub_matches(haystack, 0, len, literal, avoid);
        }
        Scenario::AbsentFiller => haystack.fill(avoid),
        Scenario::Early => {
            haystack.fill(avoid);
            install_literal(haystack, maximum.min(64), literal)?;
        }
        Scenario::Middle => {
            haystack.fill(avoid);
            install_literal(haystack, maximum / 2, literal)?;
        }
        Scenario::Tail | Scenario::AlignmentTail(_) => {
            haystack.fill(avoid);
            install_literal(haystack, maximum, literal)?;
        }
        Scenario::Dense => {
            for (index, byte) in haystack.iter_mut().enumerate() {
                *byte = literal[index % literal.len()];
            }
        }
        Scenario::FirstByteDenseAbsent => {
            if literal.iter().all(|byte| *byte == literal[0]) {
                haystack.fill(avoid);
            } else {
                haystack.fill(literal[0]);
                scrub_matches(haystack, 0, len, literal, avoid);
            }
        }
        Scenario::NearMissTail => {
            haystack.fill(avoid);
            if literal.len() > 1 {
                for chunk in haystack.chunks_exact_mut(literal.len()) {
                    chunk.copy_from_slice(literal);
                    chunk[literal.len() - 1] = avoid;
                }
            }
            scrub_matches(haystack, 0, len, literal, avoid);
            clear_around(haystack, maximum, literal.len(), avoid);
            install_literal(haystack, maximum, literal)?;
        }
        Scenario::BinaryTail => {
            for (index, byte) in haystack.iter_mut().enumerate() {
                *byte = index.to_le_bytes()[0].wrapping_add(state.to_le_bytes()[0]);
            }
            scrub_matches(haystack, 0, len, literal, avoid);
            clear_around(haystack, maximum, literal.len(), avoid);
            install_literal(haystack, maximum, literal)?;
        }
        Scenario::WindowAbsent | Scenario::WindowTail => {
            window_start = 37.min(maximum);
            window_end = len.saturating_sub(23).max(window_start + literal.len());
            window_end = window_end.min(len);
            haystack.fill(avoid);
            if window_start >= literal.len() {
                install_literal(haystack, 0, literal)?;
            }
            if window_end + literal.len() <= len {
                install_literal(haystack, window_end, literal)?;
            }
            if scenario == Scenario::WindowTail {
                install_literal(haystack, window_end - literal.len(), literal)?;
            }
        }
    }

    let portable = LiteralPlan::new(literal, LiteralBuildLimits::default())?;
    let found = portable
        .find_window(
            haystack,
            PortableWindow::new(window_start, window_end),
            LiteralSearchLimits::unlimited(),
        )?
        .0;
    match scenario {
        Scenario::AbsentEntropy
        | Scenario::AbsentFiller
        | Scenario::FirstByteDenseAbsent
        | Scenario::WindowAbsent => {
            require(found.is_none(), "intended-absent fixture contains a match")?;
        }
        _ => require(found.is_some(), "intended-hit fixture contains no match")?,
    }
    require(
        haystack.as_ptr().addr() & 15 == alignment,
        "fixture alignment mismatch",
    )?;
    Ok(Fixture {
        storage,
        start,
        len,
        window_start,
        window_end,
    })
}

fn fill_entropy(bytes: &mut [u8], state: &mut u64) {
    for chunk in bytes.chunks_mut(8) {
        let random = splitmix64(state).to_le_bytes();
        chunk.copy_from_slice(&random[..chunk.len()]);
    }
}

fn scrub_matches(bytes: &mut [u8], start: usize, end: usize, literal: &[u8], avoid: u8) {
    if end - start < literal.len() {
        return;
    }
    let mut candidate = start;
    while candidate + literal.len() <= end {
        if bytes[candidate..candidate + literal.len()] == *literal {
            bytes[candidate + literal.len() - 1] = avoid;
        }
        candidate += 1;
    }
}

fn clear_around(bytes: &mut [u8], start: usize, width: usize, value: u8) {
    let clear_start = start.saturating_sub(width);
    let clear_end = start
        .checked_add(width.saturating_mul(2))
        .unwrap_or(bytes.len())
        .min(bytes.len());
    bytes[clear_start..clear_end].fill(value);
}

fn install_literal(bytes: &mut [u8], start: usize, literal: &[u8]) -> Result<(), DynError> {
    let end = start
        .checked_add(literal.len())
        .ok_or_else(|| invalid("literal placement overflow"))?;
    bytes
        .get_mut(start..end)
        .ok_or_else(|| invalid("literal placement outside fixture"))?
        .copy_from_slice(literal);
    Ok(())
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn canonical_usize(value: &str, label: &str) -> Result<usize, DynError> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| invalid(format!("{label} is not canonical decimal")))?;
    require(
        parsed.to_string() == value,
        format!("{label} is not canonical decimal"),
    )?;
    Ok(parsed)
}

fn require(condition: bool, message: impl Into<String>) -> Result<(), DynError> {
    if condition {
        Ok(())
    } else {
        Err(invalid(message).into())
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
