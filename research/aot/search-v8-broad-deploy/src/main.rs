use std::{
    error::Error,
    hint::black_box,
    io::{self, BufWriter, Write as _},
    time::Instant,
};

use fre_jit_aarch64::{
    DecodedInstruction, EmitLimits, SearchBackendPolicy, decode, emit_audited_with_backend,
};
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

const SCREEN_SEEDS: [u64; 4] = [
    0xa551_0001_7e23_914d,
    0xf117_0002_3c84_d6a9,
    0x6b47_3a9d_e120_85cf,
    0xc2e9_5714_8ab6_3d01,
];
const WIDTHS: [usize; 32] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32,
];
const SCREEN_SIZES: [usize; 7] = [257, 1_021, 4_093, 16_381, 65_521, 262_139, 1_048_573];
const SCREEN_ALIGNMENTS: [u8; 4] = [0, 1, 7, 15];
const HEADER: &str = "schema,phase,seed,width,shape,size,scenario,alignment,window_start,window_end,repetition,order,engine,iterations,total_ns,ns_per_iter,checksum,semantic";
const SCHEMA: &str = "fre-search-v10-broad-devscreen-v1";
const CHECKSUM_SEED: u64 = 0x243f_6a88_85a3_08d3;
const MAX_CALIBRATION_ITERATIONS: usize = 1 << 30;
const HYBRID_MIN_LITERAL_BYTES: usize = 2;
const HYBRID_MIN_WINDOW_BYTES: usize = 4_093;
const HYBRID_PREFIX_CANDIDATE_STARTS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Screen,
}

impl Phase {
    fn parse(value: &str) -> Result<Self, DynError> {
        match value {
            "screen" => Ok(Self::Screen),
            _ => Err(invalid("this development binary accepts only PHASE=screen").into()),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Screen => "screen",
        }
    }

    const fn seeds(self) -> &'static [u64] {
        match self {
            Self::Screen => &SCREEN_SEEDS,
        }
    }

    const fn sizes(self) -> &'static [usize] {
        match self {
            Self::Screen => &SCREEN_SIZES,
        }
    }

    const fn alignments(self) -> &'static [u8] {
        match self {
            Self::Screen => &SCREEN_ALIGNMENTS,
        }
    }

    const fn repetitions(self) -> usize {
        match self {
            Self::Screen => 3,
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
    NearMissHead,
    NearMissTail,
    BinaryTail,
    FirstCandidateExact,
    SelectedByteHitThenFullMiss,
    WindowAbsent,
    WindowTail,
    AlignmentTail(u8),
}

impl Scenario {
    const BASE: [Self; 14] = [
        Self::AbsentEntropy,
        Self::AbsentFiller,
        Self::Early,
        Self::Middle,
        Self::Tail,
        Self::Dense,
        Self::FirstByteDenseAbsent,
        Self::NearMissHead,
        Self::NearMissTail,
        Self::BinaryTail,
        Self::FirstCandidateExact,
        Self::SelectedByteHitThenFullMiss,
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
            Self::NearMissHead => "near-miss-head".to_owned(),
            Self::NearMissTail => "near-miss-tail".to_owned(),
            Self::BinaryTail => "binary-tail".to_owned(),
            Self::FirstCandidateExact => "first_candidate_exact".to_owned(),
            Self::SelectedByteHitThenFullMiss => "selected_byte_hit_then_full_miss".to_owned(),
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
            Self::NearMissHead => 0x163,
            Self::NearMissTail => 0x16d,
            Self::BinaryTail => 0x181,
            Self::FirstCandidateExact => 0x197,
            Self::SelectedByteHitThenFullMiss => 0x19d,
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
    NativeV9,
    NativeV10,
    HybridV10,
    Portable,
}

impl Engine {
    const fn name(self) -> &'static str {
        match self {
            Self::NativeV9 => "native-v9-aot-code-tag22",
            Self::NativeV10 => "native-v10-aot-code-tag23",
            Self::HybridV10 => "hybrid-portable256-v10-tag23-floor4093-width2",
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
                        if scenario == Scenario::SelectedByteHitThenFullMiss && width == 1 {
                            continue;
                        }
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
    let portable = LiteralPlan::new(literal, LiteralBuildLimits::default())?;
    let program =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())?;
    let image_v9 = emit_audited_with_backend(
        &program,
        SearchBackendPolicy::AsimdV9,
        EmitLimits::default(),
    )?;
    let image_v10 = emit_audited_with_backend(
        &program,
        SearchBackendPolicy::AsimdV10,
        EmitLimits::default(),
    )?;
    let primary_offset = first_candidate_primary_offset(image_v10.as_image().code())?;
    let fixture = make_fixture(seed, size, scenario, literal, primary_offset)?;
    let bytes = fixture.bytes();
    let portable_window = PortableWindow::new(fixture.window_start, fixture.window_end);
    let native_window = NativeWindow::new(fixture.window_start, fixture.window_end);
    let kernel_v9 = publish_audited::<Span>(&image_v9, PublicationLimits::default())?;
    let kernel_v10 = publish_audited::<Span>(&image_v10, PublicationLimits::default())?;
    let session_v9 = kernel_v9.begin_current_thread_session()?;
    let session_v10 = kernel_v10.begin_current_thread_session()?;

    let expected = encode_portable(
        portable
            .find_window(bytes, portable_window, LiteralSearchLimits::unlimited())?
            .0,
    );
    let actual_v9 = invoke_native(&session_v9, bytes, native_window, literal.len())?;
    let actual_v10 = invoke_native(&session_v10, bytes, native_window, literal.len())?;
    let actual_hybrid =
        invoke_hybrid(&portable, &session_v10, bytes, native_window, literal.len())?;
    require(
        expected == actual_v9 && expected == actual_v10 && expected == actual_hybrid,
        "native V9/V10/hybrid/portable semantic mismatch before timing",
    )?;

    for _ in 0..3 {
        black_box(invoke_portable(&portable, bytes, portable_window)?);
        black_box(invoke_native(
            &session_v9,
            bytes,
            native_window,
            literal.len(),
        )?);
        black_box(invoke_native(
            &session_v10,
            bytes,
            native_window,
            literal.len(),
        )?);
        black_box(invoke_hybrid(
            &portable,
            &session_v10,
            bytes,
            native_window,
            literal.len(),
        )?);
    }
    let iterations = calibrate(
        &portable,
        &session_v9,
        &session_v10,
        bytes,
        portable_window,
        native_window,
        literal.len(),
        target_ns,
        expected,
    )?;
    let scenario_name = scenario.name();
    for repetition in 0..phase.repetitions() {
        let order = match repetition % 4 {
            0 => [
                Engine::NativeV9,
                Engine::NativeV10,
                Engine::HybridV10,
                Engine::Portable,
            ],
            1 => [
                Engine::NativeV10,
                Engine::HybridV10,
                Engine::Portable,
                Engine::NativeV9,
            ],
            2 => [
                Engine::HybridV10,
                Engine::Portable,
                Engine::NativeV9,
                Engine::NativeV10,
            ],
            _ => [
                Engine::Portable,
                Engine::NativeV9,
                Engine::NativeV10,
                Engine::HybridV10,
            ],
        };
        let order_name = format!(
            "{}+{}+{}+{}",
            order[0].name(),
            order[1].name(),
            order[2].name(),
            order[3].name()
        );
        for engine in order {
            let measurement = match engine {
                Engine::NativeV9 => measure(iterations, expected, || {
                    invoke_native(&session_v9, bytes, native_window, literal.len())
                })?,
                Engine::NativeV10 => measure(iterations, expected, || {
                    invoke_native(&session_v10, bytes, native_window, literal.len())
                })?,
                Engine::HybridV10 => measure(iterations, expected, || {
                    invoke_hybrid(&portable, &session_v10, bytes, native_window, literal.len())
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

fn first_candidate_primary_offset(code: &[u8]) -> Result<usize, DynError> {
    decode(code)?
        .into_iter()
        .find_map(|instruction| match instruction {
            DecodedInstruction::LoadByte {
                destination: 10,
                base: 15,
                offset,
            } => Some(usize::from(offset)),
            _ => None,
        })
        .ok_or_else(|| invalid("first-candidate prefix selected-byte load missing").into())
}

#[allow(clippy::too_many_arguments)]
fn calibrate(
    portable: &LiteralPlan,
    session_v9: &PublishedKernelThreadSession<'_, Span>,
    session_v10: &PublishedKernelThreadSession<'_, Span>,
    haystack: &[u8],
    portable_window: PortableWindow,
    native_window: NativeWindow,
    literal_bytes: usize,
    target_ns: u64,
    expected: u64,
) -> Result<usize, DynError> {
    let mut iterations = 1_usize;
    loop {
        let native_v9 = measure(iterations, expected, || {
            invoke_native(session_v9, haystack, native_window, literal_bytes)
        })?;
        let native_v10 = measure(iterations, expected, || {
            invoke_native(session_v10, haystack, native_window, literal_bytes)
        })?;
        let hybrid_v10 = measure(iterations, expected, || {
            invoke_hybrid(
                portable,
                session_v10,
                haystack,
                native_window,
                literal_bytes,
            )
        })?;
        let portable_measurement = measure(iterations, expected, || {
            invoke_portable(portable, haystack, portable_window)
        })?;
        let faster_ns = native_v9
            .total_ns
            .min(native_v10.total_ns)
            .min(hybrid_v10.total_ns)
            .min(portable_measurement.total_ns)
            .max(1);
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

fn invoke_hybrid(
    portable: &LiteralPlan,
    native_tail: &PublishedKernelThreadSession<'_, Span>,
    haystack: &[u8],
    window: NativeWindow,
    literal_bytes: usize,
) -> Result<u64, DynError> {
    let checked = CheckedSearchWindow::new(black_box(haystack), window)
        .ok_or_else(|| invalid("hybrid window rejected"))?;
    let full = portable.preflight_checked_window(checked, LiteralSearchLimits::unlimited())?;
    if literal_bytes < HYBRID_MIN_LITERAL_BYTES || full.searched_bytes() < HYBRID_MIN_WINDOW_BYTES {
        return Ok(encode_portable(full.find()?));
    }
    if let Some(matched) = full.find_prefix_candidate_starts(HYBRID_PREFIX_CANDIDATE_STARTS)? {
        return Ok(encode_portable(Some(matched)));
    }
    let Some(tail) = full.after_prefix_candidate_starts(HYBRID_PREFIX_CANDIDATE_STARTS)? else {
        return Ok(encode_portable(None));
    };
    Ok(encode_native(
        native_tail.search_checked(tail.checked_window())?,
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
    primary_offset: usize,
) -> Result<Fixture, DynError> {
    require(
        !literal.is_empty() && literal.len() <= len,
        "invalid fixture literal width",
    )?;
    require(
        primary_offset < literal.len(),
        "invalid native primary literal offset",
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
        Scenario::NearMissHead | Scenario::NearMissTail => {
            haystack.fill(avoid);
            if literal.len() > 1 {
                for chunk in haystack.chunks_exact_mut(literal.len()) {
                    chunk.copy_from_slice(literal);
                    let mutation_offset = if scenario == Scenario::NearMissHead {
                        0
                    } else {
                        literal.len() - 1
                    };
                    chunk[mutation_offset] = avoid;
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
        Scenario::FirstCandidateExact => {
            window_start = 37.min(maximum);
            window_end = len.saturating_sub(23).max(window_start + literal.len());
            window_end = window_end.min(len);
            haystack.fill(avoid);
            install_literal(haystack, window_start, literal)?;
        }
        Scenario::SelectedByteHitThenFullMiss => {
            require(
                literal.len() > 1,
                "selected-byte/full-miss fixture requires width > 1",
            )?;
            window_start = 37.min(maximum);
            window_end = len.saturating_sub(23).max(window_start + literal.len());
            window_end = window_end.min(len);
            haystack.fill(avoid);
            haystack[window_start + primary_offset] = literal[primary_offset];
            let non_primary = usize::from(primary_offset == 0);
            require(
                haystack[window_start + non_primary] != literal[non_primary],
                "selected-byte/full-miss witness is vacuous",
            )?;
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
        | Scenario::SelectedByteHitThenFullMiss
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
