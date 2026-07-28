use std::{error::Error, fmt, fs, hint::black_box, path::Path, process, time::Instant};

use fre::{
    QUALIFIED_EXACT_SEARCH_LARGE_MIN_SEARCHES, QUALIFIED_EXACT_SEARCH_LARGE_WINDOW_BYTES,
    QUALIFIED_EXACT_SEARCH_MIN_SEARCHES, QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES,
    QualifiedExactSearch, QualifiedExactSearchBackendPolicy, QualifiedExactSearchNativeAbi,
    QualifiedExactSearchNativeStatus, QualifiedExactSearchQualification, QualifiedExactSearchRoute,
    QualifiedExactSearchWorkload, SearchLimits as FacadeSearchLimits,
};
use fre_jit_aarch64::{
    BackendVersion, DecodedInstruction, EmitLimits, ImageStats, NativeImage,
    SelectedEndRegisterBackendV2, TargetSpec, decode, emit, emit_selected_end_register_v2,
};
use fre_jit_cache::{CacheLimits, KernelCache};
use fre_jit_runtime::{
    PublicationAccounting, PublicationLimits, RuntimeIdentity, RuntimeOperation, publish,
};
use fre_kernel_ir::{
    AnchorFlags, ByteClass, ExecutionLimits, Exists, Operation, SearchWindow, SelectedEnd, Span,
    ValidateLimits, ValidatedProgram, build_class_suffix, build_exact_literal,
};
use fre_kernels::{
    LiteralBuildLimits, LiteralPlan, LiteralSearchLimits, RequiredLiteralAnchors,
    RequiredLiteralBuildLimits, RequiredLiteralByteClass, RequiredLiteralPlan,
    RequiredLiteralSearchLimits,
};
use memchr::arch::all::packedpair::Pair;
use regex::bytes::{Regex, RegexBuilder};
use sha2::{Digest, Sha256};

// V3 measures the public V8 register-return ABI2 current-thread session. V2
// used the retired sessionless Search-v1 facade and generic Span-image evidence;
// those rows remain historical evidence and must never be relabeled.
const SCHEMA: &str = "fre-jit-bakeoff-v3";
const CSV_HEADER: &str = "schema,revision,pid,repetition,cell,shape,operation,size,scenario,haystack_bytes,alignment_mod16,engine,stage,timing_scope,iterations,total_ns,ns_per_iter,checksum,semantic_value,code_bytes,data_bytes,payload_used_bytes,total_mapped_bytes,total_pages,instructions,vector_instructions,loads,stores,branches,identity_bytes_hashed,identity_scratch_bytes,identity_heap_allocations,cache_bookkeeping_bytes,cache_hits,fixture,output_kind,backend,route,artifact_identity,evidence_identity,qualification_state,qualification_bundle_sha256,evidence_binding,artifact_binding,declared_min_window_bytes,declared_min_qualifying_calls,measured_calls,measured_qualifying_calls";
const EXACT_LITERAL: &[u8] = b"0123456789abcdef";
const LITERAL_1: &[u8] = b"a";
const LITERAL_6: &[u8] = b"needle";
const CLASS_BYTES: &[u8] = b"a";
const CLASS_SUFFIX: &[u8] = b"bcdefghijklmnopq";
const SHERLOCK_LITERAL: &[u8] = b"Sherlock Holmes";
const SHERLOCK_BYTES: usize = 899_232;
const SHERLOCK_MATCHES: usize = 513;
const SHERLOCK_SHA256: &str = "0d40805f6d02c8fe02bd75945b98911891f707e8ecb939e018446858065d76ea";
const NATURAL_TEXT: &[u8] = b"Elementary observations reward patient measurement. \
False candidates should be cheap, and distant evidence must remain visible. ";

fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = std::env::args().collect();
    match arguments.get(1).map(String::as_str) {
        Some("header") if arguments.len() == 2 => print_header(),
        Some("list") if arguments.len() == 2 => list_cells(),
        Some("list-adversarial") if arguments.len() == 2 => list_adversarial_cells(),
        Some("adversarial-info") if arguments.len() == 2 => print_adversarial_info(),
        Some("run") if arguments.len() == 7 => {
            let cell = Cell {
                shape: Shape::parse(&arguments[2])?,
                operation: OperationName::parse(&arguments[3])?,
                size: Size::parse(&arguments[4])?,
                scenario: Scenario::parse(&arguments[5])?,
            };
            let repetition = arguments[6].parse::<u32>()?;
            run_cell(cell, repetition)?;
        }
        Some("sherlock") if arguments.len() == 4 => {
            let repetition = arguments[3].parse::<u32>()?;
            run_sherlock(Path::new(&arguments[2]), repetition)?;
        }
        Some("inspect") if arguments.len() == 4 => {
            inspect_image(
                Shape::parse(&arguments[2])?,
                OperationName::parse(&arguments[3])?,
            )?;
        }
        _ => {
            eprintln!(
                "usage: {} header | list | list-adversarial | adversarial-info | run SHAPE OP SIZE SCENARIO REP | sherlock PATH REP | inspect SHAPE OP",
                arguments.first().map_or("fre-jit-bakeoff", String::as_str)
            );
            process::exit(2);
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Shape {
    Exact,
    Literal1,
    Literal6,
    Literal15,
    ClassSuffix,
}

impl Shape {
    fn parse(text: &str) -> Result<Self, ParseError> {
        match text {
            "exact" => Ok(Self::Exact),
            "literal1" => Ok(Self::Literal1),
            "literal6" => Ok(Self::Literal6),
            "literal15" => Ok(Self::Literal15),
            "class" => Ok(Self::ClassSuffix),
            _ => Err(ParseError::new("shape", text)),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Literal1 => "literal1",
            Self::Literal6 => "literal6",
            Self::Literal15 => "literal15",
            Self::ClassSuffix => "class",
        }
    }

    const fn literal(self) -> Option<&'static [u8]> {
        match self {
            Self::Exact => Some(EXACT_LITERAL),
            Self::Literal1 => Some(LITERAL_1),
            Self::Literal6 => Some(LITERAL_6),
            Self::Literal15 => Some(SHERLOCK_LITERAL),
            Self::ClassSuffix => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationName {
    Exists,
    SelectedEnd,
    Span,
}

impl OperationName {
    fn parse(text: &str) -> Result<Self, ParseError> {
        match text {
            "exists" => Ok(Self::Exists),
            "end" => Ok(Self::SelectedEnd),
            "span" => Ok(Self::Span),
            _ => Err(ParseError::new("operation", text)),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Exists => "exists",
            Self::SelectedEnd => "end",
            Self::Span => "span",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Size {
    Short,
    K64,
    M1,
}

impl Size {
    fn parse(text: &str) -> Result<Self, ParseError> {
        match text {
            "short" => Ok(Self::Short),
            "64k" => Ok(Self::K64),
            "1m" => Ok(Self::M1),
            _ => Err(ParseError::new("size", text)),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Short => "short",
            Self::K64 => "64k",
            Self::M1 => "1m",
        }
    }

    const fn bytes(self) -> usize {
        match self {
            Self::Short => 96,
            Self::K64 => 64 * 1024,
            Self::M1 => 1024 * 1024,
        }
    }

    const fn hot_iterations(self) -> u64 {
        match self {
            Self::Short => 20_000,
            Self::K64 => 1_024,
            Self::M1 => 64,
        }
    }

    const fn qualified_workload(self) -> QualifiedExactSearchWorkload {
        match self {
            Self::Short => QualifiedExactSearchWorkload::new(Self::Short.bytes(), 1),
            Self::K64 => QualifiedExactSearchWorkload::new(
                QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES,
                QUALIFIED_EXACT_SEARCH_MIN_SEARCHES,
            ),
            Self::M1 => QualifiedExactSearchWorkload::new(
                QUALIFIED_EXACT_SEARCH_LARGE_WINDOW_BYTES,
                QUALIFIED_EXACT_SEARCH_LARGE_MIN_SEARCHES,
            ),
        }
    }

    const fn under_threshold_workload(self) -> QualifiedExactSearchWorkload {
        match self {
            Self::Short => QualifiedExactSearchWorkload::new(Self::Short.bytes(), 1),
            Self::K64 => QualifiedExactSearchWorkload::new(
                QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES,
                QUALIFIED_EXACT_SEARCH_MIN_SEARCHES - 1,
            ),
            Self::M1 => QualifiedExactSearchWorkload::new(
                QUALIFIED_EXACT_SEARCH_LARGE_WINDOW_BYTES,
                QUALIFIED_EXACT_SEARCH_LARGE_MIN_SEARCHES - 1,
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scenario {
    Present,
    Absent,
    Dense,
    Tail,
    Unaligned,
    PrimaryDenseSecondaryAbsent,
    PairDenseLiteralAbsent,
    TripleDenseLiteralAbsent,
    FalsePairDistantMatch,
    Binary,
    NaturalText,
}

impl Scenario {
    fn parse(text: &str) -> Result<Self, ParseError> {
        match text {
            "present" => Ok(Self::Present),
            "absent" => Ok(Self::Absent),
            "dense" => Ok(Self::Dense),
            "tail" => Ok(Self::Tail),
            "unaligned" => Ok(Self::Unaligned),
            "primary-dense-secondary-absent" => Ok(Self::PrimaryDenseSecondaryAbsent),
            "pair-dense-literal-absent" => Ok(Self::PairDenseLiteralAbsent),
            "triple-dense-literal-absent" => Ok(Self::TripleDenseLiteralAbsent),
            "false-pair-distant-match" => Ok(Self::FalsePairDistantMatch),
            "binary" => Ok(Self::Binary),
            "natural-text" => Ok(Self::NaturalText),
            _ => Err(ParseError::new("scenario", text)),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Absent => "absent",
            Self::Dense => "dense",
            Self::Tail => "tail",
            Self::Unaligned => "unaligned",
            Self::PrimaryDenseSecondaryAbsent => "primary-dense-secondary-absent",
            Self::PairDenseLiteralAbsent => "pair-dense-literal-absent",
            Self::TripleDenseLiteralAbsent => "triple-dense-literal-absent",
            Self::FalsePairDistantMatch => "false-pair-distant-match",
            Self::Binary => "binary",
            Self::NaturalText => "natural-text",
        }
    }

    const fn fixture(self) -> &'static str {
        match self {
            Self::Present | Self::Absent | Self::Dense | Self::Tail | Self::Unaligned => {
                "synthetic-v1"
            }
            Self::PrimaryDenseSecondaryAbsent
            | Self::PairDenseLiteralAbsent
            | Self::FalsePairDistantMatch
            | Self::Binary
            | Self::NaturalText => "synthetic-adversarial-v1",
            Self::TripleDenseLiteralAbsent => "synthetic-adversarial-v2",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Cell {
    shape: Shape,
    operation: OperationName,
    size: Size,
    scenario: Scenario,
}

impl Cell {
    fn id(self) -> String {
        format!(
            "{}-{}-{}-{}",
            self.shape.name(),
            self.operation.name(),
            self.size.name(),
            self.scenario.name()
        )
    }
}

#[derive(Debug)]
struct ParseError {
    kind: &'static str,
    value: String,
}

impl ParseError {
    fn new(kind: &'static str, value: &str) -> Self {
        Self {
            kind,
            value: value.to_owned(),
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "unknown {} {:?}", self.kind, self.value)
    }
}

impl Error for ParseError {}

fn list_cells() {
    for shape in [Shape::Exact, Shape::ClassSuffix] {
        for operation in [
            OperationName::Exists,
            OperationName::SelectedEnd,
            OperationName::Span,
        ] {
            for size in [Size::Short, Size::K64, Size::M1] {
                for scenario in [
                    Scenario::Present,
                    Scenario::Absent,
                    Scenario::Dense,
                    Scenario::Tail,
                    Scenario::Unaligned,
                ] {
                    println!(
                        "{} {} {} {}",
                        shape.name(),
                        operation.name(),
                        size.name(),
                        scenario.name()
                    );
                }
            }
        }
    }
}

fn list_adversarial_cells() {
    for operation in [
        OperationName::Exists,
        OperationName::SelectedEnd,
        OperationName::Span,
    ] {
        for size in [Size::Short, Size::K64, Size::M1] {
            for scenario in [
                Scenario::PrimaryDenseSecondaryAbsent,
                Scenario::PairDenseLiteralAbsent,
                Scenario::TripleDenseLiteralAbsent,
                Scenario::FalsePairDistantMatch,
                Scenario::Binary,
                Scenario::NaturalText,
            ] {
                println!(
                    "{} {} {} {}",
                    Shape::Exact.name(),
                    operation.name(),
                    size.name(),
                    scenario.name()
                );
            }
        }
    }
}

fn print_adversarial_info() {
    let (primary, secondary) = selected_pair(EXACT_LITERAL);
    println!("schema=fre-jit-bakeoff-adversarial-v1");
    println!("shape=exact");
    println!("literal_hex={}", hex_encode(EXACT_LITERAL));
    println!("pair_selector=memchr-2.8.3-default-frequency-rank");
    println!("primary_offset={primary}");
    println!("primary_byte=0x{:02x}", EXACT_LITERAL[primary]);
    println!("secondary_offset={secondary}");
    println!("secondary_byte=0x{:02x}", EXACT_LITERAL[secondary]);
    let verification = selected_verification(EXACT_LITERAL, primary, secondary)
        .expect("adversarial literal has a distinct verification byte");
    println!("verification_offset={verification}");
    println!("verification_byte=0x{:02x}", EXACT_LITERAL[verification]);
}

fn run_cell(cell: Cell, repetition: u32) -> Result<(), Box<dyn Error>> {
    match cell.operation {
        OperationName::Exists => bench::<Exists>(cell, repetition),
        OperationName::SelectedEnd => bench::<SelectedEnd>(cell, repetition),
        OperationName::Span => bench::<Span>(cell, repetition),
    }
}

trait BenchOperation: RuntimeOperation {
    fn encode(output: &Self::Output) -> u64;
    fn regex_search(regex: &Regex, haystack: &[u8]) -> u64;
    fn encode_span(span: Option<(usize, usize)>) -> u64;
}

impl BenchOperation for Exists {
    fn encode(output: &Self::Output) -> u64 {
        u64::from(*output)
    }

    fn regex_search(regex: &Regex, haystack: &[u8]) -> u64 {
        u64::from(regex.is_match(haystack))
    }

    fn encode_span(span: Option<(usize, usize)>) -> u64 {
        u64::from(span.is_some())
    }
}

impl BenchOperation for SelectedEnd {
    fn encode(output: &Self::Output) -> u64 {
        encode_optional_offset(*output)
    }

    fn regex_search(regex: &Regex, haystack: &[u8]) -> u64 {
        encode_optional_offset(regex.find(haystack).map(|matched| matched.end()))
    }

    fn encode_span(span: Option<(usize, usize)>) -> u64 {
        encode_optional_offset(span.map(|(_, end)| end))
    }
}

impl BenchOperation for Span {
    fn encode(output: &Self::Output) -> u64 {
        encode_optional_span(output.map(|span| (span.start(), span.end())))
    }

    fn regex_search(regex: &Regex, haystack: &[u8]) -> u64 {
        encode_optional_span(
            regex
                .find(haystack)
                .map(|matched| (matched.start(), matched.end())),
        )
    }

    fn encode_span(span: Option<(usize, usize)>) -> u64 {
        encode_optional_span(span)
    }
}

fn encode_optional_offset(offset: Option<usize>) -> u64 {
    offset
        .and_then(|value| u64::try_from(value).ok())
        .map_or(0, |value| value.wrapping_add(1))
}

fn encode_optional_span(span: Option<(usize, usize)>) -> u64 {
    span.map_or(0, |(start, end)| {
        let start = u64::try_from(start).unwrap_or(u64::MAX);
        let end = u64::try_from(end).unwrap_or(u64::MAX);
        start.rotate_left(17) ^ end.rotate_left(41) ^ 0x9e37_79b9_7f4a_7c15
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "all timing boundaries stay adjacent so the matrix cannot silently measure different setup"
)]
fn bench<O: BenchOperation>(cell: Cell, repetition: u32) -> Result<(), Box<dyn Error>> {
    let owned_haystack = make_haystack(cell);
    let haystack = owned_haystack.as_slice();
    let window = SearchWindow::new(0, haystack.len());
    let program = build_program::<O>(cell.shape)?;
    let image = emit(&program, EmitLimits::default())?;
    let regex = build_regex(cell.shape)?;
    let native_plan = NativePlan::build(cell.shape)?;
    let qualified_workload = cell.size.qualified_workload();
    let under_threshold_workload = cell.size.under_threshold_workload();
    let qualified = if cell.shape == Shape::Exact {
        Some(build_qualified_v8(qualified_workload)?)
    } else {
        None
    };
    let under_threshold = if cell.shape == Shape::Exact {
        Some(build_qualified_v8(under_threshold_workload)?)
    } else {
        None
    };
    // The sessions borrow their owners and are established before every hot
    // timer. Even V8 uses this explicit boundary, though its construction is
    // SVE-syscall-free.
    let qualified_session = qualified
        .as_ref()
        .map(|search| search.begin_current_thread_session())
        .transpose()?;
    let under_threshold_session = under_threshold
        .as_ref()
        .map(|search| search.begin_current_thread_session())
        .transpose()?;
    let qualified_v8_artifact = if cell.shape == Shape::Exact {
        Some(qualified_v8_artifact_witness()?)
    } else {
        None
    };

    let oracle = O::encode(
        &program
            .execute(haystack, window, ExecutionLimits::unlimited())?
            .into_output(),
    );
    let regex_value = O::regex_search(&regex, haystack);
    let kernels_value = O::encode_span(native_plan.find(haystack)?);
    ensure_equal("regex", oracle, regex_value, cell)?;
    ensure_equal("fre-kernels", oracle, kernels_value, cell)?;
    let qualified_route = if let (Some(qualified), Some(session)) = (&qualified, &qualified_session)
    {
        let (matched, execution) = session.find(haystack, FacadeSearchLimits::unlimited())?;
        let qualified_value = O::encode_span(matched.map(|span| (span.start(), span.end())));
        ensure_equal("qualified exact facade", oracle, qualified_value, cell)?;
        let expected_route = if haystack.len()
            >= qualified.build_report().workload.minimum_window_bytes()
            && qualified.build_report().native.is_published()
        {
            QualifiedExactSearchRoute::NativeJit
        } else {
            QualifiedExactSearchRoute::PortableLiteral
        };
        if execution.route != expected_route {
            return Err(format!(
                "qualified facade route mismatch for {cell:?}: expected {expected_route:?}, got {:?}",
                execution.route
            )
            .into());
        }
        Some(execution.route)
    } else {
        None
    };
    let under_threshold_route = if let (Some(under_threshold), Some(session)) =
        (&under_threshold, &under_threshold_session)
    {
        let (matched, execution) = session.find(haystack, FacadeSearchLimits::unlimited())?;
        let qualified_value = O::encode_span(matched.map(|span| (span.start(), span.end())));
        ensure_equal(
            "under-threshold qualified exact facade",
            oracle,
            qualified_value,
            cell,
        )?;
        if execution.route != QualifiedExactSearchRoute::PortableLiteral
            || under_threshold.build_report().native.is_published()
        {
            return Err(format!(
                "under-threshold facade must remain portable for {cell:?}, got {:?}",
                execution.route
            )
            .into());
        }
        Some(execution.route)
    } else {
        None
    };

    let published = publish::<O>(&image, PublicationLimits::default())?;
    let jit_value = O::encode(&published.search(haystack, window)?);
    ensure_equal("JIT", oracle, jit_value, cell)?;
    let publication = published.accounting();
    let mix = InstructionMix::for_image(&image)?;

    let cache = KernelCache::<O>::new(CacheLimits::default(), PublicationLimits::default())?;
    let initial_lease = cache.get_or_publish(&image)?;
    let cache_value = O::encode(&initial_lease.search(haystack, window)?);
    ensure_equal("cache", oracle, cache_value, cell)?;
    drop(initial_lease);

    for _ in 0..8 {
        black_box(O::encode(&published.search(black_box(haystack), window)?));
        black_box(O::regex_search(&regex, black_box(haystack)));
        black_box(O::encode_span(native_plan.find(black_box(haystack))?));
        if let Some(session) = &qualified_session {
            black_box(session.find_value(black_box(haystack), FacadeSearchLimits::unlimited())?);
        }
        if let Some(session) = &under_threshold_session {
            black_box(session.find_value(black_box(haystack), FacadeSearchLimits::unlimited())?);
        }
        let lease = cache.get_or_publish(&image)?;
        black_box(O::encode(&lease.search(black_box(haystack), window)?));
    }

    let hot_iterations = cell.size.hot_iterations();
    let mut samples = Vec::with_capacity(15);
    samples.push(Sample::new(
        "jit",
        "plan",
        "cold_literal_to_validated_kernel_ir_no_regex_parse",
        measure(20, || {
            let planned =
                build_program::<O>(cell.shape).expect("fixed benchmark shape remains valid");
            cache_identity_word(planned.cache_identity())
        }),
    ));
    samples.push(Sample::new(
        "jit",
        "emit",
        "cold_compile_only",
        measure(20, || {
            let emitted = emit(black_box(&program), EmitLimits::default())
                .expect("validated emission remains valid");
            identity_word(RuntimeIdentity::for_image(&emitted))
        }),
    ));
    samples.push(Sample::new(
        "jit",
        "publish_first_call",
        "cold_mapping_first_call_compile_excluded",
        measure(8, || {
            let kernel = publish::<O>(black_box(&image), PublicationLimits::default())
                .expect("supported publication remains valid");
            O::encode(
                &kernel
                    .search(black_box(haystack), window)
                    .expect("validated call remains valid"),
            )
        }),
    ));
    samples.push(Sample::new(
        "jit",
        "build_emit_publish_first_call",
        "cold_end_to_end_compile_included",
        measure(8, || {
            let cold_program =
                build_program::<O>(cell.shape).expect("fixed benchmark shape remains valid");
            let cold_image = emit(&cold_program, EmitLimits::default())
                .expect("fixed benchmark emission remains valid");
            let kernel = publish::<O>(&cold_image, PublicationLimits::default())
                .expect("supported publication remains valid");
            O::encode(
                &kernel
                    .search(black_box(haystack), window)
                    .expect("validated call remains valid"),
            )
        }),
    ));
    samples.push(Sample::new(
        "jit",
        "direct_lease_call",
        "hot_compile_and_mapping_excluded",
        measure(hot_iterations, || {
            O::encode(
                &published
                    .search(black_box(haystack), window)
                    .expect("validated call remains valid"),
            )
        }),
    ));
    samples.push(Sample::new(
        "jit",
        "cache_lookup_call",
        "hot_compile_and_initial_publication_excluded",
        measure(hot_iterations, || {
            let lease = cache
                .get_or_publish(black_box(&image))
                .expect("resident lookup remains valid");
            O::encode(
                &lease
                    .search(black_box(haystack), window)
                    .expect("validated call remains valid"),
            )
        }),
    ));
    samples.push(Sample::new(
        "jit",
        "identity_access",
        "hot_precomputed_identity_only",
        measure(100_000, || {
            identity_word(RuntimeIdentity::for_image(black_box(&image)))
        }),
    ));
    samples.push(Sample::new(
        "rust-regex-1.12.4",
        "compile_first_call",
        "cold_compile_included",
        measure(20, || {
            let cold_regex = build_regex(cell.shape).expect("fixed regex remains valid");
            O::regex_search(&cold_regex, black_box(haystack))
        }),
    ));
    samples.push(Sample::new(
        "rust-regex-1.12.4",
        "search",
        "hot_compile_excluded",
        measure(hot_iterations, || {
            O::regex_search(&regex, black_box(haystack))
        }),
    ));
    samples.push(Sample::new(
        "fre-kernels",
        "build_first_call",
        "cold_plan_build_included",
        measure(20, || {
            let plan = NativePlan::build(cell.shape).expect("fixed native plan remains valid");
            O::encode_span(
                plan.find(black_box(haystack))
                    .expect("native plan remains valid"),
            )
        }),
    ));
    if let (
        Some(qualified),
        Some(under_threshold),
        Some(qualified_session),
        Some(under_threshold_session),
        Some(route),
        Some(under_route),
        Some(v8_artifact),
    ) = (
        &qualified,
        &under_threshold,
        &qualified_session,
        &under_threshold_session,
        qualified_route,
        under_threshold_route,
        &qualified_v8_artifact,
    ) {
        let search_timed = measure(hot_iterations, || {
            let matched = qualified_session
                .find_value(black_box(haystack), FacadeSearchLimits::unlimited())
                .expect("qualified V8 ABI2 session search remains valid");
            O::encode_span(matched.map(|span| (span.start(), span.end())))
        });
        samples.push(
            Sample::new(
                "fre-qualified-exact",
                "search",
                "session_value_search_declared_workload_build_and_session_excluded",
                search_timed,
            )
            .with_evidence(qualified_row_evidence(
                qualified,
                route,
                v8_artifact,
                haystack.len(),
                search_timed.iterations,
            )?),
        );

        let full_workload_calls = u64::try_from(qualified_workload.minimum_qualifying_searches())
            .expect("bounded declared workload fits u64");
        let full_workload_timed = measure_qualified_full_workload::<O>(
            qualified_workload,
            haystack,
            full_workload_calls,
            route,
        );
        samples.push(
            Sample::new(
                "fre-qualified-exact",
                "build_full_workload",
                "build_plus_session_plus_declared_workload_amortized_per_value_search",
                full_workload_timed,
            )
            .with_evidence(qualified_row_evidence(
                qualified,
                route,
                v8_artifact,
                haystack.len(),
                full_workload_timed.iterations,
            )?),
        );

        let under_threshold_calls =
            u64::try_from(under_threshold_workload.minimum_qualifying_searches())
                .expect("bounded under-threshold workload fits u64")
                .max(1);
        let under_search_timed = measure(under_threshold_calls, || {
            let matched = under_threshold_session
                .find_value(black_box(haystack), FacadeSearchLimits::unlimited())
                .expect("under-threshold V8 ABI2 session search remains valid");
            O::encode_span(matched.map(|span| (span.start(), span.end())))
        });
        samples.push(
            Sample::new(
                "fre-qualified-exact-under-threshold",
                "search",
                "session_value_search_forced_portable_build_and_session_excluded",
                under_search_timed,
            )
            .with_evidence(qualified_row_evidence(
                under_threshold,
                under_route,
                v8_artifact,
                haystack.len(),
                under_search_timed.iterations,
            )?),
        );

        let under_full_timed = measure_qualified_full_workload::<O>(
            under_threshold_workload,
            haystack,
            under_threshold_calls,
            under_route,
        );
        samples.push(
            Sample::new(
                "fre-qualified-exact-under-threshold",
                "build_full_workload",
                "portable_build_plus_session_plus_declared_workload_amortized_per_value_search",
                under_full_timed,
            )
            .with_evidence(qualified_row_evidence(
                under_threshold,
                under_route,
                v8_artifact,
                haystack.len(),
                under_full_timed.iterations,
            )?),
        );
    }
    samples.push(Sample::new(
        "fre-kernels",
        "search",
        "hot_plan_build_excluded",
        measure(hot_iterations, || {
            O::encode_span(
                native_plan
                    .find(black_box(haystack))
                    .expect("native plan remains valid"),
            )
        }),
    ));

    let snapshot = cache.snapshot();
    let metadata = Metadata {
        cell,
        repetition,
        haystack_bytes: haystack.len(),
        alignment_mod16: haystack.as_ptr().addr() & 15,
        semantic_value: oracle,
        image: image.stats(),
        publication,
        mix,
        identity: image.artifact_identity_receipt(),
        cache_bookkeeping_bytes: snapshot.current.bookkeeping_bytes,
        cache_hits: snapshot.totals.hits,
        fixture: cell.scenario.fixture(),
    };
    for sample in samples {
        print_sample(&metadata, &sample);
    }
    Ok(())
}

fn build_qualified_v8(
    workload: QualifiedExactSearchWorkload,
) -> Result<QualifiedExactSearch, fre::QualifiedExactSearchBuildError> {
    QualifiedExactSearch::new_with_backend(
        EXACT_LITERAL,
        workload,
        QualifiedExactSearchBackendPolicy::AsimdV8,
    )
}

fn qualified_v8_artifact_witness() -> Result<QualifiedV8ArtifactWitness, Box<dyn Error>> {
    let program = build_exact_literal::<SelectedEnd>(
        EXACT_LITERAL,
        AnchorFlags::default(),
        ValidateLimits::default(),
    )?;
    let image = emit_selected_end_register_v2(
        &program,
        SelectedEndRegisterBackendV2::AsimdV8,
        EmitLimits::default(),
    )?;
    if image.backend() != SelectedEndRegisterBackendV2::AsimdV8
        || image.backend_version() != BackendVersion::SEARCH_V8
        || image.target() != TargetSpec::AARCH64_AAPCS64
    {
        return Err("deterministic qualified witness is not exact ASIMD V8 ABI2".into());
    }
    Ok(QualifiedV8ArtifactWitness {
        image: image.stats(),
        target: image.target(),
        backend: image.backend_version(),
        artifact_sha256: *image.artifact_identity().as_bytes(),
        mix: InstructionMix::for_code(image.code())?,
    })
}

/// Time the complete qualified lifecycle without creating a self-referential
/// state object. Construction and session admission are inside the lifecycle
/// timer; the session itself is established once before the value-only loop.
fn measure_qualified_full_workload<O: BenchOperation>(
    workload: QualifiedExactSearchWorkload,
    haystack: &[u8],
    calls: u64,
    expected_route: QualifiedExactSearchRoute,
) -> Timed {
    assert!(calls > 0);
    let mut checksum = 0x6a09_e667_f3bc_c909_u64;
    let start = Instant::now();
    let qualified = build_qualified_v8(workload).expect("qualified V8 ABI2 facade build");
    let session = qualified
        .begin_current_thread_session()
        .expect("qualified V8 ABI2 current-thread session");
    for iteration in 0..calls {
        let matched = session
            .find_value(black_box(haystack), FacadeSearchLimits::unlimited())
            .expect("qualified V8 ABI2 value search remains valid");
        let value = black_box(O::encode_span(
            matched.map(|span| (span.start(), span.end())),
        ));
        checksum = checksum.rotate_left(9)
            ^ value.wrapping_add(iteration.wrapping_mul(0x9e37_79b9_7f4a_7c15));
    }
    let total_ns = start.elapsed().as_nanos();
    black_box(checksum);

    // Route reporting remains outside the measured lifecycle. It proves that
    // every value-only call used the intended native or portable executor.
    let (_, execution) = session
        .find(haystack, FacadeSearchLimits::unlimited())
        .expect("qualified V8 ABI2 reporting search remains valid");
    assert_eq!(
        execution.route, expected_route,
        "qualified route changed inside one full-workload sample"
    );
    Timed {
        iterations: calls,
        total_ns,
        checksum,
    }
}

fn build_program<O: Operation>(
    shape: Shape,
) -> Result<ValidatedProgram<O>, fre_kernel_ir::BuildError> {
    match shape {
        Shape::Exact | Shape::Literal1 | Shape::Literal6 | Shape::Literal15 => {
            build_exact_literal::<O>(
                shape.literal().expect("exact shape has a literal"),
                AnchorFlags::default(),
                ValidateLimits::default(),
            )
        }
        Shape::ClassSuffix => build_class_suffix::<O>(
            ByteClass::from_bytes(CLASS_BYTES),
            CLASS_SUFFIX,
            AnchorFlags::default(),
            ValidateLimits::default(),
        ),
    }
}

fn build_regex(shape: Shape) -> Result<Regex, regex::Error> {
    let pattern = match shape {
        Shape::Exact | Shape::Literal1 | Shape::Literal6 | Shape::Literal15 => regex::escape(
            std::str::from_utf8(shape.literal().expect("exact shape has a literal"))
                .expect("ASCII literal"),
        ),
        Shape::ClassSuffix => format!(
            "[a]+{}",
            regex::escape(std::str::from_utf8(CLASS_SUFFIX).expect("ASCII suffix"))
        ),
    };
    RegexBuilder::new(&pattern).unicode(false).build()
}

enum NativePlan {
    Exact(LiteralPlan),
    ClassSuffix(RequiredLiteralPlan),
}

impl NativePlan {
    fn build(shape: Shape) -> Result<Self, Box<dyn Error>> {
        match shape {
            Shape::Exact | Shape::Literal1 | Shape::Literal6 | Shape::Literal15 => {
                Ok(Self::Exact(LiteralPlan::new(
                    shape.literal().expect("exact shape has a literal"),
                    LiteralBuildLimits::default(),
                )?))
            }
            Shape::ClassSuffix => Ok(Self::ClassSuffix(RequiredLiteralPlan::build(
                RequiredLiteralByteClass::from_bytes(CLASS_BYTES),
                CLASS_SUFFIX,
                RequiredLiteralAnchors::default(),
                RequiredLiteralBuildLimits::default(),
            )?)),
        }
    }

    fn find(&self, haystack: &[u8]) -> Result<Option<(usize, usize)>, Box<dyn Error>> {
        match self {
            Self::Exact(plan) => Ok(plan.find(haystack, LiteralSearchLimits::unlimited())?.0),
            Self::ClassSuffix(plan) => Ok(plan
                .find(haystack, RequiredLiteralSearchLimits::unlimited())?
                .0),
        }
    }
}

struct OwnedHaystack {
    storage: Vec<u8>,
    start: usize,
    length: usize,
}

impl OwnedHaystack {
    fn as_slice(&self) -> &[u8] {
        let end = self
            .start
            .checked_add(self.length)
            .expect("bounded benchmark storage");
        &self.storage[self.start..end]
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "all benchmark scenario construction remains centralized for comparable fixtures"
)]
fn make_haystack(cell: Cell) -> OwnedHaystack {
    let length = cell.size.bytes();
    let storage_length = length.checked_add(32).expect("bounded benchmark size");
    let mut storage = vec![b'x'; storage_length];
    let base_mod16 = storage.as_ptr().addr() & 15;
    let desired = usize::from(cell.scenario == Scenario::Unaligned);
    let start = desired.wrapping_add(16).wrapping_sub(base_mod16) & 15;
    let end = start.checked_add(length).expect("bounded benchmark size");
    let slice = &mut storage[start..end];
    match cell.scenario {
        Scenario::Absent => {}
        Scenario::Dense => match cell.shape {
            Shape::Exact | Shape::Literal1 | Shape::Literal6 | Shape::Literal15 => {
                slice.fill(cell.shape.literal().expect("exact shape has a literal")[0]);
            }
            Shape::ClassSuffix => slice.fill(CLASS_BYTES[0]),
        },
        Scenario::Present | Scenario::Unaligned => {
            let matched = match_bytes(cell.shape);
            let position = length
                .checked_sub(matched.len())
                .expect("match fits benchmark haystack")
                .checked_div(2)
                .expect("nonzero divisor");
            let matched_end = position
                .checked_add(matched.len())
                .expect("match fits benchmark haystack");
            slice[position..matched_end].copy_from_slice(&matched);
        }
        Scenario::Tail => {
            let matched = match_bytes(cell.shape);
            let position = length
                .checked_sub(matched.len())
                .expect("match fits benchmark haystack");
            slice[position..].copy_from_slice(&matched);
        }
        Scenario::PrimaryDenseSecondaryAbsent => {
            let literal = adversarial_literal(cell.shape);
            let (primary, secondary) = selected_pair(literal);
            assert_ne!(
                literal[primary], literal[secondary],
                "primary-dense workload requires distinct selected bytes"
            );
            slice.fill(literal[primary]);
        }
        Scenario::PairDenseLiteralAbsent => {
            let literal = adversarial_literal(cell.shape);
            let (primary, secondary) = selected_pair(literal);
            let primary_byte = literal[primary];
            let secondary_byte = literal[secondary];
            assert_ne!(
                primary_byte, secondary_byte,
                "pair-dense workload requires distinct selected bytes"
            );
            for candidate in 0..=length
                .checked_sub(literal.len())
                .expect("literal fits benchmark haystack")
            {
                let primary_index = candidate
                    .checked_add(primary)
                    .expect("selected pair fits benchmark haystack");
                let secondary_index = candidate
                    .checked_add(secondary)
                    .expect("selected pair fits benchmark haystack");
                let primary_slot = slice[primary_index];
                let secondary_slot = slice[secondary_index];
                if (primary_slot != b'x' && primary_slot != primary_byte)
                    || (secondary_slot != b'x' && secondary_slot != secondary_byte)
                {
                    continue;
                }
                slice[primary_index] = primary_byte;
                slice[secondary_index] = secondary_byte;
            }
        }
        Scenario::TripleDenseLiteralAbsent => {
            let literal = adversarial_literal(cell.shape);
            let (primary, secondary) = selected_pair(literal);
            let verification = selected_verification(literal, primary, secondary)
                .expect("adversarial literal has a distinct verification byte");
            for candidate in 0..=length
                .checked_sub(literal.len())
                .expect("literal fits benchmark haystack")
            {
                let selected = [
                    (primary, literal[primary]),
                    (secondary, literal[secondary]),
                    (verification, literal[verification]),
                ];
                if selected.iter().any(|&(offset, byte)| {
                    let index = candidate
                        .checked_add(offset)
                        .expect("selected triple fits benchmark haystack");
                    let slot = slice[index];
                    slot != b'x' && slot != byte
                }) {
                    continue;
                }
                for (offset, byte) in selected {
                    let index = candidate
                        .checked_add(offset)
                        .expect("selected triple fits benchmark haystack");
                    slice[index] = byte;
                }
            }
        }
        Scenario::FalsePairDistantMatch => {
            let literal = adversarial_literal(cell.shape);
            let (primary, secondary) = selected_pair(literal);
            slice[primary] = literal[primary];
            slice[secondary] = literal[secondary];
            let position = length
                .checked_sub(literal.len())
                .expect("literal fits benchmark haystack");
            slice[position..].copy_from_slice(literal);
        }
        Scenario::Binary => {
            let literal = adversarial_literal(cell.shape);
            for (index, byte) in slice.iter_mut().enumerate() {
                *byte = u8::try_from(index & 0xff).expect("masked index fits in a byte");
            }
            let position = distant_position(length, literal.len());
            let matched_end = position
                .checked_add(literal.len())
                .expect("literal fits benchmark haystack");
            slice[position..matched_end].copy_from_slice(literal);
        }
        Scenario::NaturalText => {
            let literal = adversarial_literal(cell.shape);
            for (index, byte) in slice.iter_mut().enumerate() {
                let source = index
                    .checked_rem(NATURAL_TEXT.len())
                    .expect("natural-text fixture is nonempty");
                *byte = NATURAL_TEXT[source];
            }
            let position = distant_position(length, literal.len());
            let matched_end = position
                .checked_add(literal.len())
                .expect("literal fits benchmark haystack");
            slice[position..matched_end].copy_from_slice(literal);
        }
    }
    OwnedHaystack {
        storage,
        start,
        length,
    }
}

fn adversarial_literal(shape: Shape) -> &'static [u8] {
    assert_eq!(
        shape,
        Shape::Exact,
        "adversarial pair workloads are admitted only for the exact literal"
    );
    EXACT_LITERAL
}

fn selected_pair(literal: &[u8]) -> (usize, usize) {
    let pair = Pair::new(literal).expect("adversarial literal has at least two bytes");
    (usize::from(pair.index1()), usize::from(pair.index2()))
}

fn selected_verification(
    literal: &[u8],
    primary_offset: usize,
    secondary_offset: usize,
) -> Option<usize> {
    let primary_byte = *literal.get(primary_offset)?;
    let secondary_byte = *literal.get(secondary_offset)?;
    literal
        .iter()
        .position(|&byte| byte != primary_byte && byte != secondary_byte)
}

fn distant_position(haystack_len: usize, literal_len: usize) -> usize {
    haystack_len
        .checked_sub(literal_len)
        .expect("literal fits benchmark haystack")
        .checked_mul(3)
        .expect("bounded benchmark size")
        .checked_div(4)
        .expect("nonzero divisor")
}

fn match_bytes(shape: Shape) -> Vec<u8> {
    match shape {
        Shape::Exact | Shape::Literal1 | Shape::Literal6 | Shape::Literal15 => {
            shape.literal().expect("exact shape has a literal").to_vec()
        }
        Shape::ClassSuffix => {
            let mut matched = b"aaaa".to_vec();
            matched.extend_from_slice(CLASS_SUFFIX);
            matched
        }
    }
}

fn ensure_equal(
    engine: &str,
    expected: u64,
    actual: u64,
    cell: Cell,
) -> Result<(), Box<dyn Error>> {
    if expected != actual {
        return Err(format!(
            "{} semantic mismatch in {}: oracle={:#x}, actual={:#x}",
            engine,
            cell.id(),
            expected,
            actual
        )
        .into());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct Timed {
    iterations: u64,
    total_ns: u128,
    checksum: u64,
}

fn measure<F>(iterations: u64, mut measured: F) -> Timed
where
    F: FnMut() -> u64,
{
    let mut checksum = 0x6a09_e667_f3bc_c909_u64;
    let start = Instant::now();
    for iteration in 0..iterations {
        let value = black_box(measured());
        checksum = checksum.rotate_left(9)
            ^ value.wrapping_add(iteration.wrapping_mul(0x9e37_79b9_7f4a_7c15));
    }
    let total_ns = start.elapsed().as_nanos();
    black_box(checksum);
    Timed {
        iterations,
        total_ns,
        checksum,
    }
}

fn identity_word(identity: RuntimeIdentity) -> u64 {
    u64::from_le_bytes(
        identity.as_bytes()[..8]
            .try_into()
            .expect("identity prefix has fixed length"),
    )
}

fn cache_identity_word(identity: fre_kernel_ir::CacheIdentity) -> u64 {
    u64::from_le_bytes(
        identity.as_bytes()[..8]
            .try_into()
            .expect("identity prefix has fixed length"),
    )
}

#[derive(Clone, Copy, Debug, Default)]
struct InstructionMix {
    instructions: usize,
    vector: usize,
    loads: usize,
    stores: usize,
    branches: usize,
}

impl InstructionMix {
    fn for_image(image: &NativeImage) -> Result<Self, fre_jit_aarch64::DecodeError> {
        Self::for_code(image.code())
    }

    fn for_code(code: &[u8]) -> Result<Self, fre_jit_aarch64::DecodeError> {
        let decoded = decode(code)?;
        let mut mix = Self {
            instructions: decoded.len(),
            ..Self::default()
        };
        for instruction in decoded {
            mix.vector = mix
                .vector
                .wrapping_add(usize::from(instruction.is_vector()));
            if matches!(
                instruction,
                DecodedInstruction::LoadByte { .. }
                    | DecodedInstruction::LoadByteRegister { .. }
                    | DecodedInstruction::Load64RegisterScaled { .. }
                    | DecodedInstruction::LoadVector128 { .. }
            ) {
                mix.loads = mix.loads.wrapping_add(1);
            }
            if matches!(instruction, DecodedInstruction::Store64 { .. }) {
                mix.stores = mix.stores.wrapping_add(1);
            }
            if matches!(
                instruction,
                DecodedInstruction::Branch { .. }
                    | DecodedInstruction::BranchCondition { .. }
                    | DecodedInstruction::CompareBranchZero64 { .. }
                    | DecodedInstruction::Return
            ) {
                mix.branches = mix.branches.wrapping_add(1);
            }
        }
        Ok(mix)
    }
}

#[derive(Clone, Copy, Debug)]
struct QualifiedV8ArtifactWitness {
    image: ImageStats,
    target: TargetSpec,
    backend: BackendVersion,
    artifact_sha256: [u8; 32],
    mix: InstructionMix,
}

#[derive(Clone, Debug)]
struct NativeArtifactEvidence {
    image: ImageStats,
    publication: PublicationAccounting,
    mix: InstructionMix,
    artifact_identity: String,
    identity_bytes_hashed: u64,
    identity_scratch_bytes: u64,
    identity_heap_allocations: u64,
}

#[derive(Clone, Debug)]
struct RowEvidence {
    artifact: Option<NativeArtifactEvidence>,
    output_kind: &'static str,
    backend: String,
    route: &'static str,
    evidence_identity: String,
    qualification_state: &'static str,
    qualification_bundle_sha256: String,
    evidence_binding: String,
    artifact_binding: &'static str,
    declared_min_window_bytes: usize,
    declared_min_qualifying_calls: usize,
    measured_calls: u64,
    measured_qualifying_calls: u64,
}

fn qualification_row_fields(
    qualification: QualifiedExactSearchQualification,
) -> Result<(&'static str, String), Box<dyn Error>> {
    match qualification {
        QualifiedExactSearchQualification::Candidate => Ok(("candidate", "none".to_owned())),
        QualifiedExactSearchQualification::Qualified { .. } => qualification
            .authorized_bundle_sha256()
            .map(|bundle| ("qualified", hex_encode(&bundle)))
            .ok_or_else(|| "qualified facade state carries an invalid bundle identity".into()),
    }
}

fn qualified_search_backend_label(
    backend: BackendVersion,
    abi: QualifiedExactSearchNativeAbi,
) -> Result<String, Box<dyn Error>> {
    if backend != BackendVersion::SEARCH_V8
        || abi != QualifiedExactSearchNativeAbi::SelectedEndRegisterV2
    {
        return Err(format!(
            "qualified facade reported backend {}/ABI {abi:?}, expected {}/SelectedEndRegisterV2",
            backend.0,
            BackendVersion::SEARCH_V8.0
        )
        .into());
    }
    Ok(format!(
        "aarch64-search-v{}-selected-end-register-v2",
        backend.0
    ))
}

fn qualified_row_evidence(
    qualified: &QualifiedExactSearch,
    route: QualifiedExactSearchRoute,
    witness: &QualifiedV8ArtifactWitness,
    haystack_bytes: usize,
    measured_calls: u64,
) -> Result<RowEvidence, Box<dyn Error>> {
    let report = qualified.build_report();
    if report.backend_policy != QualifiedExactSearchBackendPolicy::AsimdV8 {
        return Err(
            "qualified evidence owner was not built under the explicit ASIMD V8 policy".into(),
        );
    }
    let workload = report.workload;
    let (qualification_state, qualification_bundle_sha256) =
        qualification_row_fields(report.qualification)?;
    let (
        artifact,
        backend,
        route_name,
        native_abi,
        native_output,
        target,
        artifact_binding,
        artifact_identity,
    ) = match route {
        QualifiedExactSearchRoute::NativeJit => {
            let QualifiedExactSearchNativeStatus::Published {
                image,
                mapping,
                abi,
                sve_vector_bytes_at_publication,
                required_thread_sve_vector_bytes,
                identity,
                ..
            } = &report.native
            else {
                return Err("facade reported a native route without a published image".into());
            };
            if report.backend_policy != QualifiedExactSearchBackendPolicy::AsimdV8
                || identity.backend_policy != QualifiedExactSearchBackendPolicy::AsimdV8
                || identity.backend != BackendVersion::SEARCH_V8
                || *abi != QualifiedExactSearchNativeAbi::SelectedEndRegisterV2
                || identity.abi != QualifiedExactSearchNativeAbi::SelectedEndRegisterV2
                || identity.sve_vector_bytes_at_publication.is_some()
                || identity.required_thread_sve_vector_bytes.is_some()
                || sve_vector_bytes_at_publication.is_some()
                || required_thread_sve_vector_bytes.is_some()
            {
                return Err(
                    "qualified V8 route did not retain the syscall-free register ABI2 contract"
                        .into(),
                );
            }
            if *image != witness.image
                || identity.artifact_sha256 != witness.artifact_sha256
                || identity.backend != witness.backend
                || identity.target != witness.target
            {
                let message = "facade-reported V8 ABI2 identity differs from the deterministic register-return witness";
                return Err(message.into());
            }
            if identity.qualification != report.qualification {
                return Err(
                    "facade native identity differs from the build-report qualification state"
                        .into(),
                );
            }
            let backend = qualified_search_backend_label(identity.backend, identity.abi)?;
            (
                Some(NativeArtifactEvidence {
                    image: *image,
                    publication: *mapping,
                    mix: witness.mix,
                    artifact_identity: hex_encode(&identity.artifact_sha256),
                    // ABI2 exposes the precomputed digest directly. Reading it
                    // hashes no bytes and uses no scratch or heap allocation.
                    identity_bytes_hashed: 0,
                    identity_scratch_bytes: 0,
                    identity_heap_allocations: 0,
                }),
                backend,
                "native-jit",
                "selected-end-register-v2",
                "selected-end",
                "aarch64-aapcs64-asimd",
                "facade-reported-abi2-identity+deterministic-selected-end-register-v2-image",
                hex_encode(&identity.artifact_sha256),
            )
        }
        QualifiedExactSearchRoute::PortableLiteral => (
            None,
            "portable-literal".to_owned(),
            "portable-literal",
            "none",
            "none",
            "none",
            "portable-semantic-owner",
            "none".to_owned(),
        ),
    };
    let evidence_binding = format!(
        "fre-qualified-exact-evidence-v3|public_output=span|native_output={native_output}|native_abi={native_abi}|backend_policy=asimd-v8|target={target}|backend={backend}|route={route_name}|artifact={artifact_identity}|sve_vector_bytes_at_publication=none|required_thread_sve_vector_bytes=none|qualification_state={qualification_state}|qualification_bundle={qualification_bundle_sha256}|minimum_window_bytes={}|minimum_qualifying_calls={}",
        workload.minimum_window_bytes(),
        workload.minimum_qualifying_searches(),
    );
    let measured_qualifying_calls = if haystack_bytes >= workload.minimum_window_bytes() {
        measured_calls
    } else {
        0
    };
    Ok(RowEvidence {
        artifact,
        output_kind: "span",
        backend,
        route: route_name,
        evidence_identity: hex_digest(evidence_binding.as_bytes()),
        qualification_state,
        qualification_bundle_sha256,
        evidence_binding,
        artifact_binding,
        declared_min_window_bytes: workload.minimum_window_bytes(),
        declared_min_qualifying_calls: workload.minimum_qualifying_searches(),
        measured_calls,
        measured_qualifying_calls,
    })
}

#[derive(Debug)]
struct Sample {
    engine: &'static str,
    stage: &'static str,
    scope: &'static str,
    timed: Timed,
    evidence: Option<RowEvidence>,
}

impl Sample {
    const fn new(
        engine: &'static str,
        stage: &'static str,
        scope: &'static str,
        timed: Timed,
    ) -> Self {
        Self {
            engine,
            stage,
            scope,
            timed,
            evidence: None,
        }
    }

    fn with_evidence(mut self, evidence: RowEvidence) -> Self {
        self.evidence = Some(evidence);
        self
    }
}

#[derive(Debug)]
struct Metadata {
    cell: Cell,
    repetition: u32,
    haystack_bytes: usize,
    alignment_mod16: usize,
    semantic_value: u64,
    image: fre_jit_aarch64::ImageStats,
    publication: PublicationAccounting,
    mix: InstructionMix,
    identity: fre_jit_aarch64::ArtifactIdentityReceipt,
    cache_bookkeeping_bytes: u64,
    cache_hits: u128,
    fixture: &'static str,
}

fn print_header() {
    println!("{CSV_HEADER}");
}

#[allow(
    clippy::too_many_lines,
    reason = "one CSV serializer keeps the evidence columns and positional schema adjacent"
)]
fn format_sample(metadata: &Metadata, sample: &Sample) -> String {
    let revision = std::env::var("FRE_BAKEOFF_REVISION").unwrap_or_else(|_| "unknown".to_owned());
    let direct_artifact_identity = metadata.identity.identity.to_string();
    let (
        code_bytes,
        data_bytes,
        payload_used_bytes,
        total_mapped_bytes,
        total_pages,
        instructions,
        vector_instructions,
        loads,
        stores,
        branches,
        identity_bytes_hashed,
        identity_scratch_bytes,
        identity_heap_allocations,
    ) = match sample.evidence.as_ref() {
        Some(RowEvidence {
            artifact: Some(artifact),
            ..
        }) => (
            artifact.image.code_bytes,
            artifact.image.data_bytes,
            artifact.publication.payload_used_bytes,
            artifact.publication.total_mapped_bytes,
            artifact.publication.total_pages,
            artifact.mix.instructions,
            artifact.mix.vector,
            artifact.mix.loads,
            artifact.mix.stores,
            artifact.mix.branches,
            artifact.identity_bytes_hashed,
            artifact.identity_scratch_bytes,
            artifact.identity_heap_allocations,
        ),
        Some(RowEvidence { artifact: None, .. }) => (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        None => (
            metadata.image.code_bytes,
            metadata.image.data_bytes,
            metadata.publication.payload_used_bytes,
            metadata.publication.total_mapped_bytes,
            metadata.publication.total_pages,
            metadata.mix.instructions,
            metadata.mix.vector,
            metadata.mix.loads,
            metadata.mix.stores,
            metadata.mix.branches,
            metadata.identity.canonical_bytes_hashed,
            metadata.identity.scratch_bytes,
            metadata.identity.heap_allocations,
        ),
    };
    let evidence_artifact_identity = sample
        .evidence
        .as_ref()
        .and_then(|evidence| evidence.artifact.as_ref())
        .map(|artifact| artifact.artifact_identity.as_str());
    let (
        output_kind,
        backend,
        route,
        artifact_identity,
        evidence_identity,
        qualification_state,
        qualification_bundle_sha256,
        evidence_binding,
        artifact_binding,
        declared_min_window_bytes,
        declared_min_qualifying_calls,
        measured_calls,
        measured_qualifying_calls,
    ) = if let Some(evidence) = sample.evidence.as_ref() {
        (
            evidence.output_kind,
            evidence.backend.as_str(),
            evidence.route,
            evidence_artifact_identity.unwrap_or("none"),
            evidence.evidence_identity.as_str(),
            evidence.qualification_state,
            evidence.qualification_bundle_sha256.as_str(),
            evidence.evidence_binding.as_str(),
            evidence.artifact_binding,
            evidence.declared_min_window_bytes,
            evidence.declared_min_qualifying_calls,
            evidence.measured_calls,
            evidence.measured_qualifying_calls,
        )
    } else {
        let (route, artifact_identity, artifact_binding) = if sample.engine == "jit" {
            (
                "direct-image",
                direct_artifact_identity.as_str(),
                "executed-direct-image",
            )
        } else {
            ("reference", "none", "none")
        };
        (
            metadata.cell.operation.name(),
            sample.engine,
            route,
            artifact_identity,
            artifact_identity,
            "not-applicable",
            "none",
            "legacy-unqualified-row",
            artifact_binding,
            0,
            0,
            sample.timed.iterations,
            0,
        )
    };
    format!(
        "{SCHEMA},{revision},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{:#x},{:#x},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
        process::id(),
        metadata.repetition,
        metadata.cell.id(),
        metadata.cell.shape.name(),
        metadata.cell.operation.name(),
        metadata.cell.size.name(),
        metadata.cell.scenario.name(),
        metadata.haystack_bytes,
        metadata.alignment_mod16,
        sample.engine,
        sample.stage,
        sample.scope,
        sample.timed.iterations,
        sample.timed.total_ns,
        sample
            .timed
            .total_ns
            .checked_div(u128::from(sample.timed.iterations))
            .expect("measurement iterations are nonzero"),
        sample.timed.checksum,
        metadata.semantic_value,
        code_bytes,
        data_bytes,
        payload_used_bytes,
        total_mapped_bytes,
        total_pages,
        instructions,
        vector_instructions,
        loads,
        stores,
        branches,
        identity_bytes_hashed,
        identity_scratch_bytes,
        identity_heap_allocations,
        metadata.cache_bookkeeping_bytes,
        metadata.cache_hits,
        metadata.fixture,
        output_kind,
        backend,
        route,
        artifact_identity,
        evidence_identity,
        qualification_state,
        qualification_bundle_sha256,
        evidence_binding,
        artifact_binding,
        declared_min_window_bytes,
        declared_min_qualifying_calls,
        measured_calls,
        measured_qualifying_calls,
    )
}

fn print_sample(metadata: &Metadata, sample: &Sample) {
    println!("{}", format_sample(metadata, sample));
}

fn inspect_image(shape: Shape, operation: OperationName) -> Result<(), Box<dyn Error>> {
    match operation {
        OperationName::Exists => inspect_typed::<Exists>(shape),
        OperationName::SelectedEnd => inspect_typed::<SelectedEnd>(shape),
        OperationName::Span => inspect_typed::<Span>(shape),
    }?;
    if shape == Shape::Exact && operation == OperationName::Span {
        print_qualified_v8_abi2_witness()?;
    }
    Ok(())
}

fn inspect_typed<O: Operation>(shape: Shape) -> Result<(), Box<dyn Error>> {
    let program = build_program::<O>(shape)?;
    let image = emit(&program, EmitLimits::default())?;
    let mix = InstructionMix::for_image(&image)?;
    println!("shape={} output={:?}", shape.name(), O::KIND);
    println!("stats={:?}", image.stats());
    println!("layout={:?}", image.layout());
    println!("mix={mix:?}");
    println!("identity={}", image.artifact_identity());
    for (index, instruction) in decode(image.code())?.iter().enumerate() {
        println!("{:#06x} {instruction:?}", index.wrapping_mul(4));
    }
    Ok(())
}

fn print_qualified_v8_abi2_witness() -> Result<(), Box<dyn Error>> {
    let witness = qualified_v8_artifact_witness()?;
    println!("abi2_witness_schema=fre-jit-bakeoff-v3-asimd-v8-selected-end-register-v2-witness-v1");
    println!("abi2_backend_policy=asimd-v8");
    println!("abi2_target=aarch64-aapcs64-asimd");
    println!("abi2_backend={}", witness.backend.0);
    println!("abi2_native_output=selected-end");
    println!("abi2_native_abi=selected-end-register-v2");
    println!("abi2_sve_vector_bytes_at_publication=none");
    println!("abi2_required_thread_sve_vector_bytes=none");
    println!("abi2_identity={}", hex_encode(&witness.artifact_sha256));
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "fixture authentication and its timing boundaries stay visibly coupled"
)]
fn run_sherlock(path: &Path, repetition: u32) -> Result<(), Box<dyn Error>> {
    let haystack = fs::read(path)?;
    if haystack.len() != SHERLOCK_BYTES {
        return Err(format!(
            "Sherlock fixture length mismatch: expected {}, got {}",
            SHERLOCK_BYTES,
            haystack.len()
        )
        .into());
    }
    let digest = hex_digest(&haystack);
    if digest != SHERLOCK_SHA256 {
        return Err(format!(
            "Sherlock fixture SHA-256 mismatch: expected {SHERLOCK_SHA256}, got {digest}"
        )
        .into());
    }
    let program = build_exact_literal::<Span>(
        SHERLOCK_LITERAL,
        AnchorFlags::default(),
        ValidateLimits::default(),
    )?;
    let image = emit(&program, EmitLimits::default())?;
    let published = publish::<Span>(&image, PublicationLimits::default())?;
    let regex = RegexBuilder::new("Sherlock Holmes")
        .unicode(false)
        .build()?;
    let plan = LiteralPlan::new(SHERLOCK_LITERAL, LiteralBuildLimits::default())?;

    let expected = count_regex(&regex, &haystack);
    let jit = count_jit(&published, &haystack)?;
    let kernels = count_literal_plan(&plan, &haystack)?;
    if expected.count != SHERLOCK_MATCHES || jit != expected || kernels != expected {
        return Err(format!(
            "Sherlock count authentication failed: expected_count={SHERLOCK_MATCHES}, regex={expected:?}, JIT={jit:?}, fre-kernels={kernels:?}"
        )
        .into());
    }

    let window = SearchWindow::new(0, haystack.len());
    let oracle_first = program
        .execute(&haystack, window, ExecutionLimits::unlimited())?
        .into_output();
    let jit_first = published.search(&haystack, window)?;
    if oracle_first != jit_first {
        return Err("Sherlock first-span oracle/JIT mismatch".into());
    }

    let cache = KernelCache::<Span>::new(CacheLimits::default(), PublicationLimits::default())?;
    drop(cache.get_or_publish(&image)?);
    let hot_iterations = 20;
    let samples = [
        Sample::new(
            "jit",
            "rebar_count_direct",
            "hot_compile_and_mapping_excluded",
            measure(hot_iterations, || {
                count_jit(&published, black_box(&haystack))
                    .expect("authenticated JIT count")
                    .checksum
            }),
        ),
        Sample::new(
            "jit",
            "rebar_count_cache_lookup",
            "hot_compile_and_initial_publication_excluded",
            measure(hot_iterations, || {
                let lease = cache
                    .get_or_publish(black_box(&image))
                    .expect("resident lookup");
                count_jit(&lease, black_box(&haystack))
                    .expect("authenticated cached JIT count")
                    .checksum
            }),
        ),
        Sample::new(
            "rust-regex-1.12.4",
            "rebar_count",
            "hot_compile_excluded",
            measure(hot_iterations, || {
                count_regex(&regex, black_box(&haystack)).checksum
            }),
        ),
        Sample::new(
            "fre-kernels",
            "rebar_count",
            "hot_plan_build_excluded",
            measure(hot_iterations, || {
                count_literal_plan(&plan, black_box(&haystack))
                    .expect("authenticated plan count")
                    .checksum
            }),
        ),
    ];
    let snapshot = cache.snapshot();
    let metadata = Metadata {
        cell: Cell {
            shape: Shape::Exact,
            operation: OperationName::Span,
            size: Size::M1,
            scenario: Scenario::Present,
        },
        repetition,
        haystack_bytes: haystack.len(),
        alignment_mod16: haystack.as_ptr().addr() & 15,
        semantic_value: u64::try_from(expected.count).unwrap_or(u64::MAX),
        image: image.stats(),
        publication: published.accounting(),
        mix: InstructionMix::for_image(&image)?,
        identity: image.artifact_identity_receipt(),
        cache_bookkeeping_bytes: snapshot.current.bookkeeping_bytes,
        cache_hits: snapshot.totals.hits,
        fixture: "rebar-sherlock-en-count-513",
    };
    for sample in samples {
        print_fixture_sample(&metadata, &sample);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CountResult {
    count: usize,
    checksum: u64,
}

fn count_regex(regex: &Regex, haystack: &[u8]) -> CountResult {
    let mut result = CountResult {
        count: 0,
        checksum: 0,
    };
    for matched in regex.find_iter(haystack) {
        result.count = result.count.wrapping_add(1);
        result.checksum = fold_span(result.checksum, matched.start(), matched.end());
    }
    result
}

trait SpanSearch {
    fn span_search(
        &self,
        haystack: &[u8],
        window: SearchWindow,
    ) -> Result<Option<fre_kernel_ir::MatchSpan>, fre_jit_runtime::CallError>;
}

impl SpanSearch for fre_jit_runtime::PublishedKernel<Span> {
    fn span_search(
        &self,
        haystack: &[u8],
        window: SearchWindow,
    ) -> Result<Option<fre_kernel_ir::MatchSpan>, fre_jit_runtime::CallError> {
        self.search(haystack, window)
    }
}

impl SpanSearch for fre_jit_cache::KernelLease<Span> {
    fn span_search(
        &self,
        haystack: &[u8],
        window: SearchWindow,
    ) -> Result<Option<fre_kernel_ir::MatchSpan>, fre_jit_runtime::CallError> {
        self.search(haystack, window)
    }
}

fn count_jit(
    kernel: &impl SpanSearch,
    haystack: &[u8],
) -> Result<CountResult, fre_jit_runtime::CallError> {
    let mut result = CountResult {
        count: 0,
        checksum: 0,
    };
    let mut start = 0;
    while start <= haystack.len() {
        let Some(matched) =
            kernel.span_search(haystack, SearchWindow::new(start, haystack.len()))?
        else {
            break;
        };
        result.count = result.count.wrapping_add(1);
        result.checksum = fold_span(result.checksum, matched.start(), matched.end());
        start = matched.end();
    }
    Ok(result)
}

fn count_literal_plan(
    plan: &LiteralPlan,
    haystack: &[u8],
) -> Result<CountResult, fre_kernels::LiteralError> {
    let mut result = CountResult {
        count: 0,
        checksum: 0,
    };
    let mut start = 0;
    while start <= haystack.len() {
        let Some((matched_start, matched_end)) = plan
            .find_window(
                haystack,
                fre_kernels::Window::new(start, haystack.len()),
                LiteralSearchLimits::unlimited(),
            )?
            .0
        else {
            break;
        };
        result.count = result.count.wrapping_add(1);
        result.checksum = fold_span(result.checksum, matched_start, matched_end);
        start = matched_end;
    }
    Ok(result)
}

fn fold_span(checksum: u64, start: usize, end: usize) -> u64 {
    let start = u64::try_from(start).unwrap_or(u64::MAX);
    let end = u64::try_from(end).unwrap_or(u64::MAX);
    checksum.rotate_left(7) ^ start.rotate_left(19) ^ end.rotate_left(43)
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use fmt::Write as _;
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use fmt::Write as _;
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn format_fixture_sample(metadata: &Metadata, sample: &Sample) -> String {
    let fixture_cell = "exact-count-rebar-sherlock";
    let revision = std::env::var("FRE_BAKEOFF_REVISION").unwrap_or_else(|_| "unknown".to_owned());
    let direct_artifact_identity = metadata.identity.identity.to_string();
    let (backend, route, artifact_identity, artifact_binding) = if sample.engine == "jit" {
        (
            "aarch64-jit",
            "direct-span-loop",
            direct_artifact_identity.as_str(),
            "executed-direct-image",
        )
    } else {
        (sample.engine, "reference", "none", "none")
    };
    [
        SCHEMA.to_owned(),
        revision,
        process::id().to_string(),
        metadata.repetition.to_string(),
        fixture_cell.to_owned(),
        "exact".to_owned(),
        "count".to_owned(),
        "rebar".to_owned(),
        "sherlock".to_owned(),
        metadata.haystack_bytes.to_string(),
        metadata.alignment_mod16.to_string(),
        sample.engine.to_owned(),
        sample.stage.to_owned(),
        sample.scope.to_owned(),
        sample.timed.iterations.to_string(),
        sample.timed.total_ns.to_string(),
        sample
            .timed
            .total_ns
            .checked_div(u128::from(sample.timed.iterations))
            .expect("measurement iterations are nonzero")
            .to_string(),
        format!("{:#x}", sample.timed.checksum),
        format!("{:#x}", metadata.semantic_value),
        metadata.image.code_bytes.to_string(),
        metadata.image.data_bytes.to_string(),
        metadata.publication.payload_used_bytes.to_string(),
        metadata.publication.total_mapped_bytes.to_string(),
        metadata.publication.total_pages.to_string(),
        metadata.mix.instructions.to_string(),
        metadata.mix.vector.to_string(),
        metadata.mix.loads.to_string(),
        metadata.mix.stores.to_string(),
        metadata.mix.branches.to_string(),
        metadata.identity.canonical_bytes_hashed.to_string(),
        metadata.identity.scratch_bytes.to_string(),
        metadata.identity.heap_allocations.to_string(),
        metadata.cache_bookkeeping_bytes.to_string(),
        metadata.cache_hits.to_string(),
        metadata.fixture.to_owned(),
        "span-loop-count".to_owned(),
        backend.to_owned(),
        route.to_owned(),
        artifact_identity.to_owned(),
        artifact_identity.to_owned(),
        "not-applicable".to_owned(),
        "none".to_owned(),
        "legacy-sherlock-row".to_owned(),
        artifact_binding.to_owned(),
        "0".to_owned(),
        "0".to_owned(),
        sample.timed.iterations.to_string(),
        "0".to_owned(),
    ]
    .join(",")
}

fn print_fixture_sample(metadata: &Metadata, sample: &Sample) {
    println!("{}", format_fixture_sample(metadata, sample));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact_cell(scenario: Scenario) -> Cell {
        Cell {
            shape: Shape::Exact,
            operation: OperationName::Span,
            size: Size::Short,
            scenario,
        }
    }

    fn match_offsets(haystack: &[u8]) -> Vec<usize> {
        haystack
            .windows(EXACT_LITERAL.len())
            .enumerate()
            .filter_map(|(offset, window)| (window == EXACT_LITERAL).then_some(offset))
            .collect()
    }

    #[test]
    fn exact_literal_pair_selection_is_pinned() {
        assert_eq!(selected_pair(EXACT_LITERAL), (7, 6));
        assert_eq!(selected_verification(EXACT_LITERAL, 7, 6), Some(0));
    }

    #[test]
    fn primary_dense_secondary_absent_has_no_pair_or_match() {
        let owned = make_haystack(exact_cell(Scenario::PrimaryDenseSecondaryAbsent));
        let haystack = owned.as_slice();
        let (primary, secondary) = selected_pair(EXACT_LITERAL);
        assert!(haystack.iter().all(|&byte| byte == EXACT_LITERAL[primary]));
        assert!(!haystack.contains(&EXACT_LITERAL[secondary]));
        assert!(match_offsets(haystack).is_empty());
    }

    #[test]
    fn selected_pair_is_dense_without_full_literal() {
        let owned = make_haystack(exact_cell(Scenario::PairDenseLiteralAbsent));
        let haystack = owned.as_slice();
        let (primary, secondary) = selected_pair(EXACT_LITERAL);
        let last_start = haystack
            .len()
            .checked_sub(EXACT_LITERAL.len())
            .expect("literal fits test haystack");
        let pair_candidates = (0..=last_start)
            .filter(|&candidate| {
                let primary_index = candidate
                    .checked_add(primary)
                    .expect("selected pair fits test haystack");
                let secondary_index = candidate
                    .checked_add(secondary)
                    .expect("selected pair fits test haystack");
                haystack[primary_index] == EXACT_LITERAL[primary]
                    && haystack[secondary_index] == EXACT_LITERAL[secondary]
            })
            .count();
        assert!(pair_candidates >= 5);
        assert!(match_offsets(haystack).is_empty());
    }

    #[test]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "candidate and selected offsets are bounded by the immediately preceding last-start proof"
    )]
    fn selected_triple_is_dense_without_full_literal() {
        let owned = make_haystack(exact_cell(Scenario::TripleDenseLiteralAbsent));
        let haystack = owned.as_slice();
        let (primary, secondary) = selected_pair(EXACT_LITERAL);
        let verification = selected_verification(EXACT_LITERAL, primary, secondary)
            .expect("pinned verification offset");
        let last_start = haystack
            .len()
            .checked_sub(EXACT_LITERAL.len())
            .expect("literal fits test haystack");
        let triple_candidates = (0..=last_start)
            .filter(|&candidate| {
                haystack[candidate + primary] == EXACT_LITERAL[primary]
                    && haystack[candidate + secondary] == EXACT_LITERAL[secondary]
                    && haystack[candidate + verification] == EXACT_LITERAL[verification]
            })
            .count();
        assert!(triple_candidates >= 5);
        assert!(match_offsets(haystack).is_empty());
    }

    #[test]
    fn false_pair_precedes_only_full_match() {
        let owned = make_haystack(exact_cell(Scenario::FalsePairDistantMatch));
        let haystack = owned.as_slice();
        let (primary, secondary) = selected_pair(EXACT_LITERAL);
        assert_eq!(haystack[primary], EXACT_LITERAL[primary]);
        assert_eq!(haystack[secondary], EXACT_LITERAL[secondary]);
        assert_ne!(&haystack[..EXACT_LITERAL.len()], EXACT_LITERAL);
        assert_eq!(
            match_offsets(haystack),
            vec![
                haystack
                    .len()
                    .checked_sub(EXACT_LITERAL.len())
                    .expect("literal fits test haystack")
            ]
        );
    }

    #[test]
    fn binary_and_natural_corpora_have_one_distant_match() {
        for scenario in [Scenario::Binary, Scenario::NaturalText] {
            let owned = make_haystack(exact_cell(scenario));
            let haystack = owned.as_slice();
            assert_eq!(
                match_offsets(haystack),
                vec![distant_position(haystack.len(), EXACT_LITERAL.len())]
            );
        }
    }

    #[test]
    fn qualified_v8_abi2_session_and_evidence_boundaries_are_source_sealed() {
        fn between<'source>(source: &'source str, start: &str, end: &str) -> &'source str {
            let start = source
                .find(start)
                .unwrap_or_else(|| panic!("missing ABI2 source marker: {start}"));
            let end = start
                + source[start..]
                    .find(end)
                    .unwrap_or_else(|| panic!("missing ABI2 source marker: {end}"));
            &source[start..end]
        }

        let source = include_str!("main.rs");
        assert!(source.contains("const SCHEMA: &str = \"fre-jit-bakeoff-v3\";"));
        let builder = between(
            source,
            "fn build_qualified_v8(",
            "\nfn qualified_v8_artifact_witness(",
        );
        assert!(builder.contains("QualifiedExactSearch::new_with_backend("));
        assert!(builder.contains("QualifiedExactSearchBackendPolicy::AsimdV8"));
        let witness = between(
            source,
            "fn qualified_v8_artifact_witness(",
            "\n/// Time the complete qualified lifecycle",
        );
        assert!(witness.contains("SelectedEndRegisterBackendV2::AsimdV8"));
        assert!(witness.contains("BackendVersion::SEARCH_V8"));
        assert!(witness.contains("TargetSpec::AARCH64_AAPCS64"));

        let bench = between(
            source,
            "fn bench<O: BenchOperation>(",
            "\nfn build_qualified_v8(",
        );
        let session = bench
            .find("let qualified_session")
            .expect("qualified session construction");
        let hot = bench.find("let search_timed").expect("qualified hot timer");
        assert!(session < hot);
        assert!(bench[hot..].contains("qualified_session\n                .find_value("));
        assert!(!bench[hot..].contains("qualified\n                .find("));
        for scope in [
            "session_value_search_declared_workload_build_and_session_excluded",
            "build_plus_session_plus_declared_workload_amortized_per_value_search",
            "session_value_search_forced_portable_build_and_session_excluded",
            "portable_build_plus_session_plus_declared_workload_amortized_per_value_search",
        ] {
            assert!(bench.contains(scope));
        }

        let full = between(
            source,
            "fn measure_qualified_full_workload<O: BenchOperation>(",
            "\nfn build_program<O: Operation>(",
        );
        let build = full
            .find("let qualified = build_qualified_v8(workload)")
            .expect("full-workload facade build");
        let session = full
            .find(".begin_current_thread_session()")
            .expect("full-workload session");
        let loop_start = full.find("for iteration in 0..calls").expect("value loop");
        assert!(build < session && session < loop_start);
        assert!(full[loop_start..].contains(".find_value("));
        assert!(full.contains("let total_ns = start.elapsed().as_nanos();"));

        let evidence = between(
            source,
            "fn qualified_row_evidence(",
            "\n#[derive(Debug)]\nstruct Sample",
        );
        assert!(evidence.contains("QualifiedExactSearchNativeAbi::SelectedEndRegisterV2"));
        assert!(evidence.contains("BackendVersion::SEARCH_V8"));
        assert!(evidence.contains("fre-qualified-exact-evidence-v3"));
        assert!(evidence.contains("deterministic-selected-end-register-v2-image"));
        assert!(evidence.contains("backend_policy=asimd-v8"));
        assert!(evidence.contains("target={target}"));
        assert!(evidence.contains("sve_vector_bytes_at_publication=none"));
        assert!(evidence.contains("required_thread_sve_vector_bytes=none"));

        let inspect = between(
            source,
            "fn inspect_image(",
            "\n#[allow(\n    clippy::too_many_lines",
        );
        for fact in [
            "abi2_witness_schema=fre-jit-bakeoff-v3-asimd-v8-selected-end-register-v2-witness-v1",
            "abi2_backend_policy=asimd-v8",
            "abi2_target=aarch64-aapcs64-asimd",
            "abi2_native_output=selected-end",
            "abi2_native_abi=selected-end-register-v2",
            "abi2_sve_vector_bytes_at_publication=none",
            "abi2_required_thread_sve_vector_bytes=none",
            "abi2_identity=",
        ] {
            assert!(inspect.contains(fact));
        }
    }

    #[test]
    fn normal_and_sherlock_rows_exactly_match_the_v3_csv_schema() {
        assert_eq!(SCHEMA, "fre-jit-bakeoff-v3");
        let cell = exact_cell(Scenario::Absent);
        let program = build_program::<Span>(cell.shape).expect("test program");
        let image = emit(&program, EmitLimits::default()).expect("test image");
        let published =
            publish::<Span>(&image, PublicationLimits::default()).expect("test publication");
        let metadata = Metadata {
            cell,
            repetition: 7,
            haystack_bytes: 64,
            alignment_mod16: 0,
            semantic_value: 0,
            image: image.stats(),
            publication: published.accounting(),
            mix: InstructionMix::for_image(&image).expect("test instruction mix"),
            identity: image.artifact_identity_receipt(),
            cache_bookkeeping_bytes: 0,
            cache_hits: 0,
            fixture: "schema-test",
        };
        let sample = Sample::new(
            "jit",
            "direct_lease_call",
            "schema_test",
            Timed {
                iterations: 1,
                total_ns: 1,
                checksum: 1,
            },
        );
        let header: Vec<_> = CSV_HEADER.split(',').collect();
        let normal = format_sample(&metadata, &sample);
        let sherlock = format_fixture_sample(&metadata, &sample);
        let normal_columns: Vec<_> = normal.split(',').collect();
        let sherlock_columns: Vec<_> = sherlock.split(',').collect();
        assert_eq!(header.len(), 48);
        assert_eq!(normal_columns.len(), header.len());
        assert_eq!(sherlock_columns.len(), header.len());
        let state = header
            .iter()
            .position(|column| *column == "qualification_state")
            .expect("qualification-state column");
        let bundle = header
            .iter()
            .position(|column| *column == "qualification_bundle_sha256")
            .expect("qualification-bundle column");
        assert_eq!(normal_columns[state], "not-applicable");
        assert_eq!(normal_columns[bundle], "none");
        assert_eq!(sherlock_columns[state], "not-applicable");
        assert_eq!(sherlock_columns[bundle], "none");
    }
}
