use std::{error::Error, fmt, fs, hint::black_box, path::Path, process, time::Instant};

use fre_jit_aarch64::{DecodedInstruction, EmitLimits, NativeImage, decode, emit};
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
use regex::bytes::{Regex, RegexBuilder};
use sha2::{Digest, Sha256};

const SCHEMA: &str = "fre-jit-bakeoff-v1";
const EXACT_LITERAL: &[u8] = b"0123456789abcdef";
const LITERAL_1: &[u8] = b"a";
const LITERAL_6: &[u8] = b"needle";
const CLASS_BYTES: &[u8] = b"a";
const CLASS_SUFFIX: &[u8] = b"bcdefghijklmnopq";
const SHERLOCK_LITERAL: &[u8] = b"Sherlock Holmes";
const SHERLOCK_BYTES: usize = 899_232;
const SHERLOCK_MATCHES: usize = 513;
const SHERLOCK_SHA256: &str = "0d40805f6d02c8fe02bd75945b98911891f707e8ecb939e018446858065d76ea";

fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = std::env::args().collect();
    match arguments.get(1).map(String::as_str) {
        Some("header") if arguments.len() == 2 => print_header(),
        Some("list") if arguments.len() == 2 => list_cells(),
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
                "usage: {} header | list | run SHAPE OP SIZE SCENARIO REP | sherlock PATH REP | inspect SHAPE OP",
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
            Self::K64 => 500,
            Self::M1 => 32,
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
}

impl Scenario {
    fn parse(text: &str) -> Result<Self, ParseError> {
        match text {
            "present" => Ok(Self::Present),
            "absent" => Ok(Self::Absent),
            "dense" => Ok(Self::Dense),
            "tail" => Ok(Self::Tail),
            "unaligned" => Ok(Self::Unaligned),
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

    let oracle = O::encode(
        &program
            .execute(haystack, window, ExecutionLimits::unlimited())?
            .into_output(),
    );
    let regex_value = O::regex_search(&regex, haystack);
    let kernels_value = O::encode_span(native_plan.find(haystack)?);
    ensure_equal("regex", oracle, regex_value, cell)?;
    ensure_equal("fre-kernels", oracle, kernels_value, cell)?;

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
        let lease = cache.get_or_publish(&image)?;
        black_box(O::encode(&lease.search(black_box(haystack), window)?));
    }

    let hot_iterations = cell.size.hot_iterations();
    let mut samples = Vec::with_capacity(10);
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
        fixture: "synthetic-v1",
    };
    for sample in samples {
        print_sample(&metadata, &sample);
    }
    Ok(())
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
    }
    OwnedHaystack {
        storage,
        start,
        length,
    }
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
        let decoded = decode(image.code())?;
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

#[derive(Debug)]
struct Sample {
    engine: &'static str,
    stage: &'static str,
    scope: &'static str,
    timed: Timed,
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
        }
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
    println!(
        "schema,revision,pid,repetition,cell,shape,operation,size,scenario,haystack_bytes,alignment_mod16,engine,stage,timing_scope,iterations,total_ns,ns_per_iter,checksum,semantic_value,code_bytes,data_bytes,payload_used_bytes,total_mapped_bytes,total_pages,instructions,vector_instructions,loads,stores,branches,identity_bytes_hashed,identity_scratch_bytes,identity_heap_allocations,cache_bookkeeping_bytes,cache_hits,fixture"
    );
}

fn print_sample(metadata: &Metadata, sample: &Sample) {
    let revision = std::env::var("FRE_BAKEOFF_REVISION").unwrap_or_else(|_| "unknown".to_owned());
    println!(
        "{SCHEMA},{revision},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{:#x},{:#x},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
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
        metadata.cache_bookkeeping_bytes,
        metadata.cache_hits,
        metadata.fixture,
    );
}

fn inspect_image(shape: Shape, operation: OperationName) -> Result<(), Box<dyn Error>> {
    match operation {
        OperationName::Exists => inspect_typed::<Exists>(shape),
        OperationName::SelectedEnd => inspect_typed::<SelectedEnd>(shape),
        OperationName::Span => inspect_typed::<Span>(shape),
    }
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

fn count_jit(
    kernel: &fre_jit_runtime::PublishedKernel<Span>,
    haystack: &[u8],
) -> Result<CountResult, fre_jit_runtime::CallError> {
    let mut result = CountResult {
        count: 0,
        checksum: 0,
    };
    let mut start = 0;
    while start <= haystack.len() {
        let Some(matched) = kernel.search(haystack, SearchWindow::new(start, haystack.len()))?
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

fn print_fixture_sample(metadata: &Metadata, sample: &Sample) {
    let fixture_cell = "exact-count-rebar-sherlock";
    let revision = std::env::var("FRE_BAKEOFF_REVISION").unwrap_or_else(|_| "unknown".to_owned());
    println!(
        "{SCHEMA},{revision},{},{},{fixture_cell},exact,count,rebar,sherlock,{},{},{},{},{},{},{},{},{:#x},{:#x},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
        process::id(),
        metadata.repetition,
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
        metadata.cache_bookkeeping_bytes,
        metadata.cache_hits,
        metadata.fixture,
    );
}
