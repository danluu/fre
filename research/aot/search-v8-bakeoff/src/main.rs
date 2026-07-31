#![cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code, unused_imports)
)]

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
compile_error!("the Search V8 Mach-O bakeoff requires arm64 macOS");

use std::{error::Error, hint::black_box, path::Path, time::Instant};

use fre::{
    PlanKind, PortableBuilder, PortableRegex, RustProfile, SearchLimits,
    SearchWindow as PortableSearchWindow,
};
use fre_aot_compiler::{
    MacosAarch64ExactSearchManifestV1, SearchAotRuntimeAuthorityV1, SearchCompiledObjectV1,
    plan_and_compile_macos_aarch64_exact_search_v1,
};
use fre_aot_macho::{BindingIdentity, ObjectLimits, emit_search_object, validate_search_object};
use fre_jit_aarch64::{
    BackendVersion, EmitLimits, NativeImage, SearchBackendPolicy, emit_with_backend,
};
use fre_jit_runtime::{PublicationLimits, PublishedKernel, RuntimeIdentity, publish};
use fre_kernel_ir::{
    AnchorFlags, ExecutionLimits, MatchSpan, SearchWindow as KirSearchWindow, Span, ValidateLimits,
    ValidatedProgram, build_exact_literal,
};

const PATTERN: &str = "0123456789abcdef";
const LITERAL: &[u8] = PATTERN.as_bytes();
const HOT_SCHEMA: &str = "fre-search-v8-bakeoff-hot-v1";
const COLD_SCHEMA: &str = "fre-search-v8-bakeoff-cold-v1";
const FIRST_CALL_SCHEMA: &str = "fre-search-v8-bakeoff-ready-first-call-v1";
const LIFECYCLE_SCHEMA: &str = "fre-search-v8-bakeoff-lifecycle-v1";
const HOT_HEADER: &str = "schema,revision,pid,repetition,cell,size,scenario,order,engine,stage,iterations,total_ns,ns_per_iter,checksum,semantic_value,haystack_bytes,window_start,window_end,alignment_mod16,route,authority,backend,qualification_state,production_activation,benchmark_source_sha256,semantic_identity,source_identity,artifact_identity,compile_identity,object_identity,payload_sha256";
const COLD_HEADER: &str = "schema,revision,pid,repetition,order,phase,iterations,total_ns,ns_per_iter,checksum,scope,qualification_state,production_activation,benchmark_source_sha256,semantic_identity,source_identity,artifact_identity,compile_identity,object_identity,payload_sha256";
const FIRST_CALL_HEADER: &str = "schema,revision,pid,repetition,cell,size,scenario,engine,stage,iterations,total_ns,ns_per_iter,checksum,semantic_value,haystack_bytes,alignment_mod16,route,authority,backend,qualification_state,production_activation,benchmark_source_sha256,semantic_identity,source_identity,artifact_identity,compile_identity,object_identity,payload_sha256";
const LIFECYCLE_HEADER: &str = "schema,revision,pid,repetition,cell,size,scenario,calls,order,engine,stage,total_ns,checksum,semantic_value,haystack_bytes,alignment_mod16,route,authority,backend,qualification_state,production_activation,benchmark_source_sha256,semantic_identity,source_identity,artifact_identity,compile_identity,object_identity,payload_sha256";
const BYTES_PER_HOT_SAMPLE: usize = 64 * 1024 * 1024;
const HOT_REPETITIONS: u32 = 12;
const COLD_REPETITIONS: u32 = 12;
const COLD_ITERATIONS: usize = 20;
const FIRST_CALL_REPETITIONS: u32 = 20;
const LIFECYCLE_REPETITIONS: u32 = 24;
const LIFECYCLE_CHECKSUM_SEED: u64 = 0xbb67_ae85_84ca_a73b;
const LIFECYCLE_64K_CALLS: [usize; 12] = [0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024];
const LIFECYCLE_1M_CALLS: [usize; 8] = [0, 1, 2, 4, 8, 16, 32, 64];
const NAMED_SCENARIO_COUNT: usize = 11;
const ALIGNMENT_SCENARIO_COUNT: usize = 16;
const CASES_PER_SIZE: usize = NAMED_SCENARIO_COUNT + ALIGNMENT_SCENARIO_COUNT;
const SIZE_COUNT: usize = 2;
const HOT_CELLS: usize = CASES_PER_SIZE * SIZE_COUNT;
const V8_WIDE_CANDIDATE_STARTS: usize = 64;
const V8_PRIMARY_OFFSET: usize = 7;
const V8_SECONDARY_OFFSET: usize = 6;
const POISON_START: usize = 0xa5a5_a5a5_a5a5_a5a5;
const POISON_END: usize = 0x5a5a_5a5a_5a5a_5a5a;
const EMPTY_ANCHOR: u8 = 0;

#[allow(
    unsafe_code,
    reason = "generated declaration binds the exact receipt-derived raw AOT symbol"
)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/fre_search_v8_span_bindings.rs"));
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RawSpan {
    start: usize,
    end: usize,
}

type AnyError = Box<dyn Error>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Engine {
    RawStaticAot,
    StrictWxJit,
    Portable,
}

impl Engine {
    const ALL: [Self; 3] = [Self::RawStaticAot, Self::StrictWxJit, Self::Portable];

    fn parse(value: &str) -> Result<Self, AnyError> {
        match value {
            "raw-static-aot" => Ok(Self::RawStaticAot),
            "strict-wx-jit" => Ok(Self::StrictWxJit),
            "portable" => Ok(Self::Portable),
            _ => Err(format!("invalid engine {value:?}").into()),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::RawStaticAot => "raw-static-aot",
            Self::StrictWxJit => "strict-wx-jit",
            Self::Portable => "portable",
        }
    }

    const fn route(self) -> &'static str {
        match self {
            Self::RawStaticAot => "raw-statically-linked-aot",
            Self::StrictWxJit => "strict-wx-published-jit",
            Self::Portable => "portable-exact-literal",
        }
    }

    const fn authority(self) -> &'static str {
        match self {
            Self::RawStaticAot => "benchmark-local-raw-abi-no-adoption",
            Self::StrictWxJit => "runtime-audited-candidate",
            Self::Portable => "portable",
        }
    }

    const fn backend(self) -> &'static str {
        match self {
            Self::RawStaticAot => "aarch64-search-v8-static",
            Self::StrictWxJit => "aarch64-search-v8",
            Self::Portable => "portable",
        }
    }
}

const ENGINE_ORDERS: [[Engine; 3]; 6] = [
    [Engine::RawStaticAot, Engine::StrictWxJit, Engine::Portable],
    [Engine::RawStaticAot, Engine::Portable, Engine::StrictWxJit],
    [Engine::StrictWxJit, Engine::RawStaticAot, Engine::Portable],
    [Engine::StrictWxJit, Engine::Portable, Engine::RawStaticAot],
    [Engine::Portable, Engine::RawStaticAot, Engine::StrictWxJit],
    [Engine::Portable, Engine::StrictWxJit, Engine::RawStaticAot],
];

const LIFECYCLE_ENGINE_ORDERS: [[Engine; 2]; 2] = [
    [Engine::Portable, Engine::StrictWxJit],
    [Engine::StrictWxJit, Engine::Portable],
];

fn engine_order(repetition: u32) -> ([Engine; 3], String) {
    let index = usize::try_from(repetition).expect("bounded repetition") % ENGINE_ORDERS.len();
    let order = ENGINE_ORDERS[index];
    (
        order,
        format!(
            "{}+{}+{}",
            order[0].name(),
            order[1].name(),
            order[2].name()
        ),
    )
}

fn lifecycle_engine_order(repetition: u32) -> ([Engine; 2], String) {
    let index =
        usize::try_from(repetition).expect("bounded repetition") % LIFECYCLE_ENGINE_ORDERS.len();
    let order = LIFECYCLE_ENGINE_ORDERS[index];
    (order, format!("{}+{}", order[0].name(), order[1].name()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Size {
    K64,
    M1,
}

impl Size {
    fn parse(value: &str) -> Result<Self, AnyError> {
        match value {
            "64k" => Ok(Self::K64),
            "1m" => Ok(Self::M1),
            _ => Err(format!("invalid size {value:?}").into()),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::K64 => "64k",
            Self::M1 => "1m",
        }
    }

    const fn bytes(self) -> usize {
        match self {
            Self::K64 => 64 * 1024,
            Self::M1 => 1024 * 1024,
        }
    }

    fn hot_iterations(self) -> Result<usize, AnyError> {
        let iterations = BYTES_PER_HOT_SAMPLE
            .checked_div(self.bytes())
            .ok_or("zero-size hot fixture")?;
        if iterations
            .checked_mul(self.bytes())
            .ok_or("hot byte accounting overflow")?
            != BYTES_PER_HOT_SAMPLE
        {
            return Err("fixture size does not divide fixed hot sample bytes".into());
        }
        Ok(iterations)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NamedScenario {
    Present,
    Absent,
    Dense,
    Tail,
    PrimaryDenseSecondaryAbsent,
    AdaptiveSecondaryDensePrimaryAbsent,
    PairDenseLiteralAbsent,
    TripleDenseLiteralAbsent,
    FalsePairDistantMatch,
    Binary,
    NaturalText,
}

impl NamedScenario {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "present" => Some(Self::Present),
            "absent" => Some(Self::Absent),
            "dense" => Some(Self::Dense),
            "tail" => Some(Self::Tail),
            "primary-dense-secondary-absent" => Some(Self::PrimaryDenseSecondaryAbsent),
            "adaptive-secondary-dense-primary-absent" => {
                Some(Self::AdaptiveSecondaryDensePrimaryAbsent)
            }
            "pair-dense-literal-absent" => Some(Self::PairDenseLiteralAbsent),
            "triple-dense-literal-absent" => Some(Self::TripleDenseLiteralAbsent),
            "false-pair-distant-match" => Some(Self::FalsePairDistantMatch),
            "binary" => Some(Self::Binary),
            "natural-text" => Some(Self::NaturalText),
            _ => None,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Absent => "absent",
            Self::Dense => "dense",
            Self::Tail => "tail",
            Self::PrimaryDenseSecondaryAbsent => "primary-dense-secondary-absent",
            Self::AdaptiveSecondaryDensePrimaryAbsent => "adaptive-secondary-dense-primary-absent",
            Self::PairDenseLiteralAbsent => "pair-dense-literal-absent",
            Self::TripleDenseLiteralAbsent => "triple-dense-literal-absent",
            Self::FalsePairDistantMatch => "false-pair-distant-match",
            Self::Binary => "binary",
            Self::NaturalText => "natural-text",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scenario {
    Named(NamedScenario),
    Alignment(u8),
}

impl Scenario {
    fn parse(value: &str) -> Result<Self, AnyError> {
        if let Some(named) = NamedScenario::parse(value) {
            return Ok(Self::Named(named));
        }
        let Some(residue) = value.strip_prefix("alignment-") else {
            return Err(format!("invalid scenario {value:?}").into());
        };
        let residue: u8 = residue.parse()?;
        if residue >= 16 {
            return Err(format!("alignment residue {residue} is outside 0..15").into());
        }
        Ok(Self::Alignment(residue))
    }

    fn name(self) -> String {
        match self {
            Self::Named(named) => named.name().to_owned(),
            Self::Alignment(residue) => format!("alignment-{residue}"),
        }
    }

    fn desired_alignment(self) -> usize {
        match self {
            Self::Named(_) => 0,
            Self::Alignment(residue) => usize::from(residue),
        }
    }
}

#[derive(Debug)]
struct Haystack {
    storage: Vec<u8>,
    start: usize,
    len: usize,
}

impl Haystack {
    fn bytes(&self) -> &[u8] {
        let end = self.start.checked_add(self.len).expect("validated fixture");
        self.storage
            .get(self.start..end)
            .expect("validated fixture range")
    }
}

fn checked_add(left: usize, right: usize) -> usize {
    left.checked_add(right).expect("bounded fixture arithmetic")
}

fn make_haystack(size: Size, scenario: Scenario) -> Result<Haystack, AnyError> {
    const NATURAL: &[u8] =
        b"Elementary observations reward patient measurement. False candidates stay cheap. ";
    let len = size.bytes();
    let mut storage = vec![b'x'; checked_add(len, 32)];
    let base_mod16 = storage.as_ptr().addr() & 15;
    let desired = scenario.desired_alignment();
    let start = desired.wrapping_add(16).wrapping_sub(base_mod16) & 15;
    let end = checked_add(start, len);
    let haystack = storage
        .get_mut(start..end)
        .ok_or("fixture slice exceeds storage")?;
    let maximum_literal_start = len
        .checked_sub(LITERAL.len())
        .ok_or("fixture shorter than literal")?;

    match scenario {
        Scenario::Alignment(_) => {
            let position = maximum_literal_start / 2;
            write_literal(haystack, position)?;
        }
        Scenario::Named(NamedScenario::Present) => {
            let position = maximum_literal_start / 2;
            write_literal(haystack, position)?;
        }
        Scenario::Named(NamedScenario::Absent) => {}
        Scenario::Named(NamedScenario::Dense) => haystack.fill(LITERAL[0]),
        Scenario::Named(NamedScenario::Tail) => {
            write_literal(haystack, maximum_literal_start)?;
        }
        Scenario::Named(NamedScenario::PrimaryDenseSecondaryAbsent) => {
            haystack.fill(LITERAL[V8_PRIMARY_OFFSET]);
        }
        Scenario::Named(NamedScenario::AdaptiveSecondaryDensePrimaryAbsent) => {
            populate_adaptive_secondary_dense_primary_absent(haystack, maximum_literal_start);
        }
        Scenario::Named(NamedScenario::PairDenseLiteralAbsent) => {
            install_dense_columns(
                haystack,
                maximum_literal_start,
                &[
                    (V8_PRIMARY_OFFSET, LITERAL[V8_PRIMARY_OFFSET]),
                    (V8_SECONDARY_OFFSET, LITERAL[V8_SECONDARY_OFFSET]),
                ],
            );
        }
        Scenario::Named(NamedScenario::TripleDenseLiteralAbsent) => {
            install_dense_columns(
                haystack,
                maximum_literal_start,
                &[
                    (V8_PRIMARY_OFFSET, LITERAL[V8_PRIMARY_OFFSET]),
                    (V8_SECONDARY_OFFSET, LITERAL[V8_SECONDARY_OFFSET]),
                    (0, LITERAL[0]),
                ],
            );
        }
        Scenario::Named(NamedScenario::FalsePairDistantMatch) => {
            haystack[V8_PRIMARY_OFFSET] = LITERAL[V8_PRIMARY_OFFSET];
            haystack[V8_SECONDARY_OFFSET] = LITERAL[V8_SECONDARY_OFFSET];
            write_literal(haystack, maximum_literal_start)?;
        }
        Scenario::Named(NamedScenario::Binary) => {
            for (index, byte) in haystack.iter_mut().enumerate() {
                *byte = u8::try_from(index & 0xff).expect("masked byte");
            }
            write_literal(haystack, maximum_literal_start * 3 / 4)?;
        }
        Scenario::Named(NamedScenario::NaturalText) => {
            for (index, byte) in haystack.iter_mut().enumerate() {
                *byte = NATURAL[index % NATURAL.len()];
            }
            write_literal(haystack, maximum_literal_start * 3 / 4)?;
        }
    }

    if haystack.as_ptr().addr() & 15 != desired {
        return Err("fixture base alignment does not match scenario".into());
    }
    if matches!(
        scenario,
        Scenario::Named(
            NamedScenario::Absent
                | NamedScenario::Dense
                | NamedScenario::PrimaryDenseSecondaryAbsent
                | NamedScenario::AdaptiveSecondaryDensePrimaryAbsent
                | NamedScenario::PairDenseLiteralAbsent
                | NamedScenario::TripleDenseLiteralAbsent
        )
    ) && haystack
        .windows(LITERAL.len())
        .any(|window| window == LITERAL)
    {
        return Err(format!("absent scenario {} contains the literal", scenario.name()).into());
    }
    Ok(Haystack {
        storage,
        start,
        len,
    })
}

fn write_literal(haystack: &mut [u8], start: usize) -> Result<(), AnyError> {
    let end = start
        .checked_add(LITERAL.len())
        .ok_or("literal write overflow")?;
    haystack
        .get_mut(start..end)
        .ok_or("literal write exceeds fixture")?
        .copy_from_slice(LITERAL);
    Ok(())
}

fn install_dense_columns(
    haystack: &mut [u8],
    maximum_literal_start: usize,
    columns: &[(usize, u8)],
) {
    for candidate in 0..=maximum_literal_start {
        if columns.iter().any(|&(offset, byte)| {
            let current = haystack[checked_add(candidate, offset)];
            current != b'x' && current != byte
        }) {
            continue;
        }
        for &(offset, byte) in columns {
            haystack[checked_add(candidate, offset)] = byte;
        }
    }
}

fn populate_adaptive_secondary_dense_primary_absent(
    haystack: &mut [u8],
    maximum_literal_start: usize,
) {
    haystack[V8_PRIMARY_OFFSET] = LITERAL[V8_PRIMARY_OFFSET];
    let secondary_start = checked_add(V8_WIDE_CANDIDATE_STARTS, V8_SECONDARY_OFFSET);
    haystack[secondary_start..].fill(LITERAL[V8_SECONDARY_OFFSET]);
    let first_primary_hits = (0..V8_WIDE_CANDIDATE_STARTS)
        .filter(|&candidate| {
            haystack[checked_add(candidate, V8_PRIMARY_OFFSET)] == LITERAL[V8_PRIMARY_OFFSET]
        })
        .count();
    assert_eq!(first_primary_hits, 1);
    assert!(
        (V8_WIDE_CANDIDATE_STARTS..=maximum_literal_start).all(|candidate| {
            haystack[checked_add(candidate, V8_SECONDARY_OFFSET)] == LITERAL[V8_SECONDARY_OFFSET]
                && haystack[checked_add(candidate, V8_PRIMARY_OFFSET)] != LITERAL[V8_PRIMARY_OFFSET]
        })
    );
}

struct Subject {
    portable: PortableRegex,
    program: ValidatedProgram<Span>,
    jit: Option<PublishedKernel<Span>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SubjectPreparation {
    PortableOnly,
    NativeStatic,
    NativeJit,
}

fn build_portable(source: &str) -> Result<PortableRegex, AnyError> {
    if source != PATTERN {
        return Err("portable source differs from the receipt-bound pattern".into());
    }
    let portable = PortableBuilder::new(source)
        .unicode(false)
        .build()
        .map_err(|error| format!("portable build: {error}"))?;
    if portable.build_report().plan != PlanKind::ExactLiteral {
        return Err("portable subject did not select ExactLiteral".into());
    }
    Ok(portable)
}

fn build_candidate_and_program(
    source: &str,
) -> Result<(PortableRegex, ValidatedProgram<Span>), AnyError> {
    let portable = build_portable(source)?;
    let candidate = portable
        .exact_literal_search_aot_candidate()
        .ok_or("portable subject did not expose fixed-policy AOT candidate")?;
    if candidate.source() != source
        || candidate.literal() != LITERAL
        || candidate.semantic_binding_identity().as_bytes() != &generated::SEMANTIC_IDENTITY
    {
        return Err("runtime semantic candidate differs from build receipt".into());
    }
    let program = build_exact_literal::<Span>(
        candidate.literal(),
        AnchorFlags::default(),
        ValidateLimits::default(),
    )?;
    Ok((portable, program))
}

fn emit_v8(program: &ValidatedProgram<Span>) -> Result<NativeImage, AnyError> {
    let image = emit_with_backend(program, SearchBackendPolicy::AsimdV8, EmitLimits::default())?;
    if image.backend_version() != BackendVersion::SEARCH_V8
        || image.source_identity() != program.cache_identity()
    {
        return Err("runtime image backend/source mismatch".into());
    }
    Ok(image)
}

fn compile_source_aot() -> Result<SearchCompiledObjectV1<Span>, AnyError> {
    let mut source = Vec::new();
    source.try_reserve_exact(PATTERN.len())?;
    if source.capacity() != PATTERN.len() {
        return Err("compiler source capacity is not deterministic".into());
    }
    source.extend_from_slice(PATTERN.as_bytes());
    let mut profile = RustProfile::default();
    profile.options.unicode = false;
    let compiled = plan_and_compile_macos_aarch64_exact_search_v1(
        MacosAarch64ExactSearchManifestV1::<Span>::default(),
        source,
        profile,
    )?;
    Ok(compiled)
}

fn verify_compiled_aot(compiled: &SearchCompiledObjectV1<Span>) -> Result<(), AnyError> {
    let receipt = compiled.receipt();
    if compiled.runtime_authority() != SearchAotRuntimeAuthorityV1::Absent
        || receipt.runtime_authority() != SearchAotRuntimeAuthorityV1::Absent
        || receipt.semantic_binding_identity().as_bytes() != &generated::SEMANTIC_IDENTITY
        || receipt.binding_identity().as_bytes() != &generated::BINDING_IDENTITY
        || receipt.kir_identity().as_bytes() != &generated::SOURCE_IDENTITY
        || receipt.native_artifact_identity().as_bytes() != &generated::ARTIFACT_IDENTITY
        || receipt.compile_identity().as_bytes() != &generated::COMPILE_IDENTITY
        || receipt.object_identity().as_bytes() != &generated::OBJECT_IDENTITY
        || receipt.receipt_identity().as_bytes() != &generated::COMPILER_RECEIPT_IDENTITY
        || receipt.metadata().payload_sha256() != &generated::PAYLOAD_SHA256
        || compiled.object().as_bytes().len() != generated::OBJECT_BYTES
    {
        return Err("runtime source-first AOT compiler differs from build receipt".into());
    }
    Ok(())
}

fn verify_bound_image(image: &NativeImage) -> Result<(), AnyError> {
    if image.source_identity().as_bytes() != &generated::SOURCE_IDENTITY
        || image.artifact_identity().as_bytes() != &generated::ARTIFACT_IDENTITY
        || RuntimeIdentity::for_image(image).as_bytes() != &generated::ARTIFACT_IDENTITY
    {
        return Err("runtime native image identity differs from build receipt".into());
    }
    let compiled = compile_source_aot()?;
    verify_compiled_aot(&compiled)?;
    let binding = BindingIdentity::new(generated::BINDING_IDENTITY)?;
    let object = compiled.object();
    validate_search_object(image, binding, object.as_bytes(), ObjectLimits::default())?;
    if object.compile_identity().as_bytes() != &generated::COMPILE_IDENTITY
        || object.object_identity().as_bytes() != &generated::OBJECT_IDENTITY
        || object.metadata().payload_sha256() != &generated::PAYLOAD_SHA256
        || object.as_bytes().len() != generated::OBJECT_BYTES
        || usize::try_from(object.metadata().payload_bytes()).ok() != Some(generated::PAYLOAD_BYTES)
    {
        return Err("runtime Mach-O identity differs from build receipt".into());
    }
    Ok(())
}

fn build_subject(preparation: SubjectPreparation) -> Result<Subject, AnyError> {
    verify_generated_paths()?;
    let (portable, program) = build_candidate_and_program(PATTERN)?;
    if program.cache_identity().as_bytes() != &generated::SOURCE_IDENTITY {
        return Err("runtime KIR source identity differs from build receipt".into());
    }
    let jit = match preparation {
        SubjectPreparation::PortableOnly => None,
        SubjectPreparation::NativeStatic => {
            let image = emit_v8(&program)?;
            verify_bound_image(&image)?;
            None
        }
        SubjectPreparation::NativeJit => {
            let image = emit_v8(&program)?;
            verify_bound_image(&image)?;
            let jit = publish::<Span>(&image, PublicationLimits::default())?;
            if jit.identity().as_bytes() != &generated::ARTIFACT_IDENTITY {
                return Err("published JIT identity differs from build receipt".into());
            }
            Some(jit)
        }
    };
    Ok(Subject {
        portable,
        program,
        jit,
    })
}

fn verify_generated_paths() -> Result<(), AnyError> {
    for path in [
        generated::RECEIPT_PATH,
        generated::OBJECT_PATH,
        generated::LINK_MAP_PATH,
    ] {
        if !Path::new(path).is_absolute() {
            return Err(format!("generated path is not absolute: {path:?}").into());
        }
    }
    for symbol in [
        generated::ENTRY_SYMBOL,
        generated::PAYLOAD_SYMBOL,
        generated::METADATA_SYMBOL,
    ] {
        if symbol.is_empty()
            || !symbol
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(format!("invalid generated symbol {symbol:?}").into());
        }
    }
    Ok(())
}

fn expected_span(
    program: &ValidatedProgram<Span>,
    haystack: &[u8],
) -> Result<Option<(usize, usize)>, AnyError> {
    Ok(program
        .execute(
            haystack,
            KirSearchWindow::new(0, haystack.len()),
            ExecutionLimits::unlimited(),
        )?
        .into_output()
        .map(|span| (span.start(), span.end())))
}

fn portable_span(
    portable: &PortableRegex,
    haystack: &[u8],
) -> Result<Option<(usize, usize)>, AnyError> {
    let (matched, _) = portable.find_window(
        haystack,
        PortableSearchWindow::new(0, haystack.len()),
        SearchLimits::unlimited(),
    )?;
    Ok(matched.map(|span| (span.start(), span.end())))
}

fn jit_span(
    jit: &PublishedKernel<Span>,
    haystack: &[u8],
) -> Result<Option<(usize, usize)>, AnyError> {
    Ok(jit
        .search(haystack, KirSearchWindow::new(0, haystack.len()))?
        .map(|span: MatchSpan| (span.start(), span.end())))
}

#[allow(
    unsafe_code,
    reason = "benchmark-local wrapper calls one identity-bound retained raw AOT symbol"
)]
fn raw_static_aot_span(haystack: &[u8]) -> Result<Option<(usize, usize)>, AnyError> {
    let mut result = RawSpan {
        start: POISON_START,
        end: POISON_END,
    };
    let pointer = if haystack.is_empty() {
        &raw const EMPTY_ANCHOR
    } else {
        haystack.as_ptr()
    };
    // SAFETY: build.rs binds this declaration to the exact audited object and
    // ABI. The slice is immutable/readable, the empty case uses a nonnull
    // sentinel, and `result` is one disjoint initialized writable slot.
    let status = unsafe {
        generated::linked_search_v8_span(
            pointer,
            haystack.len(),
            0,
            haystack.len(),
            &raw mut result,
        )
    };
    match status {
        0 => {
            if result
                != (RawSpan {
                    start: POISON_START,
                    end: POISON_END,
                })
            {
                return Err("raw AOT no-match status changed poisoned result".into());
            }
            Ok(None)
        }
        1 => {
            if result.start == POISON_START
                || result.end == POISON_END
                || result.end.checked_sub(result.start) != Some(LITERAL.len())
                || result.end > haystack.len()
            {
                return Err(format!("raw AOT published invalid span {result:?}").into());
            }
            Ok(Some((result.start, result.end)))
        }
        _ => {
            if result
                != (RawSpan {
                    start: POISON_START,
                    end: POISON_END,
                })
            {
                return Err(
                    format!("raw AOT error status {status} changed poisoned result").into(),
                );
            }
            Err(format!("raw AOT returned backend status {status}").into())
        }
    }
}

fn engine_span(
    engine: Engine,
    subject: &Subject,
    haystack: &[u8],
) -> Result<Option<(usize, usize)>, AnyError> {
    match engine {
        Engine::RawStaticAot => raw_static_aot_span(haystack),
        Engine::StrictWxJit => jit_span(
            subject
                .jit
                .as_ref()
                .ok_or("strict-WX JIT engine was not prepared")?,
            haystack,
        ),
        Engine::Portable => portable_span(&subject.portable, haystack),
    }
}

fn semantic_value(span: Option<(usize, usize)>) -> u64 {
    span.map_or(0, |(start, end)| {
        u64::try_from(start).unwrap_or(u64::MAX).rotate_left(17)
            ^ u64::try_from(end).unwrap_or(u64::MAX).rotate_left(41)
            ^ 0x9e37_79b9_7f4a_7c15
    })
}

#[derive(Clone, Copy, Debug)]
struct Timed {
    iterations: usize,
    total_ns: u128,
    checksum: u64,
    value: u64,
}

fn measure(
    iterations: usize,
    mut operation: impl FnMut() -> Result<u64, AnyError>,
) -> Result<Timed, AnyError> {
    if iterations == 0 {
        return Err("measurement iterations must be nonzero".into());
    }
    let started = Instant::now();
    let mut checksum = 0x6a09_e667_f3bc_c909_u64;
    let mut value = 0_u64;
    for iteration in 0..iterations {
        value = black_box(operation()?);
        checksum = checksum.rotate_left(9)
            ^ value.wrapping_add(
                u64::try_from(iteration)
                    .unwrap_or(u64::MAX)
                    .wrapping_mul(0x9e37_79b9_7f4a_7c15),
            );
    }
    let total_ns = started.elapsed().as_nanos();
    black_box(checksum);
    Ok(Timed {
        iterations,
        total_ns,
        checksum,
        value,
    })
}

fn run_hot(size: Size, scenario: Scenario, repetition: u32) -> Result<(), AnyError> {
    if repetition >= HOT_REPETITIONS {
        return Err(format!("hot repetition {repetition} is out of range").into());
    }
    let fixture = make_haystack(size, scenario)?;
    let haystack = fixture.bytes();
    let subject = build_subject(SubjectPreparation::NativeJit)?;
    let expected = expected_span(&subject.program, haystack)?;
    for engine in Engine::ALL {
        let actual = engine_span(engine, &subject, haystack)?;
        if actual != expected {
            return Err(format!(
                "{} semantic mismatch: {actual:?} != {expected:?}",
                engine.name()
            )
            .into());
        }
    }
    for _ in 0..4 {
        for engine in Engine::ALL {
            black_box(engine_span(engine, &subject, black_box(haystack))?);
        }
    }

    let iterations = size.hot_iterations()?;
    let (order, order_name) = engine_order(repetition);
    let expected_value = semantic_value(expected);
    let cell = format!("span-{}-{}", size.name(), scenario.name());
    let mut reference_checksum = None;
    for engine in order {
        let timed = measure(iterations, || {
            engine_span(engine, &subject, black_box(haystack)).map(semantic_value)
        })?;
        if timed.value != expected_value {
            return Err(format!("{} timed semantic value changed", engine.name()).into());
        }
        if let Some(checksum) = reference_checksum {
            if timed.checksum != checksum {
                return Err("same-cell hot checksums differ across engines".into());
            }
        } else {
            reference_checksum = Some(timed.checksum);
        }
        println!(
            "FRE_SEARCH_V8_HOT_ROW\t{}",
            hot_row(
                &cell,
                size,
                &scenario.name(),
                repetition,
                &order_name,
                engine,
                timed,
                expected_value,
                haystack,
            )
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn hot_row(
    cell: &str,
    size: Size,
    scenario: &str,
    repetition: u32,
    order: &str,
    engine: Engine,
    timed: Timed,
    expected: u64,
    haystack: &[u8],
) -> String {
    [
        HOT_SCHEMA.to_owned(),
        generated::SUBJECT_REVISION.to_owned(),
        std::process::id().to_string(),
        repetition.to_string(),
        cell.to_owned(),
        size.name().to_owned(),
        scenario.to_owned(),
        order.to_owned(),
        engine.name().to_owned(),
        "hot".to_owned(),
        timed.iterations.to_string(),
        timed.total_ns.to_string(),
        (timed.total_ns / u128::try_from(timed.iterations).expect("bounded iterations"))
            .to_string(),
        format!("0x{:016x}", timed.checksum),
        format!("0x{expected:016x}"),
        haystack.len().to_string(),
        "0".to_owned(),
        haystack.len().to_string(),
        (haystack.as_ptr().addr() & 15).to_string(),
        engine.route().to_owned(),
        engine.authority().to_owned(),
        engine.backend().to_owned(),
        "candidate".to_owned(),
        "absent".to_owned(),
        hex(&generated::BENCHMARK_SOURCE_IDENTITY),
        hex(&generated::SEMANTIC_IDENTITY),
        hex(&generated::SOURCE_IDENTITY),
        hex(&generated::ARTIFACT_IDENTITY),
        hex(&generated::COMPILE_IDENTITY),
        hex(&generated::OBJECT_IDENTITY),
        hex(&generated::PAYLOAD_SHA256),
    ]
    .join(",")
}

#[derive(Clone, Copy, Debug)]
enum ColdPhase {
    PortableSourceBuild,
    KirBuild,
    V8EmitRetainedKir,
    JitPublishRetainedImage,
    AotObjectRetainedImage,
    JitSourceToReady,
    AotSourceToObject,
}

impl ColdPhase {
    const ALL: [Self; 7] = [
        Self::PortableSourceBuild,
        Self::KirBuild,
        Self::V8EmitRetainedKir,
        Self::JitPublishRetainedImage,
        Self::AotObjectRetainedImage,
        Self::JitSourceToReady,
        Self::AotSourceToObject,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::PortableSourceBuild => "portable-source-build",
            Self::KirBuild => "span-kir-build",
            Self::V8EmitRetainedKir => "v8-emit-retained-kir",
            Self::JitPublishRetainedImage => "jit-publish-retained-image",
            Self::AotObjectRetainedImage => "aot-object-retained-image",
            Self::JitSourceToReady => "jit-source-to-ready",
            Self::AotSourceToObject => "aot-source-to-object",
        }
    }

    const fn scope(self) -> &'static str {
        match self {
            Self::PortableSourceBuild => "portable-runtime-construction",
            Self::KirBuild => "shared-native-kir-construction",
            Self::V8EmitRetainedKir => "shared-native-machine-code-emission",
            Self::JitPublishRetainedImage => "strict-wx-publication-only",
            Self::AotObjectRetainedImage => "macho-object-wrap-only-no-link",
            Self::JitSourceToReady => "source-kir-emit-strict-wx-no-first-call",
            Self::AotSourceToObject => {
                "source-first-compiler-to-receipted-macho-no-link-no-adoption"
            }
        }
    }
}

fn run_cold(repetition: u32) -> Result<(), AnyError> {
    if repetition >= COLD_REPETITIONS {
        return Err(format!("cold repetition {repetition} is out of range").into());
    }
    verify_generated_paths()?;
    let (_, retained_program) = build_candidate_and_program(PATTERN)?;
    let retained_image = emit_v8(&retained_program)?;
    verify_bound_image(&retained_image)?;
    let start = usize::try_from(repetition).expect("bounded repetition") % ColdPhase::ALL.len();
    let order = format!("rotation-{start}");
    for offset in 0..ColdPhase::ALL.len() {
        let phase = ColdPhase::ALL[(start + offset) % ColdPhase::ALL.len()];
        let timed = measure(COLD_ITERATIONS, || {
            cold_once(phase, &retained_program, &retained_image)
        })?;
        println!(
            "FRE_SEARCH_V8_COLD_ROW\t{}",
            cold_row(repetition, &order, phase, timed)
        );
    }
    Ok(())
}

fn cold_once(
    phase: ColdPhase,
    retained_program: &ValidatedProgram<Span>,
    retained_image: &NativeImage,
) -> Result<u64, AnyError> {
    match phase {
        ColdPhase::PortableSourceBuild => {
            let portable = PortableBuilder::new(black_box(PATTERN))
                .unicode(false)
                .build()?;
            if portable.build_report().plan != PlanKind::ExactLiteral {
                return Err("cold portable build changed plan".into());
            }
            Ok(u64::try_from(
                portable.build_report().charged_persistent_bytes,
            )?)
        }
        ColdPhase::KirBuild => {
            let program = build_exact_literal::<Span>(
                black_box(LITERAL),
                AnchorFlags::default(),
                ValidateLimits::default(),
            )?;
            Ok(identity_word(program.cache_identity().as_bytes()))
        }
        ColdPhase::V8EmitRetainedKir => {
            let image = emit_v8(black_box(retained_program))?;
            Ok(identity_word(image.artifact_identity().as_bytes()))
        }
        ColdPhase::JitPublishRetainedImage => {
            let jit = publish::<Span>(black_box(retained_image), PublicationLimits::default())?;
            Ok(identity_word(jit.identity().as_bytes()))
        }
        ColdPhase::AotObjectRetainedImage => {
            let binding = BindingIdentity::new(generated::BINDING_IDENTITY)?;
            let object =
                emit_search_object(black_box(retained_image), binding, ObjectLimits::default())?;
            Ok(identity_word(object.object_identity().as_bytes()))
        }
        ColdPhase::JitSourceToReady => {
            let (_, program) = build_candidate_and_program(PATTERN)?;
            let image = emit_v8(&program)?;
            let jit = publish::<Span>(&image, PublicationLimits::default())?;
            Ok(identity_word(jit.identity().as_bytes()))
        }
        ColdPhase::AotSourceToObject => {
            let compiled = compile_source_aot()?;
            Ok(identity_word(
                compiled.receipt().object_identity().as_bytes(),
            ))
        }
    }
}

fn cold_row(repetition: u32, order: &str, phase: ColdPhase, timed: Timed) -> String {
    [
        COLD_SCHEMA.to_owned(),
        generated::SUBJECT_REVISION.to_owned(),
        std::process::id().to_string(),
        repetition.to_string(),
        order.to_owned(),
        phase.name().to_owned(),
        timed.iterations.to_string(),
        timed.total_ns.to_string(),
        (timed.total_ns / u128::try_from(timed.iterations).expect("bounded iterations"))
            .to_string(),
        format!("0x{:016x}", timed.checksum),
        phase.scope().to_owned(),
        "candidate".to_owned(),
        "absent".to_owned(),
        hex(&generated::BENCHMARK_SOURCE_IDENTITY),
        hex(&generated::SEMANTIC_IDENTITY),
        hex(&generated::SOURCE_IDENTITY),
        hex(&generated::ARTIFACT_IDENTITY),
        hex(&generated::COMPILE_IDENTITY),
        hex(&generated::OBJECT_IDENTITY),
        hex(&generated::PAYLOAD_SHA256),
    ]
    .join(",")
}

#[derive(Clone, Copy, Debug)]
struct LifecycleTimed {
    total_ns: u128,
    checksum: u64,
    value: Option<u64>,
}

fn lifecycle_case_is_allowed(size: Size, scenario: Scenario) -> bool {
    matches!(
        (size, scenario),
        (
            Size::K64,
            Scenario::Named(
                NamedScenario::Absent | NamedScenario::AdaptiveSecondaryDensePrimaryAbsent
            )
        ) | (
            Size::M1,
            Scenario::Named(NamedScenario::Tail | NamedScenario::NaturalText)
        )
    )
}

fn lifecycle_calls_are_allowed(size: Size, calls: usize) -> bool {
    match size {
        Size::K64 => LIFECYCLE_64K_CALLS.contains(&calls),
        Size::M1 => LIFECYCLE_1M_CALLS.contains(&calls),
    }
}

fn fold_lifecycle_checksum(checksum: u64, value: u64, call: usize) -> u64 {
    checksum.rotate_left(11)
        ^ value.wrapping_add(
            u64::try_from(call)
                .unwrap_or(u64::MAX)
                .wrapping_mul(0x9e37_79b9_7f4a_7c15),
        )
}

fn expected_lifecycle_checksum(calls: usize, expected: u64) -> u64 {
    (0..calls).fold(LIFECYCLE_CHECKSUM_SEED, |checksum, call| {
        fold_lifecycle_checksum(checksum, expected, call)
    })
}

fn lifecycle_portable_once(
    source: &str,
    calls: usize,
    haystack: &[u8],
) -> Result<LifecycleTimed, AnyError> {
    let started = Instant::now();
    let portable = build_portable(source)?;
    let mut checksum = LIFECYCLE_CHECKSUM_SEED;
    let mut value = None;
    for call in 0..calls {
        let current = black_box(portable_span(&portable, black_box(haystack)).map(semantic_value)?);
        checksum = fold_lifecycle_checksum(checksum, current, call);
        value = Some(current);
    }
    let total_ns = started.elapsed().as_nanos();
    black_box(&portable);
    black_box(checksum);
    drop(portable);
    Ok(LifecycleTimed {
        total_ns,
        checksum,
        value,
    })
}

fn lifecycle_jit_once(
    source: &str,
    calls: usize,
    haystack: &[u8],
) -> Result<LifecycleTimed, AnyError> {
    let started = Instant::now();
    let (portable, program) = build_candidate_and_program(source)?;
    let image = emit_v8(&program)?;
    let jit = publish::<Span>(&image, PublicationLimits::default())?;
    let mut checksum = LIFECYCLE_CHECKSUM_SEED;
    let mut value = None;
    for call in 0..calls {
        let current = black_box(jit_span(&jit, black_box(haystack)).map(semantic_value)?);
        checksum = fold_lifecycle_checksum(checksum, current, call);
        value = Some(current);
    }
    let total_ns = started.elapsed().as_nanos();
    black_box(&portable);
    black_box(checksum);
    if program.cache_identity().as_bytes() != &generated::SOURCE_IDENTITY
        || image.artifact_identity().as_bytes() != &generated::ARTIFACT_IDENTITY
        || jit.identity().as_bytes() != &generated::ARTIFACT_IDENTITY
    {
        return Err("lifecycle JIT identity differs from build receipt".into());
    }
    drop(jit);
    drop(image);
    drop(program);
    drop(portable);
    Ok(LifecycleTimed {
        total_ns,
        checksum,
        value,
    })
}

fn lifecycle_once(
    engine: Engine,
    source: &str,
    calls: usize,
    haystack: &[u8],
) -> Result<LifecycleTimed, AnyError> {
    match engine {
        Engine::Portable => lifecycle_portable_once(source, calls, haystack),
        Engine::StrictWxJit => lifecycle_jit_once(source, calls, haystack),
        Engine::RawStaticAot => {
            Err("raw static AOT has no safe lifecycle-equivalent adopter".into())
        }
    }
}

fn run_lifecycle(
    size: Size,
    scenario: Scenario,
    calls: usize,
    repetition: u32,
) -> Result<(), AnyError> {
    if repetition >= LIFECYCLE_REPETITIONS {
        return Err(format!("lifecycle repetition {repetition} is out of range").into());
    }
    if !lifecycle_case_is_allowed(size, scenario) {
        return Err(format!(
            "lifecycle case {} {} is outside the closed matrix",
            size.name(),
            scenario.name()
        )
        .into());
    }
    if !lifecycle_calls_are_allowed(size, calls) {
        return Err(format!(
            "lifecycle call count {calls} is outside the {} grid",
            size.name()
        )
        .into());
    }
    let fixture = make_haystack(size, scenario)?;
    let haystack = fixture.bytes();
    let oracle =
        build_exact_literal::<Span>(LITERAL, AnchorFlags::default(), ValidateLimits::default())?;
    let expected = expected_span(&oracle, haystack)?;
    let expected_value = semantic_value(expected);
    let expected_checksum = expected_lifecycle_checksum(calls, expected_value);
    let (order, order_name) = lifecycle_engine_order(repetition);
    let cell = format!("span-{}-{}-calls-{calls}", size.name(), scenario.name());
    let source = black_box(PATTERN);

    // The fixture and independent KIR oracle are prepared before either
    // timer. Both routes receive the same opaque source, and no call through
    // either measured route occurs before its timer.
    for engine in order {
        let timed = lifecycle_once(engine, source, calls, black_box(haystack))?;
        if timed.checksum != expected_checksum
            || timed.value != (calls != 0).then_some(expected_value)
        {
            return Err(format!("{} lifecycle semantic checksum changed", engine.name()).into());
        }
        println!(
            "FRE_SEARCH_V8_LIFECYCLE_ROW\t{}",
            lifecycle_row(
                &cell,
                size,
                &scenario.name(),
                calls,
                repetition,
                &order_name,
                engine,
                timed,
                expected_value,
                haystack,
            )
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn lifecycle_row(
    cell: &str,
    size: Size,
    scenario: &str,
    calls: usize,
    repetition: u32,
    order: &str,
    engine: Engine,
    timed: LifecycleTimed,
    expected: u64,
    haystack: &[u8],
) -> String {
    let stage = match engine {
        Engine::Portable => "portable-builder-plus-public-calls",
        Engine::StrictWxJit => "plan-kir-emit-strict-wx-plus-public-calls",
        Engine::RawStaticAot => unreachable!("raw AOT lifecycle is excluded"),
    };
    let route = match engine {
        Engine::Portable => "portable-lifecycle",
        Engine::StrictWxJit => "strict-wx-jit-lifecycle",
        Engine::RawStaticAot => unreachable!("raw AOT lifecycle is excluded"),
    };
    [
        LIFECYCLE_SCHEMA.to_owned(),
        generated::SUBJECT_REVISION.to_owned(),
        std::process::id().to_string(),
        repetition.to_string(),
        cell.to_owned(),
        size.name().to_owned(),
        scenario.to_owned(),
        calls.to_string(),
        order.to_owned(),
        engine.name().to_owned(),
        stage.to_owned(),
        timed.total_ns.to_string(),
        format!("0x{:016x}", timed.checksum),
        format!("0x{expected:016x}"),
        haystack.len().to_string(),
        (haystack.as_ptr().addr() & 15).to_string(),
        route.to_owned(),
        engine.authority().to_owned(),
        engine.backend().to_owned(),
        "candidate".to_owned(),
        "absent".to_owned(),
        hex(&generated::BENCHMARK_SOURCE_IDENTITY),
        hex(&generated::SEMANTIC_IDENTITY),
        hex(&generated::SOURCE_IDENTITY),
        hex(&generated::ARTIFACT_IDENTITY),
        hex(&generated::COMPILE_IDENTITY),
        hex(&generated::OBJECT_IDENTITY),
        hex(&generated::PAYLOAD_SHA256),
    ]
    .join(",")
}

fn run_first_call(
    engine: Engine,
    size: Size,
    scenario: Scenario,
    repetition: u32,
) -> Result<(), AnyError> {
    if repetition >= FIRST_CALL_REPETITIONS {
        return Err(format!("first-call repetition {repetition} is out of range").into());
    }
    let fixture = make_haystack(size, scenario)?;
    let haystack = fixture.bytes();
    let preparation = match engine {
        Engine::RawStaticAot => SubjectPreparation::NativeStatic,
        Engine::StrictWxJit => SubjectPreparation::NativeJit,
        Engine::Portable => SubjectPreparation::PortableOnly,
    };
    let subject = build_subject(preparation)?;
    let expected = expected_span(&subject.program, haystack)?;
    let expected_value = semantic_value(expected);

    // No call through any benchmark engine occurs before this one. KIR
    // interpretation above is the independent semantic oracle.
    let timed = measure(1, || {
        engine_span(engine, &subject, black_box(haystack)).map(semantic_value)
    })?;
    if timed.value != expected_value {
        return Err(format!("{} first call returned wrong value", engine.name()).into());
    }
    if engine_span(engine, &subject, haystack)? != expected {
        return Err(format!("{} post-timing semantic check failed", engine.name()).into());
    }
    let cell = format!("span-{}-{}", size.name(), scenario.name());
    println!(
        "FRE_SEARCH_V8_FIRST_CALL_ROW\t{}",
        first_call_row(
            &cell,
            size,
            &scenario.name(),
            repetition,
            engine,
            timed,
            expected_value,
            haystack,
        )
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn first_call_row(
    cell: &str,
    size: Size,
    scenario: &str,
    repetition: u32,
    engine: Engine,
    timed: Timed,
    expected: u64,
    haystack: &[u8],
) -> String {
    [
        FIRST_CALL_SCHEMA.to_owned(),
        generated::SUBJECT_REVISION.to_owned(),
        std::process::id().to_string(),
        repetition.to_string(),
        cell.to_owned(),
        size.name().to_owned(),
        scenario.to_owned(),
        engine.name().to_owned(),
        "ready-first-call".to_owned(),
        "1".to_owned(),
        timed.total_ns.to_string(),
        timed.total_ns.to_string(),
        format!("0x{:016x}", timed.checksum),
        format!("0x{expected:016x}"),
        haystack.len().to_string(),
        (haystack.as_ptr().addr() & 15).to_string(),
        engine.route().to_owned(),
        engine.authority().to_owned(),
        engine.backend().to_owned(),
        "candidate".to_owned(),
        "absent".to_owned(),
        hex(&generated::BENCHMARK_SOURCE_IDENTITY),
        hex(&generated::SEMANTIC_IDENTITY),
        hex(&generated::SOURCE_IDENTITY),
        hex(&generated::ARTIFACT_IDENTITY),
        hex(&generated::COMPILE_IDENTITY),
        hex(&generated::OBJECT_IDENTITY),
        hex(&generated::PAYLOAD_SHA256),
    ]
    .join(",")
}

fn identity_word(identity: &[u8; 32]) -> u64 {
    u64::from_le_bytes(identity[..8].try_into().expect("identity prefix"))
}

fn print_metadata() {
    for (key, value) in [
        ("schema", "fre-search-v8-bakeoff-metadata-v3".to_owned()),
        ("subject_revision", generated::SUBJECT_REVISION.to_owned()),
        (
            "benchmark_source_sha256",
            hex(&generated::BENCHMARK_SOURCE_IDENTITY),
        ),
        ("semantic_identity", hex(&generated::SEMANTIC_IDENTITY)),
        ("binding_identity", hex(&generated::BINDING_IDENTITY)),
        (
            "compiler_receipt_identity",
            hex(&generated::COMPILER_RECEIPT_IDENTITY),
        ),
        ("source_identity", hex(&generated::SOURCE_IDENTITY)),
        ("artifact_identity", hex(&generated::ARTIFACT_IDENTITY)),
        ("compile_identity", hex(&generated::COMPILE_IDENTITY)),
        ("object_identity", hex(&generated::OBJECT_IDENTITY)),
        ("payload_sha256", hex(&generated::PAYLOAD_SHA256)),
        ("metadata_sha256", hex(&generated::METADATA_SHA256)),
        ("literal_hex", hex(LITERAL)),
        ("backend", "aarch64-search-v8".to_owned()),
        ("operation", "span".to_owned()),
        ("hot_sizes", SIZE_COUNT.to_string()),
        ("hot_named_scenarios", NAMED_SCENARIO_COUNT.to_string()),
        (
            "hot_alignment_scenarios",
            ALIGNMENT_SCENARIO_COUNT.to_string(),
        ),
        ("hot_cells", HOT_CELLS.to_string()),
        ("hot_repetitions", HOT_REPETITIONS.to_string()),
        ("bytes_per_hot_sample", BYTES_PER_HOT_SAMPLE.to_string()),
        ("cold_phases", ColdPhase::ALL.len().to_string()),
        ("cold_repetitions", COLD_REPETITIONS.to_string()),
        ("cold_iterations", COLD_ITERATIONS.to_string()),
        ("first_call_repetitions", FIRST_CALL_REPETITIONS.to_string()),
        ("lifecycle_repetitions", LIFECYCLE_REPETITIONS.to_string()),
        (
            "lifecycle_64k_call_grid",
            LIFECYCLE_64K_CALLS
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join("+"),
        ),
        (
            "lifecycle_1m_call_grid",
            LIFECYCLE_1M_CALLS
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join("+"),
        ),
        (
            "lifecycle_aot_route",
            "excluded-until-safe-static-adopter".to_owned(),
        ),
        (
            "aot_route",
            "raw-statically-linked-aot-with-benchmark-local-decode".to_owned(),
        ),
        ("aot_adoption", "absent".to_owned()),
        ("production_activation", "absent".to_owned()),
        ("object_path", generated::OBJECT_PATH.to_owned()),
        ("receipt_path", generated::RECEIPT_PATH.to_owned()),
        ("link_map_path", generated::LINK_MAP_PATH.to_owned()),
        ("entry_symbol", generated::ENTRY_SYMBOL.to_owned()),
        ("payload_symbol", generated::PAYLOAD_SYMBOL.to_owned()),
        ("metadata_symbol", generated::METADATA_SYMBOL.to_owned()),
    ] {
        println!("FRE_SEARCH_V8_META\t{key}\t{value}");
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        write!(output, "{byte:02x}").expect("String write");
    }
    output
}

fn main() -> Result<(), AnyError> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.as_slice() {
        [command] if command == "metadata" => {
            print_metadata();
            Ok(())
        }
        [command] if command == "hot-header" => {
            println!("FRE_SEARCH_V8_HOT_ROW\t{HOT_HEADER}");
            Ok(())
        }
        [command, size, scenario, repetition] if command == "hot" => run_hot(
            Size::parse(size)?,
            Scenario::parse(scenario)?,
            repetition.parse()?,
        ),
        [command] if command == "cold-header" => {
            println!("FRE_SEARCH_V8_COLD_ROW\t{COLD_HEADER}");
            Ok(())
        }
        [command, repetition] if command == "cold" => run_cold(repetition.parse()?),
        [command] if command == "first-call-header" => {
            println!("FRE_SEARCH_V8_FIRST_CALL_ROW\t{FIRST_CALL_HEADER}");
            Ok(())
        }
        [command, engine, size, scenario, repetition] if command == "first-call" => run_first_call(
            Engine::parse(engine)?,
            Size::parse(size)?,
            Scenario::parse(scenario)?,
            repetition.parse()?,
        ),
        [command] if command == "lifecycle-header" => {
            println!("FRE_SEARCH_V8_LIFECYCLE_ROW\t{LIFECYCLE_HEADER}");
            Ok(())
        }
        [command, size, scenario, calls, repetition] if command == "lifecycle" => run_lifecycle(
            Size::parse(size)?,
            Scenario::parse(scenario)?,
            calls.parse()?,
            repetition.parse()?,
        ),
        _ => Err("usage: fre-search-v8-bakeoff metadata|hot-header|hot SIZE SCENARIO REPETITION|cold-header|cold REPETITION|first-call-header|first-call ENGINE SIZE SCENARIO REPETITION|lifecycle-header|lifecycle SIZE SCENARIO CALLS REPETITION".into()),
    }
}
