//! Source-bound SVE2 fixed-VL16 qualification driver.
//!
//! This is an evidence producer, never an activation path. It deliberately
//! forces explicit Candidate tag21, tag10, tag19, and V8 and compares them
//! with the normal portable exact-literal plan. The boundary, guard,
//! random-binary, output-width, and adversarial-filter fixtures are retained
//! from `sve_hardware_qualification`.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "all corpus, schedule, and checksum arithmetic is bounded by fixed harness constants"
)]

use std::{
    collections::BTreeMap,
    error::Error,
    ffi::c_void,
    fs,
    hint::black_box,
    path::Path,
    ptr::{self, NonNull},
    slice,
    time::{Duration, Instant},
};

use fre::{PortableBuilder, PortableRegex, SearchLimits as PortableSearchLimits};
use fre_jit_aarch64::{
    AotLimits, BackendVersion, EmitLimits, NativeImage, emit, emit_sve2_16, emit_sve2_fixed16_v2,
    emit_sve16_v6,
};
use fre_jit_runtime::{
    KernelThreadContractError, PublicationLimits, PublishedKernel, PublishedKernelThreadSession,
    RuntimeOperation, native_host_capabilities, publish,
};
use fre_kernel_ir::{
    AnchorFlags, ExecutionLimits, Exists, MatchSpan, Operation, SearchWindow, SelectedEnd, Span,
    ValidateLimits, ValidatedProgram, build_exact_literal,
};
use fre_target_features::TuningClass;
use sha2::{Digest, Sha256};

const SCHEMA: &str = "fre-jit-sve2-fixed16-hardware-qualification-v4";
const RECEIPT_SCHEMA: &str = "fre-jit-sve2-source-build-receipt-v3";
const INVALIDATED_QUALIFICATION_BUNDLE: &str =
    "89af5a04190a39c40a4819ce916fc28630330550e1cafc15e9919122af0ae9f7";
const LITERAL: &[u8; 16] = b"0123456789abcdef";
const LITERAL_PATTERN: &str = "0123456789abcdef";
const MIN_SAMPLE_TIME: Duration = Duration::from_millis(100);
const CALIBRATION_TARGET: Duration = Duration::from_millis(125);
const MAX_SAMPLE_ITERATIONS: usize = 1 << 28;
const WARMUP_CALLS: usize = 8;
const BINARY_CASES: usize = 20_000;
const NATURAL_CASES: usize = 20_000;
const NATURAL_CORPUS: &[u8] =
    b"the quick brown fox jumps over the lazy dog; source-bound regular expression search\n";
const BOUNDARY_CASES: usize = 4_096;
const GUARD_CASES: usize = 4_096;
const WIDE_CANDIDATE_STARTS: usize = 64;
const ADAPTIVE_CORRECTNESS_BYTES: usize = 512;
const ADAPTIVE_CORRECTNESS_MATCH_START: usize = 320;
const FIVE_SOURCE_SCENARIO_NAMES: [&str; 9] = [
    "present",
    "absent",
    "primary-dense-secondary-absent",
    "adaptive-secondary-dense-primary-absent",
    "pair-dense-literal-absent",
    "triple-dense-literal-absent",
    "four-filter-dense-literal-absent",
    "five-filter-dense-literal-absent",
    "tail",
];
const FIVE_SOURCE_SCENARIO_CSV: &str = "present,absent,primary-dense-secondary-absent,adaptive-secondary-dense-primary-absent,pair-dense-literal-absent,triple-dense-literal-absent,four-filter-dense-literal-absent,five-filter-dense-literal-absent,tail";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeBackend {
    Tag21,
    Tag10,
    Tag19,
    V8,
}

impl NativeBackend {
    const ALL: [Self; 4] = [Self::Tag21, Self::Tag10, Self::Tag19, Self::V8];

    const fn name(self) -> &'static str {
        match self {
            Self::Tag21 => "tag21",
            Self::Tag10 => "tag10",
            Self::Tag19 => "tag19",
            Self::V8 => "v8",
        }
    }

    const fn version(self) -> BackendVersion {
        match self {
            Self::Tag21 => BackendVersion::SEARCH_SVE2_FIXED16_V2,
            Self::Tag10 => BackendVersion::SEARCH_SVE2_16_V1,
            Self::Tag19 => BackendVersion::SEARCH_SVE16_V6,
            Self::V8 => BackendVersion::SEARCH_V8,
        }
    }

    fn emit<O: Operation>(
        self,
        program: &ValidatedProgram<O>,
    ) -> Result<NativeImage, fre_jit_aarch64::EmitError> {
        match self {
            Self::Tag21 => emit_sve2_fixed16_v2(program, EmitLimits::default()),
            Self::Tag10 => emit_sve2_16(program, EmitLimits::default()),
            Self::Tag19 => emit_sve16_v6(program, EmitLimits::default()),
            Self::V8 => emit(program, EmitLimits::default()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Engine {
    Tag21,
    Tag10,
    Tag19,
    V8,
    Portable,
}

impl Engine {
    const ALL: [Self; 5] = [
        Self::Tag21,
        Self::Tag10,
        Self::Tag19,
        Self::V8,
        Self::Portable,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Tag21 => "tag21",
            Self::Tag10 => "tag10",
            Self::Tag19 => "tag19",
            Self::V8 => "v8",
            Self::Portable => "portable",
        }
    }

    fn parse(value: &str) -> Result<Self, Box<dyn Error>> {
        Self::ALL
            .into_iter()
            .find(|engine| engine.name() == value)
            .ok_or_else(|| format!("unknown engine {value:?}").into())
    }
}

impl From<NativeBackend> for Engine {
    fn from(value: NativeBackend) -> Self {
        match value {
            NativeBackend::Tag21 => Self::Tag21,
            NativeBackend::Tag10 => Self::Tag10,
            NativeBackend::Tag19 => Self::Tag19,
            NativeBackend::V8 => Self::V8,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scenario {
    Present,
    Absent,
    PrimaryDenseSecondaryAbsent,
    AdaptiveSecondaryDensePrimaryAbsent,
    PairDenseLiteralAbsent,
    TripleDenseLiteralAbsent,
    FourFilterDenseLiteralAbsent,
    FiveFilterDenseLiteralAbsent,
    Quarter1,
    Quarter2,
    Quarter3,
    Quarter4,
    AllQuartersExhausted,
    Tail,
}

impl Scenario {
    const ALL: [Self; 9] = [
        Self::Present,
        Self::Absent,
        Self::PrimaryDenseSecondaryAbsent,
        Self::AdaptiveSecondaryDensePrimaryAbsent,
        Self::PairDenseLiteralAbsent,
        Self::TripleDenseLiteralAbsent,
        Self::FourFilterDenseLiteralAbsent,
        Self::FiveFilterDenseLiteralAbsent,
        Self::Tail,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Absent => "absent",
            Self::PrimaryDenseSecondaryAbsent => "primary-dense-secondary-absent",
            Self::AdaptiveSecondaryDensePrimaryAbsent => "adaptive-secondary-dense-primary-absent",
            Self::PairDenseLiteralAbsent => "pair-dense-literal-absent",
            Self::TripleDenseLiteralAbsent => "triple-dense-literal-absent",
            Self::FourFilterDenseLiteralAbsent => "four-filter-dense-literal-absent",
            Self::FiveFilterDenseLiteralAbsent => "five-filter-dense-literal-absent",
            Self::Quarter1 => "quarter-1",
            Self::Quarter2 => "quarter-2",
            Self::Quarter3 => "quarter-3",
            Self::Quarter4 => "quarter-4",
            Self::AllQuartersExhausted => "all-quarters-exhausted",
            Self::Tail => "tail",
        }
    }

    fn quarter(self) -> Option<usize> {
        match self {
            Self::Quarter1 => Some(0),
            Self::Quarter2 => Some(1),
            Self::Quarter3 => Some(2),
            Self::Quarter4 => Some(3),
            _ => None,
        }
    }

    fn is_quarter_diagnostic(self) -> bool {
        self.quarter().is_some() || matches!(self, Self::AllQuartersExhausted)
    }

    fn parse(value: &str) -> Result<Self, Box<dyn Error>> {
        Self::ALL
            .into_iter()
            .find(|scenario| scenario.name() == value)
            .ok_or_else(|| format!("unknown five-source scenario {value:?}").into())
    }

    fn parse_quarter_diagnostic(value: &str) -> Result<Self, Box<dyn Error>> {
        match value {
            "quarter-1" => Ok(Self::Quarter1),
            "quarter-2" => Ok(Self::Quarter2),
            "quarter-3" => Ok(Self::Quarter3),
            "quarter-4" => Ok(Self::Quarter4),
            "all-quarters-exhausted" => Ok(Self::AllQuartersExhausted),
            _ => Err(format!("unknown scenario {value:?}").into()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Size {
    K64,
    M1,
}

impl Size {
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

    const fn initial_iterations(self) -> usize {
        match self {
            Self::K64 => 2_048,
            Self::M1 => 128,
        }
    }

    fn parse(value: &str) -> Result<Self, Box<dyn Error>> {
        match value {
            "64k" => Ok(Self::K64),
            "1m" => Ok(Self::M1),
            _ => Err(format!("unknown size {value:?}").into()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FilterOffsets([usize; 5]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AdaptiveFixtureEvidence {
    first_group_primary_hits: usize,
    first_group_pair_hits: usize,
    later_candidate_starts: usize,
    later_secondary_hits: usize,
    later_primary_hits: usize,
    literal_matches: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct QuarterFixtureEvidence {
    literal_match_start: Option<usize>,
    literal_matches: usize,
    quarter_filter_hits: [usize; 4],
}

struct Engines {
    program: ValidatedProgram<Span>,
    images: [(NativeBackend, NativeImage); 4],
    tag21: PublishedKernel<Span>,
    tag10: PublishedKernel<Span>,
    tag19: PublishedKernel<Span>,
    v8: PublishedKernel<Span>,
    portable: PortableRegex,
    portable_identity: String,
    filter_offsets: FilterOffsets,
}

struct EngineSessions<'engines> {
    engines: &'engines Engines,
    tag21: PublishedKernelThreadSession<'engines, Span>,
    tag10: PublishedKernelThreadSession<'engines, Span>,
    tag19: PublishedKernelThreadSession<'engines, Span>,
    v8: PublishedKernelThreadSession<'engines, Span>,
}

impl Engines {
    fn build(source_commit: &str, source_tree: &str) -> Result<Self, Box<dyn Error>> {
        let program = build_exact_literal::<Span>(
            LITERAL,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )?;
        let images = NativeBackend::ALL.map(|backend| {
            let image = backend
                .emit(&program)
                .expect("the fixed 16-byte exact literal is admitted");
            (backend, image)
        });
        for (backend, image) in &images {
            if image.backend_version() != backend.version() {
                return Err(format!(
                    "{} emitted backend {}, expected {}",
                    backend.name(),
                    image.backend_version().0,
                    backend.version().0
                )
                .into());
            }
        }
        let filter_offsets = require_common_filter_offsets(&images)?;
        let tag21 = publish_native(NativeBackend::Tag21, &images)?;
        let tag10 = publish_native(NativeBackend::Tag10, &images)?;
        let tag19 = publish_native(NativeBackend::Tag19, &images)?;
        let v8 = publish_native(NativeBackend::V8, &images)?;
        let portable = PortableBuilder::new(LITERAL_PATTERN)
            .unicode(false)
            .build()?;
        let portable_identity = portable_identity(source_commit, source_tree, &portable);
        Ok(Self {
            program,
            images,
            tag21,
            tag10,
            tag19,
            v8,
            portable,
            portable_identity,
            filter_offsets,
        })
    }

    fn native(&self, backend: NativeBackend) -> &PublishedKernel<Span> {
        match backend {
            NativeBackend::Tag21 => &self.tag21,
            NativeBackend::Tag10 => &self.tag10,
            NativeBackend::Tag19 => &self.tag19,
            NativeBackend::V8 => &self.v8,
        }
    }

    fn begin_current_thread_sessions(
        &self,
    ) -> Result<EngineSessions<'_>, KernelThreadContractError> {
        Ok(EngineSessions {
            engines: self,
            tag21: self.tag21.begin_current_thread_session()?,
            tag10: self.tag10.begin_current_thread_session()?,
            tag19: self.tag19.begin_current_thread_session()?,
            v8: self.v8.begin_current_thread_session()?,
        })
    }
}

impl EngineSessions<'_> {
    fn search(
        &self,
        engine: Engine,
        haystack: &[u8],
        window: SearchWindow,
    ) -> Result<Option<MatchSpan>, Box<dyn Error>> {
        match engine {
            Engine::Tag21 => Ok(self.tag21.search(haystack, window)?),
            Engine::Tag10 => Ok(self.tag10.search(haystack, window)?),
            Engine::Tag19 => Ok(self.tag19.search(haystack, window)?),
            Engine::V8 => Ok(self.v8.search(haystack, window)?),
            Engine::Portable => {
                let portable_window = fre::SearchWindow::new(window.start(), window.end());
                let matched = self
                    .engines
                    .portable
                    .find_window(haystack, portable_window, PortableSearchLimits::unlimited())?
                    .0
                    .map(|span| MatchSpan::new(span.start(), span.end()));
                Ok(matched)
            }
        }
    }

    fn assert_all_equal(
        &self,
        haystack: &[u8],
        window: SearchWindow,
    ) -> Result<u64, Box<dyn Error>> {
        let expected = self
            .engines
            .program
            .execute(haystack, window, ExecutionLimits::unlimited())?
            .into_output();
        for engine in Engine::ALL {
            let actual = self.search(engine, haystack, window)?;
            if actual != expected {
                return Err(format!(
                    "{} mismatch: length={}, window={window:?}, expected={expected:?}, actual={actual:?}",
                    engine.name(),
                    haystack.len()
                )
                .into());
            }
        }
        Ok(u64::try_from(Engine::ALL.len()).expect("five engines"))
    }
}

impl std::ops::Deref for EngineSessions<'_> {
    type Target = Engines;

    fn deref(&self) -> &Self::Target {
        self.engines
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = std::env::args().collect();
    match arguments.get(1).map(String::as_str) {
        Some("qualification") => qualification(&arguments[2..]),
        Some("cell") => cell(&arguments[2..], false),
        Some("quarter-cell") => cell(&arguments[2..], true),
        _ => Err(
            "usage: sve2_fixed16_hardware_qualification qualification ... | cell|quarter-cell SIZE SCENARIO REPETITION ORDER_CSV SOURCE_COMMIT SOURCE_TREE RUN_ID INSTANCE_TYPE DRIVER_SHA256 FACADE_SHA256 BUILD_RECEIPT_SHA256"
                .into(),
        ),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the qualification entrypoint emits one closed source, host, route, and artifact receipt"
)]
fn qualification(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    if arguments.len() != 9 {
        return Err("qualification expects nine source/run/receipt arguments".into());
    }
    if Scenario::ALL.map(Scenario::name) != FIVE_SOURCE_SCENARIO_NAMES {
        return Err("five-source scenario contract changed".into());
    }
    let source_commit = require_hex(&arguments[0], 40, "source commit")?;
    let source_tree = require_hex(&arguments[1], 40, "source tree")?;
    let run_id = &arguments[2];
    let instance_type = &arguments[3];
    let requested_cpu = arguments[4].parse::<u32>()?;
    let driver_sha256 = require_hex(&arguments[5], 64, "driver SHA-256")?;
    let facade_sha256 = require_hex(&arguments[6], 64, "facade SHA-256")?;
    let receipt_path = Path::new(&arguments[7]);
    let expected_receipt_sha256 = require_hex(&arguments[8], 64, "build receipt SHA-256")?;
    let receipt = parse_build_receipt(receipt_path, expected_receipt_sha256)?;
    let tag21_qualification = option_env!("FRE_JIT_TAG21_FACADE_EXPECTED_QUALIFICATION")
        .ok_or("qualification binary lacks its expected tag21 qualification")?;
    require_receipt_value(&receipt, "source_commit", source_commit)?;
    require_receipt_value(&receipt, "source_tree", source_tree)?;
    require_receipt_value(&receipt, "driver_binary_sha256", driver_sha256)?;
    require_receipt_value(&receipt, "facade_test_binary_sha256", facade_sha256)?;
    require_receipt_value(
        &receipt,
        "tag21_expected_qualification",
        tag21_qualification,
    )?;
    let valid_tag21_qualification = if tag21_qualification == "candidate" {
        true
    } else if let Some(bundle) = tag21_qualification.strip_prefix("qualified:") {
        let bundle = require_hex(bundle, 64, "qualified tag21 bundle")?;
        bundle.bytes().any(|byte| byte != b'0') && bundle != INVALIDATED_QUALIFICATION_BUNDLE
    } else {
        false
    };
    if !valid_tag21_qualification {
        return Err("compiled tag21 qualification is malformed, zero, or invalidated".into());
    }
    if !is_run_id(run_id)
        || !(instance_type.starts_with("c9g.") || instance_type.starts_with("m9g."))
    {
        return Err("run ID or instance type is outside the closed contract".into());
    }
    let affinity_cpu = require_host(requested_cpu)?;
    let engines = Engines::build(source_commit, source_tree)?;

    print_meta("schema", SCHEMA);
    print_meta("source_commit", source_commit);
    print_meta("source_tree", source_tree);
    print_meta(
        "source_archive_sha256",
        receipt_value(&receipt, "source_archive_sha256")?,
    );
    print_meta("build_receipt_sha256", expected_receipt_sha256);
    print_meta("qualification_binary_sha256", driver_sha256);
    print_meta("facade_test_binary_sha256", facade_sha256);
    for key in [
        "cargo_sha256",
        "rustc_sha256",
        "toolchain_closure_sha256",
        "toolchain_closure_entries",
        "toolchain_closure_file_bytes",
        "cargo_registry_closure_sha256",
        "cargo_registry_closure_entries",
        "cargo_registry_closure_file_bytes",
        "dependency_lock_archive_proof_sha256",
        "dependency_archive_count",
    ] {
        print_meta(key, receipt_value(&receipt, key)?);
    }
    print_meta("qualification_run_id", run_id);
    print_meta("instance_type", instance_type);
    print_meta("arch", "aarch64");
    print_meta("os", "linux");
    print_meta("arm_cpu_implementer", "0x0041");
    print_meta("arm_cpu_part", "0x0d84");
    print_meta("homogeneous_cpu", "true");
    print_meta("asimd", "true");
    print_meta("sve", "true");
    print_meta("sve2", "true");
    print_meta("requested_thread_sve_vector_bytes", 16);
    print_meta("observed_thread_sve_vector_bytes", 16);
    print_meta("sve_lane_contract", "PTRUE-VL16");
    print_meta("active_sve_byte_lanes", 16);
    print_meta("affinity_cpu", affinity_cpu);
    print_meta("literal_hex", "30313233343536373839616263646566");
    print_meta("candidate_engine", "tag21");
    print_meta("candidate_backend", "SEARCH_SVE2_FIXED16_V2");
    print_meta("candidate_backend_version", 21);
    print_meta("candidate_feature_bits", 7);
    print_meta("candidate_host_contract", "arm-41-d84-asimd-sve-sve2-vl16");
    print_meta("candidate_policy_state", tag21_qualification);
    print_meta(
        "automatic_routing",
        if tag21_qualification == "candidate" {
            "candidate-closed-priority-tag21-tag10-tag19-v8"
        } else {
            "qualified-priority-tag21-tag10-tag19-v8"
        },
    );
    print_meta(
        "filter_offsets",
        format!(
            "{},{},{},{},{}",
            engines.filter_offsets.0[0],
            engines.filter_offsets.0[1],
            engines.filter_offsets.0[2],
            engines.filter_offsets.0[3],
            engines.filter_offsets.0[4]
        ),
    );
    print_meta("sizes", "64k,1m");
    print_meta("scenarios", FIVE_SOURCE_SCENARIO_CSV);
    print_meta("repetitions", 120);
    print_meta("minimum_sample_ns", MIN_SAMPLE_TIME.as_nanos());
    print_meta("order_schedule", "all-120-permutations-once");
    print_meta("confidence_method", "paired-log-mean-t95-df119");
    print_meta("aggregate_confidence_method", "paired-log-mean-t95-df2159");
    print_meta(
        "per_cell_gate",
        "tag21-point-and-upper95-below-1-vs-every-incumbent",
    );
    print_meta(
        "aggregate_gate",
        "tag21-point-and-upper95-below-1-and-95pct-wins-vs-every-incumbent",
    );
    print_meta(
        "correctness_case_schema",
        "fre-jit-sve2-correctness-cases-v3",
    );
    print_meta("boundary_case_generator", "boundary-grid-v1");
    print_meta("guard_case_seed", "0x7a11c0de5eed1234");
    print_meta(
        "guard_page_contract",
        "three-page-prot-none-read-prot-none-v1",
    );
    print_meta("binary_case_seed", "0x5e116a2dc39b740f");
    print_meta("natural_case_generator", "natural-repeat-insert-v1");
    print_meta("width_case_generator", "width-output-grid-v1");

    for backend in NativeBackend::ALL {
        let image = engines
            .images
            .iter()
            .find_map(|(candidate, image)| (*candidate == backend).then_some(image))
            .expect("all native images exist");
        println!(
            "ENGINE_IDENTITY\t{}\t{}\t{}\tnative-artifact-sha256\t{}",
            backend.name(),
            image.backend_version().0,
            image.target().features.bits(),
            image.artifact_identity()
        );
    }
    println!(
        "ENGINE_IDENTITY\tportable\t0\t0\tportable-engine-semantic-sha256\t{}",
        engines.portable_identity
    );

    verify_abi_canaries(&engines)?;
    let sessions = engines.begin_current_thread_sessions()?;
    black_box(run_correctness(&sessions)?);
    Ok(())
}

#[cfg(all(
    feature = "sve-hardware-qualification",
    target_arch = "aarch64",
    any(target_os = "macos", target_os = "linux"),
    target_pointer_width = "64",
    target_endian = "little"
))]
fn verify_abi_canaries(engines: &Engines) -> Result<(), Box<dyn Error>> {
    let canaries = [
        0x0808_0808_0808_0808,
        0x0909_0909_0909_0909,
        0x1010_1010_1010_1010,
        0x1111_1111_1111_1111,
        0x1212_1212_1212_1212,
        0x1313_1313_1313_1313,
        0x1414_1414_1414_1414,
        0x1515_1515_1515_1515,
    ];
    let window = SearchWindow::new(0, LITERAL.len());
    for backend in NativeBackend::ALL {
        let _session = engines.native(backend).begin_current_thread_session()?;
        let preserved = fre_jit_runtime::qualification_preserves_vector_callee_saved_lanes(
            engines.native(backend),
            LITERAL,
            window,
            canaries,
        )?;
        if !preserved {
            return Err(format!(
                "{} clobbered an AAPCS64 vector callee-saved lane",
                backend.name()
            )
            .into());
        }
        println!(
            "ABI_CANARY\t{}\tPASS\tprocess_id={}\tobserved_thread_sve_vector_bytes=16",
            backend.name(),
            std::process::id(),
        );
    }
    Ok(())
}

#[cfg(not(all(
    feature = "sve-hardware-qualification",
    target_arch = "aarch64",
    any(target_os = "macos", target_os = "linux"),
    target_pointer_width = "64",
    target_endian = "little"
)))]
fn verify_abi_canaries(_engines: &Engines) -> Result<(), Box<dyn Error>> {
    Err("build the AArch64 qualification driver with sve-hardware-qualification".into())
}

fn cell(arguments: &[String], quarter_diagnostic: bool) -> Result<(), Box<dyn Error>> {
    if arguments.len() != 11 {
        return Err(
            "cell expects SIZE SCENARIO REPETITION ORDER_CSV SOURCE_COMMIT SOURCE_TREE RUN_ID INSTANCE_TYPE DRIVER_SHA256 FACADE_SHA256 BUILD_RECEIPT_SHA256"
                .into(),
        );
    }
    let size = Size::parse(&arguments[0])?;
    let scenario = if quarter_diagnostic {
        Scenario::parse_quarter_diagnostic(&arguments[1])?
    } else {
        Scenario::parse(&arguments[1])?
    };
    let repetition = arguments[2].parse::<usize>()?;
    if repetition >= 120 {
        return Err("cell repetition must be 0..119".into());
    }
    let order_values: Vec<&str> = arguments[3].split(',').collect();
    if order_values.len() != Engine::ALL.len() {
        return Err("cell order must contain five engines".into());
    }
    let order = [
        Engine::parse(order_values[0])?,
        Engine::parse(order_values[1])?,
        Engine::parse(order_values[2])?,
        Engine::parse(order_values[3])?,
        Engine::parse(order_values[4])?,
    ];
    let mut sorted = order.map(Engine::name);
    sorted.sort_unstable();
    if sorted != ["portable", "tag10", "tag19", "tag21", "v8"] {
        return Err("cell order is not a permutation of all engines".into());
    }
    let source_commit = require_hex(&arguments[4], 40, "source commit")?;
    let source_tree = require_hex(&arguments[5], 40, "source tree")?;
    let run_id = &arguments[6];
    let instance_type = &arguments[7];
    let driver_sha256 = require_hex(&arguments[8], 64, "driver SHA-256")?;
    let facade_sha256 = require_hex(&arguments[9], 64, "facade SHA-256")?;
    let build_receipt_sha256 = require_hex(&arguments[10], 64, "build receipt SHA-256")?;
    if !is_run_id(run_id)
        || !(instance_type.starts_with("c9g.") || instance_type.starts_with("m9g."))
    {
        return Err("cell run ID or instance type is outside the closed contract".into());
    }
    let affinity_cpu = require_single_cpu_affinity()?;
    require_host(affinity_cpu)?;
    let (process_attempt, process_attempt_capability) = launched_attempt_binding()?;
    let process_id = std::process::id();
    let engines = Engines::build(source_commit, source_tree)?;
    let haystack = make_haystack(size, scenario, engines.filter_offsets)?;
    if scenario.is_quarter_diagnostic() {
        let evidence = quarter_fixture_evidence(&haystack, engines.filter_offsets)?;
        let match_start = evidence
            .literal_match_start
            .map_or_else(|| "none".to_owned(), |position| position.to_string());
        println!(
            "QUARTER_FIXTURE\t{}\t{}\t{}\t{}\t{}\t{}",
            scenario.name(),
            match_start,
            evidence.quarter_filter_hits[0],
            evidence.quarter_filter_hits[1],
            evidence.quarter_filter_hits[2],
            evidence.quarter_filter_hits[3],
        );
    }
    let window = SearchWindow::new(0, haystack.len());
    let sessions = engines.begin_current_thread_sessions()?;
    sessions.assert_all_equal(&haystack, window)?;
    for engine in Engine::ALL {
        for _ in 0..WARMUP_CALLS {
            black_box(sessions.search(engine, black_box(&haystack), window)?);
        }
    }
    let iterations = calibrate(&sessions, &haystack, window, size, affinity_cpu)?;
    println!(
        "CELL_BINDING\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        size.name(),
        scenario.name(),
        repetition,
        arguments[3],
        source_commit,
        source_tree,
        run_id,
        instance_type,
        driver_sha256,
        facade_sha256,
        build_receipt_sha256,
        process_id,
        process_attempt,
        process_attempt_capability,
    );
    for (position, engine) in order.into_iter().enumerate() {
        let cpu_before = observed_cpu()?;
        let (elapsed, checksum) = time_engine(&sessions, engine, &haystack, window, iterations)?;
        let cpu_after = observed_cpu()?;
        require_stable_cpu(affinity_cpu, cpu_before, cpu_after)?;
        if elapsed < MIN_SAMPLE_TIME {
            return Err(format!(
                "{} {} {} sample was shorter than 100ms",
                size.name(),
                scenario.name(),
                engine.name()
            )
            .into());
        }
        println!(
            "SAMPLE\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            engine.name(),
            size.name(),
            scenario.name(),
            repetition,
            position,
            iterations,
            elapsed.as_nanos(),
            checksum,
            cpu_before,
            cpu_after
        );
    }
    Ok(())
}

fn run_correctness(engines: &EngineSessions<'_>) -> Result<u64, Box<dyn Error>> {
    let mut comparisons = 0_u64;
    let boundaries = [
        0_usize, 1, 15, 16, 17, 31, 32, 47, 48, 63, 64, 65, 79, 80, 81, 95, 96, 127,
    ];
    for case in 0..BOUNDARY_CASES {
        let length = boundaries[case % boundaries.len()];
        let alignment = case % 16;
        let mut owned = aligned_haystack(length, alignment, b'x');
        if length >= LITERAL.len() && case & 1 == 0 {
            let last = length - LITERAL.len();
            let position = [0, last / 2, last][case % 3];
            owned.as_mut_slice()[position..position + LITERAL.len()].copy_from_slice(LITERAL);
        }
        comparisons = comparisons
            .checked_add(report_span_case(
                "boundary",
                case,
                engines,
                owned.as_slice(),
                SearchWindow::new(0, length),
                "na",
            )?)
            .ok_or("boundary comparison overflow")?;
    }

    let mut guard_random = XorShift64::new(0x7a11_c0de_5eed_1234);
    for case in 0..GUARD_CASES {
        let length = guard_random.bounded(513);
        let at_right_boundary = guard_random.bounded(2) != 0;
        let mut bytes = vec![0_u8; length];
        guard_random.fill(&mut bytes);
        if length >= LITERAL.len() && guard_random.next() & 1 == 0 {
            let position = guard_random.bounded(length - LITERAL.len() + 1);
            bytes[position..position + LITERAL.len()].copy_from_slice(LITERAL);
        }
        let start = guard_random.bounded(length + 1);
        let end = start + guard_random.bounded(length - start + 1);
        let placement = if at_right_boundary { "right" } else { "left" };
        let case_comparisons = with_guarded_haystack(&bytes, at_right_boundary, |guarded| {
            report_span_case(
                "guard",
                case,
                engines,
                guarded,
                SearchWindow::new(start, end),
                placement,
            )
        })??;
        comparisons = comparisons
            .checked_add(case_comparisons)
            .ok_or("guard comparison overflow")?;
    }

    let mut binary_random = XorShift64::new(0x5e11_6a2d_c39b_740f);
    for case in 0..BINARY_CASES {
        let length = binary_random.bounded(1025);
        let mut bytes = vec![0_u8; length];
        binary_random.fill(&mut bytes);
        if length >= LITERAL.len() && binary_random.next() & 1 == 0 {
            let position = binary_random.bounded(length - LITERAL.len() + 1);
            bytes[position..position + LITERAL.len()].copy_from_slice(LITERAL);
        }
        comparisons = comparisons
            .checked_add(report_span_case(
                "binary",
                case,
                engines,
                &bytes,
                SearchWindow::new(0, length),
                "na",
            )?)
            .ok_or("binary comparison overflow")?;
    }

    for case in 0..NATURAL_CASES {
        let repetitions = 1 + case % 16;
        let mut bytes = NATURAL_CORPUS.repeat(repetitions);
        if case & 1 == 0 {
            let position = bytes.len() / 2;
            bytes.splice(position..position, LITERAL.iter().copied());
        }
        comparisons = comparisons
            .checked_add(report_span_case(
                "natural",
                case,
                engines,
                &bytes,
                SearchWindow::new(0, bytes.len()),
                "na",
            )?)
            .ok_or("natural comparison overflow")?;
    }

    let adaptive = adaptive_correctness(engines)?;
    comparisons = comparisons
        .checked_add(adaptive)
        .ok_or("adaptive comparison overflow")?;
    comparisons = comparisons
        .checked_add(expanded_output_width_correctness()?)
        .ok_or("expanded comparison overflow")?;
    Ok(comparisons)
}

fn report_span_case(
    category: &str,
    index: usize,
    engines: &EngineSessions<'_>,
    haystack: &[u8],
    window: SearchWindow,
    guard_placement: &str,
) -> Result<u64, Box<dyn Error>> {
    let expected = engines
        .program
        .execute(haystack, window, ExecutionLimits::unlimited())?
        .into_output();
    let tag21 = engines.search(Engine::Tag21, haystack, window)?;
    let tag10 = engines.search(Engine::Tag10, haystack, window)?;
    let tag19 = engines.search(Engine::Tag19, haystack, window)?;
    let v8 = engines.search(Engine::V8, haystack, window)?;
    let portable = engines.search(Engine::Portable, haystack, window)?;
    if [tag21, tag10, tag19, v8, portable]
        .into_iter()
        .any(|actual| actual != expected)
    {
        return Err(format!(
            "{category} correctness mismatch: index={index}, expected={expected:?}, tag21={tag21:?}, tag10={tag10:?}, tag19={tag19:?}, v8={v8:?}, portable={portable:?}"
        )
        .into());
    }
    println!(
        "CORRECTNESS_CASE\t{category}\t{index}\t{}\t{}\t{}\t{}\t16\tspan\t{expected:?}\t{tag21:?}\t{tag10:?}\t{tag19:?}\t{v8:?}\t{portable:?}\t{guard_placement}",
        sha256_hex(haystack),
        haystack.len(),
        window.start(),
        window.end()
    );
    Ok(u64::try_from(Engine::ALL.len()).expect("five engines"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn expanded_output_width_correctness() -> Result<u64, Box<dyn Error>> {
    let mut comparisons = 0_u64;
    let mut case_index = 0_usize;
    for width in 1..=32 {
        let literal: Vec<u8> = (0..width)
            .map(|offset| 0x80_u8.wrapping_add(u8::try_from(offset).expect("width is at most 32")))
            .collect();
        for output_comparisons in [
            expanded_for::<Exists>(&literal, &mut case_index)?,
            expanded_for::<SelectedEnd>(&literal, &mut case_index)?,
            expanded_for::<Span>(&literal, &mut case_index)?,
        ] {
            comparisons = comparisons
                .checked_add(output_comparisons)
                .ok_or("expanded correctness overflow")?;
        }
    }
    if case_index != 32 * 3 * 10 * 16 {
        return Err("width/output matrix cardinality changed".into());
    }
    Ok(comparisons)
}

#[allow(
    clippy::too_many_lines,
    reason = "the generic output-width differential keeps all backend refusal and guard-page cases together"
)]
fn expanded_for<O>(literal: &[u8], case_index: &mut usize) -> Result<u64, Box<dyn Error>>
where
    O: RuntimeOperation,
    O::Output: std::fmt::Debug + Eq,
{
    let program =
        build_exact_literal::<O>(literal, AnchorFlags::default(), ValidateLimits::default())?;
    let mut kernels: BTreeMap<&str, PublishedKernel<O>> = BTreeMap::new();
    let mut tag19_refused = false;
    let mut tag21_refused = false;
    for backend in NativeBackend::ALL {
        match backend.emit(&program) {
            Ok(image) => {
                let kernel = publish::<O>(&image, PublicationLimits::default())?;
                kernels.insert(backend.name(), kernel);
            }
            Err(error) if backend == NativeBackend::Tag19 && literal.len() < 16 => {
                black_box(error);
                tag19_refused = true;
            }
            Err(error) if backend == NativeBackend::Tag21 && literal.len() != 16 => {
                black_box(error);
                tag21_refused = true;
            }
            Err(error) => return Err(error.into()),
        }
    }
    if literal.len() < 16 && (!tag19_refused || kernels.contains_key("tag19")) {
        return Err("tag19 unexpectedly admitted a literal shorter than 16 bytes".into());
    }
    if literal.len() != 16 && (!tag21_refused || kernels.contains_key("tag21")) {
        return Err("tag21 unexpectedly admitted a non-16-byte literal".into());
    }
    if literal.len() == 16 && (tag21_refused || !kernels.contains_key("tag21")) {
        return Err("tag21 refused its exact 16-byte literal envelope".into());
    }
    let mut sessions = BTreeMap::new();
    for (backend, kernel) in &kernels {
        sessions.insert(*backend, kernel.begin_current_thread_session()?);
    }
    let mut comparisons = 0_u64;
    for length in [
        literal.len().saturating_sub(1),
        literal.len(),
        literal.len() + 1,
        16,
        31,
        32,
        63,
        64,
        65,
        96,
    ] {
        for alignment in 0..16 {
            let mut owned = aligned_haystack(length, alignment, b'x');
            if length >= literal.len() {
                let position = (length - literal.len()) / 2;
                owned.as_mut_slice()[position..position + literal.len()].copy_from_slice(literal);
            }
            let window = SearchWindow::new(0, length);
            let expected = program
                .execute(owned.as_slice(), window, ExecutionLimits::unlimited())?
                .into_output();
            let mut outputs = BTreeMap::new();
            for (backend, session) in &sessions {
                let actual = session.search(owned.as_slice(), window)?;
                if actual != expected {
                    return Err(format!(
                        "{} output/width mismatch: width={}, output={:?}",
                        backend,
                        literal.len(),
                        O::KIND
                    )
                    .into());
                }
                outputs.insert(*backend, format!("{actual:?}"));
                comparisons = comparisons.checked_add(1).ok_or("comparison overflow")?;
            }
            let output_name = match O::KIND {
                fre_kernel_ir::OutputKind::Exists => "exists",
                fre_kernel_ir::OutputKind::SelectedEnd => "selected-end",
                fre_kernel_ir::OutputKind::Span => "span",
            };
            let tag19 = if tag19_refused {
                "refused".to_owned()
            } else {
                outputs.get("tag19").ok_or("tag19 output missing")?.clone()
            };
            let tag21 = if tag21_refused {
                "refused".to_owned()
            } else {
                outputs.get("tag21").ok_or("tag21 output missing")?.clone()
            };
            println!(
                "CORRECTNESS_CASE\twidth-output\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:?}\t{}\t{}\t{}\t{}\tna\tna",
                *case_index,
                sha256_hex(owned.as_slice()),
                length,
                window.start(),
                window.end(),
                literal.len(),
                output_name,
                expected,
                tag21,
                outputs.get("tag10").ok_or("tag10 output missing")?,
                tag19,
                outputs.get("v8").ok_or("v8 output missing")?,
            );
            *case_index = (*case_index).checked_add(1).ok_or("case index overflow")?;
        }
    }
    Ok(comparisons)
}

fn adaptive_correctness(engines: &EngineSessions<'_>) -> Result<u64, Box<dyn Error>> {
    let mut absent = vec![b'x'; ADAPTIVE_CORRECTNESS_BYTES];
    let evidence =
        synthesize_adaptive_secondary_dense_primary_absent(&mut absent, engines.filter_offsets)?;
    let expected_later = ADAPTIVE_CORRECTNESS_BYTES - LITERAL.len() + 1 - WIDE_CANDIDATE_STARTS;
    if evidence
        != (AdaptiveFixtureEvidence {
            first_group_primary_hits: 1,
            first_group_pair_hits: 0,
            later_candidate_starts: expected_later,
            later_secondary_hits: expected_later,
            later_primary_hits: 0,
            literal_matches: 0,
        })
    {
        return Err("adaptive absent fixture violated its frozen invariants".into());
    }
    let mut comparisons = report_span_case(
        "adaptive",
        0,
        engines,
        &absent,
        SearchWindow::new(0, absent.len()),
        "na",
    )?;
    let mut present = absent;
    let end = ADAPTIVE_CORRECTNESS_MATCH_START + LITERAL.len();
    present[ADAPTIVE_CORRECTNESS_MATCH_START..end].copy_from_slice(LITERAL);
    comparisons = comparisons
        .checked_add(report_span_case(
            "adaptive",
            1,
            engines,
            &present,
            SearchWindow::new(0, present.len()),
            "na",
        )?)
        .ok_or("adaptive comparison overflow")?;
    Ok(comparisons)
}

fn calibrate(
    engines: &EngineSessions<'_>,
    haystack: &[u8],
    window: SearchWindow,
    size: Size,
    affinity_cpu: u32,
) -> Result<usize, Box<dyn Error>> {
    let mut iterations = size.initial_iterations();
    loop {
        let mut shortest = Duration::MAX;
        for engine in Engine::ALL {
            let before = observed_cpu()?;
            let (elapsed, checksum) = time_engine(engines, engine, haystack, window, iterations)?;
            let after = observed_cpu()?;
            require_stable_cpu(affinity_cpu, before, after)?;
            black_box(checksum);
            shortest = shortest.min(elapsed);
        }
        if shortest >= CALIBRATION_TARGET {
            return Ok(iterations);
        }
        iterations = iterations
            .checked_mul(2)
            .filter(|next| *next <= MAX_SAMPLE_ITERATIONS)
            .ok_or("calibration exceeded the iteration bound")?;
    }
}

fn time_engine(
    engines: &EngineSessions<'_>,
    engine: Engine,
    haystack: &[u8],
    window: SearchWindow,
    iterations: usize,
) -> Result<(Duration, u64), Box<dyn Error>> {
    let start = Instant::now();
    let mut checksum = 0_u64;
    for iteration in 0..iterations {
        let output = engines.search(engine, black_box(haystack), window)?;
        checksum = checksum.wrapping_add(
            encode_span(output)
                .rotate_left(u32::try_from(iteration & 63).expect("rotation is at most 63")),
        );
    }
    Ok((start.elapsed(), black_box(checksum)))
}

fn encode_span(output: Option<MatchSpan>) -> u64 {
    output.map_or(0, |span| {
        let start = u64::try_from(span.start()).expect("bounded haystack");
        let end = u64::try_from(span.end()).expect("bounded haystack");
        start.rotate_left(17) ^ end.rotate_left(41) ^ 0x9e37_79b9_7f4a_7c15
    })
}

fn portable_identity(source_commit: &str, source_tree: &str, portable: &PortableRegex) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"fre-portable-exact-literal-engine-semantic-v1\0");
    hasher.update(source_commit.as_bytes());
    hasher.update([0]);
    hasher.update(source_tree.as_bytes());
    hasher.update([0]);
    hasher.update(LITERAL);
    hasher.update([0]);
    hasher.update(format!("{:?}", portable.build_report().plan).as_bytes());
    format!("{:x}", hasher.finalize())
}

fn publish_native(
    backend: NativeBackend,
    images: &[(NativeBackend, NativeImage); 4],
) -> Result<PublishedKernel<Span>, Box<dyn Error>> {
    let image = images
        .iter()
        .find_map(|(candidate, image)| (*candidate == backend).then_some(image))
        .ok_or("native image missing")?;
    Ok(publish(image, PublicationLimits::default())?)
}

fn require_common_filter_offsets(
    images: &[(NativeBackend, NativeImage); 4],
) -> Result<FilterOffsets, Box<dyn Error>> {
    let mut common = None;
    let mut tag21_quinary = None;
    for (backend, image) in images {
        let artifact = image.to_aot(AotLimits::default())?;
        let bytes = artifact.as_bytes();
        let minimum = if *backend == NativeBackend::Tag21 {
            80
        } else {
            78
        };
        if bytes.len() < minimum || &bytes[..7] != b"FREA64\0" {
            return Err(format!("{} has malformed AOT metadata", backend.name()).into());
        }
        if read_u32(bytes, 62)? != 16
            || read_u16(bytes, 68)? != 16
            || (*backend == NativeBackend::Tag21 && read_u16(bytes, 66)? != 8)
        {
            return Err(format!("{} has the wrong literal/block width", backend.name()).into());
        }
        let offsets = [
            usize::from(read_u16(bytes, 70)?),
            usize::from(read_u16(bytes, 72)?),
            usize::from(read_u16(bytes, 74)?),
            usize::from(read_u16(bytes, 76)?),
        ];
        let mut sorted = offsets;
        sorted.sort_unstable();
        if sorted.iter().any(|offset| *offset >= LITERAL.len())
            || sorted.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(format!("{} has invalid filter offsets", backend.name()).into());
        }
        if common.is_some_and(|existing| existing != offsets) {
            return Err(format!("filter offsets differ at {}", backend.name()).into());
        }
        common = Some(offsets);
        if *backend == NativeBackend::Tag21 {
            let quinary = usize::from(read_u16(bytes, 78)?);
            if quinary >= LITERAL.len() || offsets.contains(&quinary) {
                return Err("tag21 has an invalid fifth filter offset".into());
            }
            tag21_quinary = Some(quinary);
        }
    }
    let Some(common) = common else {
        return Err("no native images".into());
    };
    let Some(quinary) = tag21_quinary else {
        return Err("tag21 fifth filter offset missing".into());
    };
    Ok(FilterOffsets([
        common[0], common[1], common[2], common[3], quinary,
    ]))
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, Box<dyn Error>> {
    let array: [u8; 2] = bytes
        .get(offset..offset.checked_add(2).ok_or("u16 offset overflow")?)
        .ok_or("short AOT u16")?
        .try_into()?;
    Ok(u16::from_le_bytes(array))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, Box<dyn Error>> {
    let array: [u8; 4] = bytes
        .get(offset..offset.checked_add(4).ok_or("u32 offset overflow")?)
        .ok_or("short AOT u32")?
        .try_into()?;
    Ok(u32::from_le_bytes(array))
}

fn require_host(requested_cpu: u32) -> Result<u32, Box<dyn Error>> {
    let affinity_cpu = require_single_cpu_affinity()?;
    if affinity_cpu != requested_cpu {
        return Err("requested CPU differs from taskset affinity".into());
    }
    let capabilities = native_host_capabilities()?;
    if !capabilities.has_asimd()
        || !capabilities.has_sve()
        || !capabilities.has_sve2()
        || capabilities.sve_vector_bytes() != Some(16)
    {
        return Err(format!(
            "qualification requires OS-usable ASIMD+SVE+SVE2 at VL16, got {capabilities:?}"
        )
        .into());
    }
    match fre_target_features::host().tuning() {
        TuningClass::ArmServer { cpu: Some(cpu) }
            if cpu.implementer == 0x41 && cpu.part == 0x0d84 => {}
        other => {
            return Err(format!("qualification requires Arm 0x41/0xd84, got {other:?}").into());
        }
    }
    require_homogeneous_d84()?;
    Ok(affinity_cpu)
}

fn require_homogeneous_d84() -> Result<(), Box<dyn Error>> {
    let cpuinfo = fs::read_to_string("/proc/cpuinfo")?;
    let mut processors = 0_usize;
    for section in cpuinfo
        .split("\n\n")
        .filter(|section| !section.trim().is_empty())
    {
        let fields: BTreeMap<&str, &str> = section
            .lines()
            .filter_map(|line| line.split_once(':'))
            .map(|(key, value)| (key.trim(), value.trim()))
            .collect();
        if !fields.contains_key("processor") {
            continue;
        }
        processors = processors
            .checked_add(1)
            .ok_or("processor count overflow")?;
        let implementer = fields
            .get("CPU implementer")
            .ok_or("CPU section lacks implementer")?;
        let part = fields.get("CPU part").ok_or("CPU section lacks part")?;
        let features = fields
            .get("Features")
            .ok_or("CPU section lacks feature list")?;
        let feature_words: Vec<&str> = features.split_whitespace().collect();
        if *implementer != "0x41"
            || *part != "0xd84"
            || !["asimd", "sve", "sve2"]
                .iter()
                .all(|feature| feature_words.contains(feature))
        {
            return Err("host is not homogeneous Arm 0x41/0xd84 ASIMD+SVE+SVE2".into());
        }
    }
    if processors == 0 {
        return Err("no processor sections in /proc/cpuinfo".into());
    }
    Ok(())
}

fn require_single_cpu_affinity() -> Result<u32, Box<dyn Error>> {
    let status = fs::read_to_string("/proc/self/status")?;
    let allowed = status
        .lines()
        .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))
        .map(str::trim)
        .ok_or("missing Cpus_allowed_list")?;
    if allowed.contains(',') || allowed.contains('-') {
        return Err(format!("qualification requires one taskset CPU, got {allowed}").into());
    }
    let affinity_cpu = allowed.parse::<u32>()?;
    if observed_cpu()? != affinity_cpu {
        return Err("current CPU differs from taskset affinity".into());
    }
    Ok(affinity_cpu)
}

fn observed_cpu() -> Result<u32, Box<dyn Error>> {
    let stat = fs::read_to_string("/proc/self/stat")?;
    let close = stat.rfind(") ").ok_or("malformed /proc/self/stat")?;
    Ok(stat[close + 2..]
        .split_whitespace()
        .nth(36)
        .ok_or("missing processor field")?
        .parse::<u32>()?)
}

fn require_stable_cpu(affinity_cpu: u32, before: u32, after: u32) -> Result<(), Box<dyn Error>> {
    if before != affinity_cpu || after != affinity_cpu {
        return Err(format!(
            "CPU affinity drift: affinity={affinity_cpu}, before={before}, after={after}"
        )
        .into());
    }
    Ok(())
}

fn parse_build_receipt(
    path: &Path,
    expected_sha256: &str,
) -> Result<BTreeMap<String, String>, Box<dyn Error>> {
    let raw = fs::read(path)?;
    if raw.is_empty()
        || raw.len() > 1024 * 1024
        || !raw.ends_with(b"\n")
        || raw.contains(&b'\r')
        || raw.contains(&0)
    {
        return Err("build receipt is malformed".into());
    }
    if format!("{:x}", Sha256::digest(&raw)) != expected_sha256 {
        return Err("build receipt SHA-256 mismatch".into());
    }
    let text = std::str::from_utf8(&raw)?;
    let mut result = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line
            .split_once('\t')
            .ok_or("build receipt row lacks one tab")?;
        if key.is_empty() || value.is_empty() || value.contains('\t') {
            return Err("build receipt row is not canonical".into());
        }
        if result.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err("build receipt repeats a key".into());
        }
    }
    require_receipt_value(&result, "schema", RECEIPT_SCHEMA)?;
    Ok(result)
}

fn receipt_value<'a>(
    receipt: &'a BTreeMap<String, String>,
    key: &str,
) -> Result<&'a str, Box<dyn Error>> {
    receipt
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("build receipt lacks {key}").into())
}

fn require_receipt_value(
    receipt: &BTreeMap<String, String>,
    key: &str,
    expected: &str,
) -> Result<(), Box<dyn Error>> {
    if receipt_value(receipt, key)? != expected {
        return Err(format!("build receipt {key} mismatch").into());
    }
    Ok(())
}

fn require_hex<'a>(value: &'a str, length: usize, label: &str) -> Result<&'a str, Box<dyn Error>> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{label} is not lowercase hexadecimal").into());
    }
    Ok(value)
}

fn is_run_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
        && value.as_bytes()[0].is_ascii_alphanumeric()
}

fn launched_attempt_binding() -> Result<(u64, String), Box<dyn Error>> {
    let attempt = std::env::var("FRE_SVE2_ATTEMPT")?;
    let canonical_attempt = attempt.parse::<u64>()?;
    if canonical_attempt == 0 || canonical_attempt.to_string() != attempt {
        return Err("launched attempt is not canonical positive decimal".into());
    }
    let capability = std::env::var("FRE_SVE2_ATTEMPT_CAPABILITY")?;
    require_hex(&capability, 64, "launched attempt capability")?;
    if capability.bytes().all(|byte| byte == b'0') {
        return Err("launched attempt capability is zero".into());
    }
    Ok((canonical_attempt, capability))
}

fn print_meta(key: &str, value: impl std::fmt::Display) {
    println!("META\t{key}\t{value}");
}

fn make_haystack(
    size: Size,
    scenario: Scenario,
    filter_offsets: FilterOffsets,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut haystack = vec![b'x'; size.bytes()];
    match scenario {
        Scenario::Present => {
            let position = (haystack.len() - LITERAL.len()) / 2;
            haystack[position..position + LITERAL.len()].copy_from_slice(LITERAL);
        }
        Scenario::Absent => {}
        Scenario::PrimaryDenseSecondaryAbsent => {
            synthesize_filter_hits(&mut haystack, filter_offsets, 1)?;
        }
        Scenario::AdaptiveSecondaryDensePrimaryAbsent => {
            synthesize_adaptive_secondary_dense_primary_absent(&mut haystack, filter_offsets)?;
        }
        Scenario::PairDenseLiteralAbsent => {
            synthesize_filter_hits(&mut haystack, filter_offsets, 2)?;
        }
        Scenario::TripleDenseLiteralAbsent => {
            synthesize_filter_hits(&mut haystack, filter_offsets, 3)?;
        }
        Scenario::FourFilterDenseLiteralAbsent => {
            synthesize_filter_hits(&mut haystack, filter_offsets, 4)?;
        }
        Scenario::FiveFilterDenseLiteralAbsent => {
            synthesize_filter_hits(&mut haystack, filter_offsets, 5)?;
        }
        Scenario::Quarter1 | Scenario::Quarter2 | Scenario::Quarter3 | Scenario::Quarter4 => {
            synthesize_quarter_match(
                &mut haystack,
                scenario
                    .quarter()
                    .ok_or("quarter scenario lost its fixed quarter")?,
            )?;
        }
        Scenario::AllQuartersExhausted => {
            synthesize_filter_hits(&mut haystack, filter_offsets, 5)?;
        }
        Scenario::Tail => {
            let position = haystack.len() - LITERAL.len();
            haystack[position..].copy_from_slice(LITERAL);
        }
    }
    let selected_columns = match scenario {
        Scenario::PrimaryDenseSecondaryAbsent => 1,
        Scenario::PairDenseLiteralAbsent => 2,
        Scenario::TripleDenseLiteralAbsent => 3,
        Scenario::FourFilterDenseLiteralAbsent => 4,
        Scenario::FiveFilterDenseLiteralAbsent | Scenario::AllQuartersExhausted => 5,
        _ => 0,
    };
    if selected_columns > 0
        && (haystack
            .windows(LITERAL.len())
            .any(|window| window == LITERAL)
            || count_filter_hits(&haystack, filter_offsets, selected_columns) == 0)
    {
        return Err("adversarial filter fixture violated its invariant".into());
    }
    if scenario.is_quarter_diagnostic() {
        validate_quarter_fixture(
            scenario,
            quarter_fixture_evidence(&haystack, filter_offsets)?,
        )?;
    }
    Ok(haystack)
}

fn synthesize_quarter_match(haystack: &mut [u8], quarter: usize) -> Result<(), Box<dyn Error>> {
    if quarter >= 4 {
        return Err("quarter fixture index is outside q1..q4".into());
    }
    let position = quarter
        .checked_mul(16)
        .and_then(|value| value.checked_add(8))
        .ok_or("quarter fixture match position overflow")?;
    let end = position
        .checked_add(LITERAL.len())
        .ok_or("quarter fixture match end overflow")?;
    let destination = haystack
        .get_mut(position..end)
        .ok_or("quarter fixture is shorter than its fixed match")?;
    destination.copy_from_slice(LITERAL);
    Ok(())
}

fn quarter_fixture_evidence(
    haystack: &[u8],
    filter_offsets: FilterOffsets,
) -> Result<QuarterFixtureEvidence, Box<dyn Error>> {
    if filter_offsets.0 != [7, 6, 8, 5, 15] {
        return Err(format!(
            "lazy-quarter diagnostic requires filter offsets 7,6,8,5,15, got {:?}",
            filter_offsets.0
        )
        .into());
    }
    let candidate_starts = haystack
        .len()
        .checked_sub(LITERAL.len())
        .and_then(|maximum| maximum.checked_add(1))
        .ok_or("quarter fixture is shorter than the literal")?;
    if candidate_starts < WIDE_CANDIDATE_STARTS {
        return Err("quarter fixture cannot cover 64 candidate starts".into());
    }
    let literal_matches: Vec<usize> = haystack
        .windows(LITERAL.len())
        .enumerate()
        .filter_map(|(position, candidate)| (candidate == LITERAL).then_some(position))
        .collect();
    let mut quarter_filter_hits = [0_usize; 4];
    for (quarter, hits) in quarter_filter_hits.iter_mut().enumerate() {
        let first = quarter * 16;
        let end = first + 16;
        *hits = (first..end)
            .filter(|candidate| {
                filter_offsets
                    .0
                    .iter()
                    .all(|offset| haystack[candidate + *offset] == LITERAL[*offset])
            })
            .count();
    }
    Ok(QuarterFixtureEvidence {
        literal_match_start: literal_matches.first().copied(),
        literal_matches: literal_matches.len(),
        quarter_filter_hits,
    })
}

fn validate_quarter_fixture(
    scenario: Scenario,
    evidence: QuarterFixtureEvidence,
) -> Result<(), Box<dyn Error>> {
    if let Some(quarter) = scenario.quarter() {
        let mut expected_hits = [0_usize; 4];
        expected_hits[quarter] = 1;
        let expected_position = quarter * 16 + 8;
        if evidence.literal_match_start != Some(expected_position)
            || evidence.literal_matches != 1
            || evidence.quarter_filter_hits != expected_hits
        {
            return Err(format!(
                "quarter match fixture mismatch: scenario={}, evidence={evidence:?}",
                scenario.name()
            )
            .into());
        }
    } else if scenario == Scenario::AllQuartersExhausted {
        if evidence.literal_match_start.is_some()
            || evidence.literal_matches != 0
            || evidence.quarter_filter_hits.contains(&0)
        {
            return Err(
                format!("all-quarter exhaustion fixture mismatch: evidence={evidence:?}").into(),
            );
        }
    } else {
        return Err("non-quarter scenario reached quarter fixture validation".into());
    }
    Ok(())
}

fn synthesize_adaptive_secondary_dense_primary_absent(
    haystack: &mut [u8],
    filter_offsets: FilterOffsets,
) -> Result<AdaptiveFixtureEvidence, Box<dyn Error>> {
    let candidate_starts = haystack
        .len()
        .checked_sub(LITERAL.len())
        .and_then(|maximum| maximum.checked_add(1))
        .ok_or("adaptive fixture is shorter than the literal")?;
    let later_candidate_starts = candidate_starts
        .checked_sub(WIDE_CANDIDATE_STARTS)
        .ok_or("adaptive fixture cannot cover 64 candidate starts")?;
    let primary_offset = filter_offsets.0[0];
    let secondary_offset = filter_offsets.0[1];
    let primary = LITERAL[primary_offset];
    let secondary = LITERAL[secondary_offset];
    if primary_offset == secondary_offset || primary == secondary {
        return Err("adaptive fixture requires distinct filters".into());
    }
    haystack[primary_offset] = primary;
    haystack[WIDE_CANDIDATE_STARTS + secondary_offset..].fill(secondary);
    let evidence = adaptive_fixture_evidence(haystack, filter_offsets)?;
    let expected = AdaptiveFixtureEvidence {
        first_group_primary_hits: 1,
        first_group_pair_hits: 0,
        later_candidate_starts,
        later_secondary_hits: later_candidate_starts,
        later_primary_hits: 0,
        literal_matches: 0,
    };
    if evidence != expected {
        return Err(format!(
            "adaptive fixture mismatch: expected={expected:?}, observed={evidence:?}"
        )
        .into());
    }
    Ok(evidence)
}

fn adaptive_fixture_evidence(
    haystack: &[u8],
    filter_offsets: FilterOffsets,
) -> Result<AdaptiveFixtureEvidence, Box<dyn Error>> {
    let candidate_starts = haystack.len() - LITERAL.len() + 1;
    if candidate_starts < WIDE_CANDIDATE_STARTS {
        return Err("adaptive fixture is too short".into());
    }
    let primary_offset = filter_offsets.0[0];
    let secondary_offset = filter_offsets.0[1];
    let primary = LITERAL[primary_offset];
    let secondary = LITERAL[secondary_offset];
    let primary_hit = |candidate: usize| haystack[candidate + primary_offset] == primary;
    let secondary_hit = |candidate: usize| haystack[candidate + secondary_offset] == secondary;
    Ok(AdaptiveFixtureEvidence {
        first_group_primary_hits: (0..WIDE_CANDIDATE_STARTS)
            .filter(|candidate| primary_hit(*candidate))
            .count(),
        first_group_pair_hits: (0..WIDE_CANDIDATE_STARTS)
            .filter(|candidate| primary_hit(*candidate) && secondary_hit(*candidate))
            .count(),
        later_candidate_starts: candidate_starts - WIDE_CANDIDATE_STARTS,
        later_secondary_hits: (WIDE_CANDIDATE_STARTS..candidate_starts)
            .filter(|candidate| secondary_hit(*candidate))
            .count(),
        later_primary_hits: (WIDE_CANDIDATE_STARTS..candidate_starts)
            .filter(|candidate| primary_hit(*candidate))
            .count(),
        literal_matches: haystack
            .windows(LITERAL.len())
            .filter(|candidate| *candidate == LITERAL)
            .count(),
    })
}

fn synthesize_filter_hits(
    haystack: &mut [u8],
    filter_offsets: FilterOffsets,
    selected_columns: usize,
) -> Result<(), Box<dyn Error>> {
    let last = haystack
        .len()
        .checked_sub(LITERAL.len())
        .ok_or("fixture shorter than literal")?;
    for candidate in 0..=last {
        let compatible = filter_offsets.0[..selected_columns].iter().all(|offset| {
            let index = candidate + *offset;
            haystack[index] == b'x' || haystack[index] == LITERAL[*offset]
        });
        if compatible {
            for offset in &filter_offsets.0[..selected_columns] {
                haystack[candidate + *offset] = LITERAL[*offset];
            }
        }
    }
    Ok(())
}

fn count_filter_hits(
    haystack: &[u8],
    filter_offsets: FilterOffsets,
    selected_columns: usize,
) -> usize {
    haystack
        .windows(LITERAL.len())
        .filter(|window| {
            filter_offsets.0[..selected_columns]
                .iter()
                .all(|offset| window[*offset] == LITERAL[*offset])
        })
        .count()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct GuardedHaystackMapping {
    base: NonNull<c_void>,
    bytes: usize,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for GuardedHaystackMapping {
    #[allow(
        unsafe_code,
        reason = "this qualification-only owner unmaps its exact three-page reservation"
    )]
    fn drop(&mut self) {
        // SAFETY: this value solely owns the exact live reservation.
        let _result = unsafe { libc::munmap(self.base.as_ptr(), self.bytes) };
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(
    unsafe_code,
    reason = "qualification must execute native kernels against real inaccessible page boundaries"
)]
fn with_guarded_haystack<T>(
    bytes: &[u8],
    at_right_boundary: bool,
    callback: impl for<'a> FnOnce(&'a [u8]) -> T,
) -> Result<T, Box<dyn Error>> {
    // SAFETY: sysconf has no pointer arguments and this is a valid selector.
    let page_result = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_result <= 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let page = usize::try_from(page_result)?;
    if bytes.len() > page {
        return Err("guarded qualification input exceeds one page".into());
    }
    let total = page.checked_mul(3).ok_or("guard mapping size overflow")?;
    // SAFETY: these are valid anonymous mapping arguments; successful
    // ownership is immediately transferred to GuardedHaystackMapping.
    let raw = unsafe {
        libc::mmap(
            ptr::null_mut(),
            total,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if raw == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error().into());
    }
    let base = NonNull::new(raw).ok_or("mmap returned a null success pointer")?;
    let mapping = GuardedHaystackMapping { base, bytes: total };
    // SAFETY: the middle page is inside the owned reservation and page aligned.
    let middle = unsafe { base.as_ptr().cast::<u8>().add(page) };
    // SAFETY: this changes only the middle page from inaccessible to RW.
    if unsafe { libc::mprotect(middle.cast(), page, libc::PROT_READ | libc::PROT_WRITE) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let offset = if at_right_boundary {
        page.checked_sub(bytes.len())
            .ok_or("guarded input is longer than one page")?
    } else {
        0
    };
    // SAFETY: the complete source fits in the writable middle page.
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), middle.add(offset), bytes.len());
    }
    // SAFETY: this removes write permission from exactly the middle page,
    // leaving the pages on both sides PROT_NONE.
    if unsafe { libc::mprotect(middle.cast(), page, libc::PROT_READ) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: the copied bytes occupy this exact readable range and mapping
    // ownership outlives the higher-ranked callback.
    let guarded = unsafe { slice::from_raw_parts(middle.add(offset), bytes.len()) };
    let result = callback(guarded);
    drop(mapping);
    Ok(result)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn with_guarded_haystack<T>(
    _bytes: &[u8],
    _at_right_boundary: bool,
    _callback: impl for<'a> FnOnce(&'a [u8]) -> T,
) -> Result<T, Box<dyn Error>> {
    Err("guarded qualification requires Linux or macOS mmap/mprotect".into())
}

struct AlignedHaystack {
    storage: Vec<u8>,
    start: usize,
    length: usize,
}

impl AlignedHaystack {
    fn as_slice(&self) -> &[u8] {
        &self.storage[self.start..self.start + self.length]
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.storage[self.start..self.start + self.length]
    }
}

fn aligned_haystack(length: usize, alignment_mod16: usize, fill: u8) -> AlignedHaystack {
    let storage = vec![fill; length + 32];
    let base_mod16 = storage.as_ptr().addr() & 15;
    let start = alignment_mod16.wrapping_add(16).wrapping_sub(base_mod16) & 15;
    AlignedHaystack {
        storage,
        start,
        length,
    }
}

struct XorShift64(u64);

impl XorShift64 {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn bounded(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(bound).expect("bounded corpus"))
            .expect("bounded corpus")
    }

    fn fill(&mut self, bytes: &mut [u8]) {
        for byte in bytes {
            *byte = self.next().to_le_bytes()[0];
        }
    }
}
