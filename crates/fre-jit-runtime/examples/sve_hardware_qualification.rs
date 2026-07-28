//! Source-bound SVE ID19 hardware correctness and performance qualification.
//!
//! This deliberately forces each versioned backend. It never changes runtime
//! routing, and its output is evidence rather than an activation decision.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "all corpus, schedule, and checksum arithmetic is bounded by fixed harness constants"
)]
use std::{
    error::Error,
    fs,
    hint::black_box,
    time::{Duration, Instant},
};

use fre_jit_aarch64::{AotLimits, BackendVersion, EmitLimits, NativeImage, emit, emit_sve16_v6};
use fre_jit_runtime::{
    PublicationLimits, PublishedKernel, RuntimeOperation, native_host_capabilities, publish,
};
use fre_kernel_ir::{
    AnchorFlags, ExecutionLimits, Exists, MatchSpan, Operation, SearchWindow, SelectedEnd, Span,
    ValidateLimits, ValidatedProgram, build_exact_literal,
};
use fre_target_features::TuningClass;

const SCHEMA: &str = "fre-jit-sve-id19-hardware-qualification-v4";
const SOURCE_COMMIT: &str = match option_env!("FRE_SOURCE_COMMIT") {
    Some(value) => value,
    None => "unbound",
};
const SOURCE_TREE: &str = match option_env!("FRE_SOURCE_TREE") {
    Some(value) => value,
    None => "unbound",
};
const SOURCE_ARCHIVE_SHA256: &str = match option_env!("FRE_SOURCE_ARCHIVE_SHA256") {
    Some(value) => value,
    None => "unbound",
};
const BUILD_RECEIPT_SHA256: &str = match option_env!("FRE_BUILD_RECEIPT_SHA256") {
    Some(value) => value,
    None => "unbound",
};
const TOOLCHAIN_ROOT: &str = match option_env!("FRE_TOOLCHAIN_ROOT") {
    Some(value) => value,
    None => "unbound",
};
const CARGO_SHA256: &str = match option_env!("FRE_CARGO_SHA256") {
    Some(value) => value,
    None => "unbound",
};
const RUSTC_SHA256: &str = match option_env!("FRE_RUSTC_SHA256") {
    Some(value) => value,
    None => "unbound",
};
const TOOLCHAIN_CLOSURE_SHA256: &str = match option_env!("FRE_TOOLCHAIN_CLOSURE_SHA256") {
    Some(value) => value,
    None => "unbound",
};
const TOOLCHAIN_CLOSURE_ENTRIES: &str = match option_env!("FRE_TOOLCHAIN_CLOSURE_ENTRIES") {
    Some(value) => value,
    None => "unbound",
};
const TOOLCHAIN_CLOSURE_FILE_BYTES: &str = match option_env!("FRE_TOOLCHAIN_CLOSURE_FILE_BYTES") {
    Some(value) => value,
    None => "unbound",
};
const RUSTC_SYSROOT_BINDING: &str = match option_env!("FRE_RUSTC_SYSROOT_BINDING") {
    Some(value) => value,
    None => "unbound",
};
const RUSTDOC_INVOCATION: &str = match option_env!("FRE_RUSTDOC_INVOCATION") {
    Some(value) => value,
    None => "unbound",
};
const CARGO_REGISTRY_ROOT: &str = match option_env!("FRE_CARGO_REGISTRY_ROOT") {
    Some(value) => value,
    None => "unbound",
};
const CARGO_REGISTRY_CLOSURE_SHA256: &str = match option_env!("FRE_CARGO_REGISTRY_CLOSURE_SHA256") {
    Some(value) => value,
    None => "unbound",
};
const CARGO_REGISTRY_CLOSURE_ENTRIES: &str = match option_env!("FRE_CARGO_REGISTRY_CLOSURE_ENTRIES")
{
    Some(value) => value,
    None => "unbound",
};
const CARGO_REGISTRY_CLOSURE_FILE_BYTES: &str =
    match option_env!("FRE_CARGO_REGISTRY_CLOSURE_FILE_BYTES") {
        Some(value) => value,
        None => "unbound",
    };
const CARGO_REGISTRY_SNAPSHOT_POLICY: &str = match option_env!("FRE_CARGO_REGISTRY_SNAPSHOT_POLICY")
{
    Some(value) => value,
    None => "unbound",
};
const DEPENDENCY_LOCK_ARCHIVE_PROOF_SHA256: &str =
    match option_env!("FRE_DEPENDENCY_LOCK_ARCHIVE_PROOF_SHA256") {
        Some(value) => value,
        None => "unbound",
    };
const DEPENDENCY_ARCHIVE_COUNT: &str = match option_env!("FRE_DEPENDENCY_ARCHIVE_COUNT") {
    Some(value) => value,
    None => "unbound",
};
const QUALIFICATION_RUN_ID: &str = match option_env!("FRE_QUALIFICATION_RUN_ID") {
    Some(value) => value,
    None => "unbound",
};
const EXPECTED_REGION: &str = match option_env!("FRE_EXPECTED_REGION") {
    Some(value) => value,
    None => "unbound",
};
const EXPECTED_INSTANCE_ID: &str = match option_env!("FRE_EXPECTED_INSTANCE_ID") {
    Some(value) => value,
    None => "unbound",
};
const EXPECTED_INSTANCE_TYPE: &str = match option_env!("FRE_EXPECTED_INSTANCE_TYPE") {
    Some(value) => value,
    None => "unbound",
};
const LITERAL: &[u8; 16] = b"0123456789abcdef";
const REPETITIONS: usize = 30;
const WARMUP_CALLS: usize = 8;
const RANDOM_CORRECTNESS_CASES: usize = 20_000;
const WIDE_CANDIDATE_STARTS: usize = 64;
const ADAPTIVE_CORRECTNESS_BYTES: usize = 512;
const ADAPTIVE_CORRECTNESS_MATCH_START: usize = 320;
const MIN_SAMPLE_TIME: Duration = Duration::from_millis(100);
const CALIBRATION_TARGET: Duration = Duration::from_millis(125);
const MAX_SAMPLE_ITERATIONS: usize = 1 << 28;
const CONFIDENCE_T_95: f64 = 2.045;
const MAX_LARGE_CELL_POINT_RATIO: f64 = 1.005;
const MAX_LARGE_CELL_UPPER_95: f64 = 1.020;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Backend {
    V8,
    Sve16V6,
}

impl Backend {
    const ALL: [Self; 2] = [Self::V8, Self::Sve16V6];

    const fn name(self) -> &'static str {
        match self {
            Self::V8 => "v8",
            Self::Sve16V6 => "sve16-v6",
        }
    }

    fn emit<O: Operation>(self, program: &ValidatedProgram<O>) -> NativeImage {
        match self {
            Self::V8 => emit(program, EmitLimits::default()),
            Self::Sve16V6 => emit_sve16_v6(program, EmitLimits::default()),
        }
        .expect("the fixed exact-literal program is admitted")
    }
}

const BACKEND_ORDERS: [[Backend; 2]; 2] = [
    [Backend::V8, Backend::Sve16V6],
    [Backend::Sve16V6, Backend::V8],
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scenario {
    Present,
    Absent,
    PrimaryDenseSecondaryAbsent,
    AdaptiveSecondaryDensePrimaryAbsent,
    PairDenseLiteralAbsent,
    TripleDenseLiteralAbsent,
    FourFilterDenseLiteralAbsent,
    Tail,
}

impl Scenario {
    const ALL: [Self; 8] = [
        Self::Present,
        Self::Absent,
        Self::PrimaryDenseSecondaryAbsent,
        Self::AdaptiveSecondaryDensePrimaryAbsent,
        Self::PairDenseLiteralAbsent,
        Self::TripleDenseLiteralAbsent,
        Self::FourFilterDenseLiteralAbsent,
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
            Self::Tail => "tail",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Size {
    Short,
    K4,
    K16,
    K64,
    M1,
}

impl Size {
    const ALL: [Self; 5] = [Self::Short, Self::K4, Self::K16, Self::K64, Self::M1];

    const fn name(self) -> &'static str {
        match self {
            Self::Short => "96",
            Self::K4 => "4k",
            Self::K16 => "16k",
            Self::K64 => "64k",
            Self::M1 => "1m",
        }
    }

    const fn bytes(self) -> usize {
        match self {
            Self::Short => 96,
            Self::K4 => 4 * 1024,
            Self::K16 => 16 * 1024,
            Self::K64 => 64 * 1024,
            Self::M1 => 1024 * 1024,
        }
    }

    const fn initial_iterations(self) -> usize {
        match self {
            Self::Short => 16_384,
            Self::K4 => 4_096,
            Self::K16 => 1_024,
            Self::K64 => 2_048,
            Self::M1 => 128,
        }
    }

    const fn is_qualification_size(self) -> bool {
        matches!(self, Self::K64 | Self::M1)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FilterOffsets([usize; 4]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AdaptiveFixtureEvidence {
    first_group_primary_hits: usize,
    first_group_pair_hits: usize,
    later_candidate_starts: usize,
    later_secondary_hits: usize,
    later_primary_hits: usize,
    literal_matches: usize,
}

struct Kernels {
    v8: PublishedKernel<Span>,
    sve16_v6: PublishedKernel<Span>,
}

impl Kernels {
    fn get(&self, backend: Backend) -> &PublishedKernel<Span> {
        match backend {
            Backend::V8 => &self.v8,
            Backend::Sve16V6 => &self.sve16_v6,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Timing {
    backend: Backend,
    repetition: usize,
    position: usize,
    iterations: usize,
    total: Duration,
    checksum: u64,
    cpu_before: u32,
    cpu_after: u32,
}

#[derive(Debug)]
struct CellRatios {
    size: Size,
    scenario: Scenario,
    v8_ns_per_call: f64,
    sve16_v6_ns_per_call: f64,
    sve16_v6: Vec<f64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ColdStage {
    Emit,
    Publish,
    PublishFirstCall,
    BuildEmitPublishFirstCall,
}

impl ColdStage {
    const ALL: [Self; 4] = [
        Self::Emit,
        Self::Publish,
        Self::PublishFirstCall,
        Self::BuildEmitPublishFirstCall,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Emit => "emit",
            Self::Publish => "publish",
            Self::PublishFirstCall => "publish-first-call",
            Self::BuildEmitPublishFirstCall => "build-emit-publish-first-call",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct ColdTiming {
    stage: ColdStage,
    backend: Backend,
    repetition: usize,
    position: usize,
    total: Duration,
    checksum: u64,
    cpu_before: u32,
    cpu_after: u32,
}

fn main() -> Result<(), Box<dyn Error>> {
    let affinity_cpu = require_and_report_environment()?;
    let program =
        build_exact_literal::<Span>(LITERAL, AnchorFlags::default(), ValidateLimits::default())?;
    let images = Backend::ALL.map(|backend| (backend, backend.emit(&program)));
    for (backend, image) in &images {
        println!(
            "IMAGE\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            backend.name(),
            image.backend_version().0,
            image.artifact_identity(),
            image.target().features.bits(),
            image.stats().code_bytes,
            image.stats().data_bytes,
            image.stats().vector_instructions,
            image.layout().total_mapped_bytes,
        );
    }
    require_backend_versions(&images)?;
    report_qualification_target(&images);
    let filter_offsets = require_common_filter_offsets(&images)?;
    print_meta(
        "authenticated_filter_offsets",
        format_args!(
            "{},{},{},{}",
            filter_offsets.0[0], filter_offsets.0[1], filter_offsets.0[2], filter_offsets.0[3]
        ),
    );

    let kernels = Kernels {
        v8: publish_image(Backend::V8, &images),
        sve16_v6: publish_image(Backend::Sve16V6, &images),
    };
    verify_abi_canaries(&kernels)?;
    let adaptive_comparisons = adaptive_correctness_matrix(&program, &kernels, filter_offsets)?;
    let comparisons = correctness_matrix(&program, &kernels)?
        .checked_add(expanded_correctness_matrix()?)
        .and_then(|count| count.checked_add(adaptive_comparisons))
        .expect("bounded correctness comparison count");
    println!("CORRECTNESS\tPASS\tcomparisons={comparisons}");
    let cold = measure_cold_costs(&program, &images, affinity_cpu)?;

    println!(
        "RAW_HEADER\tscenario\tsize\trepetition\tposition\tbackend\titerations\ttotal_ns\tns_per_call\tchecksum\tcpu_before\tcpu_after"
    );
    let mut all_cell_ratios = Vec::new();
    let mut cell_index = 0_usize;
    for size in Size::ALL {
        for scenario in Scenario::ALL {
            let haystack = make_haystack(size, scenario, filter_offsets)?;
            let window = SearchWindow::new(0, haystack.len());
            assert_all_equal(&program, &kernels, &haystack, window)?;
            let timings = measure_cell(
                &kernels,
                &haystack,
                window,
                size,
                scenario,
                cell_index,
                affinity_cpu,
            )?;
            all_cell_ratios.push(report_cell(size, scenario, &timings));
            cell_index = cell_index.checked_add(1).expect("forty fixed cells");
        }
    }
    report_break_even(&cold, &all_cell_ratios);
    if !report_gate(Backend::Sve16V6, &all_cell_ratios) {
        return Err("SVE ID19 qualification gate failed".into());
    }
    Ok(())
}

#[cfg(all(
    feature = "sve-hardware-qualification",
    target_arch = "aarch64",
    any(target_os = "macos", target_os = "linux"),
    target_pointer_width = "64",
    target_endian = "little"
))]
fn verify_abi_canaries(kernels: &Kernels) -> Result<(), Box<dyn Error>> {
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
    for backend in Backend::ALL {
        let preserved = fre_jit_runtime::qualification_preserves_vector_callee_saved_lanes(
            kernels.get(backend),
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
fn verify_abi_canaries(_kernels: &Kernels) -> Result<(), Box<dyn Error>> {
    Err("build the AArch64 qualification harness with sve-hardware-qualification".into())
}

fn require_and_report_environment() -> Result<u32, Box<dyn Error>> {
    require_source_binding()?;
    let affinity_cpu = require_single_cpu_affinity()?;
    let capabilities = native_host_capabilities()?;
    if !capabilities.has_asimd() || !capabilities.has_sve() {
        return Err(format!("qualification requires ASIMD+SVE: {capabilities:?}").into());
    }
    let observed_vector_bytes = capabilities
        .sve_vector_bytes()
        .ok_or("SVE vector length must be observable for qualification")?;
    if observed_vector_bytes != 16 {
        return Err(format!(
            "qualification launcher requested 16 SVE bytes but observed {observed_vector_bytes}"
        )
        .into());
    }
    let tuning = fre_target_features::host().tuning();
    let cpu = match tuning {
        TuningClass::ArmServer { cpu: Some(cpu) }
            if cpu.implementer == 0x41 && cpu.part == 0x0d84 =>
        {
            cpu
        }
        _ => {
            return Err(format!(
                "qualification requires homogeneous Arm 0x41/0xd84, got {tuning:?}"
            )
            .into());
        }
    };
    print_meta("schema", SCHEMA);
    print_meta("source_commit", SOURCE_COMMIT);
    print_meta("source_tree", SOURCE_TREE);
    print_meta("source_archive_sha256", SOURCE_ARCHIVE_SHA256);
    print_meta("build_receipt_sha256", BUILD_RECEIPT_SHA256);
    print_meta("toolchain_root", TOOLCHAIN_ROOT);
    print_meta("cargo_sha256", CARGO_SHA256);
    print_meta("rustc_sha256", RUSTC_SHA256);
    print_meta("toolchain_closure_sha256", TOOLCHAIN_CLOSURE_SHA256);
    print_meta("toolchain_closure_entries", TOOLCHAIN_CLOSURE_ENTRIES);
    print_meta("toolchain_closure_file_bytes", TOOLCHAIN_CLOSURE_FILE_BYTES);
    print_meta("rustc_sysroot_binding", RUSTC_SYSROOT_BINDING);
    print_meta("rustdoc_invocation", RUSTDOC_INVOCATION);
    print_meta("cargo_registry_root", CARGO_REGISTRY_ROOT);
    print_meta(
        "cargo_registry_closure_sha256",
        CARGO_REGISTRY_CLOSURE_SHA256,
    );
    print_meta(
        "cargo_registry_closure_entries",
        CARGO_REGISTRY_CLOSURE_ENTRIES,
    );
    print_meta(
        "cargo_registry_closure_file_bytes",
        CARGO_REGISTRY_CLOSURE_FILE_BYTES,
    );
    print_meta(
        "cargo_registry_snapshot_policy",
        CARGO_REGISTRY_SNAPSHOT_POLICY,
    );
    print_meta(
        "dependency_lock_archive_proof_sha256",
        DEPENDENCY_LOCK_ARCHIVE_PROOF_SHA256,
    );
    print_meta("dependency_archive_count", DEPENDENCY_ARCHIVE_COUNT);
    print_meta("qualification_run_id", QUALIFICATION_RUN_ID);
    print_meta("expected_region", EXPECTED_REGION);
    print_meta("expected_instance_id", EXPECTED_INSTANCE_ID);
    print_meta("expected_instance_type", EXPECTED_INSTANCE_TYPE);
    print_meta("process_id", std::process::id());
    print_meta("arch", std::env::consts::ARCH);
    print_meta("os", std::env::consts::OS);
    print_meta("affinity_cpu", affinity_cpu);
    print_meta("asimd", capabilities.has_asimd());
    print_meta("sve", capabilities.has_sve());
    print_meta(
        "arm_cpu_implementer",
        format_args!("0x{:04x}", cpu.implementer),
    );
    print_meta("arm_cpu_part", format_args!("0x{:04x}", cpu.part));
    print_meta("sve2_observed", capabilities.has_sve2());
    print_meta("observed_thread_sve_vector_bytes", observed_vector_bytes);
    print_meta("requested_thread_sve_vector_bytes", 16);
    print_meta("sve_lane_contract", "PTRUE-VL16");
    print_meta("active_sve_byte_lanes", 16);
    print_meta("repetitions", REPETITIONS);
    print_meta("minimum_sample_ns", MIN_SAMPLE_TIME.as_nanos());
    print_meta("confidence_method", "paired-log-mean-t95-df29");
    print_meta("order_schedule", "both-orders-alternated-fifteen-times");
    Ok(affinity_cpu)
}

#[allow(
    clippy::too_many_lines,
    reason = "the source-binding gate checks one closed ordered evidence schema in a single boundary"
)]
fn require_source_binding() -> Result<(), Box<dyn Error>> {
    for (label, value, length) in [
        ("FRE_SOURCE_COMMIT", SOURCE_COMMIT, 40),
        ("FRE_SOURCE_TREE", SOURCE_TREE, 40),
        ("FRE_SOURCE_ARCHIVE_SHA256", SOURCE_ARCHIVE_SHA256, 64),
        ("FRE_BUILD_RECEIPT_SHA256", BUILD_RECEIPT_SHA256, 64),
        ("FRE_CARGO_SHA256", CARGO_SHA256, 64),
        ("FRE_RUSTC_SHA256", RUSTC_SHA256, 64),
        ("FRE_TOOLCHAIN_CLOSURE_SHA256", TOOLCHAIN_CLOSURE_SHA256, 64),
        (
            "FRE_CARGO_REGISTRY_CLOSURE_SHA256",
            CARGO_REGISTRY_CLOSURE_SHA256,
            64,
        ),
        (
            "FRE_DEPENDENCY_LOCK_ARCHIVE_PROOF_SHA256",
            DEPENDENCY_LOCK_ARCHIVE_PROOF_SHA256,
            64,
        ),
    ] {
        if value == "unbound"
            || value.len() != length
            || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(format!("set exact hexadecimal {label} at build time").into());
        }
    }
    if TOOLCHAIN_ROOT == "unbound"
        || !TOOLCHAIN_ROOT.starts_with('/')
        || TOOLCHAIN_ROOT.ends_with('/')
        || TOOLCHAIN_ROOT.contains("//")
        || TOOLCHAIN_ROOT
            .split('/')
            .skip(1)
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
        || !TOOLCHAIN_ROOT.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'/' | b'.' | b'_' | b'+' | b'@' | b'=' | b'-')
        })
    {
        return Err("set an absolute canonical FRE_TOOLCHAIN_ROOT at build time".into());
    }
    if CARGO_REGISTRY_ROOT == "unbound"
        || !CARGO_REGISTRY_ROOT.starts_with('/')
        || !CARGO_REGISTRY_ROOT.ends_with("/registry")
        || CARGO_REGISTRY_ROOT == "/registry"
        || CARGO_REGISTRY_ROOT.contains("//")
        || CARGO_REGISTRY_ROOT
            .split('/')
            .skip(1)
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
        || !CARGO_REGISTRY_ROOT.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'/' | b'.' | b'_' | b'+' | b'@' | b'=' | b'-')
        })
    {
        return Err("set an absolute canonical FRE_CARGO_REGISTRY_ROOT at build time".into());
    }
    if RUSTC_SYSROOT_BINDING != "toolchain-root" {
        return Err("bind direct rustc sysroot to FRE_TOOLCHAIN_ROOT at build time".into());
    }
    if RUSTDOC_INVOCATION != "not-invoked" {
        return Err("qualification must build with rustdoc explicitly not invoked".into());
    }
    if CARGO_REGISTRY_SNAPSHOT_POLICY != "private-full-registry-snapshot-v1" {
        return Err("qualification must consume one private full-registry snapshot".into());
    }
    for (label, value, maximum) in [
        (
            "FRE_TOOLCHAIN_CLOSURE_ENTRIES",
            TOOLCHAIN_CLOSURE_ENTRIES,
            16_384_u64,
        ),
        (
            "FRE_TOOLCHAIN_CLOSURE_FILE_BYTES",
            TOOLCHAIN_CLOSURE_FILE_BYTES,
            4_294_967_296_u64,
        ),
        (
            "FRE_CARGO_REGISTRY_CLOSURE_ENTRIES",
            CARGO_REGISTRY_CLOSURE_ENTRIES,
            100_000_u64,
        ),
        (
            "FRE_CARGO_REGISTRY_CLOSURE_FILE_BYTES",
            CARGO_REGISTRY_CLOSURE_FILE_BYTES,
            4_294_967_296_u64,
        ),
        (
            "FRE_DEPENDENCY_ARCHIVE_COUNT",
            DEPENDENCY_ARCHIVE_COUNT,
            4_096_u64,
        ),
    ] {
        let valid = value != "unbound"
            && value.bytes().all(|byte| byte.is_ascii_digit())
            && !value.starts_with('0')
            && value.parse::<u64>().is_ok_and(|parsed| parsed <= maximum);
        if !valid {
            return Err(format!("set bounded canonical decimal {label} at build time").into());
        }
    }
    if QUALIFICATION_RUN_ID == "unbound"
        || QUALIFICATION_RUN_ID.is_empty()
        || QUALIFICATION_RUN_ID.len() > 80
        || !QUALIFICATION_RUN_ID
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err("set a bounded FRE_QUALIFICATION_RUN_ID at build time".into());
    }
    if EXPECTED_REGION == "unbound"
        || EXPECTED_INSTANCE_ID == "unbound"
        || EXPECTED_INSTANCE_TYPE == "unbound"
        || !EXPECTED_INSTANCE_ID.starts_with("i-")
        || !(EXPECTED_INSTANCE_TYPE.starts_with("m9g.")
            || EXPECTED_INSTANCE_TYPE.starts_with("c9g."))
    {
        return Err("set the attested AWS region, instance ID, and c9g/m9g type".into());
    }
    Ok(())
}

fn print_meta(key: &str, value: impl std::fmt::Display) {
    println!("META\t{key}\t{value}");
}

fn require_single_cpu_affinity() -> Result<u32, Box<dyn Error>> {
    let status = fs::read_to_string("/proc/self/status")?;
    let allowed = status
        .lines()
        .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))
        .map(str::trim)
        .ok_or("missing Cpus_allowed_list in /proc/self/status")?;
    if allowed.contains(',') || allowed.contains('-') {
        return Err(format!("qualification requires one taskset CPU, got {allowed}").into());
    }
    let affinity_cpu = allowed.parse::<u32>()?;
    let current = observed_cpu()?;
    if current != affinity_cpu {
        return Err(
            format!("current CPU {current} differs from affinity CPU {affinity_cpu}").into(),
        );
    }
    Ok(affinity_cpu)
}

fn observed_cpu() -> Result<u32, Box<dyn Error>> {
    let stat = fs::read_to_string("/proc/self/stat")?;
    let close = stat
        .rfind(") ")
        .ok_or("malformed /proc/self/stat process name")?;
    let processor = stat[close + 2..]
        .split_whitespace()
        .nth(36)
        .ok_or("missing processor field in /proc/self/stat")?;
    Ok(processor.parse::<u32>()?)
}

fn require_backend_versions(images: &[(Backend, NativeImage); 2]) -> Result<(), Box<dyn Error>> {
    let expected = [BackendVersion::SEARCH_V8, BackendVersion::SEARCH_SVE16_V6];
    for ((backend, image), expected_version) in images.iter().zip(expected) {
        if image.backend_version() != expected_version {
            return Err(format!(
                "{} emitted backend {}, expected {}",
                backend.name(),
                image.backend_version().0,
                expected_version.0
            )
            .into());
        }
    }
    Ok(())
}

fn report_qualification_target(images: &[(Backend, NativeImage); 2]) {
    let (backend, image) = images
        .iter()
        .find(|(backend, _)| *backend == Backend::Sve16V6)
        .expect("the ID19 image exists");
    println!(
        "QUALIFICATION_TARGET\t{}\tbackend_version={}\tfeature_bits={}\tqualification_state=Candidate\tartifact_identity={}",
        backend.name(),
        image.backend_version().0,
        image.target().features.bits(),
        image.artifact_identity(),
    );
}

fn require_common_filter_offsets(
    images: &[(Backend, NativeImage); 2],
) -> Result<FilterOffsets, Box<dyn Error>> {
    let mut common = None;
    for (backend, image) in images {
        let artifact = image.to_aot(AotLimits::default())?;
        let bytes = artifact.as_bytes();
        if bytes.len() < 78 || &bytes[..7] != b"FREA64\0" {
            return Err(format!(
                "{} AOT manifest is too short or has bad magic",
                backend.name()
            )
            .into());
        }
        let literal_bytes = read_u32(bytes, 62)?;
        let candidate_block_width = read_u16(bytes, 68)?;
        if literal_bytes != 16 || candidate_block_width != 16 {
            return Err(format!(
                "{} manifest shape differs: literal={literal_bytes}, block={candidate_block_width}",
                backend.name()
            )
            .into());
        }
        let offsets = FilterOffsets([
            usize::from(read_u16(bytes, 70)?),
            usize::from(read_u16(bytes, 72)?),
            usize::from(read_u16(bytes, 74)?),
            usize::from(read_u16(bytes, 76)?),
        ]);
        let mut sorted = offsets.0;
        sorted.sort_unstable();
        if sorted.iter().any(|offset| *offset >= LITERAL.len())
            || sorted.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(format!(
                "{} manifest has invalid filter offsets {offsets:?}",
                backend.name()
            )
            .into());
        }
        if common.is_some_and(|existing| existing != offsets) {
            return Err(format!("backend filter offsets differ at {}", backend.name()).into());
        }
        common = Some(offsets);
    }
    common.ok_or_else(|| "no images supplied".into())
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

fn publish_image(backend: Backend, images: &[(Backend, NativeImage); 2]) -> PublishedKernel<Span> {
    let image = images
        .iter()
        .find_map(|(candidate, image)| (*candidate == backend).then_some(image))
        .expect("both images exist");
    publish(image, PublicationLimits::default()).expect("strict W^X publication")
}

fn measure_cold_costs(
    program: &ValidatedProgram<Span>,
    images: &[(Backend, NativeImage); 2],
    affinity_cpu: u32,
) -> Result<Vec<ColdTiming>, Box<dyn Error>> {
    let haystack = vec![b'x'; 64 * 1024];
    let window = SearchWindow::new(0, haystack.len());
    println!(
        "COLD_RAW_HEADER\tstage\trepetition\tposition\tbackend\ttotal_ns\tchecksum\tcpu_before\tcpu_after"
    );
    let mut timings = Vec::with_capacity(
        ColdStage::ALL
            .len()
            .checked_mul(REPETITIONS)
            .and_then(|count| count.checked_mul(Backend::ALL.len()))
            .expect("fixed cold matrix"),
    );
    for stage in ColdStage::ALL {
        for repetition in 0..REPETITIONS {
            let order = BACKEND_ORDERS[repetition % BACKEND_ORDERS.len()];
            for (position, backend) in order.into_iter().enumerate() {
                let cpu_before = observed_cpu()?;
                let (total, checksum) =
                    time_cold(stage, backend, program, images, &haystack, window);
                let cpu_after = observed_cpu()?;
                require_stable_cpu(affinity_cpu, cpu_before, cpu_after)?;
                println!(
                    "COLD_RAW\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    stage.name(),
                    repetition,
                    position,
                    backend.name(),
                    total.as_nanos(),
                    checksum,
                    cpu_before,
                    cpu_after,
                );
                timings.push(ColdTiming {
                    stage,
                    backend,
                    repetition,
                    position,
                    total,
                    checksum,
                    cpu_before,
                    cpu_after,
                });
            }
        }
    }
    validate_cold_timings(&timings, affinity_cpu)?;
    for stage in ColdStage::ALL {
        for backend in Backend::ALL {
            let median = median_cold_ns(&timings, stage, backend);
            println!(
                "COLD_SUMMARY\t{}\t{}\tmedian_ns={median:.3}",
                stage.name(),
                backend.name()
            );
        }
    }
    Ok(timings)
}

fn validate_cold_timings(timings: &[ColdTiming], affinity_cpu: u32) -> Result<(), Box<dyn Error>> {
    for stage in ColdStage::ALL {
        for repetition in 0..REPETITIONS {
            let row: Vec<&ColdTiming> = timings
                .iter()
                .filter(|timing| timing.stage == stage && timing.repetition == repetition)
                .collect();
            if row.len() != Backend::ALL.len()
                || row.iter().any(|timing| {
                    timing.cpu_before != affinity_cpu || timing.cpu_after != affinity_cpu
                })
            {
                return Err(format!("invalid cold timing pair {stage:?}/{repetition}").into());
            }
            if matches!(
                stage,
                ColdStage::PublishFirstCall | ColdStage::BuildEmitPublishFirstCall
            ) && row
                .windows(2)
                .any(|pair| pair[0].checksum != pair[1].checksum)
            {
                return Err(
                    format!("cold semantic checksum mismatch {stage:?}/{repetition}").into(),
                );
            }
        }
    }
    Ok(())
}

fn time_cold(
    stage: ColdStage,
    backend: Backend,
    program: &ValidatedProgram<Span>,
    images: &[(Backend, NativeImage); 2],
    haystack: &[u8],
    window: SearchWindow,
) -> (Duration, u64) {
    let existing_image = images
        .iter()
        .find_map(|(candidate, image)| (*candidate == backend).then_some(image))
        .expect("all images exist");
    match stage {
        ColdStage::Emit => {
            let started = Instant::now();
            let image = backend.emit(black_box(program));
            let checksum = image_identity_checksum(&image);
            let total = started.elapsed();
            black_box(image);
            (total, checksum)
        }
        ColdStage::Publish => {
            let started = Instant::now();
            let kernel = publish::<Span>(black_box(existing_image), PublicationLimits::default())
                .expect("cold strict W^X publication");
            let checksum = runtime_identity_checksum(&kernel);
            let total = started.elapsed();
            black_box(kernel);
            (total, checksum)
        }
        ColdStage::PublishFirstCall => {
            let started = Instant::now();
            let kernel = publish::<Span>(black_box(existing_image), PublicationLimits::default())
                .expect("cold strict W^X publication");
            let output = kernel
                .search(black_box(haystack), window)
                .expect("cold first call");
            let checksum = encode_span(output);
            let total = started.elapsed();
            black_box(kernel);
            (total, checksum)
        }
        ColdStage::BuildEmitPublishFirstCall => {
            let started = Instant::now();
            let cold_program = build_exact_literal::<Span>(
                LITERAL,
                AnchorFlags::default(),
                ValidateLimits::default(),
            )
            .expect("cold Kernel IR build");
            let image = backend.emit(black_box(&cold_program));
            let kernel = publish::<Span>(&image, PublicationLimits::default())
                .expect("cold end-to-end publication");
            let output = kernel
                .search(black_box(haystack), window)
                .expect("cold end-to-end first call");
            let checksum = encode_span(output);
            let total = started.elapsed();
            black_box((cold_program, image, kernel));
            (total, checksum)
        }
    }
}

fn image_identity_checksum(image: &NativeImage) -> u64 {
    image
        .artifact_identity()
        .as_bytes()
        .iter()
        .fold(u64::from(image.backend_version().0), |checksum, byte| {
            checksum.rotate_left(5) ^ u64::from(*byte)
        })
}

fn runtime_identity_checksum(kernel: &PublishedKernel<Span>) -> u64 {
    kernel
        .identity()
        .as_bytes()
        .iter()
        .fold(0_u64, |checksum, byte| {
            checksum.rotate_left(5) ^ u64::from(*byte)
        })
}

fn require_stable_cpu(
    affinity_cpu: u32,
    cpu_before: u32,
    cpu_after: u32,
) -> Result<(), Box<dyn Error>> {
    if cpu_before != affinity_cpu || cpu_after != affinity_cpu {
        return Err(format!(
            "CPU affinity drift: affinity={affinity_cpu}, before={cpu_before}, after={cpu_after}"
        )
        .into());
    }
    Ok(())
}

fn correctness_matrix(
    program: &ValidatedProgram<Span>,
    kernels: &Kernels,
) -> Result<u64, Box<dyn Error>> {
    let mut comparisons = 0_u64;
    let lengths = [
        0_usize, 1, 15, 16, 17, 31, 32, 47, 48, 63, 64, 65, 79, 80, 81, 95, 96, 127,
    ];
    for length in lengths {
        for alignment in 0..16 {
            let mut owned = aligned_haystack(length, alignment, b'x');
            assert_all_equal(
                program,
                kernels,
                owned.as_slice(),
                SearchWindow::new(0, length),
            )?;
            comparisons = comparisons
                .checked_add(u64::try_from(Backend::ALL.len()).expect("two backends"))
                .expect("bounded matrix");
            if length >= LITERAL.len() {
                for position in candidate_positions(length) {
                    owned.as_mut_slice().fill(b'x');
                    owned.as_mut_slice()[position..position + LITERAL.len()]
                        .copy_from_slice(LITERAL);
                    for window in correctness_windows(length, position) {
                        assert_all_equal(program, kernels, owned.as_slice(), window)?;
                        comparisons = comparisons
                            .checked_add(u64::try_from(Backend::ALL.len()).expect("two backends"))
                            .expect("bounded matrix");
                    }
                }
            }
        }
    }

    let mut random = XorShift64::new(0x5e11_6a2d_c39b_740f);
    for _ in 0..RANDOM_CORRECTNESS_CASES {
        let length = random.bounded(257);
        let alignment = random.bounded(16);
        let mut owned = aligned_haystack(length, alignment, b'x');
        random.fill(owned.as_mut_slice());
        if length >= LITERAL.len() && random.next() & 1 == 0 {
            let position = random.bounded(length - LITERAL.len() + 1);
            owned.as_mut_slice()[position..position + LITERAL.len()].copy_from_slice(LITERAL);
        }
        let start = random.bounded(length + 1);
        let end = start + random.bounded(length - start + 1);
        assert_all_equal(
            program,
            kernels,
            owned.as_slice(),
            SearchWindow::new(start, end),
        )?;
        comparisons = comparisons
            .checked_add(u64::try_from(Backend::ALL.len()).expect("two backends"))
            .expect("bounded matrix");
    }
    Ok(comparisons)
}

fn adaptive_correctness_matrix(
    program: &ValidatedProgram<Span>,
    kernels: &Kernels,
    filter_offsets: FilterOffsets,
) -> Result<u64, Box<dyn Error>> {
    let mut absent = vec![b'x'; ADAPTIVE_CORRECTNESS_BYTES];
    let evidence = synthesize_adaptive_secondary_dense_primary_absent(&mut absent, filter_offsets)?;
    let expected_later = ADAPTIVE_CORRECTNESS_BYTES
        .checked_sub(LITERAL.len())
        .and_then(|maximum_start| maximum_start.checked_add(1))
        .and_then(|candidate_starts| candidate_starts.checked_sub(WIDE_CANDIDATE_STARTS))
        .expect("512-byte adaptive correctness fixture has later candidates");
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
        return Err("512-byte adaptive absent fixture violated its frozen invariants".into());
    }

    let window = SearchWindow::new(0, absent.len());
    assert_all_equal(program, kernels, &absent, window)?;
    let mut comparisons =
        u64::try_from(Backend::ALL.len()).expect("two adaptive absent backend comparisons");

    let mut present = absent;
    let match_end = ADAPTIVE_CORRECTNESS_MATCH_START
        .checked_add(LITERAL.len())
        .expect("bounded adaptive correctness match");
    present[ADAPTIVE_CORRECTNESS_MATCH_START..match_end].copy_from_slice(LITERAL);
    let literal_starts: Vec<usize> = present
        .windows(LITERAL.len())
        .enumerate()
        .filter_map(|(start, candidate)| (candidate == LITERAL).then_some(start))
        .collect();
    if literal_starts != [ADAPTIVE_CORRECTNESS_MATCH_START] {
        return Err(format!(
            "adaptive present fixture has unexpected literal starts: {literal_starts:?}"
        )
        .into());
    }
    assert_all_equal(program, kernels, &present, window)?;
    comparisons = comparisons
        .checked_add(u64::try_from(Backend::ALL.len()).expect("two adaptive present comparisons"))
        .expect("four bounded adaptive correctness comparisons");
    Ok(comparisons)
}

fn expanded_correctness_matrix() -> Result<u64, Box<dyn Error>> {
    let mut comparisons = 0_u64;
    // Tag19's exact production envelope starts at 16 literal bytes. Shorter
    // literals are rejected by the emitter and remain covered by its unit
    // refusal test rather than being mixed into this paired hardware receipt.
    for width in [16_usize, 17, 31, 32] {
        let literal: Vec<u8> = (0..width)
            .map(|offset| 0x80_u8.wrapping_add(u8::try_from(offset).expect("width is at most 32")))
            .collect();
        comparisons = comparisons
            .checked_add(expanded_correctness_for::<Exists>(&literal)?)
            .expect("bounded expanded correctness matrix");
        comparisons = comparisons
            .checked_add(expanded_correctness_for::<SelectedEnd>(&literal)?)
            .expect("bounded expanded correctness matrix");
        comparisons = comparisons
            .checked_add(expanded_correctness_for::<Span>(&literal)?)
            .expect("bounded expanded correctness matrix");
    }
    Ok(comparisons)
}

fn expanded_correctness_for<O>(literal: &[u8]) -> Result<u64, Box<dyn Error>>
where
    O: RuntimeOperation,
    O::Output: std::fmt::Debug + Eq,
{
    let program =
        build_exact_literal::<O>(literal, AnchorFlags::default(), ValidateLimits::default())?;
    let images = Backend::ALL.map(|backend| (backend, backend.emit(&program)));
    let kernels = images
        .iter()
        .map(|(backend, image)| Ok((*backend, publish::<O>(image, PublicationLimits::default())?)))
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let mut lengths = vec![
        0,
        literal.len().saturating_sub(1),
        literal.len(),
        literal.len().checked_add(1).expect("width at most 32"),
        15,
        16,
        17,
        31,
        32,
        63,
        64,
        65,
        95,
        96,
    ];
    lengths.sort_unstable();
    lengths.dedup();
    let mut comparisons = 0_u64;
    for length in lengths {
        for alignment in 0..16 {
            let mut owned = aligned_haystack(length, alignment, b'x');
            assert_generic_equal(
                &program,
                &kernels,
                owned.as_slice(),
                SearchWindow::new(0, length),
            )?;
            comparisons = comparisons
                .checked_add(u64::try_from(Backend::ALL.len()).expect("two backends"))
                .expect("bounded matrix");
            if length < literal.len() {
                continue;
            }
            for position in candidate_positions_for(length, literal.len()) {
                owned.as_mut_slice().fill(b'x');
                let end = position
                    .checked_add(literal.len())
                    .expect("literal fits correctness haystack");
                owned.as_mut_slice()[position..end].copy_from_slice(literal);
                for window in [
                    SearchWindow::new(0, length),
                    SearchWindow::new(position, end),
                    SearchWindow::new(0, position),
                    SearchWindow::new(end, length),
                ] {
                    assert_generic_equal(&program, &kernels, owned.as_slice(), window)?;
                    comparisons = comparisons
                        .checked_add(u64::try_from(Backend::ALL.len()).expect("two backends"))
                        .expect("bounded matrix");
                }
            }
        }
    }
    Ok(comparisons)
}

fn assert_generic_equal<O>(
    program: &ValidatedProgram<O>,
    kernels: &[(Backend, PublishedKernel<O>)],
    haystack: &[u8],
    window: SearchWindow,
) -> Result<(), Box<dyn Error>>
where
    O: RuntimeOperation,
    O::Output: std::fmt::Debug + Eq,
{
    let expected = program
        .execute(haystack, window, ExecutionLimits::unlimited())?
        .into_output();
    for (backend, kernel) in kernels {
        let actual = kernel.search(haystack, window)?;
        if actual != expected {
            return Err(format!(
                "{} generic mismatch: width={}, length={}, window={window:?}, expected={expected:?}, actual={actual:?}",
                backend.name(),
                program.raw().data.as_slice().len(),
                haystack.len(),
            )
            .into());
        }
    }
    Ok(())
}

fn candidate_positions_for(length: usize, literal_len: usize) -> Vec<usize> {
    let last = length
        .checked_sub(literal_len)
        .expect("literal fits correctness haystack");
    let mut positions = vec![0, last / 2, last];
    for boundary in [15_usize, 16, 31, 32, 47, 48, 63, 64] {
        if boundary <= last {
            positions.push(boundary);
        }
    }
    positions.sort_unstable();
    positions.dedup();
    positions
}

fn candidate_positions(length: usize) -> Vec<usize> {
    let last = length - LITERAL.len();
    let mut positions = vec![0, last / 2, last];
    for boundary in [15_usize, 16, 31, 32, 47, 48, 63, 64] {
        if boundary <= last {
            positions.push(boundary);
        }
    }
    positions.sort_unstable();
    positions.dedup();
    positions
}

fn correctness_windows(length: usize, position: usize) -> [SearchWindow; 4] {
    let matched_end = position + LITERAL.len();
    [
        SearchWindow::new(0, length),
        SearchWindow::new(position, matched_end),
        SearchWindow::new(0, position),
        SearchWindow::new(matched_end, length),
    ]
}

fn assert_all_equal(
    program: &ValidatedProgram<Span>,
    kernels: &Kernels,
    haystack: &[u8],
    window: SearchWindow,
) -> Result<(), Box<dyn Error>> {
    let expected = program
        .execute(haystack, window, ExecutionLimits::unlimited())?
        .into_output();
    for backend in Backend::ALL {
        let actual = kernels.get(backend).search(haystack, window)?;
        if actual != expected {
            return Err(format!(
                "{} mismatch: length={}, window={window:?}, expected={expected:?}, actual={actual:?}",
                backend.name(),
                haystack.len(),
            )
            .into());
        }
    }
    Ok(())
}

fn make_haystack(
    size: Size,
    scenario: Scenario,
    filter_offsets: FilterOffsets,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut haystack = vec![b'x'; size.bytes()];
    let adaptive_evidence = match scenario {
        Scenario::Present => {
            let position = (haystack.len() - LITERAL.len()) / 2;
            haystack[position..position + LITERAL.len()].copy_from_slice(LITERAL);
            None
        }
        Scenario::Absent => None,
        Scenario::PrimaryDenseSecondaryAbsent => {
            synthesize_filter_hits(&mut haystack, filter_offsets, 1)?;
            None
        }
        Scenario::AdaptiveSecondaryDensePrimaryAbsent => Some(
            synthesize_adaptive_secondary_dense_primary_absent(&mut haystack, filter_offsets)?,
        ),
        Scenario::PairDenseLiteralAbsent => {
            synthesize_filter_hits(&mut haystack, filter_offsets, 2)?;
            None
        }
        Scenario::TripleDenseLiteralAbsent => {
            synthesize_filter_hits(&mut haystack, filter_offsets, 3)?;
            None
        }
        Scenario::FourFilterDenseLiteralAbsent => {
            synthesize_filter_hits(&mut haystack, filter_offsets, 4)?;
            None
        }
        Scenario::Tail => {
            let position = haystack.len() - LITERAL.len();
            haystack[position..].copy_from_slice(LITERAL);
            None
        }
    };
    let filter_columns = match scenario {
        Scenario::PrimaryDenseSecondaryAbsent => 1,
        Scenario::PairDenseLiteralAbsent => 2,
        Scenario::TripleDenseLiteralAbsent => 3,
        Scenario::FourFilterDenseLiteralAbsent => 4,
        Scenario::Present
        | Scenario::Absent
        | Scenario::AdaptiveSecondaryDensePrimaryAbsent
        | Scenario::Tail => 0,
    };
    if filter_columns > 0 {
        if haystack
            .windows(LITERAL.len())
            .any(|window| window == LITERAL)
        {
            return Err(format!(
                "{} fixture accidentally contains the literal",
                scenario.name()
            )
            .into());
        }
        let hits = count_filter_hits(&haystack, filter_offsets, filter_columns);
        if hits == 0 {
            return Err(format!("{} fixture has no selected-filter hits", scenario.name()).into());
        }
        println!(
            "FIXTURE\t{}\t{}\tselected_columns={filter_columns}\tselected_filter_hits={hits}\tliteral_matches=0",
            scenario.name(),
            size.name(),
        );
    }
    if let Some(evidence) = adaptive_evidence {
        println!(
            "FIXTURE\t{}\t{}\tfirst_group_primary_hits={}\tfirst_group_pair_hits={}\tlater_candidate_starts={}\tlater_secondary_hits={}\tlater_primary_hits={}\tliteral_matches={}",
            scenario.name(),
            size.name(),
            evidence.first_group_primary_hits,
            evidence.first_group_pair_hits,
            evidence.later_candidate_starts,
            evidence.later_secondary_hits,
            evidence.later_primary_hits,
            evidence.literal_matches,
        );
    }
    Ok(haystack)
}

fn synthesize_adaptive_secondary_dense_primary_absent(
    haystack: &mut [u8],
    filter_offsets: FilterOffsets,
) -> Result<AdaptiveFixtureEvidence, Box<dyn Error>> {
    let candidate_starts = haystack
        .len()
        .checked_sub(LITERAL.len())
        .and_then(|maximum_start| maximum_start.checked_add(1))
        .ok_or("adaptive fixture is shorter than the literal")?;
    let later_candidate_starts = candidate_starts
        .checked_sub(WIDE_CANDIDATE_STARTS)
        .ok_or("adaptive fixture cannot cover the first 64 candidate starts")?;
    let primary_offset = filter_offsets.0[0];
    let secondary_offset = filter_offsets.0[1];
    let primary = *LITERAL
        .get(primary_offset)
        .ok_or("authenticated primary offset exceeds the literal")?;
    let secondary = *LITERAL
        .get(secondary_offset)
        .ok_or("authenticated secondary offset exceeds the literal")?;
    if primary_offset == secondary_offset || primary == secondary {
        return Err("adaptive fixture requires distinct primary and secondary filters".into());
    }

    haystack[primary_offset] = primary;
    let secondary_dense_start = WIDE_CANDIDATE_STARTS
        .checked_add(secondary_offset)
        .expect("bounded adaptive secondary start");
    haystack
        .get_mut(secondary_dense_start..)
        .ok_or("adaptive secondary start exceeds the haystack")?
        .fill(secondary);

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
            "adaptive fixture invariant mismatch: expected={expected:?}, observed={evidence:?}"
        )
        .into());
    }
    Ok(evidence)
}

fn adaptive_fixture_evidence(
    haystack: &[u8],
    filter_offsets: FilterOffsets,
) -> Result<AdaptiveFixtureEvidence, Box<dyn Error>> {
    let candidate_starts = haystack
        .len()
        .checked_sub(LITERAL.len())
        .and_then(|maximum_start| maximum_start.checked_add(1))
        .ok_or("adaptive fixture is shorter than the literal")?;
    if candidate_starts < WIDE_CANDIDATE_STARTS {
        return Err("adaptive fixture cannot cover the first 64 candidate starts".into());
    }
    let primary_offset = filter_offsets.0[0];
    let secondary_offset = filter_offsets.0[1];
    let primary = *LITERAL
        .get(primary_offset)
        .ok_or("authenticated primary offset exceeds the literal")?;
    let secondary = *LITERAL
        .get(secondary_offset)
        .ok_or("authenticated secondary offset exceeds the literal")?;
    let primary_hit = |candidate: usize| haystack[candidate + primary_offset] == primary;
    let secondary_hit = |candidate: usize| haystack[candidate + secondary_offset] == secondary;
    let first_group_primary_hits = (0..WIDE_CANDIDATE_STARTS)
        .filter(|candidate| primary_hit(*candidate))
        .count();
    let first_group_pair_hits = (0..WIDE_CANDIDATE_STARTS)
        .filter(|candidate| primary_hit(*candidate) && secondary_hit(*candidate))
        .count();
    let later_candidate_starts = candidate_starts - WIDE_CANDIDATE_STARTS;
    let later_secondary_hits = (WIDE_CANDIDATE_STARTS..candidate_starts)
        .filter(|candidate| secondary_hit(*candidate))
        .count();
    let later_primary_hits = (WIDE_CANDIDATE_STARTS..candidate_starts)
        .filter(|candidate| primary_hit(*candidate))
        .count();
    let literal_matches = haystack
        .windows(LITERAL.len())
        .filter(|candidate| *candidate == LITERAL)
        .count();
    Ok(AdaptiveFixtureEvidence {
        first_group_primary_hits,
        first_group_pair_hits,
        later_candidate_starts,
        later_secondary_hits,
        later_primary_hits,
        literal_matches,
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
            let index = candidate
                .checked_add(*offset)
                .expect("bounded fixture index");
            haystack[index] == b'x' || haystack[index] == LITERAL[*offset]
        });
        if !compatible {
            continue;
        }
        for offset in &filter_offsets.0[..selected_columns] {
            let index = candidate
                .checked_add(*offset)
                .expect("bounded fixture index");
            haystack[index] = LITERAL[*offset];
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

fn measure_cell(
    kernels: &Kernels,
    haystack: &[u8],
    window: SearchWindow,
    size: Size,
    scenario: Scenario,
    cell_index: usize,
    affinity_cpu: u32,
) -> Result<Vec<Timing>, Box<dyn Error>> {
    for backend in Backend::ALL {
        for _ in 0..WARMUP_CALLS {
            black_box(
                kernels
                    .get(backend)
                    .search(black_box(haystack), window)
                    .expect("warm call"),
            );
        }
    }

    let iterations = calibrate_iterations(kernels, haystack, window, size, affinity_cpu)?;
    let mut timings = Vec::with_capacity(
        REPETITIONS
            .checked_mul(Backend::ALL.len())
            .expect("fixed timing matrix"),
    );
    for repetition in 0..REPETITIONS {
        let order = BACKEND_ORDERS[(repetition + cell_index) % BACKEND_ORDERS.len()];
        for (position, backend) in order.into_iter().enumerate() {
            let cpu_before = observed_cpu()?;
            let (total, checksum) = time_hot(kernels.get(backend), haystack, window, iterations);
            let cpu_after = observed_cpu()?;
            require_stable_cpu(affinity_cpu, cpu_before, cpu_after)?;
            if total < MIN_SAMPLE_TIME {
                return Err(format!(
                    "{} {} {} sample was only {} ns after calibration",
                    scenario.name(),
                    size.name(),
                    backend.name(),
                    total.as_nanos()
                )
                .into());
            }
            black_box(checksum);
            let iterations_f64 =
                f64::from(u32::try_from(iterations).expect("fixed iteration count fits u32"));
            println!(
                "RAW\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.3}\t{}\t{}\t{}",
                scenario.name(),
                size.name(),
                repetition,
                position,
                backend.name(),
                iterations,
                total.as_nanos(),
                total.as_secs_f64() * 1e9 / iterations_f64,
                checksum,
                cpu_before,
                cpu_after,
            );
            timings.push(Timing {
                backend,
                repetition,
                position,
                iterations,
                total,
                checksum,
                cpu_before,
                cpu_after,
            });
        }
    }
    validate_hot_timings(&timings, affinity_cpu)?;
    Ok(timings)
}

fn calibrate_iterations(
    kernels: &Kernels,
    haystack: &[u8],
    window: SearchWindow,
    size: Size,
    affinity_cpu: u32,
) -> Result<usize, Box<dyn Error>> {
    let mut iterations = size.initial_iterations();
    loop {
        let mut shortest = Duration::MAX;
        for backend in Backend::ALL {
            let cpu_before = observed_cpu()?;
            let (total, checksum) = time_hot(kernels.get(backend), haystack, window, iterations);
            let cpu_after = observed_cpu()?;
            require_stable_cpu(affinity_cpu, cpu_before, cpu_after)?;
            black_box(checksum);
            shortest = shortest.min(total);
            println!(
                "CALIBRATION\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                size.name(),
                iterations,
                backend.name(),
                total.as_nanos(),
                checksum,
                cpu_before,
                cpu_after,
            );
        }
        if shortest >= CALIBRATION_TARGET {
            return Ok(iterations);
        }
        iterations = iterations
            .checked_mul(2)
            .filter(|next| *next <= MAX_SAMPLE_ITERATIONS)
            .ok_or("sample calibration exceeded iteration limit")?;
    }
}

fn time_hot(
    kernel: &PublishedKernel<Span>,
    haystack: &[u8],
    window: SearchWindow,
    iterations: usize,
) -> (Duration, u64) {
    let mut checksum = 0x6a09_e667_f3bc_c909_u64;
    let started = Instant::now();
    for iteration in 0..iterations {
        let output = kernel
            .search(black_box(haystack), window)
            .expect("timed call");
        checksum = checksum.rotate_left(7)
            ^ encode_span(output)
            ^ u64::try_from(iteration)
                .expect("bounded iterations")
                .wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }
    let total = started.elapsed();
    black_box(checksum);
    (total, checksum)
}

fn validate_hot_timings(timings: &[Timing], affinity_cpu: u32) -> Result<(), Box<dyn Error>> {
    for repetition in 0..REPETITIONS {
        let row: Vec<&Timing> = timings
            .iter()
            .filter(|timing| timing.repetition == repetition)
            .collect();
        if row.len() != Backend::ALL.len()
            || row
                .iter()
                .any(|timing| timing.cpu_before != affinity_cpu || timing.cpu_after != affinity_cpu)
            || row.windows(2).any(|pair| {
                pair[0].checksum != pair[1].checksum || pair[0].iterations != pair[1].iterations
            })
        {
            return Err(format!("invalid or unequal hot timing pair {repetition}").into());
        }
    }
    Ok(())
}

fn report_cell(size: Size, scenario: Scenario, timings: &[Timing]) -> CellRatios {
    let sve_ratios = paired_ratios(timings, Backend::Sve16V6, Backend::V8);
    let baseline_ns = median_call_ns(timings, Backend::V8);
    let sve_candidate_ns = median_call_ns(timings, Backend::Sve16V6);
    let (sve_point, sve_upper) = ratio_confidence(&sve_ratios);
    println!(
        "SUMMARY\t{}\t{}\tv8_ns_per_call={baseline_ns:.3}\tsve16_v6_ns_per_call={sve_candidate_ns:.3}\tsve16_v6_over_v8={sve_point:.6}\tsve16_v6_upper95={sve_upper:.6}",
        scenario.name(),
        size.name(),
    );
    CellRatios {
        size,
        scenario,
        v8_ns_per_call: baseline_ns,
        sve16_v6_ns_per_call: sve_candidate_ns,
        sve16_v6: sve_ratios,
    }
}

fn paired_ratios(timings: &[Timing], numerator: Backend, denominator: Backend) -> Vec<f64> {
    let mut ratios = Vec::with_capacity(REPETITIONS);
    for repetition in 0..REPETITIONS {
        let numerator_ns = timing_ns(timings, repetition, numerator);
        let denominator_ns = timing_ns(timings, repetition, denominator);
        ratios.push(numerator_ns / denominator_ns);
    }
    ratios
}

fn timing_ns(timings: &[Timing], repetition: usize, backend: Backend) -> f64 {
    let timing = timings
        .iter()
        .find(|timing| timing.repetition == repetition && timing.backend == backend)
        .expect("one timing per backend and repetition");
    black_box(timing.position);
    black_box(timing.checksum);
    timing.total.as_secs_f64() * 1e9
}

fn median_call_ns(timings: &[Timing], backend: Backend) -> f64 {
    let mut values: Vec<f64> = timings
        .iter()
        .filter(|timing| timing.backend == backend)
        .map(|timing| {
            let iterations =
                f64::from(u32::try_from(timing.iterations).expect("bounded iterations"));
            timing.total.as_secs_f64() * 1e9 / iterations
        })
        .collect();
    median(&mut values)
}

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    if values.len().is_multiple_of(2) {
        f64::midpoint(
            values[middle.checked_sub(1).expect("nonempty sample")],
            values[middle],
        )
    } else {
        values[middle]
    }
}

fn ratio_confidence(ratios: &[f64]) -> (f64, f64) {
    let logs: Vec<f64> = ratios.iter().map(|ratio| ratio.ln()).collect();
    let sample_count = f64::from(u32::try_from(logs.len()).expect("fixed sample count fits u32"));
    let mean = logs.iter().sum::<f64>() / sample_count;
    let squared_error = logs
        .iter()
        .map(|value| {
            let error = *value - mean;
            error * error
        })
        .sum::<f64>();
    let degrees_of_freedom = sample_count - 1.0;
    let standard_error = (squared_error / degrees_of_freedom / sample_count).sqrt();
    (mean.exp(), (mean + CONFIDENCE_T_95 * standard_error).exp())
}

fn report_gate(backend: Backend, cells: &[CellRatios]) -> bool {
    let qualified: Vec<&CellRatios> = cells
        .iter()
        .filter(|cell| cell.size.is_qualification_size())
        .collect();
    let mut all_cells_bounded = true;
    for cell in &qualified {
        let ratios = cell_ratios(cell, backend);
        let (point, upper) = ratio_confidence(ratios);
        let passed = point <= MAX_LARGE_CELL_POINT_RATIO && upper <= MAX_LARGE_CELL_UPPER_95;
        all_cells_bounded &= passed;
        println!(
            "GATE_CELL\t{}\t{}\t{}\t{}\tpoint={point:.6}\tupper95={upper:.6}\tpolicy=point<=1.005-and-upper95<=1.020",
            backend.name(),
            cell.scenario.name(),
            cell.size.name(),
            if passed { "PASS" } else { "FAIL" },
        );
    }
    let mut aggregate = Vec::with_capacity(REPETITIONS);
    for repetition in 0..REPETITIONS {
        let mean_log = qualified
            .iter()
            .map(|cell| cell_ratios(cell, backend)[repetition].ln())
            .sum::<f64>()
            / f64::from(u32::try_from(qualified.len()).expect("sixteen fixed cells"));
        aggregate.push(mean_log.exp());
    }
    let (point, upper) = ratio_confidence(&aggregate);
    let aggregate_passed = upper < 1.0;
    let passed = aggregate_passed && all_cells_bounded;
    println!(
        "GATE\t{}\t{}\taggregate_candidate_over_v8={point:.6}\taggregate_upper95={upper:.6}\tall_large_cells_point_le_1_005_and_upper95_le_1_020={all_cells_bounded}\tpolicy=aggregate-upper95<1.0-and-each-large-cell-point<=1.005-and-upper95<=1.020",
        backend.name(),
        if passed { "PASS" } else { "FAIL" },
    );
    passed
}

fn cell_ratios(cell: &CellRatios, backend: Backend) -> &[f64] {
    match backend {
        Backend::Sve16V6 => &cell.sve16_v6,
        Backend::V8 => unreachable!("V8 is the qualification baseline"),
    }
}

fn report_break_even(cold: &[ColdTiming], cells: &[CellRatios]) {
    let baseline_setup = median_cold_ns(cold, ColdStage::Emit, Backend::V8)
        + median_cold_ns(cold, ColdStage::Publish, Backend::V8);
    let backend = Backend::Sve16V6;
    let candidate_setup = median_cold_ns(cold, ColdStage::Emit, backend)
        + median_cold_ns(cold, ColdStage::Publish, backend);
    let setup_delta = (candidate_setup - baseline_setup).max(0.0);
    for cell in cells {
        let candidate_call = cell.sve16_v6_ns_per_call;
        let saving = cell.v8_ns_per_call - candidate_call;
        let (call_count, bytes) = if let Some(calls) = break_even_calls(setup_delta, saving) {
            (
                format!("{calls:.0}"),
                format!(
                    "{:.0}",
                    calls
                        * f64::from(
                            u32::try_from(cell.size.bytes()).expect("qualification size fits u32"),
                        )
                ),
            )
        } else {
            ("never".to_owned(), "never".to_owned())
        };
        println!(
            "BREAK_EVEN\t{}\t{}\t{}\tsetup=emit-plus-publish\tsetup_delta_ns={setup_delta:.3}\tbaseline_ns_per_call={:.3}\tcandidate_ns_per_call={candidate_call:.3}\tcalls={call_count}\thaystack_bytes={bytes}",
            backend.name(),
            cell.scenario.name(),
            cell.size.name(),
            cell.v8_ns_per_call,
        );
    }
}

fn break_even_calls(setup_delta_ns: f64, saving_ns_per_call: f64) -> Option<f64> {
    (saving_ns_per_call > 0.0).then(|| (setup_delta_ns / saving_ns_per_call).ceil())
}

fn median_cold_ns(timings: &[ColdTiming], stage: ColdStage, backend: Backend) -> f64 {
    let mut values: Vec<f64> = timings
        .iter()
        .filter(|timing| timing.stage == stage && timing.backend == backend)
        .map(|timing| {
            black_box((
                timing.repetition,
                timing.position,
                timing.checksum,
                timing.cpu_before,
                timing.cpu_after,
            ));
            timing.total.as_secs_f64() * 1e9
        })
        .collect();
    median(&mut values)
}

fn encode_span(output: Option<MatchSpan>) -> u64 {
    output.map_or(0, |span| {
        let start = u64::try_from(span.start()).expect("bounded haystack");
        let end = u64::try_from(span.end()).expect("bounded haystack");
        start.rotate_left(17) ^ end.rotate_left(41) ^ 0x9e37_79b9_7f4a_7c15
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn images() -> [(Backend, NativeImage); 2] {
        let program =
            build_exact_literal::<Span>(LITERAL, AnchorFlags::default(), ValidateLimits::default())
                .expect("fixed program");
        Backend::ALL.map(|backend| (backend, backend.emit(&program)))
    }

    #[test]
    fn authenticated_filter_offsets_match_the_frozen_ranker() {
        let offsets = require_common_filter_offsets(&images()).expect("sealed manifests");
        assert_eq!(offsets, FilterOffsets([7, 6, 8, 5]));
    }

    #[test]
    fn adversarial_fixtures_hit_selected_columns_without_a_literal() {
        let offsets = require_common_filter_offsets(&images()).expect("sealed manifests");
        for scenario in [
            Scenario::PrimaryDenseSecondaryAbsent,
            Scenario::PairDenseLiteralAbsent,
            Scenario::TripleDenseLiteralAbsent,
            Scenario::FourFilterDenseLiteralAbsent,
        ] {
            let haystack = make_haystack(Size::K4, scenario, offsets).expect("fixture");
            assert!(
                !haystack
                    .windows(LITERAL.len())
                    .any(|window| window == LITERAL)
            );
            let columns = match scenario {
                Scenario::PrimaryDenseSecondaryAbsent => 1,
                Scenario::PairDenseLiteralAbsent => 2,
                Scenario::TripleDenseLiteralAbsent => 3,
                Scenario::FourFilterDenseLiteralAbsent => 4,
                Scenario::Present
                | Scenario::Absent
                | Scenario::AdaptiveSecondaryDensePrimaryAbsent
                | Scenario::Tail => unreachable!(),
            };
            assert!(count_filter_hits(&haystack, offsets, columns) > 0);
        }
    }

    #[test]
    fn adaptive_fixture_exhaustively_matches_the_frozen_invariants() {
        let offsets = require_common_filter_offsets(&images()).expect("sealed manifests");
        let primary_offset = offsets.0[0];
        let secondary_offset = offsets.0[1];
        for size in Size::ALL {
            let mut haystack = vec![b'x'; size.bytes()];
            let evidence =
                synthesize_adaptive_secondary_dense_primary_absent(&mut haystack, offsets)
                    .expect("adaptive fixture");
            let candidate_starts = haystack.len() - LITERAL.len() + 1;
            let later_candidate_starts = candidate_starts - WIDE_CANDIDATE_STARTS;
            assert_eq!(
                evidence,
                AdaptiveFixtureEvidence {
                    first_group_primary_hits: 1,
                    first_group_pair_hits: 0,
                    later_candidate_starts,
                    later_secondary_hits: later_candidate_starts,
                    later_primary_hits: 0,
                    literal_matches: 0,
                }
            );
            for candidate in 0..WIDE_CANDIDATE_STARTS {
                let primary = haystack[candidate + primary_offset] == LITERAL[primary_offset];
                let secondary = haystack[candidate + secondary_offset] == LITERAL[secondary_offset];
                assert!(!primary || !secondary);
            }
            for candidate in WIDE_CANDIDATE_STARTS..candidate_starts {
                assert_eq!(
                    haystack[candidate + secondary_offset],
                    LITERAL[secondary_offset]
                );
                assert_ne!(
                    haystack[candidate + primary_offset],
                    LITERAL[primary_offset]
                );
            }
            assert!(
                !haystack
                    .windows(LITERAL.len())
                    .any(|candidate| candidate == LITERAL)
            );
        }
    }

    #[test]
    fn adaptive_correctness_fixture_has_only_the_declared_late_match() {
        let offsets = require_common_filter_offsets(&images()).expect("sealed manifests");
        let mut haystack = vec![b'x'; ADAPTIVE_CORRECTNESS_BYTES];
        synthesize_adaptive_secondary_dense_primary_absent(&mut haystack, offsets)
            .expect("adaptive absent fixture");
        assert!(
            !haystack
                .windows(LITERAL.len())
                .any(|candidate| candidate == LITERAL)
        );
        let end = ADAPTIVE_CORRECTNESS_MATCH_START + LITERAL.len();
        haystack[ADAPTIVE_CORRECTNESS_MATCH_START..end].copy_from_slice(LITERAL);
        let literal_starts: Vec<usize> = haystack
            .windows(LITERAL.len())
            .enumerate()
            .filter_map(|(start, candidate)| (candidate == LITERAL).then_some(start))
            .collect();
        assert_eq!(literal_starts, [ADAPTIVE_CORRECTNESS_MATCH_START]);
    }

    #[test]
    fn confidence_bound_is_one_for_identical_samples() {
        let ratios = vec![1.0; REPETITIONS];
        assert_eq!(ratio_confidence(&ratios), (1.0, 1.0));
    }

    #[test]
    fn break_even_excludes_the_first_hot_call_from_setup() {
        assert_eq!(break_even_calls(100.0, 10.0), Some(10.0));
        assert_eq!(break_even_calls(0.0, 10.0), Some(0.0));
        assert_eq!(break_even_calls(100.0, 0.0), None);
        assert_eq!(break_even_calls(100.0, -1.0), None);
    }
}
