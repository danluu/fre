#![cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code, unused_imports)
)]

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
compile_error!("the retained Count-v2 implementation requires arm64 macOS");

use std::{
    error::Error,
    fs,
    hint::black_box,
    path::Path,
    time::{Duration, Instant},
};

use fre::{AggregateBuilder, AggregatePlanKind, AggregateRunLimits, LiteralAggregateReduceLimits};
use fre_aot_static_runtime::{
    CallError, RawStaticCountAdoptionOutputV2, StaticAdoptionErrorV2, VerifiedStaticCountV2,
    adopt_linked_static_count_qualification_v2,
};
use fre_kernel_ir::AggregateExecutionLimits;
use sha2::{Digest, Sha256};

const LITERAL: &[u8] = b"needle";
const ROW_SELECTOR: u16 = 11;
const COMPILE_IDENTITY: &str = "ed06366efaed9de023166d65fcee6dbce761bec7aa62c96ba17d5bece445831f";
const OBJECT_IDENTITY: &str = "b88728fcfd040ff9e8e7094ae19e2529f9c0b08b2da6f0a0d5d471c0510fad0b";
const EXPECTATION_IDENTITY: &str =
    "afc00275b8be5b661f41521edc8f0477b668c365d779ecc0e51636a2aa1f57d5";
const RECEIPT_IDENTITY: &str = "6c04357fc22f5e5d97742361d9ea2e0be23c05d4b6c23c4c494890698ecf7d7f";
const RESOURCE_RECEIPT_IDENTITY: &str =
    "32829b6ce4c402c4c15fe7b144440b072808b868d9a0594d04e5281c7322e7b7";
const FINAL_IMAGE_GLUE_SHA256: &str =
    "08acd36cd90384db4527d4bb00df9d6edb0f8a855e9aa6ade2d7608cebade132";
const EXPECTATION_SHA256: &str = "f6533b964a4388410d6f617100e489d4bc6f0c95ca4319b33bc19cc3972e650f";
const STEADY_REPETITIONS: usize = 16;
const BYTES_PER_STEADY_SAMPLE: usize = 64 * 1024 * 1024;
const CACHED_ADOPTION_ITERATIONS: usize = 4096;
const FIXTURE_BYTES: [usize; 2] = [64 * 1024, 1024 * 1024];
const ALIGNMENT_RESIDUES: usize = 16;
const PREFIX_CASES_PER_SIZE: usize = 4;
const SUFFIX_CASES_PER_SIZE: usize = 9;
const CASES_PER_SIZE: usize = PREFIX_CASES_PER_SIZE + ALIGNMENT_RESIDUES + SUFFIX_CASES_PER_SIZE;
const TOTAL_CASES: usize = FIXTURE_BYTES.len() * CASES_PER_SIZE;
const SAMPLES_PER_CASE: usize = STEADY_REPETITIONS * 2;
const SAMPLES_PER_PROCESS: usize = TOTAL_CASES * SAMPLES_PER_CASE;
// The identity-bound `needle` Count-v2 manifest selects `d`, `l`, `n`, then
// `e`. Keep adversarial fixtures tied to those exact artifact offsets.
const C5_FILTER_OFFSETS: [usize; 4] = [3, 4, 0, 1];
const C5_FILTER_PLUS_LAST_OFFSETS: [usize; 5] = [
    C5_FILTER_OFFSETS[0],
    C5_FILTER_OFFSETS[1],
    C5_FILTER_OFFSETS[2],
    C5_FILTER_OFFSETS[3],
    LITERAL.len() - 1,
];
const DENSE_RUN_STRIDE: usize = 64;
const DENSE_RUN_MATCHES: usize = 4;
const BINARY_FILL: &[u8] = &[0x00, 0xff, 0x80, 0xc0, 0xf5, b'n', b'e', b'x'];
const NATURAL_FILL: &[u8] = b"The quick brown fox crosses a quiet field while static compilation keeps reusable work outside each request path.\n";
const _: () = assert!(
    LITERAL[C5_FILTER_OFFSETS[0]] == b'd'
        && LITERAL[C5_FILTER_OFFSETS[1]] == b'l'
        && LITERAL[C5_FILTER_OFFSETS[2]] == b'n'
        && LITERAL[C5_FILTER_OFFSETS[3]] == b'e'
);

#[allow(
    unsafe_code,
    reason = "the link name is bound to the retained C5 glue object and its fixed adoption ABI"
)]
unsafe extern "C" {
    #[link_name = "fre_aot_count_glue_v2_ed06366efaed9de023166d65fcee6dbce761bec7aa62c96ba17d5bece445831f"]
    fn linked_count_glue_v2(output: *mut RawStaticCountAdoptionOutputV2) -> u32;
}

#[derive(Clone, Copy, Debug)]
enum FixtureKind {
    SparsePresent,
    AbsentEasy,
    DenseMatch,
    Tail,
    BinaryAbsent,
    BinaryPresent,
    NaturalAbsent,
    NaturalPresent,
    SelectedPairDenseAbsent,
    SelectedTripleDenseAbsent,
    SparseFalsePositiveLateMatch,
    FirstLastDenseAbsent,
    DenseRunTransition,
}

impl FixtureKind {
    const PREFIX: [Self; PREFIX_CASES_PER_SIZE] = [
        Self::SparsePresent,
        Self::AbsentEasy,
        Self::DenseMatch,
        Self::Tail,
    ];
    const SUFFIX: [Self; SUFFIX_CASES_PER_SIZE] = [
        Self::BinaryAbsent,
        Self::BinaryPresent,
        Self::NaturalAbsent,
        Self::NaturalPresent,
        Self::SelectedPairDenseAbsent,
        Self::SelectedTripleDenseAbsent,
        Self::SparseFalsePositiveLateMatch,
        Self::FirstLastDenseAbsent,
        Self::DenseRunTransition,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::SparsePresent => "sparse-present",
            Self::AbsentEasy => "absent-easy",
            Self::DenseMatch => "dense-match",
            Self::Tail => "tail",
            Self::BinaryAbsent => "binary-absent",
            Self::BinaryPresent => "binary-present",
            Self::NaturalAbsent => "natural-absent",
            Self::NaturalPresent => "natural-present",
            Self::SelectedPairDenseAbsent => "selected-pair-dense-absent",
            Self::SelectedTripleDenseAbsent => "selected-triple-dense-absent",
            Self::SparseFalsePositiveLateMatch => "sparse-false-positive-late-match",
            Self::FirstLastDenseAbsent => "first-last-dense-absent",
            Self::DenseRunTransition => "dense-run-transition",
        }
    }
}

#[derive(Debug)]
struct Case {
    name: String,
    storage: Vec<u8>,
    haystack_start: usize,
    haystack_bytes: usize,
    expected_count: u64,
}

impl Case {
    fn new(
        name: String,
        storage: Vec<u8>,
        haystack_start: usize,
        haystack_bytes: usize,
        expected_count: u64,
    ) -> Result<Self, Box<dyn Error>> {
        let haystack_end = haystack_start
            .checked_add(haystack_bytes)
            .ok_or("fixture haystack range overflow")?;
        let haystack = storage
            .get(haystack_start..haystack_end)
            .ok_or("fixture haystack range exceeds storage")?;
        let reference = reference_count(haystack, LITERAL)?;
        if reference != expected_count {
            return Err(format!(
                "fixture {name} declared {expected_count} matches but reference counted {reference}"
            )
            .into());
        }
        Ok(Self {
            name,
            storage,
            haystack_start,
            haystack_bytes,
            expected_count,
        })
    }

    fn haystack(&self) -> &[u8] {
        let end = self
            .haystack_start
            .checked_add(self.haystack_bytes)
            .expect("validated fixture range");
        self.storage
            .get(self.haystack_start..end)
            .expect("validated fixture storage")
    }
}

#[derive(Clone, Copy, Debug)]
enum Engine {
    QualifiedAot,
    Portable,
}

impl Engine {
    const fn name(self) -> &'static str {
        match self {
            Self::QualifiedAot => "qualified-aot-handle",
            Self::Portable => "portable-count-value",
        }
    }
}

#[derive(Debug)]
struct Summary {
    case: String,
    bytes: usize,
    expected_count: u64,
    aot_ns: Vec<f64>,
    portable_ns: Vec<f64>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let first_adoption_start = Instant::now();
    let handle = adopt()?;
    let first_adoption = first_adoption_start.elapsed();
    verify_handle(handle)?;
    verify_safe_call_contract(handle)?;
    let cached_adoption = measure_cached_adoption(handle)?;
    print_bindings(handle, first_adoption, cached_adoption)?;
    run_steady_state(handle)
}

#[allow(
    unsafe_code,
    reason = "the retained candidate glue targets the separately named private qualification adopter and registry"
)]
fn adopt() -> Result<&'static VerifiedStaticCountV2, StaticAdoptionErrorV2> {
    // SAFETY: this executable links the exact retained qualification glue and
    // immutable evidence objects whose five identities are checked below.
    unsafe {
        adopt_linked_static_count_qualification_v2(|output| {
            // SAFETY: the adapter supplies one initialized writable output
            // slot to the exact process-lifetime qualification image.
            linked_count_glue_v2(output)
        })
    }
}

fn verify_handle(handle: &VerifiedStaticCountV2) -> Result<(), Box<dyn Error>> {
    let checks = [
        ("compile", hex(handle.compile_identity()), COMPILE_IDENTITY),
        ("object", hex(handle.object_identity()), OBJECT_IDENTITY),
        (
            "expectation",
            hex(handle.expectation_identity()),
            EXPECTATION_IDENTITY,
        ),
        ("receipt", hex(handle.receipt_identity()), RECEIPT_IDENTITY),
        (
            "resource receipt",
            hex(handle.resource_receipt_identity()),
            RESOURCE_RECEIPT_IDENTITY,
        ),
    ];
    for (name, actual, expected) in checks {
        if actual != expected {
            return Err(format!("{name} identity mismatch: {actual} != {expected}").into());
        }
    }
    if handle.row_selector() != ROW_SELECTOR
        || usize::try_from(handle.literal_bytes()).ok() != Some(LITERAL.len())
    {
        return Err("qualified handle row or literal width mismatch".into());
    }
    Ok(())
}

fn verify_safe_call_contract(handle: &VerifiedStaticCountV2) -> Result<(), Box<dyn Error>> {
    for (haystack, expected) in [
        (b"".as_slice(), 0),
        (b"needle".as_slice(), 1),
        (b"needleneedle".as_slice(), 2),
        (b"needle needle needle".as_slice(), 3),
        (b"needleneedl".as_slice(), 1),
    ] {
        let actual = handle.count(haystack, AggregateExecutionLimits::unlimited())?;
        if actual != expected {
            return Err(format!(
                "safe handle count mismatch for {:?}: {actual} != {expected}",
                String::from_utf8_lossy(haystack)
            )
            .into());
        }
    }
    let refused = handle.count(
        b"needle",
        AggregateExecutionLimits {
            max_haystack_bytes: 0,
            ..AggregateExecutionLimits::unlimited()
        },
    );
    if !matches!(refused, Err(CallError::Preflight(_))) {
        return Err("safe handle did not enforce the per-call policy preflight".into());
    }
    Ok(())
}

fn measure_cached_adoption(
    expected: &'static VerifiedStaticCountV2,
) -> Result<Duration, Box<dyn Error>> {
    let start = Instant::now();
    for _ in 0..CACHED_ADOPTION_ITERATIONS {
        let actual = black_box(adopt()?);
        if !std::ptr::eq(actual, expected) {
            return Err("cached adoption returned a different registry handle".into());
        }
    }
    Ok(start.elapsed())
}

fn print_bindings(
    handle: &VerifiedStaticCountV2,
    first_adoption: Duration,
    cached_adoption: Duration,
) -> Result<(), Box<dyn Error>> {
    let executable = std::env::current_exe()?;
    let accounting = handle.inspection_accounting();
    println!("META,key,value");
    println!("META,schema,fre-aot-count-qualified-benchmark-v2");
    println!("META,pid,{}", std::process::id());
    println!("META,runtime_authority,qualification-private");
    println!("META,qualification_state,candidate");
    println!("META,production_activation,absent");
    println!(
        "META,performance_scope,selector-11-needle-steady-state-plus-qualification-private-adoption-v1"
    );
    println!("META,compile_link_startup_costs,unmeasured");
    println!("META,production_adoption_latency,unmeasured");
    println!("META,fixture_cases,{TOTAL_CASES}");
    println!("META,fixture_sizes,{}", FIXTURE_BYTES.len());
    println!("META,alignment_residues,{ALIGNMENT_RESIDUES}");
    println!("META,steady_repetitions,{STEADY_REPETITIONS}");
    println!("META,samples_per_process,{SAMPLES_PER_PROCESS}");
    println!("META,bytes_per_steady_sample,{BYTES_PER_STEADY_SAMPLE}");
    println!("META,benchmark_source_sha256,{}", benchmark_source_id());
    println!("META,row_selector,{ROW_SELECTOR}");
    println!("META,compile_identity,{COMPILE_IDENTITY}");
    println!("META,object_identity,{OBJECT_IDENTITY}");
    println!("META,expectation_identity,{EXPECTATION_IDENTITY}");
    println!("META,receipt_identity,{RECEIPT_IDENTITY}");
    println!("META,resource_receipt_identity,{RESOURCE_RECEIPT_IDENTITY}");
    println!("META,implementation_object_sha256,{OBJECT_IDENTITY}");
    println!("META,final_image_glue_sha256,{FINAL_IMAGE_GLUE_SHA256}");
    println!("META,expectation_sha256,{EXPECTATION_SHA256}");
    println!("META,executable_sha256,{}", file_sha256(&executable)?);
    println!(
        "META,inspection_expectation_bytes,{}",
        accounting.expectation_bytes()
    );
    println!(
        "META,inspection_metadata_bytes,{}",
        accounting.metadata_bytes()
    );
    println!(
        "META,inspection_payload_bytes,{}",
        accounting.payload_bytes()
    );
    println!(
        "META,inspection_vm_regions_checked,{}",
        accounting.vm_regions_checked()
    );
    println!(
        "META,inspection_payload_bytes_hashed,{}",
        accounting.payload_bytes_hashed()
    );
    println!(
        "META,inspection_work_upper_bound,{}",
        accounting.work_upper_bound()
    );
    println!(
        "META,inspection_scratch_bytes_upper_bound,{}",
        accounting.scratch_bytes_upper_bound()
    );
    println!(
        "META,inspection_registry_capacity_entries,{}",
        accounting.static_registry_capacity_entries()
    );
    println!(
        "META,inspection_registry_capacity_bytes,{}",
        accounting.static_registry_capacity_bytes()
    );
    println!("META,inspection_allocations,{}", accounting.allocations());
    println!("META,first_adoption_ns,{}", first_adoption.as_nanos());
    println!("META,cached_adoption_iterations,{CACHED_ADOPTION_ITERATIONS}");
    println!(
        "META,cached_adoption_total_ns,{}",
        cached_adoption.as_nanos()
    );
    println!(
        "META,cached_adoption_ns_per_call,{:.3}",
        duration_ns_per_iteration(cached_adoption, CACHED_ADOPTION_ITERATIONS)?
    );
    Ok(())
}

fn benchmark_source_id() -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"FRE-AOT-COUNT-C5-QUALIFIED-BENCHMARK-SOURCE\0\x02");
    for &(name, bytes) in BENCHMARK_SOURCE_FILES_V2 {
        hasher.update(name.as_bytes());
        hasher.update([0]);
        hasher.update(bytes);
    }
    hex(&hasher.finalize())
}

const BENCHMARK_SOURCE_FILES_V2: &[(&str, &[u8])] = &[
    ("Cargo.lock", include_bytes!("../Cargo.lock").as_slice()),
    ("Cargo.toml", include_bytes!("../Cargo.toml").as_slice()),
    ("PROMOTION.md", include_bytes!("../PROMOTION.md").as_slice()),
    (
        "QUALIFICATION.md",
        include_bytes!("../QUALIFICATION.md").as_slice(),
    ),
    ("README.md", include_bytes!("../README.md").as_slice()),
    (
        "benchmark-source-files-v2.txt",
        include_bytes!("../benchmark-source-files-v2.txt").as_slice(),
    ),
    (
        "build-qualified-candidate.sh",
        include_bytes!("../build-qualified-candidate.sh").as_slice(),
    ),
    ("build.rs", include_bytes!("../build.rs").as_slice()),
    (
        "fingerprint-cargo-registry.sh",
        include_bytes!("../fingerprint-cargo-registry.sh").as_slice(),
    ),
    (
        "fingerprint-toolchain.sh",
        include_bytes!("../fingerprint-toolchain.sh").as_slice(),
    ),
    (
        "qualification-common.sh",
        include_bytes!("../qualification-common.sh").as_slice(),
    ),
    (
        "run-qualified-candidate.sh",
        include_bytes!("../run-qualified-candidate.sh").as_slice(),
    ),
    (
        "run-qualified-timing-wave.sh",
        include_bytes!("../run-qualified-timing-wave.sh").as_slice(),
    ),
    ("src/main.rs", include_bytes!("main.rs").as_slice()),
    (
        "src/promoted_correctness.rs",
        include_bytes!("promoted_correctness.rs").as_slice(),
    ),
    (
        "test-promotion-trust-root.sh",
        include_bytes!("../test-promotion-trust-root.sh").as_slice(),
    ),
    (
        "test-qualification-bundle.sh",
        include_bytes!("../test-qualification-bundle.sh").as_slice(),
    ),
    (
        "test-results-verifier.sh",
        include_bytes!("../test-results-verifier.sh").as_slice(),
    ),
    (
        "verify-promotion-delta.sh",
        include_bytes!("../verify-promotion-delta.sh").as_slice(),
    ),
    (
        "verify-qualification-bundle.sh",
        include_bytes!("../verify-qualification-bundle.sh").as_slice(),
    ),
    (
        "verify-results.sh",
        include_bytes!("../verify-results.sh").as_slice(),
    ),
];

#[cfg(test)]
fn benchmark_source_id_from_filesystem() -> Result<String, Box<dyn Error>> {
    let manifest = include_str!("../benchmark-source-files-v2.txt");
    let declared = manifest.lines().collect::<Vec<_>>();
    let embedded = BENCHMARK_SOURCE_FILES_V2
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>();
    if declared != embedded {
        return Err("benchmark source manifest and embedded file order differ".into());
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut hasher = Sha256::new();
    hasher.update(b"FRE-AOT-COUNT-C5-QUALIFIED-BENCHMARK-SOURCE\0\x02");
    for name in declared {
        hasher.update(name.as_bytes());
        hasher.update([0]);
        hasher.update(std::fs::read(root.join(name))?);
    }
    Ok(hex(&hasher.finalize()))
}

#[cfg(test)]
fn benchmark_source_id_with_mutation(reverse_order: bool, mutate_first_byte: bool) -> String {
    let mut files = BENCHMARK_SOURCE_FILES_V2.to_vec();
    if reverse_order {
        files.reverse();
    }
    let mut hasher = Sha256::new();
    hasher.update(b"FRE-AOT-COUNT-C5-QUALIFIED-BENCHMARK-SOURCE\0\x02");
    for (index, (name, bytes)) in files.into_iter().enumerate() {
        hasher.update(name.as_bytes());
        hasher.update([0]);
        if index == 0 && mutate_first_byte {
            let mut changed = bytes.to_vec();
            if let Some(first) = changed.first_mut() {
                *first ^= 1;
            }
            hasher.update(changed);
        } else {
            hasher.update(bytes);
        }
    }
    hex(&hasher.finalize())
}

#[cfg(test)]
#[test]
fn benchmark_source_identity_matches_manifest_bytes_and_fails_on_drift() {
    let embedded = benchmark_source_id();
    assert_eq!(
        benchmark_source_id_from_filesystem().expect("manifest-framed filesystem identity"),
        embedded
    );
    assert_ne!(
        benchmark_source_id_with_mutation(false, true),
        embedded,
        "one changed source byte must change the identity"
    );
    assert_ne!(
        benchmark_source_id_with_mutation(true, false),
        embedded,
        "a changed source-file order must change the identity"
    );
}

fn run_steady_state(handle: &'static VerifiedStaticCountV2) -> Result<(), Box<dyn Error>> {
    let portable = AggregateBuilder::new("needle")
        .unicode(false)
        .build_count()?;
    if portable.build_report().plan != AggregatePlanKind::ExactLiteral {
        return Err("portable comparison did not select ExactLiteral".into());
    }
    let portable_limits = AggregateRunLimits {
        exact_literal: LiteralAggregateReduceLimits::unlimited(),
        ..AggregateRunLimits::default()
    };
    let aot_limits = AggregateExecutionLimits::unlimited();
    let cases = build_cases()?;
    if cases.len() != TOTAL_CASES {
        return Err(format!(
            "fixture matrix produced {} cases instead of {TOTAL_CASES}",
            cases.len()
        )
        .into());
    }

    println!(
        "SAMPLE,case,bytes,expected_count,repetition,order,engine,iterations,elapsed_ns,ns_per_call,checksum"
    );
    let mut summaries = Vec::with_capacity(cases.len());
    for (case_index, case) in cases.iter().enumerate() {
        let haystack = case.haystack();
        let iterations = BYTES_PER_STEADY_SAMPLE
            .checked_div(haystack.len())
            .ok_or("zero-length steady fixture")?;
        if iterations == 0 {
            return Err("steady byte target is smaller than one fixture".into());
        }
        if iterations
            .checked_mul(haystack.len())
            .ok_or("steady byte accounting overflow")?
            != BYTES_PER_STEADY_SAMPLE
        {
            return Err("steady fixture does not divide the fixed byte target".into());
        }
        let aot_expected = handle.count(haystack, aot_limits)?;
        let portable_expected = portable.count_value(haystack, portable_limits)?;
        if aot_expected != case.expected_count || portable_expected != case.expected_count {
            return Err(format!(
                "fixture {} expected {}, AOT {aot_expected}, portable {portable_expected}",
                case.name, case.expected_count
            )
            .into());
        }
        for _ in 0..4 {
            black_box(handle.count(black_box(haystack), aot_limits)?);
            black_box(portable.count_value(black_box(haystack), portable_limits)?);
        }

        let mut summary = Summary {
            case: case.name.clone(),
            bytes: haystack.len(),
            expected_count: case.expected_count,
            aot_ns: Vec::with_capacity(STEADY_REPETITIONS),
            portable_ns: Vec::with_capacity(STEADY_REPETITIONS),
        };
        for repetition in 0..STEADY_REPETITIONS {
            let aot_first = repetition
                .checked_add(case_index)
                .ok_or("steady order overflow")?
                .is_multiple_of(2);
            let order = if aot_first {
                [Engine::QualifiedAot, Engine::Portable]
            } else {
                [Engine::Portable, Engine::QualifiedAot]
            };
            let order_name = if aot_first {
                "aot-first"
            } else {
                "portable-first"
            };
            for engine in order {
                let (elapsed, checksum) = measure_steady(
                    engine,
                    iterations,
                    haystack,
                    handle,
                    &portable,
                    &aot_limits,
                    &portable_limits,
                )?;
                let ns_per_call = duration_ns_per_iteration(elapsed, iterations)?;
                match engine {
                    Engine::QualifiedAot => summary.aot_ns.push(ns_per_call),
                    Engine::Portable => summary.portable_ns.push(ns_per_call),
                }
                println!(
                    "SAMPLE,{},{},{},{repetition},{order_name},{},{iterations},{},{ns_per_call:.3},{checksum}",
                    case.name,
                    haystack.len(),
                    case.expected_count,
                    engine.name(),
                    elapsed.as_nanos(),
                );
            }
        }
        summaries.push(summary);
    }

    println!(
        "SUMMARY,case,bytes,expected_count,qualified_aot_median_ns,portable_median_ns,portable_over_aot,qualified_aot_gib_per_s,portable_gib_per_s"
    );
    for mut summary in summaries {
        let aot = median(&mut summary.aot_ns)?;
        let portable_ns = median(&mut summary.portable_ns)?;
        let speedup = portable_ns / aot;
        let aot_gib = gib_per_second(summary.bytes, aot)?;
        let portable_gib = gib_per_second(summary.bytes, portable_ns)?;
        println!(
            "SUMMARY,{},{},{},{aot:.3},{portable_ns:.3},{speedup:.4},{aot_gib:.4},{portable_gib:.4}",
            summary.case, summary.bytes, summary.expected_count
        );
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the benchmark keeps both engines and their policies explicit"
)]
fn measure_steady(
    engine: Engine,
    iterations: usize,
    haystack: &[u8],
    handle: &VerifiedStaticCountV2,
    portable: &fre::AggregateCountRegex,
    aot_limits: &AggregateExecutionLimits,
    portable_limits: &AggregateRunLimits,
) -> Result<(Duration, u64), Box<dyn Error>> {
    let start = Instant::now();
    let mut checksum = 0_u64;
    for _ in 0..iterations {
        let value = match engine {
            Engine::QualifiedAot => handle.count(black_box(haystack), *aot_limits)?,
            Engine::Portable => portable.count_value(black_box(haystack), portable_limits)?,
        };
        checksum = checksum.wrapping_add(black_box(value));
    }
    Ok((start.elapsed(), black_box(checksum)))
}

fn build_cases() -> Result<Vec<Case>, Box<dyn Error>> {
    let mut cases = Vec::with_capacity(TOTAL_CASES);
    for bytes in FIXTURE_BYTES {
        for kind in FixtureKind::PREFIX {
            cases.push(build_named_case(kind, bytes)?);
        }
        for base_residue in 0..ALIGNMENT_RESIDUES {
            cases.push(build_alignment_case(base_residue, bytes)?);
        }
        for kind in FixtureKind::SUFFIX {
            cases.push(build_named_case(kind, bytes)?);
        }
    }
    if cases.len() != TOTAL_CASES {
        return Err("fixture matrix cardinality drifted".into());
    }
    Ok(cases)
}

#[allow(
    clippy::too_many_lines,
    reason = "each named qualification scenario keeps its exact construction and declared semantic count adjacent"
)]
fn build_named_case(kind: FixtureKind, bytes: usize) -> Result<Case, Box<dyn Error>> {
    if bytes < LITERAL.len() {
        return Err("fixture is shorter than the literal".into());
    }
    let mut storage = vec![b'x'; bytes];
    let expected_count = match kind {
        FixtureKind::SparsePresent => install_quarter_matches(&mut storage)?,
        FixtureKind::AbsentEasy => 0,
        FixtureKind::DenseMatch => {
            let mut start = 0_usize;
            let mut count = 0_u64;
            while start
                .checked_add(LITERAL.len())
                .is_some_and(|end| end <= bytes)
            {
                write_literal(&mut storage, start)?;
                count = count.checked_add(1).ok_or("dense count overflow")?;
                start = start
                    .checked_add(LITERAL.len())
                    .ok_or("dense fixture advance overflow")?;
            }
            count
        }
        FixtureKind::Tail => {
            let start = bytes
                .checked_sub(LITERAL.len())
                .ok_or("tail fixture underflow")?;
            write_literal(&mut storage, start)?;
            1
        }
        FixtureKind::BinaryAbsent => {
            repeat_fill(&mut storage, BINARY_FILL)?;
            0
        }
        FixtureKind::BinaryPresent => {
            repeat_fill(&mut storage, BINARY_FILL)?;
            install_quarter_matches(&mut storage)?
        }
        FixtureKind::NaturalAbsent => {
            repeat_fill(&mut storage, NATURAL_FILL)?;
            0
        }
        FixtureKind::NaturalPresent => {
            repeat_fill(&mut storage, NATURAL_FILL)?;
            install_quarter_matches(&mut storage)?
        }
        FixtureKind::SelectedPairDenseAbsent => {
            install_dense_filter_candidates(&mut storage, &C5_FILTER_OFFSETS[..2], 2)?;
            0
        }
        FixtureKind::SelectedTripleDenseAbsent => {
            install_dense_filter_candidates(&mut storage, &C5_FILTER_OFFSETS[..3], 8)?;
            0
        }
        FixtureKind::SparseFalsePositiveLateMatch => {
            let last_match = bytes
                .checked_sub(LITERAL.len())
                .ok_or("sparse false-positive fixture underflow")?;
            let mut start = 257_usize;
            while start
                .checked_add(LITERAL.len())
                .is_some_and(|end| end < last_match)
            {
                write_filter_bytes(&mut storage, start, &C5_FILTER_OFFSETS[..2])?;
                start = start
                    .checked_add(4096)
                    .ok_or("sparse false-positive advance overflow")?;
            }
            write_literal(&mut storage, last_match)?;
            1
        }
        FixtureKind::FirstLastDenseAbsent => {
            install_dense_filter_candidates(&mut storage, &C5_FILTER_PLUS_LAST_OFFSETS, 8)?;
            0
        }
        FixtureKind::DenseRunTransition => {
            let run_bytes = DENSE_RUN_MATCHES
                .checked_mul(LITERAL.len())
                .ok_or("dense-run byte count overflow")?;
            let mut group_start = 0_usize;
            let mut count = 0_u64;
            while group_start
                .checked_add(run_bytes)
                .is_some_and(|end| end <= bytes)
            {
                for match_index in 0..DENSE_RUN_MATCHES {
                    let match_start = match_index
                        .checked_mul(LITERAL.len())
                        .and_then(|offset| group_start.checked_add(offset))
                        .ok_or("dense-run match position overflow")?;
                    write_literal(&mut storage, match_start)?;
                    count = count.checked_add(1).ok_or("dense-run count overflow")?;
                }
                group_start = group_start
                    .checked_add(DENSE_RUN_STRIDE)
                    .ok_or("dense-run group advance overflow")?;
            }
            count
        }
    };
    Case::new(
        format!("{}-{}", kind.name(), size_name(bytes)?),
        storage,
        0,
        bytes,
        expected_count,
    )
}

fn build_alignment_case(base_residue: usize, bytes: usize) -> Result<Case, Box<dyn Error>> {
    if base_residue >= ALIGNMENT_RESIDUES {
        return Err("alignment residue exceeds the SIMD residue set".into());
    }
    let storage_bytes = bytes
        .checked_add(ALIGNMENT_RESIDUES)
        .ok_or("alignment storage byte count overflow")?;
    let mut storage = vec![b'x'; storage_bytes];
    let allocation_residue = storage.as_ptr().addr() % ALIGNMENT_RESIDUES;
    let haystack_start = base_residue
        .checked_add(ALIGNMENT_RESIDUES)
        .and_then(|value| value.checked_sub(allocation_residue))
        .ok_or("alignment base offset overflow")?
        % ALIGNMENT_RESIDUES;
    let start_residue = ALIGNMENT_RESIDUES
        .checked_sub(1)
        .and_then(|last| last.checked_sub(base_residue))
        .ok_or("alignment start residue underflow")?;
    let match_start = 256_usize
        .checked_add(start_residue)
        .ok_or("alignment match start overflow")?;
    let storage_match_start = haystack_start
        .checked_add(match_start)
        .ok_or("alignment storage match start overflow")?;
    write_literal(&mut storage, storage_match_start)?;

    let actual_base_residue = storage
        .as_ptr()
        .addr()
        .checked_add(haystack_start)
        .ok_or("alignment base address overflow")?
        % ALIGNMENT_RESIDUES;
    let actual_match_residue = storage
        .as_ptr()
        .addr()
        .checked_add(storage_match_start)
        .ok_or("alignment match address overflow")?
        % ALIGNMENT_RESIDUES;
    if actual_base_residue != base_residue
        || match_start % ALIGNMENT_RESIDUES != start_residue
        || actual_match_residue != ALIGNMENT_RESIDUES - 1
    {
        return Err("alignment fixture did not realize its declared residues".into());
    }

    Case::new(
        format!(
            "alignment-base-{base_residue:02}-start-{start_residue:02}-cross-{}",
            size_name(bytes)?
        ),
        storage,
        haystack_start,
        bytes,
        1,
    )
}

fn install_quarter_matches(haystack: &mut [u8]) -> Result<u64, Box<dyn Error>> {
    let mut count = 0_u64;
    for numerator in [1_usize, 2, 3] {
        let approximate = haystack
            .len()
            .checked_mul(numerator)
            .and_then(|value| value.checked_div(4))
            .ok_or("sparse-present fixture position overflow")?;
        let remainder = approximate
            .checked_rem(LITERAL.len())
            .ok_or("zero literal width")?;
        let start = approximate
            .checked_sub(remainder)
            .ok_or("sparse-present fixture alignment underflow")?;
        write_literal(haystack, start)?;
        count = count
            .checked_add(1)
            .ok_or("sparse-present count overflow")?;
    }
    Ok(count)
}

fn install_dense_filter_candidates(
    haystack: &mut [u8],
    offsets: &[usize],
    stride: usize,
) -> Result<(), Box<dyn Error>> {
    if stride == 0 {
        return Err("dense filter stride must be nonzero".into());
    }
    let last_start = haystack
        .len()
        .checked_sub(LITERAL.len())
        .ok_or("dense filter fixture underflow")?;
    for start in (0..=last_start).step_by(stride) {
        write_filter_bytes(haystack, start, offsets)?;
    }
    Ok(())
}

fn write_filter_bytes(
    haystack: &mut [u8],
    start: usize,
    offsets: &[usize],
) -> Result<(), Box<dyn Error>> {
    for &offset in offsets {
        let index = start
            .checked_add(offset)
            .ok_or("filter candidate index overflow")?;
        let value = *LITERAL
            .get(offset)
            .ok_or("filter candidate offset exceeds literal")?;
        *haystack
            .get_mut(index)
            .ok_or("filter candidate exceeds haystack")? = value;
    }
    Ok(())
}

fn write_literal(haystack: &mut [u8], start: usize) -> Result<(), Box<dyn Error>> {
    let end = start
        .checked_add(LITERAL.len())
        .ok_or("literal placement end overflow")?;
    haystack
        .get_mut(start..end)
        .ok_or("literal placement exceeds haystack")?
        .copy_from_slice(LITERAL);
    Ok(())
}

fn repeat_fill(haystack: &mut [u8], pattern: &[u8]) -> Result<(), Box<dyn Error>> {
    if pattern.is_empty() {
        return Err("fixture fill pattern must be nonempty".into());
    }
    for (index, byte) in haystack.iter_mut().enumerate() {
        *byte = pattern[index % pattern.len()];
    }
    Ok(())
}

fn reference_count(haystack: &[u8], literal: &[u8]) -> Result<u64, Box<dyn Error>> {
    if literal.is_empty() {
        return u64::try_from(haystack.len())
            .ok()
            .and_then(|length| length.checked_add(1))
            .ok_or_else(|| "empty-literal reference count overflow".into());
    }
    let Some(last_start) = haystack.len().checked_sub(literal.len()) else {
        return Ok(0);
    };
    let mut cursor = 0_usize;
    let mut count = 0_u64;
    while cursor <= last_start {
        let end = cursor
            .checked_add(literal.len())
            .ok_or("reference match end overflow")?;
        if haystack.get(cursor..end) == Some(literal) {
            count = count.checked_add(1).ok_or("reference count overflow")?;
            cursor = end;
        } else {
            cursor = cursor.checked_add(1).ok_or("reference cursor overflow")?;
        }
    }
    Ok(count)
}

const fn size_name(bytes: usize) -> Result<&'static str, &'static str> {
    match bytes {
        65_536 => Ok("64k"),
        1_048_576 => Ok("1m"),
        _ => Err("unknown fixture size"),
    }
}

fn duration_ns_per_iteration(elapsed: Duration, iterations: usize) -> Result<f64, Box<dyn Error>> {
    let iterations_u32 = u32::try_from(iterations)?;
    Ok(elapsed.as_secs_f64() * 1_000_000_000.0 / f64::from(iterations_u32))
}

fn median(values: &mut [f64]) -> Result<f64, Box<dyn Error>> {
    if values.is_empty() {
        return Err("empty median".into());
    }
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    if values.len().is_multiple_of(2) {
        let lower = middle.checked_sub(1).ok_or("median lower index")?;
        Ok(f64::midpoint(values[lower], values[middle]))
    } else {
        Ok(values[middle])
    }
}

fn gib_per_second(bytes: usize, ns: f64) -> Result<f64, Box<dyn Error>> {
    let bytes_u32 = u32::try_from(bytes)?;
    Ok(f64::from(bytes_u32) / (1024.0 * 1024.0 * 1024.0) / (ns / 1_000_000_000.0))
}

fn file_sha256(path: &Path) -> Result<String, Box<dyn Error>> {
    Ok(hex(&Sha256::digest(fs::read(path)?)))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes.iter().fold(String::new(), |mut output, byte| {
        write!(output, "{byte:02x}").expect("write to String");
        output
    })
}
