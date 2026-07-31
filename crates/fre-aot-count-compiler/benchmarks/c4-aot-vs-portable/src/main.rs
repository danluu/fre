#![cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code, unused_imports)
)]

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
compile_error!("the retained Count-v2 implementation object requires arm64 macOS");

use std::{
    error::Error,
    fs,
    hint::black_box,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use fre::{
    AggregateBuilder, AggregatePlanKind, AggregateRunLimits, LiteralAggregateReduceLimits,
    RustProfile,
};
use fre_aot_compiler::{
    CompiledObjectV2, MacosAarch64CountManifestV2, plan_and_compile_macos_aarch64_count_v2,
};
use fre_aot_count_compiler::{
    CountCompileClaimsV2, CountCompileLimitsV2, CountCompileRequestV2, CountFinalImageGlueLimitsV2,
    compile_count_v2, publish_count_final_image_glue_v2,
};
use sha2::{Digest, Sha256};

const LITERAL: &[u8] = b"needle";
const ROW_SELECTOR: u16 = 11;
const STEADY_REPETITIONS: usize = 16;
const COMPILE_REPETITIONS: usize = 16;
const COMPILE_ITERATIONS: usize = 64;
const LINK_REPETITIONS: usize = 16;
const BYTES_PER_STEADY_SAMPLE: usize = 64 * 1024 * 1024;
const IMPLEMENTATION_SYMBOL: &str =
    "fre_aot_count_entry_v2_54e0fe61df0a7a21135580e950940cf1bb9917f7f209ed74a12e6728cb4b36a9";

#[allow(
    unsafe_code,
    reason = "the benchmark links and calls the retained C3 ABI-audited Count entry"
)]
unsafe extern "C" {
    #[link_name = "fre_aot_count_entry_v2_54e0fe61df0a7a21135580e950940cf1bb9917f7f209ed74a12e6728cb4b36a9"]
    fn linked_aot_count_v2(haystack: *const u8, haystack_len: usize, result: *mut u64) -> u64;
}

#[derive(Clone, Copy, Debug)]
enum FixtureKind {
    Present,
    Absent,
    Dense,
    Tail,
}

impl FixtureKind {
    const ALL: [Self; 4] = [Self::Present, Self::Absent, Self::Dense, Self::Tail];

    const fn name(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Absent => "absent",
            Self::Dense => "dense",
            Self::Tail => "tail",
        }
    }
}

#[derive(Debug)]
struct Case {
    name: String,
    bytes: Vec<u8>,
    expected_count: u64,
}

#[derive(Clone, Copy, Debug)]
enum Engine {
    Aot,
    Portable,
}

impl Engine {
    const fn name(self) -> &'static str {
        match self {
            Self::Aot => "linked-aot-entry",
            Self::Portable => "portable-count-value",
        }
    }
}

#[derive(Debug)]
struct SteadySummary {
    case: String,
    bytes: usize,
    expected_count: u64,
    aot_ns: Vec<f64>,
    portable_ns: Vec<f64>,
}

#[derive(Debug)]
struct PhaseSummary {
    phase: &'static str,
    ns: Vec<f64>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "all".to_owned());
    if !matches!(mode.as_str(), "all" | "steady" | "costs") {
        return Err("usage: fre-aot-count-benchmark [all|steady|costs]".into());
    }

    print_bindings()?;
    if mode == "all" || mode == "steady" {
        run_steady_state()?;
    }
    if mode == "all" || mode == "costs" {
        run_compile_costs()?;
        run_link_costs()?;
    }
    Ok(())
}

fn print_bindings() -> Result<(), Box<dyn Error>> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let implementation = manifest.join("../../evidence/c3-count-v2/implementation.o");
    let glue = manifest.join("../../evidence/c3-count-v2/final-image-glue.o");
    let executable = std::env::current_exe()?;
    println!("META,key,value");
    println!("META,benchmark_source_sha256,{}", benchmark_source_id());
    println!(
        "META,implementation_object_sha256,{}",
        file_sha256(&implementation)?
    );
    println!("META,final_image_glue_sha256,{}", file_sha256(&glue)?);
    println!(
        "META,benchmark_executable_sha256,{}",
        file_sha256(&executable)?
    );
    println!("META,implementation_symbol,{IMPLEMENTATION_SYMBOL}");
    println!("META,literal_hex,{}", hex(LITERAL));
    println!("META,steady_repetitions,{STEADY_REPETITIONS}");
    println!("META,bytes_per_steady_sample,{BYTES_PER_STEADY_SAMPLE}");
    println!("META,compile_repetitions,{COMPILE_REPETITIONS}");
    println!("META,compile_iterations,{COMPILE_ITERATIONS}");
    println!("META,link_repetitions,{LINK_REPETITIONS}");
    Ok(())
}

fn benchmark_source_id() -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"FRE-AOT-COUNT-C4-BENCHMARK-SOURCE\0\x01");
    for (name, bytes) in [
        ("Cargo.toml", include_bytes!("../Cargo.toml").as_slice()),
        ("Cargo.lock", include_bytes!("../Cargo.lock").as_slice()),
        ("build.rs", include_bytes!("../build.rs").as_slice()),
        ("README.md", include_bytes!("../README.md").as_slice()),
        ("src/main.rs", include_bytes!("main.rs").as_slice()),
    ] {
        hasher.update(name.as_bytes());
        hasher.update([0]);
        hasher.update(bytes);
    }
    hex(&hasher.finalize())
}

fn file_sha256(path: &Path) -> Result<String, Box<dyn Error>> {
    Ok(hex(&Sha256::digest(fs::read(path)?)))
}

fn run_steady_state() -> Result<(), Box<dyn Error>> {
    let portable = AggregateBuilder::new("needle")
        .unicode(false)
        .build_count()?;
    if portable.build_report().plan != AggregatePlanKind::ExactLiteral {
        return Err("portable benchmark did not select ExactLiteral".into());
    }
    let limits = AggregateRunLimits {
        exact_literal: LiteralAggregateReduceLimits::unlimited(),
        ..AggregateRunLimits::default()
    };
    let cases = build_cases()?;

    println!(
        "SAMPLE,case,bytes,expected_count,repetition,order,engine,iterations,elapsed_ns,ns_per_call,checksum"
    );
    let mut summaries = Vec::with_capacity(cases.len());
    for (case_index, case) in cases.iter().enumerate() {
        let iterations = BYTES_PER_STEADY_SAMPLE
            .checked_div(case.bytes.len())
            .ok_or("zero-length steady fixture")?;
        if iterations == 0 {
            return Err("steady sample byte target is smaller than one fixture".into());
        }
        let aot_expected = linked_count(&case.bytes)?;
        let portable_expected = portable.count_value(&case.bytes, limits)?;
        if aot_expected != case.expected_count || portable_expected != case.expected_count {
            return Err(format!(
                "fixture {} expected {}, AOT {aot_expected}, portable {portable_expected}",
                case.name, case.expected_count
            )
            .into());
        }
        for _ in 0..4 {
            black_box(linked_count(black_box(&case.bytes))?);
            black_box(portable.count_value(black_box(&case.bytes), limits)?);
        }

        let mut summary = SteadySummary {
            case: case.name.clone(),
            bytes: case.bytes.len(),
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
                [Engine::Aot, Engine::Portable]
            } else {
                [Engine::Portable, Engine::Aot]
            };
            let order_name = if aot_first {
                "aot-first"
            } else {
                "portable-first"
            };
            for engine in order {
                let (elapsed, checksum) =
                    measure_steady(engine, iterations, case, &portable, &limits)?;
                let ns_per_call = duration_ns_per_iteration(elapsed, iterations)?;
                match engine {
                    Engine::Aot => summary.aot_ns.push(ns_per_call),
                    Engine::Portable => summary.portable_ns.push(ns_per_call),
                }
                println!(
                    "SAMPLE,{},{},{},{repetition},{order_name},{},{iterations},{},{ns_per_call:.3},{checksum}",
                    case.name,
                    case.bytes.len(),
                    case.expected_count,
                    engine.name(),
                    elapsed.as_nanos(),
                );
            }
        }
        summaries.push(summary);
    }

    println!(
        "SUMMARY,case,bytes,expected_count,aot_median_ns,portable_median_ns,portable_over_aot,linked_aot_gib_per_s,portable_gib_per_s"
    );
    for mut summary in summaries {
        let aot = median(&mut summary.aot_ns)?;
        let portable = median(&mut summary.portable_ns)?;
        let speedup = portable / aot;
        let aot_gib = gib_per_second(summary.bytes, aot)?;
        let portable_gib = gib_per_second(summary.bytes, portable)?;
        println!(
            "SUMMARY,{},{},{},{aot:.3},{portable:.3},{speedup:.4},{aot_gib:.4},{portable_gib:.4}",
            summary.case, summary.bytes, summary.expected_count
        );
    }
    Ok(())
}

fn measure_steady(
    engine: Engine,
    iterations: usize,
    case: &Case,
    portable: &fre::AggregateCountRegex,
    limits: &AggregateRunLimits,
) -> Result<(Duration, u64), Box<dyn Error>> {
    let start = Instant::now();
    let mut checksum = 0_u64;
    for _ in 0..iterations {
        let value = match engine {
            Engine::Aot => linked_count(black_box(&case.bytes))?,
            Engine::Portable => portable.count_value(black_box(&case.bytes), limits)?,
        };
        checksum = checksum.wrapping_add(black_box(value));
    }
    Ok((start.elapsed(), black_box(checksum)))
}

#[allow(
    unsafe_code,
    reason = "the retained object and hard-coded link name bind this call to the audited Count-v2 ABI"
)]
fn linked_count(haystack: &[u8]) -> Result<u64, Box<dyn Error>> {
    let mut result = u64::MAX;
    // SAFETY: the linked retained entry was independently audited for this
    // exact ABI; the slice is readable for its length and result is writable.
    let status = unsafe { linked_aot_count_v2(haystack.as_ptr(), haystack.len(), &raw mut result) };
    if status != 0 {
        return Err(format!("linked AOT entry returned status {status}").into());
    }
    Ok(result)
}

fn build_cases() -> Result<Vec<Case>, Box<dyn Error>> {
    let mut cases = Vec::with_capacity(8);
    for bytes in [64 * 1024, 1024 * 1024] {
        for kind in FixtureKind::ALL {
            cases.push(build_case(kind, bytes)?);
        }
    }
    Ok(cases)
}

fn build_case(kind: FixtureKind, bytes: usize) -> Result<Case, Box<dyn Error>> {
    if bytes < LITERAL.len() {
        return Err("fixture is shorter than the literal".into());
    }
    let mut haystack = vec![b'x'; bytes];
    let expected_count = match kind {
        FixtureKind::Absent => 0,
        FixtureKind::Tail => {
            let start = bytes
                .checked_sub(LITERAL.len())
                .ok_or("tail fixture underflow")?;
            haystack[start..].copy_from_slice(LITERAL);
            1
        }
        FixtureKind::Dense => {
            let mut start = 0_usize;
            let mut count = 0_u64;
            while start
                .checked_add(LITERAL.len())
                .is_some_and(|end| end <= bytes)
            {
                let end = start
                    .checked_add(LITERAL.len())
                    .ok_or("dense fixture end overflow")?;
                haystack[start..end].copy_from_slice(LITERAL);
                count = count.checked_add(1).ok_or("dense count overflow")?;
                start = end;
            }
            count
        }
        FixtureKind::Present => {
            let mut count = 0_u64;
            for numerator in [1_usize, 2, 3] {
                let approximate = bytes
                    .checked_mul(numerator)
                    .and_then(|value| value.checked_div(4))
                    .ok_or("present fixture position overflow")?;
                let start = approximate
                    .checked_sub(
                        approximate
                            .checked_rem(LITERAL.len())
                            .ok_or("zero literal width")?,
                    )
                    .ok_or("present fixture alignment underflow")?;
                let end = start
                    .checked_add(LITERAL.len())
                    .ok_or("present fixture end overflow")?;
                haystack
                    .get_mut(start..end)
                    .ok_or("present fixture range")?
                    .copy_from_slice(LITERAL);
                count = count.checked_add(1).ok_or("present count overflow")?;
            }
            count
        }
    };
    Ok(Case {
        name: format!("{}-{}", kind.name(), size_name(bytes)?),
        bytes: haystack,
        expected_count,
    })
}

const fn size_name(bytes: usize) -> Result<&'static str, &'static str> {
    match bytes {
        65_536 => Ok("64k"),
        1_048_576 => Ok("1m"),
        _ => Err("unsupported fixture size"),
    }
}

fn run_compile_costs() -> Result<(), Box<dyn Error>> {
    let oracle = legacy_oracle()?;
    let claims = claims_from_oracle(&oracle);
    let focused = compile_count_v2(
        CountCompileRequestV2 {
            literal: LITERAL,
            claims,
        },
        CountCompileLimitsV2::default(),
    )?;
    let _glue = publish_count_final_image_glue_v2(
        &focused,
        ROW_SELECTOR,
        CountFinalImageGlueLimitsV2::default(),
    )?;

    println!("COST_SAMPLE,phase,repetition,iterations,elapsed_ns,ns_per_iteration,checksum");
    let phases = [
        "portable-build",
        "focused-aot-compile-precomputed-claims",
        "final-image-glue-emit",
    ];
    let mut summaries: Vec<PhaseSummary> = phases
        .iter()
        .map(|phase| PhaseSummary {
            phase,
            ns: Vec::with_capacity(COMPILE_REPETITIONS),
        })
        .collect();
    for repetition in 0..COMPILE_REPETITIONS {
        for phase_offset in 0..phases.len() {
            let phase_index = repetition
                .checked_add(phase_offset)
                .ok_or("compile phase order overflow")?
                .checked_rem(phases.len())
                .ok_or("zero compile phase count")?;
            let phase = phases[phase_index];
            let (elapsed, checksum) = match phase {
                "portable-build" => measure_iterations(COMPILE_ITERATIONS, || {
                    let built = AggregateBuilder::new(black_box("needle"))
                        .unicode(false)
                        .build_count()
                        .expect("portable exact-literal benchmark build");
                    black_box(
                        u64::try_from(built.build_report().retained_capacity_bytes)
                            .expect("portable storage fits u64"),
                    )
                }),
                "focused-aot-compile-precomputed-claims" => {
                    measure_iterations(COMPILE_ITERATIONS, || {
                        let compiled = compile_count_v2(
                            CountCompileRequestV2 {
                                literal: black_box(LITERAL),
                                claims,
                            },
                            CountCompileLimitsV2::default(),
                        )
                        .expect("focused benchmark compile");
                        u64::from(compiled.implementation_object().object_identity()[0])
                    })
                }
                "final-image-glue-emit" => measure_iterations(COMPILE_ITERATIONS, || {
                    let published = publish_count_final_image_glue_v2(
                        black_box(&focused),
                        ROW_SELECTOR,
                        CountFinalImageGlueLimitsV2::default(),
                    )
                    .expect("benchmark glue emission");
                    u64::from(published.object().object_identity()[0])
                }),
                _ => unreachable!(),
            };
            let ns = duration_ns_per_iteration(elapsed, COMPILE_ITERATIONS)?;
            summaries[phase_index].ns.push(ns);
            println!(
                "COST_SAMPLE,{phase},{repetition},{COMPILE_ITERATIONS},{},{ns:.3},{checksum}",
                elapsed.as_nanos()
            );
        }
    }
    println!("COST_SUMMARY,phase,median_ns");
    for mut summary in summaries {
        let ns = median(&mut summary.ns)?;
        println!("COST_SUMMARY,{},{ns:.3}", summary.phase);
    }
    println!(
        "COST_NOTE,focused-aot-compile-precomputed-claims,planner-and-claim-production-excluded"
    );
    Ok(())
}

fn legacy_oracle() -> Result<CompiledObjectV2, Box<dyn Error>> {
    let mut profile = RustProfile::default();
    profile.options.unicode = false;
    Ok(plan_and_compile_macos_aarch64_count_v2(
        MacosAarch64CountManifestV2::default(),
        LITERAL.to_vec(),
        profile,
    )?)
}

fn claims_from_oracle(oracle: &CompiledObjectV2) -> CountCompileClaimsV2 {
    let claim = oracle.static_count_expectation().claim();
    CountCompileClaimsV2 {
        manifest_identity: *claim.manifest_identity(),
        policy_limits_identity: *claim.policy_limits_identity(),
        semantic_binding_identity: *claim.semantic_binding_identity(),
        planning_receipt_identity: *claim.planning_receipt_identity(),
        live_literal_identity: *claim.live_literal_identity(),
        program_identity: *claim.program_identity(),
        image_identity: *claim.image_identity(),
        object_binding_identity: *claim.object_binding_identity(),
        claimed_receipt_identity: *claim.receipt_identity(),
        claimed_resource_receipt_identity: *claim.resource_receipt_identity(),
    }
}

fn run_link_costs() -> Result<(), Box<dyn Error>> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let evidence = manifest.join("../../evidence/c3-count-v2");
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let output = std::env::temp_dir().join(format!(
        "fre-aot-count-c4-link-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&output)?;
    let mut samples = Vec::with_capacity(LINK_REPETITIONS);
    println!("LINK_SAMPLE,phase,repetition,elapsed_ns,ns_per_link,output_bytes");
    for repetition in 0..LINK_REPETITIONS {
        let executable = output.join(format!("linked-count-{repetition}"));
        let start = Instant::now();
        let link = Command::new("/usr/bin/clang")
            .args(["-arch", "arm64"])
            .arg(evidence.join("driver.c"))
            .arg(evidence.join("final-image-glue.o"))
            .arg(evidence.join("implementation.o"))
            .arg("-Wl,-segprot,__FRE_CONST,r,r")
            .arg("-o")
            .arg(&executable)
            .output()?;
        let elapsed = start.elapsed();
        if !link.status.success() {
            return Err(format!("timed final-image link failed: {:?}", link.stderr).into());
        }
        let output_bytes = fs::metadata(&executable)?.len();
        let ns = elapsed.as_secs_f64() * 1_000_000_000.0;
        samples.push(ns);
        println!(
            "LINK_SAMPLE,clang-driver-compile-and-final-image-link,{repetition},{},{ns:.3},{output_bytes}",
            elapsed.as_nanos()
        );
        fs::remove_file(executable)?;
    }
    fs::remove_dir(output)?;
    let median_ns = median(&mut samples)?;
    println!("LINK_SUMMARY,phase,median_ns");
    println!("LINK_SUMMARY,clang-driver-compile-and-final-image-link,{median_ns:.3}");
    Ok(())
}

fn measure_iterations(iterations: usize, mut operation: impl FnMut() -> u64) -> (Duration, u64) {
    let start = Instant::now();
    let mut checksum = 0_u64;
    for _ in 0..iterations {
        checksum = checksum.wrapping_add(black_box(operation()));
    }
    (start.elapsed(), black_box(checksum))
}

fn duration_ns_per_iteration(duration: Duration, iterations: usize) -> Result<f64, Box<dyn Error>> {
    let denominator = f64::from(u32::try_from(iterations)?);
    Ok(duration.as_secs_f64() * 1_000_000_000.0 / denominator)
}

fn median(samples: &mut [f64]) -> Result<f64, Box<dyn Error>> {
    if samples.is_empty() {
        return Err("cannot take median of empty samples".into());
    }
    samples.sort_unstable_by(f64::total_cmp);
    let midpoint = samples.len() / 2;
    if samples.len().is_multiple_of(2) {
        let lower = midpoint.checked_sub(1).ok_or("median midpoint underflow")?;
        Ok(f64::midpoint(samples[lower], samples[midpoint]))
    } else {
        Ok(samples[midpoint])
    }
}

fn gib_per_second(bytes: usize, ns: f64) -> Result<f64, Box<dyn Error>> {
    let bytes = f64::from(u32::try_from(bytes)?);
    Ok((bytes / (1024.0 * 1024.0 * 1024.0)) / (ns / 1_000_000_000.0))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes.iter().fold(String::new(), |mut encoded, byte| {
        write!(encoded, "{byte:02x}").expect("write hexadecimal byte");
        encoded
    })
}
