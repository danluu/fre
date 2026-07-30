//! Separate, non-promotable Linux Search AOT offline-cost subject.
//!
//! This example is never linked into the runtime qualification executable.
//! One invocation measures exactly one bounded stage. The admitted Python
//! owner validates and commits the emitted receipt outside the runtime bundle.

#![cfg_attr(
    not(all(target_arch = "aarch64", target_os = "linux")),
    allow(dead_code, unused_imports)
)]

use std::{
    env,
    error::Error,
    fmt::Write as _,
    fs::{self, File, OpenOptions},
    hint::black_box,
    io::{self, Read as _, Write as _},
    os::{
        fd::AsRawFd as _,
        unix::fs::{FileExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Instant,
};

use fre::RustProfile;
use fre_aot_compiler::{
    LinuxAarch64ExactSearchManifestV1, LinuxAarch64SearchBackendV1,
    LinuxAarch64SearchCompilePolicyV1, LinuxSearchCompiledObjectV1,
    LinuxSearchSpanFinalImageGlueLimitsV1, LinuxStaticSearchSpanExpectationV1,
    LinuxUnsignedSearchSpanFinalImageReceiptV1, PublishedLinuxSearchSpanFinalImageGlueV1,
    SearchAotRuntimeAuthorityV1, SearchSpanFinalImageAdopterV1,
    build_linux_static_search_span_expectation_v1, inspect_linux_search_compile_receipt_v1,
    plan_and_compile_linux_aarch64_exact_search_v1,
    publish_linux_search_span_qualification_final_image_glue_v1,
};
use fre_aot_elf::ObjectLimitsV1;
use fre_kernel_ir::{OutputKind, Span};
use sha2::{Digest, Sha256};

type DynError = Box<dyn Error>;

const SAMPLE_SCHEMA: &str = "fre-aot-linux-search-offline-subject-sample-v2";
const IDENTITY_SCHEMA: &str = "fre-aot-linux-search-offline-subject-identity-v2";
const NON_PROMOTABLE: &str = "evidence-only-no-runtime-or-production-authority";
const MAX_ARTIFACT_BYTES: u64 = 16 << 20;
const MAX_ITERATIONS: u32 = 4096;
const MAX_ELAPSED_NS: u64 = 900_000_000_000;
const IMPLEMENTATION: &str = "implementation.o";
const GLUE: &str = "final-image-glue.o";
const COMPILER_RECEIPT: &str = "compiler-receipt.bin";
const EXPECTATION: &str = "expectation.bin";
const GLUE_RECEIPT: &str = "final-image-glue-receipt.bin";
const SOURCE: &str = "source.regex";
const HASH_MANIFEST: &str = "SHA256SUMS";
const HASHED_ARTIFACTS: [&str; 10] = [
    "bindings.h",
    "bindings.rs",
    "bundle.tsv",
    COMPILER_RECEIPT,
    EXPECTATION,
    GLUE_RECEIPT,
    GLUE,
    IMPLEMENTATION,
    "source-row-proposal.tsv",
    SOURCE,
];

const EMBEDDED_SOURCE_COMMIT: Option<&str> = option_env!("FRE_AOT_OFFLINE_SOURCE_COMMIT");
const EMBEDDED_SOURCE_TREE: Option<&str> = option_env!("FRE_AOT_OFFLINE_SOURCE_TREE");
const EMBEDDED_SOURCE_MANIFEST_SHA256: Option<&str> =
    option_env!("FRE_AOT_OFFLINE_SOURCE_MANIFEST_SHA256");
const EMBEDDED_SOURCE_CLOSURE_SHA256: Option<&str> =
    option_env!("FRE_AOT_OFFLINE_SOURCE_CLOSURE_SHA256");
const EMBEDDED_INPUT_BINDING_SHA256: Option<&str> =
    option_env!("FRE_AOT_OFFLINE_INPUT_BINDING_SHA256");
const EMBEDDED_BUILD_RECEIPT_SHA256: Option<&str> =
    option_env!("FRE_AOT_OFFLINE_BUILD_RECEIPT_SHA256");
const EMBEDDED_TOOLCHAIN_CLOSURE_SHA256: Option<&str> =
    option_env!("FRE_AOT_OFFLINE_TOOLCHAIN_CLOSURE_SHA256");
const EMBEDDED_CARGO_HOME_CLOSURE_SHA256: Option<&str> =
    option_env!("FRE_AOT_OFFLINE_CARGO_HOME_CLOSURE_SHA256");
const EMBEDDED_NATIVE_CLOSURE_SHA256: Option<&str> =
    option_env!("FRE_AOT_OFFLINE_NATIVE_CLOSURE_SHA256");
const EMBEDDED_NATIVE_SYSROOT_CLOSURE_SHA256: Option<&str> =
    option_env!("FRE_AOT_OFFLINE_NATIVE_SYSROOT_CLOSURE_SHA256");
const EMBEDDED_CARGO_SHA256: Option<&str> = option_env!("FRE_AOT_OFFLINE_CARGO_SHA256");
const EMBEDDED_RUSTC_SHA256: Option<&str> = option_env!("FRE_AOT_OFFLINE_RUSTC_SHA256");
const EMBEDDED_LINK_DRIVER_SHA256: Option<&str> = option_env!("FRE_AOT_OFFLINE_LINK_DRIVER_SHA256");
const EMBEDDED_LINKER_SHA256: Option<&str> = option_env!("FRE_AOT_OFFLINE_LINKER_SHA256");

struct Candidate {
    root: PathBuf,
    source: Vec<u8>,
    backend: LinuxAarch64SearchBackendV1,
    row_selector: u16,
    compiled: LinuxSearchCompiledObjectV1<Span>,
    expectation: LinuxStaticSearchSpanExpectationV1,
    glue: PublishedLinuxSearchSpanFinalImageGlueV1,
    candidate_identity: String,
    compiler_receipt_identity: String,
    final_receipt_identity: String,
}

#[derive(Clone, Copy)]
enum Stage {
    Compiler,
    Glue,
    Link,
}

impl Stage {
    fn parse(value: &str) -> Result<Self, DynError> {
        match value {
            "source-to-receipted-elf-object" => Ok(Self::Compiler),
            "glue-object-preparation" => Ok(Self::Glue),
            "final-link" => Ok(Self::Link),
            _ => Err(invalid("unsupported offline stage").into()),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Compiler => "source-to-receipted-elf-object",
            Self::Glue => "glue-object-preparation",
            Self::Link => "final-link",
        }
    }

    const fn scope(self) -> &'static str {
        match self {
            Self::Compiler => "fre-custom-compiler-payload",
            Self::Glue => "fre-custom-expectation-and-glue-payload",
            Self::Link => "enclosing-rustc-clang-lld-final-link",
        }
    }
}

struct Request {
    stage: Stage,
    repetition: u32,
    iterations: u32,
    candidate: PathBuf,
    work: PathBuf,
    cpu: u32,
    campaign_lock_fd: u32,
    rustc: PathBuf,
    expected_rustc_sha256: String,
    link_driver: PathBuf,
    expected_link_driver_sha256: String,
    linker: PathBuf,
    expected_linker_sha256: String,
    native_sysroot: PathBuf,
}

#[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
fn main() {
    eprintln!("offline Linux Search AOT cost subject requires Linux AArch64");
    std::process::exit(1);
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
fn main() -> Result<(), DynError> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let Some(mode) = arguments.next().and_then(|value| value.into_string().ok()) else {
        return Err(invalid("usage: subject identity|sample ...").into());
    };
    match mode.as_str() {
        "identity" => {
            require(arguments.next().is_none(), "identity takes no arguments")?;
            print_identity()
        }
        "sample" => {
            let request = parse_sample_request(arguments)?;
            run_sample(&request)
        }
        _ => Err(invalid("usage: subject identity|sample ...").into()),
    }
}

fn print_identity() -> Result<(), DynError> {
    println!("schema\t{IDENTITY_SCHEMA}");
    print_embedded_identity()?;
    println!("scope\tseparate-offline-cost-subject");
    println!("promotion_authority\tabsent");
    println!("runtime_authority\tabsent");
    println!("status\t{NON_PROMOTABLE}");
    Ok(())
}

fn parse_sample_request(
    mut arguments: impl Iterator<Item = std::ffi::OsString>,
) -> Result<Request, DynError> {
    const USAGE: &str = "usage: subject sample STAGE REPETITION ITERATIONS \
        CANDIDATE WORK CPU CAMPAIGN_LOCK_FD RUSTC EXPECTED_RUSTC_SHA256 LINK_DRIVER \
        EXPECTED_LINK_DRIVER_SHA256 LINKER EXPECTED_LINKER_SHA256 \
        NATIVE_SYSROOT";
    let stage = Stage::parse(&required_string(&mut arguments, USAGE)?)?;
    let repetition = canonical_u32(&required_string(&mut arguments, USAGE)?, "repetition")?;
    let iterations = canonical_u32(&required_string(&mut arguments, USAGE)?, "iterations")?;
    require(
        iterations > 0
            && iterations <= MAX_ITERATIONS
            && (!matches!(stage, Stage::Link) || iterations == 1),
        "iteration count is outside the closed stage bound",
    )?;
    let candidate = PathBuf::from(arguments.next().ok_or_else(|| invalid(USAGE))?);
    let work = PathBuf::from(arguments.next().ok_or_else(|| invalid(USAGE))?);
    let cpu = canonical_u32(&required_string(&mut arguments, USAGE)?, "CPU")?;
    require(cpu <= 4095, "CPU is outside the closed bound")?;
    let campaign_lock_fd = canonical_u32(
        &required_string(&mut arguments, USAGE)?,
        "campaign lock descriptor",
    )?;
    require(
        (3..=2_147_483_647).contains(&campaign_lock_fd),
        "campaign lock descriptor is outside the closed bound",
    )?;
    let rustc = PathBuf::from(arguments.next().ok_or_else(|| invalid(USAGE))?);
    let expected_rustc_sha256 = required_string(&mut arguments, USAGE)?;
    let link_driver = PathBuf::from(arguments.next().ok_or_else(|| invalid(USAGE))?);
    let expected_link_driver_sha256 = required_string(&mut arguments, USAGE)?;
    let linker = PathBuf::from(arguments.next().ok_or_else(|| invalid(USAGE))?);
    let expected_linker_sha256 = required_string(&mut arguments, USAGE)?;
    let native_sysroot = PathBuf::from(arguments.next().ok_or_else(|| invalid(USAGE))?);
    require(arguments.next().is_none(), USAGE)?;
    require_hex64(&expected_rustc_sha256, "rustc SHA-256")?;
    require_hex64(&expected_link_driver_sha256, "link-driver SHA-256")?;
    require_hex64(&expected_linker_sha256, "linker SHA-256")?;
    Ok(Request {
        stage,
        repetition,
        iterations,
        candidate,
        work,
        cpu,
        campaign_lock_fd,
        rustc,
        expected_rustc_sha256,
        link_driver,
        expected_link_driver_sha256,
        linker,
        expected_linker_sha256,
        native_sysroot,
    })
}

fn required_string(
    arguments: &mut impl Iterator<Item = std::ffi::OsString>,
    usage: &str,
) -> Result<String, DynError> {
    arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| invalid(usage).into())
}

fn canonical_u32(value: &str, label: &str) -> Result<u32, DynError> {
    require(
        !value.is_empty()
            && (value == "0" || !value.starts_with('0'))
            && value.bytes().all(|byte| byte.is_ascii_digit()),
        &format!("{label} is not canonical decimal"),
    )?;
    value.parse::<u32>().map_err(Into::into)
}

fn run_sample(request: &Request) -> Result<(), DynError> {
    require_exact_affinity(request.cpu)?;
    require_campaign_lock(request.campaign_lock_fd)?;
    let candidate = load_candidate(&request.candidate)?;
    let (
        elapsed_ns,
        checksum,
        iteration_set_sha256,
        artifact_identity,
        artifact_sha256,
        output_bytes,
    ) = match request.stage {
        Stage::Compiler => measure_compiler(&candidate, request.iterations)?,
        Stage::Glue => measure_glue(&candidate, request.iterations)?,
        Stage::Link => measure_link(&candidate, request)?,
    };
    require(
        elapsed_ns > 0 && elapsed_ns <= MAX_ELAPSED_NS,
        "sample elapsed time is outside the closed bound",
    )?;
    let reopened = load_candidate(&request.candidate)?;
    require(
        reopened.candidate_identity == candidate.candidate_identity
            && reopened.compiler_receipt_identity == candidate.compiler_receipt_identity
            && reopened.final_receipt_identity == candidate.final_receipt_identity
            && reopened.backend == candidate.backend
            && reopened.row_selector == candidate.row_selector,
        "candidate identity changed across the untimed sample boundary",
    )?;
    validate_exact_bytes(
        &reopened.source,
        &candidate.source,
        "reopened candidate source",
    )?;
    validate_compiled(&candidate, &reopened.compiled)?;
    validate_glue(&candidate, &reopened.expectation, &reopened.glue)?;
    println!("schema\t{SAMPLE_SCHEMA}");
    print_embedded_identity()?;
    println!("stage\t{}", request.stage.name());
    println!("scope\t{}", request.stage.scope());
    println!("repetition\t{}", request.repetition);
    println!("iterations\t{}", request.iterations);
    println!("elapsed_ns\t{elapsed_ns}");
    println!("checksum\t{checksum}");
    println!("iteration_set_sha256\t{iteration_set_sha256}");
    println!("artifact_identity\t{artifact_identity}");
    println!("artifact_sha256\t{artifact_sha256}");
    println!("output_bytes\t{output_bytes}");
    println!("candidate_identity\t{}", candidate.candidate_identity);
    println!(
        "compiler_receipt_identity\t{}",
        candidate.compiler_receipt_identity
    );
    println!(
        "final_receipt_identity\t{}",
        candidate.final_receipt_identity
    );
    println!("backend\t{}", backend_name(candidate.backend));
    println!("row_selector\t{}", candidate.row_selector);
    println!("target_cpu\t{}", request.cpu);
    println!("campaign_lock_inherited\ttrue");
    println!("promotion_authority\tabsent");
    println!("runtime_authority\tabsent");
    println!("status\t{NON_PROMOTABLE}");
    Ok(())
}

fn print_embedded_identity() -> Result<(), DynError> {
    for (key, value) in [
        ("source_commit", EMBEDDED_SOURCE_COMMIT),
        ("source_tree", EMBEDDED_SOURCE_TREE),
        ("source_manifest_sha256", EMBEDDED_SOURCE_MANIFEST_SHA256),
        ("source_closure_sha256", EMBEDDED_SOURCE_CLOSURE_SHA256),
        ("input_binding_sha256", EMBEDDED_INPUT_BINDING_SHA256),
        ("build_receipt_sha256", EMBEDDED_BUILD_RECEIPT_SHA256),
        (
            "toolchain_closure_sha256",
            EMBEDDED_TOOLCHAIN_CLOSURE_SHA256,
        ),
        (
            "cargo_home_closure_sha256",
            EMBEDDED_CARGO_HOME_CLOSURE_SHA256,
        ),
        ("native_closure_sha256", EMBEDDED_NATIVE_CLOSURE_SHA256),
        (
            "native_sysroot_closure_sha256",
            EMBEDDED_NATIVE_SYSROOT_CLOSURE_SHA256,
        ),
        ("cargo_sha256", EMBEDDED_CARGO_SHA256),
        ("rustc_sha256", EMBEDDED_RUSTC_SHA256),
        ("link_driver_sha256", EMBEDDED_LINK_DRIVER_SHA256),
        ("linker_sha256", EMBEDDED_LINKER_SHA256),
    ] {
        let value = value.ok_or_else(|| invalid(format!("missing embedded {key}")))?;
        require_hex64_or_commit(value, key)?;
        println!("{key}\t{value}");
    }
    Ok(())
}

fn measure_compiler(
    candidate: &Candidate,
    iterations: u32,
) -> Result<(u64, u64, String, String, String, u64), DynError> {
    let mut total_ns = 0_u64;
    let mut iteration_set = Sha256::new();
    for ordinal in 0..iterations {
        // Materializing the owned source fixture is harness work and remains
        // outside the named compiler interval. The interval starts when the
        // complete owned input crosses the compiler API and includes all
        // compiler-internal allocation, planning, custom emission, ELF
        // construction, receipt construction, and internal authentication.
        let source = black_box(candidate.source.clone());
        let started = Instant::now();
        let compiled = compile_candidate(source, black_box(candidate.backend))?;
        total_ns = checked_add_elapsed(total_ns, started)?;

        // Exact output/receipt validation and hashing are deliberately after
        // the timer. Every iteration is validated before its output is
        // dropped or the next iteration begins.
        validate_compiled(candidate, &compiled)?;
        let receipt = compiled.receipt().canonical_receipt_bytes()?;
        hash_iteration(
            &mut iteration_set,
            ordinal,
            &[compiled.object().as_bytes(), &receipt],
        )?;
        drop(black_box(compiled));
    }
    let iteration_set_sha256: [u8; 32] = iteration_set.finalize().into();
    let checksum = u64::from_le_bytes(iteration_set_sha256[..8].try_into()?);
    Ok((
        total_ns,
        checksum,
        hex(&iteration_set_sha256),
        candidate.compiler_receipt_identity.clone(),
        hex(&sha256(candidate.compiled.object().as_bytes())),
        u64::try_from(candidate.compiled.object().as_bytes().len())?,
    ))
}

fn measure_glue(
    candidate: &Candidate,
    iterations: u32,
) -> Result<(u64, u64, String, String, String, u64), DynError> {
    let mut total_ns = 0_u64;
    let mut iteration_set = Sha256::new();
    for ordinal in 0..iterations {
        let started = Instant::now();
        let expectation =
            build_linux_static_search_span_expectation_v1(black_box(&candidate.compiled))?;
        let glue = publish_linux_search_span_qualification_final_image_glue_v1(
            black_box(&candidate.compiled),
            black_box(&expectation),
            candidate.row_selector,
            LinuxSearchSpanFinalImageGlueLimitsV1::default(),
        )?;
        total_ns = checked_add_elapsed(total_ns, started)?;

        // Validation, full-byte binding, and output destruction are outside
        // the named expectation/glue emission interval.
        validate_glue(candidate, &expectation, &glue)?;
        hash_iteration(
            &mut iteration_set,
            ordinal,
            &[
                expectation.as_bytes(),
                glue.object().as_bytes(),
                glue.receipt().canonical_bytes(),
            ],
        )?;
        drop(black_box((expectation, glue)));
    }
    let iteration_set_sha256: [u8; 32] = iteration_set.finalize().into();
    let checksum = u64::from_le_bytes(iteration_set_sha256[..8].try_into()?);
    Ok((
        total_ns,
        checksum,
        hex(&iteration_set_sha256),
        candidate.final_receipt_identity.clone(),
        hex(&sha256(candidate.glue.object().as_bytes())),
        u64::try_from(candidate.glue.object().as_bytes().len())?,
    ))
}

fn measure_link(
    candidate: &Candidate,
    request: &Request,
) -> Result<(u64, u64, String, String, String, u64), DynError> {
    require_private_empty_directory(&request.work)?;
    require_exact_regular_executable(&request.rustc, &request.expected_rustc_sha256, "rustc")?;
    require_exact_regular_executable(
        &request.link_driver,
        &request.expected_link_driver_sha256,
        "link driver",
    )?;
    require_exact_regular_executable(
        &request.linker,
        &request.expected_linker_sha256,
        "native linker",
    )?;
    require(
        request.native_sysroot.is_absolute()
            && request.native_sysroot.canonicalize()? == request.native_sysroot
            && request.native_sysroot.is_dir(),
        "native sysroot is not one canonical directory",
    )?;
    let rustc_input = open_inherited_regular(
        &request.rustc,
        &request.expected_rustc_sha256,
        true,
        "rustc",
    )?;
    let link_driver_input = open_inherited_regular(
        &request.link_driver,
        &request.expected_link_driver_sha256,
        true,
        "link driver",
    )?;
    let linker_input = open_inherited_regular(
        &request.linker,
        &request.expected_linker_sha256,
        true,
        "native linker",
    )?;
    let toolchain_root = request
        .rustc
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| invalid("rustc has no toolchain root"))?;
    let toolchain_input = open_inherited_directory(toolchain_root, "Rust toolchain")?;
    let native_bin = request
        .link_driver
        .parent()
        .ok_or_else(|| invalid("link driver has no parent"))?;
    let native_bin_input = open_inherited_directory(native_bin, "native bin")?;
    let native_sysroot_input = open_inherited_directory(&request.native_sysroot, "native sysroot")?;
    let implementation_input = open_inherited_exact_bytes(
        &candidate.root.join(IMPLEMENTATION),
        candidate.compiled.object().as_bytes(),
        "candidate implementation",
    )?;
    let glue_input = open_inherited_exact_bytes(
        &candidate.root.join(GLUE),
        candidate.glue.object().as_bytes(),
        "candidate glue",
    )?;
    let proc_rustc = proc_fd_path(&rustc_input);
    let proc_link_driver = proc_fd_path(&link_driver_input);
    let proc_linker = proc_fd_path(&linker_input);
    let proc_toolchain = proc_fd_path(&toolchain_input);
    let proc_native_bin = proc_fd_path(&native_bin_input);
    let proc_native_sysroot = proc_fd_path(&native_sysroot_input);
    let proc_implementation = proc_fd_path(&implementation_input);
    let proc_glue = proc_fd_path(&glue_input);
    let final_receipt = LinuxUnsignedSearchSpanFinalImageReceiptV1::from_canonical_bytes(
        &read_bounded(&candidate.root.join(GLUE_RECEIPT), MAX_ARTIFACT_BYTES)?,
    )?;
    let symbols = final_receipt.exported_symbols()?;
    let source = render_link_fixture(symbols.glue().as_str(), symbols.adopter_symbol().as_str())?;
    let source_path = request.work.join("link-fixture.rs");
    write_new(&source_path, source.as_bytes(), 0o600)?;
    let executable = request.work.join("linked-offline-fixture");
    let mut command = Command::new(&proc_rustc);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .env("PATH", &proc_native_bin)
        .arg(&source_path)
        .args([
            "--crate-name",
            "fre_aot_linux_search_offline_link_fixture",
            "--edition=2024",
            "-Copt-level=3",
            "-Cpanic=abort",
            "-Ccodegen-units=1",
            "-Ctarget-feature=+crt-static",
            "-Cstrip=none",
        ])
        .arg(format!("--sysroot={}", proc_toolchain.display()))
        .arg(format!("-Clinker={}", proc_link_driver.display()))
        .arg("-Clink-arg=--target=aarch64-unknown-linux-gnu")
        .arg(format!(
            "-Clink-arg=--sysroot={}",
            proc_native_sysroot.display()
        ))
        .arg(format!("-Clink-arg=--ld-path={}", proc_linker.display()))
        .args([
            "-Clink-arg=-static",
            "-Clink-arg=-Wl,--no-dynamic-linker",
            "-Clink-arg=-Wl,--build-id=none",
            "-Clink-arg=-Wl,-z,separate-code",
            "-Clink-arg=-Wl,-z,noexecstack",
        ])
        .arg(format!("-Clink-arg={}", proc_implementation.display()))
        .arg(format!("-Clink-arg={}", proc_glue.display()))
        .arg(format!(
            "--remap-path-prefix={}=/fre-offline-link",
            request.work.display()
        ))
        .arg("-o")
        .arg(&executable)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let started = Instant::now();
    let status = command.status()?;
    let elapsed_ns = bounded_elapsed(started)?;
    require(status.success(), "pinned rustc/linker final link failed")?;
    require_exact_regular_executable(
        &request.rustc,
        &request.expected_rustc_sha256,
        "rustc after link",
    )?;
    require_exact_regular_executable(
        &request.link_driver,
        &request.expected_link_driver_sha256,
        "link driver after link",
    )?;
    require_exact_regular_executable(
        &request.linker,
        &request.expected_linker_sha256,
        "native linker after link",
    )?;
    verify_inherited_regular(
        &rustc_input,
        &request.expected_rustc_sha256,
        true,
        "pinned rustc after link",
    )?;
    verify_inherited_regular(
        &link_driver_input,
        &request.expected_link_driver_sha256,
        true,
        "pinned link driver after link",
    )?;
    verify_inherited_regular(
        &linker_input,
        &request.expected_linker_sha256,
        true,
        "pinned native linker after link",
    )?;
    verify_inherited_exact_bytes(
        &implementation_input,
        candidate.compiled.object().as_bytes(),
        "pinned candidate implementation after link",
    )?;
    verify_inherited_exact_bytes(
        &glue_input,
        candidate.glue.object().as_bytes(),
        "pinned candidate glue after link",
    )?;
    let output_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&executable)?;
    let named_before = fs::symlink_metadata(&executable)?;
    let opened_before = output_file.metadata()?;
    require(
        named_before.file_type().is_file()
            && opened_before.file_type().is_file()
            && opened_before.nlink() == 1
            && opened_before.uid() == effective_user_id()
            && (
                named_before.dev(),
                named_before.ino(),
                named_before.mode(),
                named_before.nlink(),
                named_before.uid(),
                named_before.len(),
            ) == (
                opened_before.dev(),
                opened_before.ino(),
                opened_before.mode(),
                opened_before.nlink(),
                opened_before.uid(),
                opened_before.len(),
            ),
        "linked output path differs from its opened regular descriptor",
    )?;
    output_file.set_permissions(fs::Permissions::from_mode(0o500))?;
    let output = read_descriptor(&output_file, 64 << 20, "linked output")?;
    let named_after = fs::symlink_metadata(&executable)?;
    let opened_after = output_file.metadata()?;
    require(
        named_after.file_type().is_file()
            && opened_after.file_type().is_file()
            && opened_after.nlink() == 1
            && opened_after.uid() == effective_user_id()
            && opened_after.mode() & 0o7777 == 0o500
            && (
                named_after.dev(),
                named_after.ino(),
                named_after.mode(),
                named_after.nlink(),
                named_after.uid(),
                named_after.len(),
            ) == (
                opened_after.dev(),
                opened_after.ino(),
                opened_after.mode(),
                opened_after.nlink(),
                opened_after.uid(),
                opened_after.len(),
            )
            && (
                opened_before.dev(),
                opened_before.ino(),
                opened_before.uid(),
            ) == (opened_after.dev(), opened_after.ino(), opened_after.uid()),
        "linked output lost its named mode-0500 descriptor identity",
    )?;
    validate_static_aarch64_executable(
        &output,
        &[symbols.glue().as_str(), symbols.adopter_symbol().as_str()],
    )?;
    let digest = sha256(&output);
    let checksum = u64::from_le_bytes(digest[..8].try_into()?);
    Ok((
        elapsed_ns,
        checksum,
        hex(&sha256(&output)),
        candidate.candidate_identity.clone(),
        hex(&digest),
        u64::try_from(output.len())?,
    ))
}

fn render_link_fixture(glue: &str, adopter: &str) -> Result<String, DynError> {
    require_symbol(glue)?;
    require_symbol(adopter)?;
    let mut source = String::new();
    writeln!(source, "#![allow(dead_code)]")?;
    writeln!(source, "unsafe extern \"C\" {{")?;
    writeln!(source, "    #[link_name = \"{glue}\"]")?;
    writeln!(source, "    fn linked_glue();")?;
    writeln!(source, "}}")?;
    writeln!(source, "#[unsafe(export_name = \"{adopter}\")]")?;
    writeln!(
        source,
        "pub extern \"C\" fn offline_non_authorizing_adopter_stub() -> u32 {{ 1 }}"
    )?;
    writeln!(source, "fn main() {{")?;
    writeln!(
        source,
        "    std::hint::black_box(linked_glue as unsafe extern \"C\" fn());"
    )?;
    writeln!(source, "}}")?;
    Ok(source)
}

fn load_candidate(path: &Path) -> Result<Candidate, DynError> {
    let root = path.canonicalize()?;
    require(
        path.is_absolute() && root == path && root.is_dir(),
        "candidate is not one canonical directory",
    )?;
    let candidate_identity = verify_hash_manifest(&root)?;
    let source = read_bounded(&root.join(SOURCE), MAX_ARTIFACT_BYTES)?;
    let compiler_receipt_bytes = read_bounded(&root.join(COMPILER_RECEIPT), MAX_ARTIFACT_BYTES)?;
    let compiler_receipt = inspect_linux_search_compile_receipt_v1(&compiler_receipt_bytes)?;
    require(
        compiler_receipt.runtime_authority() == SearchAotRuntimeAuthorityV1::Absent
            && compiler_receipt.output() == OutputKind::Span,
        "compiler receipt is not an inert Span candidate",
    )?;
    let backend = compiler_receipt.backend();
    let compiled = compile_candidate(source.clone(), backend)?;
    validate_exact_bytes(
        compiled.object().as_bytes(),
        &read_bounded(&root.join(IMPLEMENTATION), MAX_ARTIFACT_BYTES)?,
        "implementation object",
    )?;
    validate_exact_bytes(
        &compiled.receipt().canonical_receipt_bytes()?,
        &compiler_receipt_bytes,
        "compiler receipt",
    )?;
    compiler_receipt.validate_object(compiled.object().as_bytes(), ObjectLimitsV1::default())?;
    let expectation = build_linux_static_search_span_expectation_v1(&compiled)?;
    validate_exact_bytes(
        expectation.as_bytes(),
        &read_bounded(&root.join(EXPECTATION), MAX_ARTIFACT_BYTES)?,
        "expectation",
    )?;
    let final_receipt_bytes = read_bounded(&root.join(GLUE_RECEIPT), MAX_ARTIFACT_BYTES)?;
    let final_receipt =
        LinuxUnsignedSearchSpanFinalImageReceiptV1::from_canonical_bytes(&final_receipt_bytes)?;
    require(
        final_receipt.runtime_authority() == SearchAotRuntimeAuthorityV1::Absent
            && final_receipt.adopter() == Some(SearchSpanFinalImageAdopterV1::QualificationPrivate),
        "offline subject accepts only signer-free private qualification glue",
    )?;
    let row_selector = final_receipt.row_selector();
    let glue = publish_linux_search_span_qualification_final_image_glue_v1(
        &compiled,
        &expectation,
        row_selector,
        LinuxSearchSpanFinalImageGlueLimitsV1::default(),
    )?;
    validate_glue_bytes(&root, &glue, &final_receipt_bytes)?;
    final_receipt.validate_reopened_candidate(
        &compiler_receipt,
        compiled.object().as_bytes(),
        expectation.as_bytes(),
        glue.object().as_bytes(),
        ObjectLimitsV1::default(),
        LinuxSearchSpanFinalImageGlueLimitsV1::default(),
    )?;
    Ok(Candidate {
        root,
        source,
        backend,
        row_selector,
        compiler_receipt_identity: hex(compiler_receipt.receipt_identity().as_bytes()),
        final_receipt_identity: hex(final_receipt.receipt_identity().as_bytes()),
        candidate_identity,
        compiled,
        expectation,
        glue,
    })
}

fn compile_candidate(
    source: Vec<u8>,
    backend: LinuxAarch64SearchBackendV1,
) -> Result<LinuxSearchCompiledObjectV1<Span>, DynError> {
    let manifest = LinuxAarch64ExactSearchManifestV1::new(
        LinuxAarch64SearchCompilePolicyV1::default(),
        backend,
    )?;
    let mut profile = RustProfile::default();
    profile.options.unicode = false;
    Ok(plan_and_compile_linux_aarch64_exact_search_v1(
        manifest, source, profile,
    )?)
}

fn validate_compiled(
    expected: &Candidate,
    actual: &LinuxSearchCompiledObjectV1<Span>,
) -> Result<(), DynError> {
    validate_exact_bytes(
        actual.object().as_bytes(),
        expected.compiled.object().as_bytes(),
        "timed implementation object",
    )?;
    validate_exact_bytes(
        &actual.receipt().canonical_receipt_bytes()?,
        &expected.compiled.receipt().canonical_receipt_bytes()?,
        "timed compiler receipt",
    )
}

fn validate_glue(
    expected: &Candidate,
    expectation: &LinuxStaticSearchSpanExpectationV1,
    glue: &PublishedLinuxSearchSpanFinalImageGlueV1,
) -> Result<(), DynError> {
    validate_exact_bytes(
        expectation.as_bytes(),
        expected.expectation.as_bytes(),
        "timed expectation",
    )?;
    validate_exact_bytes(
        glue.object().as_bytes(),
        expected.glue.object().as_bytes(),
        "timed glue object",
    )?;
    validate_exact_bytes(
        glue.receipt().canonical_bytes(),
        expected.glue.receipt().canonical_bytes(),
        "timed glue receipt",
    )
}

fn validate_glue_bytes(
    root: &Path,
    glue: &PublishedLinuxSearchSpanFinalImageGlueV1,
    receipt: &[u8],
) -> Result<(), DynError> {
    validate_exact_bytes(
        glue.object().as_bytes(),
        &read_bounded(&root.join(GLUE), MAX_ARTIFACT_BYTES)?,
        "glue object",
    )?;
    validate_exact_bytes(glue.receipt().canonical_bytes(), receipt, "glue receipt")
}

fn verify_hash_manifest(root: &Path) -> Result<String, DynError> {
    let manifest = read_bounded(&root.join(HASH_MANIFEST), 16 << 10)?;
    let text = std::str::from_utf8(&manifest)?;
    let lines: Vec<&str> = text.lines().collect();
    require(
        manifest.ends_with(b"\n") && lines.len() == HASHED_ARTIFACTS.len(),
        "candidate SHA256SUMS has the wrong shape",
    )?;
    for (line, name) in lines.iter().zip(HASHED_ARTIFACTS) {
        let expected = format!(
            "{}  {name}",
            hex(&sha256(&read_bounded(
                &root.join(name),
                MAX_ARTIFACT_BYTES,
            )?))
        );
        require(*line == expected, "candidate SHA256SUMS is not canonical")?;
    }
    Ok(hex(&sha256(&manifest)))
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, DynError> {
    let metadata = fs::symlink_metadata(path)?;
    require(
        metadata.file_type().is_file() && metadata.nlink() == 1 && metadata.len() <= maximum,
        &format!("{} is not one bounded owner file", path.display()),
    )?;
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(
            maximum
                .checked_add(1)
                .ok_or_else(|| invalid("read bound"))?,
        )
        .read_to_end(&mut bytes)?;
    require(
        u64::try_from(bytes.len())? == metadata.len(),
        &format!("{} changed while read", path.display()),
    )?;
    Ok(bytes)
}

fn proc_fd_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

#[allow(
    unsafe_code,
    reason = "geteuid is a side-effect-free query used to enforce owner-private benchmark inputs"
)]
fn effective_user_id() -> u32 {
    // SAFETY: geteuid takes no arguments and has no memory-safety preconditions.
    unsafe { libc::geteuid() }
}

#[allow(
    unsafe_code,
    reason = "fcntl is required to retain exact input descriptors across the measured exec"
)]
fn make_inheritable(file: &File) -> Result<(), DynError> {
    let descriptor = file.as_raw_fd();
    // SAFETY: descriptor is owned by `file`; F_GETFD does not mutate memory.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: descriptor remains owned by `file`; this changes only FD_CLOEXEC.
    if unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

fn read_descriptor(file: &File, maximum: u64, label: &str) -> Result<Vec<u8>, DynError> {
    let before = file.metadata()?;
    require(
        before.file_type().is_file() && before.nlink() == 1 && before.len() <= maximum,
        &format!("{label} is not one bounded regular file"),
    )?;
    let size = usize::try_from(before.len())?;
    let mut bytes = vec![0_u8; size];
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let count = file.read_at(&mut bytes[offset..], u64::try_from(offset)?)?;
        require(count > 0, &format!("{label} descriptor had a short read"))?;
        offset = offset
            .checked_add(count)
            .ok_or_else(|| invalid(format!("{label} read offset overflow")))?;
    }
    require(
        file.read_at(&mut [0_u8; 1], before.len())? == 0,
        &format!("{label} descriptor grew while read"),
    )?;
    let after = file.metadata()?;
    require(
        (
            before.dev(),
            before.ino(),
            before.mode(),
            before.nlink(),
            before.uid(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) == (
            after.dev(),
            after.ino(),
            after.mode(),
            after.nlink(),
            after.uid(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        ),
        &format!("{label} descriptor changed while read"),
    )?;
    Ok(bytes)
}

fn verify_inherited_regular(
    file: &File,
    expected_sha256: &str,
    executable: bool,
    label: &str,
) -> Result<(), DynError> {
    let metadata = file.metadata()?;
    require(
        !executable || metadata.mode() & 0o111 != 0,
        &format!("{label} is not executable"),
    )?;
    let bytes = read_descriptor(file, 512 << 20, label)?;
    require(
        hex(&sha256(&bytes)) == expected_sha256,
        &format!("{label} differs from exact SHA-256"),
    )
}

fn open_inherited_regular(
    path: &Path,
    expected_sha256: &str,
    executable: bool,
    label: &str,
) -> Result<File, DynError> {
    require(
        path.is_absolute() && path.canonicalize()? == path,
        &format!("{label} path is not canonical"),
    )?;
    let named = fs::symlink_metadata(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let opened = file.metadata()?;
    require(
        named.file_type().is_file()
            && (
                named.dev(),
                named.ino(),
                named.mode(),
                named.nlink(),
                named.uid(),
                named.len(),
            ) == (
                opened.dev(),
                opened.ino(),
                opened.mode(),
                opened.nlink(),
                opened.uid(),
                opened.len(),
            ),
        &format!("{label} path differs from opened descriptor"),
    )?;
    verify_inherited_regular(&file, expected_sha256, executable, label)?;
    make_inheritable(&file)?;
    Ok(file)
}

fn verify_inherited_exact_bytes(file: &File, expected: &[u8], label: &str) -> Result<(), DynError> {
    require(
        read_descriptor(file, MAX_ARTIFACT_BYTES, label)? == expected,
        &format!("{label} differs from authenticated candidate bytes"),
    )
}

fn open_inherited_exact_bytes(path: &Path, expected: &[u8], label: &str) -> Result<File, DynError> {
    require(
        path.is_absolute() && path.canonicalize()? == path,
        &format!("{label} path is not canonical"),
    )?;
    let named = fs::symlink_metadata(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let opened = file.metadata()?;
    require(
        named.file_type().is_file()
            && (
                named.dev(),
                named.ino(),
                named.mode(),
                named.nlink(),
                named.uid(),
                named.len(),
            ) == (
                opened.dev(),
                opened.ino(),
                opened.mode(),
                opened.nlink(),
                opened.uid(),
                opened.len(),
            ),
        &format!("{label} path differs from opened descriptor"),
    )?;
    verify_inherited_exact_bytes(&file, expected, label)?;
    make_inheritable(&file)?;
    Ok(file)
}

fn open_inherited_directory(path: &Path, label: &str) -> Result<File, DynError> {
    require(
        path.is_absolute() && path.canonicalize()? == path,
        &format!("{label} path is not canonical"),
    )?;
    let named = fs::symlink_metadata(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?;
    let opened = file.metadata()?;
    require(
        named.file_type().is_dir()
            && opened.file_type().is_dir()
            && named.mode() & 0o022 == 0
            && (named.dev(), named.ino(), named.mode(), named.uid())
                == (opened.dev(), opened.ino(), opened.mode(), opened.uid()),
        &format!("{label} path differs from opened read-only descriptor"),
    )?;
    make_inheritable(&file)?;
    Ok(file)
}

fn read_u16(bytes: &[u8], offset: usize, label: &str) -> Result<u16, DynError> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| invalid(format!("{label} offset overflow")))?;
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..end)
            .ok_or_else(|| invalid(format!("{label} exceeds ELF")))?
            .try_into()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize, label: &str) -> Result<u32, DynError> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| invalid(format!("{label} offset overflow")))?;
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..end)
            .ok_or_else(|| invalid(format!("{label} exceeds ELF")))?
            .try_into()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize, label: &str) -> Result<u64, DynError> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| invalid(format!("{label} offset overflow")))?;
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..end)
            .ok_or_else(|| invalid(format!("{label} exceeds ELF")))?
            .try_into()?,
    ))
}

fn bounded_table_entry(
    base: u64,
    entry_size: u64,
    ordinal: u64,
    minimum_size: u64,
    bytes: &[u8],
    label: &str,
) -> Result<usize, DynError> {
    require(
        entry_size >= minimum_size,
        &format!("{label} entry is undersized"),
    )?;
    let offset = base
        .checked_add(
            entry_size
                .checked_mul(ordinal)
                .ok_or_else(|| invalid(format!("{label} ordinal overflow")))?,
        )
        .ok_or_else(|| invalid(format!("{label} offset overflow")))?;
    let end = offset
        .checked_add(entry_size)
        .ok_or_else(|| invalid(format!("{label} extent overflow")))?;
    require(
        end <= u64::try_from(bytes.len())?,
        &format!("{label} exceeds ELF"),
    )?;
    Ok(usize::try_from(offset)?)
}

fn validate_required_elf_symbols(
    bytes: &[u8],
    section_offset: u64,
    section_size: u64,
    section_count: u64,
    required: &[&str],
) -> Result<(), DynError> {
    let mut found = vec![false; required.len()];
    for ordinal in 0..section_count {
        let header = bounded_table_entry(
            section_offset,
            section_size,
            ordinal,
            64,
            bytes,
            "section header",
        )?;
        let section_type = read_u32(bytes, header + 4, "section type")?;
        if section_type != 2 && section_type != 11 {
            continue;
        }
        let symbols_offset = read_u64(bytes, header + 24, "symbol table offset")?;
        let symbols_size = read_u64(bytes, header + 32, "symbol table size")?;
        let strings_index = u64::from(read_u32(bytes, header + 40, "symbol string table")?);
        let symbol_size = read_u64(bytes, header + 56, "symbol table entry size")?;
        require(
            symbol_size >= 24 && symbols_size % symbol_size == 0 && strings_index < section_count,
            "symbol table shape is invalid",
        )?;
        let strings_header = bounded_table_entry(
            section_offset,
            section_size,
            strings_index,
            64,
            bytes,
            "symbol string section",
        )?;
        let strings_offset = read_u64(bytes, strings_header + 24, "string table offset")?;
        let strings_size = read_u64(bytes, strings_header + 32, "string table size")?;
        let strings_end = strings_offset
            .checked_add(strings_size)
            .ok_or_else(|| invalid("string table extent overflow"))?;
        require(
            strings_end <= u64::try_from(bytes.len())?,
            "string table exceeds ELF",
        )?;
        let strings = bytes
            .get(usize::try_from(strings_offset)?..usize::try_from(strings_end)?)
            .ok_or_else(|| invalid("string table range"))?;
        let symbols = symbols_size / symbol_size;
        require(symbols <= 1_000_000, "symbol table exceeds bound")?;
        for symbol in 0..symbols {
            let entry =
                bounded_table_entry(symbols_offset, symbol_size, symbol, 24, bytes, "symbol")?;
            let name_offset = usize::try_from(read_u32(bytes, entry, "symbol name")?)?;
            let section_index = read_u16(bytes, entry + 6, "symbol section")?;
            if section_index == 0 || name_offset >= strings.len() {
                continue;
            }
            let suffix = &strings[name_offset..];
            let end = suffix
                .iter()
                .position(|byte| *byte == 0)
                .ok_or_else(|| invalid("unterminated symbol name"))?;
            let name = suffix
                .get(..end)
                .ok_or_else(|| invalid("symbol name extent"))?;
            for (required_name, present) in required.iter().zip(&mut found) {
                if name == required_name.as_bytes() {
                    *present = true;
                }
            }
        }
    }
    require(
        found.into_iter().all(|present| present),
        "linked ELF lacks required defined glue/adopter symbols",
    )
}

fn validate_static_aarch64_executable(
    bytes: &[u8],
    required_symbols: &[&str],
) -> Result<(), DynError> {
    require(
        bytes.len() >= 64
            && bytes.get(..7) == Some(b"\x7fELF\x02\x01\x01")
            && matches!(read_u16(bytes, 16, "ELF type")?, 2 | 3)
            && read_u16(bytes, 18, "ELF machine")? == 183
            && read_u32(bytes, 20, "ELF version")? == 1
            && read_u16(bytes, 52, "ELF header size")? == 64,
        "linked output is not Linux AArch64 ELF64LE",
    )?;
    let entry = read_u64(bytes, 24, "ELF entry")?;
    let program_offset = read_u64(bytes, 32, "program table offset")?;
    let section_offset = read_u64(bytes, 40, "section table offset")?;
    let program_size = u64::from(read_u16(bytes, 54, "program header size")?);
    let program_count = u64::from(read_u16(bytes, 56, "program header count")?);
    let section_size = u64::from(read_u16(bytes, 58, "section header size")?);
    let section_count = u64::from(read_u16(bytes, 60, "section header count")?);
    require(
        program_size == 56
            && (1..=256).contains(&program_count)
            && section_size == 64
            && (1..=4096).contains(&section_count)
            && entry != 0,
        "linked ELF header tables are outside their closed shape",
    )?;
    let mut executable_load = false;
    let mut entry_in_executable_load = false;
    let mut non_executable_stack = false;
    for ordinal in 0..program_count {
        let header = bounded_table_entry(
            program_offset,
            program_size,
            ordinal,
            56,
            bytes,
            "program header",
        )?;
        let kind = read_u32(bytes, header, "program kind")?;
        let flags = read_u32(bytes, header + 4, "program flags")?;
        let offset = read_u64(bytes, header + 8, "program offset")?;
        let virtual_address = read_u64(bytes, header + 16, "program address")?;
        let file_size = read_u64(bytes, header + 32, "program file size")?;
        let memory_size = read_u64(bytes, header + 40, "program memory size")?;
        let end = offset
            .checked_add(file_size)
            .ok_or_else(|| invalid("program extent overflow"))?;
        require(
            file_size <= memory_size && end <= u64::try_from(bytes.len())?,
            "linked ELF program segment exceeds image",
        )?;
        require(kind != 3, "linked ELF has PT_INTERP")?;
        if kind == 1 && flags & 1 != 0 {
            executable_load = true;
            entry_in_executable_load |= entry >= virtual_address
                && entry
                    < virtual_address
                        .checked_add(memory_size)
                        .ok_or_else(|| invalid("executable segment overflow"))?;
        }
        if kind == 2 {
            require(file_size % 16 == 0, "linked ELF dynamic table is malformed")?;
            let mut terminated = false;
            for dynamic in 0..(file_size / 16) {
                let dynamic_offset = offset
                    .checked_add(
                        dynamic
                            .checked_mul(16)
                            .ok_or_else(|| invalid("dynamic table overflow"))?,
                    )
                    .ok_or_else(|| invalid("dynamic table offset overflow"))?;
                let tag = read_u64(bytes, usize::try_from(dynamic_offset)?, "dynamic tag")?;
                require(tag != 1, "linked ELF has DT_NEEDED")?;
                if tag == 0 {
                    terminated = true;
                    break;
                }
            }
            require(terminated, "linked ELF dynamic table is unterminated")?;
        }
        if kind == 0x6474_e551 {
            require(flags & 1 == 0, "linked ELF requests executable stack")?;
            non_executable_stack = true;
        }
    }
    require(
        executable_load && entry_in_executable_load && non_executable_stack,
        "linked ELF lacks executable entry/non-executable stack contract",
    )?;
    validate_required_elf_symbols(
        bytes,
        section_offset,
        section_size,
        section_count,
        required_symbols,
    )
}

fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<(), DynError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn require_private_empty_directory(path: &Path) -> Result<(), DynError> {
    let metadata = fs::symlink_metadata(path)?;
    require(
        path.is_absolute()
            && path.canonicalize()? == path
            && metadata.file_type().is_dir()
            && metadata.uid() == effective_user_id()
            && metadata.mode() & 0o7777 == 0o700
            && fs::read_dir(path)?.next().is_none(),
        "link work directory is not canonical, private, and empty",
    )
}

fn require_exact_regular_executable(
    path: &Path,
    expected_sha256: &str,
    label: &str,
) -> Result<(), DynError> {
    let metadata = fs::symlink_metadata(path)?;
    require(
        path.is_absolute()
            && path.canonicalize()? == path
            && metadata.file_type().is_file()
            && metadata.nlink() == 1
            && metadata.len() <= 256 << 20
            && metadata.mode() & 0o111 != 0
            && hex(&sha256(&read_bounded(path, 256 << 20)?)) == expected_sha256,
        &format!("{label} differs from its exact pin"),
    )
}

fn require_exact_affinity(cpu: u32) -> Result<(), DynError> {
    let status = fs::read_to_string("/proc/self/status")?;
    let expected = format!("Cpus_allowed_list:\t{cpu}");
    require(
        status.lines().any(|line| line == expected),
        "subject is not confined to the admitted target CPU",
    )
}

fn require_campaign_lock(descriptor: u32) -> Result<(), DynError> {
    let path = PathBuf::from(format!("/proc/self/fd/{descriptor}"));
    let target = path.canonicalize()?;
    let metadata = fs::metadata(&path)?;
    require(
        target.file_name().is_some_and(|name| name == "run.lock")
            && metadata.file_type().is_file()
            && metadata.nlink() == 1
            && metadata.mode() & 0o7777 == 0o600,
        "inherited campaign lifetime lock has the wrong identity",
    )
}

fn bounded_elapsed(started: Instant) -> Result<u64, DynError> {
    u64::try_from(started.elapsed().as_nanos()).map_err(Into::into)
}

fn checked_add_elapsed(total: u64, started: Instant) -> Result<u64, DynError> {
    let elapsed = bounded_elapsed(started)?;
    require(
        elapsed > 0 && elapsed <= MAX_ELAPSED_NS,
        "one iteration elapsed time is outside the closed bound",
    )?;
    total
        .checked_add(elapsed)
        .ok_or_else(|| invalid("sample elapsed time overflow").into())
}

fn hash_iteration(hasher: &mut Sha256, ordinal: u32, artifacts: &[&[u8]]) -> Result<(), DynError> {
    hasher.update(b"FRE-AOT-LINUX-SEARCH-OFFLINE-ITERATION\0\x01");
    hasher.update(ordinal.to_le_bytes());
    hasher.update(u32::try_from(artifacts.len())?.to_le_bytes());
    for artifact in artifacts {
        hasher.update(u64::try_from(artifact.len())?.to_le_bytes());
        hasher.update(artifact);
    }
    Ok(())
}

fn validate_exact_bytes(actual: &[u8], expected: &[u8], label: &str) -> Result<(), DynError> {
    require(
        actual == expected,
        &format!("{label} differs from candidate"),
    )
}

fn require_symbol(value: &str) -> Result<(), DynError> {
    require(
        !value.is_empty()
            && value.len() <= 255
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
        "generated symbol is not one bounded assembler identifier",
    )
}

fn require_hex64(value: &str, label: &str) -> Result<(), DynError> {
    require(
        value.len() == 64
            && value != "0".repeat(64)
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        &format!("{label} is not canonical nonzero SHA-256"),
    )
}

fn require_hex64_or_commit(value: &str, label: &str) -> Result<(), DynError> {
    let valid = (value.len() == 40 || value.len() == 64)
        && value != "0".repeat(value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    require(valid, &format!("{label} is not canonical identity hex"))
}

const fn backend_name(backend: LinuxAarch64SearchBackendV1) -> &'static str {
    match backend {
        LinuxAarch64SearchBackendV1::AsimdV8 => "v8-asimd",
        LinuxAarch64SearchBackendV1::AsimdV9 => "v9-asimd",
        LinuxAarch64SearchBackendV1::AsimdV10 => "v10-asimd",
        LinuxAarch64SearchBackendV1::AsimdV12 => "v12-asimd",
        LinuxAarch64SearchBackendV1::AsimdV13 => "v13-asimd",
        LinuxAarch64SearchBackendV1::AsimdV15 => "v15-asimd-phase-unique",
        LinuxAarch64SearchBackendV1::Sve2Fixed16Tag21Vl16 => "tag21-sve2-fixed16",
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").expect("writing hexadecimal to String cannot fail");
    }
    output
}

fn require(condition: bool, message: &str) -> Result<(), DynError> {
    if condition {
        Ok(())
    } else {
        Err(invalid(message).into())
    }
}

fn invalid(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}
