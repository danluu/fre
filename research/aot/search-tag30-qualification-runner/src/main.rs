#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::too_many_lines,
    unsafe_code,
    reason = "the sealed qualification harness keeps authenticated fixture geometry, guarded mappings, CPU checks, and paired timing linear and explicit"
)]

use std::{
    collections::{HashMap, hash_map::Entry},
    error::Error,
    ffi::c_void,
    fs::{File, OpenOptions},
    hint::black_box,
    io::{self, BufRead as _, BufReader, BufWriter, Write as _},
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::Path,
    ptr::NonNull,
    time::Instant,
};

use fre::{
    Match, PortableBuilder, PortableRegex, SearchExactLiteralAotV1, SearchExactLiteralAutoAotV1,
    SearchLimits, SearchWindow,
};
use fre_aot_static_runtime::{
    RawStaticSearchSpanAdoptionOutputV1, VerifiedStaticSearchSpanV1,
    adopt_linked_static_search_span_family_qualification_v1,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

#[allow(
    clippy::too_many_lines,
    dead_code,
    unsafe_code,
    reason = "generated declarations retain the complete sealed build identity"
)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/generated.rs"));
}

type DynError = Box<dyn Error>;

const CONTRACT_SHA256: &str = "d39dc02c741a13adc8e0c7c3cc818ffa69e96132af89caf0fef6b5dad6d14333";
const CONTRACT_SCHEMA: &str = "fre.aot.search-tag30-qualification-campaign-contract.v1";
const UNIVERSAL_ROW_SCHEMA: &str = "fre.aot.search-tag30-learned-continuation-projection.v1";
const LONG_ROW_SCHEMA: &str = "fre.aot.search-tag30-long-input-policy-projection.v1";
const FRAGMENT_HEADER_SCHEMA: &str = "fre.aot.search-tag30-qualification-fragment-header.v1";
const CORRECTNESS_ROW_SCHEMA: &str = "fre.aot.search-tag30-qualification-correctness-row.v1";
const TIMING_ROW_SCHEMA: &str = "fre.aot.search-tag30-qualification-timing-row.v1";
const FRAGMENT_TRAILER_SCHEMA: &str = "fre.aot.search-tag30-qualification-fragment-trailer.v1";
const UNIVERSAL_PROJECTION_DOMAIN: &[u8] = b"FRE-SEARCH-TAG29-TOPOLOGY-PROJECTION\0\x01";
const LONG_PROJECTION_DOMAIN: &[u8] = b"FRE-SEARCH-TAG30-LONG-INPUT-POLICY-PROJECTION\0\x01";
const FULL_ROWS: usize = 123_424;
const UNIVERSAL_FULL_SHA256: &str =
    "0326944c2c95dfd10740d2ea0a72c910dd1a03df8c16e3a2180391d069841480";
const UNIVERSAL_TIMED_ROWS: usize = 3_078;
const UNIVERSAL_TIMED_SHA256: &str =
    "a92a59554188a82b6e7c49833dda599aa7d87014ae6815ba9fbe0f5502b31a4c";
const LONG_FULL_SHA256: &str = "c912b402244ff9814fe6160f9f5a117d7b253af5ff35ee69a78a6250aae94561";
const LONG_TIMED_ROWS: usize = 1_458;
const LONG_TIMED_SHA256: &str = "b3093f9fed70fd500852742d18994fce80d4a144cb9b9cbaac4ad0e7f84ccffd";
const EXPECTED_CANDIDATES: usize = 808;
const UNIVERSAL_DIRECT_MINIMUM_WINDOW_BYTES: usize = 4_093;
const PRODUCTION_INPUT_FLOOR: usize = 65_536;
const PORTABLE_PREFIX_CANDIDATE_STARTS: usize = 256;
const FAMILY_SELECTOR: u16 = 13;
const SHARDS: usize = 16;
const DIAGNOSTIC_ROWS: usize = 30;
const REPETITIONS: usize = 6;
const MINIMUM_ELAPSED_NS: u64 = 400_000_000;
const CALIBRATION_TARGET_NS: u64 = 600_000_000;
const CALIBRATION_FLOOR_NS: u64 = 50_000_000;
const CALIBRATION_ANCHOR_SAMPLES: usize = 3;
const MAXIMUM_ITERATIONS: usize = 1 << 30;
const MAXIMUM_ROW_BYTES: usize = 32 * 1024;
const MAXIMUM_CONTRACT_BYTES: u64 = 128 * 1024;
const MAXIMUM_PROJECTION_BYTES: u64 = 1 << 30;
const CHECKSUM_SEED: u64 = 0x6a09_e667_f3bc_c909;
#[cfg(target_os = "macos")]
const MAXIMUM_CPU_ONLY_RETRIES: usize = 64;
#[cfg(target_os = "macos")]
const MACOS_SUPER_CLASS_WAIT_TIMEOUT_NS: u64 = 5_000_000_000;
#[cfg(target_os = "macos")]
const MACOS_SUPER_CPUS: [usize; 6] = [12, 13, 14, 15, 16, 17];
#[cfg(target_os = "macos")]
const MACOS_PERFORMANCE_CPUS: [usize; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
#[cfg(target_os = "macos")]
const APPLE_HOST: &str = "local-apple-aarch64-asimd";
#[cfg(target_os = "linux")]
const C9G_HOST: &str = "zstd-eval-c9g-neoverse-v3-aarch64-asimd";
const DIAGNOSTIC_ORDINALS: [usize; DIAGNOSTIC_ROWS] = [
    0, 11, 14, 33, 73, 119, 192, 256, 315, 324, 378, 432, 486, 540, 594, 648, 702, 756, 810, 864,
    918, 972, 1_026, 1_080, 1_134, 1_188, 1_242, 1_296, 1_350, 1_404,
];
const DIAGNOSTIC_ROW_SHA256S: [&str; DIAGNOSTIC_ROWS] = [
    "84d1523421f63d6f4b9c50d26f2a870d99b25dfc80b97282c812533da0234305",
    "3316237484fb1fb4e514eb08d1c6e6a0f2934833409c9444961070b07b3ed23c",
    "4b9c597da401300566c9477fca579d53ace9189cbd38a0ab127d403d489c5b0f",
    "a6cb1550ed0c9a258a94c8f60502fa25664d3be5a250c804d313c214cda57dc1",
    "722a3b09d53df16ae416ff7b9b0213e1a7e17921882b7a32157edffda4170bf8",
    "dd1b71df17581aeb8d14b19e8550d9b3e9db0bd8abe962844abf4d1f3b92f999",
    "4d7ef983ab129f2215aa7c985f3e549758b9c6f3e48ffd960d8be6b5b81a47ad",
    "d62428276a0921ace3dbaad6afeeb995389dc899b577de5f41a9c1d0f7f57e37",
    "fa4914a001a5e53fe8370f68e972c9a0fcdf1fa92c644c6417d9e785a24ffdb3",
    "52f30e26f2c7277653ca63f05774916564ffef6eaf5bf39f35468aa67eadc312",
    "257cf9e281c54cb67bb7db4c7a5aca0e3e444ea6b2c28a801c22a3f4c6fec4eb",
    "26d9af5eb75d133b6e13f046cbbcecc598d66cefe373753b0044a11c6906979a",
    "fff3cb95b41112e2c490868576adca5dd2db464e77430af00e1a6b9bc7ffc4e4",
    "a264216b1b2943f7c2175fbba5ca1d84d2ccdc67e6e72248027c1b14c2268dae",
    "05bfb296646e855b0f6ebda633afd7144eaeb4a69328e0c47eae6636e2bebb09",
    "1e707edbf5b571f887e6e679aadff32ea4676871287c2cb13e44f1f267a572a0",
    "8fd0625aed261660c69140bdc02237f24ec745bc500bd424e49bfbe1ec3dcd71",
    "6a43c4825c17384bbe8242ef9d0e0a8911c14b916700d8f60868361ec5c47da0",
    "1a63ef33ad62ac9e17ed4e21b37ed22bfef425975c11888ed600fa8058d57ad6",
    "29361a9093d463f21b74ed3c883b87526e785ce90ac73c03092b81db844af31d",
    "53f5d8911612336f2f6c7d49b071e755fb7ef23e4d5b597154c8813960071063",
    "a6f54d230662adccd245cec6b93e2cf05be1b2e9dfec56a2c296be868a7b654c",
    "14304796d0fea001b98667b3a5589b4c1478861b7bd30953ecb3dcbea8bcf163",
    "0eabb3f09365d2b8c4ffb4e53a9900fb7bcf2558c224a0c9fa9b885d2d5ae824",
    "9a8dbbe3a60f8a541c077d6f9c0c6e965be31d366a8978a60f74a29c4b1cb9f0",
    "16b2a4ece1784097bd27363f9e06bca0acb6f3c332f1e4b706b95ed9671cea9b",
    "86ff8bc8cdd8d7424f032fa47700514b716203ce046a1b5448422ab4012bf664",
    "6b623d268cd97c2b022f13ceed65ac72cacb307f4eebce299e40225016dd1279",
    "43a6e170e030a028a989daecb8a4d1d72a9dd3bf8bc0dc063a5113ac1d570507",
    "7894069f2d0e8ab57a32de9136456153f01bbba95aba490a281426d6da0dd0b0",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProjectionKind {
    Universal,
    LongPolicy,
    Diagnostic,
}

impl ProjectionKind {
    fn parse(value: &str) -> Result<Self, io::Error> {
        match value {
            "universal" => Ok(Self::Universal),
            "long-policy" => Ok(Self::LongPolicy),
            "diagnostic" => Ok(Self::Diagnostic),
            _ => Err(invalid(
                "projection kind must be universal, long-policy, or diagnostic",
            )),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Universal => "universal",
            Self::LongPolicy => "long-policy",
            Self::Diagnostic => "diagnostic",
        }
    }

    const fn row_schema(self) -> &'static str {
        match self {
            Self::Universal => UNIVERSAL_ROW_SCHEMA,
            Self::LongPolicy | Self::Diagnostic => LONG_ROW_SCHEMA,
        }
    }

    const fn domain(self) -> &'static [u8] {
        match self {
            Self::Universal => UNIVERSAL_PROJECTION_DOMAIN,
            Self::LongPolicy | Self::Diagnostic => LONG_PROJECTION_DOMAIN,
        }
    }

    const fn full_sha256(self) -> &'static str {
        match self {
            Self::Universal => UNIVERSAL_FULL_SHA256,
            Self::LongPolicy | Self::Diagnostic => LONG_FULL_SHA256,
        }
    }

    const fn timed_rows(self) -> usize {
        match self {
            Self::Universal => UNIVERSAL_TIMED_ROWS,
            Self::LongPolicy | Self::Diagnostic => LONG_TIMED_ROWS,
        }
    }

    const fn timed_sha256(self) -> &'static str {
        match self {
            Self::Universal => UNIVERSAL_TIMED_SHA256,
            Self::LongPolicy | Self::Diagnostic => LONG_TIMED_SHA256,
        }
    }

    const fn expected_route_counts(self) -> (usize, usize) {
        match self {
            Self::Universal => (49_248, 74_176),
            Self::LongPolicy => (23_328, 100_096),
            Self::Diagnostic => (0, 0),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Correctness,
    Timing,
}

impl Mode {
    const fn name(self) -> &'static str {
        match self {
            Self::Correctness => "correctness",
            Self::Timing => "timing",
        }
    }

    const fn projection_rows(self, kind: ProjectionKind) -> usize {
        match self {
            Self::Correctness => FULL_ROWS,
            Self::Timing => kind.timed_rows(),
        }
    }

    const fn projection_sha256(self, kind: ProjectionKind) -> &'static str {
        match self {
            Self::Correctness => kind.full_sha256(),
            Self::Timing => kind.timed_sha256(),
        }
    }

    const fn campaign_rows(self, kind: ProjectionKind) -> usize {
        match (self, kind) {
            (Self::Timing, ProjectionKind::Diagnostic) => DIAGNOSTIC_ROWS,
            _ => self.projection_rows(kind),
        }
    }
}

#[derive(Debug, Deserialize)]
struct ProjectionRow {
    schema: String,
    row_sha256: String,
    literal_sha256: String,
    literal_hex: String,
    literal_bytes: usize,
    topology: String,
    mutation_class: usize,
    learned_source_kind: String,
    #[serde(default)]
    learned_source_relations: Vec<String>,
    literal_phase_class: usize,
    selector_primary_offset_class: usize,
    logical_prefix_bytes: usize,
    window_bytes: usize,
    outcome: String,
    expected_match_start: Option<usize>,
    expected_match_end: Option<usize>,
    expected_route: String,
    expected_compiler_disposition: String,
    expected_static_invoked: bool,
    selector_eligible: bool,
    right_guarded: bool,
    expected_physical_window_start_mod16: usize,
    fixture_recipe: FixtureRecipe,
    #[serde(default)]
    parent_schema: Option<String>,
    #[serde(default)]
    parent_row_sha256: Option<String>,
    #[serde(default)]
    parent_expected_route: Option<String>,
    #[serde(default)]
    production_input_floor_bytes: Option<usize>,
    #[serde(default)]
    production_eligible: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct FixtureRecipe {
    construction_version: String,
    background_byte: u8,
    near_miss_tile_hex: String,
    window_start: usize,
    window_end: usize,
    true_literal_guard_bytes: usize,
    scalar_oracle_required: bool,
}

#[derive(Debug)]
struct Engine {
    portable: PortableRegex,
    verified: Option<&'static VerifiedStaticSearchSpanV1>,
}

#[derive(Debug)]
enum FixtureStorage {
    Padded {
        bytes: Vec<u8>,
        haystack_start: usize,
        haystack_bytes: usize,
    },
    Guarded {
        mapping: NonNull<c_void>,
        mapping_bytes: usize,
        haystack: NonNull<u8>,
        haystack_bytes: usize,
        page_bytes: usize,
    },
}

impl FixtureStorage {
    fn haystack(&self) -> &[u8] {
        match self {
            Self::Padded {
                bytes,
                haystack_start,
                haystack_bytes,
            } => &bytes[*haystack_start..*haystack_start + *haystack_bytes],
            Self::Guarded {
                haystack,
                haystack_bytes,
                ..
            } => {
                // SAFETY: materialization retains the readable mapping for the
                // FixtureStorage lifetime and the slice stops at the guard.
                unsafe { std::slice::from_raw_parts(haystack.as_ptr(), *haystack_bytes) }
            }
        }
    }

    fn haystack_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Padded {
                bytes,
                haystack_start,
                haystack_bytes,
            } => &mut bytes[*haystack_start..*haystack_start + *haystack_bytes],
            Self::Guarded {
                haystack,
                haystack_bytes,
                ..
            } => {
                // SAFETY: construction owns one private writable mapping; no
                // alias is published while materialization mutates it.
                unsafe { std::slice::from_raw_parts_mut(haystack.as_ptr(), *haystack_bytes) }
            }
        }
    }

    fn mapping_receipt(&self) -> Value {
        match self {
            Self::Padded {
                haystack_start,
                haystack_bytes,
                ..
            } => json!({
                "kind": "right-padded",
                "haystack_start_offset": haystack_start,
                "haystack_bytes": haystack_bytes,
                "guard_page": false,
            }),
            Self::Guarded {
                mapping_bytes,
                haystack_bytes,
                page_bytes,
                ..
            } => json!({
                "kind": "right-guarded",
                "mapping_bytes": mapping_bytes,
                "haystack_bytes": haystack_bytes,
                "page_bytes": page_bytes,
                "guard_page": true,
                "guard_protection": "none",
            }),
        }
    }
}

impl Drop for FixtureStorage {
    fn drop(&mut self) {
        if let Self::Guarded {
            mapping,
            mapping_bytes,
            ..
        } = self
        {
            // SAFETY: the pointer and exact extent come from one successful
            // mmap and are released once by this Drop implementation.
            let status = unsafe { libc::munmap(mapping.as_ptr(), *mapping_bytes) };
            debug_assert_eq!(status, 0);
        }
    }
}

#[derive(Debug)]
struct Fixture {
    storage: FixtureStorage,
    window: SearchWindow,
}

impl Fixture {
    fn haystack(&self) -> &[u8] {
        self.storage.haystack()
    }
}

#[derive(Clone, Copy, Debug)]
struct CpuAttempt {
    cpu_before: usize,
    cpu_after: usize,
    accepted: bool,
}

#[derive(Clone, Debug)]
struct Measurement {
    iterations: usize,
    elapsed_ns: u64,
    checksum: u64,
    cpu_before: usize,
    cpu_after: usize,
    cpu_attempts: Vec<CpuAttempt>,
}

#[derive(Clone, Debug)]
struct CalibrationReceipt {
    portable_pilots: Vec<Measurement>,
    candidate_pilots: Vec<Measurement>,
    selected_iterations: usize,
}

#[derive(Clone, Debug)]
struct CpuResidenceReceipt {
    method: &'static str,
    affinity_request_status: i32,
    qos_class: Option<u32>,
    qos_request_status: Option<i32>,
    accepted_cpu_class: &'static str,
    accepted_cpu_ids: Vec<usize>,
    macos_performance_levels: Option<Value>,
}

enum CandidateView<'a> {
    Direct(SearchExactLiteralAotV1<'a>),
    Automatic(SearchExactLiteralAutoAotV1<'a>),
}

impl CandidateView<'_> {
    fn find_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
    ) -> Result<Option<Match>, DynError> {
        match self {
            Self::Direct(view) => Ok(view
                .find_window(haystack, window, SearchLimits::unlimited())?
                .0),
            Self::Automatic(view) => Ok(view
                .find_window(haystack, window, SearchLimits::unlimited())?
                .0),
        }
    }
}

struct FragmentWriter {
    writer: BufWriter<File>,
    records: Sha256,
    rows: usize,
}

impl FragmentWriter {
    fn create(path: &Path, header: &Value) -> Result<Self, DynError> {
        let output = OpenOptions::new().write(true).create_new(true).open(path)?;
        let mut writer = BufWriter::new(output);
        write_json_line(&mut writer, header)?;
        Ok(Self {
            writer,
            records: Sha256::new(),
            rows: 0,
        })
    }

    fn record(&mut self, value: &Value) -> Result<(), DynError> {
        let mut encoded = serde_json::to_vec(value)?;
        encoded.push(b'\n');
        self.records
            .update(u64::try_from(encoded.len())?.to_le_bytes());
        self.records.update(&encoded);
        self.writer.write_all(&encoded)?;
        self.rows = self
            .rows
            .checked_add(1)
            .ok_or_else(|| invalid("fragment row count overflow"))?;
        Ok(())
    }

    fn finish(
        mut self,
        expected_rows: usize,
        shard_start: usize,
        shard_end: usize,
    ) -> Result<(), DynError> {
        require(self.rows == expected_rows, "fragment row total changed")?;
        let records: [u8; 32] = self.records.finalize().into();
        write_json_line(
            &mut self.writer,
            &json!({
                "schema": FRAGMENT_TRAILER_SCHEMA,
                "rows": self.rows,
                "shard_start": shard_start,
                "shard_end": shard_end,
                "records_sha256": hex(&records),
                "complete": true,
            }),
        )?;
        self.writer.flush()?;
        self.writer.get_ref().sync_all()?;
        self.writer
            .get_ref()
            .set_permissions(std::fs::Permissions::from_mode(0o444))?;
        self.writer.get_ref().sync_all()?;
        Ok(())
    }
}

fn main() -> Result<(), DynError> {
    validate_linked_build()?;
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [mode, contract, kind, projection, shard, host, cpu, output]
            if mode == "correctness" =>
        {
            run(
                Mode::Correctness,
                Path::new(contract),
                ProjectionKind::parse(kind)?,
                Path::new(projection),
                shard.parse()?,
                host,
                cpu.parse()?,
                Path::new(output),
            )
        }
        [mode, contract, kind, projection, shard, host, cpu, output]
            if mode == "timing" =>
        {
            run(
                Mode::Timing,
                Path::new(contract),
                ProjectionKind::parse(kind)?,
                Path::new(projection),
                shard.parse()?,
                host,
                cpu.parse()?,
                Path::new(output),
            )
        }
        _ => Err(invalid(
            "usage: correctness CONTRACT (universal|long-policy) PROJECTION SHARD_ID HOST_ID CPU_ID NEW_OUTPUT | timing CONTRACT (universal|long-policy|diagnostic) PROJECTION SHARD_ID HOST_ID CPU_ID NEW_OUTPUT",
        )
        .into()),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "all campaign-bound command inputs remain explicit at the runner boundary"
)]
fn run(
    mode: Mode,
    contract: &Path,
    kind: ProjectionKind,
    projection: &Path,
    shard: usize,
    host: &str,
    cpu: usize,
    output: &Path,
) -> Result<(), DynError> {
    authenticate_contract(contract)?;
    validate_host(host)?;
    require(shard < SHARDS, "shard ID is outside the frozen set")?;
    require(
        !(mode == Mode::Correctness && kind == ProjectionKind::Diagnostic),
        "the preregistered diagnostic has timing mode only",
    )?;
    if mode == Mode::Timing {
        require(
            generated::TIMING_PERMITTED,
            "linked identity does not permit qualification timing",
        )?;
    }
    let cpu_residence = pin_current_thread(cpu)?;
    let (shard_start, shard_end) = shard_bounds(mode, kind, shard)?;
    let rows = load_authenticated_shard(projection, mode, kind, shard_start, shard_end)?;
    let runner_binary_sha256 = current_binary_sha256()?;
    let header = json!({
        "schema": FRAGMENT_HEADER_SCHEMA,
        "contract_schema": CONTRACT_SCHEMA,
        "contract_sha256": CONTRACT_SHA256,
        "mode": mode.name(),
        "projection_kind": kind.name(),
        "projection_schema": kind.row_schema(),
        "projection_rows": mode.projection_rows(kind),
        "projection_sha256": mode.projection_sha256(kind),
        "shard_id": shard,
        "shard_start": shard_start,
        "shard_end": shard_end,
        "host_id": host,
        "logical_cpu": cpu,
        "cpu_residence_method": cpu_residence.method,
        "affinity_request_status": cpu_residence.affinity_request_status,
        "qos_class": cpu_residence.qos_class,
        "qos_request_status": cpu_residence.qos_request_status,
        "accepted_cpu_class": cpu_residence.accepted_cpu_class,
        "accepted_cpu_ids": cpu_residence.accepted_cpu_ids,
        "macos_performance_levels": cpu_residence.macos_performance_levels,
        "macos_super_class_wait_timeout_ns": macos_super_class_wait_timeout_ns(),
        "maximum_cpu_only_retries_per_variant": maximum_cpu_only_retries(),
        "runner_source_sha256": generated::RUNNER_SOURCE_SHA256,
        "runner_binary_sha256": runner_binary_sha256,
        "runner_identity_sha256": generated::IDENTITY_SHA256,
        "compiler_identity": generated::COMPILER_IDENTITY,
        "platform_manifest_identity": generated::PLATFORM_MANIFEST_IDENTITY,
        "build_receipt_sha256": generated::BUILD_RECEIPT_SHA256,
        "object_candidate_manifest_sha256": generated::OBJECT_CANDIDATE_MANIFEST_SHA256,
        "backend_tag": generated::BACKEND_TAG,
        "backend_name": generated::BACKEND_NAME,
        "family_selector": generated::FAMILY_SELECTOR,
        "minimum_window_bytes": generated::MINIMUM_WINDOW_BYTES,
        "portable_prefix_candidate_starts": generated::PORTABLE_PREFIX_CANDIDATE_STARTS,
        "timing_repetitions": if mode == Mode::Timing { Some(REPETITIONS) } else { None },
        "minimum_elapsed_ns_each_variant": if mode == Mode::Timing { Some(MINIMUM_ELAPSED_NS) } else { None },
        "rebar_accepted_as_input": false,
        "result_derived_exclusions": false,
    });
    let fragment = FragmentWriter::create(output, &header)?;
    match mode {
        Mode::Correctness => correctness_rows(kind, rows, fragment, shard_start, shard_end, cpu)?,
        Mode::Timing => timing_rows(kind, rows, fragment, shard_start, shard_end, cpu)?,
    }
    println!(
        "{}",
        serde_json::to_string(&json!({
            "schema": "fre.aot.search-tag30-qualification-shard-summary.v1",
            "mode": mode.name(),
            "projection_kind": kind.name(),
            "shard_id": shard,
            "shard_start": shard_start,
            "shard_end": shard_end,
            "host_id": host,
            "logical_cpu": cpu,
            "output": output,
            "complete": true,
            "rebar_accepted_as_input": false,
        }))?
    );
    Ok(())
}

fn correctness_rows(
    kind: ProjectionKind,
    rows: Vec<(usize, ProjectionRow)>,
    mut fragment: FragmentWriter,
    shard_start: usize,
    shard_end: usize,
    cpu: usize,
) -> Result<(), DynError> {
    let candidate_indices = candidate_indices()?;
    let mut engines = HashMap::new();
    let mut static_rows = 0_usize;
    let mut portable_rows = 0_usize;
    for (ordinal, row) in rows {
        validate_row(kind, &row)?;
        let fixture = materialize(&row)?;
        let expected = expected_match(&row);
        let engine = engine_for(&mut engines, &candidate_indices, &row)?;
        let portable = engine
            .portable
            .find_window(
                fixture.haystack(),
                fixture.window,
                SearchLimits::unlimited(),
            )?
            .0;
        require(
            project(portable) == expected,
            "portable correctness mismatch",
        )?;
        let mut direct = None;
        let mut automatic = None;
        if row.selector_eligible {
            let verified = engine
                .verified
                .ok_or_else(|| invalid("eligible literal lacks static object"))?;
            let direct_view = SearchExactLiteralAotV1::bind(&engine.portable, verified)?;
            let matched = direct_view
                .find_window(
                    fixture.haystack(),
                    fixture.window,
                    SearchLimits::unlimited(),
                )?
                .0;
            require(
                project(matched) == expected,
                "direct V17 correctness mismatch",
            )?;
            direct = Some(project(matched));
            if kind == ProjectionKind::LongPolicy {
                let automatic_view = SearchExactLiteralAutoAotV1::bind(&engine.portable, verified)?;
                require(
                    usize::try_from(
                        automatic_view
                            .family_execution_policy()
                            .minimum_window_bytes(),
                    )? == PRODUCTION_INPUT_FLOOR,
                    "automatic family floor changed",
                )?;
                let matched = automatic_view
                    .find_window(
                        fixture.haystack(),
                        fixture.window,
                        SearchLimits::unlimited(),
                    )?
                    .0;
                require(
                    project(matched) == expected,
                    "automatic long-policy correctness mismatch",
                )?;
                automatic = Some(project(matched));
            }
        } else {
            require(
                engine.verified.is_none(),
                "structural refusal unexpectedly has a static object",
            )?;
        }
        if row.expected_static_invoked {
            static_rows = static_rows
                .checked_add(1)
                .ok_or_else(|| invalid("static row overflow"))?;
        } else {
            portable_rows = portable_rows
                .checked_add(1)
                .ok_or_else(|| invalid("portable row overflow"))?;
        }
        fragment.record(&json!({
            "schema": CORRECTNESS_ROW_SCHEMA,
            "ordinal": ordinal,
            "row_sha256": row.row_sha256,
            "literal_sha256": row.literal_sha256,
            "selector_eligible": row.selector_eligible,
            "expected_compiler_disposition": row.expected_compiler_disposition,
            "expected_route": row.expected_route,
            "expected_static_invoked": row.expected_static_invoked,
            "scalar_span": expected,
            "portable_span": project(portable),
            "direct_v17_span": direct,
            "automatic_long_policy_span": automatic,
            "mapping": fixture.storage.mapping_receipt(),
            "actual_window_start_mod16": checked_start_mod16(&fixture),
            "worker_logical_cpu": cpu,
            "pass": true,
        }))?;
    }
    let (expected_static, expected_portable) = kind.expected_route_counts();
    let shard_rows = shard_end
        .checked_sub(shard_start)
        .ok_or_else(|| invalid("shard interval underflow"))?;
    require(
        static_rows.checked_add(portable_rows) == Some(shard_rows),
        "correctness shard route total changed",
    )?;
    if shard_start == 0 && shard_end == FULL_ROWS {
        require(
            (static_rows, portable_rows) == (expected_static, expected_portable),
            "full correctness route totals changed",
        )?;
    }
    fragment.finish(shard_rows, shard_start, shard_end)
}

fn timing_rows(
    kind: ProjectionKind,
    rows: Vec<(usize, ProjectionRow)>,
    mut fragment: FragmentWriter,
    shard_start: usize,
    shard_end: usize,
    cpu: usize,
) -> Result<(), DynError> {
    let candidate_indices = candidate_indices()?;
    let mut engines = HashMap::new();
    for (ordinal, row) in rows {
        validate_row(kind, &row)?;
        require(
            row.selector_eligible && row.expected_static_invoked,
            "timed projection contains a non-static row",
        )?;
        let fixture = materialize(&row)?;
        let expected = expected_match(&row);
        let engine = engine_for(&mut engines, &candidate_indices, &row)?;
        let verified = engine
            .verified
            .ok_or_else(|| invalid("timed literal lacks static object"))?;
        let candidate = match kind {
            ProjectionKind::Universal => {
                CandidateView::Direct(SearchExactLiteralAotV1::bind(&engine.portable, verified)?)
            }
            ProjectionKind::LongPolicy | ProjectionKind::Diagnostic => {
                let automatic = SearchExactLiteralAutoAotV1::bind(&engine.portable, verified)?;
                require(
                    usize::try_from(automatic.family_execution_policy().minimum_window_bytes())?
                        == PRODUCTION_INPUT_FLOOR,
                    "automatic family floor changed",
                )?;
                CandidateView::Automatic(automatic)
            }
        };
        verify_pair(&engine.portable, &candidate, &fixture, expected)?;
        wait_for_measurement_cpu(cpu)?;
        let calibration = calibrated_iterations(&engine.portable, &candidate, &fixture, cpu)?;
        let iterations = calibration.selected_iterations;
        let mut pairs = Vec::with_capacity(REPETITIONS);
        for repetition in 0..REPETITIONS {
            wait_for_measurement_cpu(cpu)?;
            let (portable, candidate_measurement, order) = if repetition % 2 == 0 {
                (
                    measure_portable(&engine.portable, &fixture, iterations, cpu)?,
                    measure_candidate(&candidate, &fixture, iterations, cpu)?,
                    "portable-first",
                )
            } else {
                let candidate_measurement =
                    measure_candidate(&candidate, &fixture, iterations, cpu)?;
                let portable = measure_portable(&engine.portable, &fixture, iterations, cpu)?;
                (portable, candidate_measurement, "candidate-first")
            };
            require_measurement_cpu(&portable, cpu)?;
            require_measurement_cpu(&candidate_measurement, cpu)?;
            require(
                portable.iterations == candidate_measurement.iterations
                    && portable.checksum == candidate_measurement.checksum,
                "timed pair semantics differ",
            )?;
            require(
                portable.elapsed_ns >= MINIMUM_ELAPSED_NS
                    && candidate_measurement.elapsed_ns >= MINIMUM_ELAPSED_NS,
                "timed variant did not reach the frozen minimum elapsed time",
            )?;
            pairs.push(json!({
                "repetition": repetition,
                "order": order,
                "iterations": iterations,
                "portable_elapsed_ns": portable.elapsed_ns,
                "candidate_elapsed_ns": candidate_measurement.elapsed_ns,
                "portable_checksum": portable.checksum,
                "candidate_checksum": candidate_measurement.checksum,
                "portable_cpu_before": portable.cpu_before,
                "portable_cpu_after": portable.cpu_after,
                "portable_cpu_retries": portable.cpu_attempts.len() - 1,
                "portable_cpu_attempts": cpu_attempt_receipts(&portable),
                "candidate_cpu_before": candidate_measurement.cpu_before,
                "candidate_cpu_after": candidate_measurement.cpu_after,
                "candidate_cpu_retries": candidate_measurement.cpu_attempts.len() - 1,
                "candidate_cpu_attempts": cpu_attempt_receipts(&candidate_measurement),
            }));
        }
        wait_for_measurement_cpu(cpu)?;
        fragment.record(&json!({
            "schema": TIMING_ROW_SCHEMA,
            "ordinal": ordinal,
            "row_sha256": row.row_sha256,
            "literal_sha256": row.literal_sha256,
            "literal_bytes": row.literal_bytes,
            "topology": row.topology,
            "mutation_class": row.mutation_class,
            "learned_source_kind": row.learned_source_kind,
            "learned_source_relations": row.learned_source_relations,
            "literal_phase_class": row.literal_phase_class,
            "selector_primary_offset_class": row.selector_primary_offset_class,
            "logical_prefix_bytes": row.logical_prefix_bytes,
            "window_bytes": row.window_bytes,
            "outcome": row.outcome,
            "right_guarded": row.right_guarded,
            "expected_route": row.expected_route,
            "candidate_call": if kind == ProjectionKind::Universal {
                "direct-v17"
            } else {
                "automatic-portable-prefix-static-tail"
            },
            "mapping": fixture.storage.mapping_receipt(),
            "actual_window_start_mod16": checked_start_mod16(&fixture),
            "logical_cpu": cpu,
            "minimum_elapsed_ns_each_variant": MINIMUM_ELAPSED_NS,
            "calibration": calibration_receipt(&calibration),
            "pairs": pairs,
            "pass": true,
            "rebar_accepted_as_input": false,
        }))?;
    }
    let expected_rows = shard_end
        .checked_sub(shard_start)
        .ok_or_else(|| invalid("timing shard interval underflow"))?;
    fragment.finish(expected_rows, shard_start, shard_end)
}

fn validate_linked_build() -> Result<(), io::Error> {
    require(generated::LINKED, "qualification runner was not linked")?;
    require(
        generated::BACKEND_TAG == 30
            && generated::BACKEND_NAME == "AsimdV17"
            && generated::FAMILY_SELECTOR == FAMILY_SELECTOR
            && generated::MINIMUM_WINDOW_BYTES == PRODUCTION_INPUT_FLOOR
            && generated::PORTABLE_PREFIX_CANDIDATE_STARTS == PORTABLE_PREFIX_CANDIDATE_STARTS
            && generated::CANDIDATES.len() == EXPECTED_CANDIDATES,
        "linked tag30 build identity changed",
    )
}

fn authenticate_contract(path: &Path) -> Result<(), DynError> {
    let metadata = std::fs::symlink_metadata(path)?;
    require(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.nlink() == 1
            && metadata.len() > 0
            && metadata.len() <= MAXIMUM_CONTRACT_BYTES,
        "campaign contract is not one bounded unshared regular file",
    )?;
    let bytes = std::fs::read(path)?;
    require(
        sha256_hex(&bytes) == CONTRACT_SHA256,
        "campaign contract identity changed",
    )?;
    let contract: Value = serde_json::from_slice(&bytes)?;
    require(
        contract.get("schema").and_then(Value::as_str) == Some(CONTRACT_SCHEMA)
            && contract.get("result_blind").and_then(Value::as_bool) == Some(true)
            && contract
                .get("rebar_inputs")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty),
        "campaign contract contents changed",
    )
    .map_err(Into::into)
}

fn current_binary_sha256() -> Result<String, DynError> {
    let path = std::env::current_exe()?;
    let metadata = std::fs::symlink_metadata(&path)?;
    require(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.nlink() == 1
            && metadata.len() > 0
            && metadata.len() <= MAXIMUM_PROJECTION_BYTES,
        "runner binary is not one bounded unshared regular file",
    )?;
    let bytes = std::fs::read(path)?;
    Ok(sha256_hex(&bytes))
}

fn validate_host(host: &str) -> Result<(), io::Error> {
    #[cfg(target_os = "macos")]
    let valid = host == APPLE_HOST;
    #[cfg(target_os = "linux")]
    let valid = host == C9G_HOST;
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let valid = false;
    require(valid, "host ID does not match this runner target")
}

fn shard_bounds(
    mode: Mode,
    kind: ProjectionKind,
    shard: usize,
) -> Result<(usize, usize), io::Error> {
    require(shard < SHARDS, "shard ID is outside the frozen set")?;
    let total = mode.campaign_rows(kind);
    let quotient = total / SHARDS;
    let remainder = total % SHARDS;
    let start = shard
        .checked_mul(quotient)
        .and_then(|value| value.checked_add(shard.min(remainder)))
        .ok_or_else(|| invalid("shard start overflow"))?;
    let end = start
        .checked_add(quotient)
        .and_then(|value| value.checked_add(usize::from(shard < remainder)))
        .ok_or_else(|| invalid("shard end overflow"))?;
    Ok((start, end))
}

fn load_authenticated_shard(
    path: &Path,
    mode: Mode,
    kind: ProjectionKind,
    shard_start: usize,
    shard_end: usize,
) -> Result<Vec<(usize, ProjectionRow)>, DynError> {
    let metadata = std::fs::symlink_metadata(path)?;
    require(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.nlink() == 1
            && metadata.len() > 0
            && metadata.len() <= MAXIMUM_PROJECTION_BYTES,
        "projection is not one bounded unshared regular file",
    )?;
    let file = File::open(path)?;
    let held = file.metadata()?;
    require(
        (held.dev(), held.ino(), held.len()) == (metadata.dev(), metadata.ino(), metadata.len()),
        "projection descriptor identity changed",
    )?;
    let mut reader = BufReader::new(file);
    let mut digest = Sha256::new();
    digest.update(kind.domain());
    let mut encoded = Vec::with_capacity(MAXIMUM_ROW_BYTES + 1);
    let mut rows = 0_usize;
    let capacity = shard_end
        .checked_sub(shard_start)
        .ok_or_else(|| invalid("shard interval underflow"))?;
    let mut selected = Vec::with_capacity(capacity);
    loop {
        encoded.clear();
        let bytes = reader.read_until(b'\n', &mut encoded)?;
        if bytes == 0 {
            break;
        }
        require(
            encoded.last() == Some(&b'\n')
                && encoded.len() > 1
                && encoded.len() <= MAXIMUM_ROW_BYTES + 1,
            "projection framing changed",
        )?;
        digest.update(u64::try_from(encoded.len())?.to_le_bytes());
        digest.update(&encoded);
        if kind == ProjectionKind::Diagnostic {
            let local = selected
                .len()
                .checked_add(shard_start)
                .ok_or_else(|| invalid("diagnostic local ordinal overflow"))?;
            if local < shard_end && DIAGNOSTIC_ORDINALS[local] == rows {
                let row: ProjectionRow = serde_json::from_slice(&encoded)?;
                require(
                    row.row_sha256 == DIAGNOSTIC_ROW_SHA256S[local],
                    "diagnostic source row identity changed",
                )?;
                selected.push((rows, row));
            }
        } else if (shard_start..shard_end).contains(&rows) {
            let row: ProjectionRow = serde_json::from_slice(&encoded)?;
            selected.push((rows, row));
        }
        rows = rows
            .checked_add(1)
            .ok_or_else(|| invalid("projection row count overflow"))?;
    }
    let after = reader.get_ref().metadata()?;
    require(
        (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime_nsec(),
            after.ctime_nsec(),
        ) == (
            held.dev(),
            held.ino(),
            held.len(),
            held.mtime_nsec(),
            held.ctime_nsec(),
        ),
        "projection changed while held",
    )?;
    let actual: [u8; 32] = digest.finalize().into();
    require(
        rows == mode.projection_rows(kind)
            && hex(&actual) == mode.projection_sha256(kind)
            && selected.len() == capacity,
        "projection identity or shard membership changed",
    )?;
    Ok(selected)
}

fn candidate_indices() -> Result<HashMap<&'static str, usize>, io::Error> {
    require(
        generated::CANDIDATES.len() == EXPECTED_CANDIDATES,
        "linked candidate count changed",
    )?;
    let mut result = HashMap::with_capacity(generated::CANDIDATES.len());
    for (index, candidate) in generated::CANDIDATES.iter().enumerate() {
        require(
            result.insert(candidate.literal_hex, index).is_none(),
            "linked candidate literal is duplicated",
        )?;
    }
    Ok(result)
}

fn engine_for<'a>(
    engines: &'a mut HashMap<String, Engine>,
    candidate_indices: &HashMap<&str, usize>,
    row: &ProjectionRow,
) -> Result<&'a Engine, DynError> {
    match engines.entry(row.literal_hex.clone()) {
        Entry::Occupied(entry) => Ok(entry.into_mut()),
        Entry::Vacant(entry) => {
            let literal = decode_hex(&row.literal_hex)?;
            let portable = PortableBuilder::new(canonical_exact_source(&literal)).build()?;
            let exact = portable
                .exact_literal_search_aot_candidate()
                .ok_or_else(|| invalid("portable source is not one exact literal"))?;
            require(
                exact.literal() == literal && sha256_hex(exact.literal()) == row.literal_sha256,
                "portable literal identity changed",
            )?;
            let verified = if row.selector_eligible {
                let index = *candidate_indices
                    .get(row.literal_hex.as_str())
                    .ok_or_else(|| invalid("eligible literal is not linked"))?;
                Some(adopt(index)?)
            } else {
                require(
                    !candidate_indices.contains_key(row.literal_hex.as_str()),
                    "ineligible literal is linked",
                )?;
                None
            };
            Ok(entry.insert(Engine { portable, verified }))
        }
    }
}

#[allow(
    unsafe_code,
    reason = "generated glue selectors are receipt-bound and independently validated by the static runtime"
)]
fn adopt(index: usize) -> Result<&'static VerifiedStaticSearchSpanV1, DynError> {
    // SAFETY: invoke selects one generated retained glue symbol; the runtime
    // validates the family before resolving a registry-owned handle.
    let verified = unsafe {
        adopt_linked_static_search_span_family_qualification_v1(
            |output: *mut RawStaticSearchSpanAdoptionOutputV1| generated::invoke(index, output),
        )
    }?;
    require(
        verified.row_selector() == generated::FAMILY_SELECTOR && verified.backend_version() == 30,
        "adopted tag30 family identity changed",
    )?;
    Ok(verified)
}

const fn universal_direct_route_expected(selector_eligible: bool, window_bytes: usize) -> bool {
    selector_eligible && window_bytes >= UNIVERSAL_DIRECT_MINIMUM_WINDOW_BYTES
}

fn validate_row(kind: ProjectionKind, row: &ProjectionRow) -> Result<(), io::Error> {
    require(row.schema == kind.row_schema(), "projection schema changed")?;
    let universal_contract = row.fixture_recipe.construction_version
        == "near-miss-sentinel-tile-tail-v1"
        && row.fixture_recipe.scalar_oracle_required
        && row.literal_bytes == row.literal_hex.len() / 2
        && (4..=32).contains(&row.literal_bytes)
        && row.fixture_recipe.window_start == row.logical_prefix_bytes
        && row.fixture_recipe.window_end == row.logical_prefix_bytes + row.window_bytes
        && row.fixture_recipe.true_literal_guard_bytes + 1 == row.literal_bytes
        && row.expected_physical_window_start_mod16 < 16
        && row.expected_compiler_disposition
            == if row.selector_eligible {
                "tag30-object"
            } else {
                "structural-refusal"
            };
    require(universal_contract, "projection row contract changed")?;
    match kind {
        ProjectionKind::Universal => require(
            row.parent_schema.is_none()
                && row.expected_static_invoked == (row.expected_route == "tag30-static-tail")
                && row.expected_static_invoked
                    == universal_direct_route_expected(row.selector_eligible, row.window_bytes),
            "universal tag30 route changed",
        ),
        ProjectionKind::LongPolicy | ProjectionKind::Diagnostic => {
            let production_eligible =
                row.selector_eligible && row.window_bytes >= PRODUCTION_INPUT_FLOOR;
            require(
                row.parent_schema.as_deref() == Some(UNIVERSAL_ROW_SCHEMA)
                    && row.parent_row_sha256.as_deref().is_some_and(is_hex64)
                    && row.parent_expected_route.is_some()
                    && row.production_input_floor_bytes == Some(PRODUCTION_INPUT_FLOOR)
                    && row.production_eligible == Some(production_eligible)
                    && row.expected_static_invoked == production_eligible
                    && row.expected_route
                        == if production_eligible {
                            "tag30-static-tail"
                        } else {
                            "portable-only"
                        },
                "derived long-policy route changed",
            )
        }
    }
}

fn materialize(row: &ProjectionRow) -> Result<Fixture, DynError> {
    let literal = decode_hex(&row.literal_hex)?;
    let tile = decode_hex(&row.fixture_recipe.near_miss_tile_hex)?;
    require(
        tile.len() == literal.len() + 1 && tile.last() == Some(&row.fixture_recipe.background_byte),
        "fixture tile changed",
    )?;
    let window_start = row.fixture_recipe.window_start;
    let window_end = row.fixture_recipe.window_end;
    let mut storage = if row.right_guarded {
        guarded_storage(window_end)?
    } else {
        padded_storage(
            window_start,
            window_end,
            row.expected_physical_window_start_mod16,
        )?
    };
    let haystack = storage.haystack_mut();
    haystack.fill(row.fixture_recipe.background_byte);
    for (offset, byte) in haystack[window_start..window_end].iter_mut().enumerate() {
        *byte = tile[offset % tile.len()];
    }
    if row.outcome == "tail-hit" {
        let final_start = window_end
            .checked_sub(literal.len())
            .ok_or_else(|| invalid("literal wider than fixture window"))?;
        let guard_start = final_start
            .saturating_sub(row.fixture_recipe.true_literal_guard_bytes)
            .max(window_start);
        haystack[guard_start..final_start].fill(row.fixture_recipe.background_byte);
        haystack[final_start..window_end].copy_from_slice(&literal);
    } else {
        require(row.outcome == "absent", "fixture outcome changed")?;
    }
    let actual_mod = (haystack.as_ptr() as usize + window_start) % 16;
    require(
        actual_mod == row.expected_physical_window_start_mod16,
        "fixture physical alignment changed",
    )?;
    let scalar = scalar_find(&haystack[window_start..window_end], &literal)
        .map(|offset| [window_start + offset, window_start + offset + literal.len()]);
    require(
        scalar == expected_match(row),
        "fixture scalar oracle mismatch",
    )?;
    Ok(Fixture {
        storage,
        window: SearchWindow::new(window_start, window_end),
    })
}

fn padded_storage(
    window_start: usize,
    window_end: usize,
    expected_mod16: usize,
) -> Result<FixtureStorage, io::Error> {
    let haystack_bytes = window_end
        .checked_add(32)
        .ok_or_else(|| invalid("padded fixture extent overflow"))?;
    let allocation_bytes = haystack_bytes
        .checked_add(64)
        .ok_or_else(|| invalid("padded allocation overflow"))?;
    let bytes = vec![0_u8; allocation_bytes];
    let base = bytes.as_ptr() as usize;
    let desired_base_mod = (expected_mod16 + 16 - window_start % 16) % 16;
    let haystack_start = 32 + (desired_base_mod + 16 - base % 16) % 16;
    require(
        haystack_start.checked_add(haystack_bytes) <= Some(bytes.len()),
        "padded fixture extent changed",
    )?;
    Ok(FixtureStorage::Padded {
        bytes,
        haystack_start,
        haystack_bytes,
    })
}

fn guarded_storage(haystack_bytes: usize) -> Result<FixtureStorage, io::Error> {
    require(haystack_bytes > 0, "guarded fixture is empty")?;
    // SAFETY: sysconf has no memory-safety precondition.
    let raw_page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page_bytes =
        usize::try_from(raw_page).map_err(|_| invalid("page size is not representable"))?;
    require(
        page_bytes.is_power_of_two() && page_bytes >= 4_096,
        "unsupported page size",
    )?;
    let accessible_bytes = haystack_bytes
        .checked_add(page_bytes - 1)
        .map(|value| value & !(page_bytes - 1))
        .ok_or_else(|| invalid("guarded accessible extent overflow"))?;
    let mapping_bytes = accessible_bytes
        .checked_add(page_bytes)
        .ok_or_else(|| invalid("guarded mapping extent overflow"))?;
    // SAFETY: one private anonymous mapping is requested with a validated
    // nonzero extent; MAP_FAILED is rejected before pointer construction.
    let raw = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            mapping_bytes,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if raw == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    let mapping = NonNull::new(raw).ok_or_else(|| invalid("mmap returned null"))?;
    // SAFETY: accessible_bytes is inside the newly allocated mapping.
    let guard_raw = unsafe { mapping.as_ptr().cast::<u8>().add(accessible_bytes) }.cast();
    // SAFETY: the final page is page aligned and lies wholly in the mapping.
    if unsafe { libc::mprotect(guard_raw, page_bytes, libc::PROT_NONE) } != 0 {
        let error = io::Error::last_os_error();
        // SAFETY: release the exact successful mapping after mprotect failure.
        let _ = unsafe { libc::munmap(mapping.as_ptr(), mapping_bytes) };
        return Err(error);
    }
    require(!guard_raw.is_null(), "guard page pointer is null")?;
    // SAFETY: haystack_bytes <= accessible_bytes, so subtraction remains in
    // the accessible mapping and ends exactly at the guard.
    let haystack_raw = unsafe {
        mapping
            .as_ptr()
            .cast::<u8>()
            .add(accessible_bytes - haystack_bytes)
    };
    let haystack = NonNull::new(haystack_raw).ok_or_else(|| invalid("haystack pointer is null"))?;
    Ok(FixtureStorage::Guarded {
        mapping,
        mapping_bytes,
        haystack,
        haystack_bytes,
        page_bytes,
    })
}

fn checked_start_mod16(fixture: &Fixture) -> usize {
    (fixture.haystack().as_ptr() as usize + fixture.window.start()) % 16
}

fn scalar_find(haystack: &[u8], literal: &[u8]) -> Option<usize> {
    haystack
        .windows(literal.len())
        .position(|candidate| candidate == literal)
}

fn expected_match(row: &ProjectionRow) -> Option<[usize; 2]> {
    row.expected_match_start
        .zip(row.expected_match_end)
        .map(|(start, end)| [start, end])
}

fn verify_pair(
    portable: &PortableRegex,
    candidate: &CandidateView<'_>,
    fixture: &Fixture,
    expected: Option<[usize; 2]>,
) -> Result<(), DynError> {
    let portable_match = portable
        .find_window(
            fixture.haystack(),
            fixture.window,
            SearchLimits::unlimited(),
        )?
        .0;
    let candidate_match = candidate.find_window(fixture.haystack(), fixture.window)?;
    require(
        project(portable_match) == expected && project(candidate_match) == expected,
        "paired correctness mismatch",
    )
    .map_err(Into::into)
}

fn calibrated_iterations(
    portable: &PortableRegex,
    candidate: &CandidateView<'_>,
    fixture: &Fixture,
    cpu: usize,
) -> Result<CalibrationReceipt, DynError> {
    let portable_pilots = pilot(
        || measure_portable(portable, fixture, 1, cpu),
        |iterations| measure_portable(portable, fixture, iterations, cpu),
    )?;
    let candidate_pilots = pilot(
        || measure_candidate(candidate, fixture, 1, cpu),
        |iterations| measure_candidate(candidate, fixture, iterations, cpu),
    )?;
    for measurement in portable_pilots.iter().chain(&candidate_pilots) {
        require_measurement_cpu(measurement, cpu)?;
    }
    let portable_iterations = scaled_anchor_iterations(CALIBRATION_TARGET_NS, &portable_pilots)?;
    let candidate_iterations = scaled_anchor_iterations(CALIBRATION_TARGET_NS, &candidate_pilots)?;
    Ok(CalibrationReceipt {
        portable_pilots,
        candidate_pilots,
        selected_iterations: portable_iterations.max(candidate_iterations),
    })
}

fn pilot(
    mut first: impl FnMut() -> Result<Measurement, DynError>,
    mut measure: impl FnMut(usize) -> Result<Measurement, DynError>,
) -> Result<Vec<Measurement>, DynError> {
    let mut result = first()?;
    let mut results = vec![result.clone()];
    let mut iterations = 1_usize;
    while result.elapsed_ns < CALIBRATION_FLOOR_NS && iterations < MAXIMUM_ITERATIONS {
        iterations = iterations
            .checked_mul(4)
            .unwrap_or(MAXIMUM_ITERATIONS)
            .min(MAXIMUM_ITERATIONS);
        result = measure(iterations)?;
        results.push(result.clone());
    }
    for _ in 1..CALIBRATION_ANCHOR_SAMPLES {
        results.push(measure(iterations)?);
    }
    Ok(results)
}

fn scaled_anchor_iterations(target_ns: u64, pilots: &[Measurement]) -> Result<usize, io::Error> {
    require(
        pilots.len() >= CALIBRATION_ANCHOR_SAMPLES,
        "calibration lacks frozen anchor samples",
    )?;
    let anchors = &pilots[pilots.len() - CALIBRATION_ANCHOR_SAMPLES..];
    let anchor_iterations = anchors[0].iterations;
    require(
        anchors
            .iter()
            .all(|measurement| measurement.iterations == anchor_iterations),
        "calibration anchor iterations changed",
    )?;
    anchors
        .iter()
        .map(|measurement| scaled_iterations(target_ns, measurement))
        .try_fold(1_usize, |selected, scaled| {
            scaled.map(|iterations| selected.max(iterations))
        })
}

fn scaled_iterations(target_ns: u64, pilot: &Measurement) -> Result<usize, io::Error> {
    require(pilot.elapsed_ns > 0, "zero-duration pilot")?;
    let numerator = u128::from(target_ns)
        .checked_mul(u128::try_from(pilot.iterations).map_err(|_| invalid("iteration overflow"))?)
        .and_then(|value| value.checked_add(u128::from(pilot.elapsed_ns) - 1))
        .ok_or_else(|| invalid("calibration overflow"))?;
    let iterations = numerator / u128::from(pilot.elapsed_ns);
    usize::try_from(iterations)
        .map(|value| value.clamp(1, MAXIMUM_ITERATIONS))
        .map_err(|_| invalid("calibrated iterations overflow"))
}

fn measure_portable(
    portable: &PortableRegex,
    fixture: &Fixture,
    iterations: usize,
    cpu: usize,
) -> Result<Measurement, DynError> {
    measure(iterations, cpu, || {
        portable
            .find_window(
                black_box(fixture.haystack()),
                fixture.window,
                SearchLimits::unlimited(),
            )
            .map(|result| result.0)
            .map_err(Into::into)
    })
}

fn measure_candidate(
    candidate: &CandidateView<'_>,
    fixture: &Fixture,
    iterations: usize,
    cpu: usize,
) -> Result<Measurement, DynError> {
    measure(iterations, cpu, || {
        candidate.find_window(black_box(fixture.haystack()), fixture.window)
    })
}

fn measure(
    iterations: usize,
    cpu: usize,
    mut invoke: impl FnMut() -> Result<Option<Match>, DynError>,
) -> Result<Measurement, DynError> {
    let maximum_retries = maximum_cpu_only_retries();
    let mut attempts = Vec::with_capacity(maximum_retries + 1);
    for _ in 0..=maximum_retries {
        wait_for_measurement_cpu(cpu)?;
        let mut checksum = CHECKSUM_SEED;
        let cpu_before = current_cpu()?;
        let start = Instant::now();
        for _ in 0..iterations {
            checksum = mix(checksum, encode(invoke()?));
        }
        let elapsed_ns = u64::try_from(start.elapsed().as_nanos())?;
        let cpu_after = current_cpu()?;
        let accepted = measurement_cpu_accepted(cpu_before, cpu_after, cpu);
        attempts.push(CpuAttempt {
            cpu_before,
            cpu_after,
            accepted,
        });
        if accepted {
            black_box(checksum);
            return Ok(Measurement {
                iterations,
                elapsed_ns,
                checksum,
                cpu_before,
                cpu_after,
                cpu_attempts: attempts,
            });
        }
    }
    Err(invalid("measured variant exhausted the frozen CPU-only retry bound").into())
}

fn require_measurement_cpu(measurement: &Measurement, expected: usize) -> Result<(), io::Error> {
    require(
        !measurement.cpu_attempts.is_empty()
            && measurement.cpu_attempts.len() <= maximum_cpu_only_retries() + 1
            && measurement
                .cpu_attempts
                .last()
                .is_some_and(|attempt| attempt.accepted)
            && measurement.cpu_attempts[..measurement.cpu_attempts.len() - 1]
                .iter()
                .all(|attempt| !attempt.accepted)
            && measurement_cpu_accepted(measurement.cpu_before, measurement.cpu_after, expected),
        "measured variant CPU receipt changed",
    )
}

fn cpu_attempt_receipts(measurement: &Measurement) -> Vec<Value> {
    measurement
        .cpu_attempts
        .iter()
        .enumerate()
        .map(|(attempt, receipt)| {
            json!({
                "attempt": attempt,
                "cpu_before": receipt.cpu_before,
                "cpu_after": receipt.cpu_after,
                "accepted": receipt.accepted,
            })
        })
        .collect()
}

fn calibration_measurement_receipt(measurement: &Measurement) -> Value {
    json!({
        "iterations": measurement.iterations,
        "elapsed_ns": measurement.elapsed_ns,
        "checksum": measurement.checksum,
        "cpu_before": measurement.cpu_before,
        "cpu_after": measurement.cpu_after,
        "cpu_retries": measurement.cpu_attempts.len() - 1,
        "cpu_attempts": cpu_attempt_receipts(measurement),
    })
}

fn calibration_receipt(calibration: &CalibrationReceipt) -> Value {
    json!({
        "target_elapsed_ns": CALIBRATION_TARGET_NS,
        "floor_elapsed_ns": CALIBRATION_FLOOR_NS,
        "anchor_samples": CALIBRATION_ANCHOR_SAMPLES,
        "maximum_iterations": MAXIMUM_ITERATIONS,
        "selected_iterations": calibration.selected_iterations,
        "portable_pilots": calibration
            .portable_pilots
            .iter()
            .map(calibration_measurement_receipt)
            .collect::<Vec<_>>(),
        "candidate_pilots": calibration
            .candidate_pilots
            .iter()
            .map(calibration_measurement_receipt)
            .collect::<Vec<_>>(),
    })
}

#[cfg(target_os = "linux")]
fn pin_current_thread(cpu: usize) -> Result<CpuResidenceReceipt, io::Error> {
    require(
        cpu < libc::CPU_SETSIZE as usize,
        "logical CPU is out of range",
    )?;
    // SAFETY: cpu_set_t is a plain C bitset initialized before use.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    // SAFETY: cpu is checked against CPU_SETSIZE.
    unsafe {
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
    }
    // SAFETY: pid 0 names the current thread and set has the exact C extent.
    if unsafe {
        libc::sched_setaffinity(
            0,
            std::mem::size_of::<libc::cpu_set_t>(),
            std::ptr::from_ref(&set),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    require_current_cpu(cpu)?;
    Ok(CpuResidenceReceipt {
        method: "linux-sched-setaffinity-plus-samples",
        affinity_request_status: 0,
        qos_class: None,
        qos_request_status: None,
        accepted_cpu_class: "exact-requested",
        accepted_cpu_ids: vec![cpu],
        macos_performance_levels: None,
    })
}

#[cfg(target_os = "macos")]
fn pin_current_thread(cpu: usize) -> Result<CpuResidenceReceipt, io::Error> {
    #[repr(C)]
    struct ThreadAffinityPolicy {
        affinity_tag: i32,
    }
    const THREAD_AFFINITY_POLICY: i32 = 4;
    const QOS_CLASS_USER_INTERACTIVE_RAW: u32 = 0x21;
    unsafe extern "C" {
        fn mach_thread_self() -> u32;
        fn thread_policy_set(thread: u32, flavor: i32, policy_info: *const i32, count: u32) -> i32;
    }
    authenticate_macos_performance_levels()?;
    require(
        MACOS_SUPER_CPUS.contains(&cpu),
        "macOS worker label is outside the frozen Super set",
    )?;
    // SAFETY: the QoS class is a declared libc enum value and zero is the
    // documented relative priority for this class.
    let qos_status = unsafe {
        libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_USER_INTERACTIVE, 0)
    };
    if qos_status != 0 {
        return Err(io::Error::from_raw_os_error(qos_status));
    }
    let affinity_tag = i32::try_from(
        cpu.checked_add(1)
            .ok_or_else(|| invalid("affinity tag overflow"))?,
    )
    .map_err(|_| invalid("affinity tag is not representable"))?;
    let policy = ThreadAffinityPolicy { affinity_tag };
    // SAFETY: policy is one correctly laid-out integer and the Mach port is
    // the current thread. The affinity tag is a scheduling constraint; exact
    // CPU residence is separately sampled and enforced for every variant.
    let status = unsafe {
        thread_policy_set(
            mach_thread_self(),
            THREAD_AFFINITY_POLICY,
            std::ptr::from_ref(&policy).cast(),
            1,
        )
    };
    if !matches!(status, 0 | 46) {
        return Err(invalid(format!(
            "failed to install macOS thread affinity: Mach status {status}"
        )));
    }
    wait_for_measurement_cpu(cpu)?;
    Ok(CpuResidenceReceipt {
        method: "macos-user-interactive-qos-affinity-hint-bounded-super-wait-cpu-only-retry",
        affinity_request_status: status,
        qos_class: Some(QOS_CLASS_USER_INTERACTIVE_RAW),
        qos_request_status: Some(qos_status),
        accepted_cpu_class: "Super",
        accepted_cpu_ids: MACOS_SUPER_CPUS.to_vec(),
        macos_performance_levels: Some(macos_performance_level_receipt()),
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn pin_current_thread(_cpu: usize) -> Result<CpuResidenceReceipt, io::Error> {
    Err(invalid("qualification runner requires Linux or macOS"))
}

#[cfg(target_os = "macos")]
fn macos_sysctl_bytes(name: &'static [u8]) -> Result<Vec<u8>, io::Error> {
    require(
        name.last() == Some(&0),
        "macOS sysctl name is not NUL terminated",
    )?;
    let mut length = 0_usize;
    // SAFETY: name is NUL terminated; the first call requests the exact size.
    if unsafe {
        libc::sysctlbyname(
            name.as_ptr().cast(),
            std::ptr::null_mut(),
            std::ptr::from_mut(&mut length),
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    require(
        (1..=1 << 20).contains(&length),
        "macOS sysctl value has an invalid extent",
    )?;
    let mut bytes = vec![0_u8; length];
    // SAFETY: bytes has the exact extent returned by the size query.
    if unsafe {
        libc::sysctlbyname(
            name.as_ptr().cast(),
            bytes.as_mut_ptr().cast(),
            std::ptr::from_mut(&mut length),
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    bytes.truncate(length);
    Ok(bytes)
}

#[cfg(target_os = "macos")]
fn macos_sysctl_string(name: &'static [u8]) -> Result<String, io::Error> {
    let mut bytes = macos_sysctl_bytes(name)?;
    require(
        bytes.last() == Some(&0),
        "macOS string sysctl lacks NUL termination",
    )?;
    bytes.pop();
    String::from_utf8(bytes).map_err(|_| invalid("macOS string sysctl is not UTF-8"))
}

#[cfg(target_os = "macos")]
fn macos_sysctl_u64(name: &'static [u8]) -> Result<u64, io::Error> {
    let bytes = macos_sysctl_bytes(name)?;
    match bytes.len() {
        4 => Ok(u64::from(u32::from_ne_bytes(
            bytes.as_slice().try_into().expect("four-byte sysctl value"),
        ))),
        8 => Ok(u64::from_ne_bytes(
            bytes
                .as_slice()
                .try_into()
                .expect("eight-byte sysctl value"),
        )),
        _ => Err(invalid("macOS integer sysctl has an unexpected width")),
    }
}

#[cfg(target_os = "macos")]
fn authenticate_macos_performance_levels() -> Result<(), io::Error> {
    let exact_strings = [
        (b"machdep.cpu.brand_string\0".as_slice(), "Apple M5 Max"),
        (b"hw.model\0".as_slice(), "Mac17,7"),
        (b"hw.perflevel0.name\0".as_slice(), "Super"),
        (b"hw.perflevel1.name\0".as_slice(), "Performance"),
    ];
    for (name, expected) in exact_strings {
        require(
            macos_sysctl_string(name)? == expected,
            "macOS machine or performance-level name changed",
        )?;
    }
    let exact_integers = [
        (b"hw.nperflevels\0".as_slice(), 2),
        (b"hw.perflevel0.physicalcpu\0".as_slice(), 6),
        (b"hw.perflevel0.logicalcpu\0".as_slice(), 6),
        (b"hw.perflevel0.cpusperl2\0".as_slice(), 6),
        (b"hw.perflevel0.l1dcachesize\0".as_slice(), 131_072),
        (b"hw.perflevel0.l2cachesize\0".as_slice(), 16_777_216),
        (b"hw.perflevel1.physicalcpu\0".as_slice(), 12),
        (b"hw.perflevel1.logicalcpu\0".as_slice(), 12),
        (b"hw.perflevel1.cpusperl2\0".as_slice(), 6),
        (b"hw.perflevel1.l1dcachesize\0".as_slice(), 65_536),
        (b"hw.perflevel1.l2cachesize\0".as_slice(), 8_388_608),
    ];
    for (name, expected) in exact_integers {
        require(
            macos_sysctl_u64(name)? == expected,
            "macOS performance-level tuple changed",
        )?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_performance_level_receipt() -> Value {
    json!({
        "machine_model": "Mac17,7",
        "chip": "Apple M5 Max",
        "mapping_authority": "ioreg-cluster-type-logical-cluster-plus-sysctl",
        "levels": [
            {
                "index": 0,
                "name": "Super",
                "physical_cpus": 6,
                "logical_cpus": 6,
                "cpus_per_l2": 6,
                "l1_data_cache_bytes": 131_072,
                "l2_cache_bytes": 16_777_216,
                "logical_cpu_ids": MACOS_SUPER_CPUS,
            },
            {
                "index": 1,
                "name": "Performance",
                "physical_cpus": 12,
                "logical_cpus": 12,
                "cpus_per_l2": 6,
                "l1_data_cache_bytes": 65_536,
                "l2_cache_bytes": 8_388_608,
                "logical_cpu_ids": MACOS_PERFORMANCE_CPUS,
            },
        ],
    })
}

#[cfg(target_os = "linux")]
fn current_cpu() -> Result<usize, io::Error> {
    // SAFETY: sched_getcpu has no pointer arguments or preconditions.
    let cpu = unsafe { libc::sched_getcpu() };
    usize::try_from(cpu).map_err(|_| io::Error::last_os_error())
}

#[cfg(target_os = "macos")]
fn current_cpu() -> Result<usize, io::Error> {
    unsafe extern "C" {
        fn pthread_cpu_number_np(cpu_number_out: *mut usize) -> i32;
    }
    let mut cpu = 0_usize;
    // SAFETY: cpu is a live writable output word for the duration of the call.
    let status = unsafe { pthread_cpu_number_np(std::ptr::from_mut(&mut cpu)) };
    if status == 0 {
        Ok(cpu)
    } else {
        Err(io::Error::from_raw_os_error(status))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn current_cpu() -> Result<usize, io::Error> {
    Err(invalid("qualification runner requires Linux or macOS"))
}

#[cfg(target_os = "linux")]
const fn measurement_cpu_accepted(cpu_before: usize, cpu_after: usize, expected: usize) -> bool {
    cpu_before == expected && cpu_after == expected
}

#[cfg(target_os = "macos")]
fn measurement_cpu_accepted(cpu_before: usize, cpu_after: usize, expected: usize) -> bool {
    MACOS_SUPER_CPUS.contains(&expected)
        && MACOS_SUPER_CPUS.contains(&cpu_before)
        && MACOS_SUPER_CPUS.contains(&cpu_after)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const fn measurement_cpu_accepted(_cpu_before: usize, _cpu_after: usize, _expected: usize) -> bool {
    false
}

#[cfg(target_os = "macos")]
const fn maximum_cpu_only_retries() -> usize {
    MAXIMUM_CPU_ONLY_RETRIES
}

#[cfg(target_os = "macos")]
const fn macos_super_class_wait_timeout_ns() -> Option<u64> {
    Some(MACOS_SUPER_CLASS_WAIT_TIMEOUT_NS)
}

#[cfg(not(target_os = "macos"))]
const fn maximum_cpu_only_retries() -> usize {
    0
}

#[cfg(not(target_os = "macos"))]
const fn macos_super_class_wait_timeout_ns() -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn wait_for_measurement_cpu(expected: usize) -> Result<(), io::Error> {
    require_current_cpu(expected)
}

#[cfg(target_os = "macos")]
fn wait_for_measurement_cpu(expected: usize) -> Result<(), io::Error> {
    require(
        MACOS_SUPER_CPUS.contains(&expected),
        "macOS worker label is outside the frozen Super set",
    )?;
    let start = Instant::now();
    loop {
        if MACOS_SUPER_CPUS.contains(&current_cpu()?) {
            return Ok(());
        }
        if start.elapsed().as_nanos() >= u128::from(MACOS_SUPER_CLASS_WAIT_TIMEOUT_NS) {
            break;
        }
        std::thread::yield_now();
    }
    Err(invalid(
        "worker did not reach the authenticated macOS Super class",
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn wait_for_measurement_cpu(_expected: usize) -> Result<(), io::Error> {
    Err(invalid("qualification runner requires Linux or macOS"))
}

#[cfg(target_os = "linux")]
fn require_current_cpu(expected: usize) -> Result<(), io::Error> {
    let actual = current_cpu()?;
    require(
        measurement_cpu_accepted(actual, actual, expected),
        "worker is outside its authenticated CPU residence",
    )
}

const fn mix(checksum: u64, value: u64) -> u64 {
    checksum.rotate_left(9) ^ value.wrapping_mul(0x9e37_79b9_7f4a_7c15)
}

fn encode(matched: Option<Match>) -> u64 {
    matched.map_or(u64::MAX, |value| {
        u64::try_from(value.start())
            .unwrap_or(u64::MAX)
            .rotate_left(17)
            ^ u64::try_from(value.end()).unwrap_or(u64::MAX)
    })
}

fn project(matched: Option<Match>) -> Option<[usize; 2]> {
    matched.map(|value| [value.start(), value.end()])
}

fn canonical_exact_source(literal: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut source = String::with_capacity(6 + literal.len() * 4);
    source.push_str("(?-u:");
    for byte in literal {
        write!(source, "\\x{byte:02x}").expect("String formatting");
    }
    source.push(')');
    source
}

fn decode_hex(value: &str) -> Result<Vec<u8>, io::Error> {
    require(
        !value.is_empty()
            && value.len().is_multiple_of(2)
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "hex input is not canonical lowercase",
    )?;
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| invalid("hex input is not UTF-8"))?;
            u8::from_str_radix(text, 16).map_err(|_| invalid("hex input is malformed"))
        })
        .collect()
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    hex(&digest)
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(output, "{byte:02x}").expect("String formatting");
    }
    output
}

fn write_json_line(writer: &mut impl io::Write, value: &Value) -> Result<(), DynError> {
    serde_json::to_writer(&mut *writer, value)?;
    writer.write_all(b"\n")?;
    Ok(())
}

fn require(condition: bool, message: &str) -> Result<(), io::Error> {
    if condition {
        Ok(())
    } else {
        Err(invalid(message))
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_shards_are_exact_partitions() {
        for mode in [Mode::Correctness, Mode::Timing] {
            for kind in [
                ProjectionKind::Universal,
                ProjectionKind::LongPolicy,
                ProjectionKind::Diagnostic,
            ] {
                if mode == Mode::Correctness && kind == ProjectionKind::Diagnostic {
                    continue;
                }
                let mut cursor = 0;
                for shard in 0..SHARDS {
                    let (start, end) = shard_bounds(mode, kind, shard).unwrap();
                    assert_eq!(start, cursor);
                    assert!(end > start);
                    cursor = end;
                }
                assert_eq!(cursor, mode.campaign_rows(kind));
            }
        }
    }

    #[test]
    fn frozen_projection_identities_are_distinct() {
        assert_ne!(UNIVERSAL_FULL_SHA256, LONG_FULL_SHA256);
        assert_ne!(UNIVERSAL_TIMED_SHA256, LONG_TIMED_SHA256);
        assert_ne!(UNIVERSAL_PROJECTION_DOMAIN, LONG_PROJECTION_DOMAIN);
        assert_eq!(
            ProjectionKind::LongPolicy.expected_route_counts(),
            (23_328, 100_096)
        );
    }

    #[test]
    fn universal_direct_route_has_the_frozen_mechanism_floor() {
        assert!(!universal_direct_route_expected(true, 4_092));
        assert!(universal_direct_route_expected(true, 4_093));
        assert!(!universal_direct_route_expected(false, usize::MAX));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn current_cpu_and_host_affinity_contract() {
        let cpu = current_cpu().unwrap();
        pin_current_thread(cpu).unwrap();
        assert_eq!(current_cpu().unwrap(), cpu);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn current_cpu_and_host_affinity_contract() {
        pin_current_thread(MACOS_SUPER_CPUS[0]).unwrap();
        let cpu = current_cpu().unwrap();
        assert!(MACOS_SUPER_CPUS.contains(&cpu));
        authenticate_macos_performance_levels().unwrap();
    }
}
