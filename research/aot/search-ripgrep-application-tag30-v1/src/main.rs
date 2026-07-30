#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::too_many_lines,
    unsafe_code,
    reason = "the sealed application harness keeps fixture geometry, linked-object adoption, CPU checks, and paired timing linear and auditable"
)]

use std::{
    collections::{HashMap, hash_map::Entry},
    error::Error,
    fs::{File, OpenOptions},
    hint::black_box,
    io::{self, BufRead as _, BufReader, BufWriter, Read as _, Write as _},
    os::unix::fs::MetadataExt as _,
    path::Path,
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
use serde_json::{Map, Value, json};
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

const CONTRACT_SCHEMA: &str = "fre.aot.search-tag30-ripgrep-application-contract.v1";
const CONTRACT_SHA256: &str = "c52132527ffa184c0efceb66f4b1eb4a4b19b964c48d58d989520b8a1a906da5";
const PROJECTION_SCHEMA: &str = "fre.aot.search-tag30-ripgrep-application-projection-row.v1";
const PROJECTION_DOMAIN: &[u8] = b"FRE-SEARCH-TAG30-RIPGREP-APPLICATION-PROJECTION\0\x01";
const PROJECTION_ROWS: usize = 154;
const PROJECTION_SHA256: &str = "1ea6896b7d89bb812130d6f6c4b743d9eed79169c0154f0b6bb37686576b9332";
const PROJECTION_FILE_SHA256: &str =
    "d53ab752f7fc7b16e14e9989a08e4780a2a6865ace451efb9d1a14019040aa77";
const FIXTURE_MANIFEST_SHA256: &str =
    "b20181470c604d01d2ec236259293cfcb6e5eff145bcd3e4daa91554c8cebcca";
const OBJECT_MANIFEST_SHA256: &str =
    "ec4e1cf7bbd70f99dc0675b6e3fd47b2da9034753d4f5a1a836206c5756ed0b6";
const DISPOSITIONS_SHA256: &str =
    "433029525cfb74122f275f4282901fc6e7711b34aa7115b4bd53ef537dd5e1a1";
const BUILD_RECEIPT_SCHEMA: &str =
    "fre.aot.search-tag30-ripgrep-application-runner-build-receipt.v1";
const FRAGMENT_HEADER_SCHEMA: &str = "fre.aot.search-tag30-ripgrep-application-fragment-header.v1";
const CORRECTNESS_ROW_SCHEMA: &str = "fre.aot.search-tag30-ripgrep-application-correctness-row.v1";
const TIMING_ROW_SCHEMA: &str = "fre.aot.search-tag30-ripgrep-application-timing-row.v1";
const FRAGMENT_TRAILER_SCHEMA: &str =
    "fre.aot.search-tag30-ripgrep-application-fragment-trailer.v1";
const SUMMARY_SCHEMA: &str = "fre.aot.search-tag30-ripgrep-application-shard-summary.v1";
const EXPECTED_CANDIDATES: usize = 5;
const SHARDS: usize = 16;
const REPETITIONS: usize = 6;
const MINIMUM_ELAPSED_NS: u64 = 400_000_000;
const CALIBRATION_TARGET_NS: u64 = 500_000_000;
const CALIBRATION_FLOOR_NS: u64 = 100_000;
const MAXIMUM_ITERATIONS: usize = 1 << 30;
const MAXIMUM_ROW_BYTES: usize = 32 * 1024;
const MAXIMUM_PROJECTION_BYTES: u64 = 1 << 20;
const MAXIMUM_CONTRACT_BYTES: u64 = 128 * 1024;
const MAXIMUM_BUILD_RECEIPT_BYTES: u64 = 4 * 1024 * 1024;
const MAXIMUM_FIXTURE_BYTES: u64 = 2 * 1024 * 1024;
const CHECKSUM_SEED: u64 = 0x6a09_e667_f3bc_c909;
const ALLOCATION_DOMAIN: &[u8] = b"FRE-SEARCH-TAG30-RIPGREP-APPLICATION-ALLOCATION\0\x01";
#[cfg(target_os = "macos")]
const EXPECTED_HOST: &str = "local-apple-aarch64-asimd";
#[cfg(target_os = "linux")]
const EXPECTED_HOST: &str = "zstd-eval-c9g-neoverse-v3-aarch64-asimd";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Correctness,
    Timing,
}

impl Mode {
    fn parse(value: &str) -> Result<Self, io::Error> {
        match value {
            "correctness" => Ok(Self::Correctness),
            "timing" => Ok(Self::Timing),
            _ => Err(invalid("mode must be correctness or timing")),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Correctness => "correctness",
            Self::Timing => "timing",
        }
    }
}

#[allow(
    clippy::struct_excessive_bools,
    reason = "the projection deliberately retains independent frozen selector, route, and authority booleans"
)]
#[derive(Clone, Debug, Deserialize)]
struct ProjectionRow {
    schema: String,
    row_sha256: String,
    ordinal: usize,
    case_id: String,
    candidate_sha256: String,
    literal_hex: String,
    literal_sha256: String,
    literal_bytes: usize,
    scenario: String,
    fixture_path: String,
    fixture_sha256: String,
    fixture_bytes: usize,
    alignment_offset: usize,
    padding_sentinel: u8,
    expected_span: Option<[usize; 2]>,
    expected_nonoverlapping_count: usize,
    selector_eligible: bool,
    selected_offsets: Vec<usize>,
    expected_compiler_disposition: String,
    route_class: String,
    expected_static_invoked: bool,
    rebar_accepted_as_input: bool,
    result_derived_exclusion: bool,
}

#[derive(Debug)]
struct Engine {
    portable: PortableRegex,
    verified: Option<&'static VerifiedStaticSearchSpanV1>,
}

#[derive(Debug)]
struct Fixture {
    storage: Vec<u8>,
    start: usize,
    bytes: usize,
    receipt: Value,
}

impl Fixture {
    fn haystack(&self) -> &[u8] {
        &self.storage[self.start..self.start + self.bytes]
    }
}

enum CandidateView<'a> {
    Portable(&'a PortableRegex),
    Automatic(SearchExactLiteralAutoAotV1<'a>),
}

impl CandidateView<'_> {
    fn find(&self, haystack: &[u8]) -> Result<Option<Match>, DynError> {
        let window = SearchWindow::new(0, haystack.len());
        match self {
            Self::Portable(portable) => Ok(portable
                .find_window(haystack, window, SearchLimits::unlimited())?
                .0),
            Self::Automatic(automatic) => Ok(automatic
                .find_window(haystack, window, SearchLimits::unlimited())?
                .0),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Measurement {
    iterations: usize,
    elapsed_ns: u64,
    checksum: u64,
    cpu_before: usize,
    cpu_after: usize,
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
        Ok(())
    }
}

fn main() -> Result<(), DynError> {
    validate_linked_build()?;
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let [
        mode,
        contract,
        projection,
        fixture_root,
        build_receipt,
        shard,
        host,
        cpu,
        output,
    ] = arguments.as_slice()
    else {
        return Err(invalid(
            "usage: (correctness|timing) CONTRACT PROJECTION FIXTURE_ROOT BUILD_RECEIPT SHARD_ID HOST_ID CPU_ID NEW_OUTPUT",
        )
        .into());
    };
    run(
        Mode::parse(mode)?,
        Path::new(contract),
        Path::new(projection),
        Path::new(fixture_root),
        Path::new(build_receipt),
        shard.parse()?,
        host,
        cpu.parse()?,
        Path::new(output),
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "all campaign-bound inputs remain explicit at the runner boundary"
)]
fn run(
    mode: Mode,
    contract: &Path,
    projection: &Path,
    fixture_root: &Path,
    build_receipt: &Path,
    shard: usize,
    host: &str,
    cpu: usize,
    output: &Path,
) -> Result<(), DynError> {
    authenticate_contract(contract)?;
    require(
        host == EXPECTED_HOST,
        "host ID does not match runner target",
    )?;
    require(shard < SHARDS, "shard ID is outside the frozen set")?;
    if mode == Mode::Timing {
        require(
            generated::TIMING_PERMITTED,
            "linked identity does not permit application timing",
        )?;
    }
    let build_receipt_sha256 = authenticate_build_receipt(build_receipt)?;
    pin_current_thread(cpu)?;
    let (shard_start, shard_end) = shard_bounds(shard)?;
    let rows = load_projection_shard(projection, shard_start, shard_end)?;
    let header = json!({
        "schema": FRAGMENT_HEADER_SCHEMA,
        "mode": mode.name(),
        "contract_schema": CONTRACT_SCHEMA,
        "contract_sha256": CONTRACT_SHA256,
        "projection_schema": PROJECTION_SCHEMA,
        "projection_rows": PROJECTION_ROWS,
        "projection_sha256": PROJECTION_SHA256,
        "projection_file_sha256": PROJECTION_FILE_SHA256,
        "shard_id": shard,
        "shard_start": shard_start,
        "shard_end": shard_end,
        "host_id": host,
        "logical_cpu": cpu,
        "runner_binary_sha256": current_binary_sha256()?,
        "runner_source_sha256": generated::RUNNER_SOURCE_SHA256,
        "runner_identity_sha256": generated::IDENTITY_SHA256,
        "build_receipt_sha256": build_receipt_sha256,
        "object_manifest_sha256": generated::OBJECT_CANDIDATE_MANIFEST_SHA256,
        "literal_dispositions_sha256": generated::LITERAL_DISPOSITIONS_SHA256,
        "fixture_manifest_sha256": generated::FIXTURE_MANIFEST_SHA256,
        "backend_tag": generated::BACKEND_TAG,
        "backend_name": generated::BACKEND_NAME,
        "family_selector": generated::FAMILY_SELECTOR,
        "minimum_window_bytes": generated::MINIMUM_WINDOW_BYTES,
        "portable_prefix_candidate_starts": generated::PORTABLE_PREFIX_CANDIDATE_STARTS,
        "plan_identity": generated::PLAN_IDENTITY,
        "analyzer_identity": generated::ANALYZER_IDENTITY,
        "evidence_identity": generated::EVIDENCE_IDENTITY,
        "private_family_authorization_identity": generated::PRIVATE_AUTHORIZATION_IDENTITY,
        "application_contract_identity": generated::APPLICATION_CONTRACT_IDENTITY,
        "timing_repetitions": if mode == Mode::Timing { Some(REPETITIONS) } else { None },
        "minimum_elapsed_ns_each_variant": if mode == Mode::Timing {
            Some(MINIMUM_ELAPSED_NS)
        } else {
            None
        },
        "production_authority": false,
        "rebar_accepted_as_input": false,
        "heldout_materialized": false,
        "result_derived_exclusions": false,
    });
    let fragment = FragmentWriter::create(output, &header)?;
    match mode {
        Mode::Correctness => {
            correctness_rows(rows, fixture_root, fragment, shard_start, shard_end, cpu)?;
        }
        Mode::Timing => {
            timing_rows(rows, fixture_root, fragment, shard_start, shard_end, cpu)?;
        }
    }
    println!(
        "{}",
        serde_json::to_string(&json!({
            "schema": SUMMARY_SCHEMA,
            "mode": mode.name(),
            "shard_id": shard,
            "shard_start": shard_start,
            "shard_end": shard_end,
            "host_id": host,
            "logical_cpu": cpu,
            "output": output,
            "complete": true,
            "production_authority": false,
            "rebar_accepted_as_input": false,
        }))?
    );
    Ok(())
}

fn correctness_rows(
    rows: Vec<ProjectionRow>,
    fixture_root: &Path,
    mut fragment: FragmentWriter,
    shard_start: usize,
    shard_end: usize,
    cpu: usize,
) -> Result<(), DynError> {
    let candidate_indices = candidate_indices()?;
    let mut engines = HashMap::new();
    for row in rows {
        validate_row(&row)?;
        let fixture = load_fixture(fixture_root, &row)?;
        let literal = decode_hex(&row.literal_hex)?;
        let (scalar_span, scalar_count) = scalar_nonoverlapping(fixture.haystack(), &literal);
        require(
            scalar_span == row.expected_span && scalar_count == row.expected_nonoverlapping_count,
            "scalar fixture oracle changed",
        )?;
        let engine = engine_for(
            &mut engines,
            &candidate_indices,
            &row.literal_hex,
            &row.literal_sha256,
            row.selector_eligible,
        )?;
        let portable = engine
            .portable
            .find_window(
                fixture.haystack(),
                SearchWindow::new(0, fixture.bytes),
                SearchLimits::unlimited(),
            )?
            .0;
        require(
            project(portable) == row.expected_span,
            "portable span changed",
        )?;

        let (candidate, direct_tail) = if row.selector_eligible {
            let verified = engine
                .verified
                .ok_or_else(|| invalid("eligible literal lacks static object"))?;
            let automatic = SearchExactLiteralAutoAotV1::bind(&engine.portable, verified)?;
            verify_policy(&automatic)?;
            let candidate = automatic
                .find_window(
                    fixture.haystack(),
                    SearchWindow::new(0, fixture.bytes),
                    SearchLimits::unlimited(),
                )?
                .0;
            let direct_tail = if row.route_class == "tag30-static-tail" {
                verify_static_tail(&engine.portable, verified, fixture.haystack(), &row)?
            } else {
                require(
                    row.route_class == "portable-prefix-return",
                    "eligible route changed",
                )?;
                verify_prefix_return(&engine.portable, fixture.haystack(), &row)?;
                None
            };
            (candidate, direct_tail)
        } else {
            require(
                engine.verified.is_none() && row.route_class == "full-portable-fallback",
                "refused literal acquired a static route",
            )?;
            (portable, None)
        };
        require(
            project(candidate) == row.expected_span,
            "candidate span changed",
        )?;
        require_current_cpu(cpu)?;
        fragment.record(&json!({
            "schema": CORRECTNESS_ROW_SCHEMA,
            "ordinal": row.ordinal,
            "row_sha256": row.row_sha256,
            "case_id": row.case_id,
            "candidate_sha256": row.candidate_sha256,
            "literal_sha256": row.literal_sha256,
            "fixture_sha256": row.fixture_sha256,
            "scenario": row.scenario,
            "compiler_disposition": row.expected_compiler_disposition,
            "route_class": row.route_class,
            "expected_static_invoked": row.expected_static_invoked,
            "portable_span": project(portable),
            "candidate_span": project(candidate),
            "direct_tail_span": direct_tail,
            "scalar_span": scalar_span,
            "scalar_nonoverlapping_count": scalar_count,
            "mapping": fixture.receipt,
            "worker_logical_cpu": cpu,
            "pass": true,
        }))?;
    }
    let expected = shard_end
        .checked_sub(shard_start)
        .ok_or_else(|| invalid("shard interval underflow"))?;
    fragment.finish(expected, shard_start, shard_end)
}

fn timing_rows(
    rows: Vec<ProjectionRow>,
    fixture_root: &Path,
    mut fragment: FragmentWriter,
    shard_start: usize,
    shard_end: usize,
    cpu: usize,
) -> Result<(), DynError> {
    let candidate_indices = candidate_indices()?;
    let mut engines = HashMap::new();
    for row in rows {
        validate_row(&row)?;
        let fixture = load_fixture(fixture_root, &row)?;
        let engine = engine_for(
            &mut engines,
            &candidate_indices,
            &row.literal_hex,
            &row.literal_sha256,
            row.selector_eligible,
        )?;
        let candidate = if row.selector_eligible {
            let verified = engine
                .verified
                .ok_or_else(|| invalid("eligible literal lacks static object"))?;
            let automatic = SearchExactLiteralAutoAotV1::bind(&engine.portable, verified)?;
            verify_policy(&automatic)?;
            if row.route_class == "tag30-static-tail" {
                let _ = verify_static_tail(&engine.portable, verified, fixture.haystack(), &row)?;
            } else {
                verify_prefix_return(&engine.portable, fixture.haystack(), &row)?;
            }
            CandidateView::Automatic(automatic)
        } else {
            require(
                engine.verified.is_none() && row.route_class == "full-portable-fallback",
                "refused literal acquired a static route",
            )?;
            CandidateView::Portable(&engine.portable)
        };
        let expected = row.expected_span;
        verify_pair(&engine.portable, &candidate, fixture.haystack(), expected)?;
        require_current_cpu(cpu)?;
        let iterations =
            calibrated_iterations(&engine.portable, &candidate, fixture.haystack(), cpu)?;
        let mut pairs = Vec::with_capacity(REPETITIONS);
        for repetition in 0..REPETITIONS {
            require_current_cpu(cpu)?;
            let (portable, candidate_measurement, order) = if repetition % 2 == 0 {
                (
                    measure_portable(&engine.portable, fixture.haystack(), iterations)?,
                    measure_candidate(&candidate, fixture.haystack(), iterations)?,
                    "portable-first",
                )
            } else {
                let candidate_measurement =
                    measure_candidate(&candidate, fixture.haystack(), iterations)?;
                let portable = measure_portable(&engine.portable, fixture.haystack(), iterations)?;
                (portable, candidate_measurement, "candidate-first")
            };
            require_measurement_cpu(portable, cpu)?;
            require_measurement_cpu(candidate_measurement, cpu)?;
            require(
                portable.iterations == candidate_measurement.iterations
                    && portable.checksum == candidate_measurement.checksum,
                "timed pair semantics differ",
            )?;
            require(
                portable.elapsed_ns >= MINIMUM_ELAPSED_NS
                    && candidate_measurement.elapsed_ns >= MINIMUM_ELAPSED_NS,
                "timed variant did not reach the frozen minimum",
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
                "candidate_cpu_before": candidate_measurement.cpu_before,
                "candidate_cpu_after": candidate_measurement.cpu_after,
            }));
        }
        require_current_cpu(cpu)?;
        fragment.record(&json!({
            "schema": TIMING_ROW_SCHEMA,
            "ordinal": row.ordinal,
            "row_sha256": row.row_sha256,
            "case_id": row.case_id,
            "candidate_sha256": row.candidate_sha256,
            "literal_sha256": row.literal_sha256,
            "fixture_sha256": row.fixture_sha256,
            "scenario": row.scenario,
            "compiler_disposition": row.expected_compiler_disposition,
            "route_class": row.route_class,
            "expected_static_invoked": row.expected_static_invoked,
            "mapping": fixture.receipt,
            "logical_cpu": cpu,
            "minimum_elapsed_ns_each_variant": MINIMUM_ELAPSED_NS,
            "pairs": pairs,
            "pass": true,
            "production_authority": false,
            "rebar_accepted_as_input": false,
        }))?;
    }
    let expected = shard_end
        .checked_sub(shard_start)
        .ok_or_else(|| invalid("shard interval underflow"))?;
    fragment.finish(expected, shard_start, shard_end)
}

fn validate_linked_build() -> Result<(), io::Error> {
    require(generated::LINKED, "application runner was not linked")?;
    require(
        generated::TIMING_PERMITTED
            && generated::BACKEND_TAG == 30
            && generated::BACKEND_NAME == "AsimdV17"
            && generated::FAMILY_SELECTOR == 13
            && generated::MINIMUM_WINDOW_BYTES == 65_536
            && generated::PORTABLE_PREFIX_CANDIDATE_STARTS == 256
            && generated::OBJECT_CANDIDATE_MANIFEST_SHA256 == OBJECT_MANIFEST_SHA256
            && generated::LITERAL_DISPOSITIONS_SHA256 == DISPOSITIONS_SHA256
            && generated::FIXTURE_MANIFEST_SHA256 == FIXTURE_MANIFEST_SHA256
            && generated::APPLICATION_CONTRACT_IDENTITY == CONTRACT_SHA256
            && generated::CANDIDATES.len() == EXPECTED_CANDIDATES,
        "linked tag30 application identity changed",
    )
}

fn authenticate_contract(path: &Path) -> Result<(), DynError> {
    let bytes = regular_file(path, MAXIMUM_CONTRACT_BYTES)?;
    require(
        sha256_hex(&bytes) == CONTRACT_SHA256,
        "application contract identity changed",
    )?;
    let contract: Value = serde_json::from_slice(&bytes)?;
    require(
        contract.get("schema").and_then(Value::as_str) == Some(CONTRACT_SCHEMA)
            && contract.get("result_blind").and_then(Value::as_bool) == Some(true)
            && contract
                .get("production_authority")
                .and_then(Value::as_bool)
                == Some(false)
            && contract
                .get("rebar_inputs")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
            && contract
                .get("heldout_materialized")
                .and_then(Value::as_bool)
                == Some(false),
        "application contract fields changed",
    )
    .map_err(Into::into)
}

fn authenticate_build_receipt(path: &Path) -> Result<String, DynError> {
    let bytes = regular_file(path, MAXIMUM_BUILD_RECEIPT_BYTES)?;
    let sha256 = sha256_hex(&bytes);
    let receipt: Value = serde_json::from_slice(&bytes)?;
    require(
        receipt.get("schema").and_then(Value::as_str) == Some(BUILD_RECEIPT_SCHEMA)
            && receipt.get("identity_sha256").and_then(Value::as_str)
                == Some(generated::IDENTITY_SHA256)
            && receipt.get("runner_source_sha256").and_then(Value::as_str)
                == Some(generated::RUNNER_SOURCE_SHA256)
            && receipt.get("backend_tag").and_then(Value::as_u64) == Some(30)
            && receipt.get("backend_name").and_then(Value::as_str) == Some("AsimdV17")
            && receipt.get("backend_version").and_then(Value::as_str) == Some("SEARCH_V17")
            && receipt.get("candidate_policy").and_then(Value::as_u64) == Some(15)
            && receipt.get("family_selector").and_then(Value::as_u64) == Some(13)
            && receipt.get("minimum_window_bytes").and_then(Value::as_u64) == Some(65_536)
            && receipt
                .get("portable_prefix_candidate_starts")
                .and_then(Value::as_u64)
                == Some(256)
            && receipt
                .get("object_candidate_manifest_sha256")
                .and_then(Value::as_str)
                == Some(OBJECT_MANIFEST_SHA256)
            && receipt
                .get("literal_dispositions_sha256")
                .and_then(Value::as_str)
                == Some(DISPOSITIONS_SHA256)
            && receipt
                .get("fixture_manifest_sha256")
                .and_then(Value::as_str)
                == Some(FIXTURE_MANIFEST_SHA256)
            && receipt.get("plan_identity").and_then(Value::as_str)
                == Some(generated::PLAN_IDENTITY)
            && receipt.get("analyzer_identity").and_then(Value::as_str)
                == Some(generated::ANALYZER_IDENTITY)
            && receipt.get("evidence_identity").and_then(Value::as_str)
                == Some(generated::EVIDENCE_IDENTITY)
            && receipt
                .get("private_family_authorization_identity")
                .and_then(Value::as_str)
                == Some(generated::PRIVATE_AUTHORIZATION_IDENTITY)
            && receipt
                .get("application_contract_identity")
                .and_then(Value::as_str)
                == Some(CONTRACT_SHA256)
            && receipt
                .get("application_qualification_authority")
                .and_then(Value::as_bool)
                == Some(true)
            && receipt.get("production_authority").and_then(Value::as_bool) == Some(false)
            && receipt
                .get("rebar_accepted_as_input")
                .and_then(Value::as_bool)
                == Some(false)
            && receipt.get("llvm").and_then(Value::as_bool) == Some(false)
            && receipt
                .get("candidates")
                .and_then(Value::as_array)
                .is_some_and(|values| values.len() == 5)
            && receipt
                .get("refusals")
                .and_then(Value::as_array)
                .is_some_and(|values| values.len() == 6),
        "application build receipt changed",
    )?;
    Ok(sha256)
}

fn shard_bounds(shard: usize) -> Result<(usize, usize), io::Error> {
    require(shard < SHARDS, "shard ID is outside the frozen set")?;
    let quotient = PROJECTION_ROWS / SHARDS;
    let remainder = PROJECTION_ROWS % SHARDS;
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

fn load_projection_shard(
    path: &Path,
    shard_start: usize,
    shard_end: usize,
) -> Result<Vec<ProjectionRow>, DynError> {
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
    let mut file_digest = Sha256::new();
    digest.update(PROJECTION_DOMAIN);
    let mut encoded = Vec::with_capacity(MAXIMUM_ROW_BYTES + 1);
    let mut rows = 0_usize;
    let mut selected = Vec::new();
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
        file_digest.update(&encoded);
        let row: ProjectionRow = serde_json::from_slice(&encoded)?;
        require(row.ordinal == rows, "projection ordinal changed")?;
        validate_row_digest(&encoded, &row.row_sha256)?;
        if (shard_start..shard_end).contains(&rows) {
            selected.push(row);
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
    let file_actual: [u8; 32] = file_digest.finalize().into();
    require(
        rows == PROJECTION_ROWS
            && hex(&actual) == PROJECTION_SHA256
            && hex(&file_actual) == PROJECTION_FILE_SHA256
            && selected.len() == shard_end - shard_start,
        "projection identity or shard membership changed",
    )?;
    Ok(selected)
}

fn validate_row_digest(encoded: &[u8], expected: &str) -> Result<(), DynError> {
    let mut value: Value = serde_json::from_slice(encoded)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| invalid("projection row is not an object"))?;
    let removed = object.remove("row_sha256");
    require(
        removed.as_ref().and_then(Value::as_str) == Some(expected),
        "projection row digest field changed",
    )?;
    require(
        sha256_hex(&canonical_json_bytes(object)?) == expected,
        "projection row digest changed",
    )
    .map_err(Into::into)
}

fn validate_row(row: &ProjectionRow) -> Result<(), io::Error> {
    let literal = decode_hex(&row.literal_hex)?;
    require(
        row.schema == PROJECTION_SCHEMA
            && is_hex64(&row.row_sha256)
            && is_hex64(&row.case_id)
            && is_hex64(&row.candidate_sha256)
            && sha256_hex(&literal) == row.literal_sha256
            && literal.len() == row.literal_bytes
            && (1..=32).contains(&row.literal_bytes)
            && row.fixture_bytes == 1_048_576
            && row.alignment_offset < 16
            && row.fixture_path.starts_with(&row.candidate_sha256)
            && row
                .fixture_path
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            && !row.fixture_path.contains("..")
            && !row.rebar_accepted_as_input
            && !row.result_derived_exclusion,
        "projection row identity changed",
    )?;
    let actual_eligible = cyclic_phase_unique(&literal, &row.selected_offsets);
    require(
        actual_eligible == row.selector_eligible
            && row.expected_compiler_disposition
                == if actual_eligible {
                    "tag30-object"
                } else {
                    "structural-refusal"
                },
        "projection structural disposition changed",
    )?;
    let expected_route = if !actual_eligible {
        "full-portable-fallback"
    } else if matches!(row.scenario.as_str(), "early" | "dense") {
        "portable-prefix-return"
    } else {
        "tag30-static-tail"
    };
    require(
        row.route_class == expected_route
            && row.expected_static_invoked == (expected_route == "tag30-static-tail"),
        "projection route changed",
    )?;
    if let Some([start, end]) = row.expected_span {
        require(
            start < end && end <= row.fixture_bytes && end - start == row.literal_bytes,
            "projection expected span changed",
        )?;
    }
    Ok(())
}

fn cyclic_phase_unique(literal: &[u8], selected: &[usize]) -> bool {
    if !(6..=32).contains(&literal.len())
        || selected.len() != 5
        || selected.iter().any(|&offset| offset >= literal.len())
        || selected
            .iter()
            .enumerate()
            .any(|(index, offset)| selected[..index].contains(offset))
    {
        return false;
    }
    (1..literal.len()).all(|shift| {
        selected.iter().any(|&offset| {
            let shifted = (offset + shift) % literal.len();
            literal[offset] != literal[shifted]
        })
    })
}

fn candidate_indices() -> Result<HashMap<&'static str, usize>, io::Error> {
    require(
        generated::CANDIDATES.len() == EXPECTED_CANDIDATES,
        "linked candidate count changed",
    )?;
    let mut result = HashMap::new();
    for (index, candidate) in generated::CANDIDATES.iter().enumerate() {
        require(
            result.insert(candidate.literal_hex, index).is_none(),
            "linked candidate literal duplicated",
        )?;
    }
    Ok(result)
}

fn engine_for<'a>(
    engines: &'a mut HashMap<String, Engine>,
    indices: &HashMap<&str, usize>,
    literal_hex: &str,
    literal_sha256: &str,
    eligible: bool,
) -> Result<&'a Engine, DynError> {
    match engines.entry(literal_hex.to_owned()) {
        Entry::Occupied(entry) => Ok(entry.into_mut()),
        Entry::Vacant(entry) => {
            let literal = decode_hex(literal_hex)?;
            let portable = PortableBuilder::new(canonical_exact_source(&literal)).build()?;
            let exact = portable
                .exact_literal_search_aot_candidate()
                .ok_or_else(|| invalid("portable source is not exact"))?;
            require(
                exact.literal() == literal && sha256_hex(exact.literal()) == literal_sha256,
                "portable literal identity changed",
            )?;
            let verified = if eligible {
                let index = *indices
                    .get(literal_hex)
                    .ok_or_else(|| invalid("eligible literal not linked"))?;
                Some(adopt(index)?)
            } else {
                require(
                    !indices.contains_key(literal_hex),
                    "ineligible literal was linked",
                )?;
                None
            };
            Ok(entry.insert(Engine { portable, verified }))
        }
    }
}

#[allow(
    unsafe_code,
    reason = "generated selectors are receipt-bound and runtime-validated"
)]
fn adopt(index: usize) -> Result<&'static VerifiedStaticSearchSpanV1, DynError> {
    // SAFETY: generated invoke selects one retained glue symbol; the runtime
    // validates all metadata before returning a registry-owned handle.
    let verified = unsafe {
        adopt_linked_static_search_span_family_qualification_v1(
            |output: *mut RawStaticSearchSpanAdoptionOutputV1| generated::invoke(index, output),
        )
    }?;
    require(
        verified.row_selector() == 13 && verified.backend_version() == 30,
        "adopted tag30 family identity changed",
    )?;
    Ok(verified)
}

fn verify_policy(automatic: &SearchExactLiteralAutoAotV1<'_>) -> Result<(), io::Error> {
    let policy = automatic.family_execution_policy();
    require(
        policy.minimum_window_bytes() == 65_536
            && policy.portable_prefix_candidate_starts() == 256
            && policy.plan_identity() == decode_digest(generated::PLAN_IDENTITY)?
            && policy.analyzer_identity() == decode_digest(generated::ANALYZER_IDENTITY)?
            && policy.evidence_identity() == decode_digest(generated::EVIDENCE_IDENTITY)?,
        "adopted automatic policy changed",
    )
}

fn verify_prefix_return(
    portable: &PortableRegex,
    haystack: &[u8],
    row: &ProjectionRow,
) -> Result<(), DynError> {
    let prefix_end = 256_usize
        .checked_add(row.literal_bytes)
        .and_then(|value| value.checked_sub(1))
        .ok_or_else(|| invalid("portable prefix extent overflow"))?
        .min(haystack.len());
    let matched = portable
        .find_window(
            haystack,
            SearchWindow::new(0, prefix_end),
            SearchLimits::unlimited(),
        )?
        .0;
    require(
        project(matched) == row.expected_span,
        "prefix-return proof changed",
    )
    .map_err(Into::into)
}

fn verify_static_tail(
    portable: &PortableRegex,
    verified: &'static VerifiedStaticSearchSpanV1,
    haystack: &[u8],
    row: &ProjectionRow,
) -> Result<Option<[usize; 2]>, DynError> {
    let prefix_end = 256_usize
        .checked_add(row.literal_bytes)
        .and_then(|value| value.checked_sub(1))
        .ok_or_else(|| invalid("portable prefix extent overflow"))?
        .min(haystack.len());
    let prefix = portable
        .find_window(
            haystack,
            SearchWindow::new(0, prefix_end),
            SearchLimits::unlimited(),
        )?
        .0;
    require(prefix.is_none(), "static-tail fixture matched the prefix")?;
    let direct = SearchExactLiteralAotV1::bind(portable, verified)?
        .find_window(
            haystack,
            SearchWindow::new(256.min(haystack.len()), haystack.len()),
            SearchLimits::unlimited(),
        )?
        .0;
    require(
        project(direct) == row.expected_span,
        "direct static-tail proof changed",
    )?;
    Ok(project(direct))
}

fn load_fixture(root: &Path, row: &ProjectionRow) -> Result<Fixture, DynError> {
    let path = root.join(&row.fixture_path);
    let raw = regular_file(&path, MAXIMUM_FIXTURE_BYTES)?;
    require(
        raw.len() == row.fixture_bytes && sha256_hex(&raw) == row.fixture_sha256,
        "fixture bytes changed",
    )?;
    let allocation_bytes = row
        .fixture_bytes
        .checked_add(63)
        .ok_or_else(|| invalid("fixture allocation overflow"))?;
    let mut storage = vec![row.padding_sentinel; allocation_bytes];
    let base = storage.as_ptr() as usize;
    let start = 16 + (row.alignment_offset + 16 - ((base + 16) % 16)) % 16;
    let end = start
        .checked_add(row.fixture_bytes)
        .ok_or_else(|| invalid("fixture checked extent overflow"))?;
    require(end <= storage.len(), "fixture checked extent changed")?;
    storage[start..end].copy_from_slice(&raw);
    let checked = storage.as_ptr() as usize + start;
    require(
        checked % 16 == row.alignment_offset
            && storage[..start]
                .iter()
                .all(|&byte| byte == row.padding_sentinel)
            && storage[end..]
                .iter()
                .all(|&byte| byte == row.padding_sentinel),
        "fixture physical alignment changed",
    )?;
    let mut allocation = Sha256::new();
    allocation.update(ALLOCATION_DOMAIN);
    allocation.update(row.case_id.as_bytes());
    allocation.update(u64::try_from(base)?.to_le_bytes());
    allocation.update(u64::try_from(start)?.to_le_bytes());
    allocation.update(u64::try_from(row.fixture_bytes)?.to_le_bytes());
    let allocation_receipt: [u8; 32] = allocation.finalize().into();
    let receipt = json!({
        "allocation_start_address": base,
        "allocation_bytes": allocation_bytes,
        "checked_pointer_address": checked,
        "checked_bytes": row.fixture_bytes,
        "start_offset": start,
        "actual_window_start_mod16": checked % 16,
        "readable_left_bytes": start,
        "readable_right_bytes": storage.len() - end,
        "padding_sentinel": row.padding_sentinel,
        "padding_verified": true,
        "allocation_receipt_sha256": hex(&allocation_receipt),
    });
    Ok(Fixture {
        storage,
        start,
        bytes: row.fixture_bytes,
        receipt,
    })
}

fn scalar_nonoverlapping(haystack: &[u8], literal: &[u8]) -> (Option<[usize; 2]>, usize) {
    let mut cursor = 0_usize;
    let mut first = None;
    let mut count = 0_usize;
    while cursor <= haystack.len().saturating_sub(literal.len()) {
        let Some(relative) = haystack[cursor..]
            .windows(literal.len())
            .position(|window| window == literal)
        else {
            break;
        };
        let start = cursor + relative;
        let end = start + literal.len();
        first.get_or_insert([start, end]);
        count += 1;
        cursor = end;
    }
    (first, count)
}

fn verify_pair(
    portable: &PortableRegex,
    candidate: &CandidateView<'_>,
    haystack: &[u8],
    expected: Option<[usize; 2]>,
) -> Result<(), DynError> {
    let portable_match = portable
        .find_window(
            haystack,
            SearchWindow::new(0, haystack.len()),
            SearchLimits::unlimited(),
        )?
        .0;
    let candidate_match = candidate.find(haystack)?;
    require(
        project(portable_match) == expected && project(candidate_match) == expected,
        "paired correctness mismatch",
    )
    .map_err(Into::into)
}

fn calibrated_iterations(
    portable: &PortableRegex,
    candidate: &CandidateView<'_>,
    haystack: &[u8],
    cpu: usize,
) -> Result<usize, DynError> {
    let portable_pilot = pilot(
        || measure_portable(portable, haystack, 1),
        |iterations| measure_portable(portable, haystack, iterations),
        cpu,
    )?;
    let candidate_pilot = pilot(
        || measure_candidate(candidate, haystack, 1),
        |iterations| measure_candidate(candidate, haystack, iterations),
        cpu,
    )?;
    Ok(scaled_iterations(CALIBRATION_TARGET_NS, portable_pilot)?
        .max(scaled_iterations(CALIBRATION_TARGET_NS, candidate_pilot)?))
}

fn pilot(
    mut single: impl FnMut() -> Result<Measurement, DynError>,
    mut multiple: impl FnMut(usize) -> Result<Measurement, DynError>,
    cpu: usize,
) -> Result<Measurement, DynError> {
    let one = single()?;
    require_measurement_cpu(one, cpu)?;
    if one.elapsed_ns >= CALIBRATION_FLOOR_NS {
        return Ok(one);
    }
    let iterations = usize::try_from(
        u128::from(CALIBRATION_FLOOR_NS)
            .checked_add(u128::from(one.elapsed_ns.max(1)) - 1)
            .ok_or_else(|| invalid("pilot ceil overflow"))?
            / u128::from(one.elapsed_ns.max(1)),
    )?
    .clamp(2, 1 << 20);
    let measured = multiple(iterations)?;
    require_measurement_cpu(measured, cpu)?;
    Ok(measured)
}

fn scaled_iterations(target_ns: u64, pilot: Measurement) -> Result<usize, io::Error> {
    let elapsed = pilot.elapsed_ns.max(1);
    let numerator = u128::from(target_ns)
        .checked_mul(
            u128::try_from(pilot.iterations).map_err(|_| invalid("pilot iterations overflow"))?,
        )
        .and_then(|value| value.checked_add(u128::from(elapsed) - 1))
        .ok_or_else(|| invalid("calibration overflow"))?;
    let scaled = usize::try_from(numerator / u128::from(elapsed))
        .map_err(|_| invalid("calibrated iterations overflow"))?;
    Ok(scaled.clamp(1, MAXIMUM_ITERATIONS))
}

fn measure_portable(
    portable: &PortableRegex,
    haystack: &[u8],
    iterations: usize,
) -> Result<Measurement, DynError> {
    measure(iterations, || {
        Ok(portable
            .find_window(
                black_box(haystack),
                SearchWindow::new(0, haystack.len()),
                SearchLimits::unlimited(),
            )?
            .0)
    })
}

fn measure_candidate(
    candidate: &CandidateView<'_>,
    haystack: &[u8],
    iterations: usize,
) -> Result<Measurement, DynError> {
    measure(iterations, || candidate.find(black_box(haystack)))
}

fn measure(
    iterations: usize,
    mut invoke: impl FnMut() -> Result<Option<Match>, DynError>,
) -> Result<Measurement, DynError> {
    let cpu_before = current_cpu()?;
    let start = Instant::now();
    let mut checksum = CHECKSUM_SEED;
    for ordinal in 0..iterations {
        checksum = mix(
            checksum,
            encode(black_box(invoke()?)) ^ u64::try_from(ordinal).unwrap_or(u64::MAX),
        );
    }
    let elapsed_ns = u64::try_from(start.elapsed().as_nanos())?;
    let cpu_after = current_cpu()?;
    Ok(Measurement {
        iterations,
        elapsed_ns,
        checksum: black_box(checksum),
        cpu_before,
        cpu_after,
    })
}

fn require_measurement_cpu(measurement: Measurement, expected: usize) -> Result<(), io::Error> {
    require(
        measurement.cpu_before == expected && measurement.cpu_after == expected,
        "worker migrated during a measured variant",
    )
}

#[cfg(target_os = "linux")]
fn pin_current_thread(cpu: usize) -> Result<(), io::Error> {
    require(
        cpu < libc::CPU_SETSIZE as usize,
        "logical CPU is out of range",
    )?;
    // SAFETY: cpu_set_t is initialized and cpu is in range.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    // SAFETY: cpu is checked against CPU_SETSIZE.
    unsafe {
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
    }
    // SAFETY: pid zero is the current thread and set has its exact C extent.
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
    require_current_cpu(cpu)
}

#[cfg(target_os = "macos")]
fn pin_current_thread(cpu: usize) -> Result<(), io::Error> {
    #[repr(C)]
    struct ThreadAffinityPolicy {
        affinity_tag: i32,
    }
    const THREAD_AFFINITY_POLICY: i32 = 4;
    unsafe extern "C" {
        fn mach_thread_self() -> u32;
        fn thread_policy_set(thread: u32, flavor: i32, policy_info: *const i32, count: u32) -> i32;
    }
    let affinity_tag = i32::try_from(
        cpu.checked_add(1)
            .ok_or_else(|| invalid("affinity tag overflow"))?,
    )
    .map_err(|_| invalid("affinity tag is not representable"))?;
    let policy = ThreadAffinityPolicy { affinity_tag };
    // SAFETY: policy is one correctly laid-out integer for the current thread.
    let status = unsafe {
        thread_policy_set(
            mach_thread_self(),
            THREAD_AFFINITY_POLICY,
            std::ptr::from_ref(&policy).cast(),
            1,
        )
    };
    require(status == 0, "failed to install macOS affinity")?;
    for _ in 0..100_000 {
        if current_cpu()? == cpu {
            return Ok(());
        }
        std::thread::yield_now();
    }
    Err(invalid("worker did not reach requested macOS CPU"))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn pin_current_thread(_cpu: usize) -> Result<(), io::Error> {
    Err(invalid("application runner requires Linux or macOS"))
}

#[cfg(target_os = "linux")]
fn current_cpu() -> Result<usize, io::Error> {
    // SAFETY: sched_getcpu has no pointer arguments.
    let cpu = unsafe { libc::sched_getcpu() };
    usize::try_from(cpu).map_err(|_| io::Error::last_os_error())
}

#[cfg(target_os = "macos")]
fn current_cpu() -> Result<usize, io::Error> {
    unsafe extern "C" {
        fn pthread_cpu_number_np(cpu_number_out: *mut usize) -> i32;
    }
    let mut cpu = 0_usize;
    // SAFETY: cpu is a live writable output word.
    let status = unsafe { pthread_cpu_number_np(std::ptr::from_mut(&mut cpu)) };
    if status == 0 {
        Ok(cpu)
    } else {
        Err(io::Error::from_raw_os_error(status))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn current_cpu() -> Result<usize, io::Error> {
    Err(invalid("application runner requires Linux or macOS"))
}

fn require_current_cpu(expected: usize) -> Result<(), io::Error> {
    require(
        current_cpu()? == expected,
        "worker is not on its requested CPU",
    )
}

fn current_binary_sha256() -> Result<String, DynError> {
    let path = std::env::current_exe()?;
    Ok(sha256_hex(&regular_file(&path, 1 << 30)?))
}

fn regular_file(path: &Path, maximum: u64) -> Result<Vec<u8>, io::Error> {
    let before = std::fs::symlink_metadata(path)?;
    require(
        before.is_file()
            && !before.file_type().is_symlink()
            && before.nlink() == 1
            && before.len() > 0
            && before.len() <= maximum,
        "input is not one bounded unshared regular file",
    )?;
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    require(
        (opened.dev(), opened.ino(), opened.len()) == (before.dev(), before.ino(), before.len()),
        "input changed before open",
    )?;
    let capacity =
        usize::try_from(opened.len()).map_err(|_| invalid("input size is not representable"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| invalid("input allocation failed"))?;
    file.read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    require(
        bytes.len() == capacity
            && (
                after.dev(),
                after.ino(),
                after.len(),
                after.mtime_nsec(),
                after.ctime_nsec(),
            ) == (
                opened.dev(),
                opened.ino(),
                opened.len(),
                opened.mtime_nsec(),
                opened.ctime_nsec(),
            ),
        "input changed while held",
    )?;
    Ok(bytes)
}

fn canonical_json_bytes(object: &Map<String, Value>) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(object)
}

fn canonical_exact_source(literal: &[u8]) -> String {
    let mut source = String::with_capacity(literal.len() * 4 + 6);
    source.push_str("(?-u:");
    for byte in literal {
        use std::fmt::Write as _;
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
        "hex value is not canonical lowercase",
    )?;
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| invalid("hex pair is not UTF-8"))?;
            u8::from_str_radix(text, 16).map_err(|_| invalid("hex pair is invalid"))
        })
        .collect()
}

fn decode_digest(value: &str) -> Result<[u8; 32], io::Error> {
    let bytes = decode_hex(value)?;
    bytes
        .try_into()
        .map_err(|_| invalid("identity digest has wrong width"))
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn project(matched: Option<Match>) -> Option<[usize; 2]> {
    matched.map(|value| [value.start(), value.end()])
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

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
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
    fn shards_cover_projection_once() {
        let mut cursor = 0;
        for shard in 0..SHARDS {
            let (start, end) = shard_bounds(shard).unwrap();
            assert_eq!(start, cursor);
            assert!(end > start);
            cursor = end;
        }
        assert_eq!(cursor, PROJECTION_ROWS);
    }

    #[test]
    fn selector_rejects_uniform_and_short_literals() {
        assert!(!cyclic_phase_unique(b"Watso", &[0, 1, 2, 3, 4]));
        assert!(!cyclic_phase_unique(b"ZZZZZZZZ", &[0, 1, 2, 3, 7]));
        assert!(cyclic_phase_unique(b"Watson", &[0, 3, 4, 1, 5]));
    }

    #[test]
    fn scalar_oracle_is_nonoverlapping() {
        assert_eq!(scalar_nonoverlapping(b"aaaaa", b"aa"), (Some([0, 2]), 2));
        assert_eq!(scalar_nonoverlapping(b"xxxxx", b"aa"), (None, 0));
    }

    #[test]
    fn committed_projection_is_canonical_and_complete() {
        let projection = include_bytes!("../projection-v1.jsonl");
        assert_eq!(sha256_hex(projection), PROJECTION_FILE_SHA256);

        let mut digest = Sha256::new();
        digest.update(PROJECTION_DOMAIN);
        let mut routes = HashMap::new();
        let mut rows = 0_usize;
        for encoded in projection.split_inclusive(|&byte| byte == b'\n') {
            assert_eq!(encoded.last(), Some(&b'\n'));
            digest.update(u64::try_from(encoded.len()).unwrap().to_le_bytes());
            digest.update(encoded);
            let row: ProjectionRow = serde_json::from_slice(encoded).unwrap();
            assert_eq!(row.ordinal, rows);
            validate_row_digest(encoded, &row.row_sha256).unwrap();
            validate_row(&row).unwrap();
            *routes.entry(row.route_class.clone()).or_insert(0_usize) += 1;
            rows += 1;
        }

        assert_eq!(rows, PROJECTION_ROWS);
        assert_eq!(hex(&digest.finalize()), PROJECTION_SHA256);
        assert_eq!(routes.get("tag30-static-tail"), Some(&75));
        assert_eq!(routes.get("portable-prefix-return"), Some(&10));
        assert_eq!(routes.get("full-portable-fallback"), Some(&69));
    }
}
