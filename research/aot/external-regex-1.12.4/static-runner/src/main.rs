use std::{
    error::Error,
    fs,
    hint::black_box,
    io::{self, BufWriter, Write as _},
    path::{Path, PathBuf},
    time::Instant,
};

use fre::{Match, PortableBuilder, PortableRegex, SearchExactLiteralAutoAotV1, SearchLimits};
use fre_aot_static_runtime::{
    RawStaticSearchSpanAdoptionOutputV1, adopt_linked_static_search_span_family_qualification_v1,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[allow(
    unsafe_code,
    reason = "generated declarations bind receipt-authenticated static family glue"
)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/generated.rs"));
}

type DynError = Box<dyn Error>;

const FIXTURE_MANIFEST_SHA256: &str =
    "b979ed327db7e9623bccba1ef775d1957b7323c8b30edb44f40593176f52b44a";
const FIXTURE_SCHEMA: &str = "fre.aot.external-regex-1.12.4-development-fixtures.v2";
const RESULT_SCHEMA: &str = "fre.aot.external-regex-1.12.4-static-search-results.v1";
const TARGET_NS: u64 = 500_000_000;
const MINIMUM_NS: u64 = 400_000_000;
const PILOT_NS: u64 = 50_000_000;
const REPETITIONS: usize = 6;
const MAX_ITERATIONS: usize = 1 << 30;
const CHECKSUM_SEED: u64 = 0x6a09_e667_f3bc_c909;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureManifest {
    schema: String,
    payload_sha256: String,
    payload: FixturePayload,
}

#[derive(Debug, Deserialize)]
struct FixturePayload {
    backend_identity: String,
    timing_permitted: bool,
    candidate_count: usize,
    fixture_count: usize,
    fixture_bytes_each: usize,
    candidates: Vec<FixtureCandidate>,
}

#[derive(Debug, Deserialize)]
struct FixtureCandidate {
    semantic_candidate_sha256: String,
    literal_hex: String,
    literal_sha256: String,
    literal_bytes: usize,
    fixtures: Vec<FixtureRow>,
}

#[derive(Clone, Debug, Deserialize)]
struct FixtureRow {
    scenario: String,
    path: String,
    bytes: usize,
    sha256: String,
    alignment_offset: u8,
    expected_leftmost_span: Option<[usize; 2]>,
    expected_nonoverlapping_count: usize,
}

#[derive(Debug)]
struct AlignedFixture {
    storage: Vec<u8>,
    start: usize,
    row: FixtureRow,
}

impl AlignedFixture {
    fn bytes(&self) -> &[u8] {
        let end = self
            .start
            .checked_add(self.row.bytes)
            .expect("validated fixture slice");
        &self.storage[self.start..end]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Engine {
    Portable,
    StaticAutoAot,
}

impl Engine {
    const fn name(self) -> &'static str {
        match self {
            Self::Portable => "portable",
            Self::StaticAutoAot => "static-auto-aot",
        }
    }

    const fn route(self) -> &'static str {
        match self {
            Self::Portable => "portable-exact-literal",
            Self::StaticAutoAot => "source-family-portable-prefix-static-tail",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Measurement {
    iterations: usize,
    total_ns: u64,
    checksum: u64,
    semantic: u64,
}

fn main() -> Result<(), DynError> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let [mode, fixture_root] = arguments.as_slice() else {
        return Err(invalid("usage: inspect|run FIXTURE_ROOT").into());
    };
    if !generated::LINKED {
        return Err(invalid(
            "runner is selector-neutral; rebuild with FRE_EXTERNAL_SEARCH_STATIC_IDENTITY",
        )
        .into());
    }
    let root = canonical_fixture_root(Path::new(fixture_root))?;
    let manifest = load_manifest(&root)?;
    match mode.as_str() {
        "inspect" => inspect(&root, &manifest),
        "run" => {
            require(
                generated::TIMING_PERMITTED,
                "linked identity does not permit development timing",
            )?;
            run(&root, &manifest)
        }
        _ => Err(invalid("mode must be inspect or run").into()),
    }
}

fn inspect(root: &Path, manifest: &FixtureManifest) -> Result<(), DynError> {
    let mut fixture_total = 0_usize;
    for (index, candidate) in manifest.payload.candidates.iter().enumerate() {
        let portable = build_portable(candidate)?;
        let verified = adopt(index)?;
        let automatic = SearchExactLiteralAutoAotV1::bind(&portable, verified)?;
        require(
            automatic.literal_bytes() == u32::try_from(candidate.literal_bytes)?,
            "adopted literal width differs from fixture candidate",
        )?;
        for row in &candidate.fixtures {
            let fixture = load_fixture(root, row)?;
            let literal = decode_hex(&candidate.literal_hex)?;
            verify_oracle(fixture.bytes(), &literal, row)?;
            let portable_match = portable.find(fixture.bytes(), SearchLimits::unlimited())?.0;
            let automatic_match = automatic
                .find(fixture.bytes(), SearchLimits::unlimited())?
                .0;
            require(
                project(portable_match) == row.expected_leftmost_span
                    && project(automatic_match) == row.expected_leftmost_span,
                "facade correctness differs from fixture oracle",
            )?;
            fixture_total = fixture_total
                .checked_add(1)
                .ok_or_else(|| invalid("fixture count overflow"))?;
        }
    }
    require(
        fixture_total == manifest.payload.fixture_count,
        "inspected fixture count differs",
    )?;
    println!("linked=true");
    println!("timing_permitted={}", generated::TIMING_PERMITTED);
    println!("identity_sha256={}", generated::IDENTITY_SHA256);
    println!("runner_source_sha256={}", generated::RUNNER_SOURCE_SHA256);
    println!(
        "backend={} tag={}",
        generated::BACKEND_NAME,
        generated::BACKEND_TAG
    );
    println!("family_selector={}", generated::FAMILY_SELECTOR);
    println!("candidates={}", manifest.payload.candidate_count);
    println!("fixtures={fixture_total}");
    println!("correctness=pass");
    Ok(())
}

fn run(root: &Path, manifest: &FixtureManifest) -> Result<(), DynError> {
    let stdout = io::stdout();
    let mut output = BufWriter::new(stdout.lock());
    writeln!(
        output,
        "schema,identity_sha256,runner_source_sha256,backend_name,backend_tag,family_selector,candidate_sha256,literal_hex,scenario,fixture_sha256,alignment,repetition,order,engine,route,iterations,total_ns,ns_per_iter,checksum,semantic,expected_nonoverlapping_count,tail_owned"
    )?;
    for (index, candidate) in manifest.payload.candidates.iter().enumerate() {
        let portable = build_portable(candidate)?;
        let verified = adopt(index)?;
        let automatic = SearchExactLiteralAutoAotV1::bind(&portable, verified)?;
        for row in &candidate.fixtures {
            let fixture = load_fixture(root, row)?;
            let literal = decode_hex(&candidate.literal_hex)?;
            verify_oracle(fixture.bytes(), &literal, row)?;
            verify_pair(&portable, &automatic, fixture.bytes(), row)?;
            let iterations = calibrated_iterations(&portable, &automatic, fixture.bytes())?;
            let tail_owned = tail_owned(row, candidate.literal_bytes)?;
            for repetition in 0..REPETITIONS {
                let order = if repetition % 2 == 0 {
                    [Engine::Portable, Engine::StaticAutoAot]
                } else {
                    [Engine::StaticAutoAot, Engine::Portable]
                };
                let order_name = format!("{}+{}", order[0].name(), order[1].name());
                let mut pair = Vec::with_capacity(2);
                for engine in order {
                    let measured = match engine {
                        Engine::Portable => {
                            measure_portable(&portable, fixture.bytes(), iterations)?
                        }
                        Engine::StaticAutoAot => {
                            measure_automatic(&automatic, fixture.bytes(), iterations)?
                        }
                    };
                    require(
                        measured.total_ns >= MINIMUM_NS,
                        "timed sample did not reach the preregistered minimum",
                    )?;
                    pair.push((engine, measured));
                }
                require(
                    pair[0].1.iterations == pair[1].1.iterations
                        && pair[0].1.checksum == pair[1].1.checksum
                        && pair[0].1.semantic == pair[1].1.semantic,
                    "paired engines differ semantically",
                )?;
                for (engine, measured) in pair {
                    let ns_per_iter = format_ns_per_iter(measured.total_ns, measured.iterations)?;
                    writeln!(
                        output,
                        "{RESULT_SCHEMA},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
                        generated::IDENTITY_SHA256,
                        generated::RUNNER_SOURCE_SHA256,
                        generated::BACKEND_NAME,
                        generated::BACKEND_TAG,
                        generated::FAMILY_SELECTOR,
                        candidate.semantic_candidate_sha256,
                        candidate.literal_hex,
                        row.scenario,
                        row.sha256,
                        row.alignment_offset,
                        repetition,
                        order_name,
                        engine.name(),
                        engine.route(),
                        measured.iterations,
                        measured.total_ns,
                        ns_per_iter,
                        measured.checksum,
                        measured.semantic,
                        row.expected_nonoverlapping_count,
                        tail_owned,
                    )?;
                }
                output.flush()?;
            }
        }
    }
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "one generated family glue call is resolved through the disjoint private registry"
)]
fn adopt(
    index: usize,
) -> Result<&'static fre_aot_static_runtime::VerifiedStaticSearchSpanV1, DynError> {
    // SAFETY: generated::invoke selects only one receipt-bound retained glue
    // symbol. The runtime independently selects the source family before any
    // final-image pointer is inspected.
    let verified = unsafe {
        adopt_linked_static_search_span_family_qualification_v1(
            |output: *mut RawStaticSearchSpanAdoptionOutputV1| generated::invoke(index, output),
        )
    }?;
    require(
        verified.row_selector() == generated::FAMILY_SELECTOR,
        "adopted family selector differs from sealed runner identity",
    )?;
    let policy = verified
        .family_execution_policy()
        .ok_or_else(|| invalid("adopted row lacks source-family execution policy"))?;
    require(
        policy.minimum_window_bytes() == u32::try_from(generated::MINIMUM_WINDOW_BYTES)?
            && policy.portable_prefix_candidate_starts()
                == u32::try_from(generated::PORTABLE_PREFIX_CANDIDATE_STARTS)?
            && hex_bytes(&policy.plan_identity()) == generated::PLAN_IDENTITY
            && hex_bytes(&policy.analyzer_identity()) == generated::ANALYZER_IDENTITY
            && hex_bytes(&policy.evidence_identity()) == generated::EVIDENCE_IDENTITY,
        "adopted source-family policy differs from sealed runner identity",
    )?;
    Ok(verified)
}

fn build_portable(candidate: &FixtureCandidate) -> Result<PortableRegex, DynError> {
    let source = String::from_utf8(decode_hex(&candidate.literal_hex)?)?;
    let portable = PortableBuilder::new(source).unicode(true).build()?;
    let exact = portable
        .exact_literal_search_aot_candidate()
        .ok_or_else(|| invalid("fixture source is not an exact-literal AOT candidate"))?;
    require(
        exact.literal() == decode_hex(&candidate.literal_hex)?
            && sha256_hex(exact.literal()) == candidate.literal_sha256,
        "portable candidate literal differs from external identity",
    )?;
    Ok(portable)
}

fn verify_pair(
    portable: &PortableRegex,
    automatic: &SearchExactLiteralAutoAotV1<'_>,
    haystack: &[u8],
    row: &FixtureRow,
) -> Result<(), DynError> {
    let portable_match = portable.find(haystack, SearchLimits::unlimited())?.0;
    let automatic_match = automatic.find(haystack, SearchLimits::unlimited())?.0;
    require(
        project(portable_match) == row.expected_leftmost_span
            && project(automatic_match) == row.expected_leftmost_span,
        "paired facade correctness differs",
    )
    .map_err(Into::into)
}

fn calibrated_iterations(
    portable: &PortableRegex,
    automatic: &SearchExactLiteralAutoAotV1<'_>,
    haystack: &[u8],
) -> Result<usize, DynError> {
    let portable_pilot = pilot_portable(portable, haystack)?;
    let automatic_pilot = pilot_automatic(automatic, haystack)?;
    require(
        portable_pilot.semantic == automatic_pilot.semantic,
        "pilot semantics differ",
    )?;
    let portable_cross = u128::from(portable_pilot.total_ns)
        .checked_mul(u128::try_from(automatic_pilot.iterations)?)
        .ok_or_else(|| invalid("portable pilot ratio overflow"))?;
    let automatic_cross = u128::from(automatic_pilot.total_ns)
        .checked_mul(u128::try_from(portable_pilot.iterations)?)
        .ok_or_else(|| invalid("automatic pilot ratio overflow"))?;
    let faster = if portable_cross <= automatic_cross {
        portable_pilot
    } else {
        automatic_pilot
    };
    require(
        faster.total_ns > 0 && faster.iterations > 0,
        "invalid pilot duration",
    )?;
    let denominator = u128::from(faster.total_ns);
    let numerator = u128::from(TARGET_NS)
        .checked_mul(u128::try_from(faster.iterations)?)
        .ok_or_else(|| invalid("calibrated iteration numerator overflow"))?;
    let rounding = denominator
        .checked_sub(1)
        .ok_or_else(|| invalid("zero calibration denominator"))?;
    let rounded_numerator = numerator
        .checked_add(rounding)
        .ok_or_else(|| invalid("calibrated iteration rounding overflow"))?;
    let iterations = usize::try_from(
        rounded_numerator
            .checked_div(denominator)
            .ok_or_else(|| invalid("zero calibration denominator"))?,
    )?;
    require(
        iterations > 0 && iterations <= MAX_ITERATIONS,
        "calibrated iterations exceed the fixed bound",
    )?;
    Ok(iterations)
}

fn pilot_portable(portable: &PortableRegex, haystack: &[u8]) -> Result<Measurement, DynError> {
    let mut iterations = 1_usize;
    loop {
        let measured = measure_portable(portable, haystack, iterations)?;
        if measured.total_ns >= PILOT_NS {
            return Ok(measured);
        }
        iterations = iterations
            .checked_mul(2)
            .filter(|value| *value <= MAX_ITERATIONS)
            .ok_or_else(|| invalid("portable pilot iteration overflow"))?;
    }
}

fn pilot_automatic(
    automatic: &SearchExactLiteralAutoAotV1<'_>,
    haystack: &[u8],
) -> Result<Measurement, DynError> {
    let mut iterations = 1_usize;
    loop {
        let measured = measure_automatic(automatic, haystack, iterations)?;
        if measured.total_ns >= PILOT_NS {
            return Ok(measured);
        }
        iterations = iterations
            .checked_mul(2)
            .filter(|value| *value <= MAX_ITERATIONS)
            .ok_or_else(|| invalid("automatic pilot iteration overflow"))?;
    }
}

fn measure_portable(
    portable: &PortableRegex,
    haystack: &[u8],
    iterations: usize,
) -> Result<Measurement, DynError> {
    measure(iterations, || {
        Ok(portable
            .find(black_box(haystack), SearchLimits::unlimited())?
            .0)
    })
}

fn measure_automatic(
    automatic: &SearchExactLiteralAutoAotV1<'_>,
    haystack: &[u8],
    iterations: usize,
) -> Result<Measurement, DynError> {
    measure(iterations, || {
        Ok(automatic
            .find(black_box(haystack), SearchLimits::unlimited())?
            .0)
    })
}

fn measure(
    iterations: usize,
    mut invoke: impl FnMut() -> Result<Option<Match>, DynError>,
) -> Result<Measurement, DynError> {
    let mut checksum = CHECKSUM_SEED;
    let mut semantic = 0_u64;
    let started = Instant::now();
    for iteration in 0..iterations {
        semantic = encode(invoke()?);
        checksum = checksum
            .rotate_left(11)
            .wrapping_add(semantic)
            .wrapping_add(u64::try_from(iteration)?);
        black_box(checksum);
    }
    let total_ns = u64::try_from(started.elapsed().as_nanos())?;
    Ok(Measurement {
        iterations,
        total_ns,
        checksum,
        semantic,
    })
}

fn format_ns_per_iter(total_ns: u64, iterations: usize) -> Result<String, DynError> {
    let denominator = u64::try_from(iterations)?;
    require(denominator > 0, "zero iterations")?;
    let whole = total_ns
        .checked_div(denominator)
        .ok_or_else(|| invalid("zero iterations"))?;
    let remainder = total_ns
        .checked_rem(denominator)
        .ok_or_else(|| invalid("zero iterations"))?;
    let fractional = u128::from(remainder)
        .checked_mul(1_000_000_000)
        .ok_or_else(|| invalid("nanosecond fraction overflow"))?
        .checked_div(u128::from(denominator))
        .ok_or_else(|| invalid("zero iterations"))?;
    Ok(format!("{whole}.{fractional:09}"))
}

fn load_manifest(root: &Path) -> Result<FixtureManifest, DynError> {
    let bytes = regular_file(&root.join("manifest.json"), 1 << 20)?;
    require(
        sha256_hex(&bytes) == FIXTURE_MANIFEST_SHA256,
        "fixture manifest SHA-256 differs",
    )?;
    let manifest: FixtureManifest = serde_json::from_slice(&bytes)?;
    require(manifest.schema == FIXTURE_SCHEMA, "fixture schema differs")?;
    require(
        manifest.payload_sha256.len() == 64,
        "fixture payload identity is malformed",
    )?;
    require(
        manifest.payload.backend_identity == "required-unresolved-input"
            && !manifest.payload.timing_permitted,
        "immutable fixture generator improperly granted backend/timing authority",
    )?;
    require(
        manifest.payload.candidate_count == generated::CANDIDATES.len()
            && manifest.payload.candidates.len() == generated::CANDIDATES.len()
            && manifest.payload.fixture_count == 28
            && manifest.payload.fixture_bytes_each == 1_048_576,
        "fixture cardinality differs",
    )?;
    for (candidate, expected) in manifest
        .payload
        .candidates
        .iter()
        .zip(generated::CANDIDATES)
    {
        require(
            candidate.semantic_candidate_sha256 == expected.semantic_candidate_sha256
                && candidate.literal_hex == expected.literal_hex
                && !expected.implementation_sha256.is_empty()
                && !expected.glue_sha256.is_empty()
                && candidate.fixtures.len() == 7,
            "linked candidate identity differs from fixture candidate",
        )?;
    }
    Ok(manifest)
}

fn load_fixture(root: &Path, row: &FixtureRow) -> Result<AlignedFixture, DynError> {
    require(
        row.alignment_offset < 16 && row.bytes == 1_048_576 && canonical_relative(&row.path),
        "fixture row path/size/alignment differs",
    )?;
    let bytes = regular_file(&root.join(&row.path), u64::try_from(row.bytes)?)?;
    require(
        bytes.len() == row.bytes && sha256_hex(&bytes) == row.sha256,
        "fixture bytes differ from manifest",
    )?;
    let storage_bytes = row
        .bytes
        .checked_add(15)
        .ok_or_else(|| invalid("fixture alignment allocation overflow"))?;
    let mut storage = vec![0_u8; storage_bytes];
    let base_residue = storage.as_ptr().addr() & 15;
    let start = usize::from(row.alignment_offset).wrapping_sub(base_residue) & 15;
    let end = start
        .checked_add(row.bytes)
        .ok_or_else(|| invalid("fixture aligned slice overflow"))?;
    storage[start..end].copy_from_slice(&bytes);
    require(
        storage[start..].as_ptr().addr() & 15 == usize::from(row.alignment_offset),
        "fixture alignment construction failed",
    )?;
    Ok(AlignedFixture {
        storage,
        start,
        row: row.clone(),
    })
}

fn verify_oracle(haystack: &[u8], literal: &[u8], row: &FixtureRow) -> Result<(), DynError> {
    let (leftmost, count) = scalar_oracle(haystack, literal);
    require(
        leftmost == row.expected_leftmost_span && count == row.expected_nonoverlapping_count,
        "scalar oracle differs from fixture manifest",
    )
    .map_err(Into::into)
}

fn scalar_oracle(haystack: &[u8], literal: &[u8]) -> (Option<[usize; 2]>, usize) {
    let leftmost = haystack
        .windows(literal.len())
        .position(|window| window == literal)
        .map(|start| {
            [
                start,
                start
                    .checked_add(literal.len())
                    .expect("matching window is in bounds"),
            ]
        });
    let mut count = 0_usize;
    let mut cursor = 0_usize;
    while cursor <= haystack.len().saturating_sub(literal.len()) {
        let Some(relative) = haystack[cursor..]
            .windows(literal.len())
            .position(|window| window == literal)
        else {
            break;
        };
        cursor = cursor
            .checked_add(relative)
            .and_then(|value| value.checked_add(literal.len()))
            .expect("matching window advances within the haystack");
        count = count.checked_add(1).expect("count bounded by haystack");
    }
    (leftmost, count)
}

fn canonical_fixture_root(path: &Path) -> Result<PathBuf, DynError> {
    let root = fs::canonicalize(path)?;
    require(
        fs::metadata(&root)?.is_dir(),
        "fixture root is not a directory",
    )?;
    Ok(root)
}

fn regular_file(path: &Path, maximum: u64) -> Result<Vec<u8>, DynError> {
    let metadata = fs::symlink_metadata(path)?;
    require(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= maximum,
        "fixture input is not one bounded regular file",
    )?;
    Ok(fs::read(path)?)
}

fn canonical_relative(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && path
            .split('/')
            .all(|component| !matches!(component, "" | "." | ".."))
}

fn decode_hex(value: &str) -> Result<Vec<u8>, DynError> {
    require(
        value.len().is_multiple_of(2) && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid lowercase hex",
    )?;
    let mut output = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let text = std::str::from_utf8(pair)?;
        output.push(u8::from_str_radix(text, 16)?);
    }
    Ok(output)
}

fn project(matched: Option<Match>) -> Option<[usize; 2]> {
    matched.map(|value| [value.start(), value.end()])
}

fn encode(matched: Option<Match>) -> u64 {
    matched.map_or(u64::MAX, |value| {
        u64::try_from(value.start())
            .unwrap_or(u64::MAX)
            .rotate_left(17)
            ^ u64::try_from(value.end()).unwrap_or(u64::MAX)
    })
}

fn tail_owned(row: &FixtureRow, literal_bytes: usize) -> Result<bool, io::Error> {
    if row.bytes < generated::MINIMUM_WINDOW_BYTES {
        return Ok(false);
    }
    let candidate_starts = row
        .bytes
        .checked_sub(literal_bytes)
        .and_then(|last| last.checked_add(1))
        .ok_or_else(|| invalid("literal is wider than fixture"))?;
    if candidate_starts <= generated::PORTABLE_PREFIX_CANDIDATE_STARTS {
        return Ok(false);
    }
    Ok(row
        .expected_leftmost_span
        .is_none_or(|[start, _]| start >= generated::PORTABLE_PREFIX_CANDIDATE_STARTS))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    hex_bytes(&digest)
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use std::fmt::Write as _;
        write!(output, "{byte:02x}").expect("String formatting");
    }
    output
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
