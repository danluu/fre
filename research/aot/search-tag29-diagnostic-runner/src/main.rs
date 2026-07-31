#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::too_many_lines,
    reason = "the bounded non-authoritative harness keeps fixture geometry and paired timing linear and explicit"
)]

use std::{
    collections::{HashMap, hash_map::Entry},
    error::Error,
    fs::{File, OpenOptions},
    hint::black_box,
    io::{self, BufRead as _, BufReader, BufWriter, Write as _},
    path::Path,
    time::Instant,
};

use fre::{
    Match, PortableBuilder, PortableRegex, SearchExactLiteralAutoAotV1, SearchLimits, SearchWindow,
};
use fre_aot_static_runtime::{
    RawStaticSearchSpanAdoptionOutputV1, VerifiedStaticSearchSpanV1,
    adopt_linked_static_search_span_family_qualification_v1,
};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest as _, Sha256};

#[allow(
    clippy::too_many_lines,
    dead_code,
    unsafe_code,
    reason = "generated declarations include sealed-runner fields not consumed by the diagnostic"
)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/generated.rs"));
}

type DynError = Box<dyn Error>;

const ROW_SCHEMA: &str = "fre.aot.search-tag29-topology-projection.v1";
const RESULT_SCHEMA: &str = "fre.aot.search-tag29-diagnostic-result.v1";
const CHECKSUM_SEED: u64 = 0x6a09_e667_f3bc_c909;
const CALIBRATION_FLOOR_NS: u64 = 100_000;
const MAXIMUM_ITERATIONS: usize = 1 << 30;
const MAXIMUM_ROW_BYTES: usize = 16 * 1024;
const PROJECTION_DOMAIN: &[u8] = b"FRE-SEARCH-TAG29-TOPOLOGY-PROJECTION\0\x01";
const FULL_PROJECTION_ROWS: usize = 123_424;
const FULL_PROJECTION_SHA256: &str =
    "5d548159e8c93d6ddb8d57847e01cc97ea2b661f736b2e8a126df6cd35cf612f";
const TIMED_PROJECTION_ROWS: usize = 3_078;
const TIMED_PROJECTION_SHA256: &str =
    "72d85a032a90e4347be2d537c2ff11bac15016787c055332843f143da72e487f";
const EXPECTED_CANDIDATES: usize = 808;
const EXPECTED_UNIQUE_LITERALS: usize = 922;

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
struct Fixture {
    storage: Vec<u8>,
    start: usize,
    bytes: usize,
    window: SearchWindow,
}

impl Fixture {
    fn haystack(&self) -> &[u8] {
        &self.storage[self.start..self.start + self.bytes]
    }
}

#[derive(Clone, Copy, Debug)]
struct Measurement {
    iterations: usize,
    elapsed_ns: u64,
    checksum: u64,
}

fn main() -> Result<(), DynError> {
    require(generated::LINKED, "diagnostic runner was not linked")?;
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [mode, projection] if mode == "correctness" => correctness(Path::new(projection)),
        [mode, projection, target_ns, repetitions, output] if mode == "timing" => timing(
            Path::new(projection),
            target_ns.parse()?,
            repetitions.parse()?,
            Path::new(output),
        ),
        _ => Err(invalid(
            "usage: correctness PROJECTION | timing PROJECTION TARGET_NS REPETITIONS NEW_OUTPUT",
        )
        .into()),
    }
}

fn correctness(projection: &Path) -> Result<(), DynError> {
    validate_projection(projection, FULL_PROJECTION_ROWS, FULL_PROJECTION_SHA256)?;
    let candidate_indices = candidate_indices()?;
    let mut engines = HashMap::new();
    let mut rows = 0_usize;
    let mut static_rows = 0_usize;
    let mut portable_rows = 0_usize;
    for row in projection_rows(projection)? {
        let row = row?;
        validate_row(&row)?;
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
        if row.selector_eligible {
            let automatic = SearchExactLiteralAutoAotV1::bind(
                &engine.portable,
                engine
                    .verified
                    .ok_or_else(|| invalid("eligible literal lacks static object"))?,
            )?;
            let candidate = automatic
                .find_window(
                    fixture.haystack(),
                    fixture.window,
                    SearchLimits::unlimited(),
                )?
                .0;
            require(
                project(candidate) == expected,
                "automatic AOT correctness mismatch",
            )?;
        } else {
            require(
                engine.verified.is_none(),
                "structural refusal unexpectedly has a static object",
            )?;
        }
        rows = rows.checked_add(1).ok_or_else(|| invalid("row overflow"))?;
        if row.expected_static_invoked {
            static_rows = static_rows
                .checked_add(1)
                .ok_or_else(|| invalid("static-row overflow"))?;
        } else {
            portable_rows = portable_rows
                .checked_add(1)
                .ok_or_else(|| invalid("portable-row overflow"))?;
        }
    }
    require(
        rows == FULL_PROJECTION_ROWS
            && engines.len() == EXPECTED_UNIQUE_LITERALS
            && static_rows == 49_248
            && portable_rows == 74_176,
        "full projection totals changed",
    )?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "schema": "fre.aot.search-tag29-diagnostic-correctness-summary.v1",
            "rows": rows,
            "unique_literals": engines.len(),
            "expected_static_rows": static_rows,
            "expected_portable_rows": portable_rows,
            "correctness": "PASS",
            "promotion_authority": false,
            "rebar_accepted_as_input": false,
        }))?
    );
    Ok(())
}

fn timing(
    projection: &Path,
    target_ns: u64,
    repetitions: usize,
    output: &Path,
) -> Result<(), DynError> {
    require(
        (100_000..=1_000_000_000).contains(&target_ns),
        "target duration is outside diagnostic bounds",
    )?;
    require(
        (1..=12).contains(&repetitions),
        "repetition count is outside bounds",
    )?;
    validate_projection(projection, TIMED_PROJECTION_ROWS, TIMED_PROJECTION_SHA256)?;
    let output_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    let mut writer = BufWriter::new(output_file);
    let candidate_indices = candidate_indices()?;
    let mut engines = HashMap::new();
    let mut rows = 0_usize;
    for row in projection_rows(projection)? {
        let row = row?;
        validate_row(&row)?;
        require(
            row.selector_eligible && row.expected_static_invoked,
            "timed projection contains a non-static row",
        )?;
        let fixture = materialize(&row)?;
        let expected = expected_match(&row);
        let engine = engine_for(&mut engines, &candidate_indices, &row)?;
        let automatic = SearchExactLiteralAutoAotV1::bind(
            &engine.portable,
            engine
                .verified
                .ok_or_else(|| invalid("timed literal lacks static object"))?,
        )?;
        verify_pair(&engine.portable, &automatic, &fixture, expected)?;
        let iterations = calibrated_iterations(&engine.portable, &automatic, &fixture, target_ns)?;
        let mut pairs = Vec::with_capacity(repetitions);
        for repetition in 0..repetitions {
            let (portable, candidate, order) = if repetition % 2 == 0 {
                (
                    measure_portable(&engine.portable, &fixture, iterations)?,
                    measure_candidate(&automatic, &fixture, iterations)?,
                    "portable-first",
                )
            } else {
                let candidate = measure_candidate(&automatic, &fixture, iterations)?;
                let portable = measure_portable(&engine.portable, &fixture, iterations)?;
                (portable, candidate, "candidate-first")
            };
            require(
                portable.iterations == candidate.iterations
                    && portable.checksum == candidate.checksum,
                "timed pair semantics differ",
            )?;
            pairs.push(json!({
                "repetition": repetition,
                "order": order,
                "iterations": iterations,
                "portable_elapsed_ns": portable.elapsed_ns,
                "candidate_elapsed_ns": candidate.elapsed_ns,
                "portable_checksum": portable.checksum,
                "candidate_checksum": candidate.checksum,
            }));
        }
        writeln!(
            writer,
            "{}",
            serde_json::to_string(&json!({
                "schema": RESULT_SCHEMA,
                "row_sha256": row.row_sha256,
                "literal_sha256": row.literal_sha256,
                "literal_bytes": row.literal_bytes,
                "topology": row.topology,
                "mutation_class": row.mutation_class,
                "learned_source_kind": row.learned_source_kind,
                "literal_phase_class": row.literal_phase_class,
                "selector_primary_offset_class": row.selector_primary_offset_class,
                "logical_prefix_bytes": row.logical_prefix_bytes,
                "window_bytes": row.window_bytes,
                "outcome": row.outcome,
                "right_guarded": row.right_guarded,
                "expected_route": row.expected_route,
                "target_ns": target_ns,
                "pairs": pairs,
                "promotion_authority": false,
                "rebar_accepted_as_input": false,
            }))?
        )?;
        rows = rows.checked_add(1).ok_or_else(|| invalid("row overflow"))?;
    }
    require(
        rows == TIMED_PROJECTION_ROWS && engines.len() == EXPECTED_CANDIDATES,
        "timed projection totals changed",
    )?;
    writer.flush()?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "schema": "fre.aot.search-tag29-diagnostic-timing-summary.v1",
            "rows": rows,
            "unique_literals": engines.len(),
            "target_ns": target_ns,
            "repetitions": repetitions,
            "output": output,
            "promotion_authority": false,
            "rebar_accepted_as_input": false,
        }))?
    );
    Ok(())
}

fn projection_rows(
    path: &Path,
) -> Result<impl Iterator<Item = Result<ProjectionRow, DynError>>, DynError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    Ok(reader.lines().enumerate().map(|(index, line)| {
        let line = line?;
        require(
            !line.is_empty() && line.len() <= MAXIMUM_ROW_BYTES,
            "projection row violates its byte bound",
        )?;
        serde_json::from_str(&line)
            .map_err(|error| format!("projection row {}: {error}", index + 1).into())
    }))
}

fn validate_projection(
    path: &Path,
    expected_rows: usize,
    expected_sha256: &str,
) -> Result<(), DynError> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut digest = Sha256::new();
    digest.update(PROJECTION_DOMAIN);
    let mut encoded = Vec::with_capacity(MAXIMUM_ROW_BYTES + 1);
    let mut rows = 0_usize;
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
        rows = rows
            .checked_add(1)
            .ok_or_else(|| invalid("projection row count overflow"))?;
    }
    let actual: [u8; 32] = digest.finalize().into();
    require(
        rows == expected_rows && hex(&actual) == expected_sha256,
        "projection identity changed",
    )
    .map_err(Into::into)
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
    reason = "the generated glue selector is validated by the static runtime"
)]
fn adopt(index: usize) -> Result<&'static VerifiedStaticSearchSpanV1, DynError> {
    // SAFETY: generated::invoke selects a receipt-bound retained glue symbol;
    // the runtime independently validates the family before exposing a handle.
    let verified = unsafe {
        adopt_linked_static_search_span_family_qualification_v1(
            |output: *mut RawStaticSearchSpanAdoptionOutputV1| generated::invoke(index, output),
        )
    }?;
    require(
        verified.row_selector() == generated::FAMILY_SELECTOR,
        "adopted family selector changed",
    )?;
    Ok(verified)
}

fn validate_row(row: &ProjectionRow) -> Result<(), io::Error> {
    require(row.schema == ROW_SCHEMA, "projection schema changed")?;
    require(
        row.fixture_recipe.construction_version == "near-miss-sentinel-tile-tail-v1"
            && row.fixture_recipe.scalar_oracle_required
            && row.literal_bytes == row.literal_hex.len() / 2
            && row.literal_bytes >= 4
            && row.literal_bytes <= 32
            && row.fixture_recipe.window_start == row.logical_prefix_bytes
            && row.fixture_recipe.window_end == row.logical_prefix_bytes + row.window_bytes
            && row.fixture_recipe.true_literal_guard_bytes + 1 == row.literal_bytes
            && row.expected_physical_window_start_mod16 < 16
            && row.expected_compiler_disposition
                == if row.selector_eligible {
                    "tag29-object"
                } else {
                    "structural-refusal"
                }
            && row.expected_static_invoked == (row.expected_route == "tag29-static-tail"),
        "projection row contract changed",
    )
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
    let haystack_bytes = window_end
        .checked_add(32)
        .ok_or_else(|| invalid("fixture extent overflow"))?;
    let mut storage = vec![row.fixture_recipe.background_byte; haystack_bytes + 64];
    let base = storage.as_ptr() as usize;
    let desired_base_mod = (row.expected_physical_window_start_mod16 + 16 - window_start % 16) % 16;
    let start = 32 + (desired_base_mod + 16 - base % 16) % 16;
    let haystack = &mut storage[start..start + haystack_bytes];
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
    require(
        (haystack.as_ptr() as usize + window_start) % 16
            == row.expected_physical_window_start_mod16,
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
        start,
        bytes: haystack_bytes,
        window: SearchWindow::new(window_start, window_end),
    })
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
    automatic: &SearchExactLiteralAutoAotV1<'_>,
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
    let candidate_match = automatic
        .find_window(
            fixture.haystack(),
            fixture.window,
            SearchLimits::unlimited(),
        )?
        .0;
    require(
        project(portable_match) == expected && project(candidate_match) == expected,
        "paired correctness mismatch",
    )
    .map_err(Into::into)
}

fn calibrated_iterations(
    portable: &PortableRegex,
    automatic: &SearchExactLiteralAutoAotV1<'_>,
    fixture: &Fixture,
    target_ns: u64,
) -> Result<usize, DynError> {
    let portable_pilot = pilot(|iterations| measure_portable(portable, fixture, iterations))?;
    let candidate_pilot = pilot(|iterations| measure_candidate(automatic, fixture, iterations))?;
    require(
        portable_pilot.checksum == candidate_pilot.checksum
            || portable_pilot.iterations != candidate_pilot.iterations,
        "pilot semantics differ",
    )?;
    let portable_iterations = scaled_iterations(target_ns, portable_pilot)?;
    let candidate_iterations = scaled_iterations(target_ns, candidate_pilot)?;
    Ok(portable_iterations.max(candidate_iterations))
}

fn pilot(
    mut measure: impl FnMut(usize) -> Result<Measurement, DynError>,
) -> Result<Measurement, DynError> {
    let mut iterations = 1_usize;
    loop {
        let result = measure(iterations)?;
        if result.elapsed_ns >= CALIBRATION_FLOOR_NS || iterations == MAXIMUM_ITERATIONS {
            return Ok(result);
        }
        iterations = iterations
            .checked_mul(4)
            .unwrap_or(MAXIMUM_ITERATIONS)
            .min(MAXIMUM_ITERATIONS);
    }
}

fn scaled_iterations(target_ns: u64, pilot: Measurement) -> Result<usize, io::Error> {
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
) -> Result<Measurement, DynError> {
    let mut checksum = CHECKSUM_SEED;
    let start = Instant::now();
    for _ in 0..iterations {
        let matched = portable
            .find_window(
                black_box(fixture.haystack()),
                fixture.window,
                SearchLimits::unlimited(),
            )?
            .0;
        checksum = mix(checksum, encode(matched));
    }
    let elapsed_ns = u64::try_from(start.elapsed().as_nanos())?;
    black_box(checksum);
    Ok(Measurement {
        iterations,
        elapsed_ns,
        checksum,
    })
}

fn measure_candidate(
    automatic: &SearchExactLiteralAutoAotV1<'_>,
    fixture: &Fixture,
    iterations: usize,
) -> Result<Measurement, DynError> {
    let mut checksum = CHECKSUM_SEED;
    let start = Instant::now();
    for _ in 0..iterations {
        let matched = automatic
            .find_window(
                black_box(fixture.haystack()),
                fixture.window,
                SearchLimits::unlimited(),
            )?
            .0;
        checksum = mix(checksum, encode(matched));
    }
    let elapsed_ns = u64::try_from(start.elapsed().as_nanos())?;
    black_box(checksum);
    Ok(Measurement {
        iterations,
        elapsed_ns,
        checksum,
    })
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
    require(value.len().is_multiple_of(2), "hex input has odd length")?;
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| invalid("hex input is not UTF-8"))?;
            u8::from_str_radix(text, 16).map_err(|_| invalid("hex input is malformed"))
        })
        .collect()
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
