use std::{
    collections::BTreeSet,
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
const APPLICATION_FIXTURE_SCHEMA_V2: &str = "fre.aot.search-ripgrep-application-fixtures.v2";
const APPLICATION_FIXTURE_MANIFEST_SHA256_V2: &str =
    "b20181470c604d01d2ec236259293cfcb6e5eff145bcd3e4daa91554c8cebcca";
const APPLICATION_OBJECT_MANIFEST_SCHEMA_V1: &str =
    "fre.aot.search-tag29-application-object-candidates.v1";
const APPLICATION_OBJECT_MANIFEST_SHA256_V1: &str =
    "2e6612dc25e1186e0dd78597f045a4ece6ecc8dafcc2270cacc445be8753aff4";
const UNRESOLVED_BACKEND_PROVENANCE: &str = "required-unresolved-input";
const TAG29_BACKEND_PROVENANCE: &str = "required-tag29-frozen-input";
const TAG29_BACKEND_TAG: u16 = 29;
const TAG29_BACKEND_NAME: &str = "AsimdV16";
const TAG29_MINIMUM_WINDOW_BYTES: usize = 4_093;
const TAG29_PORTABLE_PREFIX_CANDIDATE_STARTS: usize = 256;
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

#[derive(Clone, Copy, Debug)]
struct FixtureBackendAuthority<'a> {
    linked: bool,
    fixture_manifest_schema: &'a str,
    fixture_manifest_sha256: &'a str,
    backend_tag: u16,
    backend_name: &'a str,
    family_selector: u16,
    minimum_window_bytes: usize,
    portable_prefix_candidate_starts: usize,
    identity_sha256: &'a str,
    runner_source_sha256: &'a str,
    object_manifest_schema: &'a str,
    object_manifest_sha256: &'a str,
    plan_identity: &'a str,
    analyzer_identity: &'a str,
    evidence_identity: &'a str,
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
    if !generated::LINKED {
        return Err(invalid(
            "runner is selector-neutral; rebuild with FRE_EXTERNAL_SEARCH_STATIC_IDENTITY",
        )
        .into());
    }
    match arguments.as_slice() {
        [mode, fixture_root] if mode == "inspect" => {
            let root = canonical_fixture_root(Path::new(fixture_root))?;
            let manifest = load_manifest(&root)?;
            inspect(&root, &manifest)
        }
        [mode, fixture_root, shard, shards] if mode == "run" => {
            require(
                generated::TIMING_PERMITTED,
                "linked identity does not permit development timing",
            )?;
            let root = canonical_fixture_root(Path::new(fixture_root))?;
            let manifest = load_manifest(&root)?;
            let shard = parse_usize(shard, "shard")?;
            let shards = parse_usize(shards, "shards")?;
            require(
                shards > 0 && shard < shards && shards <= manifest.payload.fixture_count,
                "invalid shard coordinates",
            )?;
            run(&root, &manifest, shard, shards)
        }
        _ => Err(invalid("usage: inspect FIXTURE_ROOT | run FIXTURE_ROOT SHARD SHARDS").into()),
    }
}

fn inspect(root: &Path, manifest: &FixtureManifest) -> Result<(), DynError> {
    let mut fixture_total = 0_usize;
    for candidate in &manifest.payload.candidates {
        let index = linked_candidate_index(candidate)?;
        let portable = build_portable(candidate)?;
        let verified = index.map(adopt).transpose()?;
        let automatic = verified
            .map(|verified| SearchExactLiteralAutoAotV1::bind(&portable, verified))
            .transpose()?;
        if let Some(automatic) = &automatic {
            require(
                automatic.literal_bytes() == u32::try_from(candidate.literal_bytes)?,
                "adopted literal width differs from fixture candidate",
            )?;
        }
        for row in &candidate.fixtures {
            let fixture = load_fixture(root, row)?;
            let literal = decode_hex(&candidate.literal_hex)?;
            verify_oracle(fixture.bytes(), &literal, row)?;
            let portable_match = portable
                .find_accounted(fixture.bytes(), SearchLimits::unlimited())?
                .0;
            let automatic_match = find_automatic(&portable, automatic.as_ref(), fixture.bytes())?;
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
    println!(
        "object_candidate_manifest_schema={}",
        generated::OBJECT_CANDIDATE_MANIFEST_SCHEMA
    );
    println!(
        "object_candidate_manifest_sha256={}",
        generated::OBJECT_CANDIDATE_MANIFEST_SHA256
    );
    println!("linked_object_candidates={}", generated::CANDIDATES.len());
    println!("candidates={}", manifest.payload.candidate_count);
    println!("fixtures={fixture_total}");
    println!("correctness=pass");
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "one auditable measurement transaction keeps sharding, calibration, paired ordering, semantic equality, minimum duration, and exact row emission adjacent"
)]
fn run(
    root: &Path,
    manifest: &FixtureManifest,
    shard: usize,
    shards: usize,
) -> Result<(), DynError> {
    let stdout = io::stdout();
    let mut output = BufWriter::new(stdout.lock());
    writeln!(
        output,
        "schema,identity_sha256,runner_source_sha256,backend_name,backend_tag,family_selector,candidate_sha256,literal_hex,scenario,fixture_sha256,alignment,repetition,order,engine,route,iterations,total_ns,ns_per_iter,checksum,semantic,expected_nonoverlapping_count,tail_owned"
    )?;
    let mut fixture_ordinal = 0_usize;
    let mut selected_fixtures = 0_usize;
    for candidate in &manifest.payload.candidates {
        let index = linked_candidate_index(candidate)?;
        let portable = build_portable(candidate)?;
        let verified = index.map(adopt).transpose()?;
        let automatic = verified
            .map(|verified| SearchExactLiteralAutoAotV1::bind(&portable, verified))
            .transpose()?;
        for row in &candidate.fixtures {
            let selected = fixture_ordinal
                .checked_rem(shards)
                .ok_or_else(|| invalid("zero shard count"))?
                == shard;
            fixture_ordinal = fixture_ordinal
                .checked_add(1)
                .ok_or_else(|| invalid("fixture ordinal overflow"))?;
            if !selected {
                continue;
            }
            selected_fixtures = selected_fixtures
                .checked_add(1)
                .ok_or_else(|| invalid("selected fixture count overflow"))?;
            let fixture = load_fixture(root, row)?;
            let literal = decode_hex(&candidate.literal_hex)?;
            verify_oracle(fixture.bytes(), &literal, row)?;
            verify_pair(&portable, automatic.as_ref(), fixture.bytes(), row)?;
            let iterations = calibrated_iterations(&portable, automatic.as_ref(), fixture.bytes())?;
            let tail_owned = tail_owned(row, automatic.is_some());
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
                        Engine::StaticAutoAot => measure_automatic(
                            &portable,
                            automatic.as_ref(),
                            fixture.bytes(),
                            iterations,
                        )?,
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
    require(
        fixture_ordinal == manifest.payload.fixture_count && selected_fixtures > 0,
        "sharded fixture traversal differs from manifest",
    )?;
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
    let literal = decode_hex(&candidate.literal_hex)?;
    let portable = if generated::CANONICAL_BYTE_ESCAPED_SOURCES {
        PortableBuilder::new(canonical_exact_source(&literal)).build()?
    } else {
        PortableBuilder::new(String::from_utf8(literal.clone())?)
            .unicode(true)
            .build()?
    };
    let exact = portable
        .exact_literal_search_aot_candidate()
        .ok_or_else(|| invalid("fixture source is not an exact-literal AOT candidate"))?;
    require(
        exact.literal() == literal && sha256_hex(exact.literal()) == candidate.literal_sha256,
        "portable candidate literal differs from external identity",
    )?;
    Ok(portable)
}

fn linked_candidate_index(candidate: &FixtureCandidate) -> Result<Option<usize>, io::Error> {
    let mut matches = generated::CANDIDATES
        .iter()
        .enumerate()
        .filter(|(_, linked)| {
            linked.semantic_candidate_sha256 == candidate.semantic_candidate_sha256
                && linked.literal_hex == candidate.literal_hex
        });
    let index = matches.next().map(|(index, _)| index);
    require(
        matches.next().is_none(),
        "fixture candidate maps to multiple linked object/glue pairs",
    )?;
    Ok(index)
}

fn verify_pair(
    portable: &PortableRegex,
    automatic: Option<&SearchExactLiteralAutoAotV1<'_>>,
    haystack: &[u8],
    row: &FixtureRow,
) -> Result<(), DynError> {
    let portable_match = portable
        .find_accounted(haystack, SearchLimits::unlimited())?
        .0;
    let automatic_match = find_automatic(portable, automatic, haystack)?;
    require(
        project(portable_match) == row.expected_leftmost_span
            && project(automatic_match) == row.expected_leftmost_span,
        "paired facade correctness differs",
    )
    .map_err(Into::into)
}

fn calibrated_iterations(
    portable: &PortableRegex,
    automatic: Option<&SearchExactLiteralAutoAotV1<'_>>,
    haystack: &[u8],
) -> Result<usize, DynError> {
    let portable_pilot = pilot_portable(portable, haystack)?;
    let automatic_pilot = pilot_automatic(portable, automatic, haystack)?;
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
    portable: &PortableRegex,
    automatic: Option<&SearchExactLiteralAutoAotV1<'_>>,
    haystack: &[u8],
) -> Result<Measurement, DynError> {
    let mut iterations = 1_usize;
    loop {
        let measured = measure_automatic(portable, automatic, haystack, iterations)?;
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
            .find_accounted(black_box(haystack), SearchLimits::unlimited())?
            .0)
    })
}

fn measure_automatic(
    portable: &PortableRegex,
    automatic: Option<&SearchExactLiteralAutoAotV1<'_>>,
    haystack: &[u8],
    iterations: usize,
) -> Result<Measurement, DynError> {
    measure(iterations, || {
        find_automatic(portable, automatic, black_box(haystack))
    })
}

fn find_automatic(
    portable: &PortableRegex,
    automatic: Option<&SearchExactLiteralAutoAotV1<'_>>,
    haystack: &[u8],
) -> Result<Option<Match>, DynError> {
    if let Some(automatic) = automatic {
        Ok(automatic.find(haystack, SearchLimits::unlimited())?.0)
    } else {
        Ok(portable
            .find_accounted(haystack, SearchLimits::unlimited())?
            .0)
    }
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
    let (expected_sha256, expected_schema) = if generated::CANONICAL_BYTE_ESCAPED_SOURCES {
        (
            generated::FIXTURE_MANIFEST_SHA256,
            generated::FIXTURE_MANIFEST_SCHEMA,
        )
    } else {
        (FIXTURE_MANIFEST_SHA256, FIXTURE_SCHEMA)
    };
    require(
        sha256_hex(&bytes) == expected_sha256,
        "fixture manifest SHA-256 differs",
    )?;
    let manifest: FixtureManifest = serde_json::from_slice(&bytes)?;
    require(manifest.schema == expected_schema, "fixture schema differs")?;
    require(
        manifest.payload_sha256.len() == 64,
        "fixture payload identity is malformed",
    )?;
    let backend_authority = FixtureBackendAuthority {
        linked: generated::LINKED,
        fixture_manifest_schema: expected_schema,
        fixture_manifest_sha256: expected_sha256,
        backend_tag: generated::BACKEND_TAG,
        backend_name: generated::BACKEND_NAME,
        family_selector: generated::FAMILY_SELECTOR,
        minimum_window_bytes: generated::MINIMUM_WINDOW_BYTES,
        portable_prefix_candidate_starts: generated::PORTABLE_PREFIX_CANDIDATE_STARTS,
        identity_sha256: generated::IDENTITY_SHA256,
        runner_source_sha256: generated::RUNNER_SOURCE_SHA256,
        object_manifest_schema: generated::OBJECT_CANDIDATE_MANIFEST_SCHEMA,
        object_manifest_sha256: generated::OBJECT_CANDIDATE_MANIFEST_SHA256,
        plan_identity: generated::PLAN_IDENTITY,
        analyzer_identity: generated::ANALYZER_IDENTITY,
        evidence_identity: generated::EVIDENCE_IDENTITY,
    };
    require(
        fixture_backend_contract_is_admissible(
            &manifest.payload.backend_identity,
            manifest.payload.timing_permitted,
            backend_authority,
        ),
        "immutable fixture generator improperly granted backend/timing authority",
    )?;
    require(
        manifest.payload.candidate_count == manifest.payload.candidates.len()
            && manifest.payload.fixture_bytes_each == 1_048_576,
        "fixture cardinality differs",
    )?;
    let mut fixture_count = 0_usize;
    let mut linked_indexes = BTreeSet::new();
    for candidate in &manifest.payload.candidates {
        if let Some(index) = linked_candidate_index(candidate)? {
            let linked = generated::CANDIDATES
                .get(index)
                .ok_or_else(|| invalid("linked object candidate index is invalid"))?;
            require(
                !linked.implementation_sha256.is_empty()
                    && !linked.glue_sha256.is_empty()
                    && linked_indexes.insert(index),
                "linked candidate identity differs or is duplicated",
            )?;
        }
        fixture_count = fixture_count
            .checked_add(candidate.fixtures.len())
            .ok_or_else(|| invalid("fixture cardinality overflow"))?;
    }
    require(
        fixture_count == manifest.payload.fixture_count
            && linked_indexes.len() == generated::CANDIDATES.len(),
        "fixture row or linked-object cardinality differs",
    )?;
    Ok(manifest)
}

fn fixture_backend_contract_is_admissible(
    fixture_backend_provenance: &str,
    fixture_timing_permitted: bool,
    authority: FixtureBackendAuthority<'_>,
) -> bool {
    if fixture_timing_permitted {
        return false;
    }
    if fixture_backend_provenance == UNRESOLVED_BACKEND_PROVENANCE {
        return true;
    }
    fixture_backend_provenance == TAG29_BACKEND_PROVENANCE
        && authority.linked
        && authority.fixture_manifest_schema == APPLICATION_FIXTURE_SCHEMA_V2
        && authority.fixture_manifest_sha256 == APPLICATION_FIXTURE_MANIFEST_SHA256_V2
        && authority.backend_tag == TAG29_BACKEND_TAG
        && authority.backend_name == TAG29_BACKEND_NAME
        && authority.family_selector > 0
        && authority.minimum_window_bytes == TAG29_MINIMUM_WINDOW_BYTES
        && authority.portable_prefix_candidate_starts == TAG29_PORTABLE_PREFIX_CANDIDATE_STARTS
        && authority.object_manifest_schema == APPLICATION_OBJECT_MANIFEST_SCHEMA_V1
        && authority.object_manifest_sha256 == APPLICATION_OBJECT_MANIFEST_SHA256_V1
        && pinned_sha256(authority.identity_sha256)
        && pinned_sha256(authority.runner_source_sha256)
        && pinned_sha256(authority.plan_identity)
        && pinned_sha256(authority.analyzer_identity)
        && pinned_sha256(authority.evidence_identity)
}

fn pinned_sha256(value: &str) -> bool {
    value.len() == 64
        && value != "0000000000000000000000000000000000000000000000000000000000000000"
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

fn canonical_exact_source(literal: &[u8]) -> String {
    let mut source = String::with_capacity(
        literal
            .len()
            .checked_mul(4)
            .and_then(|bytes| bytes.checked_add(6))
            .expect("bounded fixture literal source"),
    );
    source.push_str("(?-u:");
    for byte in literal {
        use std::fmt::Write as _;
        write!(source, "\\x{byte:02x}").expect("String formatting");
    }
    source.push(')');
    source
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

fn tail_owned(row: &FixtureRow, eligible: bool) -> bool {
    eligible && !matches!(row.scenario.as_str(), "early" | "dense")
}

fn parse_usize(value: &str, label: &str) -> Result<usize, io::Error> {
    require(
        !value.is_empty()
            && value.bytes().all(|byte| byte.is_ascii_digit())
            && (value == "0" || !value.starts_with('0')),
        &format!("{label} is not a canonical unsigned integer"),
    )?;
    value
        .parse()
        .map_err(|_| invalid(format!("{label} is out of range")))
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

#[cfg(test)]
mod tests {
    use super::{
        APPLICATION_FIXTURE_MANIFEST_SHA256_V2, APPLICATION_FIXTURE_SCHEMA_V2,
        APPLICATION_OBJECT_MANIFEST_SCHEMA_V1, APPLICATION_OBJECT_MANIFEST_SHA256_V1,
        FixtureBackendAuthority, TAG29_BACKEND_PROVENANCE, UNRESOLVED_BACKEND_PROVENANCE,
        fixture_backend_contract_is_admissible,
    };

    const PIN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn tag29_authority() -> FixtureBackendAuthority<'static> {
        FixtureBackendAuthority {
            linked: true,
            fixture_manifest_schema: APPLICATION_FIXTURE_SCHEMA_V2,
            fixture_manifest_sha256: APPLICATION_FIXTURE_MANIFEST_SHA256_V2,
            backend_tag: 29,
            backend_name: "AsimdV16",
            family_selector: 17,
            minimum_window_bytes: 4_093,
            portable_prefix_candidate_starts: 256,
            identity_sha256: PIN,
            runner_source_sha256: PIN,
            object_manifest_schema: APPLICATION_OBJECT_MANIFEST_SCHEMA_V1,
            object_manifest_sha256: APPLICATION_OBJECT_MANIFEST_SHA256_V1,
            plan_identity: PIN,
            analyzer_identity: PIN,
            evidence_identity: PIN,
        }
    }

    #[test]
    fn exact_application_provenance_requires_independent_tag29_authority() {
        assert!(fixture_backend_contract_is_admissible(
            TAG29_BACKEND_PROVENANCE,
            false,
            tag29_authority(),
        ));
    }

    #[test]
    fn application_fixture_label_cannot_select_or_authorize_a_backend() {
        let mut authority = tag29_authority();
        authority.backend_tag = 28;
        assert!(!fixture_backend_contract_is_admissible(
            TAG29_BACKEND_PROVENANCE,
            false,
            authority,
        ));

        authority = tag29_authority();
        authority.backend_name = "unresolved";
        assert!(!fixture_backend_contract_is_admissible(
            TAG29_BACKEND_PROVENANCE,
            false,
            authority,
        ));

        authority = tag29_authority();
        authority.identity_sha256 = "unresolved";
        assert!(!fixture_backend_contract_is_admissible(
            TAG29_BACKEND_PROVENANCE,
            false,
            authority,
        ));

        authority = tag29_authority();
        authority.object_manifest_sha256 = PIN;
        assert!(!fixture_backend_contract_is_admissible(
            TAG29_BACKEND_PROVENANCE,
            false,
            authority,
        ));

        authority = tag29_authority();
        authority.fixture_manifest_sha256 = PIN;
        assert!(!fixture_backend_contract_is_admissible(
            TAG29_BACKEND_PROVENANCE,
            false,
            authority,
        ));

        assert!(!fixture_backend_contract_is_admissible(
            TAG29_BACKEND_PROVENANCE,
            true,
            tag29_authority(),
        ));
    }

    #[test]
    fn unresolved_fixture_provenance_remains_backend_neutral() {
        let mut authority = tag29_authority();
        authority.linked = false;
        authority.backend_tag = 0;
        authority.backend_name = "unresolved";
        authority.identity_sha256 = "unresolved";
        assert!(fixture_backend_contract_is_admissible(
            UNRESOLVED_BACKEND_PROVENANCE,
            false,
            authority,
        ));
        assert!(!fixture_backend_contract_is_admissible(
            "fixture-selected-backend",
            false,
            authority,
        ));
        assert!(!fixture_backend_contract_is_admissible(
            UNRESOLVED_BACKEND_PROVENANCE,
            true,
            authority,
        ));
    }
}
