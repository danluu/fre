//! Deterministic qualification manifests derived from `rebar measure --list`.
//!
//! The list output contains only four columns. This crate deliberately marks
//! facts not established by those columns (or by the two audited adapters)
//! as unknown instead of filling them with plausible defaults.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::Read;

use serde::Serialize;

pub const SCHEMA_VERSION: &str = "fre.rebar-qualification-manifest.v1";
pub const RUST_ADAPTER: &str = "RebarRustMetaBytes100MBuildMany";
pub const RE2_ADAPTER: &str = "RebarRe2MatchLoopByteAdvance";

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct InventoryRecord {
    pub full_name: String,
    pub model: String,
    pub engine_name: String,
    pub engine_version: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Manifest {
    pub schema_version: &'static str,
    pub source: Source,
    pub jobs: Vec<Job>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Source {
    pub format: &'static str,
    pub command: &'static str,
    pub runner_revision: String,
    pub revision_provenance: &'static str,
    pub record_count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct Job {
    pub job_id: String,
    pub identity: Identity,
    pub benchmark: Benchmark,
    pub model: String,
    pub engine: Engine,
    pub runner_revision: String,
    pub adapter: Adapter,
    pub operation_progress_wrapper: EvidenceValue,
    pub output_reducer: EvidenceValue,
    pub timed_boundary: EvidenceValue,
    pub cache_state: EvidenceValue,
    pub semantic_comparator: SemanticComparator,
}

#[derive(Clone, Debug, Serialize)]
pub struct Identity {
    pub full_name: String,
    pub model: String,
    pub engine_name: String,
    pub engine_version: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Benchmark {
    pub full_name: String,
    pub definition: String,
    pub case: String,
    pub split_provenance: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct Engine {
    pub name: String,
    pub version: String,
    pub availability: Availability,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Reported,
    ErrorReportedByRebar,
}

#[derive(Clone, Debug, Serialize)]
pub struct Adapter {
    pub name: EvidenceValue,
    pub constructor: EvidenceValue,
    pub configuration: EvidenceValue,
    pub limits: EvidenceValue,
}

#[derive(Clone, Debug, Serialize)]
pub struct EvidenceValue {
    pub status: FactStatus,
    pub value: Option<String>,
    pub evidence: String,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FactStatus {
    Known,
    Unknown,
}

#[derive(Clone, Debug, Serialize)]
pub struct SemanticComparator {
    pub status: ComparatorStatus,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparatorStatus {
    Unverified,
}

impl EvidenceValue {
    fn known(value: impl Into<String>, evidence: impl Into<String>) -> Self {
        Self {
            status: FactStatus::Known,
            value: Some(value.into()),
            evidence: evidence.into(),
        }
    }

    fn unknown(reason: impl Into<String>) -> Self {
        Self {
            status: FactStatus::Unknown,
            value: None,
            evidence: reason.into(),
        }
    }
}

/// Parse the headerless CSV emitted by `rebar measure --list`.
///
/// # Errors
///
/// Returns an error for malformed CSV, rows other than four nonempty columns,
/// malformed benchmark full names, or duplicate job identities.
pub fn parse_inventory(reader: impl Read) -> Result<Vec<InventoryRecord>, String> {
    let mut csv = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(false)
        .from_reader(reader);
    let mut records = Vec::new();
    let mut seen = BTreeSet::new();
    for (index, row) in csv.records().enumerate() {
        // A `Vec` cannot contain `usize::MAX` records, but use saturating
        // display arithmetic so diagnostics do not rely on that platform fact.
        let record_number = index.saturating_add(1);
        let row = row.map_err(|err| format!("CSV record {record_number}: {err}"))?;
        if row.len() != 4 {
            return Err(format!(
                "CSV record {}: expected 4 columns, found {}",
                record_number,
                row.len()
            ));
        }
        if row.iter().any(str::is_empty) {
            return Err(format!(
                "CSV record {record_number}: columns must not be empty"
            ));
        }
        let record = InventoryRecord {
            full_name: row[0].to_owned(),
            model: row[1].to_owned(),
            engine_name: row[2].to_owned(),
            engine_version: row[3].to_owned(),
        };
        split_benchmark_name(&record.full_name)
            .map_err(|err| format!("CSV record {record_number}: {err}"))?;
        if !seen.insert(record.clone()) {
            return Err(format!(
                "CSV record {}: duplicate job ({}, {}, {}, {})",
                record_number,
                record.full_name,
                record.model,
                record.engine_name,
                record.engine_version
            ));
        }
        records.push(record);
    }
    records.sort();
    Ok(records)
}

fn split_benchmark_name(full_name: &str) -> Result<(&str, &str), String> {
    let Some((definition, case)) = full_name.rsplit_once('/') else {
        return Err(format!(
            "benchmark name {full_name:?} has no definition/case separator"
        ));
    };
    if definition.is_empty() || case.is_empty() {
        return Err(format!(
            "benchmark name {full_name:?} has an empty component"
        ));
    }
    Ok((definition, case))
}

/// Build the deterministic manifest for a validated inventory.
///
/// # Errors
///
/// Returns an error when `runner_revision` is not a full hexadecimal Git
/// object ID or a programmatically supplied record has a malformed full name.
pub fn build_manifest(
    records: Vec<InventoryRecord>,
    runner_revision: &str,
) -> Result<Manifest, String> {
    validate_revision(runner_revision)?;
    let record_count = records.len();
    let mut jobs = Vec::with_capacity(record_count);
    for (index, record) in records.into_iter().enumerate() {
        let (definition, case) = split_benchmark_name(&record.full_name)?;
        let details = adapter_details(&record.engine_name, &record.model);
        jobs.push(Job {
            job_id: format!("rebar-{index:06}"),
            identity: Identity {
                full_name: record.full_name.clone(),
                model: record.model.clone(),
                engine_name: record.engine_name.clone(),
                engine_version: record.engine_version.clone(),
            },
            benchmark: Benchmark {
                full_name: record.full_name.clone(),
                definition: definition.to_owned(),
                case: case.to_owned(),
                split_provenance: "Rebar full names are definition/name; split at the final slash",
            },
            model: record.model.clone(),
            engine: Engine {
                name: record.engine_name,
                availability: if record.engine_version == "ERROR" {
                    Availability::ErrorReportedByRebar
                } else {
                    Availability::Reported
                },
                version: record.engine_version,
            },
            runner_revision: runner_revision.to_owned(),
            adapter: details.adapter,
            operation_progress_wrapper: details.operation_progress_wrapper,
            output_reducer: details.output_reducer,
            timed_boundary: details.timed_boundary,
            cache_state: details.cache_state,
            semantic_comparator: SemanticComparator {
                status: ComparatorStatus::Unverified,
                reason: "rebar measure --list contains inventory, not canonical result traces; qualification requires an explicit same-semantics comparator run".to_owned(),
            },
        });
    }
    Ok(Manifest {
        schema_version: SCHEMA_VERSION,
        source: Source {
            format: "headerless CSV: full_name,model,engine,engine_version",
            command: "rebar measure --list",
            runner_revision: runner_revision.to_owned(),
            revision_provenance: "caller-supplied; this tool validates shape but does not query Git",
            record_count,
        },
        jobs,
    })
}

/// Serialize records as canonical headerless CSV in manifest sort order.
///
/// # Errors
///
/// Returns an error if CSV serialization or final buffer extraction fails.
pub fn render_inventory(records: &[InventoryRecord]) -> Result<Vec<u8>, String> {
    let mut records = records.to_vec();
    records.sort();
    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_writer(Vec::new());
    for record in records {
        writer
            .write_record([
                record.full_name,
                record.model,
                record.engine_name,
                record.engine_version,
            ])
            .map_err(|err| format!("serialize canonical inventory: {err}"))?;
    }
    writer
        .into_inner()
        .map_err(|err| format!("finish canonical inventory: {}", err.error()))
}

fn validate_revision(revision: &str) -> Result<(), String> {
    if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "runner revision must be a full 40-character hexadecimal Git object ID, got {revision:?}"
        ));
    }
    Ok(())
}

struct AdapterDetails {
    adapter: Adapter,
    operation_progress_wrapper: EvidenceValue,
    output_reducer: EvidenceValue,
    timed_boundary: EvidenceValue,
    cache_state: EvidenceValue,
}

fn adapter_details(engine: &str, model: &str) -> AdapterDetails {
    match engine {
        "rust/regex" => known_adapter(
            RUST_ADAPTER,
            "regex_automata::meta::Regex::builder().configure(meta).syntax(syntax).build_many(patterns)",
            "meta: utf8_empty(false); syntax: utf8(false), unicode=benchmark.unicode, case_insensitive=benchmark.case_insensitive; ordered multi-pattern match semantics",
            "Thompson NFA size limit 100 MiB; DFA cache limit remains the upstream default",
            "engines/rust/regex/main.rs",
            model,
            RunnerKind::Rust,
        ),
        "re2" => known_adapter(
            RE2_ADAPTER,
            "one RE2::RE2 instance constructed through the Rebar C++ shim; multi-pattern input is unsupported",
            "log_errors=false; EncodingUTF8 iff benchmark.unicode, otherwise EncodingLatin1; case_sensitive=!benchmark.case_insensitive",
            "RE2 resource limits are not overridden by the Rebar adapter",
            "engines/re2/main.rs and engines/re2/ffi.rs",
            model,
            RunnerKind::Re2,
        ),
        _ => {
            let reason = format!(
                "engine {engine:?} is inventoried by --list but its adapter source has not been audited by this tool"
            );
            AdapterDetails {
                adapter: Adapter {
                    name: EvidenceValue::unknown(reason.clone()),
                    constructor: EvidenceValue::unknown(reason.clone()),
                    configuration: EvidenceValue::unknown(reason.clone()),
                    limits: EvidenceValue::unknown(reason.clone()),
                },
                operation_progress_wrapper: EvidenceValue::unknown(reason.clone()),
                output_reducer: EvidenceValue::unknown(reason.clone()),
                timed_boundary: EvidenceValue::unknown(reason.clone()),
                cache_state: EvidenceValue::unknown(reason),
            }
        }
    }
}

#[derive(Clone, Copy)]
enum RunnerKind {
    Rust,
    Re2,
}

fn known_adapter(
    name: &str,
    constructor: &str,
    configuration: &str,
    limits: &str,
    evidence: &str,
    model: &str,
    kind: RunnerKind,
) -> AdapterDetails {
    let model_evidence = match kind {
        RunnerKind::Rust => "engines/rust/regex/main.rs and shared/timer/lib.rs",
        RunnerKind::Re2 => "engines/re2/main.rs, engines/re2/ffi.rs, and shared/timer/lib.rs",
    };
    let (operation, reducer, boundary, cache) = model_contract(model, kind).unwrap_or_else(|| {
        let reason =
            format!("model {model:?} is not in the audited Rebar model set for adapter {name}");
        (
            EvidenceValue::unknown(reason.clone()),
            EvidenceValue::unknown(reason.clone()),
            EvidenceValue::unknown(reason.clone()),
            EvidenceValue::unknown(reason),
        )
    });
    AdapterDetails {
        adapter: Adapter {
            name: EvidenceValue::known(name, evidence),
            constructor: EvidenceValue::known(constructor, evidence),
            configuration: EvidenceValue::known(configuration, evidence),
            limits: EvidenceValue::known(limits, evidence),
        },
        operation_progress_wrapper: with_evidence(operation, model_evidence),
        output_reducer: with_evidence(reducer, model_evidence),
        timed_boundary: with_evidence(boundary, model_evidence),
        cache_state: with_evidence(cache, model_evidence),
    }
}

fn with_evidence(mut fact: EvidenceValue, evidence: &str) -> EvidenceValue {
    if matches!(fact.status, FactStatus::Known) {
        evidence.clone_into(&mut fact.evidence);
    }
    fact
}

fn model_contract(
    model: &str,
    kind: RunnerKind,
) -> Option<(EvidenceValue, EvidenceValue, EvidenceValue, EvidenceValue)> {
    let find_iter = match kind {
        RunnerKind::Rust => {
            "meta::Regex::find_iter over the whole byte haystack; the library iterator implements non-overlapping progress and empty-match handling"
        }
        RunnerKind::Re2 => {
            "Rebar FindMatches loop over the whole byte haystack: search at current offset; advance to nonempty match end; after an empty match at the same prior end, advance one byte and search again"
        }
    };
    let captures = match kind {
        RunnerKind::Rust => {
            "reused Captures plus search_captures(Input(start)); after each match set start=group-0 end; benchmark contract guarantees nonempty matches"
        }
        RunnerKind::Re2 => {
            "reused capture allocation plus RE2::Match over [at,len); after each match set at=group-0 end; benchmark contract guarantees nonempty matches"
        }
    };
    let compile_cache = "fresh regex constructed in every timed sample after separate harness warmup iterations; validation search/count is outside the timed duration; processor cache state is uncontrolled";
    let search_cache = "one compiled regex and capture allocation (when needed) are reused across warmup and timed samples; harness warmup is enabled by its run configuration; processor cache state is uncontrolled";
    let regex_redux_cache = "fresh regex constructions occur inside every timed regex-redux sample; harness warmup runs whole samples first; processor cache state is uncontrolled";
    let known = |value: &str| EvidenceValue::known(value, "assigned below");
    Some(match model {
        "compile" => (
            known(
                "construct the configured regex; after timing, run find_iter only to validate the count",
            ),
            known("untimed number of non-overlapping matches from the newly constructed regex"),
            known(
                "only regex construction is timed; validation search and reduction occur after duration capture",
            ),
            known(compile_cache),
        ),
        "count" => (
            known(find_iter),
            known("number of non-overlapping matches"),
            known(
                "the complete match iteration and integer count reduction are timed; construction is outside the sample",
            ),
            known(search_cache),
        ),
        "count-spans" => (
            known(find_iter),
            known("sum of group-0 match lengths in bytes (end-start)"),
            known(
                "the complete match iteration and match-length sum are timed; construction is outside the sample",
            ),
            known(search_cache),
        ),
        "count-captures" => (
            known(captures),
            known("number of participating capture groups, including group 0, across all matches"),
            known(
                "capture searches, per-group participation checks, progress, and integer reduction are timed; construction/allocation are outside the sample",
            ),
            known(search_cache),
        ),
        "grep" => (
            known(
                "bstr byte-line iteration strips LF and an optional preceding CR; run an unanchored existence search independently on every line",
            ),
            known("number of lines containing at least one match"),
            known(
                "line splitting/CR stripping, per-line searches, and integer reduction are timed; construction is outside the sample",
            ),
            known(search_cache),
        ),
        "grep-captures" => (
            known(
                "bstr byte-line iteration strips LF and optional CR; within each line use the audited capture loop and advance to group-0 end; benchmark contract guarantees nonempty matches",
            ),
            known(
                "number of participating capture groups, including group 0, across every match on every line",
            ),
            known(
                "line splitting/CR stripping, capture searches, participation checks, progress, and reduction are timed; construction/allocation are outside the sample",
            ),
            known(search_cache),
        ),
        "regex-redux" => (
            known(
                "shared serial regexredux::generic protocol: compile each embedded pattern on demand, repeatedly search suffix slices, perform literal replacement construction/copying, format and verify the prescribed result",
            ),
            known("shared regex-redux result verification; timer sample count is zero"),
            known(
                "the entire serial shared regex-redux protocol, including fresh constructions, searches, replacements, allocation/copying, formatting, and verification, is timed",
            ),
            known(regex_redux_cache),
        ),
        _ => return None,
    })
}

/// Produce a deterministic, timestamp-free inventory summary.
#[must_use]
pub fn render_summary(manifest: &Manifest) -> String {
    let mut by_model = BTreeMap::<&str, usize>::new();
    let mut by_engine = BTreeMap::<&str, usize>::new();
    let mut adapters = BTreeMap::<&str, usize>::new();
    let mut unavailable = 0usize;
    for job in &manifest.jobs {
        let model_count = by_model.entry(&job.model).or_default();
        *model_count = model_count.saturating_add(1);
        let engine_count = by_engine.entry(&job.engine.name).or_default();
        *engine_count = engine_count.saturating_add(1);
        if matches!(job.engine.availability, Availability::ErrorReportedByRebar) {
            unavailable = unavailable.saturating_add(1);
        }
        if let Some(name) = job.adapter.name.value.as_deref() {
            let adapter_count = adapters.entry(name).or_default();
            *adapter_count = adapter_count.saturating_add(1);
        }
    }
    let mut out = String::new();
    writeln!(out, "# Rebar qualification inventory\n").unwrap();
    writeln!(out, "- Schema: `{}`", manifest.schema_version).unwrap();
    writeln!(
        out,
        "- Runner revision: `{}`",
        manifest.source.runner_revision
    )
    .unwrap();
    writeln!(out, "- Source command: `{}`", manifest.source.command).unwrap();
    writeln!(
        out,
        "- Canonical input: `inventory.csv` (sorted headerless CSV; four fields per job)"
    )
    .unwrap();
    writeln!(out, "- Jobs: {}", manifest.jobs.len()).unwrap();
    writeln!(
        out,
        "- Jobs whose version field is Rebar's literal `ERROR`: {unavailable}"
    )
    .unwrap();
    writeln!(
        out,
        "- Semantic comparator results: 0 verified; all jobs remain `unverified`\n"
    )
    .unwrap();
    writeln!(out, "## Models\n").unwrap();
    writeln!(out, "| Model | Jobs |\n|---|---:|").unwrap();
    for (model, count) in by_model {
        writeln!(out, "| `{model}` | {count} |").unwrap();
    }
    writeln!(out, "\n## Audited adapters\n").unwrap();
    writeln!(out, "| Adapter | Jobs |\n|---|---:|").unwrap();
    for (adapter, count) in adapters {
        writeln!(out, "| `{adapter}` | {count} |").unwrap();
    }
    writeln!(out, "\n## Engines\n").unwrap();
    writeln!(out, "| Engine | Jobs |\n|---|---:|").unwrap();
    for (engine, count) in by_engine {
        writeln!(out, "| `{engine}` | {count} |").unwrap();
    }
    writeln!(out, "\n## Interpretation\n").unwrap();
    out.push_str(
        "The manifest is an inventory and qualification input, not a performance or correctness result. Only the current `rust/regex` and `re2` Rebar adapters have audited constructor, configuration, progress, reducer, timing, and cache descriptions. Other adapters are retained with explicit `unknown` values. A literal `ERROR` engine version is retained as an unavailable job instead of being filtered out. Comparator status stays `unverified` until a separate same-semantics trace comparison succeeds.\n",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const REV: &str = "463d00f31887e84c38467805b9e3122c314b9521";

    #[test]
    fn parses_quoted_csv_and_sorts_deterministically() {
        let csv = concat!(
            "z/def/case,count,re2,ERROR\n",
            "\"a/def/case,with-comma\",compile,rust/regex,1.12.4\n",
        );
        let got = parse_inventory(csv.as_bytes()).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].full_name, "a/def/case,with-comma");
        assert_eq!(got[1].engine_name, "re2");
    }

    #[test]
    fn rejects_bad_width_duplicate_and_bad_name() {
        assert!(parse_inventory("a/b,count,re2\n".as_bytes()).is_err());
        assert!(parse_inventory("no-slash,count,re2,1\n".as_bytes()).is_err());
        assert!(parse_inventory("a/b,count,re2,1\na/b,count,re2,1\n".as_bytes()).is_err());
    }

    #[test]
    fn splits_nested_definition_at_final_slash() {
        assert_eq!(
            split_benchmark_name("wild/parol-veryl/multi").unwrap(),
            ("wild/parol-veryl", "multi")
        );
    }

    #[test]
    fn rust_profile_is_exact_and_comparator_is_not_claimed() {
        let rows = parse_inventory(
            "curated/05-lexer-veryl/multi,count-spans,rust/regex,1.12.4\n".as_bytes(),
        )
        .unwrap();
        let manifest = build_manifest(rows, REV).unwrap();
        let job = &manifest.jobs[0];
        assert_eq!(job.adapter.name.value.as_deref(), Some(RUST_ADAPTER));
        assert!(
            job.adapter
                .constructor
                .value
                .as_deref()
                .unwrap()
                .contains("build_many")
        );
        assert!(
            job.adapter
                .limits
                .value
                .as_deref()
                .unwrap()
                .contains("100 MiB")
        );
        assert_eq!(job.semantic_comparator.status, ComparatorStatus::Unverified);
    }

    #[test]
    fn re2_profile_records_byte_progress_and_unavailability() {
        let rows = parse_inventory("test/iter/empty,count,re2,ERROR\n".as_bytes()).unwrap();
        let manifest = build_manifest(rows, REV).unwrap();
        let job = &manifest.jobs[0];
        assert_eq!(job.adapter.name.value.as_deref(), Some(RE2_ADAPTER));
        assert!(
            job.adapter
                .configuration
                .value
                .as_deref()
                .unwrap()
                .contains("log_errors=false")
        );
        assert!(
            job.operation_progress_wrapper
                .value
                .as_deref()
                .unwrap()
                .contains("one byte")
        );
        assert!(matches!(
            job.engine.availability,
            Availability::ErrorReportedByRebar
        ));
    }

    #[test]
    fn unknown_engine_values_serialize_as_explicit_null() {
        let rows = parse_inventory("x/y,count,mystery/engine,9\n".as_bytes()).unwrap();
        let manifest = build_manifest(rows, REV).unwrap();
        let json = serde_json::to_value(manifest).unwrap();
        let adapter = &json["jobs"][0]["adapter"];
        assert_eq!(adapter["name"]["status"], "unknown");
        assert!(adapter["name"]["value"].is_null());
    }

    #[test]
    fn validates_full_revision() {
        assert!(build_manifest(Vec::new(), "463d00f").is_err());
        assert!(build_manifest(Vec::new(), REV).is_ok());
    }

    #[test]
    fn output_is_byte_deterministic() {
        let input = "b/y,count,re2,2\na/x,count,rust/regex,1\n";
        let one = build_manifest(parse_inventory(input.as_bytes()).unwrap(), REV).unwrap();
        let two = build_manifest(parse_inventory(input.as_bytes()).unwrap(), REV).unwrap();
        assert_eq!(
            serde_json::to_vec_pretty(&one).unwrap(),
            serde_json::to_vec_pretty(&two).unwrap()
        );
        assert_eq!(render_summary(&one), render_summary(&two));
    }

    #[test]
    fn canonical_inventory_round_trips_and_sorts() {
        let input = "z/case,count,re2,ERROR\n\"a/case,comma\",compile,rust/regex,1\n";
        let records = parse_inventory(input.as_bytes()).unwrap();
        let canonical = render_inventory(&records).unwrap();
        assert_eq!(parse_inventory(canonical.as_slice()).unwrap(), records);
        assert!(canonical.starts_with(b"\"a/case,comma\",compile"));
    }
}
