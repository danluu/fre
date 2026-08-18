//! Authenticated, counterbalanced pointwise Rebar performance screens.
//!
//! This executable runs only under the resource coordinator timing lease. It
//! accepts one preregistered campaign, authenticates the frozen semantic
//! report, source checkout, KLV bytes and all three runners, and emits raw
//! paired samples plus exact integer summaries. It never computes a cross-row
//! aggregate.
//!
//! Child protocol inputs omit row identity and expected values. This does not
//! hide the live collector or its authenticated report from a same-UID child;
//! production execution therefore still requires an external process sandbox
//! or privilege boundary. Concurrent bounded pipes, wall deadlines and
//! process-group cleanup below protect collector availability; they do not
//! provide filesystem, network, process or resource isolation.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "bounded schedule indexing uses fixed nonzero campaign lengths"
)]

use std::{
    env,
    fmt::Write as _,
    fs,
    io::{Read, Write},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, ExitStatus, Stdio},
    sync::mpsc::{self, TryRecvError},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use rebar_compare::{Receipt, Report, Status};
use regex::bytes::RegexBuilder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

type DynError = Box<dyn std::error::Error + Send + Sync + 'static>;

const SCHEMA: &str = "fre.rebar.stratified-performance.v3";
const PAIRS: usize = 6;
const QUALIFICATION_PROBES_PER_ROW: usize = 4;
const PARTS_PER_MILLION: u128 = 1_000_000;
// The immutable semantic oracle predates this candidate's runtime-only v2
// specialization. Candidate source and runtime identity are authenticated
// independently below; a v2 frontier regeneration remains a promotion gate.
const FRE_ADAPTER: &str = "fre-current-aggregate-capture-v10-portable-word-run-v1";
const RUST_ADAPTER: &str = "rebar-rust-regex-1.12.4";
const RE2_ADAPTER: &str = "rebar-re2-2025-11-05";
const REPORT_SCHEMA: &str = "fre.rebar.comparison.v2";
const SEMANTIC_REPORT_SHA256: &str =
    "f1f40ff23aa316fc69fd32b5bb9c508d7085f0b91b360baea7387dd66c23273e";
const SEMANTIC_RECEIPTS_SHA256: &str =
    "6122094efae0d307e458ca8f07243f73bee0a1e31938610b4b386bbebd2d6fca";
const MANIFEST_SHA256: &str = "09a7bfe5df8a4d78c21144b4d45f584167a1607f412990a60045878227553e43";
const REBAR_REVISION: &str = "463d00f31887e84c38467805b9e3122c314b9521";
const REBAR_TREE: &str = "16dfbb450d4729afb6065664d0ce48fe24a3aecc";
const REBAR_BINARY_SHA256: &str =
    "8509c6b0370afe05fe1fc339566b7212706937ab28bbbc9c9da406cb320d68ed";
const RUST_BINARY_SHA256: &str = "8ef7a4a47264c584c02432a70f7e917c1aab2639451f0ba42da0ef04041951fc";
const RE2_BINARY_SHA256: &str = "42a53794bc7a1a911484b84dd239b625e7241c8aca41b28d677ca76686266d4b";
const MIN_FREE_KIB: u64 = 20 * 1_048_576;
const FRE_EXECUTOR_FLAG: &str = "--anonymous-executor-v2";
const FRE_DESCRIBE_FLAG: &str = "--describe-anonymous-executor-v2";
const FRE_EXECUTOR_REQUEST_SCHEMA: &str = "fre.rebar.anonymous-executor-request.v2";
const FRE_EXECUTOR_DESCRIPTION_SCHEMA: &str = "fre.rebar.anonymous-executor-description.v2";
const FRE_EXECUTOR_RESPONSE_SCHEMA: &str = "fre.rebar.anonymous-executor-response.v2";
const MAX_RUNNER_OUTPUT_BYTES: usize = 64 * 1_024;
const FORMAL_COMPILE_PLAN: &str = "compile-aggregate-continuation-program";
#[cfg(test)]
const FORMAL_AGGREGATE_OPERATION_PLAN: &str = "aggregate-continuation-program";
const FORMAL_GREP_PLAN: &str = "rebar-lines-is-match-v3";
const RUNNER_WALL_TIMEOUT: Duration = Duration::from_secs(120);
const RUNNER_CHILD_POLL: Duration = Duration::from_millis(5);
const RUNNER_EXIT_PIPE_GRACE: Duration = Duration::from_secs(1);
const RUNNER_CLEANUP_GRACE: Duration = Duration::from_secs(2);
const RUNNER_SIGNAL_TIMEOUT: Duration = Duration::from_secs(1);

const RETENTION_ROWS: [&str; 9] = [
    "curated/01-literal/sherlock-en@rust/regex",
    "curated/02-literal-alternate/sherlock-en@rust/regex",
    "curated/10-bounded-repeat/letters-en@rust/regex",
    "imported/sherlock/line-boundary-sherlock-holmes@rust/regex",
    "unicode/word/around-holmes-english@rust/regex",
    "imported/rsc/hard-32@rust/regex",
    "imported/rsc/hard-1mb@rust/regex",
    "imported/lh3lh3-reb/email@rust/regex",
    "folly/literal-never-match-rare@rust/regex",
];

const ASSERTION_FOCUSED_ROWS: [&str; 5] = [
    "grep/long-words-ascii@rust/regex",
    "opt/accelerate/whole-line@rust/regex",
    "imported/lh3lh3-reb/email@rust/regex",
    "imported/sherlock/line-boundary-sherlock-holmes@rust/regex",
    "curated/09-aws-keys/quick@rust/regex",
];

const COMPILE_SMOKE_ROWS: [&str; 4] = [
    "test/model/compile@rust/regex",
    "curated/10-bounded-repeat/compile-context@rust/regex",
    "test/model/count@rust/regex",
    "test/model/count-spans@rust/regex",
];

const COMPILE_FOCUSED_ROWS: [&str; 11] = [
    "test/model/compile@rust/regex",
    "curated/04-ruff-noqa/compile-real@rust/regex",
    "curated/05-lexer-veryl/compile-single@rust/regex",
    "curated/07-unicode-character-data/compile@rust/regex",
    "curated/10-bounded-repeat/compile-context@rust/regex",
    "reported/i787-keywords/compile@rust/regex",
    "reported/i988-cloudflare-compile/javascript-obfuscation@rust/regex",
    "unicode/compile/fifty-letters-ascii@rust/regex",
    "test/model/count@rust/regex",
    "test/model/count-spans@rust/regex",
    "curated/01-literal/sherlock-en@rust/regex",
];

const COMPILE_ALL_ROWS: [&str; 17] = [
    "curated/04-ruff-noqa/compile-real@rust/regex",
    "curated/05-lexer-veryl/compile-single@rust/regex",
    "curated/07-unicode-character-data/compile@rust/regex",
    "curated/09-aws-keys/compile-full@rust/regex",
    "curated/09-aws-keys/compile-quick@rust/regex",
    "curated/10-bounded-repeat/compile-capitals@rust/regex",
    "curated/10-bounded-repeat/compile-context@rust/regex",
    "curated/11-unstructured-to-json/compile@rust/regex",
    "curated/12-dictionary/compile-single@rust/regex",
    "dictionary/compile/english-15@rust/regex",
    "reported/i1095-word-repetition/ascii-compile@rust/regex",
    "reported/i787-keywords/compile@rust/regex",
    "reported/i988-cloudflare-compile/javascript-obfuscation@rust/regex",
    "reported/i988-cloudflare-compile/sql-injection@rust/regex",
    "test/model/compile@rust/regex",
    "unicode/compile/fifty-letters-ascii@rust/regex",
    "unicode/compile/match-every-line-ascii@rust/regex",
];

const UNICODE_DELTA_ROWS: [&str; 8] = [
    "curated/02-literal-alternate/sherlock-zh@rust/regex",
    "dictionary/compile/english-15@rust/regex",
    "hyperscan/literal-casei-russian-nosom@rust/regex",
    "hyperscan/literal-casei-russian-som@rust/regex",
    "opt/literal-alt/one-pattern@rust/regex",
    "opt/prefilter/literal-casei-russian@rust/regex",
    "test/unicode/case/ascii-with-unicode@rust/regex",
    "test/unicode/case/unicode@rust/regex",
];

const BREADTH_CURRENT_ROWS: [&str; 5] = [
    "grep/long-words-unicode@rust/regex",
    "grep/long-words-ascii@rust/regex",
    "imported/rsc/match-class-unicode@rust/regex",
    "curated/01-literal/sherlock-en@rust/regex",
    "unicode/word/boundary-any-english@rust/regex",
];

#[allow(
    clippy::too_many_lines,
    reason = "the campaign gate keeps authentication, measurement and durable output ordering auditable"
)]
fn main() -> Result<(), DynError> {
    require_timing_lease()?;
    let mut arguments = env::args_os().skip(1);
    let campaign = Campaign::parse(&text_arg(&mut arguments, "CAMPAIGN")?)?;
    let semantic_path = path_arg(&mut arguments, "SEMANTIC_REPORT")?;
    let rebar_bin = path_arg(&mut arguments, "REBAR_BIN")?;
    let rebar_checkout = path_arg(&mut arguments, "REBAR_CHECKOUT")?;
    let fre_runner = path_arg(&mut arguments, "FRE_RUNNER")?;
    let expected_fre_sha256 = text_arg(&mut arguments, "FRE_RUNNER_SHA256")?;
    let rust_runner = path_arg(&mut arguments, "RUST_RUNNER")?;
    let re2_runner = path_arg(&mut arguments, "RE2_RUNNER")?;
    let output = path_arg(&mut arguments, "OUTPUT")?;
    if arguments.next().is_some() {
        return Err("unexpected trailing timing-gate argument".into());
    }
    validate_digest(&expected_fre_sha256, "FRE_RUNNER_SHA256")?;
    let sidecar = sidecar_path(&output)?;
    require_new_output(&output)?;
    require_new_output(&sidecar)?;

    let checkout_before = authenticate_checkout(&rebar_checkout)?;
    let semantic_bytes = fs::read(&semantic_path)?;
    let semantic_sha256 = sha256(&semantic_bytes);
    if semantic_sha256 != SEMANTIC_REPORT_SHA256 {
        return Err(format!(
            "semantic report digest {semantic_sha256} differs from {SEMANTIC_REPORT_SHA256}"
        )
        .into());
    }
    let semantic = read_exact_report(&semantic_bytes)?;
    authenticate_report(&semantic)?;

    let runners = Runners {
        fre: Runner::authenticate("fre", &fre_runner, &expected_fre_sha256, VersionRule::Fre)?,
        rust: Runner::authenticate(
            "rust/regex",
            &rust_runner,
            RUST_BINARY_SHA256,
            VersionRule::Exact("1.12.4"),
        )?,
        re2: Runner::authenticate(
            "re2",
            &re2_runner,
            RE2_BINARY_SHA256,
            VersionRule::Exact("2025-11-05"),
        )?,
    };
    authenticate_adapter_runtime(&semantic, RUST_ADAPTER, RUST_BINARY_SHA256)?;
    authenticate_adapter_runtime(&semantic, RE2_ADAPTER, RE2_BINARY_SHA256)?;
    authenticate_adapter_runtime(&semantic, FRE_ADAPTER, "")?;

    let rebar_binary_before = exact_file_hash(&rebar_bin, REBAR_BINARY_SHA256, "Rebar")?;
    let mut rows = prepare_rows(&semantic, campaign.rows(), &rebar_bin, &rebar_checkout)?;
    if authenticate_checkout(&rebar_checkout)? != checkout_before {
        return Err("Rebar checkout changed while KLV inputs were prepared".into());
    }
    if file_sha256(&rebar_bin)? != rebar_binary_before {
        return Err("Rebar binary changed while KLV inputs were prepared".into());
    }

    let qualification_seed = fresh_qualification_seed()?;
    let mut qualification = qualify_rows(&runners, &rows, &qualification_seed)?;
    qualification.untimed_canonical_warmup_invocations =
        warm_all_scheduled_runners(&runners, &rows)?;
    let guard_before = guard_snapshot(&output)?;
    run_schedule(&runners, &mut rows)?;

    let guard_after = guard_snapshot(&output)?;
    let checkout_after = authenticate_checkout(&rebar_checkout)?;
    if checkout_after != checkout_before {
        return Err("Rebar checkout changed during the timing campaign".into());
    }
    let rebar_binary_after = file_sha256(&rebar_bin)?;
    if rebar_binary_after != rebar_binary_before {
        return Err("Rebar binary changed during the timing campaign".into());
    }
    let runners_after = runners.rehash()?;
    if runners_after != runners.hashes() {
        return Err("one or more timing runners changed during the campaign".into());
    }

    let timing_rows = rows
        .into_iter()
        .map(PreparedRow::finish)
        .collect::<Result<Vec<_>, DynError>>()?;
    let all_pointwise_pass = timing_rows.iter().all(TimingRow::passes);
    let report = TimingReport {
        schema: SCHEMA,
        campaign: campaign.name(),
        disposition: if all_pointwise_pass {
            "pointwise-pass"
        } else {
            "pointwise-reject"
        },
        semantic_report_sha256: semantic_sha256,
        semantic_receipts_sha256: semantic.receipts_sha256,
        manifest_sha256: semantic.manifest_sha256,
        rebar_revision: semantic.rebar_revision,
        rebar_checkout: checkout_before,
        started_unix_ns: guard_before.unix_ns,
        finished_unix_ns: guard_after.unix_ns,
        timing_holder_token_sha256: timing_token_sha256()?,
        pairs_per_comparator: PAIRS,
        warmup_iterations_per_process: 0,
        measured_iterations_per_process: 1,
        retry_policy: "none: any child/identity/guard failure aborts the whole campaign",
        timed_api_boundary: "compile=CurrentFreAggregateCompileLifecycle::construct including builder/profile/options; count=CurrentFreAggregateOperationLifecycle::execute through the source-independent certified Count portfolio with Aggregate Auto fallback; count-spans=the retained complete-span session visiting every start/end bound with checked end-start summation; grep=PortableRegex::is_match over bstr lines",
        qualification,
        guard_before,
        guard_after,
        rebar_binary_sha256: rebar_binary_before,
        runners,
        included_rows: timing_rows.len(),
        all_pointwise_pass,
        rows: timing_rows,
    };
    let mut bytes = serde_json::to_vec_pretty(&report)?;
    bytes.push(b'\n');
    let output_sha256 = sha256(&bytes);
    fs::write(&output, &bytes)?;
    fs::write(&sidecar, format!("{output_sha256}  {}\n", output.display()))?;
    println!(
        "campaign={} disposition={} rows={} qualification_cases={} qualification_sha256={} report_sha256={output_sha256}",
        campaign.name(),
        report.disposition,
        report.included_rows,
        report.qualification.observations,
        report.qualification.evidence_sha256,
    );
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum Campaign {
    BreadthCurrent,
    AssertionFocused,
    AssertionFull,
    CompileSmoke,
    CompileFocused,
    CompileAll,
    CompileFull,
    UnicodeFull,
}

impl Campaign {
    fn parse(value: &str) -> Result<Self, DynError> {
        match value {
            "breadth-current" => Ok(Self::BreadthCurrent),
            "assertion-focused" => Ok(Self::AssertionFocused),
            "assertion-full" => Ok(Self::AssertionFull),
            "compile-smoke" => Ok(Self::CompileSmoke),
            "compile-focused" => Ok(Self::CompileFocused),
            "compile-all" => Ok(Self::CompileAll),
            "compile-full" => Ok(Self::CompileFull),
            "unicode-full" => Ok(Self::UnicodeFull),
            _ => Err(format!("unknown preregistered campaign {value:?}").into()),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::BreadthCurrent => "breadth-current-v1",
            Self::AssertionFocused => "assertion-focused-v1",
            Self::AssertionFull => "assertion-full-v1",
            Self::CompileSmoke => "compile-smoke-v1",
            Self::CompileFocused => "compile-focused-v1",
            Self::CompileAll => "compile-all-v1",
            Self::CompileFull => "compile-full-v1",
            Self::UnicodeFull => "unicode-full-v1",
        }
    }

    fn rows(self) -> Vec<&'static str> {
        match self {
            Self::BreadthCurrent => BREADTH_CURRENT_ROWS.to_vec(),
            Self::AssertionFocused => ASSERTION_FOCUSED_ROWS.to_vec(),
            Self::AssertionFull => {
                let mut rows = vec![
                    "grep/long-words-ascii@rust/regex",
                    "opt/accelerate/whole-line@rust/regex",
                ];
                rows.extend(RETENTION_ROWS);
                rows.push("curated/09-aws-keys/quick@rust/regex");
                rows
            }
            Self::CompileSmoke => COMPILE_SMOKE_ROWS.to_vec(),
            Self::CompileFocused => COMPILE_FOCUSED_ROWS.to_vec(),
            Self::CompileAll => COMPILE_ALL_ROWS.to_vec(),
            Self::CompileFull => {
                let mut rows = COMPILE_ALL_ROWS.to_vec();
                rows.extend(RETENTION_ROWS);
                rows.sort_unstable();
                rows.dedup();
                rows
            }
            Self::UnicodeFull => {
                let mut rows = UNICODE_DELTA_ROWS.to_vec();
                rows.extend(RETENTION_ROWS);
                rows
            }
        }
    }
}

fn require_timing_lease() -> Result<(), DynError> {
    if env::var("FRE_RESOURCE_HOLDER_KIND").as_deref() != Ok("timing") {
        return Err("stratified gate requires the resource coordinator timing lease".into());
    }
    if env::var("FRE_RESOURCE_HOLDER_TOKEN").is_err() {
        return Err("timing holder token is absent".into());
    }
    Ok(())
}

fn timing_token_sha256() -> Result<String, DynError> {
    let token = env::var("FRE_RESOURCE_HOLDER_TOKEN")?;
    if token.is_empty() {
        return Err("timing holder token is empty".into());
    }
    Ok(sha256(token.as_bytes()))
}

fn path_arg(
    arguments: &mut impl Iterator<Item = std::ffi::OsString>,
    name: &str,
) -> Result<PathBuf, DynError> {
    arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing {name}").into())
}

fn text_arg(
    arguments: &mut impl Iterator<Item = std::ffi::OsString>,
    name: &str,
) -> Result<String, DynError> {
    path_arg(arguments, name)?
        .into_os_string()
        .into_string()
        .map_err(|_| format!("{name} is not UTF-8").into())
}

fn validate_digest(value: &str, label: &str) -> Result<(), DynError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{label} is not a SHA-256 digest").into());
    }
    Ok(())
}

fn sidecar_path(path: &Path) -> Result<PathBuf, DynError> {
    let name = path
        .file_name()
        .ok_or("timing output has no file name")?
        .to_string_lossy();
    Ok(path.with_file_name(format!("{name}.sha256")))
}

fn require_new_output(path: &Path) -> Result<(), DynError> {
    if path.exists() {
        return Err(format!("refusing to overwrite {}", path.display()).into());
    }
    if path.parent().is_none_or(|parent| !parent.is_dir()) {
        return Err(format!("output parent for {} does not exist", path.display()).into());
    }
    Ok(())
}

fn authenticate_report(report: &Report) -> Result<(), DynError> {
    if report.schema != REPORT_SCHEMA {
        return Err(format!("unexpected semantic report schema {}", report.schema).into());
    }
    if report.rebar_revision != REBAR_REVISION {
        return Err(format!("unexpected Rebar revision {}", report.rebar_revision).into());
    }
    if report.manifest_sha256 != MANIFEST_SHA256 {
        return Err(format!("unexpected manifest digest {}", report.manifest_sha256).into());
    }
    if report.receipts_sha256 != SEMANTIC_RECEIPTS_SHA256 {
        return Err(format!("unexpected receipt digest {}", report.receipts_sha256).into());
    }
    let receipt_digest = sha256(&serde_json::to_vec(&report.receipts)?);
    if receipt_digest != report.receipts_sha256 {
        return Err("semantic receipt bytes do not match their embedded digest".into());
    }
    Ok(())
}

fn read_exact_report(bytes: &[u8]) -> Result<Report, DynError> {
    let report: Report = serde_json::from_slice(bytes)?;
    let mut canonical = serde_json::to_vec(&report)?;
    canonical.push(b'\n');
    if canonical != bytes {
        return Err("semantic report bytes are not canonical compact JSON".into());
    }
    Ok(report)
}

fn authenticate_adapter_runtime(
    report: &Report,
    adapter: &str,
    expected_sha256: &str,
) -> Result<(), DynError> {
    let mut identities = report
        .adapters
        .iter()
        .filter(|identity| identity.adapter == adapter);
    let identity = identities
        .next()
        .ok_or_else(|| format!("semantic report lacks adapter identity {adapter}"))?;
    if identities.next().is_some() {
        return Err(format!("semantic report duplicates adapter identity {adapter}").into());
    }
    if expected_sha256.is_empty() {
        if identity.runtime_sha256.is_some() {
            return Err(
                format!("in-process adapter {adapter} unexpectedly names a runtime").into(),
            );
        }
    } else if identity.runtime_sha256.as_deref() != Some(expected_sha256) {
        return Err(format!("semantic adapter runtime digest differs for {adapter}").into());
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct CheckoutIdentity {
    revision: String,
    tree: String,
    clean: bool,
}

fn authenticate_checkout(checkout: &Path) -> Result<CheckoutIdentity, DynError> {
    let revision = git_output(checkout, &["rev-parse", "HEAD"])?;
    let tree = git_output(checkout, &["rev-parse", "HEAD^{tree}"])?;
    let status = git_output(checkout, &["status", "--porcelain=v1"])?;
    let identity = CheckoutIdentity {
        revision,
        tree,
        clean: status.is_empty(),
    };
    if identity.revision != REBAR_REVISION || identity.tree != REBAR_TREE || !identity.clean {
        return Err(format!("Rebar checkout identity is not frozen: {identity:?}").into());
    }
    Ok(identity)
}

fn git_output(checkout: &Path, arguments: &[&str]) -> Result<String, DynError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(checkout)
        .args(arguments)
        .output()?;
    if !output.status.success() {
        return Err(format!("git {arguments:?} failed").into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

#[derive(Clone, Debug, Serialize)]
struct GuardSnapshot {
    unix_ns: u128,
    load_average: String,
    power: String,
    free_kib: u64,
}

fn guard_snapshot(output: &Path) -> Result<GuardSnapshot, DynError> {
    let power = command_text("pmset", &["-g", "batt"])?;
    if !power.contains("AC Power") {
        return Err(format!("timing host is not on AC power: {power:?}").into());
    }
    let load_average = command_text("sysctl", &["-n", "vm.loadavg"])?;
    let parent = output.parent().ok_or("timing output has no parent")?;
    let parent_text = parent.to_str().ok_or("timing output parent is not UTF-8")?;
    let disk = command_text("df", &["-Pk", parent_text])?;
    let last = disk.lines().last().ok_or("df returned no rows")?;
    let free_kib = last
        .split_whitespace()
        .nth(3)
        .ok_or("df row lacks available-KiB field")?
        .parse::<u64>()?;
    if free_kib < MIN_FREE_KIB {
        return Err(format!("timing host has only {free_kib} KiB free").into());
    }
    Ok(GuardSnapshot {
        unix_ns: SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
        load_average,
        power,
        free_kib,
    })
}

fn command_text(program: &str, arguments: &[&str]) -> Result<String, DynError> {
    let output = Command::new(program).args(arguments).output()?;
    if !output.status.success() {
        return Err(format!("{program} {arguments:?} failed").into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

struct SelectedReceipts<'a> {
    fre: &'a Receipt,
    re2: Option<&'a Receipt>,
}

fn select_receipts<'a>(
    receipts: &'a [Receipt],
    job_id: &str,
) -> Result<SelectedReceipts<'a>, DynError> {
    let mut fre = receipts
        .iter()
        .filter(|receipt| receipt.job_id == job_id && receipt.adapter == FRE_ADAPTER);
    let fre = exactly_one(&mut fre, "FRE", job_id)?;
    require_pass(fre)?;
    if fre.target_engine != "rust/regex" {
        return Err(format!("FRE receipt {job_id} has unexpected target engine").into());
    }
    if fre.candidate_plan.is_none() {
        return Err(format!("FRE receipt {job_id} lacks selected plan identity").into());
    }

    let mut rust = receipts
        .iter()
        .filter(|receipt| receipt.job_id == job_id && receipt.adapter == RUST_ADAPTER);
    let rust = exactly_one(&mut rust, "Rust", job_id)?;
    require_pass(rust)?;
    if rust.target_engine != "rust/regex"
        || fre.expected != rust.expected
        || fre.input != rust.input
        || fre.model != rust.model
        || fre.benchmark != rust.benchmark
    {
        return Err(format!("FRE and Rust semantic identities differ for {job_id}").into());
    }

    let re2_job_id = format!("{}@re2", fre.benchmark);
    let mut re2 = receipts
        .iter()
        .filter(|receipt| receipt.job_id == re2_job_id && receipt.adapter == RE2_ADAPTER);
    let re2 = match (re2.next(), re2.next()) {
        (None, None) => None,
        (Some(receipt), None) => {
            require_pass(receipt)?;
            if receipt.target_engine != "re2"
                || fre.expected != receipt.expected
                || fre.input != receipt.input
                || fre.model != receipt.model
                || fre.benchmark != receipt.benchmark
            {
                return Err(format!("FRE and RE2 semantic identities differ for {job_id}").into());
            }
            Some(receipt)
        }
        _ => return Err(format!("duplicate RE2 receipt for {job_id}").into()),
    };
    Ok(SelectedReceipts { fre, re2 })
}

fn exactly_one<'a>(
    receipts: &mut impl Iterator<Item = &'a Receipt>,
    engine: &str,
    job_id: &str,
) -> Result<&'a Receipt, DynError> {
    let first = receipts
        .next()
        .ok_or_else(|| format!("missing {engine} receipt for {job_id}"))?;
    if receipts.next().is_some() {
        return Err(format!("duplicate {engine} receipt for {job_id}").into());
    }
    Ok(first)
}

fn require_pass(receipt: &Receipt) -> Result<(), DynError> {
    if receipt.status != Status::Pass || receipt.actual != Some(receipt.expected) {
        return Err(format!(
            "receipt {} via {} is not an exact semantic pass",
            receipt.job_id, receipt.adapter
        )
        .into());
    }
    Ok(())
}

struct PreparedRow<'a> {
    selected: SelectedReceipts<'a>,
    klv: Vec<u8>,
    klv_sha256: String,
    rust_pairs: Vec<RawPair>,
    re2_pairs: Vec<RawPair>,
}

fn prepare_rows<'a>(
    semantic: &'a Report,
    job_ids: Vec<&str>,
    rebar_bin: &Path,
    rebar_checkout: &Path,
) -> Result<Vec<PreparedRow<'a>>, DynError> {
    let mut rows = Vec::with_capacity(job_ids.len());
    for job_id in job_ids {
        let selected = select_receipts(&semantic.receipts, job_id)?;
        let klv = rebar_klv(rebar_bin, rebar_checkout, &selected.fre.benchmark)?;
        verify_klv(&klv, selected.fre)?;
        rows.push(PreparedRow {
            selected,
            klv_sha256: sha256(&klv),
            klv,
            rust_pairs: Vec::with_capacity(PAIRS),
            re2_pairs: Vec::with_capacity(PAIRS),
        });
    }
    Ok(rows)
}

fn fresh_qualification_seed() -> Result<[u8; 32], DynError> {
    let mut seed = [0_u8; 32];
    fs::File::open("/dev/urandom")?.read_exact(&mut seed)?;
    if seed == [0_u8; 32] {
        return Err("qualification entropy source returned an all-zero seed".into());
    }
    Ok(seed)
}

#[derive(Debug, Serialize)]
struct QualificationEvidence {
    job_id: String,
    probe_index: usize,
    probe_kind: &'static str,
    haystack_sha256: String,
    reference_actual: u64,
    candidate_actual: u64,
    candidate_plan: String,
    candidate_runtime: Option<String>,
}

fn qualify_rows(
    runners: &Runners,
    rows: &[PreparedRow<'_>],
    seed: &[u8; 32],
) -> Result<QualificationSummary, DynError> {
    let mut evidence = Vec::with_capacity(
        rows.len()
            .checked_mul(QUALIFICATION_PROBES_PER_ROW)
            .ok_or("qualification observation count overflow")?,
    );
    let mut invariant_rows = 0_usize;
    let mut invariant_job_ids = Vec::new();
    let mut plain_literal_witness_rows = 0_usize;
    for (row_index, row) in rows.iter().enumerate() {
        let canonical = ParsedKlv::parse(&row.klv)?;
        let expectations = FreExpectations {
            benchmark: &row.selected.fre.benchmark,
            model: &row.selected.fre.model,
            plan: row
                .selected
                .fre
                .candidate_plan
                .as_deref()
                .ok_or("FRE receipt lacks plan")?,
            runtime: expected_grep_runtime(&row.selected.fre.model, &row.selected.fre.job_id),
        };
        let canonical_description = runners.fre.describe_fre(&canonical, expectations)?;
        let mutations =
            same_length_held_out_haystacks(&canonical, row.selected.fre.expected, seed, row_index)?;
        if mutations.plain_literal_witness {
            plain_literal_witness_rows = plain_literal_witness_rows
                .checked_add(1)
                .ok_or("qualification literal-witness row count overflow")?;
        }
        let mut output_changed = false;
        for (probe_index, haystack) in mutations.haystacks.into_iter().enumerate() {
            if haystack.len() != canonical.haystack.len() {
                return Err("held-out qualification changed haystack length".into());
            }
            let mut probe = canonical.clone();
            probe.haystack = haystack;
            let reference = runners.rust.sample_reference_unchecked(&probe)?;
            let (description, candidate) =
                runners
                    .fre
                    .sample_fre_with_description(&probe, reference.count, expectations)?;
            validate_qualification_probe(
                &canonical_description,
                &description,
                reference.count,
                candidate.count,
            )?;
            output_changed |= reference.count != row.selected.fre.expected;
            evidence.push(QualificationEvidence {
                job_id: row.selected.fre.job_id.clone(),
                probe_index,
                probe_kind: qualification_probe_kind(probe_index, mutations.plain_literal_witness)?,
                haystack_sha256: sha256(&probe.haystack),
                reference_actual: reference.count,
                candidate_actual: candidate.count,
                candidate_plan: description.candidate_plan,
                candidate_runtime: description.candidate_runtime,
            });
        }
        if !output_changed {
            require_preregistered_invariant_identity(expectations, &canonical_description)?;
            invariant_rows = invariant_rows
                .checked_add(1)
                .ok_or("qualification invariant-row count overflow")?;
            invariant_job_ids.push(row.selected.fre.job_id.clone());
        }
    }
    let expected_observations = rows
        .len()
        .checked_mul(QUALIFICATION_PROBES_PER_ROW)
        .ok_or("qualification observation count overflow")?;
    if evidence.len() != expected_observations {
        return Err("qualification did not execute every preregistered probe".into());
    }
    let evidence_sha256 = sha256(&serde_json::to_vec(&evidence)?);
    Ok(QualificationSummary {
        policy: "four same-length haystack probes per row (zero, ff, plain-ASCII literal witness when available otherwise alternating-line, secret-seeded); exact authenticated Rust reducer; stable preregistered FRE plan/runtime; invariant outputs require an exact audited formal identity; one untimed canonical warmup per scheduled runner precedes the timing guard snapshot",
        seed_sha256: sha256(seed),
        rows: rows.len(),
        observations: evidence.len(),
        plain_literal_witness_rows,
        invariant_rows,
        invariant_job_ids,
        untimed_canonical_warmup_invocations: 0,
        evidence_sha256,
    })
}

fn warm_all_scheduled_runners(
    runners: &Runners,
    rows: &[PreparedRow<'_>],
) -> Result<usize, DynError> {
    let mut invocations = 0_usize;
    for (row_index, row) in rows.iter().enumerate() {
        let expectations = FreExpectations {
            benchmark: &row.selected.fre.benchmark,
            model: &row.selected.fre.model,
            plan: row
                .selected
                .fre
                .candidate_plan
                .as_deref()
                .ok_or("FRE receipt lacks plan")?,
            runtime: expected_grep_runtime(&row.selected.fre.model, &row.selected.fre.job_id),
        };
        let warm_fre = || {
            runners
                .fre
                .sample(&row.klv, row.selected.fre.expected, Some(expectations))
                .map(|_| ())
        };
        let warm_rust = || {
            runners
                .rust
                .sample(&row.klv, row.selected.fre.expected, None)
                .map(|_| ())
        };
        let warm_re2 = || {
            if row.selected.re2.is_some() {
                runners
                    .re2
                    .sample(&row.klv, row.selected.fre.expected, None)
                    .map(|_| 1_usize)
            } else {
                Ok(0_usize)
            }
        };
        let row_invocations;
        if row_index.is_multiple_of(2) {
            warm_fre()?;
            warm_rust()?;
            row_invocations = 2_usize
                .checked_add(warm_re2()?)
                .ok_or("untimed canonical warmup count overflow")?;
        } else {
            let re2_invocations = warm_re2()?;
            warm_rust()?;
            warm_fre()?;
            row_invocations = 2_usize
                .checked_add(re2_invocations)
                .ok_or("untimed canonical warmup count overflow")?;
        }
        invocations = invocations
            .checked_add(row_invocations)
            .ok_or("untimed canonical warmup count overflow")?;
    }
    Ok(invocations)
}

struct HeldOutHaystacks {
    haystacks: [Vec<u8>; QUALIFICATION_PROBES_PER_ROW],
    plain_literal_witness: bool,
}

fn same_length_held_out_haystacks(
    canonical: &ParsedKlv,
    canonical_expected: u64,
    seed: &[u8; 32],
    row_index: usize,
) -> Result<HeldOutHaystacks, DynError> {
    let length = canonical.haystack.len();
    let mut secret = Vec::with_capacity(length);
    let row_index = u64::try_from(row_index)?;
    let mut block_index = 0_u64;
    while secret.len() < length {
        let mut block = Sha256::new();
        block.update(b"fre-rebar-held-out-haystack-v1\0");
        block.update(seed);
        block.update(row_index.to_le_bytes());
        block.update(block_index.to_le_bytes());
        secret.extend_from_slice(&block.finalize());
        block_index = block_index
            .checked_add(1)
            .ok_or("qualification secret-stream counter overflow")?;
    }
    secret.truncate(length);
    let mut haystacks = [
        vec![0_u8; length],
        vec![0xff_u8; length],
        (0..length)
            .map(|index| if index.is_multiple_of(2) { b'a' } else { b'\n' })
            .collect::<Vec<_>>(),
        secret,
    ];
    if length == 0 {
        return Ok(HeldOutHaystacks {
            haystacks,
            plain_literal_witness: false,
        });
    }
    for index in 0..haystacks.len() {
        make_qualification_probe_distinct(&mut haystacks, index, &canonical.haystack)?;
    }
    let witness = plain_ascii_literal_witness(
        canonical,
        canonical_expected,
        [
            canonical.haystack.as_slice(),
            haystacks[0].as_slice(),
            haystacks[1].as_slice(),
        ],
    );
    let plain_literal_witness = witness.is_some();
    if let Some(witness) = witness {
        haystacks[2] = witness;
        // The secret stream can equal a one-byte or full-length witness. Keep
        // witness availability seed-independent by applying the same bounded
        // uniqueness adjustment already used for every nonempty probe.
        make_qualification_probe_distinct(&mut haystacks, 3, &canonical.haystack)?;
    }
    Ok(HeldOutHaystacks {
        haystacks,
        plain_literal_witness,
    })
}

fn make_qualification_probe_distinct(
    haystacks: &mut [Vec<u8>; QUALIFICATION_PROBES_PER_ROW],
    index: usize,
    canonical: &[u8],
) -> Result<(), DynError> {
    let mut attempts = 0_u16;
    while haystacks[index] == canonical
        || haystacks[..index]
            .iter()
            .any(|previous| previous == &haystacks[index])
    {
        haystacks[index][0] = haystacks[index][0].wrapping_add(1);
        attempts = attempts
            .checked_add(1)
            .ok_or("qualification mutation uniqueness counter overflow")?;
        if attempts > u16::from(u8::MAX) {
            return Err("could not construct distinct same-length qualification probes".into());
        }
    }
    Ok(())
}

fn plain_ascii_literal_witness(
    parsed: &ParsedKlv,
    canonical_expected: u64,
    forbidden: [&[u8]; 3],
) -> Option<Vec<u8>> {
    if canonical_expected != 0
        || !matches!(parsed.model.as_str(), "compile" | "count" | "count-spans")
        || parsed.case_insensitive
    {
        return None;
    }
    let [pattern] = parsed.patterns.as_slice() else {
        return None;
    };
    if pattern.is_empty()
        || pattern.len() > parsed.haystack.len()
        || !pattern.iter().copied().all(is_plain_ascii_literal_byte)
    {
        return None;
    }

    // A filler byte absent from the literal makes the inserted occurrence the
    // only possible occurrence: a later start either begins with the filler or
    // must cross into a filler byte that the literal does not contain.
    for filler in 0_u8..=u8::MAX {
        if pattern.contains(&filler) {
            continue;
        }
        let mut witness = vec![filler; parsed.haystack.len()];
        witness[..pattern.len()].copy_from_slice(pattern);
        if forbidden.iter().all(|reserved| *reserved != witness) {
            return Some(witness);
        }
    }
    None
}

fn is_plain_ascii_literal_byte(byte: u8) -> bool {
    (byte.is_ascii_graphic() || byte == b' ') && !b"\\.^$*+?()[]{}|".contains(&byte)
}

fn qualification_probe_kind(
    probe_index: usize,
    plain_literal_witness: bool,
) -> Result<&'static str, DynError> {
    match (probe_index, plain_literal_witness) {
        (0, _) => Ok("zero"),
        (1, _) => Ok("ff"),
        (2, true) => Ok("plain-ascii-literal-witness"),
        (2, false) => Ok("alternating-line"),
        (3, _) => Ok("secret-seeded"),
        _ => Err("qualification probe index is out of range".into()),
    }
}

fn validate_qualification_probe(
    canonical: &FreExecutorDescription,
    observed: &FreExecutorDescription,
    reference_actual: u64,
    candidate_actual: u64,
) -> Result<(), DynError> {
    if observed != canonical {
        return Err("FRE candidate plan/runtime changed on a same-length held-out haystack".into());
    }
    if candidate_actual != reference_actual {
        return Err(format!(
            "FRE held-out candidate returned {candidate_actual}, trusted Rust reference returned {reference_actual}"
        )
        .into());
    }
    Ok(())
}

fn require_preregistered_invariant_identity(
    expectations: FreExpectations<'_>,
    canonical: &FreExecutorDescription,
) -> Result<(), DynError> {
    validate_fre_description(canonical, expectations)?;
    match (expectations.model, canonical.candidate_plan.as_str()) {
        ("compile", FORMAL_COMPILE_PLAN) if canonical.candidate_runtime.is_none() => Ok(()),
        ("count", plan)
            if canonical.candidate_runtime.is_none() && preregistered_count_plan(plan) =>
        {
            Ok(())
        }
        ("count-spans", plan)
            if canonical.candidate_runtime.is_none() && preregistered_complete_spans_plan(plan) =>
        {
            Ok(())
        }
        ("grep", FORMAL_GREP_PLAN)
            if matches!(
                canonical.candidate_runtime.as_deref(),
                Some("k0" | "ascii-word-run-linear-v1" | "unicode-word-run-linear-v1")
            ) =>
        {
            Ok(())
        }
        _ => Err(
            "oracle-invariant row is outside the exact audited formal plan/runtime allowlist"
                .into(),
        ),
    }
}

fn preregistered_count_plan(plan: &str) -> bool {
    matches!(
        plan,
        "aggregate-ascii-casefold-literal-alternation-v1"
            | "aggregate-fixed-unicode-class-sequence-v1"
            | "aggregate-terminal-byte-frontier-count-v1"
            | "aggregate-unicode-folded-literal-v4"
            | "aggregate-casefold-canonical-bytes-sparse-v2"
            | "aggregate-exact-literal"
            | "aggregate-unicode-scalar-class"
            | "aggregate-word-run-v1"
            | "aggregate-fixed-class-chunks-v1"
            | "aggregate-literal-assertions-v1"
            | "aggregate-blocking-delimiter-v1"
            | "aggregate-token-phrase-v2"
            | "aggregate-fixed-class-sandwich"
            | "aggregate-literal-class-run-literal-v2"
            | "aggregate-reverse-inner-independent-v1"
            | "aggregate-reverse-inner-adaptive-union-v2"
            | "aggregate-reverse-inner-grouped-union-v2"
            | "aggregate-grapheme-scalar-dfa"
            | "aggregate-bounded-class-sequence"
            | "aggregate-bounded-separated-fields"
            | "aggregate-delimiter-field-spans"
            | "aggregate-prefix-class-alternation"
            | "aggregate-bounded-context"
            | "aggregate-bounded-affix"
            | "aggregate-fixed-absolute-domain"
            | "aggregate-bounded-literal-pair-v1"
            | "aggregate-bounded-literal-pair-v2"
            | "aggregate-finite-literal-bucket-trie-count-v1"
            | "aggregate-finite-literal-sparse"
            | "aggregate-finite-literal-dfa"
            | "aggregate-finite-literal-packed-v3"
            | "aggregate-guarded-ascii-word"
            | "aggregate-guarded-unicode-word"
            | "aggregate-fixed-predicate-word64"
            | "aggregate-url"
            | "aggregate-continuation-program"
            | "aggregate-many-ordered-literal"
            | "aggregate-many-continuation-program"
    )
}

fn preregistered_complete_spans_plan(plan: &str) -> bool {
    matches!(
        plan,
        "aggregate-many-ordered-literal"
            | "aggregate-many-continuation-program"
            | "aggregate-many-ascii-word-shadow-continuation-sweep-v1"
    ) || plan.starts_with("rebar-complete-spans-aggregate-visit-v1-")
        || plan.starts_with("rebar-complete-spans-portable-find-v2-")
        || plan.starts_with("rebar-complete-spans-portable-visit-v1-")
}

fn rebar_klv(rebar_bin: &Path, checkout: &Path, benchmark: &str) -> Result<Vec<u8>, DynError> {
    let output = Command::new(rebar_bin)
        .current_dir(checkout)
        .args([
            "klv",
            "--max-iters",
            "1",
            "--max-warmup-iters",
            "0",
            "--max-time",
            "0ns",
            "--max-warmup-time",
            "0ns",
            benchmark,
        ])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "Rebar KLV failed for {benchmark}: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output.stdout)
}

#[derive(Clone, Debug)]
struct ParsedKlv {
    name: String,
    model: String,
    patterns: Vec<Vec<u8>>,
    case_insensitive: bool,
    unicode: bool,
    haystack: Vec<u8>,
    max_iters: u64,
    max_warmup_iters: u64,
    max_time: u64,
    max_warmup_time: u64,
}

fn verify_klv(bytes: &[u8], receipt: &Receipt) -> Result<(), DynError> {
    let parsed = ParsedKlv::parse(bytes)?;
    let pattern_sha256 = parsed
        .patterns
        .iter()
        .map(|pattern| sha256(pattern))
        .collect::<Vec<_>>();
    if parsed.name != receipt.benchmark
        || parsed.model != receipt.model
        || pattern_sha256 != receipt.input.pattern_sha256
        || sha256(&parsed.haystack) != receipt.input.haystack_sha256
        || parsed.haystack.len() != receipt.input.haystack_bytes
        || parsed.unicode != receipt.input.unicode
        || parsed.case_insensitive != receipt.input.case_insensitive
        || parsed.max_iters != 1
        || parsed.max_warmup_iters != 0
        || parsed.max_time != 0
        || parsed.max_warmup_time != 0
    {
        return Err(format!("KLV identity differs from receipt {}", receipt.job_id).into());
    }
    Ok(())
}

impl ParsedKlv {
    fn parse(mut input: &[u8]) -> Result<Self, DynError> {
        let mut name = None;
        let mut model = None;
        let mut patterns = Vec::new();
        let mut case_insensitive = None;
        let mut unicode = None;
        let mut haystack = None;
        let mut max_iters = None;
        let mut max_warmup_iters = None;
        let mut max_time = None;
        let mut max_warmup_time = None;
        while !input.is_empty() {
            let key_end = input
                .iter()
                .position(|&byte| byte == b':')
                .ok_or("KLV field has no key delimiter")?;
            let key = std::str::from_utf8(&input[..key_end])?;
            input = &input[key_end + 1..];
            let length_end = input
                .iter()
                .position(|&byte| byte == b':')
                .ok_or("KLV field has no length delimiter")?;
            let length = std::str::from_utf8(&input[..length_end])?.parse::<usize>()?;
            input = &input[length_end + 1..];
            let value_end = length.checked_add(1).ok_or("KLV field length overflow")?;
            if input.len() < value_end || input[length] != b'\n' {
                return Err("KLV field is truncated or lacks trailing newline".into());
            }
            let value = &input[..length];
            input = &input[value_end..];
            match key {
                "name" => set_once(&mut name, utf8(value, key)?.to_owned(), key)?,
                "model" => set_once(&mut model, utf8(value, key)?.to_owned(), key)?,
                "pattern" => patterns.push(value.to_vec()),
                "case-insensitive" => {
                    set_once(&mut case_insensitive, parse_bool(value, key)?, key)?;
                }
                "unicode" => set_once(&mut unicode, parse_bool(value, key)?, key)?,
                "haystack" => set_once(&mut haystack, value.to_vec(), key)?,
                "max-iters" => set_once(&mut max_iters, parse_u64(value, key)?, key)?,
                "max-warmup-iters" => {
                    set_once(&mut max_warmup_iters, parse_u64(value, key)?, key)?;
                }
                "max-time" => set_once(&mut max_time, parse_u64(value, key)?, key)?,
                "max-warmup-time" => {
                    set_once(&mut max_warmup_time, parse_u64(value, key)?, key)?;
                }
                unknown => return Err(format!("unrecognized KLV key {unknown:?}").into()),
            }
        }
        Ok(Self {
            name: required(name, "name")?,
            model: required(model, "model")?,
            patterns,
            case_insensitive: required(case_insensitive, "case-insensitive")?,
            unicode: required(unicode, "unicode")?,
            haystack: required(haystack, "haystack")?,
            max_iters: required(max_iters, "max-iters")?,
            max_warmup_iters: required(max_warmup_iters, "max-warmup-iters")?,
            max_time: required(max_time, "max-time")?,
            max_warmup_time: required(max_warmup_time, "max-warmup-time")?,
        })
    }

    fn fre_executor_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        append_executor_field(
            &mut output,
            "schema",
            FRE_EXECUTOR_REQUEST_SCHEMA.as_bytes(),
        );
        append_executor_field(
            &mut output,
            "mode",
            if self.model == "regex-redux" {
                b"performance-raw"
            } else {
                b"samples"
            },
        );
        append_executor_field(&mut output, "model", self.model.as_bytes());
        append_executor_field(
            &mut output,
            "case-insensitive",
            self.case_insensitive.to_string().as_bytes(),
        );
        append_executor_field(&mut output, "unicode", self.unicode.to_string().as_bytes());
        if self.model == "regex-redux" {
            append_executor_field(&mut output, "boundary", b"complete-regex-redux");
        }
        for pattern in &self.patterns {
            append_executor_field(&mut output, "pattern", pattern);
        }
        append_executor_field(&mut output, "haystack", &self.haystack);
        output
    }

    fn reference_executor_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        append_executor_field(&mut output, "name", b"anonymous/rebar-workload");
        append_executor_field(&mut output, "model", self.model.as_bytes());
        for pattern in &self.patterns {
            append_executor_field(&mut output, "pattern", pattern);
        }
        append_executor_field(
            &mut output,
            "case-insensitive",
            self.case_insensitive.to_string().as_bytes(),
        );
        append_executor_field(&mut output, "unicode", self.unicode.to_string().as_bytes());
        append_executor_field(&mut output, "haystack", &self.haystack);
        append_executor_field(
            &mut output,
            "max-iters",
            self.max_iters.to_string().as_bytes(),
        );
        append_executor_field(
            &mut output,
            "max-warmup-iters",
            self.max_warmup_iters.to_string().as_bytes(),
        );
        append_executor_field(
            &mut output,
            "max-time",
            self.max_time.to_string().as_bytes(),
        );
        append_executor_field(
            &mut output,
            "max-warmup-time",
            self.max_warmup_time.to_string().as_bytes(),
        );
        output
    }
}

fn append_executor_field(output: &mut Vec<u8>, key: &str, value: &[u8]) {
    write!(output, "{key}:{}:", value.len()).expect("write to Vec");
    output.extend_from_slice(value);
    output.push(b'\n');
}

fn utf8<'a>(value: &'a [u8], key: &str) -> Result<&'a str, DynError> {
    std::str::from_utf8(value).map_err(|error| format!("{key} is not UTF-8: {error}").into())
}

fn parse_bool(value: &[u8], key: &str) -> Result<bool, DynError> {
    match utf8(value, key)? {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(format!("{key} has invalid boolean {other:?}").into()),
    }
}

fn parse_u64(value: &[u8], key: &str) -> Result<u64, DynError> {
    utf8(value, key)?
        .parse::<u64>()
        .map_err(|error| format!("{key} has invalid integer: {error}").into())
}

fn set_once<T>(slot: &mut Option<T>, value: T, key: &str) -> Result<(), DynError> {
    if slot.replace(value).is_some() {
        return Err(format!("duplicate scalar KLV key {key:?}").into());
    }
    Ok(())
}

fn required<T>(value: Option<T>, key: &str) -> Result<T, DynError> {
    value.ok_or_else(|| format!("missing required KLV key {key:?}").into())
}

#[derive(Clone, Copy)]
enum Comparator {
    Rust,
    Re2,
}

fn run_schedule(runners: &Runners, rows: &mut [PreparedRow<'_>]) -> Result<(), DynError> {
    if rows.is_empty() {
        return Err("preregistered campaign is empty".into());
    }
    let mut sequence = 0_usize;
    for pair_index in 0..PAIRS {
        for offset in 0..rows.len() {
            let row_index = (offset + pair_index) % rows.len();
            let comparators = if (row_index + pair_index).is_multiple_of(2) {
                [Comparator::Rust, Comparator::Re2]
            } else {
                [Comparator::Re2, Comparator::Rust]
            };
            for comparator in comparators {
                if matches!(comparator, Comparator::Re2) && rows[row_index].selected.re2.is_none() {
                    continue;
                }
                let pair = run_pair(runners, &rows[row_index], comparator, pair_index, sequence)?;
                sequence = sequence
                    .checked_add(1)
                    .ok_or("schedule sequence overflow")?;
                match comparator {
                    Comparator::Rust => rows[row_index].rust_pairs.push(pair),
                    Comparator::Re2 => rows[row_index].re2_pairs.push(pair),
                }
            }
        }
    }
    Ok(())
}

fn run_pair(
    runners: &Runners,
    row: &PreparedRow<'_>,
    comparator: Comparator,
    pair_index: usize,
    sequence: usize,
) -> Result<RawPair, DynError> {
    let reference = match comparator {
        Comparator::Rust => &runners.rust,
        Comparator::Re2 => &runners.re2,
    };
    let fre_first = pair_index.is_multiple_of(2);
    let expectations = FreExpectations {
        benchmark: &row.selected.fre.benchmark,
        model: &row.selected.fre.model,
        plan: row
            .selected
            .fre
            .candidate_plan
            .as_deref()
            .ok_or("FRE receipt lacks plan")?,
        runtime: expected_grep_runtime(&row.selected.fre.model, &row.selected.fre.job_id),
    };
    let (fre, reference_sample) = if fre_first {
        (
            runners
                .fre
                .sample(&row.klv, row.selected.fre.expected, Some(expectations))?,
            reference.sample(&row.klv, row.selected.fre.expected, None)?,
        )
    } else {
        let reference_sample = reference.sample(&row.klv, row.selected.fre.expected, None)?;
        let fre = runners
            .fre
            .sample(&row.klv, row.selected.fre.expected, Some(expectations))?;
        (fre, reference_sample)
    };
    Ok(RawPair {
        sequence,
        pair_index,
        order: if fre_first {
            vec![runners.fre.name.clone(), reference.name.clone()]
        } else {
            vec![reference.name.clone(), runners.fre.name.clone()]
        },
        fre,
        reference: reference_sample,
        ratio_ppm: ratio_ppm(fre.duration_ns, reference_sample.duration_ns)?,
    })
}

fn expected_grep_runtime(model: &str, job_id: &str) -> Option<&'static str> {
    if model != "grep" {
        return None;
    }
    match job_id {
        "grep/long-words-unicode@rust/regex" => Some("unicode-word-run-linear-v1"),
        "grep/long-words-ascii@rust/regex" => Some("ascii-word-run-linear-v1"),
        _ => Some("k0"),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct Runner {
    name: String,
    path: PathBuf,
    sha256: String,
    version: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum FreExecutorMode {
    Samples,
    CaptureRaw,
    PerformanceRaw,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct FreExecutorDescription {
    schema: String,
    mode: FreExecutorMode,
    model: String,
    candidate_plan: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    candidate_runtime: Option<String>,
    priming_operations: u8,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct FreExecutorSample {
    elapsed_ns: u64,
    actual: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct FreExecutorResponse {
    schema: String,
    mode: FreExecutorMode,
    model: String,
    candidate_plan: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    candidate_runtime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    regex_redux_stage_receipt: Option<RegexReduxStageReceipt>,
    priming_operations: u8,
    samples: Vec<FreExecutorSample>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct RegexReduxStageReceipt {
    input_length: u64,
    clean_length: u64,
    variant_counts: [u64; 9],
    substitution_lengths: [u64; 5],
    final_length: u64,
    report_length: u64,
}

#[derive(Clone, Copy)]
enum VersionRule<'a> {
    Exact(&'a str),
    Fre,
}

impl Runner {
    fn authenticate(
        name: &str,
        path: &Path,
        expected_sha256: &str,
        version_rule: VersionRule<'_>,
    ) -> Result<Self, DynError> {
        let canonical = fs::canonicalize(path)?;
        let sha256 = exact_file_hash(&canonical, expected_sha256, name)?;
        let mut command = Command::new(&canonical);
        command.arg("--version").env_clear().current_dir("/");
        let (status, stdout, stderr) = invoke_command_bounded(command, None)?;
        if !status.success() || !stderr.is_empty() {
            return Err(format!("{name} --version failed").into());
        }
        let version = String::from_utf8(stdout)?.trim().to_owned();
        match version_rule {
            VersionRule::Exact(expected) if version != expected => {
                return Err(format!("{name} version {version:?} differs from {expected:?}").into());
            }
            VersionRule::Fre => authenticate_fre_version(&version)?,
            VersionRule::Exact(_) => {}
        }
        Ok(Self {
            name: name.to_owned(),
            path: canonical,
            sha256,
            version,
        })
    }

    fn sample(
        &self,
        klv: &[u8],
        expected: u64,
        fre: Option<FreExpectations<'_>>,
    ) -> Result<RawSample, DynError> {
        let parsed = ParsedKlv::parse(klv)?;
        if let Some(expectations) = fre {
            return self.sample_fre(&parsed, expected, expectations);
        }
        let input = parsed.reference_executor_bytes();
        let output = self.invoke_bounded(None, &input)?;
        parse_reference_sample(&self.name, expected, &output)
    }

    fn sample_reference_unchecked(&self, parsed: &ParsedKlv) -> Result<RawSample, DynError> {
        let input = parsed.reference_executor_bytes();
        let output = self.invoke_bounded(None, &input)?;
        parse_reference_sample_unchecked(&self.name, &output)
    }

    fn describe_fre(
        &self,
        parsed: &ParsedKlv,
        expectations: FreExpectations<'_>,
    ) -> Result<FreExecutorDescription, DynError> {
        if parsed.name != expectations.benchmark || parsed.model != expectations.model {
            return Err("outer collector KLV identity differs from FRE receipt".into());
        }
        let request = parsed.fre_executor_bytes();
        let bytes = self.invoke_bounded(Some(FRE_DESCRIBE_FLAG), &request)?;
        let description = parse_canonical_json(&bytes, "FRE executor description")?;
        validate_fre_description(&description, expectations)?;
        Ok(description)
    }

    fn sample_fre(
        &self,
        parsed: &ParsedKlv,
        expected: u64,
        expectations: FreExpectations<'_>,
    ) -> Result<RawSample, DynError> {
        self.sample_fre_with_description(parsed, expected, expectations)
            .map(|(_, sample)| sample)
    }

    fn sample_fre_with_description(
        &self,
        parsed: &ParsedKlv,
        expected: u64,
        expectations: FreExpectations<'_>,
    ) -> Result<(FreExecutorDescription, RawSample), DynError> {
        if parsed.name != expectations.benchmark || parsed.model != expectations.model {
            return Err("outer collector KLV identity differs from FRE receipt".into());
        }
        let request = parsed.fre_executor_bytes();
        let expected_regex_redux_stage_receipt = trusted_regex_redux_stage_receipt(parsed)?;
        collect_fre_sample_with_description(
            expectations,
            expected,
            expected_regex_redux_stage_receipt.as_ref(),
            || {
                let bytes = self.invoke_bounded(Some(FRE_DESCRIBE_FLAG), &request)?;
                parse_canonical_json(&bytes, "FRE executor description")
            },
            || {
                let bytes = self.invoke_bounded(Some(FRE_EXECUTOR_FLAG), &request)?;
                parse_canonical_json(&bytes, "FRE executor response")
            },
        )
    }

    fn invoke_bounded(&self, argument: Option<&str>, input: &[u8]) -> Result<Vec<u8>, DynError> {
        let mut command = Command::new(&self.path);
        if let Some(argument) = argument {
            command.arg(argument);
        }
        command.env_clear().current_dir("/");
        let (status, stdout, stderr) = invoke_command_bounded(command, Some(input))?;
        if !status.success() {
            return Err(format!(
                "{} runner failed: {}",
                self.name,
                String::from_utf8_lossy(&stderr)
            )
            .into());
        }
        if !stderr.is_empty() {
            return Err(format!("{} runner wrote stderr", self.name).into());
        }
        Ok(stdout)
    }
}

fn invoke_command_bounded(
    command: Command,
    input: Option<&[u8]>,
) -> Result<(std::process::ExitStatus, Vec<u8>, Vec<u8>), DynError> {
    invoke_command_bounded_with_limits(command, input, RUNNER_WALL_TIMEOUT, MAX_RUNNER_OUTPUT_BYTES)
}

enum RunnerWorkerEvent {
    Stdin(Result<(), String>),
    Stdout(Result<Vec<u8>, String>),
    Stderr(Result<Vec<u8>, String>),
}

struct RunnerWorkerState {
    stdin_done: bool,
    stdout: Option<Vec<u8>>,
    stderr: Option<Vec<u8>>,
}

struct RunnerProcessGroup {
    anchor: Child,
    anchor_stdin: Option<ChildStdin>,
    id: i32,
    anchor_reaped: bool,
}

impl RunnerProcessGroup {
    fn spawn() -> Result<Self, DynError> {
        // Keep a collector-owned process alive as the process-group leader.
        // Without it, `Child::try_wait` reaps the candidate before descendant
        // cleanup, and its numeric PGID could be reused before the group kill.
        let mut anchor = Command::new("/bin/cat")
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .map_err(|error| format!("spawn runner process-group anchor: {error}"))?;
        let id = match i32::try_from(anchor.id()) {
            Ok(id) => id,
            Err(error) => {
                let _ = anchor.kill();
                let _ = anchor.wait();
                return Err(format!("runner process-group ID does not fit pid_t: {error}").into());
            }
        };
        let anchor_stdin = match anchor.stdin.take() {
            Some(stdin) => stdin,
            None => {
                let _ = anchor.kill();
                let _ = anchor.wait();
                return Err("runner process-group anchor stdin is absent".into());
            }
        };
        Ok(Self {
            anchor,
            anchor_stdin: Some(anchor_stdin),
            id,
            anchor_reaped: false,
        })
    }

    fn configure_candidate(&self, command: &mut Command) {
        command.process_group(self.id);
    }

    fn require_live_anchor(&mut self) -> Result<(), String> {
        if self.anchor_reaped {
            return Err("runner process-group anchor exited early".to_string());
        }
        match self.anchor.try_wait() {
            Ok(None) => Ok(()),
            Ok(Some(status)) => {
                self.anchor_reaped = true;
                Err(format!(
                    "runner process-group anchor exited early with {status}"
                ))
            }
            Err(error) => Err(format!("poll runner process-group anchor: {error}")),
        }
    }
}

impl RunnerWorkerState {
    const fn new(has_input: bool) -> Self {
        Self {
            stdin_done: !has_input,
            stdout: None,
            stderr: None,
        }
    }

    fn record(&mut self, event: RunnerWorkerEvent) -> Result<(), String> {
        match event {
            RunnerWorkerEvent::Stdin(result) => {
                if self.stdin_done {
                    return Err("runner stdin worker completed twice".to_string());
                }
                result?;
                self.stdin_done = true;
            }
            RunnerWorkerEvent::Stdout(result) => {
                if self.stdout.is_some() {
                    return Err("runner stdout worker completed twice".to_string());
                }
                self.stdout = Some(result?);
            }
            RunnerWorkerEvent::Stderr(result) => {
                if self.stderr.is_some() {
                    return Err("runner stderr worker completed twice".to_string());
                }
                self.stderr = Some(result?);
            }
        }
        Ok(())
    }

    const fn complete(&self) -> bool {
        self.stdin_done && self.stdout.is_some() && self.stderr.is_some()
    }
}

fn invoke_command_bounded_with_limits(
    mut command: Command,
    input: Option<&[u8]>,
    wall_timeout: Duration,
    maximum_output_bytes: usize,
) -> Result<(ExitStatus, Vec<u8>, Vec<u8>), DynError> {
    if wall_timeout.is_zero() {
        return Err("runner wall timeout must be nonzero".into());
    }
    if maximum_output_bytes == 0 {
        return Err("runner output bound must be nonzero".into());
    }
    let input = input.map(<[u8]>::to_vec);
    let has_input = input.is_some();
    let mut process_group = RunnerProcessGroup::spawn()?;
    command
        .stdin(if has_input {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    process_group.configure_candidate(&mut command);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let cleanup = terminate_runner_processes(&mut process_group, None, true);
            return Err(with_cleanup_error(&format!("spawn runner: {error}"), cleanup).into());
        }
    };
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            let cleanup = terminate_runner_processes(&mut process_group, Some(&mut child), false);
            return Err(with_cleanup_error("runner stdout is absent", cleanup).into());
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            let cleanup = terminate_runner_processes(&mut process_group, Some(&mut child), false);
            return Err(with_cleanup_error("runner stderr is absent", cleanup).into());
        }
    };
    let stdin = if has_input {
        match child.stdin.take() {
            Some(stdin) => Some(stdin),
            None => {
                let cleanup =
                    terminate_runner_processes(&mut process_group, Some(&mut child), false);
                return Err(with_cleanup_error("runner stdin is absent", cleanup).into());
            }
        }
    } else {
        None
    };

    let (events, receiver) = mpsc::channel();
    let mut workers = Vec::with_capacity(if stdin.is_some() { 3 } else { 2 });
    let stdout_worker = spawn_runner_worker("rebar-runner-stdout", events.clone(), move || {
        RunnerWorkerEvent::Stdout(read_runner_pipe_bounded(
            stdout,
            "runner stdout",
            maximum_output_bytes,
        ))
    });
    match stdout_worker {
        Ok(worker) => workers.push(worker),
        Err(error) => {
            let cleanup = cleanup_runner_failure(&mut child, &mut process_group, false, workers);
            return Err(with_cleanup_error(
                &format!("spawn runner stdout worker: {error}"),
                cleanup,
            )
            .into());
        }
    }
    let stderr_worker = spawn_runner_worker("rebar-runner-stderr", events.clone(), move || {
        RunnerWorkerEvent::Stderr(read_runner_pipe_bounded(
            stderr,
            "runner stderr",
            maximum_output_bytes,
        ))
    });
    match stderr_worker {
        Ok(worker) => workers.push(worker),
        Err(error) => {
            let cleanup = cleanup_runner_failure(&mut child, &mut process_group, false, workers);
            return Err(with_cleanup_error(
                &format!("spawn runner stderr worker: {error}"),
                cleanup,
            )
            .into());
        }
    }
    if let (Some(mut stdin), Some(input)) = (stdin, input) {
        let stdin_worker = spawn_runner_worker("rebar-runner-stdin", events.clone(), move || {
            RunnerWorkerEvent::Stdin(
                stdin
                    .write_all(&input)
                    .map_err(|error| format!("write runner stdin: {error}")),
            )
        });
        match stdin_worker {
            Ok(worker) => workers.push(worker),
            Err(error) => {
                let cleanup =
                    cleanup_runner_failure(&mut child, &mut process_group, false, workers);
                return Err(with_cleanup_error(
                    &format!("spawn runner stdin worker: {error}"),
                    cleanup,
                )
                .into());
            }
        }
    }
    drop(events);

    let started = Instant::now();
    let mut state = RunnerWorkerState::new(has_input);
    let mut status = None;
    let mut exit_observed = None;
    let mut failure = None;
    loop {
        loop {
            match receiver.try_recv() {
                Ok(event) => {
                    if let Err(error) = state.record(event) {
                        failure = Some(error);
                        break;
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    if !state.complete() {
                        failure = Some("runner I/O worker channel closed early".to_string());
                    }
                    break;
                }
            }
        }
        if failure.is_some() {
            break;
        }
        if let Err(error) = process_group.require_live_anchor() {
            failure = Some(error);
            break;
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(Some(observed)) => {
                    status = Some(observed);
                    exit_observed = Some(Instant::now());
                }
                Ok(None) => {}
                Err(error) => {
                    failure = Some(format!("poll runner process: {error}"));
                    break;
                }
            }
        }
        if status.is_some() && state.complete() {
            break;
        }
        if exit_observed.is_some_and(|observed| observed.elapsed() >= RUNNER_EXIT_PIPE_GRACE) {
            failure = Some("runner pipes remained open after the direct child exited".to_string());
            break;
        }
        if started.elapsed() >= wall_timeout {
            failure = Some(format!(
                "runner exceeded monotonic wall deadline of {} ms",
                wall_timeout.as_millis()
            ));
            break;
        }
        thread::sleep(RUNNER_CHILD_POLL);
    }

    if let Some(error) = failure {
        let cleanup =
            cleanup_runner_failure(&mut child, &mut process_group, status.is_some(), workers);
        let error = with_cleanup_error(&error, cleanup);
        return Err(error.into());
    }

    // Even a successful direct child may have left a same-group descendant
    // whose standard descriptors were redirected. It is not part of the
    // one-process runner contract and must not survive this invocation.
    terminate_runner_processes(&mut process_group, Some(&mut child), true)?;
    finish_runner_workers(workers)?;
    let status = status.ok_or("runner completed without an exit status")?;
    let stdout = state.stdout.ok_or("runner stdout worker did not finish")?;
    let stderr = state.stderr.ok_or("runner stderr worker did not finish")?;
    Ok((status, stdout, stderr))
}

fn spawn_runner_worker<F>(
    name: &'static str,
    events: mpsc::Sender<RunnerWorkerEvent>,
    work: F,
) -> std::io::Result<thread::JoinHandle<()>>
where
    F: FnOnce() -> RunnerWorkerEvent + Send + 'static,
{
    thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            let _ = events.send(work());
        })
}

fn read_runner_pipe_bounded(
    mut pipe: impl Read,
    label: &'static str,
    maximum: usize,
) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::with_capacity(maximum.min(16 * 1_024));
    let mut chunk = [0_u8; 4_096];
    loop {
        let read = pipe
            .read(&mut chunk)
            .map_err(|error| format!("read {label}: {error}"))?;
        if read == 0 {
            return Ok(bytes);
        }
        let next = bytes
            .len()
            .checked_add(read)
            .ok_or_else(|| format!("{label} byte count overflow"))?;
        if next > maximum {
            return Err(format!("{label} exceeds {maximum} bytes"));
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
}

fn finish_runner_workers(workers: Vec<thread::JoinHandle<()>>) -> Result<(), String> {
    let started = Instant::now();
    while workers.iter().any(|worker| !worker.is_finished())
        && started.elapsed() < RUNNER_CLEANUP_GRACE
    {
        thread::sleep(RUNNER_CHILD_POLL);
    }
    if workers.iter().any(|worker| !worker.is_finished()) {
        return Err("runner I/O workers survived process cleanup".to_string());
    }
    for worker in workers {
        worker
            .join()
            .map_err(|_| "runner I/O worker panicked".to_string())?;
    }
    Ok(())
}

fn cleanup_runner_failure(
    child: &mut Child,
    process_group: &mut RunnerProcessGroup,
    child_reaped: bool,
    workers: Vec<thread::JoinHandle<()>>,
) -> Result<(), String> {
    let process = terminate_runner_processes(process_group, Some(child), child_reaped);
    let workers = finish_runner_workers(workers);
    match (process, workers) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(process), Ok(())) => Err(process),
        (Ok(()), Err(workers)) => Err(workers),
        (Err(process), Err(workers)) => Err(format!("{process}; {workers}")),
    }
}

fn terminate_runner_processes(
    process_group: &mut RunnerProcessGroup,
    mut child: Option<&mut Child>,
    mut child_reaped: bool,
) -> Result<(), String> {
    let mut errors = Vec::new();
    if let Err(error) = signal_runner_process_group(process_group.id) {
        errors.push(error);
    }
    // Always address the two direct children by PID as well. A candidate can
    // deliberately leave the anchored process group; successful group
    // signaling must not then be mistaken for successful candidate cleanup.
    if !child_reaped {
        match child.as_deref_mut() {
            Some(child) => {
                kill_runner_process(child, &mut child_reaped, "runner process", &mut errors)
            }
            None => errors.push("runner process handle is absent during cleanup".to_string()),
        }
    }
    kill_runner_process(
        &mut process_group.anchor,
        &mut process_group.anchor_reaped,
        "runner process-group anchor",
        &mut errors,
    );
    // Closing the keepalive also lets the anchor exit if group signaling
    // failed after it was spawned but before it delivered SIGKILL.
    process_group.anchor_stdin.take();

    let started = Instant::now();
    let mut child_poll_failed = false;
    let mut anchor_poll_failed = false;
    while (!child_reaped || !process_group.anchor_reaped)
        && started.elapsed() < RUNNER_CLEANUP_GRACE
    {
        if !child_reaped && !child_poll_failed {
            match child.as_deref_mut() {
                Some(child) => match child.try_wait() {
                    Ok(Some(_)) => child_reaped = true,
                    Ok(None) => {}
                    Err(error) => {
                        errors.push(format!("reap runner process: {error}"));
                        child_poll_failed = true;
                    }
                },
                None => {
                    errors.push("runner process handle is absent during cleanup".to_string());
                    child_poll_failed = true;
                }
            }
        }
        if !process_group.anchor_reaped && !anchor_poll_failed {
            match process_group.anchor.try_wait() {
                Ok(Some(_)) => process_group.anchor_reaped = true,
                Ok(None) => {}
                Err(error) => {
                    errors.push(format!("reap runner process-group anchor: {error}"));
                    anchor_poll_failed = true;
                }
            }
        }
        if !child_reaped || !process_group.anchor_reaped {
            thread::sleep(RUNNER_CHILD_POLL);
        }
    }
    if !child_reaped {
        errors.push("runner process survived SIGKILL and reap deadline".to_string());
    }
    if !process_group.anchor_reaped {
        errors.push("runner process-group anchor survived SIGKILL and reap deadline".to_string());
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn kill_runner_process(
    child: &mut Child,
    reaped: &mut bool,
    label: &str,
    errors: &mut Vec<String>,
) {
    if *reaped {
        return;
    }
    if let Err(kill_error) = child.kill() {
        match child.try_wait() {
            Ok(Some(_)) => *reaped = true,
            Ok(None) => errors.push(format!("kill {label} directly: {kill_error}")),
            Err(wait_error) => errors.push(format!(
                "kill {label} directly: {kill_error}; poll after failed kill: {wait_error}"
            )),
        }
    }
}

fn signal_runner_process_group(process_group: i32) -> Result<(), String> {
    let group = format!("-{process_group}");
    let mut signaler = Command::new("/bin/kill")
        .args(["-KILL", "--", group.as_str()])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("spawn process-group signaler: {error}"))?;
    let started = Instant::now();
    loop {
        match signaler.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => {
                return Err(format!(
                    "process-group signaler failed with exit status {status}"
                ));
            }
            Ok(None) if started.elapsed() < RUNNER_SIGNAL_TIMEOUT => {
                thread::sleep(RUNNER_CHILD_POLL);
            }
            Ok(None) => {
                let cleanup = terminate_runner_signaler(&mut signaler);
                return Err(with_cleanup_error(
                    "process-group signaler exceeded monotonic deadline",
                    cleanup,
                ));
            }
            Err(error) => {
                let cleanup = terminate_runner_signaler(&mut signaler);
                return Err(with_cleanup_error(
                    &format!("wait for process-group signaler: {error}"),
                    cleanup,
                ));
            }
        }
    }
}

fn terminate_runner_signaler(signaler: &mut Child) -> Result<(), String> {
    let mut errors = Vec::new();
    if let Err(error) = signaler.kill() {
        errors.push(format!("kill process-group signaler: {error}"));
    }
    let started = Instant::now();
    loop {
        match signaler.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if started.elapsed() < RUNNER_CLEANUP_GRACE => {
                thread::sleep(RUNNER_CHILD_POLL);
            }
            Ok(None) => {
                errors
                    .push("process-group signaler survived SIGKILL and reap deadline".to_string());
                break;
            }
            Err(error) => {
                errors.push(format!("reap process-group signaler: {error}"));
                break;
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn with_cleanup_error(primary: &str, cleanup: Result<(), String>) -> String {
    match cleanup {
        Ok(()) => primary.to_string(),
        Err(cleanup) => format!("{primary}; cleanup failed: {cleanup}"),
    }
}

fn parse_reference_sample(
    runner: &str,
    expected: u64,
    output: &[u8],
) -> Result<RawSample, DynError> {
    let sample = parse_reference_sample_unchecked(runner, output)?;
    if sample.count != expected {
        return Err(format!(
            "{runner} runner returned {}, expected {expected}",
            sample.count
        )
        .into());
    }
    Ok(sample)
}

fn parse_reference_sample_unchecked(runner: &str, output: &[u8]) -> Result<RawSample, DynError> {
    let text = std::str::from_utf8(output)?;
    let mut lines = text.lines();
    let line = lines.next().ok_or("runner returned no timing sample")?;
    if lines.next().is_some() {
        return Err(format!("{runner} runner returned multiple timing samples").into());
    }
    let (duration, count) = line
        .split_once(',')
        .ok_or("runner sample lacks comma delimiter")?;
    let duration_ns = duration.parse::<u64>()?;
    let count = count.parse::<u64>()?;
    if duration_ns == 0 {
        return Err(format!("{runner} runner returned a zero-duration sample").into());
    }
    Ok(RawSample { duration_ns, count })
}

fn validate_fre_description(
    description: &FreExecutorDescription,
    expectations: FreExpectations<'_>,
) -> Result<(), DynError> {
    let expected_mode = if expectations.model == "regex-redux" {
        FreExecutorMode::PerformanceRaw
    } else {
        FreExecutorMode::Samples
    };
    if description.schema != FRE_EXECUTOR_DESCRIPTION_SCHEMA
        || description.mode != expected_mode
        || description.model != expectations.model
        || description.candidate_plan != expectations.plan
        || description.candidate_runtime.as_deref() != expectations.runtime
        || description.priming_operations != 0
    {
        return Err("FRE executor description differs from the authenticated receipt".into());
    }
    Ok(())
}

#[cfg(test)]
fn collect_fre_sample<D, M>(
    expectations: FreExpectations<'_>,
    expected: u64,
    expected_regex_redux_stage_receipt: Option<&RegexReduxStageReceipt>,
    describe: D,
    measure: M,
) -> Result<RawSample, DynError>
where
    D: FnOnce() -> Result<FreExecutorDescription, DynError>,
    M: FnOnce() -> Result<FreExecutorResponse, DynError>,
{
    collect_fre_sample_with_description(
        expectations,
        expected,
        expected_regex_redux_stage_receipt,
        describe,
        measure,
    )
    .map(|(_, sample)| sample)
}

fn collect_fre_sample_with_description<D, M>(
    expectations: FreExpectations<'_>,
    expected: u64,
    expected_regex_redux_stage_receipt: Option<&RegexReduxStageReceipt>,
    describe: D,
    measure: M,
) -> Result<(FreExecutorDescription, RawSample), DynError>
where
    D: FnOnce() -> Result<FreExecutorDescription, DynError>,
    M: FnOnce() -> Result<FreExecutorResponse, DynError>,
{
    let description = describe()?;
    validate_fre_description(&description, expectations)?;
    let response = measure()?;
    let sample = validate_fre_response(
        &response,
        &description,
        expected,
        expected_regex_redux_stage_receipt,
    )?;
    Ok((description, sample))
}

fn validate_fre_response(
    response: &FreExecutorResponse,
    description: &FreExecutorDescription,
    expected: u64,
    expected_regex_redux_stage_receipt: Option<&RegexReduxStageReceipt>,
) -> Result<RawSample, DynError> {
    if response.schema != FRE_EXECUTOR_RESPONSE_SCHEMA
        || response.mode != description.mode
        || response.model != description.model
        || response.candidate_plan != description.candidate_plan
        || response.candidate_runtime != description.candidate_runtime
        || response.priming_operations != description.priming_operations
    {
        return Err("measured FRE executor identity differs from its admitted description".into());
    }
    let [sample] = response.samples.as_slice() else {
        return Err("measured FRE executor must return exactly one sample".into());
    };
    if sample.elapsed_ns == 0 {
        return Err("measured FRE executor returned a zero-duration sample".into());
    }
    if sample.actual != expected {
        return Err(format!(
            "measured FRE executor returned {}, expected {expected}",
            sample.actual
        )
        .into());
    }
    match (
        description.model.as_str(),
        response.regex_redux_stage_receipt.as_ref(),
        expected_regex_redux_stage_receipt,
    ) {
        ("regex-redux", Some(actual), Some(expected)) if actual == expected => {}
        ("regex-redux", Some(actual), Some(expected)) => {
            return Err(format!(
                "measured FRE regex-redux stage evidence {actual:?} differs from trusted reference evidence {expected:?}"
            )
            .into());
        }
        ("regex-redux", _, _) => {
            return Err(
                "measured FRE regex-redux execution lacks independently derived stage evidence"
                    .into(),
            );
        }
        (_, None, None) => {}
        (_, Some(_), _) => {
            return Err("non-regex-redux FRE response contains regex-redux stage evidence".into());
        }
        (_, None, Some(_)) => {
            return Err("trusted regex-redux evidence was bound to a different model".into());
        }
    }
    Ok(RawSample {
        duration_ns: sample.elapsed_ns,
        count: sample.actual,
    })
}

const REGEX_REDUX_VARIANTS: [&str; 9] = [
    r"agggtaaa|tttaccct",
    r"[cgt]gggtaaa|tttaccc[acg]",
    r"a[act]ggtaaa|tttacc[agt]t",
    r"ag[act]gtaaa|tttac[agt]ct",
    r"agg[act]taaa|ttta[agt]cct",
    r"aggg[acg]aaa|ttt[cgt]ccct",
    r"agggt[cgt]aa|tt[acg]accct",
    r"agggta[cgt]a|t[acg]taccct",
    r"agggtaa[cgt]|[acg]ttaccct",
];

const REGEX_REDUX_SUBSTITUTIONS: [(&str, &str); 5] = [
    (r"tHa[Nt]", "<4>"),
    (r"aND|caN|Ha[DS]|WaS", "<3>"),
    (r"a[NSt]|BY", "<2>"),
    (r"<[^>]*>", "|"),
    (r"\|[^|][^|]*\|", "-"),
];

fn trusted_regex_redux_stage_receipt(
    parsed: &ParsedKlv,
) -> Result<Option<RegexReduxStageReceipt>, DynError> {
    if parsed.model != "regex-redux" {
        return Ok(None);
    }
    if !parsed.patterns.is_empty() || parsed.unicode || parsed.case_insensitive {
        return Err("trusted regex-redux oracle received a noncanonical model shape".into());
    }
    std::str::from_utf8(&parsed.haystack)?;
    let mut sequence = parsed.haystack.clone();
    let input_length = u64::try_from(sequence.len())?;
    let flatten = RegexBuilder::new(r">[^\n]*\n|\n")
        .unicode(false)
        .case_insensitive(false)
        .build()?;
    sequence = flatten.replace_all(&sequence, b"").into_owned();
    let clean_length = u64::try_from(sequence.len())?;

    let mut variant_counts = [0_u64; 9];
    let mut report = String::new();
    for (index, pattern) in REGEX_REDUX_VARIANTS.into_iter().enumerate() {
        let regex = RegexBuilder::new(pattern)
            .unicode(false)
            .case_insensitive(false)
            .build()?;
        let count = u64::try_from(regex.find_iter(&sequence).count())?;
        variant_counts[index] = count;
        writeln!(&mut report, "{pattern} {count}")?;
    }

    let mut substitution_lengths = [0_u64; 5];
    for (index, (pattern, replacement)) in REGEX_REDUX_SUBSTITUTIONS.into_iter().enumerate() {
        let regex = RegexBuilder::new(pattern)
            .unicode(false)
            .case_insensitive(false)
            .build()?;
        sequence = regex
            .replace_all(&sequence, replacement.as_bytes())
            .into_owned();
        substitution_lengths[index] = u64::try_from(sequence.len())?;
    }
    let final_length = u64::try_from(sequence.len())?;
    writeln!(
        &mut report,
        "\n{input_length}\n{clean_length}\n{final_length}"
    )?;
    Ok(Some(RegexReduxStageReceipt {
        input_length,
        clean_length,
        variant_counts,
        substitution_lengths,
        final_length,
        report_length: u64::try_from(report.len())?,
    }))
}

fn parse_canonical_json<T>(bytes: &[u8], label: &str) -> Result<T, DynError>
where
    T: serde::de::DeserializeOwned + Serialize,
{
    let value = serde_json::from_slice(bytes)?;
    let mut canonical = serde_json::to_vec(&value)?;
    canonical.push(b'\n');
    if canonical != bytes {
        return Err(format!("{label} is not canonical JSON plus LF").into());
    }
    Ok(value)
}

fn authenticate_fre_version(version: &str) -> Result<(), DynError> {
    let required = [
        "fre.rebar.klv-runner.v1",
        "protocol=stratified-v1",
        "adapter=fre-current-aggregate-capture-v10-portable-word-run-v2",
        "report=fre.rebar.comparison.v2",
        "rebar=463d00f31887e84c38467805b9e3122c314b9521",
        "canonical-sha=",
        "canonical-tree=",
        "engine-sha=",
        "engine-tree=",
        "runner-sha=",
        "runner-tree=",
        "lock=",
        "profile=release",
        "toolchain=",
        "target=",
    ];
    if required.iter().any(|field| !version.contains(field)) || version.contains("unbound") {
        return Err(format!("FRE runner version is not fully bound: {version:?}").into());
    }
    Ok(())
}

fn exact_file_hash(path: &Path, expected: &str, label: &str) -> Result<String, DynError> {
    let actual = file_sha256(path)?;
    if actual != expected {
        return Err(format!("{label} digest {actual} differs from {expected}").into());
    }
    Ok(actual)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct Runners {
    fre: Runner,
    rust: Runner,
    re2: Runner,
}

impl Runners {
    fn hashes(&self) -> Vec<String> {
        vec![
            self.fre.sha256.clone(),
            self.rust.sha256.clone(),
            self.re2.sha256.clone(),
        ]
    }

    fn rehash(&self) -> Result<Vec<String>, DynError> {
        Ok(vec![
            file_sha256(&self.fre.path)?,
            file_sha256(&self.rust.path)?,
            file_sha256(&self.re2.path)?,
        ])
    }
}

#[derive(Clone, Copy)]
struct FreExpectations<'a> {
    benchmark: &'a str,
    model: &'a str,
    plan: &'a str,
    runtime: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct TimingReport<'a> {
    schema: &'a str,
    campaign: &'a str,
    disposition: &'a str,
    semantic_report_sha256: String,
    semantic_receipts_sha256: String,
    manifest_sha256: String,
    rebar_revision: String,
    rebar_checkout: CheckoutIdentity,
    started_unix_ns: u128,
    finished_unix_ns: u128,
    timing_holder_token_sha256: String,
    pairs_per_comparator: usize,
    warmup_iterations_per_process: u64,
    measured_iterations_per_process: u64,
    retry_policy: &'a str,
    timed_api_boundary: &'a str,
    qualification: QualificationSummary,
    guard_before: GuardSnapshot,
    guard_after: GuardSnapshot,
    rebar_binary_sha256: String,
    runners: Runners,
    included_rows: usize,
    all_pointwise_pass: bool,
    rows: Vec<TimingRow>,
}

#[derive(Debug, Serialize)]
struct QualificationSummary {
    policy: &'static str,
    seed_sha256: String,
    rows: usize,
    observations: usize,
    plain_literal_witness_rows: usize,
    invariant_rows: usize,
    invariant_job_ids: Vec<String>,
    untimed_canonical_warmup_invocations: usize,
    evidence_sha256: String,
}

#[derive(Debug, Serialize)]
struct TimingRow {
    job_id: String,
    benchmark: String,
    model: String,
    candidate_plan: String,
    expected_runtime: Option<String>,
    timed_api: &'static str,
    expected: u64,
    input_pattern_sha256: Vec<String>,
    input_haystack_sha256: String,
    klv_sha256: String,
    rust: Comparison,
    re2: Option<Comparison>,
    re2_coverage: &'static str,
}

impl TimingRow {
    fn passes(&self) -> bool {
        self.rust.pointwise_pass
            && self
                .re2
                .as_ref()
                .is_none_or(|comparison| comparison.pointwise_pass)
    }
}

impl PreparedRow<'_> {
    fn finish(self) -> Result<TimingRow, DynError> {
        if self.rust_pairs.len() != PAIRS {
            return Err(format!("{} lacks six Rust pairs", self.selected.fre.job_id).into());
        }
        let rust = Comparison::from_pairs("rust/regex", self.rust_pairs)?;
        let (re2, re2_coverage) = if self.selected.re2.is_some() {
            if self.re2_pairs.len() != PAIRS {
                return Err(format!("{} lacks six RE2 pairs", self.selected.fre.job_id).into());
            }
            (
                Some(Comparison::from_pairs("re2", self.re2_pairs)?),
                "authenticated-pass",
            )
        } else {
            (None, "not-selected-by-rebar-definition")
        };
        let model = self.selected.fre.model.clone();
        let expected_runtime = expected_grep_runtime(&model, &self.selected.fre.job_id);
        Ok(TimingRow {
            job_id: self.selected.fre.job_id.clone(),
            benchmark: self.selected.fre.benchmark.clone(),
            model: model.clone(),
            candidate_plan: self
                .selected
                .fre
                .candidate_plan
                .clone()
                .ok_or("FRE receipt lacks plan")?,
            expected_runtime: expected_runtime.map(str::to_owned),
            timed_api: match model.as_str() {
                "compile" => "build_compile",
                "count" => "count_value",
                "count-spans" => "stream_spans_then_sum_every_start_end_bound",
                "grep" => "line_loop_is_match",
                "regex-redux" => "complete_regex_redux_with_stage_receipt",
                _ => return Err(format!("unexpected timed model {model}").into()),
            },
            expected: self.selected.fre.expected,
            input_pattern_sha256: self.selected.fre.input.pattern_sha256.clone(),
            input_haystack_sha256: self.selected.fre.input.haystack_sha256.clone(),
            klv_sha256: self.klv_sha256,
            rust,
            re2,
            re2_coverage,
        })
    }
}

#[derive(Debug, Serialize)]
struct Comparison {
    reference: String,
    fre_summary: SampleSummary,
    reference_summary: SampleSummary,
    ratio_of_medians_ppm: u64,
    paired_ratios: RatioSummary,
    pointwise_pass: bool,
    pointwise_rule: &'static str,
    pairs: Vec<RawPair>,
}

impl Comparison {
    fn from_pairs(reference: &str, pairs: Vec<RawPair>) -> Result<Self, DynError> {
        let fre_summary = summarize_samples(pairs.iter().map(|pair| pair.fre.duration_ns))?;
        let reference_summary =
            summarize_samples(pairs.iter().map(|pair| pair.reference.duration_ns))?;
        let ratio_of_medians_ppm = ratio_ppm(
            fre_summary.median_twice_ns,
            reference_summary.median_twice_ns,
        )?;
        let paired_ratios = summarize_ratios(&pairs)?;
        let pointwise_pass = paired_ratios.median_ppm < 1_000_000
            && paired_ratios.fre_win_pairs >= 4
            && paired_ratios.ab_median_ppm < 1_000_000
            && paired_ratios.ba_median_ppm < 1_000_000;
        Ok(Self {
            reference: reference.to_owned(),
            fre_summary,
            reference_summary,
            ratio_of_medians_ppm,
            paired_ratios,
            pointwise_pass,
            pointwise_rule: "FRE median, AB median and BA median each < reference; FRE wins >=4/6 pairs",
            pairs,
        })
    }
}

#[derive(Debug, Serialize)]
struct RawPair {
    sequence: usize,
    pair_index: usize,
    order: Vec<String>,
    fre: RawSample,
    reference: RawSample,
    ratio_ppm: u64,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct RawSample {
    duration_ns: u64,
    count: u64,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct SampleSummary {
    minimum_ns: u64,
    median_twice_ns: u64,
    maximum_ns: u64,
    max_over_min_ppm: u64,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct RatioSummary {
    minimum_ppm: u64,
    median_ppm: u64,
    maximum_ppm: u64,
    ab_median_ppm: u64,
    ba_median_ppm: u64,
    fre_win_pairs: usize,
    pair_count: usize,
}

fn summarize_samples(values: impl Iterator<Item = u64>) -> Result<SampleSummary, DynError> {
    let mut values = values.collect::<Vec<_>>();
    if values.len() != PAIRS || values.contains(&0) {
        return Err("sample summary requires six nonzero durations".into());
    }
    values.sort_unstable();
    let median_twice_ns = values[2]
        .checked_add(values[3])
        .ok_or("sample median overflow")?;
    Ok(SampleSummary {
        minimum_ns: values[0],
        median_twice_ns,
        maximum_ns: values[5],
        max_over_min_ppm: ratio_ppm(values[5], values[0])?,
    })
}

fn summarize_ratios(pairs: &[RawPair]) -> Result<RatioSummary, DynError> {
    if pairs.len() != PAIRS {
        return Err("ratio summary requires six pairs".into());
    }
    let mut ratios = pairs.iter().map(|pair| pair.ratio_ppm).collect::<Vec<_>>();
    ratios.sort_unstable();
    let ab = pairs
        .iter()
        .filter(|pair| pair.order[0] == "fre")
        .map(|pair| pair.ratio_ppm)
        .collect::<Vec<_>>();
    let ba = pairs
        .iter()
        .filter(|pair| pair.order[0] != "fre")
        .map(|pair| pair.ratio_ppm)
        .collect::<Vec<_>>();
    Ok(RatioSummary {
        minimum_ppm: ratios[0],
        median_ppm: midpoint(ratios[2], ratios[3])?,
        maximum_ppm: ratios[5],
        ab_median_ppm: odd_median(ab)?,
        ba_median_ppm: odd_median(ba)?,
        fre_win_pairs: ratios.iter().filter(|&&ratio| ratio < 1_000_000).count(),
        pair_count: ratios.len(),
    })
}

fn midpoint(left: u64, right: u64) -> Result<u64, DynError> {
    Ok(left.checked_add(right).ok_or("ratio median overflow")? / 2)
}

fn odd_median(mut values: Vec<u64>) -> Result<u64, DynError> {
    if values.len() != 3 {
        return Err("order-stratified summary requires three pairs".into());
    }
    values.sort_unstable();
    Ok(values[1])
}

fn ratio_ppm(numerator: u64, denominator: u64) -> Result<u64, DynError> {
    if denominator == 0 {
        return Err("ratio denominator is zero".into());
    }
    let scaled = u128::from(numerator)
        .checked_mul(PARTS_PER_MILLION)
        .ok_or("ratio multiplication overflow")?
        / u128::from(denominator);
    u64::try_from(scaled).map_err(|_| "ratio does not fit u64".into())
}

fn file_sha256(path: &Path) -> Result<String, DynError> {
    Ok(sha256(&fs::read(path)?))
}

fn sha256(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_WALL_TIMEOUT: Duration = Duration::from_secs(5);

    struct FixturePidFile {
        path: PathBuf,
        armed: bool,
    }

    impl FixturePidFile {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("fixture time after epoch")
                .as_nanos();
            let path = env::temp_dir().join(format!(
                "fre-stratified-gate-{label}-{}-{nonce}.pid",
                std::process::id()
            ));
            let _ = fs::remove_file(&path);
            Self { path, armed: true }
        }

        fn command(&self, script: &str) -> Command {
            let mut command = Command::new("/bin/sh");
            command.args([
                "-c",
                script,
                "fixture",
                self.path.to_str().expect("UTF-8 fixture PID path"),
            ]);
            command
        }

        fn pid(&self) -> u32 {
            fs::read_to_string(&self.path)
                .unwrap_or_else(|error| panic!("read fixture PID {}: {error}", self.path.display()))
                .trim()
                .parse()
                .expect("numeric fixture PID")
        }

        fn assert_reaped(mut self) {
            let pid = self.pid();
            let started = Instant::now();
            while process_exists(pid) && started.elapsed() < RUNNER_CLEANUP_GRACE {
                thread::sleep(RUNNER_CHILD_POLL);
            }
            assert!(
                !process_exists(pid),
                "fixture process {pid} survived cleanup"
            );
            self.armed = false;
            fs::remove_file(&self.path).expect("remove fixture PID file");
        }
    }

    impl Drop for FixturePidFile {
        fn drop(&mut self) {
            if self.armed {
                if let Ok(pid) = fs::read_to_string(&self.path).map(|pid| pid.trim().to_string()) {
                    let _ = Command::new("/bin/kill")
                        .args(["-KILL", pid.as_str()])
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                }
                let _ = fs::remove_file(&self.path);
            }
        }
    }

    fn process_exists(pid: u32) -> bool {
        Command::new("/bin/kill")
            .args(["-0", pid.to_string().as_str()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    #[test]
    fn exact_sample_summary_retains_half_nanosecond_median() {
        let summary = summarize_samples([40, 10, 30, 20, 50, 60].into_iter()).unwrap();
        assert_eq!(summary.minimum_ns, 10);
        assert_eq!(summary.median_twice_ns, 70);
        assert_eq!(summary.maximum_ns, 60);
        assert_eq!(summary.max_over_min_ppm, 6_000_000);
    }

    #[test]
    fn klv_identity_parser_preserves_binary_haystack() {
        let mut input = Vec::new();
        for (key, value) in [
            ("name", b"secret/benchmark-identity-marker".as_slice()),
            ("model", b"count".as_slice()),
            ("case-insensitive", b"false".as_slice()),
            ("unicode", b"false".as_slice()),
            ("max-iters", b"1".as_slice()),
            ("max-warmup-iters", b"0".as_slice()),
            ("max-time", b"0".as_slice()),
            ("max-warmup-time", b"0".as_slice()),
            ("pattern", b"a:b".as_slice()),
            ("haystack", b"a\n\xFF".as_slice()),
        ] {
            write!(input, "{key}:{}:", value.len()).unwrap();
            input.extend_from_slice(value);
            input.push(b'\n');
        }
        let parsed = ParsedKlv::parse(&input).unwrap();
        assert_eq!(parsed.patterns, vec![b"a:b".to_vec()]);
        assert_eq!(parsed.haystack, b"a\n\xFF");

        let mut renamed = parsed.clone();
        renamed.name = "renamed/held-out-identity-marker".to_string();
        assert_eq!(parsed.fre_executor_bytes(), renamed.fre_executor_bytes());
        assert_eq!(
            parsed.reference_executor_bytes(),
            renamed.reference_executor_bytes()
        );
        for bytes in [
            parsed.fre_executor_bytes(),
            parsed.reference_executor_bytes(),
        ] {
            for forbidden in [
                parsed.name.as_bytes(),
                renamed.name.as_bytes(),
                b"expected-plan-marker".as_slice(),
                b"expected-runtime-marker".as_slice(),
                b"expected-count-marker".as_slice(),
            ] {
                assert!(!bytes.windows(forbidden.len()).any(|part| part == forbidden));
            }
        }

        let mut retimed = parsed.clone();
        retimed.max_iters = 17;
        retimed.max_warmup_iters = 19;
        retimed.max_time = 23;
        retimed.max_warmup_time = 29;
        assert_eq!(
            parsed.fre_executor_bytes(),
            retimed.fre_executor_bytes(),
            "trusted KLV timing fields must not fingerprint the candidate request"
        );
        assert_ne!(
            parsed.reference_executor_bytes(),
            retimed.reference_executor_bytes(),
            "the reference KLV must retain its full trusted timing metadata"
        );
        for forbidden in [
            b"max-iters".as_slice(),
            b"max-warmup-iters".as_slice(),
            b"max-time".as_slice(),
            b"max-warmup-time".as_slice(),
        ] {
            let candidate = parsed.fre_executor_bytes();
            assert!(
                !candidate
                    .windows(forbidden.len())
                    .any(|part| part == forbidden)
            );
        }
    }

    fn regex_redux_parsed(haystack: &[u8]) -> ParsedKlv {
        ParsedKlv {
            name: "held-out/regex-redux".to_string(),
            model: "regex-redux".to_string(),
            patterns: Vec::new(),
            case_insensitive: false,
            unicode: false,
            haystack: haystack.to_vec(),
            max_iters: 1,
            max_warmup_iters: 0,
            max_time: 0,
            max_warmup_time: 0,
        }
    }

    #[test]
    fn trusted_regex_redux_oracle_distinguishes_equal_scalar_stage_histories() {
        let variant = trusted_regex_redux_stage_receipt(&regex_redux_parsed(b"agggtaaa"))
            .expect("trusted variant oracle")
            .expect("regex-redux evidence");
        let miss = trusted_regex_redux_stage_receipt(&regex_redux_parsed(b"xxxxxxxx"))
            .expect("trusted miss oracle")
            .expect("regex-redux evidence");

        assert_eq!(variant.final_length, 8);
        assert_eq!(variant.final_length, miss.final_length);
        assert_ne!(variant.variant_counts, miss.variant_counts);
        assert_eq!(variant.variant_counts[0], 1);
        assert_eq!(miss.variant_counts, [0; 9]);
        assert_eq!(variant.substitution_lengths, [8; 5]);
        assert!(variant.report_length > 0);
    }

    #[test]
    fn outer_collector_rejects_forged_regex_redux_stage_evidence() {
        let expected = trusted_regex_redux_stage_receipt(&regex_redux_parsed(b"agggtaaa"))
            .expect("trusted oracle")
            .expect("regex-redux evidence");
        let description = FreExecutorDescription {
            schema: FRE_EXECUTOR_DESCRIPTION_SCHEMA.to_string(),
            mode: FreExecutorMode::PerformanceRaw,
            model: "regex-redux".to_string(),
            candidate_plan: "regex-redux-rebar-generic-session-v2".to_string(),
            candidate_runtime: None,
            priming_operations: 0,
        };
        let response = FreExecutorResponse {
            schema: FRE_EXECUTOR_RESPONSE_SCHEMA.to_string(),
            mode: FreExecutorMode::PerformanceRaw,
            model: "regex-redux".to_string(),
            candidate_plan: description.candidate_plan.clone(),
            candidate_runtime: None,
            regex_redux_stage_receipt: Some(expected),
            priming_operations: 0,
            samples: vec![FreExecutorSample {
                elapsed_ns: 1,
                actual: expected.final_length,
            }],
        };
        validate_fre_response(
            &response,
            &description,
            expected.final_length,
            Some(&expected),
        )
        .expect("matching independent stage evidence");

        let mut forged = response.clone();
        forged
            .regex_redux_stage_receipt
            .as_mut()
            .expect("stage evidence")
            .variant_counts[0] ^= 1;
        assert!(
            validate_fre_response(
                &forged,
                &description,
                expected.final_length,
                Some(&expected)
            )
            .is_err()
        );

        let mut absent = response;
        absent.regex_redux_stage_receipt = None;
        assert!(
            validate_fre_response(
                &absent,
                &description,
                expected.final_length,
                Some(&expected)
            )
            .is_err()
        );
    }

    #[test]
    fn wrong_description_fails_before_measurement_process_is_started() {
        let measured = std::cell::Cell::new(false);
        let expectations = FreExpectations {
            benchmark: "secret/benchmark",
            model: "count",
            plan: "expected-plan",
            runtime: None,
        };
        let error = collect_fre_sample(
            expectations,
            17,
            None,
            || {
                Ok(FreExecutorDescription {
                    schema: FRE_EXECUTOR_DESCRIPTION_SCHEMA.to_string(),
                    mode: FreExecutorMode::Samples,
                    model: "count".to_string(),
                    candidate_plan: "wrong-plan".to_string(),
                    candidate_runtime: None,
                    priming_operations: 0,
                })
            },
            || {
                measured.set(true);
                Ok(FreExecutorResponse {
                    schema: FRE_EXECUTOR_RESPONSE_SCHEMA.to_string(),
                    mode: FreExecutorMode::Samples,
                    model: "count".to_string(),
                    candidate_plan: "wrong-plan".to_string(),
                    candidate_runtime: None,
                    regex_redux_stage_receipt: None,
                    priming_operations: 0,
                    samples: vec![FreExecutorSample {
                        elapsed_ns: 1,
                        actual: 17,
                    }],
                })
            },
        )
        .expect_err("wrong plan must fail admission");
        assert!(error.to_string().contains("authenticated receipt"));
        assert!(!measured.get());
    }

    fn qualification_description(plan: &str) -> FreExecutorDescription {
        FreExecutorDescription {
            schema: FRE_EXECUTOR_DESCRIPTION_SCHEMA.to_string(),
            mode: FreExecutorMode::Samples,
            model: "count".to_string(),
            candidate_plan: plan.to_string(),
            candidate_runtime: None,
            priming_operations: 0,
        }
    }

    fn qualification_parsed(
        model: &str,
        patterns: &[&[u8]],
        haystack: &[u8],
        case_insensitive: bool,
    ) -> ParsedKlv {
        ParsedKlv {
            name: "held-out/qualification".to_string(),
            model: model.to_string(),
            patterns: patterns.iter().map(|pattern| pattern.to_vec()).collect(),
            case_insensitive,
            unicode: false,
            haystack: haystack.to_vec(),
            max_iters: 1,
            max_warmup_iters: 0,
            max_time: 0,
            max_warmup_time: 0,
        }
    }

    #[test]
    fn held_out_mutations_are_same_length_distinct_and_secret_seeded() {
        let canonical = b"canonical haystack bytes";
        let parsed = qualification_parsed("count", &[b"a.*"], canonical, false);
        let first = same_length_held_out_haystacks(&parsed, 0, &[7_u8; 32], 3).unwrap();
        let second = same_length_held_out_haystacks(&parsed, 0, &[11_u8; 32], 3).unwrap();
        assert!(!first.plain_literal_witness);
        assert_eq!(first.haystacks.len(), QUALIFICATION_PROBES_PER_ROW);
        for probe in &first.haystacks {
            assert_eq!(probe.len(), canonical.len());
            assert_ne!(probe, canonical);
        }
        let unique = first
            .haystacks
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(unique.len(), QUALIFICATION_PROBES_PER_ROW);
        assert_ne!(first.haystacks[3], second.haystacks[3]);

        let empty = qualification_parsed("count", &[b"a"], b"", false);
        let empty = same_length_held_out_haystacks(&empty, 0, &[13_u8; 32], 5).unwrap();
        assert!(!empty.plain_literal_witness);
        assert!(empty.haystacks.iter().all(Vec::is_empty));
    }

    #[test]
    fn zero_result_plain_ascii_literal_gets_an_exact_one_match_witness() {
        let pattern = b"ZQZQZQZQZQ";
        let canonical = vec![b'x'; 128];
        for model in ["compile", "count", "count-spans"] {
            let parsed = qualification_parsed(model, &[pattern], &canonical, false);
            let probes = same_length_held_out_haystacks(&parsed, 0, &[17_u8; 32], 9).unwrap();

            assert!(probes.plain_literal_witness, "model={model}");
            assert_eq!(
                qualification_probe_kind(2, probes.plain_literal_witness).unwrap(),
                "plain-ascii-literal-witness"
            );
            let witness = &probes.haystacks[2];
            assert_eq!(witness.len(), canonical.len());
            assert_eq!(
                witness
                    .windows(pattern.len())
                    .filter(|window| *window == pattern)
                    .count(),
                1
            );
            let regex = RegexBuilder::new(std::str::from_utf8(pattern).unwrap())
                .unicode(false)
                .case_insensitive(false)
                .build()
                .unwrap();
            let matches = regex.find_iter(witness).collect::<Vec<_>>();
            assert_eq!(matches.len(), 1);
            assert_eq!(matches[0].end() - matches[0].start(), pattern.len());
            let unique = probes
                .haystacks
                .iter()
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(unique.len(), QUALIFICATION_PROBES_PER_ROW);
            assert!(probes.haystacks.iter().all(|probe| probe != &canonical));
        }
    }

    #[test]
    fn one_byte_literal_witness_preserves_four_distinct_probes() {
        let parsed = qualification_parsed("count", &[b"a"], b"x", false);
        let probes = same_length_held_out_haystacks(&parsed, 0, &[19_u8; 32], 11).unwrap();
        assert!(probes.plain_literal_witness);
        assert_eq!(probes.haystacks[2], b"a");
        let unique = probes
            .haystacks
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(unique.len(), QUALIFICATION_PROBES_PER_ROW);
    }

    #[test]
    fn secret_collision_cannot_make_one_byte_witness_admission_seed_dependent() {
        let seed = [31_u8; 32];
        let baseline = qualification_parsed("count", &[b"."], b"x", false);
        let (row_index, literal) = (0..1_024)
            .find_map(|row_index| {
                let probes =
                    same_length_held_out_haystacks(&baseline, 0, &seed, row_index).unwrap();
                let literal = probes.haystacks[3][0];
                (literal != b'x' && is_plain_ascii_literal_byte(literal))
                    .then_some((row_index, literal))
            })
            .expect("fixed seed exposes a printable one-byte secret probe");
        let parsed = qualification_parsed("count", &[&[literal]], b"x", false);
        let probes = same_length_held_out_haystacks(&parsed, 0, &seed, row_index).unwrap();

        assert!(probes.plain_literal_witness);
        assert_eq!(probes.haystacks[2], [literal]);
        assert_ne!(probes.haystacks[3], probes.haystacks[2]);
        let unique = probes
            .haystacks
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(unique.len(), QUALIFICATION_PROBES_PER_ROW);
    }

    #[test]
    fn literal_witness_conservatively_falls_back_for_unproved_shapes() {
        let canonical = vec![b'x'; 64];
        for (model, patterns, case_insensitive, expected) in [
            ("count", vec![b"ZQ+".as_slice()], false, 0),
            ("count", vec![br"ZQ\x5A".as_slice()], false, 0),
            ("count", vec![b"ZQ".as_slice()], true, 0),
            ("count", vec![b"ZQ".as_slice(), b"XY".as_slice()], false, 0),
            ("grep", vec![b"ZQ".as_slice()], false, 0),
            ("count", vec![b"ZQ".as_slice()], false, 1),
        ] {
            let parsed = qualification_parsed(model, &patterns, &canonical, case_insensitive);
            let probes =
                same_length_held_out_haystacks(&parsed, expected, &[23_u8; 32], 13).unwrap();
            assert!(
                !probes.plain_literal_witness,
                "model={model} patterns={patterns:?}"
            );
        }

        let too_long = qualification_parsed("count-spans", &[b"ZQZQ"], b"xx", false);
        let probes = same_length_held_out_haystacks(&too_long, 0, &[29_u8; 32], 15).unwrap();
        assert!(!probes.plain_literal_witness);
    }

    #[test]
    fn held_out_qualification_rejects_constant_answer_responses() {
        let description = qualification_description("aggregate-continuation-program");
        validate_qualification_probe(&description, &description, 1, 1).unwrap();
        let error = validate_qualification_probe(&description, &description, 4, 1)
            .expect_err("a constant answer must fail when the trusted mutation result changes");
        assert!(error.to_string().contains("trusted Rust reference"));
    }

    #[test]
    fn held_out_qualification_rejects_haystack_selected_plan_responses() {
        let canonical = qualification_description("aggregate-continuation-program");
        let selected = qualification_description("fixture-hash-special-case");
        let error = validate_qualification_probe(&canonical, &selected, 3, 3)
            .expect_err("a same-answer plan switch must fail qualification");
        assert!(error.to_string().contains("plan/runtime changed"));
    }

    #[test]
    fn invariant_qualification_requires_an_exact_audited_formal_plan() {
        let admitted = qualification_description(FORMAL_AGGREGATE_OPERATION_PLAN);
        require_preregistered_invariant_identity(
            FreExpectations {
                benchmark: "anonymous/invariant",
                model: "count",
                plan: FORMAL_AGGREGATE_OPERATION_PLAN,
                runtime: None,
            },
            &admitted,
        )
        .expect("formal complete-bound plan must be admitted");

        let spoofed = qualification_description("fixture-hash-special-case");
        let error = require_preregistered_invariant_identity(
            FreExpectations {
                benchmark: "anonymous/invariant",
                model: "count",
                plan: "fixture-hash-special-case",
                runtime: None,
            },
            &spoofed,
        )
        .expect_err("a receipt and response cannot bless an arbitrary invariant plan");
        assert!(error.to_string().contains("exact audited formal"));
    }

    #[test]
    fn runner_pipe_reader_stops_at_its_memory_bound() {
        assert_eq!(
            read_runner_pipe_bounded(
                std::io::Cursor::new(vec![b'x'; MAX_RUNNER_OUTPUT_BYTES]),
                "fixture output",
                MAX_RUNNER_OUTPUT_BYTES,
            )
            .expect("bounded output")
            .len(),
            MAX_RUNNER_OUTPUT_BYTES
        );
        let error = read_runner_pipe_bounded(
            std::io::Cursor::new(vec![b'x'; MAX_RUNNER_OUTPUT_BYTES + 1]),
            "fixture output",
            MAX_RUNNER_OUTPUT_BYTES,
        )
        .expect_err("oversized output must stop at its first excess byte");
        assert!(error.contains("exceeds"));
    }

    #[test]
    fn runner_group_signaling_fails_closed_for_a_missing_group() {
        let error = signal_runner_process_group(i32::MAX)
            .expect_err("a nonexistent process group must not be reported as signaled");
        assert!(error.contains("signaler failed"));
    }

    #[test]
    fn runner_direct_cleanup_catches_a_candidate_outside_the_anchored_group() {
        let mut process_group = RunnerProcessGroup::spawn().expect("fixture process-group anchor");
        let mut command = Command::new("/bin/sleep");
        command
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        let mut child = command.spawn().expect("escaped fixture candidate");
        let pid = child.id();
        if let Err(error) = terminate_runner_processes(&mut process_group, Some(&mut child), false)
        {
            let _ = child.kill();
            let _ = child.wait();
            let _ = process_group.anchor.kill();
            let _ = process_group.anchor.wait();
            panic!("clean escaped fixture candidate: {error}");
        }
        assert!(
            !process_exists(pid),
            "escaped fixture candidate {pid} survived direct cleanup"
        );
    }

    #[test]
    fn runner_normal_input_output_completes() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "read value; printf 'result:%s' \"$value\""]);
        let (status, stdout, stderr) = invoke_command_bounded_with_limits(
            command,
            Some(b"ordinary-input\n"),
            FIXTURE_WALL_TIMEOUT,
            MAX_RUNNER_OUTPUT_BYTES,
        )
        .expect("ordinary runner operation");
        assert!(status.success());
        assert_eq!(stdout, b"result:ordinary-input");
        assert!(stderr.is_empty());
    }

    #[test]
    fn runner_io_is_concurrent_when_child_writes_before_reading() {
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            "/usr/bin/yes x | /usr/bin/head -c 131072; /bin/cat >/dev/null",
        ]);
        let input = vec![b'i'; 256 * 1_024];
        let (status, stdout, stderr) = invoke_command_bounded_with_limits(
            command,
            Some(&input),
            FIXTURE_WALL_TIMEOUT,
            256 * 1_024,
        )
        .expect("concurrent runner I/O");
        assert!(status.success());
        assert_eq!(stdout.len(), 131_072);
        assert!(stderr.is_empty());
    }

    #[test]
    fn runner_finite_oversized_output_is_rejected() {
        let mut command = Command::new("/usr/bin/head");
        command.args(["-c", "4097", "/dev/zero"]);
        let error = invoke_command_bounded_with_limits(command, None, FIXTURE_WALL_TIMEOUT, 4_096)
            .expect_err("oversized runner output must fail");
        assert!(
            error
                .to_string()
                .contains("runner stdout exceeds 4096 bytes")
        );
    }

    #[test]
    fn runner_infinite_output_is_killed_and_reaped() {
        let pid = FixturePidFile::new("infinite-output");
        let command = pid.command("echo $$ > \"$1\"; exec /usr/bin/yes x");
        let started = Instant::now();
        let error = invoke_command_bounded_with_limits(command, None, FIXTURE_WALL_TIMEOUT, 4_096)
            .expect_err("infinite output must hit the live bound");
        assert!(
            error
                .to_string()
                .contains("runner stdout exceeds 4096 bytes")
        );
        assert!(started.elapsed() < FIXTURE_WALL_TIMEOUT);
        pid.assert_reaped();
    }

    #[test]
    fn runner_wall_timeout_kills_and_reaps_sleeping_child() {
        let pid = FixturePidFile::new("wall-timeout");
        let command = pid.command("echo $$ > \"$1\"; exec /bin/sleep 30");
        let error = invoke_command_bounded_with_limits(
            command,
            None,
            Duration::from_millis(150),
            MAX_RUNNER_OUTPUT_BYTES,
        )
        .expect_err("sleeping runner must time out");
        assert!(error.to_string().contains("monotonic wall deadline"));
        pid.assert_reaped();
    }

    #[test]
    fn runner_stdin_failure_kills_and_reaps_child() {
        let pid = FixturePidFile::new("stdin-failure");
        let command = pid.command("echo $$ > \"$1\"; exec 0<&-; exec /bin/sleep 30");
        let input = vec![b'i'; 256 * 1_024];
        let error = invoke_command_bounded_with_limits(
            command,
            Some(&input),
            FIXTURE_WALL_TIMEOUT,
            MAX_RUNNER_OUTPUT_BYTES,
        )
        .expect_err("closed child stdin must fail the writer");
        assert!(error.to_string().contains("write runner stdin"));
        pid.assert_reaped();
    }

    #[test]
    fn runner_descendant_cannot_hold_output_pipes_open() {
        let pid = FixturePidFile::new("pipe-holder");
        let command = pid.command("/bin/sleep 30 & echo $! > \"$1\"; exit 0");
        let started = Instant::now();
        let error = invoke_command_bounded_with_limits(
            command,
            None,
            FIXTURE_WALL_TIMEOUT,
            MAX_RUNNER_OUTPUT_BYTES,
        )
        .expect_err("runner descendant must not retain output pipes");
        assert!(error.to_string().contains("pipes remained open"));
        assert!(started.elapsed() < FIXTURE_WALL_TIMEOUT);
        pid.assert_reaped();
    }

    #[test]
    fn successful_runner_cleanup_kills_redirected_descendants() {
        let pid = FixturePidFile::new("redirected-descendant");
        let command =
            pid.command("/bin/sleep 30 </dev/null >/dev/null 2>&1 & echo $! > \"$1\"; exit 0");
        let (status, stdout, stderr) = invoke_command_bounded_with_limits(
            command,
            None,
            FIXTURE_WALL_TIMEOUT,
            MAX_RUNNER_OUTPUT_BYTES,
        )
        .expect("direct runner completed normally");
        assert!(status.success());
        assert!(stdout.is_empty());
        assert!(stderr.is_empty());
        pid.assert_reaped();
    }

    #[test]
    fn campaigns_are_nonempty_and_unique() {
        for campaign in [
            Campaign::BreadthCurrent,
            Campaign::AssertionFocused,
            Campaign::AssertionFull,
            Campaign::CompileSmoke,
            Campaign::CompileFocused,
            Campaign::CompileAll,
            Campaign::CompileFull,
            Campaign::UnicodeFull,
        ] {
            let rows = campaign.rows();
            assert!(!rows.is_empty());
            let unique = rows
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(rows.len(), unique.len());
        }
    }

    #[test]
    fn breadth_grep_rows_bind_exact_runtime_implementations() {
        assert_eq!(
            expected_grep_runtime("grep", "grep/long-words-unicode@rust/regex"),
            Some("unicode-word-run-linear-v1")
        );
        assert_eq!(
            expected_grep_runtime("grep", "grep/long-words-ascii@rust/regex"),
            Some("ascii-word-run-linear-v1")
        );
        assert_eq!(
            expected_grep_runtime("count", "curated/01-literal/sherlock-en@rust/regex"),
            None
        );
    }
}
