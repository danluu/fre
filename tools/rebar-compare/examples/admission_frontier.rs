//! Deterministically probe construction eligibility before operation routing.

use std::{
    collections::BTreeMap,
    env, fs,
    path::{Component, Path, PathBuf},
    process::ExitCode,
};

use fre::{PortableBuilder, RustProfile};
use rebar_expand::Manifest;
use serde::Serialize;
use sha2::{Digest, Sha256};

const SCHEMA: &str = "fre.rebar.admission-frontier.v1";
const MAX_MANIFEST_BYTES: u64 = 256 * 1_048_576;
const MAX_PATTERN_BYTES: usize = 64 * 1_048_576;

#[derive(Debug, Serialize)]
struct Report {
    schema: &'static str,
    manifest_sha256: String,
    rust_jobs: usize,
    coverage: BTreeMap<String, BTreeMap<String, usize>>,
    jobs: Vec<JobRecord>,
}

#[derive(Debug, Serialize)]
struct JobRecord {
    job_id: String,
    model: String,
    pattern_count: usize,
    pattern_bytes: usize,
    unicode: bool,
    case_insensitive: bool,
    outcome: String,
    selected_plan: Option<String>,
    reason: Option<String>,
}

fn main() -> ExitCode {
    match real_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("admission-frontier: {error}");
            ExitCode::FAILURE
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "keeping manifest authentication and the deterministic probe loop contiguous makes the diagnostic auditable"
)]
fn real_main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os().skip(1);
    let manifest_path = arguments
        .next()
        .map(PathBuf::from)
        .ok_or("usage: admission_frontier MANIFEST OUTPUT")?;
    let output_path = arguments
        .next()
        .map(PathBuf::from)
        .ok_or("missing output path")?;
    if arguments.next().is_some() {
        return Err("unexpected extra argument".into());
    }
    let metadata = fs::metadata(&manifest_path)?;
    if metadata.len() > MAX_MANIFEST_BYTES {
        return Err(format!("manifest has {} bytes", metadata.len()).into());
    }
    let manifest_bytes = fs::read(&manifest_path)?;
    let manifest_sha256 = sha256(&manifest_bytes);
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;
    if manifest.schema != rebar_expand::SCHEMA {
        return Err(format!("unexpected manifest schema {}", manifest.schema).into());
    }
    if manifest.source.revision != rebar_expand::AUDITED_REBAR_REVISION {
        return Err(format!("unexpected Rebar revision {}", manifest.source.revision).into());
    }
    if manifest.jobs.len() != manifest.scope.job_count {
        return Err("manifest job count does not match its scope".into());
    }
    let base = manifest_path.parent().ok_or("manifest has no parent")?;

    let mut jobs = Vec::new();
    let mut coverage = BTreeMap::<String, BTreeMap<String, usize>>::new();
    for job in manifest
        .jobs
        .iter()
        .filter(|job| job.engine == "rust/regex")
    {
        let pattern_bytes = job.regex.patterns.iter().try_fold(0_usize, |total, item| {
            total
                .checked_add(item.bytes)
                .ok_or("aggregate pattern length overflow")
        })?;
        let (outcome, selected_plan, reason) = if job.regex.case_insensitive {
            (
                "option-unsupported".to_owned(),
                None,
                Some("facade has no case-insensitive builder option".to_owned()),
            )
        } else if job.regex.patterns.len() != 1 {
            (
                "build-many-unsupported".to_owned(),
                None,
                Some("facade requires exactly one ordered pattern".to_owned()),
            )
        } else {
            let blob = &job.regex.patterns[0];
            if blob.bytes > MAX_PATTERN_BYTES {
                return Err(format!("{} pattern exceeds diagnostic cap", job.id).into());
            }
            let path = safe_join(base, &blob.blob)?;
            let bytes = fs::read(path)?;
            if bytes.len() != blob.bytes || sha256(&bytes) != blob.sha256 {
                return Err(format!("{} pattern blob identity differs", job.id).into());
            }
            let pattern = String::from_utf8(bytes)?;
            match PortableBuilder::new(pattern)
                .profile(RustProfile::rebar_1_12_4())
                .unicode(job.regex.unicode)
                .build()
            {
                Ok(regex) => (
                    "build-admitted".to_owned(),
                    Some(format!("{:?}", regex.build_report().plan)),
                    None,
                ),
                Err(error) => ("build-refused".to_owned(), None, Some(error.to_string())),
            }
        };
        increment(&mut coverage, &job.model, &outcome)?;
        jobs.push(JobRecord {
            job_id: job.id.clone(),
            model: job.model.clone(),
            pattern_count: job.regex.patterns.len(),
            pattern_bytes,
            unicode: job.regex.unicode,
            case_insensitive: job.regex.case_insensitive,
            outcome,
            selected_plan,
            reason,
        });
    }
    jobs.sort_by(|left, right| left.job_id.cmp(&right.job_id));
    let report = Report {
        schema: SCHEMA,
        manifest_sha256,
        rust_jobs: jobs.len(),
        coverage,
        jobs,
    };
    let mut bytes = serde_json::to_vec_pretty(&report)?;
    bytes.push(b'\n');
    fs::write(output_path, bytes)?;
    Ok(())
}

fn increment(
    coverage: &mut BTreeMap<String, BTreeMap<String, usize>>,
    model: &str,
    outcome: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let value = coverage
        .entry(model.to_owned())
        .or_default()
        .entry(outcome.to_owned())
        .or_default();
    *value = value.checked_add(1).ok_or("coverage count overflow")?;
    Ok(())
}

fn safe_join(base: &Path, relative: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let relative = Path::new(relative);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("unsafe blob path {}", relative.display()).into());
    }
    Ok(base.join(relative))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::{increment, safe_join};
    use std::{collections::BTreeMap, path::Path};

    #[test]
    fn diagnostic_paths_and_counts_are_bounded() {
        assert!(safe_join(Path::new("root"), "blobs/a.pattern").is_ok());
        assert!(safe_join(Path::new("root"), "../escape").is_err());
        assert!(safe_join(Path::new("root"), "/absolute").is_err());

        let mut coverage = BTreeMap::new();
        increment(&mut coverage, "count", "admitted").unwrap();
        increment(&mut coverage, "count", "admitted").unwrap();
        assert_eq!(coverage["count"]["admitted"], 2);
    }
}
