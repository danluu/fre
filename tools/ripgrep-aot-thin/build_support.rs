//! Pure build-input parsing shared by the build script and focused unit tests.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) const PATTERNS_FILE_ENV: &str = "FRE_RIPGREP_AOT_PATTERNS_FILE";
pub(crate) const VARIANTS_ENV: &str = "FRE_RIPGREP_AOT_VARIANTS";
const GENERATED_REGISTRY: &str = "registry.rs";
const GENERATED_ARCHIVE: &str = "libfre_ripgrep_aot_objects.a";
const GENERATED_ARTIFACT_SUFFIXES: &[&str] = &[
    "_fast_exists.o",
    "_fast_exists.program",
    "_fast_span.o",
    "_fast_span.program",
    "_optimizing_exists.o",
    "_optimizing_exists.program",
    "_optimizing_span.o",
    "_optimizing_span.program",
    "_optimizing_grep_count.o",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Pattern {
    pub(crate) id: String,
    pub(crate) case_insensitive: bool,
    pub(crate) source: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BuildMode {
    Fast,
    Optimizing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BuildOutput {
    Exists,
    GrepCount,
    Span,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VariantPolicy {
    All,
    OptimizingExists,
    OptimizingGrepCount,
}

impl VariantPolicy {
    pub(crate) fn parse(value: Option<&OsStr>) -> Result<Self, String> {
        let Some(value) = value else {
            return Ok(Self::All);
        };
        let value = value
            .to_str()
            .ok_or_else(|| format!("{VARIANTS_ENV} must be valid UTF-8"))?;
        match value {
            "" | "all" => Ok(Self::All),
            "optimizing-exists" => Ok(Self::OptimizingExists),
            "optimizing-grep-count" => Ok(Self::OptimizingGrepCount),
            value => Err(format!(
                "invalid {VARIANTS_ENV} value {value:?}; expected \"all\", \"optimizing-exists\", or \"optimizing-grep-count\""
            )),
        }
    }

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::OptimizingExists => "optimizing-exists",
            Self::OptimizingGrepCount => "optimizing-grep-count",
        }
    }

    pub(crate) const fn includes(self, mode: BuildMode, output: BuildOutput) -> bool {
        match self {
            Self::All => matches!(output, BuildOutput::Exists | BuildOutput::Span),
            Self::OptimizingExists => {
                matches!(mode, BuildMode::Optimizing) && matches!(output, BuildOutput::Exists)
            }
            Self::OptimizingGrepCount => {
                matches!(mode, BuildMode::Optimizing) && matches!(output, BuildOutput::GrepCount)
            }
        }
    }
}

pub(crate) fn patterns_path(
    manifest_dir: &Path,
    configured: Option<&OsStr>,
) -> Result<PathBuf, String> {
    let Some(configured) = configured else {
        return Ok(manifest_dir.join("patterns.tsv"));
    };
    if configured.is_empty() {
        return Err(format!("{PATTERNS_FILE_ENV} must not be empty"));
    }
    let configured = Path::new(configured);
    let path = if configured.is_absolute() {
        configured.to_owned()
    } else {
        manifest_dir.join(configured)
    };
    let printable = path.to_str().ok_or_else(|| {
        format!("{PATTERNS_FILE_ENV} must resolve to a UTF-8 path for Cargo rerun tracking")
    })?;
    if printable.contains(['\n', '\r']) {
        return Err(format!("{PATTERNS_FILE_ENV} must not contain a line break"));
    }
    Ok(path)
}

pub(crate) fn read_patterns(path: &Path) -> Result<Vec<Pattern>, String> {
    let text = fs::read_to_string(path)
        .map_err(|error| format!("read patterns TSV {}: {error}", path.display()))?;
    parse_patterns(&text, &path.display().to_string())
}

/// Remove only artifacts owned by this build script from Cargo's package
/// `OUT_DIR` before generating a new registry.
pub(crate) fn purge_generated_artifacts(out_dir: &Path) -> Result<(), String> {
    let entries = fs::read_dir(out_dir)
        .map_err(|error| format!("read Cargo OUT_DIR {}: {error}", out_dir.display()))?;
    for entry in entries {
        let entry = entry
            .map_err(|error| format!("read Cargo OUT_DIR entry in {}: {error}", out_dir.display()))?;
        let path = entry.path();
        if is_generated_artifact(&path) {
            fs::remove_file(&path).map_err(|error| {
                format!("remove stale generated artifact {}: {error}", path.display())
            })?;
        }
    }
    Ok(())
}

fn is_generated_artifact(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name == GENERATED_REGISTRY
        || name == GENERATED_ARCHIVE
        || GENERATED_ARTIFACT_SUFFIXES.iter().any(|suffix| {
            name.strip_suffix(suffix)
                .is_some_and(is_valid_pattern_id)
        })
}

fn is_valid_pattern_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn parse_patterns(text: &str, source_name: &str) -> Result<Vec<Pattern>, String> {
    let mut ids = BTreeSet::new();
    let mut patterns = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut columns = line.splitn(3, '\t');
        let id = columns.next().unwrap_or_default();
        if !is_valid_pattern_id(id) {
            return Err(format!(
                "{source_name}:{line_number}: pattern id must be a nonempty Rust identifier suffix: {id:?}"
            ));
        }
        if !ids.insert(id.to_owned()) {
            return Err(format!(
                "{source_name}:{line_number}: duplicate pattern id {id:?}"
            ));
        }
        let case_insensitive = match columns.next() {
            Some("0") => false,
            Some("1") => true,
            other => {
                return Err(format!(
                    "{source_name}:{line_number}: invalid case-insensitive field for {id}: {other:?}"
                ));
            }
        };
        let source = columns
            .next()
            .ok_or_else(|| format!("{source_name}:{line_number}: missing pattern for {id}"))?;
        patterns.push(Pattern {
            id: id.to_owned(),
            case_insensitive,
            source: source.to_owned(),
        });
    }
    if patterns.is_empty() {
        return Err(format!("{source_name}: patterns TSV must not be empty"));
    }
    Ok(patterns)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            static NEXT: std::sync::atomic::AtomicUsize =
                std::sync::atomic::AtomicUsize::new(0);
            let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "fre-ripgrep-aot-thin-{name}-{}-{serial}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create synthetic OUT_DIR");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn parses_comments_empty_regexes_and_tabs_without_private_inputs() {
        let patterns = parse_patterns(
            "# generated shape-only fixture\n\nplain_1\t0\tfoo|bar\nci\t1\t\nwith_tab\t0\ta\tb\n",
            "fixture.tsv",
        )
        .expect("parse patterns");
        assert_eq!(
            patterns,
            [
                Pattern {
                    id: "plain_1".to_owned(),
                    case_insensitive: false,
                    source: "foo|bar".to_owned(),
                },
                Pattern {
                    id: "ci".to_owned(),
                    case_insensitive: true,
                    source: String::new(),
                },
                Pattern {
                    id: "with_tab".to_owned(),
                    case_insensitive: false,
                    source: "a\tb".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn rejects_malformed_and_duplicate_pattern_rows() {
        for (text, expected) in [
            ("\t0\tfoo\n", "nonempty Rust identifier suffix"),
            ("bad-id\t0\tfoo\n", "nonempty Rust identifier suffix"),
            ("p\t2\tfoo\n", "invalid case-insensitive field"),
            ("p\t0\n", "missing pattern"),
            ("p\t0\tfoo\np\t1\tbar\n", "duplicate pattern id"),
            ("# comments only\n", "must not be empty"),
        ] {
            let error = parse_patterns(text, "fixture.tsv").expect_err("invalid fixture");
            assert!(error.contains(expected), "{error:?}");
        }
    }

    #[test]
    fn resolves_external_paths_from_the_package_directory() {
        let manifest = Path::new("/workspace/tools/ripgrep-aot-thin");
        assert_eq!(
            patterns_path(manifest, None).expect("default path"),
            manifest.join("patterns.tsv")
        );
        assert_eq!(
            patterns_path(manifest, Some(OsStr::new("fixtures/demo.tsv"))).expect("relative path"),
            manifest.join("fixtures/demo.tsv")
        );
        assert_eq!(
            patterns_path(manifest, Some(OsStr::new("/tmp/demo.tsv"))).expect("absolute path"),
            Path::new("/tmp/demo.tsv")
        );
        assert!(patterns_path(manifest, Some(OsStr::new(""))).is_err());
        assert!(patterns_path(manifest, Some(OsStr::new("bad\npath"))).is_err());
    }

    #[test]
    fn variant_policy_defaults_to_all_and_prunes_only_on_request() {
        assert_eq!(
            VariantPolicy::parse(None).expect("default policy"),
            VariantPolicy::All
        );
        assert_eq!(
            VariantPolicy::parse(Some(OsStr::new("all"))).expect("explicit all"),
            VariantPolicy::All
        );
        let pruned =
            VariantPolicy::parse(Some(OsStr::new("optimizing-exists"))).expect("pruned policy");
        assert_eq!(pruned, VariantPolicy::OptimizingExists);
        assert!(pruned.includes(BuildMode::Optimizing, BuildOutput::Exists));
        assert!(!pruned.includes(BuildMode::Fast, BuildOutput::Exists));
        assert!(!pruned.includes(BuildMode::Optimizing, BuildOutput::Span));
        assert!(!pruned.includes(BuildMode::Optimizing, BuildOutput::GrepCount));
        assert!(VariantPolicy::All.includes(BuildMode::Fast, BuildOutput::Span));
        assert!(!VariantPolicy::All.includes(BuildMode::Optimizing, BuildOutput::GrepCount));
        let grep_count = VariantPolicy::parse(Some(OsStr::new("optimizing-grep-count")))
            .expect("GrepCount policy");
        assert_eq!(grep_count, VariantPolicy::OptimizingGrepCount);
        assert!(grep_count.includes(BuildMode::Optimizing, BuildOutput::GrepCount));
        assert!(!grep_count.includes(BuildMode::Fast, BuildOutput::GrepCount));
        assert!(!grep_count.includes(BuildMode::Optimizing, BuildOutput::Exists));
        assert!(VariantPolicy::parse(Some(OsStr::new("exists"))).is_err());
    }

    #[test]
    fn purge_removes_only_generated_registry_objects_programs_and_archive() {
        let out_dir = TempDir::new("purge");
        for name in [
            GENERATED_REGISTRY,
            GENERATED_ARCHIVE,
            "old_fast_exists.o",
            "old_optimizing_span.program",
            "old_optimizing_grep_count.o",
            "patterns.tsv",
            "keep.rs",
            "unrelated.o",
            "unrelated.program",
            "bad-id_fast_exists.o",
            "_fast_exists.o",
            "old_optimizing_grep_count.program",
            "object.o.backup",
            "libfre_ripgrep_aot_objects.a.backup",
        ] {
            fs::write(out_dir.0.join(name), name).expect("write synthetic artifact");
        }

        purge_generated_artifacts(&out_dir.0).expect("purge generated artifacts");

        for removed in [
            GENERATED_REGISTRY,
            GENERATED_ARCHIVE,
            "old_fast_exists.o",
            "old_optimizing_span.program",
            "old_optimizing_grep_count.o",
        ] {
            assert!(!out_dir.0.join(removed).exists(), "retained {removed}");
        }
        for retained in [
            "patterns.tsv",
            "keep.rs",
            "unrelated.o",
            "unrelated.program",
            "bad-id_fast_exists.o",
            "_fast_exists.o",
            "old_optimizing_grep_count.program",
            "object.o.backup",
            "libfre_ripgrep_aot_objects.a.backup",
        ] {
            assert!(out_dir.0.join(retained).exists(), "removed {retained}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn purge_preserves_unrelated_symlinks_and_never_follows_generated_symlinks() {
        use std::os::unix::fs::symlink;

        let out_dir = TempDir::new("purge-symlink");
        let unrelated_target = out_dir.0.join("outside-generated-grammar");
        let unrelated_link = out_dir.0.join("unrelated.program");
        let generated_target = out_dir.0.join("generated-link-target");
        let generated_link = out_dir.0.join("stale_fast_exists.o");
        fs::write(&unrelated_target, b"public unrelated target")
            .expect("write unrelated symlink target");
        fs::write(&generated_target, b"public generated-name target")
            .expect("write generated-name symlink target");
        symlink(&unrelated_target, &unrelated_link).expect("create unrelated synthetic symlink");
        symlink(&generated_target, &generated_link)
            .expect("create generated-name synthetic symlink");

        purge_generated_artifacts(&out_dir.0).expect("purge generated artifacts");

        assert!(
            fs::symlink_metadata(&unrelated_link)
                .expect("preserved symlink metadata")
                .file_type()
                .is_symlink()
        );
        assert!(
            matches!(
                fs::symlink_metadata(&generated_link),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound
            ),
            "generated-name symlink itself was retained"
        );
        assert_eq!(
            fs::read(&unrelated_target).expect("read preserved unrelated target"),
            b"public unrelated target"
        );
        assert_eq!(
            fs::read(&generated_target).expect("read un-followed generated-name target"),
            b"public generated-name target"
        );
    }
}
