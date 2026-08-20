//! Pure build-input parsing shared by the build script and focused unit tests.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) const PATTERNS_FILE_ENV: &str = "FRE_RIPGREP_AOT_PATTERNS_FILE";
pub(crate) const VARIANTS_ENV: &str = "FRE_RIPGREP_AOT_VARIANTS";

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
    Span,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VariantPolicy {
    All,
    OptimizingExists,
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
            value => Err(format!(
                "invalid {VARIANTS_ENV} value {value:?}; expected \"all\" or \"optimizing-exists\""
            )),
        }
    }

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::OptimizingExists => "optimizing-exists",
        }
    }

    pub(crate) const fn includes(self, mode: BuildMode, output: BuildOutput) -> bool {
        match self {
            Self::All => true,
            Self::OptimizingExists => {
                matches!(mode, BuildMode::Optimizing) && matches!(output, BuildOutput::Exists)
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
        if id.is_empty()
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
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
        assert!(VariantPolicy::All.includes(BuildMode::Fast, BuildOutput::Span));
        assert!(VariantPolicy::parse(Some(OsStr::new("exists"))).is_err());
    }
}
