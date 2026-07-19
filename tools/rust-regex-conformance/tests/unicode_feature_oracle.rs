use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use fre_syntax::{CompatibilityProfile, ParseRequest, RustProfile, RustUnicodeFeatures, parse};

const CONFIGURATIONS: &[(&str, &str, RustUnicodeFeatures)] = &[
    ("none", "", RustUnicodeFeatures::NONE),
    ("age", "unicode-age", RustUnicodeFeatures::AGE),
    (
        "all",
        "unicode-age,unicode-bool,unicode-case,unicode-gencat,unicode-perl,unicode-script,unicode-segment",
        RustUnicodeFeatures::ALL,
    ),
];

const PROBES: &[(&str, &str)] = &[
    ("ascii", "ascii"),
    ("age", r"\p{Age:6.0}"),
    ("age-equal", r"\p{age=V6_0}"),
    ("age-not-equal", r"\p{Age!=6.0}"),
    ("age-negated", r"\P{Age=6.0}"),
    ("age-normalized-name", r"\p{A_g-e = 6.0}"),
    ("age-normalized-is-name", r"\p{iS_A-g e=6.0}"),
    ("age-is-prefix", r"\p{IsAge=6.0}"),
    ("age-unassigned", r"\p{Age=Unassigned}"),
    ("age-non-ascii-name", r"\p{A💥ge=6.0}"),
    ("age-invalid-value", r"\p{Age=definitely-invalid}"),
    ("age-bare-name", r"\p{Age}"),
    ("age-extra-name", r"\p{Ageish=6.0}"),
    ("age-casefold", r"(?i:\p{Age=6.0})"),
    ("age-set-subtraction", r"[\p{Age=6.0}--\p{Age=5.0}]"),
    ("bool", r"\p{Alphabetic}"),
    ("case", r"(?i:\u{03B4})"),
    ("gencat", r"\pL"),
    ("perl", r"\b\w\b"),
    ("script", r"\p{Greek}"),
    ("segment", r"\p{Grapheme_Cluster_Break=Extend}"),
    ("white-space", r"\p{White_Space}"),
    ("decimal-number", r"\p{Nd}"),
    ("any", r"\p{Any}"),
    ("assigned", r"\p{Assigned}"),
    ("collision-cf", r"\p{cf}"),
    ("collision-sc", r"\p{sc}"),
    ("collision-lc", r"\p{lc}"),
    ("is-script", r"\p{IsGreek}"),
    ("is-bool", r"\p{IsAlphabetic}"),
    ("unknown", r"\p{definitely_not_a_unicode_property}"),
    ("bare-i", r"(?i)"),
    ("i-dot", r"(?i:.)"),
    ("i-assertion", r"(?i:^$)"),
    ("iu-literal", r"(?i:a)"),
    ("i-no-u-literal", r"(?i-u:a)"),
    ("no-u-perl", r"(?-u:\d\s\w\b)"),
    ("i-direct-perl", r"(?i:\w)"),
    ("i-bracket-perl", r"(?i:[\w])"),
    ("scoped-order", r"(?i)(?-u:a)(?-i:\u{03B4})"),
];

#[test]
fn typed_profiles_match_feature_isolated_regex_syntax_0_8_11() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/unicode-feature-oracle/Cargo.toml");
    let target_root = unique_target_root();
    fs::create_dir(&target_root).expect("create private oracle target root");

    for &(name, cargo_features, availability) in CONFIGURATIONS {
        let oracle = run_oracle(&fixture, &target_root.join(name), cargo_features);
        let mut profile = RustProfile::regex_1_12_4();
        profile.unicode_features = availability;
        for &(id, pattern) in PROBES {
            let actual = parse(ParseRequest::rust(
                pattern,
                CompatibilityProfile::RustText(profile.clone()),
            ))
            .is_ok();
            assert_eq!(
                actual, oracle[id],
                "configuration={name} probe={id} pattern={pattern}",
            );
        }
    }
    fs::remove_dir_all(&target_root).expect("remove private oracle target root");
}

fn run_oracle(manifest: &Path, target: &Path, features: &str) -> BTreeMap<String, bool> {
    let mut command = Command::new(env!("CARGO"));
    command
        .arg("run")
        .arg("--offline")
        .arg("--locked")
        .arg("--quiet")
        .arg("--manifest-path")
        .arg(manifest)
        .arg("--target-dir")
        .arg(target)
        .arg("--no-default-features");
    if !features.is_empty() {
        command.arg("--features").arg(features);
    }
    let output = command
        .output()
        .expect("execute isolated regex-syntax oracle");
    assert!(
        output.status.success(),
        "oracle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("oracle output is UTF-8");
    let mut parsed = BTreeMap::new();
    for line in stdout.lines() {
        let (id, value) = line
            .split_once('\t')
            .expect("oracle output field separator");
        let value = match value {
            "0" => false,
            "1" => true,
            _ => panic!("invalid oracle boolean {value}"),
        };
        assert!(parsed.insert(id.to_owned(), value).is_none());
    }
    assert_eq!(parsed.len(), PROBES.len());
    parsed
}

fn unique_target_root() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "fre-regex-syntax-feature-oracle-{}-{nonce}",
        std::process::id()
    ))
}
