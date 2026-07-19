use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use fre_syntax::{CompatibilityProfile, ParseRequest, RustProfile, RustUnicodeFeatures, parse};
use sha2::{Digest, Sha256};

const CONFIGURATIONS: &[(&str, &str, RustUnicodeFeatures)] = &[
    ("none", "", RustUnicodeFeatures::NONE),
    ("age", "unicode-age", RustUnicodeFeatures::AGE),
    ("bool", "unicode-bool", RustUnicodeFeatures::BOOL),
    ("case", "unicode-case", RustUnicodeFeatures::CASE),
    (
        "all",
        "unicode-age,unicode-bool,unicode-case,unicode-gencat,unicode-perl,unicode-script,unicode-segment",
        RustUnicodeFeatures::ALL,
    ),
];

const BOOL_PROPERTY_ALIASES: &[&str] =
    include!("../../../crates/fre-syntax/src/unicode_bool_aliases.in");
const BOOL_PROPERTY_ALIAS_SET_SHA256: &str =
    "5842f13e797cbf08ec527894fb76f1502522dc10b8bd5ec89f02a0a3fbdf9caf";

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
    ("bool-normalized", r"\p{P_at-tern White Space}"),
    ("bool-is-prefix", r"\p{IsAlphabetic}"),
    ("bool-non-ascii", r"\p{A💥lpha}"),
    ("bool-long-alias", r"\p{Other_Default_Ignorable_Code_Point}"),
    ("bool-set-intersection", r"[\p{Uppercase}&&\p{Alphabetic}]"),
    ("bool-space", r"\s"),
    ("bool-space-casefold", r"(?i:\s)"),
    ("bool-space-bracket-casefold", r"(?i:[\s])"),
    ("bool-property-bracket-casefold", r"(?i:[\p{Alphabetic}])"),
    ("bool-space-no-u", r"(?-u:\s)"),
    ("bool-named-value", r"\p{Alphabetic=Yes}"),
    ("bool-near-miss", r"\p{Alphabeticish}"),
    ("bool-unreachable-incb", r"\p{InCB}"),
    ("bool-is-c-collision", r"\p{IsC}"),
    ("case", r"(?i:\u{03B4})"),
    ("case-ascii", r"(?i:a)"),
    ("case-kelvin", r"(?i:\u{212A})"),
    ("case-long-s", r"(?i:\u{017F})"),
    ("case-sigma", r"(?i:\u{03C2})"),
    ("case-unmapped", r"(?i:\u{1F600})"),
    ("case-class", r"(?i:[a-z\u{03B4}])"),
    ("case-negated-class", r"(?i:[^\u{03B4}])"),
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
    ("nested-case-scope", r"(?i:(?-i:\u{03B4})a)"),
];

#[test]
fn typed_profiles_match_feature_isolated_regex_syntax_0_8_11() {
    assert_eq!(BOOL_PROPERTY_ALIASES.len(), 121);
    assert!(
        BOOL_PROPERTY_ALIASES
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    assert_eq!(
        BOOL_PROPERTY_ALIASES.iter().map(|alias| alias.len()).max(),
        Some(30)
    );
    let mut alias_bytes = BOOL_PROPERTY_ALIASES.join("\n").into_bytes();
    alias_bytes.push(b'\n');
    assert_eq!(
        format!("{:x}", Sha256::digest(&alias_bytes)),
        BOOL_PROPERTY_ALIAS_SET_SHA256
    );
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
        for (index, &alias) in BOOL_PROPERTY_ALIASES.iter().enumerate() {
            let pattern = format!(r"\p{{{alias}}}");
            let actual = parse(ParseRequest::rust(
                &pattern,
                CompatibilityProfile::RustText(profile.clone()),
            ))
            .is_ok();
            let id = format!("bool-alias-{index}:{alias}");
            assert_eq!(
                actual, oracle[&id],
                "configuration={name} alias={alias} pattern={pattern}",
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
    let expected = PROBES
        .len()
        .checked_add(BOOL_PROPERTY_ALIASES.len())
        .expect("oracle probe cardinality fits usize");
    assert_eq!(parsed.len(), expected);
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
