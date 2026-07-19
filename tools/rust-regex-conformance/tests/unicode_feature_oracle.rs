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
    ("gencat", "unicode-gencat", RustUnicodeFeatures::GENCAT),
    ("perl", "unicode-perl", RustUnicodeFeatures::PERL),
    ("script", "unicode-script", RustUnicodeFeatures::SCRIPT),
    ("segment", "unicode-segment", RustUnicodeFeatures::SEGMENT),
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
const GENCAT_ALIASES: &[&str] =
    include!("../../../crates/fre-syntax/src/unicode_gencat_aliases.in");
const GENCAT_ALIAS_SET_SHA256: &str =
    "88e48d3f8c7b4e5ad2d25d32d8d7f17a136c0ac1dc42b6ee6f761e8412cbdc61";
const SCRIPT_ALIASES: &[&str] =
    include!("../../../crates/fre-syntax/src/unicode_script_aliases.in");
const SCRIPT_ALIAS_SET_SHA256: &str =
    "8f0e49dddba24d9809bcda8d5915b199062c4bbe828e77711c541fa0d21d8bf7";
const SEGMENT_ALIASES: &[(&[&str], &[&str])] =
    include!("../../../crates/fre-syntax/src/unicode_segment_aliases.in");
const SEGMENT_ALIAS_SOURCE: &[u8] =
    include_bytes!("../../../crates/fre-syntax/src/unicode_segment_aliases.in");
const SEGMENT_ALIAS_SOURCE_SHA256: &str =
    "d6f79b87c29e23e664028331e2fc84084bd1413a9167b4ca3d85e82cb3601470";
const SCRIPT_SOURCE_HASHES: &[(&str, &str)] = &[
    (
        "src/unicode_tables/property_names.rs",
        "8c93985d1bcb01735667a3c4cb92f7e260d267326bde9d7f048bc77cd7e07855",
    ),
    (
        "src/unicode_tables/property_values.rs",
        "ef9131ce0a575c7327ec6d466aafd8b7c25600d80c232b5a4110bbf0a5a59136",
    ),
    (
        "src/unicode_tables/script.rs",
        "41bd424f1e3a03290cf4995ced678dcf24c94b38c905c62f6819bf67e098a2ec",
    ),
    (
        "src/unicode_tables/script_extension.rs",
        "a314099ddbf50a07fe350bb0835bf2fe494ed5ad278b30e171e21506eb557906",
    ),
];
const SEGMENT_SOURCE_HASHES: &[(&str, &str)] = &[
    (
        "src/unicode_tables/grapheme_cluster_break.rs",
        "0dd9d66bad598f4ec3451b6699f05c17c52079e37d463baf6385bbe51aa218f1",
    ),
    (
        "src/unicode_tables/sentence_break.rs",
        "be84fbe8c5c67e761b16fe6c27f16664dbb145357835cd6b92bc2a4a4c52ee79",
    ),
    (
        "src/unicode_tables/word_break.rs",
        "c551681ad49ec28c7ae32bab1371945821c736ca8f0de410cb89f28066ec2ecf",
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
    ("gencat-normalized", r"\p{se PaRa ToR}"),
    (
        "gencat-named-value",
        r"\p{General_Category=Uppercase_Letter}",
    ),
    ("gencat-is-property", r"\p{Is_G-C=Letter}"),
    ("gencat-not-equal", r"\P{gc!=Separator}"),
    ("gencat-surrogate-short", r"\p{cs}"),
    ("gencat-surrogate-long", r"\p{Surrogate}"),
    ("gencat-is-c-collision", r"\p{IsC}"),
    ("gencat-is-cf-collision", r"\p{IsCf}"),
    ("gencat-digit", r"\d"),
    ("gencat-digit-casefold", r"(?i:\d)"),
    ("gencat-bracket-digit-casefold", r"(?i:[\d])"),
    ("gencat-property-casefold", r"(?i:\pL)"),
    ("perl", r"\b\w\b"),
    ("perl-digit", r"\d"),
    ("perl-digit-negated", r"\D"),
    ("perl-space", r"\s"),
    ("perl-space-negated", r"\S"),
    ("perl-word", r"\w"),
    ("perl-word-negated", r"\W"),
    ("perl-space-is-prefix", r"\p{IsWhite_Space}"),
    ("perl-space-short-alias", r"\p{wspace}"),
    ("perl-decimal-named-value", r"\p{gc=Nd}"),
    ("perl-decimal-normalized", r"\p{Is_G-C=D_e-cimal Number}"),
    ("perl-binary-named-value", r"\p{White_Space=Yes}"),
    ("perl-set", r"[\w&&[\s&&\d]]"),
    ("script", r"\p{Greek}"),
    ("script-short", r"\p{Grek}"),
    ("script-is-prefix", r"\p{IsGreek}"),
    ("script-named-value", r"\p{Script=Greek}"),
    ("script-named-short", r"\p{sc=Grek}"),
    ("script-extension", r"\p{Script_Extensions=Hiragana}"),
    ("script-extension-short", r"\p{scx=Hira}"),
    ("script-normalized", r"\p{Is_S-c r i p t=G_r-e e k}"),
    ("script-invalid-value", r"\p{sc=definitely-invalid}"),
    ("script-bare-property", r"\p{Script}"),
    ("script-set", r"[\p{Greek}&&[\p{scx=Common}--\p{Latin}]]"),
    ("segment", r"\p{Grapheme_Cluster_Break=Extend}"),
    (
        "segment-normalized",
        r"\p{Is_G-r a p h e m e _ Cluster _ Break=EX}",
    ),
    ("segment-sentence", r"\p{Sentence_Break=Lower}"),
    ("segment-sentence-short", r"\p{sb=AT}"),
    ("segment-word", r"\p{Word_Break=ALetter}"),
    ("segment-word-short", r"\p{wb=ExtendNumLet}"),
    ("segment-invalid-value", r"\p{gcb=definitely-invalid}"),
    ("segment-unmaterialized-gcb", r"\p{gcb=E_Base}"),
    ("segment-unmaterialized-sb", r"\p{sb=Other}"),
    ("segment-unmaterialized-wb", r"\p{wb=E_Base}"),
    ("segment-bare-property", r"\p{Grapheme_Cluster_Break}"),
    ("segment-cross-family", r"\p{gcb=ALetter}"),
    (
        "segment-set",
        r"[\p{gcb=Extend}~~[\p{sb=Lower}--\p{wb=ALetter}]]",
    ),
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
    ("i-direct-perl-all", r"(?i:\d\s\w)"),
    ("i-bracket-perl", r"(?i:[\w])"),
    ("scoped-order", r"(?i)(?-u:a)(?-i:\u{03B4})"),
    ("nested-case-scope", r"(?i:(?-i:\u{03B4})a)"),
];

fn authenticate_alias_sets() {
    fn authenticate(aliases: &[&str], count: usize, max_len: usize, expected_sha256: &str) {
        assert_eq!(aliases.len(), count);
        assert!(aliases.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(aliases.iter().map(|alias| alias.len()).max(), Some(max_len));
        let mut bytes = aliases.join("\n").into_bytes();
        bytes.push(b'\n');
        assert_eq!(format!("{:x}", Sha256::digest(&bytes)), expected_sha256);
    }

    authenticate(
        BOOL_PROPERTY_ALIASES,
        121,
        30,
        BOOL_PROPERTY_ALIAS_SET_SHA256,
    );
    authenticate(GENCAT_ALIASES, 81, 20, GENCAT_ALIAS_SET_SHA256);
    authenticate(SCRIPT_ALIASES, 338, 21, SCRIPT_ALIAS_SET_SHA256);
    assert_eq!(SEGMENT_ALIASES.len(), 3);
    assert_eq!(SEGMENT_ALIASES[0].1.len(), 18);
    assert_eq!(SEGMENT_ALIASES[1].1.len(), 25);
    assert_eq!(SEGMENT_ALIASES[2].1.len(), 31);
    for &(names, values) in SEGMENT_ALIASES {
        assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(values.windows(2).all(|pair| pair[0] < pair[1]));
    }
    assert_eq!(
        format!("{:x}", Sha256::digest(SEGMENT_ALIAS_SOURCE)),
        SEGMENT_ALIAS_SOURCE_SHA256
    );
}

#[test]
fn typed_profiles_match_feature_isolated_regex_syntax_0_8_11() {
    authenticate_alias_sets();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/unicode-feature-oracle/Cargo.toml");
    authenticate_unicode_sources(&fixture);
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
        for (index, &alias) in GENCAT_ALIASES.iter().enumerate() {
            let pattern = format!(r"\p{{{alias}}}");
            let actual = parse(ParseRequest::rust(
                &pattern,
                CompatibilityProfile::RustText(profile.clone()),
            ))
            .is_ok();
            let id = format!("gencat-alias-{index}:{alias}");
            assert_eq!(
                actual, oracle[&id],
                "configuration={name} alias={alias} pattern={pattern}",
            );
        }
        for (index, &alias) in SCRIPT_ALIASES.iter().enumerate() {
            for (kind, pattern) in [
                ("bare", format!(r"\p{{{alias}}}")),
                ("sc", format!(r"\p{{sc={alias}}}")),
                ("scx", format!(r"\p{{scx={alias}}}")),
            ] {
                let actual = parse(ParseRequest::rust(
                    &pattern,
                    CompatibilityProfile::RustText(profile.clone()),
                ))
                .is_ok();
                let id = format!("script-alias-{index}:{kind}:{alias}");
                assert_eq!(
                    actual, oracle[&id],
                    "configuration={name} alias={alias} kind={kind} pattern={pattern}",
                );
            }
        }
        for (name_family, &(names, _)) in SEGMENT_ALIASES.iter().enumerate() {
            for (name_index, &property_name) in names.iter().enumerate() {
                for (value_family, &(_, values)) in SEGMENT_ALIASES.iter().enumerate() {
                    for (value_index, &property_value) in values.iter().enumerate() {
                        let pattern = format!(r"\p{{{property_name}={property_value}}}");
                        let actual = parse(ParseRequest::rust(
                            &pattern,
                            CompatibilityProfile::RustText(profile.clone()),
                        ))
                        .is_ok();
                        let id = format!(
                            "segment-alias-{name_family}:{name_index}:{value_family}:{value_index}:{property_name}:{property_value}"
                        );
                        assert_eq!(
                            actual, oracle[&id],
                            "configuration={name} property={property_name} value={property_value} pattern={pattern}",
                        );
                    }
                }
            }
        }
    }
    fs::remove_dir_all(&target_root).expect("remove private oracle target root");
}

fn authenticate_unicode_sources(fixture: &Path) {
    let output = Command::new(env!("CARGO"))
        .arg("metadata")
        .arg("--offline")
        .arg("--locked")
        .arg("--format-version=1")
        .arg("--manifest-path")
        .arg(fixture)
        .output()
        .expect("read isolated regex-syntax metadata");
    assert!(
        output.status.success(),
        "metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("metadata is JSON");
    let manifest = metadata["packages"]
        .as_array()
        .expect("metadata packages")
        .iter()
        .find(|package| {
            package["name"].as_str() == Some("regex-syntax")
                && package["version"].as_str() == Some("0.8.11")
        })
        .and_then(|package| package["manifest_path"].as_str())
        .map(PathBuf::from)
        .expect("pinned regex-syntax manifest");
    let root = manifest.parent().expect("regex-syntax package root");
    let root_metadata = fs::symlink_metadata(root).expect("stat regex-syntax package root");
    assert!(root_metadata.file_type().is_dir());
    assert!(!root_metadata.file_type().is_symlink());
    for &(relative, expected) in SCRIPT_SOURCE_HASHES.iter().chain(SEGMENT_SOURCE_HASHES) {
        let path = root.join(relative);
        let metadata = fs::symlink_metadata(&path).expect("stat pinned Unicode source");
        assert!(metadata.file_type().is_file(), "{}", path.display());
        assert!(!metadata.file_type().is_symlink(), "{}", path.display());
        let bytes = fs::read(&path).expect("read pinned Unicode source");
        assert_eq!(
            format!("{:x}", Sha256::digest(&bytes)),
            expected,
            "{}",
            path.display()
        );
    }
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
        .and_then(|count| count.checked_add(GENCAT_ALIASES.len()))
        .and_then(|count| count.checked_add(SCRIPT_ALIASES.len().checked_mul(3)?))
        .and_then(|count| {
            let names = SEGMENT_ALIASES
                .iter()
                .try_fold(0_usize, |sum, (names, _)| sum.checked_add(names.len()))?;
            let values = SEGMENT_ALIASES
                .iter()
                .try_fold(0_usize, |sum, (_, values)| sum.checked_add(values.len()))?;
            count.checked_add(names.checked_mul(values)?)
        })
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
