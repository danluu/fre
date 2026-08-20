#![forbid(unsafe_code)]

use fre::{PortableBuilder, RustProfile, SearchLimits, escape};

const UPSTREAM_REGEX_REVISION: &str = "7b96fdc9d5fe6a0cb4efe30e6689b050493fc1e1";
const UPSTREAM_REGEX_PACKAGE_SHA256: &str =
    "f1292b7759ae1cb9ec195452d1390a074f0cd8541ab7a5a8c31cd6db45d4a6ba";
const UPSTREAM_REGEX_PATH: &str = "src/lib.rs";
const UPSTREAM_REGEX_SHA256: &str =
    "033460754d7a51fb9fa90ad096f76dbaaf10dc4c49f1195bb088fe23d35ded75";
const UPSTREAM_SYNTAX_REVISION: &str = "140167995737fa11dfe11b8af8b9aa143b790b4e";
const UPSTREAM_SYNTAX_PACKAGE_SHA256: &str =
    "d6f6ff9a378485b298a5286656da665ba74413d36db0979633275d2e708145d4";
const UPSTREAM_SYNTAX_PATH: &str = "src/lib.rs";
const UPSTREAM_SYNTAX_SHA256: &str =
    "c51d1e55a8b6c4608e21a278ed0ef9480f73ab5b814b6ca6127f4a049c4d5007";
const UPSTREAM_API_IDS: &[&str] = &["escape"];

#[test]
fn authenticated_escape_api_inventory_has_no_silent_omissions() {
    let profile = RustProfile::regex_1_12_4();
    assert_eq!(profile.regex.vcs_revision.commit(), UPSTREAM_REGEX_REVISION);
    assert_eq!(profile.regex.checksum, UPSTREAM_REGEX_PACKAGE_SHA256);
    assert_eq!(
        profile.regex_syntax.vcs_revision.commit(),
        UPSTREAM_SYNTAX_REVISION
    );
    assert_eq!(
        profile.regex_syntax.checksum,
        UPSTREAM_SYNTAX_PACKAGE_SHA256
    );
    assert_eq!(UPSTREAM_REGEX_PATH, "src/lib.rs");
    assert_eq!(UPSTREAM_REGEX_SHA256.len(), 64);
    assert_eq!(UPSTREAM_SYNTAX_PATH, "src/lib.rs");
    assert_eq!(UPSTREAM_SYNTAX_SHA256.len(), 64);
    assert_eq!(UPSTREAM_API_IDS, &["escape"]);
}

#[test]
fn escape_matches_pinned_rust_over_every_unicode_scalar() {
    let scalars: String = (0..=u32::from(char::MAX))
        .filter_map(char::from_u32)
        .collect();
    assert_eq!(escape(&scalars), regex::escape(&scalars));
}

#[test]
fn escaped_patterns_match_the_original_text_literally() {
    const LITERALS: &[&str] = &[
        "",
        r"\.+*?()|[]{}^$#&-~",
        "ordinary ASCII",
        "line one\nline two\t\0",
        "snowman ☃, Greek αβ, emoji 🦀",
    ];

    for literal in LITERALS {
        let escaped = escape(literal);
        assert_eq!(escaped, regex::escape(literal), "{literal:?}");

        let regex = PortableBuilder::new(escaped)
            .build()
            .unwrap_or_else(|error| panic!("escaped literal {literal:?} did not build: {error}"));
        let matched = regex
            .find_accounted(literal.as_bytes(), SearchLimits::unlimited())
            .unwrap_or_else(|error| panic!("escaped literal {literal:?} failed to search: {error}"))
            .0
            .unwrap_or_else(|| panic!("escaped literal {literal:?} did not match itself"));
        assert_eq!(matched.range(), 0..literal.len(), "{literal:?}");
    }
}
