use core::fmt;

use crate::AdmissionStatus;

/// A pinned upstream source revision that participates in semantic identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum UpstreamRevision {
    /// Packaged VCS revision for `regex` 1.12.4.
    RustRegex1_12_4_7b96fdc,
    /// Packaged VCS revision for `regex-automata` 0.4.14.
    RustRegexAutomata0_4_14_5e195de,
    /// Packaged VCS revision for `regex-syntax` 0.8.11.
    RustRegexSyntax0_8_11_1401679,
    /// Rebar revision whose Rust adapter configuration is represented here.
    Rebar463d00f,
    /// `google/re2` at revision `972a15cedd008d846f1a39b2e88ce48d7f166cbd`.
    Re2_972a15c,
}

impl UpstreamRevision {
    #[must_use]
    pub const fn commit(self) -> &'static str {
        match self {
            Self::RustRegex1_12_4_7b96fdc => "7b96fdc9d5fe6a0cb4efe30e6689b050493fc1e1",
            Self::RustRegexAutomata0_4_14_5e195de => "5e195de266e203441b2c8001d6ebefab1161a59e",
            Self::RustRegexSyntax0_8_11_1401679 => "140167995737fa11dfe11b8af8b9aa143b790b4e",
            Self::Rebar463d00f => "463d00f31887e84c38467805b9e3122c314b9521",
            Self::Re2_972a15c => "972a15cedd008d846f1a39b2e88ce48d7f166cbd",
        }
    }
}

/// A crates.io package version participating in compatibility identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PackageVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl fmt::Display for PackageVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Exact crates.io and packaged-source receipt for one Rust component.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PackageIdentity {
    pub version: PackageVersion,
    pub checksum: &'static str,
    pub vcs_revision: UpstreamRevision,
}

impl PackageIdentity {
    pub const REGEX_1_12_4: Self = Self {
        version: PackageVersion {
            major: 1,
            minor: 12,
            patch: 4,
        },
        checksum: "f1292b7759ae1cb9ec195452d1390a074f0cd8541ab7a5a8c31cd6db45d4a6ba",
        vcs_revision: UpstreamRevision::RustRegex1_12_4_7b96fdc,
    };
    pub const REGEX_AUTOMATA_0_4_14: Self = Self {
        version: PackageVersion {
            major: 0,
            minor: 4,
            patch: 14,
        },
        checksum: "6e1dd4122fc1595e8162618945476892eefca7b88c52820e74af6262213cae8f",
        vcs_revision: UpstreamRevision::RustRegexAutomata0_4_14_5e195de,
    };
    pub const REGEX_SYNTAX_0_8_11: Self = Self {
        version: PackageVersion {
            major: 0,
            minor: 8,
            patch: 11,
        },
        checksum: "d6f6ff9a378485b298a5286656da665ba74413d36db0979633275d2e708145d4",
        vcs_revision: UpstreamRevision::RustRegexSyntax0_8_11_1401679,
    };
}

/// Unicode Character Database version used by a semantic profile.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UnicodeVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl UnicodeVersion {
    pub const RUST_16_0_0: Self = Self {
        major: 16,
        minor: 0,
        patch: 0,
    };
    pub const RE2_15_1_0: Self = Self {
        major: 15,
        minor: 1,
        patch: 0,
    };
}

impl fmt::Display for UnicodeVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// All public Rust regex builder settings that affect compatibility identity.
///
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "fields intentionally mirror the public Rust RegexBuilder surface one-for-one"
)]
pub struct RustOptions {
    pub case_insensitive: bool,
    pub multi_line: bool,
    pub dot_matches_new_line: bool,
    pub crlf: bool,
    pub line_terminator: u8,
    pub swap_greed: bool,
    pub ignore_whitespace: bool,
    pub unicode: bool,
    pub octal: bool,
    pub nest_limit: u32,
}

impl Default for RustOptions {
    fn default() -> Self {
        Self {
            case_insensitive: false,
            multi_line: false,
            dot_matches_new_line: false,
            crlf: false,
            line_terminator: b'\n',
            swap_greed: false,
            ignore_whitespace: false,
            unicode: true,
            octal: false,
            nest_limit: 250,
        }
    }
}

/// Match selection configured by a Rust constructor profile.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RustMatchKind {
    LeftmostFirst,
}

/// Constructor and feature identity beyond syntax builder options.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RustConstructor {
    /// High-level `regex::bytes::RegexBuilder` release defaults.
    RegexBuilder {
        size_limit: u64,
        dfa_size_limit: u64,
        text_syntax_utf8: bool,
        bytes_syntax_utf8: bool,
        text_utf8_empty: bool,
        bytes_utf8_empty: bool,
        match_kind: RustMatchKind,
    },
    /// High-level `regex::bytes::RegexSetBuilder` release defaults.
    ///
    /// The fields deliberately mirror [`Self::RegexBuilder`], but the
    /// compiled-size limit applies once to the combined capture-free NFA for
    /// all patterns. It must not be applied independently to each pattern.
    RegexSetBuilder {
        size_limit: u64,
        dfa_size_limit: u64,
        text_syntax_utf8: bool,
        bytes_syntax_utf8: bool,
        text_utf8_empty: bool,
        bytes_utf8_empty: bool,
        match_kind: RustMatchKind,
    },
    /// Rebar's ordered `regex_automata::meta::Regex::builder` configuration.
    RebarMeta {
        rebar_revision: UpstreamRevision,
        regex_default_features: bool,
        regex_logging: bool,
        regex_perf_dfa_full: bool,
        regex_automata_default_features: bool,
        syntax_utf8: bool,
        utf8_empty: bool,
        match_kind: RustMatchKind,
        build_many_ordered: bool,
        thompson_nfa_size_limit: u64,
        admission_status: AdmissionStatus,
    },
}

/// Versioned Rust-regex profile data shared by text and bytes facades.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RustProfile {
    pub regex: PackageIdentity,
    pub regex_automata: PackageIdentity,
    pub regex_syntax: PackageIdentity,
    pub unicode: UnicodeVersion,
    pub constructor: RustConstructor,
    pub options: RustOptions,
}

impl Default for RustProfile {
    fn default() -> Self {
        Self::regex_1_12_4()
    }
}

impl RustProfile {
    /// Honest high-level `regex` 1.12.4 release-stack identity.
    #[must_use]
    pub fn regex_1_12_4() -> Self {
        Self {
            regex: PackageIdentity::REGEX_1_12_4,
            regex_automata: PackageIdentity::REGEX_AUTOMATA_0_4_14,
            regex_syntax: PackageIdentity::REGEX_SYNTAX_0_8_11,
            unicode: UnicodeVersion::RUST_16_0_0,
            constructor: RustConstructor::RegexBuilder {
                size_limit: 10 * (1 << 20),
                dfa_size_limit: 2 * (1 << 20),
                text_syntax_utf8: true,
                bytes_syntax_utf8: false,
                text_utf8_empty: true,
                bytes_utf8_empty: false,
                match_kind: RustMatchKind::LeftmostFirst,
            },
            options: RustOptions::default(),
        }
    }

    /// Exact high-level `regex::bytes::RegexSetBuilder` release identity.
    #[must_use]
    pub fn regex_set_1_12_4() -> Self {
        Self::regex_1_12_4().into_regex_set_builder()
    }

    /// Convert a high-level single-regex constructor stamp into the
    /// corresponding set constructor while preserving every configured
    /// option and component identity.
    ///
    /// Non-high-level constructor profiles are returned unchanged.
    #[must_use]
    pub fn into_regex_set_builder(mut self) -> Self {
        if let RustConstructor::RegexBuilder {
            size_limit,
            dfa_size_limit,
            text_syntax_utf8,
            bytes_syntax_utf8,
            text_utf8_empty,
            bytes_utf8_empty,
            match_kind,
        } = self.constructor
        {
            self.constructor = RustConstructor::RegexSetBuilder {
                size_limit,
                dfa_size_limit,
                text_syntax_utf8,
                bytes_syntax_utf8,
                text_utf8_empty,
                bytes_utf8_empty,
                match_kind,
            };
        }
        self
    }

    /// Convert a high-level set constructor stamp into the corresponding
    /// single-regex constructor while preserving every configured option and
    /// component identity.
    ///
    /// Non-high-level constructor profiles are returned unchanged.
    #[must_use]
    pub fn into_regex_builder(mut self) -> Self {
        if let RustConstructor::RegexSetBuilder {
            size_limit,
            dfa_size_limit,
            text_syntax_utf8,
            bytes_syntax_utf8,
            text_utf8_empty,
            bytes_utf8_empty,
            match_kind,
        } = self.constructor
        {
            self.constructor = RustConstructor::RegexBuilder {
                size_limit,
                dfa_size_limit,
                text_syntax_utf8,
                bytes_syntax_utf8,
                text_utf8_empty,
                bytes_utf8_empty,
                match_kind,
            };
        }
        self
    }

    /// Exact Rebar 1.12.4 Rust adapter construction identity.
    #[must_use]
    pub fn rebar_1_12_4() -> Self {
        Self {
            regex: PackageIdentity::REGEX_1_12_4,
            regex_automata: PackageIdentity::REGEX_AUTOMATA_0_4_14,
            regex_syntax: PackageIdentity::REGEX_SYNTAX_0_8_11,
            unicode: UnicodeVersion::RUST_16_0_0,
            constructor: RustConstructor::RebarMeta {
                rebar_revision: UpstreamRevision::Rebar463d00f,
                regex_default_features: true,
                regex_logging: true,
                regex_perf_dfa_full: true,
                regex_automata_default_features: true,
                syntax_utf8: false,
                utf8_empty: false,
                match_kind: RustMatchKind::LeftmostFirst,
                build_many_ordered: true,
                thompson_nfa_size_limit: 100 * 1_048_576,
                admission_status: AdmissionStatus::UpstreamOraclePending,
            },
            options: RustOptions::default(),
        }
    }

    /// Stable textual receipt derived from the typed component/config stamp.
    #[must_use]
    pub fn identity_string(&self) -> String {
        format!(
            "regex={}@{}#{}; regex-automata={}@{}#{}; regex-syntax={}@{}#{}; unicode={}; constructor={:?}; options={:?}",
            self.regex.version,
            self.regex.vcs_revision.commit(),
            self.regex.checksum,
            self.regex_automata.version,
            self.regex_automata.vcs_revision.commit(),
            self.regex_automata.checksum,
            self.regex_syntax.version,
            self.regex_syntax.vcs_revision.commit(),
            self.regex_syntax.checksum,
            self.unicode,
            self.constructor,
            self.options,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Re2Encoding {
    Utf8,
    Latin1,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Re2Syntax {
    Perl,
    Posix,
}

/// Complete public `RE2::Options` identity at the pinned revision.
///
/// The defaults intentionally include `log_errors = true`; it is a common and
/// compatibility-breaking mistake to assume all RE2 booleans default false.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "fields intentionally mirror every public RE2::Options bit one-for-one"
)]
pub struct Re2Options {
    pub max_mem: i64,
    pub encoding: Re2Encoding,
    pub posix_syntax: bool,
    pub longest_match: bool,
    pub log_errors: bool,
    pub literal: bool,
    pub never_nl: bool,
    pub dot_nl: bool,
    pub never_capture: bool,
    pub case_sensitive: bool,
    pub perl_classes: bool,
    pub word_boundary: bool,
    pub one_line: bool,
}

impl Default for Re2Options {
    fn default() -> Self {
        Self {
            max_mem: 8 << 20,
            encoding: Re2Encoding::Utf8,
            posix_syntax: false,
            longest_match: false,
            log_errors: true,
            literal: false,
            never_nl: false,
            dot_nl: false,
            never_capture: false,
            case_sensitive: true,
            perl_classes: false,
            word_boundary: false,
            one_line: false,
        }
    }
}

/// A complete RE2 profile stamp. Options are never canonicalized away.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Re2Profile {
    pub revision: UpstreamRevision,
    pub unicode: UnicodeVersion,
    pub options: Re2Options,
}

impl Default for Re2Profile {
    fn default() -> Self {
        Self {
            revision: UpstreamRevision::Re2_972a15c,
            unicode: UnicodeVersion::RE2_15_1_0,
            options: Re2Options::default(),
        }
    }
}

impl Re2Profile {
    #[must_use]
    pub const fn syntax(&self) -> Re2Syntax {
        if self.options.posix_syntax {
            Re2Syntax::Posix
        } else {
            Re2Syntax::Perl
        }
    }

    #[must_use]
    pub const fn encoding(&self) -> Re2Encoding {
        self.options.encoding
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum InputKind {
    ValidUtf8,
    ArbitraryBytes,
    Re2Utf8Domain,
    Latin1Bytes,
}

/// A complete compatibility identity, before operation-specific lowering.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CompatibilityProfile {
    RustText(RustProfile),
    RustBytes(RustProfile),
    Re2(Re2Profile),
}

impl CompatibilityProfile {
    #[must_use]
    pub fn rust_text() -> Self {
        Self::RustText(RustProfile::default())
    }

    #[must_use]
    pub fn rust_bytes() -> Self {
        Self::RustBytes(RustProfile::default())
    }

    #[must_use]
    pub fn re2() -> Self {
        Self::Re2(Re2Profile::default())
    }

    #[must_use]
    pub const fn input_kind(&self) -> InputKind {
        match self {
            Self::RustText(_) => InputKind::ValidUtf8,
            Self::RustBytes(_) => InputKind::ArbitraryBytes,
            Self::Re2(profile) => match profile.options.encoding {
                Re2Encoding::Utf8 => InputKind::Re2Utf8Domain,
                Re2Encoding::Latin1 => InputKind::Latin1Bytes,
            },
        }
    }
}
