use core::fmt;

/// A pinned upstream source revision that participates in semantic identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum UpstreamRevision {
    /// `rust-lang/regex` 1.13.0 at the revision used by this prototype.
    RustRegex1_13_0_926af2e,
    /// `google/re2` at revision `972a15cedd008d846f1a39b2e88ce48d7f166cbd`.
    Re2_972a15c,
}

impl UpstreamRevision {
    #[must_use]
    pub const fn commit(self) -> &'static str {
        match self {
            Self::RustRegex1_13_0_926af2e => "926af2e68eca3ce089815790541cf50759ba2c59",
            Self::Re2_972a15c => "972a15cedd008d846f1a39b2e88ce48d7f166cbd",
        }
    }
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
/// `size_limit` and `dfa_size_limit` do not change language semantics, but do
/// change constructor behavior and therefore remain in cache/admission keys.
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
    pub size_limit: u64,
    pub dfa_size_limit: u64,
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
            size_limit: 10 * (1 << 20),
            dfa_size_limit: 2 * (1 << 20),
            nest_limit: 250,
        }
    }
}

/// Versioned Rust-regex profile data shared by text and bytes facades.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RustProfile {
    pub revision: UpstreamRevision,
    pub regex_syntax_version: (u16, u16, u16),
    pub unicode: UnicodeVersion,
    pub options: RustOptions,
}

impl Default for RustProfile {
    fn default() -> Self {
        Self {
            revision: UpstreamRevision::RustRegex1_13_0_926af2e,
            regex_syntax_version: (0, 8, 11),
            unicode: UnicodeVersion::RUST_16_0_0,
            options: RustOptions::default(),
        }
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
