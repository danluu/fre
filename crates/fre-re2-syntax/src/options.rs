//! RE2 constructor options and parser resource limits.

/// Pattern and haystack encoding.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Encoding {
    /// Pattern bytes must be well-formed UTF-8.
    Utf8,
    /// Every pattern byte is one Latin-1 code point.
    Latin1,
}

/// User-visible syntax selection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SyntaxMode {
    /// RE2's default syntax, corresponding to `Regexp::LikePerl`.
    Perl,
    /// RE2's POSIX constructor mode.
    Posix,
}

/// All fields of `RE2::Options` that affect syntax, matching, diagnostics, or
/// cache/profile identity at the pinned revision.
#[allow(
    clippy::struct_excessive_bools,
    reason = "the public RE2 Options ABI is itself a set of orthogonal booleans"
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Options {
    /// RE2's total program/DFA memory budget; retained in profile identity.
    pub max_mem: i64,
    /// Input encoding.
    pub encoding: Encoding,
    /// Perl-like default syntax or POSIX mode.
    pub syntax: SyntaxMode,
    /// Request leftmost-longest matching; retained in profile identity.
    pub longest_match: bool,
    /// Permit upstream error logging. This crate itself never logs parse errors.
    pub log_errors: bool,
    /// Treat the pattern as literal text.
    pub literal: bool,
    /// Exclude newline even when mentioned explicitly.
    pub never_nl: bool,
    /// Permit dot to match newline.
    pub dot_nl: bool,
    /// Parse every parenthesis as non-capturing.
    pub never_capture: bool,
    /// Apply simple case folding when false.
    pub case_sensitive: bool,
    /// Enable Perl character classes in POSIX mode.
    pub perl_classes: bool,
    /// Enable Perl word-boundary escapes in POSIX mode.
    pub word_boundary: bool,
    /// Make `^` and `$` text anchors instead of line anchors.
    pub one_line: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            max_mem: Self::DEFAULT_MAX_MEM,
            encoding: Encoding::Utf8,
            syntax: SyntaxMode::Perl,
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

impl Options {
    /// `RE2::Options::kDefaultMaxMem` at the pinned revision.
    pub const DEFAULT_MAX_MEM: i64 = 8 << 20;

    /// RE2's canned POSIX options.
    #[must_use]
    pub const fn posix() -> Self {
        Self {
            max_mem: Self::DEFAULT_MAX_MEM,
            encoding: Encoding::Utf8,
            syntax: SyntaxMode::Posix,
            longest_match: true,
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

    /// RE2's canned Latin-1 options.
    #[must_use]
    pub const fn latin1() -> Self {
        Self {
            encoding: Encoding::Latin1,
            ..Self::posix_like_perl()
        }
    }

    const fn posix_like_perl() -> Self {
        Self {
            max_mem: Self::DEFAULT_MAX_MEM,
            encoding: Encoding::Utf8,
            syntax: SyntaxMode::Perl,
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

/// Checked parser resource envelope.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ParseLimits {
    /// Maximum source length in bytes.
    pub max_pattern_bytes: usize,
    /// Maximum AST arena nodes.
    pub max_nodes: usize,
    /// Maximum emitted tokens.
    pub max_tokens: usize,
    /// Maximum open-parenthesis depth.
    pub max_nesting: usize,
    /// Maximum number of captures.
    pub max_captures: usize,
    /// Maximum aggregate class atoms/ranges.
    pub max_class_items: usize,
    /// Maximum parser-loop work units.
    pub max_work: usize,
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_pattern_bytes: 1 << 20,
            max_nodes: 1 << 20,
            max_tokens: 1 << 20,
            max_nesting: 1 << 14,
            max_captures: 1 << 20,
            max_class_items: 1 << 20,
            max_work: 8 << 20,
        }
    }
}
