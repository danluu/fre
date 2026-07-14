//! Typed parse, resource, and incomplete-surface outcomes.

use crate::ast::{Ast, PatternSpan};

/// RE2 constructor error code names at the pinned revision.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ParseErrorCode {
    Internal,
    BadEscape,
    BadCharClass,
    BadCharRange,
    MissingBracket,
    MissingParen,
    UnexpectedParen,
    TrailingBackslash,
    RepeatArgument,
    RepeatSize,
    RepeatOp,
    BadPerlOp,
    BadUtf8,
    BadNamedCapture,
    PatternTooLarge,
}

impl ParseErrorCode {
    /// Pinned `RegexpStatus::CodeText`, or RE2's compile-failure text for
    /// [`Self::PatternTooLarge`].
    #[must_use]
    pub const fn re2_code_text(self) -> &'static str {
        match self {
            Self::Internal => "unexpected error",
            Self::BadEscape => "invalid escape sequence",
            Self::BadCharClass => "invalid character class",
            Self::BadCharRange => "invalid character class range",
            Self::MissingBracket => "missing ]",
            Self::MissingParen => "missing )",
            Self::UnexpectedParen => "unexpected )",
            Self::TrailingBackslash => "trailing \\",
            Self::RepeatArgument => "no argument for repetition operator",
            Self::RepeatSize => "invalid repetition size",
            Self::RepeatOp => "bad repetition operator",
            Self::BadPerlOp => "invalid perl operator",
            Self::BadUtf8 => "invalid UTF-8",
            Self::BadNamedCapture => "invalid named capture group",
            Self::PatternTooLarge => "pattern too large - compile failed",
        }
    }
}

/// Parser resource that exhausted its explicit envelope.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LimitKind {
    PatternBytes,
    AstNodes,
    Tokens,
    Nesting,
    Captures,
    ClassItems,
    Work,
    IntegerArithmetic,
}

/// Successfully charged parser usage.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ResourceUsage {
    pub source_bytes: usize,
    pub nodes: usize,
    pub tokens: usize,
    pub maximum_nesting: usize,
    pub captures: usize,
    pub class_items: usize,
    pub work: usize,
}

/// Exact parser error evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseError {
    /// RE2-compatible category when qualified; `PatternTooLarge` for limits.
    pub code: ParseErrorCode,
    /// Offending bytes in the original input when an exact span is known.
    pub argument: PatternSpan,
    /// Bytes RE2 exposes as `error_arg()` for source-derived diagnostics.
    /// Latin-1 patterns are converted to UTF-8 by pinned RE2 before parsing.
    pub argument_bytes: Box<[u8]>,
    /// Stable crate-owned explanation, not claimed byte-identical to RE2 logs.
    pub message: String,
    /// Explicit resource if this was an admission failure.
    pub limit: Option<LimitKind>,
    /// Exact attempted value for `limit`, when this was an admission failure.
    /// This is kept separate from `usage`, which records only successfully
    /// charged resources and therefore never exceeds its envelope.
    pub observed: Option<usize>,
    /// Usage charged before failure.
    pub usage: ResourceUsage,
}

impl ParseError {
    /// Reconstructs pinned RE2's byte-level status text for syntax errors.
    /// Admission-limit errors are crate policy rather than upstream syntax and
    /// therefore return `None`.
    #[must_use]
    pub fn re2_status_text(&self) -> Option<Vec<u8>> {
        if self.limit.is_some() {
            return None;
        }
        let mut text = self.code.re2_code_text().as_bytes().to_vec();
        if !self.argument_bytes.is_empty() {
            text.extend_from_slice(b": ");
            text.extend_from_slice(&self.argument_bytes);
        }
        Some(text)
    }
}

/// Syntax deliberately not interpreted by this incremental track.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum UnsupportedFeature {
    /// Full category validation for non-ASCII capture names requires importing
    /// the pinned Unicode general-category range union.
    UnicodeCaptureName,
}

/// Explicit non-success for an unqualified surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotYetImplemented {
    pub feature: UnsupportedFeature,
    pub span: PatternSpan,
    pub usage: ResourceUsage,
    pub evidence: &'static str,
}

/// Three-way result: success, qualified RE2-style rejection, or incomplete.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseOutcome {
    /// Syntax was represented under the requested envelope. This does not
    /// claim RE2 constructor admission, which also compiles under `max_mem`.
    Parsed {
        ast: Ast,
        usage: ResourceUsage,
    },
    Rejected(ParseError),
    NotYetImplemented(NotYetImplemented),
}
