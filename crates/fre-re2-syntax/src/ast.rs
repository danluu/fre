//! Byte-preserving arena AST and lexical evidence.

use crate::options::Options;
use std::collections::BTreeMap;

/// Half-open source byte span in the original pattern.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PatternSpan {
    /// Inclusive source byte offset.
    pub start: usize,
    /// Exclusive source byte offset.
    pub end: usize,
}

impl PatternSpan {
    /// Builds a half-open span.
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }
}

/// Stable index into [`Ast::nodes`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NodeId(pub u32);

/// Quantifier preference after current inline flags are applied.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Greediness {
    /// Prefer more repetitions.
    Greedy,
    /// Prefer fewer repetitions.
    NonGreedy,
}

/// A checked repetition interval. `max == None` is unbounded.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RepeatRange {
    /// Minimum repetitions.
    pub min: u16,
    /// Maximum repetitions, or no maximum.
    pub max: Option<u16>,
}

/// Source family of a repetition operator.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RepeatSyntax {
    /// `*`, `+`, or `?`.
    Simple,
    /// `{m}`, `{m,}`, or `{m,n}`.
    Counted,
}

/// Zero-width assertion.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AnchorKind {
    /// Beginning of text (`\A`, or `^` under one-line).
    BeginText,
    /// End of text (`\z`, or `$` under one-line).
    EndText,
    /// Beginning of line.
    BeginLine,
    /// End of line.
    EndLine,
    /// ASCII word boundary.
    WordBoundary,
    /// Not an ASCII word boundary.
    NotWordBoundary,
}

/// Character-class container kind.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ClassKind {
    /// Explicit bracket expression.
    Bracket { negated: bool },
    /// Built-in Perl class escape.
    Perl,
    /// Pinned RE2 Unicode group escape.
    Unicode,
}

/// POSIX named ASCII class from pinned `re2/perl_groups.cc`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PosixClass {
    Alnum,
    Alpha,
    Ascii,
    Blank,
    Cntrl,
    Digit,
    Graph,
    Lower,
    Print,
    Punct,
    Space,
    Upper,
    Word,
    Xdigit,
}

/// Symbolic class atom whose exact upstream meaning is stable.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ClassAtom {
    Digit,
    NotDigit,
    Space,
    NotSpace,
    Word,
    NotWord,
}

/// Item in a byte-preserving character class.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum ClassItem {
    /// Inclusive Unicode scalar/Latin-1 code-point range.
    Range { lo: u32, hi: u32, span: PatternSpan },
    /// Symbolic Perl class retained without table expansion.
    Perl { atom: ClassAtom, span: PatternSpan },
    /// Symbolic POSIX group, tied to the pinned profile.
    Posix {
        class: PosixClass,
        negated: bool,
        span: PatternSpan,
    },
    /// Symbolic Unicode group, tied to the pinned generated table.
    Unicode {
        name: String,
        negated: bool,
        span: PatternSpan,
    },
}

/// AST operation. Child ordering is source/priority ordering.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum NodeKind {
    /// Matches no strings (for example, a literal newline under `never_nl`).
    NoMatch,
    /// Matches the empty string.
    Empty,
    /// One decoded rune (or one Latin-1 byte).
    Literal { value: u32, fold_case: bool },
    /// Ordered concatenation.
    Concat { children: Vec<NodeId> },
    /// Ordered alternation.
    Alternation { branches: Vec<NodeId> },
    /// Capturing parenthesis.
    Capture {
        index: u32,
        name: Option<String>,
        child: NodeId,
    },
    /// Character class.
    Class {
        kind: ClassKind,
        items: Vec<ClassItem>,
        fold_case: bool,
        class_newline: bool,
        never_newline: bool,
    },
    /// Any rune, with newline behavior frozen at the source site.
    AnyChar { matches_newline: bool },
    /// RE2's `\C`: one byte, even in UTF-8 mode.
    AnyByte,
    /// Zero-width assertion.
    Anchor(AnchorKind),
    /// Quantified child.
    Repeat {
        child: NodeId,
        range: RepeatRange,
        greediness: Greediness,
        syntax: RepeatSyntax,
        /// Pinned RE2 `ParseFlags` at the operator site. This is retained so
        /// parser-level repeat squashing follows upstream flag equality.
        parse_flags: u16,
    },
}

/// One arena node with its exact source extent.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Node {
    pub kind: NodeKind,
    pub span: PatternSpan,
}

/// Lexical evidence retained for diagnostics and conformance replay.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TokenKind {
    Literal,
    Escape,
    OpenCapture,
    OpenNamedCapture,
    OpenNonCapture,
    CloseGroup,
    Alternation,
    Quantifier,
    CharacterClass,
    Anchor,
    Dot,
    InlineFlags,
    QuotedLiteral,
}

/// One source token.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: PatternSpan,
}

/// Parsed, byte-preserving syntax artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ast {
    /// Unmodified source bytes, including invalid UTF-8 in Latin-1 mode.
    pub pattern: Box<[u8]>,
    /// Immutable constructor options used for parsing.
    pub options: Options,
    /// Arena nodes in construction order.
    pub nodes: Vec<Node>,
    /// Root node.
    pub root: NodeId,
    /// Source tokens.
    pub tokens: Vec<Token>,
    /// Number of capturing groups.
    pub capture_count: u32,
}

impl Ast {
    /// Resolves an arena identifier.
    #[must_use]
    pub fn node(&self, id: NodeId) -> Option<&Node> {
        usize::try_from(id.0)
            .ok()
            .and_then(|index| self.nodes.get(index))
    }

    /// Returns the original bytes covered by `span`.
    #[must_use]
    pub fn source(&self, span: PatternSpan) -> Option<&[u8]> {
        self.pattern.get(span.start..span.end)
    }

    /// RE2-style name-to-first-capture map.
    #[must_use]
    pub fn named_captures(&self) -> BTreeMap<String, u32> {
        let mut names = BTreeMap::new();
        for node in &self.nodes {
            if let NodeKind::Capture {
                index,
                name: Some(name),
                ..
            } = &node.kind
            {
                names
                    .entry(name.clone())
                    .and_modify(|prior: &mut u32| *prior = (*prior).min(*index))
                    .or_insert(*index);
            }
        }
        names
    }

    /// RE2-style capture-to-name map.
    #[must_use]
    pub fn capture_names(&self) -> BTreeMap<u32, String> {
        let mut names = BTreeMap::new();
        for node in &self.nodes {
            if let NodeKind::Capture {
                index,
                name: Some(name),
                ..
            } = &node.kind
            {
                names.insert(*index, name.clone());
            }
        }
        names
    }
}
