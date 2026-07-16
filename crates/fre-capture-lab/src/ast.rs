//! Deliberately small, byte-oriented capture AST.

/// Repetition preference for the Rust leftmost-first profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Greed {
    /// Prefer another repetition before exiting.
    Greedy,
    /// Prefer exiting before another repetition.
    Lazy,
}

/// A zero-width predicate with exact logical-window context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Assertion {
    /// Beginning of the logical window.
    Start,
    /// End of the logical window.
    End,
    /// Beginning of the logical window or immediately after LF.
    StartLf,
    /// End of the logical window or immediately before LF.
    EndLf,
    /// Beginning of the logical window or immediately after the configured byte.
    StartLine(u8),
    /// End of the logical window or immediately before the configured byte.
    EndLine(u8),
    /// Beginning of a CRLF-aware line without splitting a CRLF pair.
    StartCrlf,
    /// End of a CRLF-aware line without splitting a CRLF pair.
    EndCrlf,
    /// ASCII word boundary.
    WordAscii,
    /// Negated ASCII word boundary.
    WordAsciiNegate,
    /// Start of an ASCII word.
    WordStartAscii,
    /// End of an ASCII word.
    WordEndAscii,
    /// Left half of an ASCII word-start predicate.
    WordStartHalfAscii,
    /// Right half of an ASCII word-end predicate.
    WordEndHalfAscii,
    /// Positive Unicode word boundary using the pinned UTS#18 word set.
    WordUnicode,
    /// Negated Unicode word boundary.
    WordUnicodeNegate,
    /// Start of a Unicode word.
    WordStartUnicode,
    /// End of a Unicode word.
    WordEndUnicode,
    /// Left half of a Unicode word-start predicate.
    WordStartHalfUnicode,
    /// Right half of a Unicode word-end predicate.
    WordEndHalfUnicode,
}

/// Syntax accepted by the capture laboratory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Ast {
    /// The empty expression.
    Empty,
    /// One exact byte.
    Byte(u8),
    /// One byte in any inclusive range. Ranges must be sorted and disjoint.
    Class(Vec<(u8, u8)>),
    /// Concatenation, in source order.
    Concat(Vec<Ast>),
    /// Ordered leftmost-first alternation.
    Alt(Vec<Ast>),
    /// Repetition. `None` means no finite maximum.
    Repeat {
        /// Repeated expression.
        child: Box<Ast>,
        /// Minimum repetition count.
        min: u32,
        /// Optional inclusive maximum repetition count.
        max: Option<u32>,
        /// Greedy or lazy branch priority.
        greed: Greed,
    },
    /// A numbered and optionally named capture.
    Capture {
        /// One-based capture index in source opening-parenthesis order.
        index: u32,
        /// Optional unique ASCII name.
        name: Option<String>,
        /// Captured expression.
        child: Box<Ast>,
    },
    /// Beginning of the logical window.
    Start,
    /// End of the logical window.
    End,
    /// Another admitted zero-width assertion.
    Assert(Assertion),
}

impl Ast {
    /// Construct an ordered concatenation.
    #[must_use]
    pub fn concat(parts: impl IntoIterator<Item = Self>) -> Self {
        Self::Concat(parts.into_iter().collect())
    }

    /// Construct an ordered alternation.
    #[must_use]
    pub fn alt(parts: impl IntoIterator<Item = Self>) -> Self {
        Self::Alt(parts.into_iter().collect())
    }

    /// Construct a repetition.
    #[must_use]
    pub fn repeat(self, min: u32, max: Option<u32>, greed: Greed) -> Self {
        Self::Repeat {
            child: Box::new(self),
            min,
            max,
            greed,
        }
    }

    /// Construct an unnamed capture.
    #[must_use]
    pub fn capture(self, index: u32) -> Self {
        Self::Capture {
            index,
            name: None,
            child: Box::new(self),
        }
    }

    /// Construct a named capture.
    #[must_use]
    pub fn named(self, index: u32, name: impl Into<String>) -> Self {
        Self::Capture {
            index,
            name: Some(name.into()),
            child: Box::new(self),
        }
    }
}
