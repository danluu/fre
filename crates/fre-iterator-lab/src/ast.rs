//! The deliberately small, capture-free byte syntax used by the laboratory.

/// Greedy or lazy priority at a repetition choice.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Greed {
    /// Prefer another body iteration before exiting.
    Greedy,
    /// Prefer exiting before another body iteration.
    Lazy,
}

/// One ordered alternative inside a zero-or-more repetition body.
///
/// A consuming alternative advances exactly one byte. A zero-width
/// alternative exits that repetition attempt without taking its loop
/// backedge. Keeping these alternatives ordered is semantically important:
/// `(?:|a)*` and `(?:a|)*` select different spans on `a`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RepeatAtom {
    /// Succeed without consuming.
    Empty,
    /// Consume one exact byte.
    Byte(u8),
    /// Consume any one byte, including a newline or malformed UTF-8 byte.
    AnyByte,
    /// Assert the start of the original haystack.
    StartText,
    /// Assert the end of the original haystack.
    EndText,
}

/// Ordered capture-free byte regular-expression AST.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Ast {
    /// Succeed without consuming.
    Empty,
    /// Consume one exact byte.
    Byte(u8),
    /// Consume any one byte.
    AnyByte,
    /// Assert the start of the original haystack.
    StartText,
    /// Assert the end of the original haystack.
    EndText,
    /// Match every child from left to right. An empty vector is empty regex.
    Concat(Vec<Ast>),
    /// Try children in declaration order. An empty vector is rejected.
    Alt(Vec<Ast>),
    /// Repeat an ordered one-boundary body zero or more times.
    Repeat {
        /// Ordered body alternatives. An empty vector is rejected.
        body: Vec<RepeatAtom>,
        /// Whether body or exit has higher priority.
        greed: Greed,
    },
    /// Repeat an arbitrary capture-free child with checked bounds.
    ///
    /// This is the generalization track. Unlike [`Ast::Repeat`], its child may
    /// contain concatenation, alternation and nested repetitions. Unbounded
    /// nullable children are compiled with explicit per-iteration progress
    /// state instead of erasing their empty alternatives.
    Repetition {
        /// Repeated expression.
        child: Box<Ast>,
        /// Minimum number of iterations.
        min: u32,
        /// Inclusive maximum, or no maximum.
        max: Option<u32>,
        /// Priority between another optional iteration and exit.
        greed: Greed,
    },
}
