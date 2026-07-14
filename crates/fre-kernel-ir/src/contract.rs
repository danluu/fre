use core::fmt::Debug;

/// Stable output-contract tag encoded into a kernel cache key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OutputKind {
    /// Report only whether any match exists.
    Exists = 1,
    /// Report the selected match end offset.
    SelectedEnd = 2,
    /// Report the selected match span.
    Span = 3,
}

/// A half-open byte span in the original haystack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatchSpan {
    start: usize,
    end: usize,
}

impl MatchSpan {
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    #[must_use]
    pub const fn start(self) -> usize {
        self.start
    }

    #[must_use]
    pub const fn end(self) -> usize {
        self.end
    }
}

/// A checked half-open search window in the original haystack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchWindow {
    start: usize,
    end: usize,
}

impl SearchWindow {
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    #[must_use]
    pub const fn start(self) -> usize {
        self.start
    }

    #[must_use]
    pub const fn end(self) -> usize {
        self.end
    }

    pub(crate) fn validate(self, haystack_len: usize) -> bool {
        self.start <= self.end && self.end <= haystack_len
    }
}

mod sealed {
    pub trait Sealed {}
}

/// Compile-time marker for one exact output contract.
pub trait Operation: sealed::Sealed + Debug {
    /// Output returned by the portable oracle or a conforming native backend.
    type Output: Debug + Eq + PartialEq;

    /// Stable runtime tag checked while validating an untrusted raw program.
    const KIND: OutputKind;

    #[doc(hidden)]
    fn project(found: Option<MatchSpan>) -> Self::Output;
}

/// Type marker for existence-only search.
#[derive(Debug)]
pub struct Exists;

impl sealed::Sealed for Exists {}

impl Operation for Exists {
    type Output = bool;

    const KIND: OutputKind = OutputKind::Exists;

    fn project(found: Option<MatchSpan>) -> Self::Output {
        found.is_some()
    }
}

/// Type marker for the selected match end.
#[derive(Debug)]
pub struct SelectedEnd;

impl sealed::Sealed for SelectedEnd {}

impl Operation for SelectedEnd {
    type Output = Option<usize>;

    const KIND: OutputKind = OutputKind::SelectedEnd;

    fn project(found: Option<MatchSpan>) -> Self::Output {
        found.map(MatchSpan::end)
    }
}

/// Type marker for the selected match span.
#[derive(Debug)]
pub struct Span;

impl sealed::Sealed for Span {}

impl Operation for Span {
    type Output = Option<MatchSpan>;

    const KIND: OutputKind = OutputKind::Span;

    fn project(found: Option<MatchSpan>) -> Self::Output {
        found
    }
}
