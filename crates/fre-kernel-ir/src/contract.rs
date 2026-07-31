use core::fmt::{self, Debug};

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

/// A half-open search-window request in the original haystack.
///
/// Safe executor boundaries validate this request before reading the
/// haystack. [`CheckedSearchWindow`] retains that proof for composed callers
/// that must cross more than one such boundary.
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

/// A half-open search window proven to belong to one borrowed haystack.
///
/// Private fields make the bounds proof non-forgeable in safe code. Keeping
/// the haystack borrow in the token also prevents a checked range from being
/// paired with a different or shorter slice at an executor boundary.
#[derive(Clone, Copy)]
pub struct CheckedSearchWindow<'haystack> {
    haystack: &'haystack [u8],
    window: SearchWindow,
    searched_bytes: usize,
}

impl<'haystack> CheckedSearchWindow<'haystack> {
    /// Validate one window and bind it to the exact borrowed haystack.
    #[must_use]
    #[inline]
    pub fn new(haystack: &'haystack [u8], window: SearchWindow) -> Option<Self> {
        let searched_bytes = window.end.checked_sub(window.start)?;
        if window.end > haystack.len() {
            return None;
        }
        Some(Self {
            haystack,
            window,
            searched_bytes,
        })
    }

    /// The haystack whose bounds were checked at construction.
    #[must_use]
    #[inline]
    pub const fn haystack(self) -> &'haystack [u8] {
        self.haystack
    }

    /// The validated half-open byte window.
    #[must_use]
    #[inline]
    pub const fn window(self) -> SearchWindow {
        self.window
    }

    /// Exact byte length of the validated window.
    #[must_use]
    #[inline]
    pub const fn searched_bytes(self) -> usize {
        self.searched_bytes
    }
}

impl fmt::Debug for CheckedSearchWindow<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CheckedSearchWindow")
            .field("haystack_len", &self.haystack.len())
            .field("window", &self.window)
            .field("searched_bytes", &self.searched_bytes)
            .finish()
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
