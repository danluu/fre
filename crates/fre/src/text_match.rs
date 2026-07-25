//! Borrowed match values for the theorem-gated Rust text facade.

use core::fmt;

use crate::{
    Match, PortableFindIterAccounting, PortableFindIterError, PortableFindIterLimits,
    PortableTextMatches, PortableTextRegex, SearchAccounting, SearchError, SearchLimits,
    SearchSessionSetupAccounting,
};

/// A UTF-8 match that retains the exact original haystack it was selected from.
///
/// [`Match`] remains the compact offset-only value used by accounting-oriented
/// APIs. This companion preserves the pinned Rust text API's borrowed-match
/// contract, including direct access to the selected `str` and lossless
/// conversion to either that string or its original byte range.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct PortableTextMatch<'h> {
    haystack: &'h str,
    span: Match,
}

impl<'h> PortableTextMatch<'h> {
    fn new(haystack: &'h str, span: Match) -> Self {
        debug_assert!(
            haystack.get(span.range()).is_some(),
            "portable text match must retain UTF-8 boundary offsets"
        );
        Self { haystack, span }
    }

    /// Inclusive byte start in the original haystack.
    #[must_use]
    pub const fn start(&self) -> usize {
        self.span.start()
    }

    /// Exclusive byte end in the original haystack.
    #[must_use]
    pub const fn end(&self) -> usize {
        self.span.end()
    }

    /// Whether the selected match consumed no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.span.is_empty()
    }

    /// Number of matched bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.span.len()
    }

    /// Half-open byte range in the original haystack.
    #[must_use]
    pub const fn range(&self) -> core::ops::Range<usize> {
        self.span.range()
    }

    /// Borrow the exact selected UTF-8 substring.
    #[must_use]
    pub fn as_str(&self) -> &'h str {
        self.haystack
            .get(self.span.range())
            .expect("portable text matcher published non-boundary offsets")
    }
}

impl fmt::Debug for PortableTextMatch<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PortableTextMatch")
            .field("start", &self.start())
            .field("end", &self.end())
            .field("string", &self.as_str())
            .finish()
    }
}

impl<'h> From<PortableTextMatch<'h>> for &'h str {
    fn from(matched: PortableTextMatch<'h>) -> Self {
        matched.as_str()
    }
}

impl From<PortableTextMatch<'_>> for core::ops::Range<usize> {
    fn from(matched: PortableTextMatch<'_>) -> Self {
        matched.range()
    }
}

impl PortableTextRegex {
    /// Return the selected match while retaining the exact original haystack.
    ///
    /// This is the borrowed-text companion to [`Self::find`]. It performs the
    /// same search exactly once and returns identical execution accounting;
    /// constructing [`PortableTextMatch`] allocates nothing.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same resource contract as
    /// [`Self::find`].
    pub fn find_borrowed<'h>(
        &self,
        haystack: &'h str,
        limits: SearchLimits,
    ) -> Result<(Option<PortableTextMatch<'h>>, SearchAccounting), SearchError> {
        let (matched, accounting) = self.find(haystack, limits)?;
        Ok((
            matched.map(|span| PortableTextMatch::new(haystack, span)),
            accounting,
        ))
    }

    /// Return the selected match at or after `start` while retaining the
    /// complete original haystack.
    ///
    /// Interior UTF-8 offsets have exactly the normalization and assertion
    /// context of [`Self::find_at`]. The match value adds no allocation or
    /// search work.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same range and resource contract as
    /// [`Self::find_at`].
    pub fn find_at_borrowed<'h>(
        &self,
        haystack: &'h str,
        start: usize,
        limits: SearchLimits,
    ) -> Result<(Option<PortableTextMatch<'h>>, SearchAccounting), SearchError> {
        let (matched, accounting) = self.find_at(haystack, start, limits)?;
        Ok((
            matched.map(|span| PortableTextMatch::new(haystack, span)),
            accounting,
        ))
    }

    /// Iterate over non-overlapping matches that retain the original haystack.
    ///
    /// Selection, UTF-8 empty-match progress, workspace reuse, resource limits
    /// and accounting are identical to [`Self::find_iter`]. This wrapper only
    /// projects each selected offset span into [`PortableTextMatch`].
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same construction contract as
    /// [`Self::find_iter`]. Per-search failures remain visible as
    /// [`PortableFindIterError`] iterator items.
    pub fn find_iter_borrowed<'r, 'h>(
        &'r self,
        haystack: &'h str,
        limits: PortableFindIterLimits,
    ) -> Result<PortableTextBorrowedMatches<'r, 'h>, SearchError> {
        Ok(PortableTextBorrowedMatches {
            haystack,
            inner: self.find_iter(haystack, limits)?,
        })
    }
}

/// Fallible borrowed-value projection of [`PortableTextMatches`].
///
/// The complete search and resource ledger remains owned by the inner
/// iterator. This wrapper retains one `&str` and allocates no storage.
#[derive(Debug)]
pub struct PortableTextBorrowedMatches<'r, 'h> {
    haystack: &'h str,
    inner: PortableTextMatches<'r, 'h>,
}

impl PortableTextBorrowedMatches<'_, '_> {
    /// Exact counters accumulated through the most recent iterator action.
    #[must_use]
    pub const fn accounting(&self) -> PortableFindIterAccounting {
        self.inner.accounting()
    }

    /// One-time K0 workspace setup facts, or `None` for native plans.
    #[must_use]
    pub const fn workspace_setup_accounting(&self) -> Option<SearchSessionSetupAccounting> {
        self.inner.workspace_setup_accounting()
    }
}

impl<'h> Iterator for PortableTextBorrowedMatches<'_, 'h> {
    type Item = Result<PortableTextMatch<'h>, PortableFindIterError>;

    fn next(&mut self) -> Option<Self::Item> {
        let haystack = self.haystack;
        self.inner
            .next()
            .map(|result| result.map(|span| PortableTextMatch::new(haystack, span)))
    }
}

impl core::iter::FusedIterator for PortableTextBorrowedMatches<'_, '_> {}
