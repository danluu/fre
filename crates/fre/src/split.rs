use crate::{
    AggregateExecutionError, AggregateExecutionReport, AggregateRunLimits, AggregateSpans,
    AggregateSpansRegex, PortableFindIterAccounting, PortableFindIterError, PortableFindIterLimits,
    PortableMatches, PortableRegex, SearchError, SearchSessionSetupAccounting,
};

impl PortableRegex {
    /// Lazily split a byte haystack around every non-overlapping match.
    ///
    /// Match selection retains the complete original haystack for assertion
    /// context and uses Rust-bytes empty-match progress. Iterator items are
    /// fallible so an execution limit cannot be mistaken for ordinary
    /// exhaustion after publishing a partial split sequence.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] if reusable K0 workspace construction exceeds
    /// `limits.session`. Per-search and whole-iterator failures are yielded as
    /// [`PortableFindIterError`] items.
    pub fn split<'r, 'h>(
        &'r self,
        haystack: &'h [u8],
        limits: PortableFindIterLimits,
    ) -> Result<PortableSplit<'r, 'h>, SearchError> {
        let matches = self.find_iter(haystack, limits)?;
        Ok(PortableSplit::new(haystack, Some(matches), None))
    }

    /// Lazily split a byte haystack into at most `limit` fields.
    ///
    /// A limit of zero yields no fields. A limit of one yields the complete
    /// haystack. Otherwise at most `limit - 1` matches are consumed as
    /// separators and the unsplit remainder is the final field. Limits below
    /// two do not construct a search session because they cannot inspect a
    /// match.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] if a required reusable K0 workspace exceeds
    /// `limits.session`. Per-search and whole-iterator failures are yielded as
    /// [`PortableFindIterError`] items.
    pub fn splitn<'r, 'h>(
        &'r self,
        haystack: &'h [u8],
        limit: usize,
        limits: PortableFindIterLimits,
    ) -> Result<PortableSplit<'r, 'h>, SearchError> {
        let matches = if limit > 1 {
            Some(self.find_iter(haystack, limits)?)
        } else {
            None
        };
        Ok(PortableSplit::new(haystack, matches, Some(limit)))
    }
}

/// Fallible, allocation-free split fields over contextual portable searches.
#[derive(Debug)]
pub struct PortableSplit<'r, 'h> {
    haystack: &'h [u8],
    matches: Option<PortableMatches<'r, 'h>>,
    cursor: usize,
    remaining: Option<usize>,
    finished: bool,
}

impl<'r, 'h> PortableSplit<'r, 'h> {
    fn new(
        haystack: &'h [u8],
        matches: Option<PortableMatches<'r, 'h>>,
        remaining: Option<usize>,
    ) -> Self {
        Self {
            haystack,
            matches,
            cursor: 0,
            remaining,
            finished: false,
        }
    }

    /// Exact complete-iteration counters through the most recent action.
    #[must_use]
    pub fn accounting(&self) -> PortableFindIterAccounting {
        self.matches.as_ref().map_or_else(
            PortableFindIterAccounting::default,
            PortableMatches::accounting,
        )
    }

    /// One-time K0 workspace setup facts, or `None` for native/no-search plans.
    #[must_use]
    pub fn workspace_setup_accounting(&self) -> Option<SearchSessionSetupAccounting> {
        self.matches
            .as_ref()
            .and_then(PortableMatches::workspace_setup_accounting)
    }

    fn finish_with_tail(&mut self) -> &'h [u8] {
        self.finished = true;
        self.remaining = Some(0);
        let field = &self.haystack[self.cursor..];
        self.cursor = self.haystack.len();
        field
    }
}

impl<'h> Iterator for PortableSplit<'_, 'h> {
    type Item = Result<&'h [u8], PortableFindIterError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished || self.remaining == Some(0) {
            self.finished = true;
            return None;
        }
        if self.remaining == Some(1) || self.matches.is_none() {
            return Some(Ok(self.finish_with_tail()));
        }

        match self.matches.as_mut().and_then(Iterator::next) {
            Some(Ok(separator)) => {
                debug_assert!(separator.start() >= self.cursor);
                debug_assert!(separator.end() <= self.haystack.len());
                let field = &self.haystack[self.cursor..separator.start()];
                self.cursor = separator.end();
                if let Some(remaining) = self.remaining.as_mut() {
                    *remaining = remaining.saturating_sub(1);
                }
                Some(Ok(field))
            }
            Some(Err(error)) => {
                self.finished = true;
                Some(Err(error))
            }
            None => Some(Ok(self.finish_with_tail())),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.finished {
            return (0, Some(0));
        }
        match self.remaining {
            Some(0) => (0, Some(0)),
            Some(remaining) => (1, Some(remaining)),
            None => (1, None),
        }
    }
}

impl core::iter::FusedIterator for PortableSplit<'_, '_> {}

impl AggregateSpansRegex {
    /// Split a byte haystack around every complete non-overlapping match.
    ///
    /// Separators at either edge and adjacent separators produce empty
    /// fields. Empty regex matches retain the byte-boundary progress of the
    /// Rust bytes profile, including inside valid UTF-8. Complete match
    /// selection is performed once under `limits`; advancing the returned
    /// iterator performs no allocation.
    pub fn split<'h>(
        &self,
        haystack: &'h [u8],
        limits: impl core::borrow::Borrow<AggregateRunLimits>,
    ) -> Result<AggregateSplit<'h>, AggregateExecutionError> {
        let spans = self.spans(haystack, limits)?;
        Ok(AggregateSplit::new(haystack, spans, None))
    }

    /// Split a byte haystack into at most `limit` fields.
    ///
    /// A limit of zero yields no fields. A limit of one yields the entire
    /// haystack. Otherwise at most `limit - 1` selected matches are consumed
    /// as separators and the unsplit remainder is the final field. The
    /// selector still admits the complete match sequence once so its existing
    /// resource certificate remains the sole execution boundary.
    pub fn splitn<'h>(
        &self,
        haystack: &'h [u8],
        limit: usize,
        limits: impl core::borrow::Borrow<AggregateRunLimits>,
    ) -> Result<AggregateSplit<'h>, AggregateExecutionError> {
        let spans = self.spans(haystack, limits)?;
        Ok(AggregateSplit::new(haystack, spans, Some(limit)))
    }
}

/// Allocation-free fields over one fully admitted immutable span sequence.
#[derive(Debug)]
pub struct AggregateSplit<'h> {
    haystack: &'h [u8],
    spans: AggregateSpans,
    next_span: usize,
    cursor: usize,
    remaining: usize,
}

impl<'h> AggregateSplit<'h> {
    fn new(haystack: &'h [u8], spans: AggregateSpans, limit: Option<usize>) -> Self {
        // A Vec-backed span sequence cannot contain `usize::MAX` elements, so
        // its complete split sequence always has room for the trailing field.
        let available = spans.len().saturating_add(1);
        let remaining = limit.map_or(available, |limit| limit.min(available));
        Self {
            haystack,
            spans,
            next_span: 0,
            cursor: 0,
            remaining,
        }
    }

    /// Report for the complete match selection performed before iteration.
    #[must_use]
    pub const fn selector_report(&self) -> &AggregateExecutionReport {
        self.spans.report()
    }

    /// Number of separators selected before the split limit is applied.
    #[must_use]
    pub fn selected_matches(&self) -> usize {
        self.spans.len()
    }
}

impl<'h> Iterator for AggregateSplit<'h> {
    type Item = &'h [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        if self.remaining == 1 {
            self.remaining = 0;
            self.next_span = self.spans.len();
            let field = &self.haystack[self.cursor..];
            self.cursor = self.haystack.len();
            return Some(field);
        }

        let separator = self.spans.span_at(self.next_span)?;
        debug_assert!(separator.start() >= self.cursor);
        debug_assert!(separator.end() <= self.haystack.len());
        let field = &self.haystack[self.cursor..separator.start()];
        self.cursor = separator.end();
        self.next_span = self.next_span.saturating_add(1);
        self.remaining = self.remaining.saturating_sub(1);
        Some(field)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for AggregateSplit<'_> {}
impl core::iter::FusedIterator for AggregateSplit<'_> {}
