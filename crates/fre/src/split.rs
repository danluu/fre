use crate::{
    AggregateExecutionError, AggregateExecutionReport, AggregateRunLimits, AggregateSpans,
    AggregateSpansRegex,
};

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
