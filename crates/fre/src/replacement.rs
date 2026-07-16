use core::fmt;

use crate::{
    AggregateCacheIdentity, AggregateExecutionDetails, AggregateExecutionSource,
    AggregateRunLimits, AggregateSpans, AggregateSpansRegex,
};

/// A byte source accepted by the literal/no-expansion replacement facade.
///
/// Unlike Rust regex's general `Replacer` contract, implementations of this
/// trait are always copied literally: `$` has no special meaning. The standard
/// byte containers are supported alongside the UTF-8 string containers used
/// by upstream's replacement type-surface tests.
pub trait LiteralReplacer {
    /// Borrow the exact bytes to insert for every selected match.
    fn literal_bytes(&self) -> &[u8];
}

impl LiteralReplacer for [u8] {
    fn literal_bytes(&self) -> &[u8] {
        self
    }
}

impl<const N: usize> LiteralReplacer for [u8; N] {
    fn literal_bytes(&self) -> &[u8] {
        self
    }
}

impl LiteralReplacer for Vec<u8> {
    fn literal_bytes(&self) -> &[u8] {
        self
    }
}

impl LiteralReplacer for str {
    fn literal_bytes(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl LiteralReplacer for String {
    fn literal_bytes(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl LiteralReplacer for std::borrow::Cow<'_, [u8]> {
    fn literal_bytes(&self) -> &[u8] {
        self.as_ref()
    }
}

impl LiteralReplacer for std::borrow::Cow<'_, str> {
    fn literal_bytes(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<T: LiteralReplacer + ?Sized> LiteralReplacer for &T {
    fn literal_bytes(&self) -> &[u8] {
        (*self).literal_bytes()
    }
}

/// Per-call policy for literal/no-expansion replacement.
///
/// The aggregate limits bound complete match selection. `max_output_bytes`
/// separately bounds the one output allocation before any bytes are copied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiteralReplacementLimits {
    /// Complete selected-span execution policy.
    pub aggregate: AggregateRunLimits,
    /// Maximum length of the replaced haystack.
    pub max_output_bytes: usize,
}

impl Default for LiteralReplacementLimits {
    fn default() -> Self {
        Self {
            aggregate: AggregateRunLimits::default(),
            max_output_bytes: 67_108_864,
        }
    }
}

/// Complete semantic and resource identity for one replacement invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiteralReplacementIdentity {
    /// Identity of the complete-span selector used without fallback.
    pub selector: AggregateCacheIdentity,
    /// Rust-compatible `replacen` limit. Zero means replace all matches.
    pub limit: usize,
    /// Number of literal bytes inserted for every selected match.
    pub replacement_bytes: usize,
    /// Output-allocation ceiling applied after exact size preflight.
    pub max_output_bytes: usize,
}

/// Exact work and byte counts for a completed replacement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiteralReplacementAccounting {
    /// Complete matches selected before the `replacen` bound is applied.
    pub selected_matches: usize,
    /// Matches actually replaced.
    pub replacements: usize,
    /// Selected spans visited by the size and copy passes together.
    pub span_visits: usize,
    /// Original haystack bytes copied from unmatched regions.
    pub haystack_bytes_copied: usize,
    /// Literal replacement bytes copied into the output.
    pub replacement_bytes_copied: usize,
    /// Exact final output length.
    pub output_bytes: usize,
}

/// Successful replacement evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiteralReplacementReport {
    /// Complete invocation identity, including all resource limits.
    pub identity: LiteralReplacementIdentity,
    /// Selected-plan counters and certificate from complete span execution.
    pub selector_details: AggregateExecutionDetails,
    /// Exact replacement-loop accounting.
    pub accounting: LiteralReplacementAccounting,
}

/// Owned result of a bounded literal replacement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiteralReplacementResult {
    bytes: Vec<u8>,
    report: LiteralReplacementReport,
}

impl LiteralReplacementResult {
    /// Borrow the replaced bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the result and return the replaced bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Auditable selected-plan and replacement accounting.
    #[must_use]
    pub const fn report(&self) -> &LiteralReplacementReport {
        &self.report
    }
}

/// Typed failure after replacement semantics and limits are fixed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiteralReplacementError {
    /// Complete attempted invocation identity.
    pub identity: Box<LiteralReplacementIdentity>,
    /// Selected-plan, size, quota, allocation or invariant failure.
    pub source: LiteralReplacementErrorSource,
}

impl fmt::Display for LiteralReplacementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "literal replacement with replacen limit {} failed: {}",
            self.identity.limit, self.source
        )
    }
}

impl std::error::Error for LiteralReplacementError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.source {
            LiteralReplacementErrorSource::Selector(source) => Some(source),
            LiteralReplacementErrorSource::OutputSizeOverflow
            | LiteralReplacementErrorSource::OutputBytesLimit { .. }
            | LiteralReplacementErrorSource::AllocationFailed { .. }
            | LiteralReplacementErrorSource::InternalInvariant(_) => None,
        }
    }
}

/// Precise source of a replacement failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LiteralReplacementErrorSource {
    /// Complete span selection refused under its fixed plan and limits.
    Selector(AggregateExecutionSource),
    /// Exact output-size or work accounting overflowed `usize`.
    OutputSizeOverflow,
    /// Exact output length exceeded the caller's ceiling.
    OutputBytesLimit { needed: usize, limit: usize },
    /// The single preflighted output allocation failed.
    AllocationFailed { requested: usize },
    /// A fully admitted selector span violated the facade contract.
    InternalInvariant(&'static str),
}

impl fmt::Display for LiteralReplacementErrorSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Selector(source) => source.fmt(formatter),
            Self::OutputSizeOverflow => formatter.write_str("exact output size overflowed usize"),
            Self::OutputBytesLimit { needed, limit } => write!(
                formatter,
                "output needs {needed} bytes, exceeding the {limit}-byte limit"
            ),
            Self::AllocationFailed { requested } => {
                write!(formatter, "failed to allocate {requested} output bytes")
            }
            Self::InternalInvariant(detail) => {
                write!(formatter, "replacement invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for LiteralReplacementErrorSource {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Selector(source) => Some(source),
            Self::OutputSizeOverflow
            | Self::OutputBytesLimit { .. }
            | Self::AllocationFailed { .. }
            | Self::InternalInvariant(_) => None,
        }
    }
}

impl AggregateSpansRegex {
    /// Replace the first match with literal bytes.
    ///
    /// The replacement is equivalent to `regex::bytes::NoExpand`: dollar
    /// syntax is copied verbatim and no capture value is observed.
    pub fn replace_literal<R: LiteralReplacer>(
        &self,
        haystack: &[u8],
        replacement: R,
        limits: impl core::borrow::Borrow<LiteralReplacementLimits>,
    ) -> Result<LiteralReplacementResult, LiteralReplacementError> {
        self.replacen_literal(haystack, 1, replacement, limits)
    }

    /// Replace every non-overlapping match with literal bytes.
    ///
    /// Empty-match progress and absolute anchor context come from the same
    /// complete-span selector used by the aggregate facade.
    pub fn replace_all_literal<R: LiteralReplacer>(
        &self,
        haystack: &[u8],
        replacement: R,
        limits: impl core::borrow::Borrow<LiteralReplacementLimits>,
    ) -> Result<LiteralReplacementResult, LiteralReplacementError> {
        self.replacen_literal(haystack, 0, replacement, limits)
    }

    /// Replace at most `limit` complete non-overlapping matches. A zero limit
    /// replaces all matches, matching Rust regex's `replacen` contract.
    ///
    /// This is a bounded semantic floor rather than a capture-template API.
    /// It selects all spans once, computes the exact output length without
    /// allocation, enforces the caller's byte ceiling, reserves once and then
    /// copies the unchanged gaps and literal replacement.
    pub fn replacen_literal<R: LiteralReplacer>(
        &self,
        haystack: &[u8],
        limit: usize,
        replacement: R,
        limits: impl core::borrow::Borrow<LiteralReplacementLimits>,
    ) -> Result<LiteralReplacementResult, LiteralReplacementError> {
        let replacement = replacement.literal_bytes();
        let limits = *limits.borrow();
        let spans =
            self.spans(haystack, limits.aggregate)
                .map_err(|error| LiteralReplacementError {
                    identity: Box::new(LiteralReplacementIdentity {
                        selector: *error.identity,
                        limit,
                        replacement_bytes: replacement.len(),
                        max_output_bytes: limits.max_output_bytes,
                    }),
                    source: LiteralReplacementErrorSource::Selector(error.source),
                })?;
        let selector_report = spans.report().clone();
        let identity = LiteralReplacementIdentity {
            selector: selector_report.identity,
            limit,
            replacement_bytes: replacement.len(),
            max_output_bytes: limits.max_output_bytes,
        };
        let accounting = replacement_preflight(&spans, haystack.len(), replacement.len(), limit)
            .map_err(|source| replacement_error(&identity, source))?;
        if accounting.output_bytes > limits.max_output_bytes {
            return Err(replacement_error(
                &identity,
                LiteralReplacementErrorSource::OutputBytesLimit {
                    needed: accounting.output_bytes,
                    limit: limits.max_output_bytes,
                },
            ));
        }

        let mut output = Vec::new();
        output
            .try_reserve_exact(accounting.output_bytes)
            .map_err(|_| {
                replacement_error(
                    &identity,
                    LiteralReplacementErrorSource::AllocationFailed {
                        requested: accounting.output_bytes,
                    },
                )
            })?;
        let mut cursor = 0_usize;
        for matched in spans.iter().take(accounting.replacements) {
            let gap = haystack.get(cursor..matched.start).ok_or_else(|| {
                replacement_error(
                    &identity,
                    LiteralReplacementErrorSource::InternalInvariant(
                        "selector spans are not ordered within the haystack",
                    ),
                )
            })?;
            output.extend_from_slice(gap);
            output.extend_from_slice(replacement);
            cursor = matched.end;
        }
        let tail = haystack.get(cursor..).ok_or_else(|| {
            replacement_error(
                &identity,
                LiteralReplacementErrorSource::InternalInvariant(
                    "selector span ended outside the haystack",
                ),
            )
        })?;
        output.extend_from_slice(tail);
        if output.len() != accounting.output_bytes {
            return Err(replacement_error(
                &identity,
                LiteralReplacementErrorSource::InternalInvariant(
                    "preflight and copied output lengths differ",
                ),
            ));
        }
        Ok(LiteralReplacementResult {
            bytes: output,
            report: LiteralReplacementReport {
                identity,
                selector_details: selector_report.details,
                accounting,
            },
        })
    }
}

fn replacement_preflight(
    spans: &AggregateSpans,
    haystack_len: usize,
    replacement_len: usize,
    limit: usize,
) -> Result<LiteralReplacementAccounting, LiteralReplacementErrorSource> {
    let mut replacements = 0_usize;
    let mut cursor = 0_usize;
    let mut haystack_bytes_copied = 0_usize;
    let replacement_count = if limit == 0 { usize::MAX } else { limit };
    for matched in spans.iter().take(replacement_count) {
        if matched.start < cursor || matched.end < matched.start || matched.end > haystack_len {
            return Err(LiteralReplacementErrorSource::InternalInvariant(
                "selector spans are not ordered within the haystack",
            ));
        }
        let gap_bytes = matched.start.checked_sub(cursor).ok_or(
            LiteralReplacementErrorSource::InternalInvariant(
                "selector spans are not ordered within the haystack",
            ),
        )?;
        haystack_bytes_copied = haystack_bytes_copied
            .checked_add(gap_bytes)
            .ok_or(LiteralReplacementErrorSource::OutputSizeOverflow)?;
        cursor = matched.end;
        replacements = replacements
            .checked_add(1)
            .ok_or(LiteralReplacementErrorSource::OutputSizeOverflow)?;
    }
    let tail_bytes = haystack_len.checked_sub(cursor).ok_or(
        LiteralReplacementErrorSource::InternalInvariant(
            "selector span ended outside the haystack",
        ),
    )?;
    haystack_bytes_copied = haystack_bytes_copied
        .checked_add(tail_bytes)
        .ok_or(LiteralReplacementErrorSource::OutputSizeOverflow)?;
    let replacement_bytes_copied = replacement_len
        .checked_mul(replacements)
        .ok_or(LiteralReplacementErrorSource::OutputSizeOverflow)?;
    let output_bytes = haystack_bytes_copied
        .checked_add(replacement_bytes_copied)
        .ok_or(LiteralReplacementErrorSource::OutputSizeOverflow)?;
    let span_visits = replacements
        .checked_mul(2)
        .ok_or(LiteralReplacementErrorSource::OutputSizeOverflow)?;
    Ok(LiteralReplacementAccounting {
        selected_matches: spans.len(),
        replacements,
        span_visits,
        haystack_bytes_copied,
        replacement_bytes_copied,
        output_bytes,
    })
}

fn replacement_error(
    identity: &LiteralReplacementIdentity,
    source: LiteralReplacementErrorSource,
) -> LiteralReplacementError {
    LiteralReplacementError {
        identity: Box::new(identity.clone()),
        source,
    }
}
