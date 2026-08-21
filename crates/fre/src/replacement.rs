use core::fmt;
use std::borrow::Cow;

use crate::{
    AggregateCacheIdentity, AggregateExecutionDetails, AggregateExecutionSource,
    AggregateRunLimits, AggregateSpans, AggregateSpansRegex, Match, PortableFindIterError,
    PortableFindIterLimits, PortableFindIterRunLimits, PortableRegex, PortableSearchSession,
    SearchError,
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

/// Forces replacement bytes to be copied literally without capture expansion.
///
/// This is the bounded FRE counterpart of `regex::bytes::NoExpand`. It can be
/// passed to the literal replacement methods even when the replacement
/// contains `$` syntax that a capture-aware API would otherwise expand.
#[derive(Clone, Debug)]
pub struct NoExpand<'s>(pub &'s [u8]);

impl LiteralReplacer for NoExpand<'_> {
    fn literal_bytes(&self) -> &[u8] {
        self.0
    }
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

/// Output-allocation policy for one value-only literal replacement.
///
/// Search setup, per-search work and the iterator call cap remain governed by
/// [`PortableFindIterLimits`] or [`PortableFindIterRunLimits`]. These two
/// ceilings cover only the logical replacement result and, when a match is
/// replaced, its FRE-owned output allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValueReplacementOutputLimits {
    /// Maximum logical length of the returned byte string.
    ///
    /// This applies to a borrowed no-match result as well as an owned replaced
    /// result, even though the borrowed result retains no output allocation.
    pub max_output_bytes: usize,
    /// Maximum allocator-observed retained capacity of an owned result.
    pub max_output_capacity_bytes: usize,
}

impl Default for ValueReplacementOutputLimits {
    fn default() -> Self {
        Self {
            max_output_bytes: 67_108_864,
            max_output_capacity_bytes: 67_108_864,
        }
    }
}

/// Typed refusal from first-match value-only literal replacement.
///
/// The value route intentionally exposes no aggregate selector receipt. Setup
/// and iteration failures are preserved losslessly, while every output
/// failure occurs before replacement bytes are published.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PortableValueReplacementError {
    /// Fresh value-iterator session construction was refused.
    Setup(SearchError),
    /// The first contextual iterator search was refused.
    Iteration(PortableFindIterError),
    /// Exact result-length arithmetic overflowed `usize`.
    OutputSizeOverflow,
    /// The exact logical result length exceeded its ceiling.
    OutputBytesLimit { needed: usize, limit: usize },
    /// The allocator-observed retained output capacity exceeded its ceiling.
    OutputCapacityBytesLimit { needed: usize, limit: usize },
    /// The single exact output reservation failed.
    AllocationFailed { requested: usize },
    /// A selected whole-match span violated the value-iterator contract.
    InternalInvariant(&'static str),
}

impl fmt::Display for PortableValueReplacementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Setup(error) => {
                write!(formatter, "value replacement session setup failed: {error}")
            }
            Self::Iteration(error) => {
                write!(formatter, "value replacement search failed: {error}")
            }
            Self::OutputSizeOverflow => {
                formatter.write_str("value replacement output size overflowed usize")
            }
            Self::OutputBytesLimit { needed, limit } => write!(
                formatter,
                "value replacement output needs {needed} bytes, exceeding the {limit}-byte limit"
            ),
            Self::OutputCapacityBytesLimit { needed, limit } => write!(
                formatter,
                "value replacement output capacity is {needed} bytes, exceeding the {limit}-byte capacity limit"
            ),
            Self::AllocationFailed { requested } => write!(
                formatter,
                "failed to allocate {requested} value replacement output bytes"
            ),
            Self::InternalInvariant(detail) => {
                write!(formatter, "value replacement invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for PortableValueReplacementError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Setup(error) => Some(error),
            Self::Iteration(error) => Some(error),
            Self::OutputSizeOverflow
            | Self::OutputBytesLimit { .. }
            | Self::OutputCapacityBytesLimit { .. }
            | Self::AllocationFailed { .. }
            | Self::InternalInvariant(_) => None,
        }
    }
}

/// Per-call resource policy for expanding one capture replacement template.
///
/// Expansion first computes the exact output length and charged work without
/// allocating. It then reserves the complete output once and performs a
/// second parse/copy pass under the same pinned replacement grammar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureExpansionLimits {
    /// Maximum number of bytes in the expanded template.
    pub max_output_bytes: usize,
    /// Maximum charged template-scan, name-lookup and copy work.
    pub max_work: usize,
}

impl Default for CaptureExpansionLimits {
    fn default() -> Self {
        Self {
            max_output_bytes: 67_108_864,
            max_work: 268_435_456,
        }
    }
}

/// Exact deterministic counters for one capture-template expansion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureExpansionAccounting {
    /// Conservative parser scan work charged across preflight and copy passes.
    ///
    /// This is a linear upper bound after caching the next closing brace and
    /// the first invalid UTF-8 byte for malformed braced references.
    pub template_bytes_scanned: usize,
    /// Capture references parsed across one semantic pass.
    pub capture_references: usize,
    /// References whose indexed slot participated in this match.
    pub participating_references: usize,
    /// Capture-name slots examined across preflight and copy passes.
    pub name_slots_examined: usize,
    /// Capture-name comparison work charged across both passes.
    pub name_bytes_compared: usize,
    /// Literal template bytes copied after applying `$$` escaping.
    pub literal_bytes_copied: usize,
    /// Participating capture bytes copied.
    pub capture_bytes_copied: usize,
    /// Exact final output length.
    pub output_bytes: usize,
    /// Total charged scan, lookup and byte-copy work.
    pub work: usize,
}

/// Complete identity and counters for one capture-template expansion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureExpansionReport {
    /// Number of capture slots required by the compiled pattern.
    pub capture_slots: usize,
    /// Original replacement-template byte length.
    pub replacement_bytes: usize,
    /// Exact resource policy applied before allocation.
    pub limits: CaptureExpansionLimits,
    /// Deterministic semantic and resource counters.
    pub accounting: CaptureExpansionAccounting,
}

/// Owned result of one bounded capture-template expansion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureExpansionResult {
    bytes: Vec<u8>,
    report: CaptureExpansionReport,
}

impl CaptureExpansionResult {
    /// Borrow the expanded bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the result and return the expanded bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Exact expansion identity and accounting.
    #[must_use]
    pub const fn report(&self) -> &CaptureExpansionReport {
        &self.report
    }
}

/// Typed refusal from bounded capture-template expansion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureExpansionError {
    /// The supplied capture record did not match the compiled pattern shape.
    CaptureSlotCount { expected: usize, actual: usize },
    /// Exact output-size arithmetic overflowed `usize`.
    OutputSizeOverflow,
    /// Exact charged-work arithmetic overflowed `usize`.
    WorkOverflow,
    /// Exact expanded bytes exceed the caller's output ceiling.
    OutputBytesLimit { needed: usize, limit: usize },
    /// Exact charged work exceeds the caller's work ceiling.
    WorkLimit { needed: usize, limit: usize },
    /// The single preflighted output reservation failed.
    AllocationFailed { requested: usize },
    /// Preflight and copy passes disagreed despite sharing one parser.
    InternalInvariant(&'static str),
}

impl fmt::Display for CaptureExpansionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CaptureSlotCount { expected, actual } => write!(
                formatter,
                "capture template needs {expected} capture slots, got {actual}"
            ),
            Self::OutputSizeOverflow => {
                formatter.write_str("capture-template output size overflowed usize")
            }
            Self::WorkOverflow => {
                formatter.write_str("capture-template charged work overflowed usize")
            }
            Self::OutputBytesLimit { needed, limit } => write!(
                formatter,
                "capture-template output needs {needed} bytes, exceeding the {limit}-byte limit"
            ),
            Self::WorkLimit { needed, limit } => write!(
                formatter,
                "capture-template expansion needs {needed} work, exceeding the {limit}-work limit"
            ),
            Self::AllocationFailed { requested } => write!(
                formatter,
                "failed to allocate {requested} capture-template output bytes"
            ),
            Self::InternalInvariant(detail) => {
                write!(formatter, "capture-template invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for CaptureExpansionError {}

/// Per-call policy for literal/no-expansion replacement.
///
/// The aggregate limits bound complete match selection. Logical output length
/// and observed retained capacity have separate ceilings so allocator
/// rounding cannot hide behind an exact-size preflight.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiteralReplacementLimits {
    /// Complete selected-span execution policy.
    pub aggregate: AggregateRunLimits,
    /// Maximum length of the replaced haystack.
    pub max_output_bytes: usize,
    /// Maximum observed retained capacity of the replaced haystack.
    pub max_output_capacity_bytes: usize,
}

impl Default for LiteralReplacementLimits {
    fn default() -> Self {
        Self {
            aggregate: AggregateRunLimits::default(),
            max_output_bytes: 67_108_864,
            max_output_capacity_bytes: 67_108_864,
        }
    }
}

/// Functional replacement uses the same complete-span and output-byte policy
/// as literal replacement.
pub type FunctionalReplacementLimits = LiteralReplacementLimits;

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
    /// Observed output-capacity ceiling applied before copying.
    pub max_output_capacity_bytes: usize,
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
    /// Observed retained capacity of the owned output allocation.
    pub output_capacity_bytes: usize,
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

    /// Observed retained capacity of the owned replacement output.
    #[must_use]
    pub fn capacity_bytes(&self) -> usize {
        self.bytes.capacity()
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
            | LiteralReplacementErrorSource::OutputCapacityBytesLimit { .. }
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
    /// Observed retained output capacity exceeded the caller's ceiling.
    OutputCapacityBytesLimit { needed: usize, limit: usize },
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
            Self::OutputCapacityBytesLimit { needed, limit } => write!(
                formatter,
                "output capacity is {needed} bytes, exceeding the {limit}-byte capacity limit"
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
            | Self::OutputCapacityBytesLimit { .. }
            | Self::AllocationFailed { .. }
            | Self::InternalInvariant(_) => None,
        }
    }
}

/// Complete semantic and resource identity for one functional whole-match
/// replacement invocation.
///
/// The callback is deliberately not part of this identity: it is caller code
/// executed synchronously and is never cached or persisted by FRE. The fixed
/// identity covers the selector, replacement count and every FRE-owned output
/// resource bound.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FunctionalReplacementIdentity {
    /// Identity of the complete-span selector used without fallback.
    pub selector: AggregateCacheIdentity,
    /// Rust-compatible `replacen` limit. Zero means replace all matches.
    pub limit: usize,
    /// Output-allocation ceiling checked before every FRE-owned growth.
    pub max_output_bytes: usize,
}

/// Exact deterministic counters for one functional replacement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FunctionalReplacementAccounting {
    /// Complete matches selected before the `replacen` bound is applied.
    pub selected_matches: usize,
    /// Matches actually replaced and callbacks invoked.
    pub replacements: usize,
    /// Selected spans visited by the single callback/copy pass.
    pub span_visits: usize,
    /// Original haystack bytes copied from unmatched regions.
    pub haystack_bytes_copied: usize,
    /// Callback-produced bytes copied into the output.
    pub replacement_bytes_copied: usize,
    /// Exact final output length.
    pub output_bytes: usize,
}

/// Successful functional replacement evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FunctionalReplacementReport {
    /// Complete invocation identity, including all FRE-owned resource limits.
    pub identity: FunctionalReplacementIdentity,
    /// Selected-plan counters and certificate from complete span execution.
    pub selector_details: AggregateExecutionDetails,
    /// Exact callback and copy-loop accounting.
    pub accounting: FunctionalReplacementAccounting,
}

/// Owned result of one bounded functional replacement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FunctionalReplacementResult {
    bytes: Vec<u8>,
    report: FunctionalReplacementReport,
}

impl FunctionalReplacementResult {
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

    /// Auditable selected-plan and functional replacement accounting.
    #[must_use]
    pub const fn report(&self) -> &FunctionalReplacementReport {
        &self.report
    }
}

/// Typed failure after functional replacement semantics and limits are fixed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FunctionalReplacementError {
    /// Complete attempted invocation identity.
    pub identity: Box<FunctionalReplacementIdentity>,
    /// Selected-plan, size, quota, allocation or invariant failure.
    pub source: FunctionalReplacementErrorSource,
}

impl fmt::Display for FunctionalReplacementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "functional replacement with replacen limit {} failed: {}",
            self.identity.limit, self.source
        )
    }
}

impl std::error::Error for FunctionalReplacementError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.source {
            FunctionalReplacementErrorSource::Selector(source) => Some(source),
            FunctionalReplacementErrorSource::OutputSizeOverflow
            | FunctionalReplacementErrorSource::OutputBytesLimit { .. }
            | FunctionalReplacementErrorSource::AllocationFailed { .. }
            | FunctionalReplacementErrorSource::InternalInvariant(_) => None,
        }
    }
}

/// Precise source of a functional replacement failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FunctionalReplacementErrorSource {
    /// Complete span selection refused under its fixed plan and limits.
    Selector(AggregateExecutionSource),
    /// Exact output-size accounting overflowed `usize`.
    OutputSizeOverflow,
    /// Exact output length exceeded the caller's ceiling.
    OutputBytesLimit { needed: usize, limit: usize },
    /// A checked incremental output reservation failed.
    AllocationFailed { requested: usize },
    /// A fully admitted selector span violated the facade contract.
    InternalInvariant(&'static str),
}

impl fmt::Display for FunctionalReplacementErrorSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Selector(source) => source.fmt(formatter),
            Self::OutputSizeOverflow => formatter.write_str("exact output size overflowed usize"),
            Self::OutputBytesLimit { needed, limit } => write!(
                formatter,
                "output needs {needed} bytes, exceeding the {limit}-byte limit"
            ),
            Self::AllocationFailed { requested } => {
                write!(formatter, "failed to grow output to {requested} bytes")
            }
            Self::InternalInvariant(detail) => {
                write!(
                    formatter,
                    "functional replacement invariant failed: {detail}"
                )
            }
        }
    }
}

impl std::error::Error for FunctionalReplacementErrorSource {
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

impl PortableRegex {
    /// Replace the first selected byte match with literal bytes through a
    /// value-only selected-span route.
    ///
    /// `$` has no special meaning: this is the bounded counterpart of pinned
    /// Rust bytes replacement with [`NoExpand`]. A no-match result borrows the
    /// original haystack and retains no output allocation. A matched result is
    /// preflighted exactly, reserved once and returned owned.
    ///
    /// This method intentionally exposes no aggregate selector receipt. Use
    /// [`AggregateSpansRegex::replace_literal`] when complete match selection
    /// and its execution accounting are required.
    ///
    /// # Errors
    ///
    /// Exact literals, fixed-predicate words, pure byte-class repetitions and
    /// bounded byte-class sequences execute their first selected-span search
    /// directly; other plans retain the value iterator and its reusable-session
    /// setup.
    /// Returns a typed setup, first-search, output-bound, allocation or
    /// invariant refusal. The iterator call cap is consumed only for the first
    /// hit or miss; a successful hit never probes for a later match.
    #[inline]
    pub fn replace_literal_value<'h, R: LiteralReplacer>(
        &self,
        haystack: &'h [u8],
        replacement: R,
        iterator_limits: PortableFindIterLimits,
        output_limits: ValueReplacementOutputLimits,
    ) -> Result<Cow<'h, [u8]>, PortableValueReplacementError> {
        let replacement = replacement.literal_bytes();
        let plan = self.build_report().plan;
        if matches!(
            plan,
            crate::PlanKind::PureByteClassRepeat | crate::PlanKind::BoundedByteClassSequence
        ) {
            return replace_direct_literal_value(
                self,
                haystack,
                replacement,
                iterator_limits,
                output_limits,
            );
        }
        if matches!(
            plan,
            crate::PlanKind::ExactLiteral | crate::PlanKind::FixedPredicateWord64
        ) {
            return replace_direct_literal_value(
                self,
                haystack,
                replacement,
                iterator_limits,
                output_limits,
            );
        }

        let mut matches = self
            .find_iter_value(haystack, iterator_limits)
            .map_err(PortableValueReplacementError::Setup)?;
        let first = matches.next();
        drop(matches);
        replace_first_literal_value(haystack, replacement, first, output_limits)
    }

    /// Expand one pinned Rust bytes replacement template from capture values.
    ///
    /// `captures` is in capture-index order and must contain exactly
    /// [`PortableRegex::captures_len`] slots. `None` represents a capture that
    /// did not participate. `$N`, `$name`, `${ref}` and `$$` follow the pinned
    /// `regex` 1.12.4 bytes grammar; unknown, out-of-range and nonparticipating
    /// references expand to the empty byte string.
    ///
    /// This method deliberately performs no regex search. It is the bounded
    /// interpolation floor shared by future capture-preserving replacement
    /// operations and accepts capture values materialized by such an
    /// operation.
    ///
    /// # Errors
    ///
    /// Returns a typed slot-shape, arithmetic, work, output or allocation
    /// refusal. Work and output limits are checked before output allocation.
    pub fn expand_capture_template(
        &self,
        captures: &[Option<&[u8]>],
        replacement: &[u8],
        limits: CaptureExpansionLimits,
    ) -> Result<CaptureExpansionResult, CaptureExpansionError> {
        if captures.len() != self.captures_len() {
            return Err(CaptureExpansionError::CaptureSlotCount {
                expected: self.captures_len(),
                actual: captures.len(),
            });
        }
        let accounting =
            capture_expansion_preflight(&self.capture_names, captures, replacement, limits)?;

        let mut output = Vec::new();
        output
            .try_reserve_exact(accounting.output_bytes)
            .map_err(|_| CaptureExpansionError::AllocationFailed {
                requested: accounting.output_bytes,
            })?;
        for piece in CaptureTemplateParser::new(replacement) {
            match piece {
                CaptureTemplatePiece::Literal(bytes) => output.extend_from_slice(bytes),
                CaptureTemplatePiece::Capture(reference) => {
                    let index = capture_reference_index(&self.capture_names, reference);
                    if let Some(bytes) = index
                        .and_then(|index| captures.get(index))
                        .and_then(|capture| *capture)
                    {
                        output.extend_from_slice(bytes);
                    }
                }
            }
        }
        if output.len() != accounting.output_bytes {
            return Err(CaptureExpansionError::InternalInvariant(
                "preflight and copied output lengths differ",
            ));
        }
        Ok(CaptureExpansionResult {
            bytes: output,
            report: CaptureExpansionReport {
                capture_slots: captures.len(),
                replacement_bytes: replacement.len(),
                limits,
                accounting,
            },
        })
    }
}

#[inline(always)]
fn replace_direct_literal_value<'h>(
    regex: &PortableRegex,
    haystack: &'h [u8],
    replacement: &[u8],
    iterator_limits: PortableFindIterLimits,
    output_limits: ValueReplacementOutputLimits,
) -> Result<Cow<'h, [u8]>, PortableValueReplacementError> {
    if iterator_limits.max_search_calls == 0 {
        return Err(PortableValueReplacementError::Iteration(
            PortableFindIterError::SearchCallLimit {
                needed: 1,
                limit: 0,
            },
        ));
    }
    let first = match regex.find_value(haystack, iterator_limits.search) {
        Ok(first) => first,
        Err(error) => {
            return Err(PortableValueReplacementError::Iteration(
                PortableFindIterError::Search(error),
            ));
        }
    };
    replace_selected_literal_value(haystack, replacement, first, output_limits)
}

impl PortableSearchSession<'_> {
    /// Replace the first selected byte match with literal bytes while reusing
    /// this session's already allocated search workspace.
    ///
    /// Semantics and output limits are identical to
    /// [`PortableRegex::replace_literal_value`]. Constructing the value
    /// iterator allocates no search workspace; only a matched owned result may
    /// retain a new output allocation.
    ///
    /// # Errors
    ///
    /// Returns a typed first-search, output-bound, allocation or invariant
    /// refusal. Search failure leaves the session reusable under its existing
    /// per-search transaction contract.
    pub fn replace_literal_value<'h, R: LiteralReplacer>(
        &mut self,
        haystack: &'h [u8],
        replacement: R,
        iterator_limits: PortableFindIterRunLimits,
        output_limits: ValueReplacementOutputLimits,
    ) -> Result<Cow<'h, [u8]>, PortableValueReplacementError> {
        let replacement = replacement.literal_bytes();
        let first = {
            let mut matches = self.find_iter_value(haystack, iterator_limits);
            matches.next()
        };
        replace_first_literal_value(haystack, replacement, first, output_limits)
    }
}

fn replace_first_literal_value<'h>(
    haystack: &'h [u8],
    replacement: &[u8],
    first: Option<Result<Match, PortableFindIterError>>,
    limits: ValueReplacementOutputLimits,
) -> Result<Cow<'h, [u8]>, PortableValueReplacementError> {
    let matched = first
        .transpose()
        .map_err(PortableValueReplacementError::Iteration)?;
    replace_selected_literal_value(haystack, replacement, matched, limits)
}

#[inline(always)]
fn replace_selected_literal_value<'h>(
    haystack: &'h [u8],
    replacement: &[u8],
    matched: Option<Match>,
    limits: ValueReplacementOutputLimits,
) -> Result<Cow<'h, [u8]>, PortableValueReplacementError> {
    let Some(matched) = matched else {
        enforce_value_replacement_output_bytes(haystack.len(), limits.max_output_bytes)?;
        return Ok(Cow::Borrowed(haystack));
    };
    if matched.start() > matched.end() || matched.end() > haystack.len() {
        return Err(PortableValueReplacementError::InternalInvariant(
            "selected span is not ordered within the haystack",
        ));
    }
    let retained_haystack_bytes = haystack
        .len()
        .checked_sub(matched.len())
        .ok_or(PortableValueReplacementError::OutputSizeOverflow)?;
    let output_bytes = retained_haystack_bytes
        .checked_add(replacement.len())
        .ok_or(PortableValueReplacementError::OutputSizeOverflow)?;
    enforce_value_replacement_output_bytes(output_bytes, limits.max_output_bytes)?;

    let mut output = Vec::new();
    output.try_reserve_exact(output_bytes).map_err(|_| {
        PortableValueReplacementError::AllocationFailed {
            requested: output_bytes,
        }
    })?;
    let output_capacity = output.capacity();
    if output_capacity > limits.max_output_capacity_bytes {
        return Err(PortableValueReplacementError::OutputCapacityBytesLimit {
            needed: output_capacity,
            limit: limits.max_output_capacity_bytes,
        });
    }

    let prefix =
        haystack
            .get(..matched.start())
            .ok_or(PortableValueReplacementError::InternalInvariant(
                "selected span starts outside the haystack",
            ))?;
    let suffix =
        haystack
            .get(matched.end()..)
            .ok_or(PortableValueReplacementError::InternalInvariant(
                "selected span ends outside the haystack",
            ))?;
    output.extend_from_slice(prefix);
    output.extend_from_slice(replacement);
    output.extend_from_slice(suffix);
    if output.len() != output_bytes {
        return Err(PortableValueReplacementError::InternalInvariant(
            "preflight and copied output lengths differ",
        ));
    }
    Ok(Cow::Owned(output))
}

fn enforce_value_replacement_output_bytes(
    needed: usize,
    limit: usize,
) -> Result<(), PortableValueReplacementError> {
    if needed > limit {
        return Err(PortableValueReplacementError::OutputBytesLimit { needed, limit });
    }
    Ok(())
}

impl AggregateSpansRegex {
    /// Replace the first match with bytes returned by a whole-match callback.
    ///
    /// The callback receives the selected span and the complete original
    /// haystack, so it can return either owned bytes or a borrowed subslice.
    /// It is invoked at most once.
    pub fn replace_with_match<'h, F, R>(
        &self,
        haystack: &'h [u8],
        replacement: F,
        limits: impl core::borrow::Borrow<FunctionalReplacementLimits>,
    ) -> Result<FunctionalReplacementResult, FunctionalReplacementError>
    where
        F: FnMut(Match, &'h [u8]) -> R,
        R: LiteralReplacer,
    {
        self.replacen_with_match(haystack, 1, replacement, limits)
    }

    /// Replace every non-overlapping match with bytes returned by a
    /// whole-match callback.
    ///
    /// Callback order, absolute anchor context and adjacent-empty progress all
    /// come from the fully admitted complete-span sequence.
    pub fn replace_all_with_match<'h, F, R>(
        &self,
        haystack: &'h [u8],
        replacement: F,
        limits: impl core::borrow::Borrow<FunctionalReplacementLimits>,
    ) -> Result<FunctionalReplacementResult, FunctionalReplacementError>
    where
        F: FnMut(Match, &'h [u8]) -> R,
        R: LiteralReplacer,
    {
        self.replacen_with_match(haystack, 0, replacement, limits)
    }

    /// Replace at most `limit` complete non-overlapping matches using a
    /// whole-match callback. A zero limit replaces all matches, matching Rust
    /// regex's `replacen` contract.
    ///
    /// This floor deliberately exposes only group zero; capture-aware
    /// callbacks remain a separate capability. FRE invokes the callback once
    /// per replaced match and immediately copies its returned bytes. Before
    /// every FRE-owned vector growth, the exact resulting length is checked
    /// against `max_output_bytes` and the growth uses a fallible reservation.
    /// Allocations performed internally by caller code are outside FRE's
    /// resource accounting.
    pub fn replacen_with_match<'h, F, R>(
        &self,
        haystack: &'h [u8],
        limit: usize,
        mut replacement: F,
        limits: impl core::borrow::Borrow<FunctionalReplacementLimits>,
    ) -> Result<FunctionalReplacementResult, FunctionalReplacementError>
    where
        F: FnMut(Match, &'h [u8]) -> R,
        R: LiteralReplacer,
    {
        let limits = *limits.borrow();
        let spans = self.spans(haystack, limits.aggregate).map_err(|error| {
            let (selector, source) = match error.identity.as_cache_identity() {
                Some(identity) => (
                    identity.clone(),
                    FunctionalReplacementErrorSource::Selector(error.source),
                ),
                None if error.has_closed_fixed_attempt() => (
                    self.cache_identity(limits.aggregate),
                    FunctionalReplacementErrorSource::Selector(error.source),
                ),
                None => (
                    self.cache_identity(limits.aggregate),
                    FunctionalReplacementErrorSource::InternalInvariant(
                        "span selector returned an unauthenticated fixed-domain identity",
                    ),
                ),
            };
            FunctionalReplacementError {
                identity: Box::new(FunctionalReplacementIdentity {
                    selector,
                    limit,
                    max_output_bytes: limits.max_output_bytes,
                }),
                source,
            }
        })?;
        let selector_report = spans.report().clone();
        let identity = FunctionalReplacementIdentity {
            selector: selector_report.cache_identity(),
            limit,
            max_output_bytes: limits.max_output_bytes,
        };
        let replacement_count = if limit == 0 { usize::MAX } else { limit };
        let mut output = Vec::new();
        let mut cursor = 0_usize;
        let mut replacements = 0_usize;
        let mut span_visits = 0_usize;
        let mut haystack_bytes_copied = 0_usize;
        let mut replacement_bytes_copied = 0_usize;

        for matched in spans.iter().take(replacement_count) {
            if matched.start < cursor || matched.end < matched.start || matched.end > haystack.len()
            {
                return Err(functional_replacement_error(
                    &identity,
                    FunctionalReplacementErrorSource::InternalInvariant(
                        "selector spans are not ordered within the haystack",
                    ),
                ));
            }
            let gap = &haystack[cursor..matched.start];
            functional_extend(&mut output, gap, &identity)?;
            haystack_bytes_copied =
                functional_checked_add(&identity, haystack_bytes_copied, gap.len())?;

            let produced = replacement(matched, haystack);
            let bytes = produced.literal_bytes();
            functional_extend(&mut output, bytes, &identity)?;
            replacement_bytes_copied =
                functional_checked_add(&identity, replacement_bytes_copied, bytes.len())?;
            replacements = functional_checked_add(&identity, replacements, 1)?;
            span_visits = functional_checked_add(&identity, span_visits, 1)?;
            cursor = matched.end;
        }

        let tail = haystack.get(cursor..).ok_or_else(|| {
            functional_replacement_error(
                &identity,
                FunctionalReplacementErrorSource::InternalInvariant(
                    "selector span ended outside the haystack",
                ),
            )
        })?;
        functional_extend(&mut output, tail, &identity)?;
        haystack_bytes_copied =
            functional_checked_add(&identity, haystack_bytes_copied, tail.len())?;
        let accounted_output =
            functional_checked_add(&identity, haystack_bytes_copied, replacement_bytes_copied)?;
        if output.len() != accounted_output {
            return Err(functional_replacement_error(
                &identity,
                FunctionalReplacementErrorSource::InternalInvariant(
                    "copy loop and accounted output lengths differ",
                ),
            ));
        }
        Ok(FunctionalReplacementResult {
            bytes: output,
            report: FunctionalReplacementReport {
                identity,
                selector_details: selector_report.into_details(),
                accounting: FunctionalReplacementAccounting {
                    selected_matches: spans.len(),
                    replacements,
                    span_visits,
                    haystack_bytes_copied,
                    replacement_bytes_copied,
                    output_bytes: accounted_output,
                },
            },
        })
    }

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
    #[allow(
        clippy::too_many_lines,
        reason = "the replacement transaction keeps selection, exact sizing, one reservation and copy accounting together"
    )]
    pub fn replacen_literal<R: LiteralReplacer>(
        &self,
        haystack: &[u8],
        limit: usize,
        replacement: R,
        limits: impl core::borrow::Borrow<LiteralReplacementLimits>,
    ) -> Result<LiteralReplacementResult, LiteralReplacementError> {
        let replacement = replacement.literal_bytes();
        let limits = *limits.borrow();
        let spans = self.spans(haystack, limits.aggregate).map_err(|error| {
            let (selector, source) = match error.identity.as_cache_identity() {
                Some(identity) => (
                    identity.clone(),
                    LiteralReplacementErrorSource::Selector(error.source),
                ),
                None if error.has_closed_fixed_attempt() => (
                    self.cache_identity(limits.aggregate),
                    LiteralReplacementErrorSource::Selector(error.source),
                ),
                None => (
                    self.cache_identity(limits.aggregate),
                    LiteralReplacementErrorSource::InternalInvariant(
                        "span selector returned an unauthenticated fixed-domain identity",
                    ),
                ),
            };
            LiteralReplacementError {
                identity: Box::new(LiteralReplacementIdentity {
                    selector,
                    limit,
                    replacement_bytes: replacement.len(),
                    max_output_bytes: limits.max_output_bytes,
                    max_output_capacity_bytes: limits.max_output_capacity_bytes,
                }),
                source,
            }
        })?;
        let selector_report = spans.report().clone();
        let identity = LiteralReplacementIdentity {
            selector: selector_report.cache_identity(),
            limit,
            replacement_bytes: replacement.len(),
            max_output_bytes: limits.max_output_bytes,
            max_output_capacity_bytes: limits.max_output_capacity_bytes,
        };
        let mut accounting =
            replacement_preflight(&spans, haystack.len(), replacement.len(), limit)
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
        accounting.output_capacity_bytes = output.capacity();
        if accounting.output_capacity_bytes > limits.max_output_capacity_bytes {
            return Err(replacement_error(
                &identity,
                LiteralReplacementErrorSource::OutputCapacityBytesLimit {
                    needed: accounting.output_capacity_bytes,
                    limit: limits.max_output_capacity_bytes,
                },
            ));
        }
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
                selector_details: selector_report.into_details(),
                accounting,
            },
        })
    }
}

fn functional_extend(
    output: &mut Vec<u8>,
    bytes: &[u8],
    identity: &FunctionalReplacementIdentity,
) -> Result<(), FunctionalReplacementError> {
    let needed = output.len().checked_add(bytes.len()).ok_or_else(|| {
        functional_replacement_error(
            identity,
            FunctionalReplacementErrorSource::OutputSizeOverflow,
        )
    })?;
    if needed > identity.max_output_bytes {
        return Err(functional_replacement_error(
            identity,
            FunctionalReplacementErrorSource::OutputBytesLimit {
                needed,
                limit: identity.max_output_bytes,
            },
        ));
    }
    output.try_reserve_exact(bytes.len()).map_err(|_| {
        functional_replacement_error(
            identity,
            FunctionalReplacementErrorSource::AllocationFailed { requested: needed },
        )
    })?;
    output.extend_from_slice(bytes);
    Ok(())
}

fn functional_checked_add(
    identity: &FunctionalReplacementIdentity,
    current: usize,
    amount: usize,
) -> Result<usize, FunctionalReplacementError> {
    current.checked_add(amount).ok_or_else(|| {
        functional_replacement_error(
            identity,
            FunctionalReplacementErrorSource::OutputSizeOverflow,
        )
    })
}

fn functional_replacement_error(
    identity: &FunctionalReplacementIdentity,
    source: FunctionalReplacementErrorSource,
) -> FunctionalReplacementError {
    FunctionalReplacementError {
        identity: Box::new(identity.clone()),
        source,
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
        output_capacity_bytes: 0,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CaptureTemplatePiece<'a> {
    Literal(&'a [u8]),
    Capture(CaptureReference<'a>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CaptureReference<'a> {
    Index(usize),
    Name(&'a str),
}

#[derive(Clone, Debug)]
struct CaptureTemplateParser<'a> {
    replacement: &'a [u8],
    cursor: usize,
    next_closing_brace: Option<usize>,
    invalid_utf8: Option<(usize, usize)>,
    no_more_closing_braces: bool,
}

impl<'a> CaptureTemplateParser<'a> {
    const fn new(replacement: &'a [u8]) -> Self {
        Self {
            replacement,
            cursor: 0,
            next_closing_brace: None,
            invalid_utf8: None,
            no_more_closing_braces: false,
        }
    }

    fn parse_reference(&mut self, start: usize) -> Option<(CaptureReference<'a>, usize)> {
        let replacement = self.replacement.get(start..)?;
        if replacement.first() != Some(&b'$') {
            return None;
        }
        if replacement.get(1) == Some(&b'{') {
            let content_start = start.checked_add(2)?;
            let closing = match self.next_closing_brace {
                Some(closing) if closing >= content_start => closing,
                _ if self.no_more_closing_braces => return None,
                _ => {
                    let suffix = self.replacement.get(content_start..)?;
                    let Some(relative_closing) = suffix.iter().position(|&byte| byte == b'}')
                    else {
                        self.next_closing_brace = None;
                        self.invalid_utf8 = None;
                        self.no_more_closing_braces = true;
                        return None;
                    };
                    let closing = content_start.checked_add(relative_closing)?;
                    self.next_closing_brace = Some(closing);
                    self.invalid_utf8 = None;
                    closing
                }
            };
            if let Some((invalid_closing, invalid_byte)) = self.invalid_utf8
                && invalid_closing == closing
                && content_start <= invalid_byte
            {
                return None;
            }
            let content = self.replacement.get(content_start..closing)?;
            let name = match core::str::from_utf8(content) {
                Ok(name) => name,
                Err(error) => {
                    let invalid_byte = content_start.checked_add(error.valid_up_to())?;
                    self.invalid_utf8 = Some((closing, invalid_byte));
                    return None;
                }
            };
            let consumed = closing.checked_sub(start)?.checked_add(1)?;
            return Some((capture_reference(name), consumed));
        }
        let name_start = start.checked_add(1)?;
        let suffix = self.replacement.get(name_start..)?;
        let name_len = suffix
            .iter()
            .take_while(|&&byte| byte.is_ascii_alphanumeric() || byte == b'_')
            .count();
        if name_len == 0 {
            return None;
        }
        let name_end = name_start.checked_add(name_len)?;
        let name = core::str::from_utf8(self.replacement.get(name_start..name_end)?)
            .expect("unbraced capture references contain only ASCII bytes");
        Some((capture_reference(name), name_len.checked_add(1)?))
    }
}

impl<'a> Iterator for CaptureTemplateParser<'a> {
    type Item = CaptureTemplatePiece<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= self.replacement.len() {
            return None;
        }
        let remaining = &self.replacement[self.cursor..];
        let dollar = remaining.iter().position(|&byte| byte == b'$');
        let Some(relative_dollar) = dollar else {
            self.cursor = self.replacement.len();
            return Some(CaptureTemplatePiece::Literal(remaining));
        };
        if relative_dollar != 0 {
            let start = self.cursor;
            self.cursor = self.cursor.saturating_add(relative_dollar);
            return Some(CaptureTemplatePiece::Literal(
                &self.replacement[start..self.cursor],
            ));
        }

        let start = self.cursor;
        if self.replacement.get(start.saturating_add(1)) == Some(&b'$') {
            self.cursor = self.cursor.saturating_add(2);
            return Some(CaptureTemplatePiece::Literal(
                &self.replacement[start..start.saturating_add(1)],
            ));
        }
        let Some((reference, consumed)) = self.parse_reference(start) else {
            self.cursor = self.cursor.saturating_add(1);
            return Some(CaptureTemplatePiece::Literal(
                &self.replacement[start..self.cursor],
            ));
        };
        self.cursor = self.cursor.saturating_add(consumed);
        Some(CaptureTemplatePiece::Capture(reference))
    }
}

fn capture_reference(name: &str) -> CaptureReference<'_> {
    name.parse::<usize>()
        .map_or(CaptureReference::Name(name), CaptureReference::Index)
}

fn capture_reference_index(
    names: &[Option<Box<str>>],
    reference: CaptureReference<'_>,
) -> Option<usize> {
    match reference {
        CaptureReference::Index(index) => Some(index),
        CaptureReference::Name(name) => names
            .iter()
            .position(|candidate| candidate.as_deref() == Some(name)),
    }
}

fn capture_expansion_preflight(
    names: &[Option<Box<str>>],
    captures: &[Option<&[u8]>],
    replacement: &[u8],
    limits: CaptureExpansionLimits,
) -> Result<CaptureExpansionAccounting, CaptureExpansionError> {
    let template_scan_one_pass = capture_template_scan_work(replacement.len())?;
    enforce_capture_work(template_scan_one_pass, limits.max_work)?;
    let mut capture_references = 0_usize;
    let mut participating_references = 0_usize;
    let mut name_slots_one_pass = 0_usize;
    let mut name_comparison_work_one_pass = 0_usize;
    let mut literal_bytes_copied = 0_usize;
    let mut capture_bytes_copied = 0_usize;

    for piece in CaptureTemplateParser::new(replacement) {
        match piece {
            CaptureTemplatePiece::Literal(bytes) => {
                literal_bytes_copied = literal_bytes_copied
                    .checked_add(bytes.len())
                    .ok_or(CaptureExpansionError::OutputSizeOverflow)?;
            }
            CaptureTemplatePiece::Capture(reference) => {
                capture_references = capture_references
                    .checked_add(1)
                    .ok_or(CaptureExpansionError::WorkOverflow)?;
                let index = capture_reference_index_preflight(
                    names,
                    reference,
                    template_scan_one_pass,
                    capture_references,
                    &mut name_slots_one_pass,
                    &mut name_comparison_work_one_pass,
                    limits.max_work,
                )?;
                if let Some(bytes) = index
                    .and_then(|index| captures.get(index))
                    .and_then(|capture| *capture)
                {
                    participating_references = participating_references
                        .checked_add(1)
                        .ok_or(CaptureExpansionError::WorkOverflow)?;
                    capture_bytes_copied = capture_bytes_copied
                        .checked_add(bytes.len())
                        .ok_or(CaptureExpansionError::OutputSizeOverflow)?;
                }
            }
        }
    }

    let output_bytes = literal_bytes_copied
        .checked_add(capture_bytes_copied)
        .ok_or(CaptureExpansionError::OutputSizeOverflow)?;
    if output_bytes > limits.max_output_bytes {
        return Err(CaptureExpansionError::OutputBytesLimit {
            needed: output_bytes,
            limit: limits.max_output_bytes,
        });
    }
    let template_bytes_scanned = template_scan_one_pass
        .checked_mul(2)
        .ok_or(CaptureExpansionError::WorkOverflow)?;
    let name_slots_examined = name_slots_one_pass
        .checked_mul(2)
        .ok_or(CaptureExpansionError::WorkOverflow)?;
    let name_bytes_compared = name_comparison_work_one_pass
        .checked_mul(2)
        .ok_or(CaptureExpansionError::WorkOverflow)?;
    let reference_work = capture_references
        .checked_mul(2)
        .ok_or(CaptureExpansionError::WorkOverflow)?;
    let work = template_bytes_scanned
        .checked_add(reference_work)
        .and_then(|work| work.checked_add(name_bytes_compared))
        .and_then(|work| work.checked_add(output_bytes))
        .ok_or(CaptureExpansionError::WorkOverflow)?;
    enforce_capture_work(work, limits.max_work)?;
    Ok(CaptureExpansionAccounting {
        template_bytes_scanned,
        capture_references,
        participating_references,
        name_slots_examined,
        name_bytes_compared,
        literal_bytes_copied,
        capture_bytes_copied,
        output_bytes,
        work,
    })
}

fn capture_reference_index_preflight(
    names: &[Option<Box<str>>],
    reference: CaptureReference<'_>,
    template_scan_work: usize,
    capture_references: usize,
    name_slots: &mut usize,
    name_comparison_work: &mut usize,
    max_work: usize,
) -> Result<Option<usize>, CaptureExpansionError> {
    let work = template_scan_work
        .checked_add(capture_references)
        .and_then(|work| work.checked_add(*name_comparison_work))
        .ok_or(CaptureExpansionError::WorkOverflow)?;
    enforce_capture_work(work, max_work)?;
    let name = match reference {
        CaptureReference::Index(index) => return Ok(Some(index)),
        CaptureReference::Name(name) => name,
    };

    for (index, candidate) in names.iter().enumerate() {
        *name_slots = name_slots
            .checked_add(1)
            .ok_or(CaptureExpansionError::WorkOverflow)?;
        let comparison_work = candidate.as_deref().map_or(1, |candidate| {
            candidate.len().min(name.len()).saturating_add(1)
        });
        *name_comparison_work = name_comparison_work
            .checked_add(comparison_work)
            .ok_or(CaptureExpansionError::WorkOverflow)?;
        let work = template_scan_work
            .checked_add(capture_references)
            .and_then(|work| work.checked_add(*name_comparison_work))
            .ok_or(CaptureExpansionError::WorkOverflow)?;
        enforce_capture_work(work, max_work)?;
        if candidate.as_deref() == Some(name) {
            return Ok(Some(index));
        }
    }
    Ok(None)
}

fn capture_template_scan_work(length: usize) -> Result<usize, CaptureExpansionError> {
    // Per pass, dollar discovery examines at most 2N bytes. The monotonic
    // caches bound closing-brace searches and UTF-8 validation to N each, and
    // unbraced-name scans examine at most N more bytes. Retain the prior
    // triangular bound when it is tighter for tiny templates.
    let linear = length
        .checked_mul(5)
        .ok_or(CaptureExpansionError::WorkOverflow)?;
    let triangular = length
        .checked_add(1)
        .and_then(|successor| length.checked_mul(successor))
        .map_or(usize::MAX, |product| product / 2);
    Ok(linear.min(triangular))
}

fn enforce_capture_work(needed: usize, limit: usize) -> Result<(), CaptureExpansionError> {
    if needed > limit {
        return Err(CaptureExpansionError::WorkLimit { needed, limit });
    }
    Ok(())
}
