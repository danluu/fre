use core::marker::PhantomData;
use core::ops::Range;

use fre_exact_alloc::{CopyError, ExactVec};
use fre_kernels::{
    RequiredInternalAnchorCountError, RequiredInternalAnchorCountLimits,
    RequiredInternalAnchorCountUpperBounds, RequiredInternalAnchorPlan,
};

use crate::accounting::ExecutionAccounting;
use crate::candidate;
use crate::compile::{CompiledRegex, PlanId, RequiredSuffixes, TerminalFrontierSeed};
use crate::error::{add, enforce, mul};
use crate::program::{
    Assertion, AssertionContext, Inst, NO_SPLIT_RANK, Program, ScalarSet, decode_first_scalar,
};
use crate::{Error, OperationLimits, Resource};

mod terminal_frontier;

/// Half-open absolute byte span in the original haystack.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

/// Forced whole-operation storage formulation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Strategy {
    /// Materialize one endpoint word per `(input boundary, program state)`.
    FullTable,
    /// Materialize construction-selected fixed-size split/root decisions or
    /// reachable endpoints in reverse boundary order and consume them through
    /// a forward-only sequential reader.
    ReverseSequentialRows,
}

/// Construction-selected record stored by [`Strategy::ReverseSequentialRows`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RowStorage {
    /// One preferred/fallback bit per split plus one reachable-root bit.
    SplitDecisions,
    /// The selected reachable endpoint, encoded in the fewest whole bytes
    /// required by the admitted input boundary count.
    ReachableEndpoints,
}

/// Marker for complete span iteration.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SpanIteration;

/// Marker for match counting.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MatchCount;

/// Marker for checked matched-byte summation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SpanSum;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum OperationKind {
    Spans,
    Count,
    Sum,
}

/// Stable identity of a regex plan, forced strategy and operation type.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OperationId([u8; 16]);

impl OperationId {
    #[must_use]
    pub const fn bytes(self) -> [u8; 16] {
        self.0
    }
}

impl core::fmt::Display for OperationId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Whole-operation certificate checked before a result handle is published.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationCertificate {
    pub regex_plan_id: PlanId,
    pub operation_id: OperationId,
    pub strategy: Strategy,
    pub range: Range<usize>,
    pub states: usize,
    pub boundaries: usize,
    pub table_cells: usize,
    pub row_storage: Option<RowStorage>,
    pub row_record_bytes: usize,
    /// Whether HIR-certified terminal candidates fed a bounded ordered
    /// frontier instead of evaluating every program state at every boundary.
    pub terminal_frontier: bool,
    pub work_bound: usize,
    pub random_access_bytes: usize,
    pub scratch_bytes: usize,
    pub log_bytes: usize,
    pub sequential_bytes_bound: usize,
    pub match_events: usize,
    pub output_matches: usize,
    pub output_bytes: usize,
    pub span_sum: usize,
    pub peak_bytes: usize,
}

#[derive(Debug)]
struct Common<K> {
    certificate: OperationCertificate,
    accounting: ExecutionAccounting,
    marker: PhantomData<K>,
}

/// Fully admitted immutable span sequence.
#[derive(Debug)]
pub struct AdmittedSpans {
    common: Common<SpanIteration>,
    spans: Vec<Span>,
}

impl AdmittedSpans {
    #[must_use]
    pub fn iter(&self) -> SpanIter<'_> {
        SpanIter {
            inner: self.spans.iter(),
        }
    }

    #[must_use]
    pub fn as_slice(&self) -> &[Span] {
        &self.spans
    }

    #[must_use]
    pub const fn certificate(&self) -> &OperationCertificate {
        &self.common.certificate
    }

    #[must_use]
    pub const fn accounting(&self) -> ExecutionAccounting {
        self.common.accounting
    }
}

impl<'a> IntoIterator for &'a AdmittedSpans {
    type Item = Span;
    type IntoIter = SpanIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Pull iterator over a sequence whose complete operation was already
/// admitted. Pulling performs no regex work and cannot fail.
#[derive(Clone, Debug)]
pub struct SpanIter<'a> {
    inner: core::slice::Iter<'a, Span>,
}

impl Iterator for SpanIter<'_> {
    type Item = Span;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().copied()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl ExactSizeIterator for SpanIter<'_> {}
impl core::iter::FusedIterator for SpanIter<'_> {}

/// Fully admitted count reducer.
#[derive(Debug)]
pub struct AdmittedCount {
    common: Common<MatchCount>,
    value: usize,
}

impl AdmittedCount {
    #[must_use]
    pub const fn value(&self) -> usize {
        self.value
    }

    #[must_use]
    pub const fn certificate(&self) -> &OperationCertificate {
        &self.common.certificate
    }

    #[must_use]
    pub const fn accounting(&self) -> ExecutionAccounting {
        self.common.accounting
    }
}

/// Fully admitted checked matched-byte sum reducer.
#[derive(Debug)]
pub struct AdmittedSpanSum {
    common: Common<SpanSum>,
    value: usize,
}

impl AdmittedSpanSum {
    #[must_use]
    pub const fn value(&self) -> usize {
        self.value
    }

    #[must_use]
    pub const fn certificate(&self) -> &OperationCertificate {
        &self.common.certificate
    }

    #[must_use]
    pub const fn accounting(&self) -> ExecutionAccounting {
        self.common.accounting
    }
}

impl CompiledRegex {
    /// Admit and evaluate a complete non-overlapping span sequence.
    pub fn admit_spans(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
    ) -> Result<AdmittedSpans, Error> {
        let result =
            self.execute::<false>(haystack, range, strategy, OperationKind::Spans, limits)?;
        Ok(AdmittedSpans {
            common: Common {
                certificate: result.certificate,
                accounting: result.accounting,
                marker: PhantomData,
            },
            spans: result.spans,
        })
    }

    /// Admit and evaluate a complete non-overlapping span sequence while
    /// enforcing execution work against the exact observed charge. This
    /// retains the full certificate, accounting, and spans required by an
    /// enclosing reducer that must validate match-level invariants.
    pub fn admit_spans_observed(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
    ) -> Result<AdmittedSpans, Error> {
        let result =
            self.execute::<true>(haystack, range, strategy, OperationKind::Spans, limits)?;
        Ok(AdmittedSpans {
            common: Common {
                certificate: result.certificate,
                accounting: result.accounting,
                marker: PhantomData,
            },
            spans: result.spans,
        })
    }

    /// Admit and evaluate a complete match-count reduction.
    pub fn admit_count(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
    ) -> Result<AdmittedCount, Error> {
        let result =
            self.execute::<false>(haystack, range, strategy, OperationKind::Count, limits)?;
        Ok(AdmittedCount {
            value: result.summary.matches,
            common: Common {
                certificate: result.certificate,
                accounting: result.accounting,
                marker: PhantomData,
            },
        })
    }

    /// Admit and evaluate a complete checked matched-byte sum reduction.
    pub fn admit_span_sum(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
    ) -> Result<AdmittedSpanSum, Error> {
        let result =
            self.execute::<false>(haystack, range, strategy, OperationKind::Sum, limits)?;
        Ok(AdmittedSpanSum {
            value: result.summary.span_sum,
            common: Common {
                certificate: result.certificate,
                accounting: result.accounting,
                marker: PhantomData,
            },
        })
    }

    /// Evaluate a complete match-count reduction while enforcing execution
    /// work against the exact observed charge instead of the conservative
    /// replay upper bound used by an admitted diagnostic result.
    pub fn count_value(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
    ) -> Result<usize, Error> {
        self.execute::<true>(haystack, range, strategy, OperationKind::Count, limits)
            .map(|result| result.summary.matches)
    }

    /// Evaluate a complete checked matched-byte sum while enforcing execution
    /// work against the exact observed charge instead of the conservative
    /// replay upper bound used by an admitted diagnostic result.
    pub fn span_sum_value(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
    ) -> Result<usize, Error> {
        self.execute::<true>(haystack, range, strategy, OperationKind::Sum, limits)
            .map(|result| result.summary.span_sum)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "whole-operation admission keeps failure-before-publication ordering auditable"
    )]
    fn execute<const OBSERVED_WORK: bool>(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        kind: OperationKind,
        limits: OperationLimits,
    ) -> Result<ExecutionResult, Error> {
        if range.start > range.end || range.end > haystack.len() {
            return Err(Error::InvalidRange {
                start: range.start,
                end: range.end,
                haystack_len: haystack.len(),
            });
        }
        let local = &haystack[range.clone()];
        if kind == OperationKind::Count
            && strategy == Strategy::ReverseSequentialRows
            && let Some(plan) = &self.required_internal_anchor
        {
            return self.execute_required_internal_anchor(plan, local, range, strategy, limits);
        }
        if OBSERVED_WORK
            && kind == OperationKind::Count
            && strategy == Strategy::ReverseSequentialRows
            && let Some(plan) = &self.candidate
            && candidate::executable_for(&self.program)
        {
            return self.execute_candidate(plan, haystack, range, strategy, limits);
        }
        let mut accounting = ExecutionAccounting::default();
        let utf8_validation =
            preflight_unicode_word_utf8(&self.program, haystack, limits, &mut accounting)?;
        let mut engine_limits = limits;
        engine_limits.max_work = engine_limits.max_work.checked_sub(utf8_validation).ok_or(
            Error::ArithmeticOverflow {
                resource: Resource::ExecutionWork,
            },
        )?;
        engine_limits.max_sequential_bytes = engine_limits
            .max_sequential_bytes
            .checked_sub(utf8_validation)
            .ok_or(Error::ArithmeticOverflow {
                resource: Resource::SequentialBytes,
            })?;
        let assertion_context = AssertionContext::new(haystack, range.start, local.len())?;
        let boundaries = add(local.len(), 1, Resource::Boundaries)?;
        enforce(boundaries, limits.max_boundaries, Resource::Boundaries)?;
        let passes = if kind == OperationKind::Spans { 2 } else { 1 };
        let terminal_seed = (strategy == Strategy::ReverseSequentialRows
            && !self.terminal_frontier.is_empty())
        .then_some(SparseSeed::TerminalFrontier(&self.terminal_frontier));
        let fallback_seed = if self.required_suffixes.is_empty() {
            None
        } else {
            Some(SparseSeed::RequiredSuffixes(&self.required_suffixes))
        };
        let dense = Requirements::new::<OBSERVED_WORK>(
            &self.program,
            boundaries,
            strategy,
            passes,
            engine_limits,
        );
        let (requirements, sparse_seed) = if let Some(seed) = terminal_seed {
            match Requirements::new_for_seed(
                &self.program,
                boundaries,
                strategy,
                passes,
                engine_limits,
                seed,
            ) {
                Ok(requirements) => (requirements, Some(seed)),
                Err(terminal_error) => match dense {
                    Ok(requirements)
                        if !OBSERVED_WORK || requirements.work_bound <= engine_limits.max_work =>
                    {
                        (requirements, None)
                    }
                    Ok(_) | Err(_) => return Err(terminal_error),
                },
            }
        } else {
            match dense {
                Ok(requirements)
                    if OBSERVED_WORK
                        && requirements.work_bound > engine_limits.max_work
                        && strategy == Strategy::ReverseSequentialRows =>
                {
                    if let Some(seed) = fallback_seed {
                        (
                            Requirements::new_for_seed(
                                &self.program,
                                boundaries,
                                strategy,
                                passes,
                                engine_limits,
                                seed,
                            )?,
                            Some(seed),
                        )
                    } else {
                        (
                            Requirements::new_cached::<OBSERVED_WORK>(
                                &self.program,
                                boundaries,
                                strategy,
                                passes,
                                engine_limits,
                            )?,
                            None,
                        )
                    }
                }
                Ok(requirements) => (requirements, None),
                Err(
                    error @ Error::ResourceLimit {
                        resource: Resource::ExecutionWork,
                        ..
                    },
                ) if strategy == Strategy::ReverseSequentialRows => {
                    if let Some(seed) = fallback_seed {
                        (
                            Requirements::new_for_seed(
                                &self.program,
                                boundaries,
                                strategy,
                                passes,
                                engine_limits,
                                seed,
                            )?,
                            Some(seed),
                        )
                    } else {
                        (
                            Requirements::new_cached_after_refusal(
                                error,
                                &self.program,
                                boundaries,
                                passes,
                                engine_limits,
                            )?,
                            None,
                        )
                    }
                }
                Err(error) => return Err(error),
            }
        };
        let requirements = requirements.with_prefix::<OBSERVED_WORK>(utf8_validation, limits)?;
        let mut engine = Engine::build::<OBSERVED_WORK>(
            &self.program,
            local,
            assertion_context,
            strategy,
            requirements,
            sparse_seed,
            limits,
            &mut accounting,
        )?;
        let summary = engine.scan::<OBSERVED_WORK>(
            &self.program,
            local,
            assertion_context,
            requirements.work_bound,
            limits.max_work,
            &mut accounting,
            |_| Ok(()),
        )?;
        enforce(
            summary.events,
            limits.max_match_events,
            Resource::MatchEvents,
        )?;
        enforce(
            summary.matches,
            limits.max_output_matches,
            Resource::OutputMatches,
        )?;
        if kind == OperationKind::Sum {
            enforce(summary.span_sum, limits.max_span_sum, Resource::SpanSum)?;
        }
        let requested_output_bytes = if kind == OperationKind::Spans {
            mul(
                summary.matches,
                core::mem::size_of::<Span>(),
                Resource::OutputBytes,
            )?
        } else {
            0
        };
        enforce(
            requested_output_bytes,
            limits.max_output_bytes,
            Resource::OutputBytes,
        )?;
        let requested_peak = engine.peak_with_output(requested_output_bytes)?;
        enforce(requested_peak, limits.max_peak_bytes, Resource::PeakBytes)?;
        let mut spans = Vec::new();
        if kind == OperationKind::Spans {
            spans
                .try_reserve_exact(summary.matches)
                .map_err(|_| Error::AllocationFailed {
                    resource: Resource::OutputBytes,
                    items: summary.matches,
                })?;
            let allocated_output_bytes = mul(
                spans.capacity(),
                core::mem::size_of::<Span>(),
                Resource::OutputBytes,
            )?;
            enforce(
                allocated_output_bytes,
                limits.max_output_bytes,
                Resource::OutputBytes,
            )?;
            let allocated_peak = engine.peak_with_output(allocated_output_bytes)?;
            enforce(allocated_peak, limits.max_peak_bytes, Resource::PeakBytes)?;
            let repeated = engine.scan::<OBSERVED_WORK>(
                &self.program,
                local,
                assertion_context,
                requirements.work_bound,
                limits.max_work,
                &mut accounting,
                |span| {
                    spans.push(span);
                    Ok(())
                },
            )?;
            if repeated != summary || spans.len() != summary.matches {
                return Err(Error::InternalInvariant(
                    "second admitted replay changed the match sequence",
                ));
            }
            accounting.output_bytes = allocated_output_bytes;
            accounting.peak_bytes = allocated_peak;
        } else {
            accounting.peak_bytes = engine.peak_with_output(0)?;
        }
        validate_admitted_work(&accounting, requirements.work_bound, limits.max_work)?;
        accounting.emitted_matches = summary.matches;
        let certificate = OperationCertificate {
            regex_plan_id: self.plan_id(),
            operation_id: operation_identity(
                self.plan_id(),
                strategy,
                kind,
                requirements.terminal_frontier,
            ),
            strategy,
            range,
            states: self.program.insts.len(),
            boundaries,
            table_cells: requirements.table_cells,
            row_storage: requirements.row_storage,
            row_record_bytes: requirements.record_bytes,
            terminal_frontier: requirements.terminal_frontier,
            work_bound: requirements.work_bound,
            random_access_bytes: accounting.random_access_peak_bytes,
            scratch_bytes: accounting.scratch_peak_bytes,
            log_bytes: accounting.log_bytes,
            sequential_bytes_bound: requirements.sequential_bound,
            match_events: summary.events,
            output_matches: summary.matches,
            output_bytes: accounting.output_bytes,
            span_sum: summary.span_sum,
            peak_bytes: accounting.peak_bytes,
        };
        Ok(ExecutionResult {
            certificate,
            accounting,
            summary,
            spans,
        })
    }

    fn execute_required_internal_anchor(
        &self,
        plan: &RequiredInternalAnchorPlan,
        local: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
    ) -> Result<ExecutionResult, Error> {
        let (boundaries, upper) = preflight_required_internal_anchor(plan, local.len(), limits)?;
        let result = plan
            .count(local, exact_required_anchor_limits(upper, limits))
            .map_err(|error| map_required_anchor_error(&error))?;
        let matches = usize::try_from(result.count).map_err(|_| Error::ArithmeticOverflow {
            resource: Resource::OutputMatches,
        })?;
        let actual = result.accounting.actual;
        let accounting = ExecutionAccounting {
            transition_checks: actual.continuation_steps,
            root_probes: actual.candidate_visits,
            successful_paths: matches,
            emitted_matches: matches,
            sequential_bytes_read: actual.sequential_bytes,
            random_access_bytes_read: actual.random_access_bytes,
            peak_bytes: actual.peak_bytes,
            work: actual.work,
            required_anchor_candidates: actual.candidate_visits,
            required_anchor_scan_windows: actual.anchor_window_attempts,
            required_anchor_anchor_comparisons: actual.finder_source_accesses,
            required_anchor_prefix_steps: actual.prefix_steps,
            required_anchor_continuation_steps: actual.continuation_steps,
            required_anchor_source_accesses: actual.source_accesses,
            required_anchor_queue_peak: actual.queue_entries,
            required_anchor_frontier_peak: actual.frontier_entries,
            ..ExecutionAccounting::default()
        };
        let certificate = OperationCertificate {
            regex_plan_id: self.plan_id(),
            operation_id: operation_identity(self.plan_id(), strategy, OperationKind::Count, false),
            strategy,
            range,
            states: self.program.insts.len(),
            boundaries,
            table_cells: 0,
            row_storage: None,
            row_record_bytes: 0,
            terminal_frontier: false,
            work_bound: upper.work,
            random_access_bytes: upper.random_access_bytes,
            scratch_bytes: 0,
            log_bytes: 0,
            sequential_bytes_bound: upper.sequential_bytes,
            match_events: matches,
            output_matches: matches,
            output_bytes: 0,
            span_sum: 0,
            peak_bytes: upper.peak_bytes,
        };
        Ok(ExecutionResult {
            certificate,
            accounting,
            summary: ScanSummary {
                matches,
                events: matches,
                suppressed: 0,
                span_sum: 0,
            },
            spans: Vec::new(),
        })
    }

    fn execute_candidate(
        &self,
        plan: &candidate::Plan,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
    ) -> Result<ExecutionResult, Error> {
        let result = candidate::count(plan, &self.program, haystack, range.clone(), limits)?;
        let boundaries = add(
            range
                .end
                .checked_sub(range.start)
                .ok_or(Error::InternalInvariant("candidate range reversed"))?,
            1,
            Resource::Boundaries,
        )?;
        let certificate = OperationCertificate {
            regex_plan_id: self.plan_id(),
            operation_id: operation_identity(self.plan_id(), strategy, OperationKind::Count, false),
            strategy,
            range,
            states: self.program.insts.len(),
            boundaries,
            table_cells: 0,
            row_storage: None,
            row_record_bytes: 0,
            terminal_frontier: false,
            work_bound: result.accounting.work,
            random_access_bytes: result.accounting.random_access_peak_bytes,
            scratch_bytes: result.accounting.scratch_peak_bytes,
            log_bytes: 0,
            sequential_bytes_bound: result.accounting.sequential_bytes_read,
            match_events: result.value,
            output_matches: result.value,
            output_bytes: 0,
            span_sum: 0,
            peak_bytes: result.accounting.peak_bytes,
        };
        Ok(ExecutionResult {
            certificate,
            accounting: result.accounting,
            summary: ScanSummary {
                matches: result.value,
                events: result.value,
                suppressed: 0,
                span_sum: 0,
            },
            spans: Vec::new(),
        })
    }
}

fn preflight_required_internal_anchor(
    plan: &RequiredInternalAnchorPlan,
    input_bytes: usize,
    limits: OperationLimits,
) -> Result<(usize, RequiredInternalAnchorCountUpperBounds), Error> {
    let boundaries = add(input_bytes, 1, Resource::Boundaries)?;
    enforce(boundaries, limits.max_boundaries, Resource::Boundaries)?;
    let upper = plan
        .count_upper_bounds(input_bytes)
        .map_err(|error| map_required_anchor_error(&error))?;
    enforce(
        upper.candidate_visits,
        limits.max_match_events,
        Resource::MatchEvents,
    )?;
    let count = usize::try_from(upper.count).map_err(|_| Error::ArithmeticOverflow {
        resource: Resource::OutputMatches,
    })?;
    enforce(count, limits.max_output_matches, Resource::OutputMatches)?;
    enforce(
        upper.random_access_bytes,
        limits.max_random_access_bytes,
        Resource::RandomAccessBytes,
    )?;
    enforce(
        upper.sequential_bytes,
        limits.max_sequential_bytes,
        Resource::SequentialBytes,
    )?;
    enforce(upper.work, limits.max_work, Resource::ExecutionWork)?;
    enforce(
        upper.scratch_bytes,
        limits.max_scratch_bytes,
        Resource::ScratchBytes,
    )?;
    enforce(upper.peak_bytes, limits.max_peak_bytes, Resource::PeakBytes)?;
    Ok((boundaries, upper))
}

fn exact_required_anchor_limits(
    upper: RequiredInternalAnchorCountUpperBounds,
    public: OperationLimits,
) -> RequiredInternalAnchorCountLimits {
    let public_count = u64::try_from(public.max_output_matches).unwrap_or(u64::MAX);
    RequiredInternalAnchorCountLimits {
        max_input_bytes: upper.input_bytes,
        max_candidate_visits: upper.candidate_visits.min(public.max_match_events),
        max_continuation_steps: upper.continuation_steps,
        max_source_accesses: upper.source_accesses,
        max_random_access_bytes: upper
            .random_access_bytes
            .min(public.max_random_access_bytes),
        max_sequential_bytes: upper.sequential_bytes.min(public.max_sequential_bytes),
        max_work: upper.work.min(public.max_work),
        max_count: upper.count.min(public_count),
        max_queue_entries: upper.queue_entries,
        max_frontier_entries: upper.frontier_entries,
        max_allocations: upper.allocations,
        max_scratch_bytes: upper.scratch_bytes,
        max_peak_bytes: upper.peak_bytes.min(public.max_peak_bytes),
    }
}

fn map_required_anchor_error(error: &RequiredInternalAnchorCountError) -> Error {
    match error {
        RequiredInternalAnchorCountError::Overflow(_) => Error::ArithmeticOverflow {
            resource: Resource::ExecutionWork,
        },
        RequiredInternalAnchorCountError::Resource { .. }
        | RequiredInternalAnchorCountError::CountResource { .. }
        | RequiredInternalAnchorCountError::AccountingInvariant { .. } => {
            Error::InternalInvariant("required internal-anchor admission diverged from preflight")
        }
        _ => Error::InternalInvariant("unclassified required internal-anchor execution refusal"),
    }
}

fn preflight_unicode_word_utf8(
    program: &Program,
    haystack: &[u8],
    limits: OperationLimits,
    accounting: &mut ExecutionAccounting,
) -> Result<usize, Error> {
    if !program.contains_unicode_word_boundary() {
        return Ok(0);
    }
    let bytes = haystack.len();
    enforce(bytes, limits.max_work, Resource::ExecutionWork)?;
    enforce(
        bytes,
        limits.max_sequential_bytes,
        Resource::SequentialBytes,
    )?;
    accounting.utf8_validation_work = bytes;
    accounting.work = bytes;
    accounting.sequential_bytes_read = bytes;
    if core::str::from_utf8(haystack).is_err() {
        return Err(Error::InvalidUtf8ForUnicodeWordBoundary);
    }
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ScanSummary {
    matches: usize,
    events: usize,
    suppressed: usize,
    span_sum: usize,
}

impl ScanSummary {
    const fn empty() -> Self {
        Self {
            matches: 0,
            events: 0,
            suppressed: 0,
            span_sum: 0,
        }
    }
}

struct ExecutionResult {
    certificate: OperationCertificate,
    accounting: ExecutionAccounting,
    summary: ScanSummary,
    spans: Vec<Span>,
}

#[derive(Clone, Copy)]
enum SparseSeed<'a> {
    RequiredSuffixes(&'a RequiredSuffixes),
    TerminalFrontier(&'a TerminalFrontierSeed),
}

#[derive(Clone, Copy, Debug)]
struct Requirements {
    table_cells: usize,
    row_storage: Option<RowStorage>,
    record_bytes: usize,
    requested_log_bytes: usize,
    sequential_bound: usize,
    work_bound: usize,
    terminal_frontier: bool,
    frontier: Option<terminal_frontier::FrontierRequirements>,
    cached_frontier: Option<CachedFrontierRequirements>,
    cache_attempt_work: usize,
}

impl Requirements {
    fn new_for_seed(
        program: &Program,
        boundaries: usize,
        strategy: Strategy,
        passes: usize,
        limits: OperationLimits,
        seed: SparseSeed<'_>,
    ) -> Result<Self, Error> {
        match seed {
            SparseSeed::RequiredSuffixes(_) => {
                Self::new_sparse(program, boundaries, strategy, passes, limits)
            }
            SparseSeed::TerminalFrontier(_) => {
                let SparseSeed::TerminalFrontier(seed) = seed else {
                    return Err(Error::InternalInvariant("terminal seed changed variant"));
                };
                Self::new_terminal_frontier(program, boundaries, strategy, passes, seed, limits)
            }
        }
    }

    fn with_prefix<const OBSERVED_WORK: bool>(
        mut self,
        work: usize,
        limits: OperationLimits,
    ) -> Result<Self, Error> {
        self.work_bound = add(self.work_bound, work, Resource::ExecutionWork)?;
        if !OBSERVED_WORK {
            enforce(self.work_bound, limits.max_work, Resource::ExecutionWork)?;
        }
        self.sequential_bound = add(self.sequential_bound, work, Resource::SequentialBytes)?;
        enforce(
            self.sequential_bound,
            limits.max_sequential_bytes,
            Resource::SequentialBytes,
        )?;
        Ok(self)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "each storage strategy keeps its exact work and byte bounds beside admission"
    )]
    fn new<const OBSERVED_WORK: bool>(
        program: &Program,
        boundaries: usize,
        strategy: Strategy,
        passes: usize,
        limits: OperationLimits,
    ) -> Result<Self, Error> {
        let states = program.insts.len();
        let per_boundary = add(
            program.execution_state_work(),
            usize::from(program.contains_scalar_transition()),
            Resource::ExecutionWork,
        )?;
        let build_work = mul(per_boundary, boundaries, Resource::ExecutionWork)?;
        let scan_base = mul(
            mul(boundaries, 4, Resource::ExecutionWork)?,
            passes,
            Resource::ExecutionWork,
        )?;
        let (table_cells, row_storage, record_bytes, random, scratch, log, sequential, replay) =
            match strategy {
                Strategy::FullTable => {
                    let cells = mul(states, boundaries, Resource::TableCells)?;
                    enforce(cells, limits.max_table_cells, Resource::TableCells)?;
                    let bytes = mul(
                        cells,
                        core::mem::size_of::<usize>(),
                        Resource::RandomAccessBytes,
                    )?;
                    (cells, None, 0, bytes, bytes, 0, 0, 0)
                }
                Strategy::ReverseSequentialRows => {
                    let rows = ReverseRowRequirements::new(program, boundaries, passes)?;
                    (
                        0,
                        Some(rows.storage),
                        rows.record_bytes,
                        rows.row_bytes,
                        rows.row_bytes,
                        rows.log_bytes,
                        rows.sequential_bound,
                        rows.replay_bound,
                    )
                }
            };
        enforce(
            random,
            limits.max_random_access_bytes,
            Resource::RandomAccessBytes,
        )?;
        enforce(scratch, limits.max_scratch_bytes, Resource::ScratchBytes)?;
        enforce(log, limits.max_log_bytes, Resource::LogBytes)?;
        enforce(
            sequential,
            limits.max_sequential_bytes,
            Resource::SequentialBytes,
        )?;
        let work_bound = add(
            add(build_work, scan_base, Resource::ExecutionWork)?,
            replay,
            Resource::ExecutionWork,
        )?;
        if !OBSERVED_WORK {
            enforce(work_bound, limits.max_work, Resource::ExecutionWork)?;
        }
        Ok(Self {
            table_cells,
            row_storage,
            record_bytes,
            requested_log_bytes: log,
            sequential_bound: sequential,
            work_bound,
            terminal_frontier: false,
            frontier: None,
            cached_frontier: None,
            cache_attempt_work: 0,
        })
    }

    fn cached(
        program: &Program,
        boundaries: usize,
        passes: usize,
        limits: OperationLimits,
    ) -> Result<Option<Self>, Error> {
        let cache = CachedFrontierRequirements::new(program.insts.len(), boundaries, passes)?;
        // A caller using observed-work admission can legitimately set its
        // limit below the cache's fixed initialization cost while the dense
        // executor still fits at its exact observed charge. In that case the
        // cache is not an admissible alternative: selecting it would replace
        // a successful exact-limit replay with a larger resource refusal.
        if cache.initialization_work()? > limits.max_work {
            return Ok(None);
        }
        Ok(cache.fits(limits)?.then_some(Self {
            table_cells: 0,
            row_storage: None,
            record_bytes: cache.record_bytes,
            requested_log_bytes: cache.log_bytes,
            sequential_bound: cache.sequential_bound,
            work_bound: limits.max_work,
            terminal_frontier: false,
            frontier: None,
            cached_frontier: Some(cache),
            cache_attempt_work: 1,
        }))
    }

    fn new_cached<const OBSERVED_WORK: bool>(
        program: &Program,
        boundaries: usize,
        strategy: Strategy,
        passes: usize,
        limits: OperationLimits,
    ) -> Result<Self, Error> {
        if let Some(requirements) = Self::cached(program, boundaries, passes, limits)? {
            return Ok(requirements);
        }
        Self::new::<OBSERVED_WORK>(program, boundaries, strategy, passes, limits)
    }

    fn new_cached_after_refusal(
        refusal: Error,
        program: &Program,
        boundaries: usize,
        passes: usize,
        limits: OperationLimits,
    ) -> Result<Self, Error> {
        Self::cached(program, boundaries, passes, limits)?.ok_or(refusal)
    }

    fn new_sparse(
        program: &Program,
        boundaries: usize,
        strategy: Strategy,
        passes: usize,
        limits: OperationLimits,
    ) -> Result<Self, Error> {
        if strategy != Strategy::ReverseSequentialRows {
            return Err(Error::InternalInvariant(
                "sparse continuation requires reverse sequential rows",
            ));
        }
        let rows = ReverseRowRequirements::new(program, boundaries, passes)?;
        enforce(
            rows.row_bytes,
            limits.max_random_access_bytes,
            Resource::RandomAccessBytes,
        )?;
        enforce(
            rows.row_bytes,
            limits.max_scratch_bytes,
            Resource::ScratchBytes,
        )?;
        enforce(rows.log_bytes, limits.max_log_bytes, Resource::LogBytes)?;
        enforce(
            rows.sequential_bound,
            limits.max_sequential_bytes,
            Resource::SequentialBytes,
        )?;
        Ok(Self {
            table_cells: 0,
            row_storage: Some(rows.storage),
            record_bytes: rows.record_bytes,
            requested_log_bytes: rows.log_bytes,
            sequential_bound: rows.sequential_bound,
            // Sparse construction charges every observed unit before it is
            // performed, so the caller's limit is its explicit admission cap.
            work_bound: limits.max_work,
            terminal_frontier: false,
            frontier: None,
            cached_frontier: None,
            cache_attempt_work: 0,
        })
    }

    fn new_terminal_frontier(
        program: &Program,
        boundaries: usize,
        strategy: Strategy,
        passes: usize,
        seed: &TerminalFrontierSeed,
        limits: OperationLimits,
    ) -> Result<Self, Error> {
        if strategy != Strategy::ReverseSequentialRows {
            return Err(Error::InternalInvariant(
                "terminal frontier requires reverse sequential rows",
            ));
        }
        let rows = ReverseRowRequirements::new_terminal_frontier(program, boundaries, passes)?;
        let scan_work = mul(
            mul(boundaries, 4, Resource::ExecutionWork)?,
            passes,
            Resource::ExecutionWork,
        )?;
        let post_build_work = add(scan_work, rows.replay_bound, Resource::ExecutionWork)?;
        let frontier = terminal_frontier::requirements(
            program,
            seed,
            boundaries,
            rows.log_bytes,
            post_build_work,
            limits,
        )?;
        enforce(
            frontier.bytes,
            limits.max_random_access_bytes,
            Resource::RandomAccessBytes,
        )?;
        enforce(
            frontier.bytes,
            limits.max_scratch_bytes,
            Resource::ScratchBytes,
        )?;
        enforce(rows.log_bytes, limits.max_log_bytes, Resource::LogBytes)?;
        let source = frontier.source_bytes_bound;
        let sequential = add(rows.sequential_bound, source, Resource::SequentialBytes)?;
        enforce(
            sequential,
            limits.max_sequential_bytes,
            Resource::SequentialBytes,
        )?;
        enforce(
            add(rows.log_bytes, frontier.bytes, Resource::PeakBytes)?,
            limits.max_peak_bytes,
            Resource::PeakBytes,
        )?;
        Ok(Self {
            table_cells: 0,
            row_storage: Some(rows.storage),
            record_bytes: rows.record_bytes,
            requested_log_bytes: rows.log_bytes,
            sequential_bound: sequential,
            work_bound: limits.max_work,
            terminal_frontier: true,
            frontier: Some(frontier),
            cached_frontier: None,
            cache_attempt_work: 0,
        })
    }
}

const MAX_CACHED_FRONTIERS: usize = 4_096;
const MAX_CACHED_TRANSITIONS: usize = 65_536;
const CACHED_TRANSITION_SLOTS: usize = MAX_CACHED_TRANSITIONS * 2;
const UNCACHED_FRONTIER: u16 = u16::MAX;

fn cached_frontier_words(states: usize) -> Result<usize, Error> {
    add(states, 63, Resource::ScratchBytes)?
        .checked_div(64)
        .ok_or(Error::InternalInvariant("zero cached-frontier word width"))
}

/// Prospective fixed-capacity theorem for the interned Boolean-frontier
/// executor. Every retained cache image owns exactly `ceil(Q / 64)` Boolean
/// words, the transition table has twice the maximum installed entries, and
/// every boundary owns one `u16` image ID or an uncached sentinel. A sentinel
/// is recomputed from the next retained checkpoint during replay, making both
/// caches best-effort accelerators: filling either one cannot change semantics
/// or cause a cache-capacity refusal. No allocation depends on cache hits,
/// collisions, or input contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CachedFrontierRequirements {
    words: usize,
    record_bytes: usize,
    state_word_capacity: usize,
    boundary_count: usize,
    log_bytes: usize,
    random_bytes: usize,
    scratch_bytes: usize,
    peak_bytes: usize,
    sequential_bound: usize,
}

impl CachedFrontierRequirements {
    fn new(states: usize, boundaries: usize, passes: usize) -> Result<Self, Error> {
        let words = cached_frontier_words(states)?;
        let record_bytes = core::mem::size_of::<u16>();
        let state_word_capacity = mul(words, MAX_CACHED_FRONTIERS, Resource::ScratchBytes)?;
        let state_bytes = mul(
            state_word_capacity,
            core::mem::size_of::<u64>(),
            Resource::RandomAccessBytes,
        )?;
        let hash_bytes = mul(
            MAX_CACHED_FRONTIERS,
            core::mem::size_of::<u64>(),
            Resource::ScratchBytes,
        )?;
        let transition_bytes = mul(
            CACHED_TRANSITION_SLOTS,
            core::mem::size_of::<CachedTransitionSlot>(),
            Resource::ScratchBytes,
        )?;
        let candidate_bytes = mul(
            mul(words, 2, Resource::ScratchBytes)?,
            core::mem::size_of::<u64>(),
            Resource::ScratchBytes,
        )?;
        let phase_scratch_bytes = add(
            add(hash_bytes, transition_bytes, Resource::ScratchBytes)?,
            candidate_bytes,
            Resource::ScratchBytes,
        )?;
        let random_bytes = add(
            state_bytes,
            phase_scratch_bytes,
            Resource::RandomAccessBytes,
        )?;
        let scratch_bytes = random_bytes;
        let log_bytes = mul(boundaries, record_bytes, Resource::LogBytes)?;
        let peak_bytes = add(log_bytes, random_bytes, Resource::PeakBytes)?;
        let read_passes = mul(passes, 3, Resource::SequentialBytes)?;
        let sequential_bound = mul(
            log_bytes,
            add(read_passes, 1, Resource::SequentialBytes)?,
            Resource::SequentialBytes,
        )?;
        Ok(Self {
            words,
            record_bytes,
            state_word_capacity,
            boundary_count: boundaries,
            log_bytes,
            random_bytes,
            scratch_bytes,
            peak_bytes,
            sequential_bound,
        })
    }

    fn enforce(self, limits: OperationLimits) -> Result<(), Error> {
        enforce(
            self.random_bytes,
            limits.max_random_access_bytes,
            Resource::RandomAccessBytes,
        )?;
        enforce(
            self.scratch_bytes,
            limits.max_scratch_bytes,
            Resource::ScratchBytes,
        )?;
        enforce(self.log_bytes, limits.max_log_bytes, Resource::LogBytes)?;
        enforce(
            self.sequential_bound,
            limits.max_sequential_bytes,
            Resource::SequentialBytes,
        )?;
        enforce(self.peak_bytes, limits.max_peak_bytes, Resource::PeakBytes)
    }

    fn fits(self, limits: OperationLimits) -> Result<bool, Error> {
        match self.enforce(limits) {
            Ok(()) => Ok(true),
            Err(Error::ResourceLimit {
                resource:
                    Resource::RandomAccessBytes
                    | Resource::ScratchBytes
                    | Resource::LogBytes
                    | Resource::SequentialBytes
                    | Resource::PeakBytes,
                ..
            }) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn initialization_work(self) -> Result<usize, Error> {
        let initialized = add(
            add(
                add(
                    self.boundary_count,
                    self.state_word_capacity,
                    Resource::ExecutionWork,
                )?,
                MAX_CACHED_FRONTIERS,
                Resource::ExecutionWork,
            )?,
            add(
                CACHED_TRANSITION_SLOTS,
                mul(self.words, 2, Resource::ExecutionWork)?,
                Resource::ExecutionWork,
            )?,
            Resource::ExecutionWork,
        )?;
        add(initialized, 6, Resource::ExecutionWork)
    }
}

#[derive(Clone, Copy, Debug)]
struct ReverseRowRequirements {
    storage: RowStorage,
    record_bytes: usize,
    row_bytes: usize,
    log_bytes: usize,
    sequential_bound: usize,
    replay_bound: usize,
}

impl ReverseRowRequirements {
    fn new(program: &Program, boundaries: usize, passes: usize) -> Result<Self, Error> {
        let bits = add(program.split_count, 1, Resource::LogBytes)?;
        let decision_record = ceil_div(bits, 8)?;
        let endpoint_record = encoded_width(boundaries);
        // Equal widths keep the established split/replay certificate. The
        // endpoint form is selected only when it strictly reduces the bounded
        // log, containing this construction change to the refusal it solves.
        let (storage, record_bytes, replay_bound) = if endpoint_record < decision_record {
            (RowStorage::ReachableEndpoints, endpoint_record, 0)
        } else {
            let replay_factor = add(
                4,
                program.max_scalar_search_checks(),
                Resource::ExecutionWork,
            )?;
            let replay = mul(
                mul(
                    mul(program.insts.len(), boundaries, Resource::ExecutionWork)?,
                    replay_factor,
                    Resource::ExecutionWork,
                )?,
                passes,
                Resource::ExecutionWork,
            )?;
            (RowStorage::SplitDecisions, decision_record, replay)
        };
        let log_bytes = mul(record_bytes, boundaries, Resource::LogBytes)?;
        let row_words = mul(program.insts.len(), 2, Resource::RandomAccessBytes)?;
        let row_bytes = mul(
            row_words,
            core::mem::size_of::<usize>(),
            Resource::RandomAccessBytes,
        )?;
        let sequential_bound = mul(
            log_bytes,
            add(passes, 1, Resource::SequentialBytes)?,
            Resource::SequentialBytes,
        )?;
        Ok(Self {
            storage,
            record_bytes,
            row_bytes,
            log_bytes,
            sequential_bound,
            replay_bound,
        })
    }

    fn new_terminal_frontier(
        program: &Program,
        boundaries: usize,
        passes: usize,
    ) -> Result<Self, Error> {
        // The frontier has already selected the exact ordered endpoint for
        // every boundary. Retain that endpoint directly: replaying split
        // decisions would re-walk every program state at every boundary and
        // discard the frontier's prospective candidate bound.
        let record_bytes = encoded_width(boundaries);
        let log_bytes = mul(record_bytes, boundaries, Resource::LogBytes)?;
        let row_words = mul(program.insts.len(), 2, Resource::RandomAccessBytes)?;
        let row_bytes = mul(
            row_words,
            core::mem::size_of::<usize>(),
            Resource::RandomAccessBytes,
        )?;
        let sequential_bound = mul(
            log_bytes,
            add(passes, 1, Resource::SequentialBytes)?,
            Resource::SequentialBytes,
        )?;
        Ok(Self {
            storage: RowStorage::ReachableEndpoints,
            record_bytes,
            row_bytes,
            log_bytes,
            sequential_bound,
            replay_bound: 0,
        })
    }
}

enum Engine {
    Full(FullTable),
    Rows(RowStore),
    SparseRows(RowStore),
    TerminalFrontier(RowStore),
    CachedFrontiers(CachedFrontierStore),
}

impl Engine {
    #[allow(
        clippy::too_many_arguments,
        reason = "engine construction binds the exact program, range, selected route, limits, and accounting"
    )]
    fn build<const OBSERVED_WORK: bool>(
        program: &Program,
        haystack: &[u8],
        assertions: AssertionContext<'_>,
        strategy: Strategy,
        requirements: Requirements,
        sparse_seed: Option<SparseSeed<'_>>,
        limits: OperationLimits,
        accounting: &mut ExecutionAccounting,
    ) -> Result<Self, Error> {
        if requirements.cache_attempt_work != 0 {
            try_charge_frontier_amount(
                accounting,
                requirements.work_bound,
                requirements.cache_attempt_work,
            )?;
        }
        if let Some(cache) = requirements.cached_frontier {
            return CachedFrontierStore::build(
                program,
                haystack,
                assertions,
                requirements,
                cache,
                limits,
                accounting,
            )
            .map(Self::CachedFrontiers);
        }
        match strategy {
            Strategy::FullTable => FullTable::build::<OBSERVED_WORK>(
                program,
                haystack,
                assertions,
                requirements,
                limits,
                accounting,
            )
            .map(Self::Full),
            Strategy::ReverseSequentialRows => match sparse_seed {
                Some(SparseSeed::RequiredSuffixes(seed)) => RowStore::build_sparse(
                    program,
                    haystack,
                    assertions,
                    requirements,
                    seed,
                    limits,
                    accounting,
                )
                .map(Self::SparseRows),
                Some(SparseSeed::TerminalFrontier(seed)) => terminal_frontier::build(
                    program,
                    haystack,
                    assertions,
                    requirements,
                    seed,
                    limits,
                    accounting,
                )
                .map(Self::TerminalFrontier),
                None => RowStore::build::<OBSERVED_WORK>(
                    program,
                    haystack,
                    assertions,
                    requirements,
                    limits,
                    accounting,
                )
                .map(Self::Rows),
            },
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "structural and caller work limits stay explicit at the scan admission boundary"
    )]
    fn scan<const OBSERVED_WORK: bool>(
        &mut self,
        program: &Program,
        haystack: &[u8],
        assertions: AssertionContext<'_>,
        admitted_work_bound: usize,
        caller_work_limit: usize,
        accounting: &mut ExecutionAccounting,
        mut emit: impl FnMut(Span) -> Result<(), Error>,
    ) -> Result<ScanSummary, Error> {
        match self {
            Self::Full(table) => scan_sequence::<OBSERVED_WORK>(
                haystack.len(),
                assertions.base(),
                accounting,
                admitted_work_bound,
                caller_work_limit,
                |start, _| table.selected(program, start),
                &mut emit,
            ),
            Self::Rows(store) => {
                let mut reader = store.reader();
                scan_sequence::<OBSERVED_WORK>(
                    haystack.len(),
                    assertions.base(),
                    accounting,
                    admitted_work_bound,
                    caller_work_limit,
                    |start, accounting| {
                        if reader.storage == RowStorage::ReachableEndpoints {
                            return reader.endpoint(start, accounting);
                        }
                        if !reader.root(start, accounting)? {
                            return Ok(None);
                        }
                        RowStore::replay::<OBSERVED_WORK>(
                            program,
                            haystack,
                            assertions,
                            start,
                            &mut reader,
                            accounting,
                            admitted_work_bound,
                            caller_work_limit,
                        )
                        .map(Some)
                    },
                    &mut emit,
                )
            }
            Self::SparseRows(store) | Self::TerminalFrontier(store) => {
                let mut reader = store.reader();
                scan_sequence_sparse(
                    haystack.len(),
                    assertions.base(),
                    accounting,
                    admitted_work_bound,
                    |start, accounting| {
                        if reader.storage == RowStorage::ReachableEndpoints {
                            return reader.endpoint(start, accounting);
                        }
                        if !reader.root(start, accounting)? {
                            return Ok(None);
                        }
                        RowStore::replay_sparse(
                            program,
                            haystack,
                            assertions,
                            start,
                            &mut reader,
                            accounting,
                            admitted_work_bound,
                        )
                        .map(Some)
                    },
                    &mut emit,
                )
            }
            Self::CachedFrontiers(cache) => cache.scan(
                program,
                haystack,
                assertions,
                accounting,
                admitted_work_bound,
                &mut emit,
            ),
        }
    }

    fn peak_with_output(&self, output_bytes: usize) -> Result<usize, Error> {
        match self {
            Self::Full(table) => add(table.allocated_bytes, output_bytes, Resource::PeakBytes),
            Self::Rows(store) | Self::SparseRows(store) | Self::TerminalFrontier(store) => {
                let build = add(
                    store.allocated_store_bytes,
                    store.build_scratch_bytes,
                    Resource::PeakBytes,
                )?;
                let replay = add(
                    store.allocated_store_bytes,
                    output_bytes,
                    Resource::PeakBytes,
                )?;
                Ok(build.max(replay))
            }
            Self::CachedFrontiers(cache) => {
                let replay = add(cache.replay_bytes, output_bytes, Resource::PeakBytes)?;
                Ok(cache.build_peak_bytes.max(replay))
            }
        }
    }
}

struct FullTable {
    values: Vec<usize>,
    allocated_bytes: usize,
}

impl FullTable {
    #[allow(
        clippy::too_many_lines,
        reason = "the table construction loop keeps every exact work charge beside its transition"
    )]
    fn build<const OBSERVED_WORK: bool>(
        program: &Program,
        haystack: &[u8],
        assertions: AssertionContext<'_>,
        requirements: Requirements,
        limits: OperationLimits,
        accounting: &mut ExecutionAccounting,
    ) -> Result<Self, Error> {
        let mut values = zeroed_usizes(requirements.table_cells, Resource::RandomAccessBytes)?;
        let allocated_bytes = mul(
            values.capacity(),
            core::mem::size_of::<usize>(),
            Resource::RandomAccessBytes,
        )?;
        enforce(
            allocated_bytes,
            limits.max_random_access_bytes,
            Resource::RandomAccessBytes,
        )?;
        enforce(
            allocated_bytes,
            limits.max_scratch_bytes,
            Resource::ScratchBytes,
        )?;
        enforce(allocated_bytes, limits.max_peak_bytes, Resource::PeakBytes)?;
        accounting.random_access_peak_bytes = allocated_bytes;
        accounting.scratch_peak_bytes = allocated_bytes;
        let states = program.insts.len();
        let boundaries = add(haystack.len(), 1, Resource::Boundaries)?;
        let mut row_end = values.len();
        for position in (0..boundaries).rev() {
            let row_start = row_end
                .checked_sub(states)
                .ok_or(Error::InternalInvariant("full-table row underflow"))?;
            let (through_row, later_rows) = values.split_at_mut(row_end);
            let row = through_row
                .get_mut(row_start..)
                .ok_or(Error::InternalInvariant("full-table row outside table"))?;
            // The final input boundary has no successor row, but it also has
            // no input byte and therefore cannot follow a Consume edge.
            let next_row = later_rows.get(..states).unwrap_or(&[]);
            let input = haystack.get(position).copied();
            let scalar = if program.contains_scalar_transition() {
                charge_transition::<OBSERVED_WORK>(
                    accounting,
                    requirements.work_bound,
                    limits.max_work,
                )?;
                haystack.get(position..).and_then(decode_first_scalar)
            } else {
                None
            };
            for &pc in &program.epsilon_order {
                charge_state::<OBSERVED_WORK>(
                    accounting,
                    requirements.work_bound,
                    limits.max_work,
                )?;
                let value = match program.instruction(pc)? {
                    Inst::Unfilled => {
                        return Err(Error::InternalInvariant("unfilled execution state"));
                    }
                    Inst::Fail => 0,
                    Inst::Match => encode(position)?,
                    Inst::Consume { bytes, next } => {
                        charge_transition::<OBSERVED_WORK>(
                            accounting,
                            requirements.work_bound,
                            limits.max_work,
                        )?;
                        if input.is_some_and(|byte| bytes.contains(byte)) {
                            next_row[*next]
                        } else {
                            0
                        }
                    }
                    Inst::ConsumeScalar {
                        scalars,
                        next_by_width,
                    } => {
                        charge_transition::<OBSERVED_WORK>(
                            accounting,
                            requirements.work_bound,
                            limits.max_work,
                        )?;
                        let Some(scalar) = scalar else {
                            row[pc] = 0;
                            continue;
                        };
                        let matches = scalars.contains_with(scalar, || {
                            charge_transition::<OBSERVED_WORK>(
                                accounting,
                                requirements.work_bound,
                                limits.max_work,
                            )
                        })?;
                        if matches {
                            let width_index = scalar.len_utf8().checked_sub(1).ok_or(
                                Error::InternalInvariant("Unicode scalar has zero byte width"),
                            )?;
                            let next =
                                *next_by_width
                                    .get(width_index)
                                    .ok_or(Error::InternalInvariant(
                                        "Unicode scalar width outside dispatch",
                                    ))?;
                            *next_row.get(next).ok_or(Error::InternalInvariant(
                                "scalar successor state outside table row",
                            ))?
                        } else {
                            0
                        }
                    }
                    Inst::Assert { assertion, next } => {
                        charge_assertion::<OBSERVED_WORK>(
                            accounting,
                            requirements.work_bound,
                            limits.max_work,
                        )?;
                        if assertions.is_match(*assertion, position)? {
                            row[*next]
                        } else {
                            0
                        }
                    }
                    Inst::Split {
                        preferred,
                        fallback,
                    } => {
                        charge_transition::<OBSERVED_WORK>(
                            accounting,
                            requirements.work_bound,
                            limits.max_work,
                        )?;
                        let selected = row[*preferred];
                        if selected != 0 {
                            selected
                        } else {
                            charge_transition::<OBSERVED_WORK>(
                                accounting,
                                requirements.work_bound,
                                limits.max_work,
                            )?;
                            row[*fallback]
                        }
                    }
                };
                row[pc] = value;
            }
            row_end = row_start;
        }
        if row_end != 0 {
            return Err(Error::InternalInvariant(
                "full-table rows did not fill table",
            ));
        }
        Ok(Self {
            values,
            allocated_bytes,
        })
    }

    fn selected(&self, program: &Program, start: usize) -> Result<Option<usize>, Error> {
        let value = *self
            .values
            .get(index(start, program.entry, program.insts.len())?)
            .ok_or(Error::InternalInvariant("full-table root outside table"))?;
        Ok(decode(value))
    }
}

struct RowStore {
    bytes: Vec<u8>,
    storage: RowStorage,
    record_bytes: usize,
    allocated_store_bytes: usize,
    build_scratch_bytes: usize,
    root_rank: usize,
}

fn exact_allocation_error(error: CopyError, resource: Resource, items: usize) -> Error {
    match error {
        CopyError::LayoutOverflow => Error::ArithmeticOverflow { resource },
        CopyError::AllocationFailed => Error::AllocationFailed { resource, items },
    }
}

fn exact_filled<T: Copy>(
    length: usize,
    value: T,
    resource: Resource,
) -> Result<ExactVec<T>, Error> {
    let mut values = ExactVec::try_with_capacity(length)
        .map_err(|error| exact_allocation_error(error, resource, length))?;
    for _ in 0..length {
        values
            .try_push(value)
            .map_err(|_| Error::InternalInvariant("exact allocation changed capacity"))?;
    }
    Ok(values)
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct CachedTransitionSlot {
    symbol: u64,
    next_state: u16,
    result_state: u16,
    occupied: bool,
}

impl CachedTransitionSlot {
    const EMPTY: Self = Self {
        symbol: 0,
        next_state: 0,
        result_state: 0,
        occupied: false,
    };
}

fn cached_compute_row(
    program: &Program,
    symbol: u64,
    next_frontier: &[u64],
    row: &mut [u64],
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
) -> Result<(), Error> {
    try_charge_frontier_amount(accounting, admitted_work_bound, row.len())?;
    row.fill(0);
    for &pc in &program.epsilon_order {
        try_charge_state(accounting, admitted_work_bound)?;
        let present =
            match program.instruction(pc)? {
                Inst::Unfilled => {
                    return Err(Error::InternalInvariant(
                        "cached frontier reached an unfilled state",
                    ));
                }
                Inst::Fail => false,
                Inst::Match => cached_symbol_seeded(symbol),
                Inst::Consume { bytes, next } => {
                    try_charge_transition(accounting, admitted_work_bound)?;
                    cached_symbol_byte(symbol).is_some_and(|byte| bytes.contains(byte))
                        && cached_candidate_bit(next_frontier, *next)?
                }
                Inst::ConsumeScalar {
                    scalars,
                    next_by_width,
                } => {
                    try_charge_transition(accounting, admitted_work_bound)?;
                    if let Some(scalar) = cached_symbol_scalar(symbol) {
                        let matches = scalars.contains_with(scalar, || {
                            try_charge_transition(accounting, admitted_work_bound)
                        })?;
                        if matches {
                            let width_index = scalar.len_utf8().checked_sub(1).ok_or(
                                Error::InternalInvariant("Unicode scalar has zero byte width"),
                            )?;
                            let next =
                                *next_by_width
                                    .get(width_index)
                                    .ok_or(Error::InternalInvariant(
                                        "Unicode scalar width outside cached dispatch",
                                    ))?;
                            cached_candidate_bit(next_frontier, next)?
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                Inst::Assert { assertion, next } => {
                    try_charge_transition(accounting, admitted_work_bound)?;
                    cached_symbol_assertion(symbol, *assertion) && cached_candidate_bit(row, *next)?
                }
                Inst::Split {
                    preferred,
                    fallback,
                } => {
                    try_charge_transition(accounting, admitted_work_bound)?;
                    if cached_candidate_bit(row, *preferred)? {
                        true
                    } else {
                        try_charge_transition(accounting, admitted_work_bound)?;
                        cached_candidate_bit(row, *fallback)?
                    }
                }
            };
        if present {
            cached_set_candidate_bit(row, pc)?;
        }
    }
    Ok(())
}

fn cached_replay_scalar(
    scalars: &ScalarSet,
    next_by_width: &[usize; 4],
    haystack: &[u8],
    position: usize,
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
) -> Result<usize, Error> {
    let scalar = haystack
        .get(position..)
        .and_then(decode_first_scalar)
        .ok_or(Error::InternalInvariant(
            "cached frontier replay selected invalid Unicode scalar",
        ))?;
    if !scalars.contains_with(scalar, || {
        try_charge_replay(accounting, admitted_work_bound)
    })? {
        return Err(Error::InternalInvariant(
            "cached frontier replay selected failing Unicode scalar",
        ));
    }
    let width_index = scalar
        .len_utf8()
        .checked_sub(1)
        .ok_or(Error::InternalInvariant(
            "Unicode scalar has zero byte width",
        ))?;
    next_by_width
        .get(width_index)
        .copied()
        .ok_or(Error::InternalInvariant(
            "Unicode scalar width outside cached replay dispatch",
        ))
}

/// Stable Boolean row images plus a bounded transition cache. Liveness is
/// sufficient during the reverse sweep: replay consults the retained row at
/// each boundary and therefore applies preferred/fallback priority exactly at
/// the original decision point.
struct CachedFrontierStore {
    boundary_states: ExactVec<u16>,
    state_bits: ExactVec<u64>,
    replay_current: ExactVec<u64>,
    replay_next: ExactVec<u64>,
    words: usize,
    used_assertions: u32,
    checkpoint_log_bytes_read: usize,
    build_peak_bytes: usize,
    replay_bytes: usize,
}

impl CachedFrontierStore {
    #[allow(
        clippy::too_many_lines,
        reason = "cached-frontier construction keeps its fixed capacity, semantic key, and exact charges together"
    )]
    fn build(
        program: &Program,
        haystack: &[u8],
        assertions: AssertionContext<'_>,
        requirements: Requirements,
        cache: CachedFrontierRequirements,
        limits: OperationLimits,
        accounting: &mut ExecutionAccounting,
    ) -> Result<Self, Error> {
        cache.enforce(limits)?;
        try_charge_frontier_amount(
            accounting,
            requirements.work_bound,
            cache.initialization_work()?,
        )?;
        let mut boundary_states = exact_filled(cache.boundary_count, 0_u16, Resource::LogBytes)?;
        let mut state_bits = exact_filled(
            cache.state_word_capacity,
            0_u64,
            Resource::RandomAccessBytes,
        )?;
        let mut state_hashes = exact_filled(MAX_CACHED_FRONTIERS, 0_u64, Resource::ScratchBytes)?;
        let mut transitions = exact_filled(
            CACHED_TRANSITION_SLOTS,
            CachedTransitionSlot::EMPTY,
            Resource::ScratchBytes,
        )?;
        let mut candidate = exact_filled(cache.words, 0_u64, Resource::ScratchBytes)?;
        let mut next_frontier = exact_filled(cache.words, 0_u64, Resource::ScratchBytes)?;

        // State zero is the all-failing successor beyond the terminal row.
        let mut state_count = 1_usize;
        try_charge_frontier_amount(accounting, requirements.work_bound, 1)?;
        state_hashes[0] = cached_row_hash(&candidate, accounting, requirements.work_bound)?;
        let mut transition_count = 0_usize;
        let mut next_state = Some(0_u16);
        let used_assertions =
            cached_program_assertion_mask(program, accounting, requirements.work_bound)?;
        for position in (0..cache.boundary_count).rev() {
            let symbol = cached_boundary_symbol(
                program,
                assertions,
                haystack,
                position,
                used_assertions,
                accounting,
                requirements.work_bound,
            )?;
            let (cached, slot) = if let Some(state) = next_state {
                let (cached, slot) = cached_transition_lookup(
                    &transitions,
                    state,
                    symbol,
                    accounting,
                    requirements.work_bound,
                )?;
                (cached, Some(slot))
            } else {
                (None, None)
            };
            let current = if let Some(state) = cached {
                let start = mul(usize::from(state), cache.words, Resource::ScratchBytes)?;
                let end = add(start, cache.words, Resource::ScratchBytes)?;
                try_charge_frontier_amount(accounting, requirements.work_bound, cache.words)?;
                candidate.copy_from_slice(state_bits.get(start..end).ok_or(
                    Error::InternalInvariant("cached frontier hit outside retained store"),
                )?);
                Some(state)
            } else {
                cached_compute_row(
                    program,
                    symbol,
                    &next_frontier,
                    &mut candidate,
                    accounting,
                    requirements.work_bound,
                )?;
                let hash = cached_row_hash(&candidate, accounting, requirements.work_bound)?;
                let mut interned = None;
                for state in 0..state_count {
                    try_charge_frontier_amount(accounting, requirements.work_bound, 1)?;
                    if state_hashes[state] != hash {
                        continue;
                    }
                    let start = mul(state, cache.words, Resource::ScratchBytes)?;
                    let end = add(start, cache.words, Resource::ScratchBytes)?;
                    let retained = state_bits.get(start..end).ok_or(Error::InternalInvariant(
                        "cached frontier row outside store",
                    ))?;
                    let mut equal = true;
                    for (&left, &right) in retained.iter().zip(candidate.iter()) {
                        try_charge_frontier_amount(accounting, requirements.work_bound, 1)?;
                        if left != right {
                            equal = false;
                            break;
                        }
                    }
                    if equal {
                        interned = Some(u16::try_from(state).map_err(|_| {
                            Error::InternalInvariant("cached frontier ID does not fit u16")
                        })?);
                        break;
                    }
                }
                let result = if let Some(state) = interned {
                    Some(state)
                } else if state_count < MAX_CACHED_FRONTIERS {
                    let required = add(state_count, 1, Resource::TableCells)?;
                    let start = mul(state_count, cache.words, Resource::ScratchBytes)?;
                    let end = add(start, cache.words, Resource::ScratchBytes)?;
                    try_charge_frontier_amount(accounting, requirements.work_bound, cache.words)?;
                    state_bits
                        .get_mut(start..end)
                        .ok_or(Error::InternalInvariant(
                            "cached frontier insertion outside store",
                        ))?
                        .copy_from_slice(&candidate);
                    try_charge_frontier_amount(accounting, requirements.work_bound, 1)?;
                    state_hashes[state_count] = hash;
                    let state = u16::try_from(state_count).map_err(|_| {
                        Error::InternalInvariant("cached frontier ID does not fit u16")
                    })?;
                    state_count = required;
                    Some(state)
                } else {
                    None
                };
                if let (Some(slot), Some(next_state), Some(result_state)) =
                    (slot, next_state, result)
                    && transition_count < MAX_CACHED_TRANSITIONS
                {
                    let required = add(transition_count, 1, Resource::TableCells)?;
                    try_charge_frontier_amount(accounting, requirements.work_bound, 1)?;
                    transitions[slot] = CachedTransitionSlot {
                        symbol,
                        next_state,
                        result_state,
                        occupied: true,
                    };
                    transition_count = required;
                }
                result
            };
            try_charge_frontier_amount(accounting, requirements.work_bound, 1)?;
            boundary_states[position] = current.unwrap_or(UNCACHED_FRONTIER);
            accounting.sequential_bytes_written = add(
                accounting.sequential_bytes_written,
                core::mem::size_of::<u16>(),
                Resource::SequentialBytes,
            )?;
            core::mem::swap(&mut candidate, &mut next_frontier);
            next_state = current;
        }

        accounting.random_access_peak_bytes = cache.random_bytes;
        accounting.scratch_peak_bytes = cache.scratch_bytes;
        accounting.log_bytes = cache.log_bytes;
        let replay_bytes = add(
            add(
                cache.log_bytes,
                mul(
                    cache.state_word_capacity,
                    core::mem::size_of::<u64>(),
                    Resource::PeakBytes,
                )?,
                Resource::PeakBytes,
            )?,
            mul(
                mul(cache.words, 2, Resource::PeakBytes)?,
                core::mem::size_of::<u64>(),
                Resource::PeakBytes,
            )?,
            Resource::PeakBytes,
        )?;
        drop(transitions);
        drop(state_hashes);
        Ok(Self {
            boundary_states,
            state_bits,
            replay_current: candidate,
            replay_next: next_frontier,
            words: cache.words,
            used_assertions,
            checkpoint_log_bytes_read: 0,
            build_peak_bytes: cache.peak_bytes,
            replay_bytes,
        })
    }

    fn scan(
        &mut self,
        program: &Program,
        haystack: &[u8],
        assertions: AssertionContext<'_>,
        accounting: &mut ExecutionAccounting,
        admitted_work_bound: usize,
        mut emit: impl FnMut(Span) -> Result<(), Error>,
    ) -> Result<ScanSummary, Error> {
        scan_sequence_sparse(
            haystack.len(),
            assertions.base(),
            accounting,
            admitted_work_bound,
            |start, accounting| {
                self.selected(
                    program,
                    haystack,
                    assertions,
                    start,
                    accounting,
                    admitted_work_bound,
                )
            },
            &mut emit,
        )
    }

    fn selected(
        &mut self,
        program: &Program,
        haystack: &[u8],
        assertions: AssertionContext<'_>,
        start: usize,
        accounting: &mut ExecutionAccounting,
        admitted_work_bound: usize,
    ) -> Result<Option<usize>, Error> {
        self.load_boundary(
            program,
            haystack,
            assertions,
            start,
            accounting,
            admitted_work_bound,
        )?;
        if !cached_candidate_bit(&self.replay_current, program.entry)? {
            return Ok(None);
        }
        let mut pc = program.entry;
        let mut position = start;
        loop {
            try_charge_replay(accounting, admitted_work_bound)?;
            match program.instruction(pc)? {
                Inst::Unfilled => {
                    return Err(Error::InternalInvariant(
                        "cached frontier replay reached an unfilled state",
                    ));
                }
                Inst::Fail => {
                    return Err(Error::InternalInvariant(
                        "cached frontier replay selected failure",
                    ));
                }
                Inst::Match => return Ok(Some(position)),
                Inst::Consume { bytes, next } => {
                    if position >= haystack.len() || !bytes.contains(haystack[position]) {
                        return Err(Error::InternalInvariant(
                            "cached frontier replay selected failing byte",
                        ));
                    }
                    position = add(position, 1, Resource::Boundaries)?;
                    self.load_boundary(
                        program,
                        haystack,
                        assertions,
                        position,
                        accounting,
                        admitted_work_bound,
                    )?;
                    pc = *next;
                }
                Inst::ConsumeScalar {
                    scalars,
                    next_by_width,
                } => {
                    pc = cached_replay_scalar(
                        scalars,
                        next_by_width,
                        haystack,
                        position,
                        accounting,
                        admitted_work_bound,
                    )?;
                    position = add(position, 1, Resource::Boundaries)?;
                    self.load_boundary(
                        program,
                        haystack,
                        assertions,
                        position,
                        accounting,
                        admitted_work_bound,
                    )?;
                }
                Inst::Assert { assertion, next } => {
                    try_charge_assertion(accounting, admitted_work_bound)?;
                    if !assertions.is_match(*assertion, position)? {
                        return Err(Error::InternalInvariant(
                            "cached frontier replay selected failing assertion",
                        ));
                    }
                    pc = *next;
                }
                Inst::Split {
                    preferred,
                    fallback,
                } => {
                    pc = if cached_candidate_bit(&self.replay_current, *preferred)? {
                        *preferred
                    } else {
                        *fallback
                    };
                }
            }
        }
    }

    fn load_boundary(
        &mut self,
        program: &Program,
        haystack: &[u8],
        assertions: AssertionContext<'_>,
        position: usize,
        accounting: &mut ExecutionAccounting,
        admitted_work_bound: usize,
    ) -> Result<(), Error> {
        accounting.sequential_bytes_read = add(
            accounting.sequential_bytes_read,
            core::mem::size_of::<u16>(),
            Resource::SequentialBytes,
        )?;
        let first = self
            .boundary_states
            .get(position)
            .copied()
            .ok_or(Error::InternalInvariant(
                "cached frontier boundary outside state stream",
            ))?;
        if first != UNCACHED_FRONTIER {
            return cached_copy_retained_row(
                &self.state_bits,
                self.words,
                first,
                &mut self.replay_current,
                accounting,
                admitted_work_bound,
            );
        }

        let mut checkpoint = add(position, 1, Resource::Boundaries)?;
        loop {
            if checkpoint == self.boundary_states.len() {
                try_charge_frontier_amount(
                    accounting,
                    admitted_work_bound,
                    self.replay_current.len(),
                )?;
                self.replay_current.fill(0);
                break;
            }
            try_charge_frontier_amount(accounting, admitted_work_bound, 1)?;
            self.checkpoint_log_bytes_read = add(
                self.checkpoint_log_bytes_read,
                core::mem::size_of::<u16>(),
                Resource::LogBytes,
            )?;
            let state = *self
                .boundary_states
                .get(checkpoint)
                .ok_or(Error::InternalInvariant(
                    "cached frontier checkpoint outside state stream",
                ))?;
            if state != UNCACHED_FRONTIER {
                cached_copy_retained_row(
                    &self.state_bits,
                    self.words,
                    state,
                    &mut self.replay_current,
                    accounting,
                    admitted_work_bound,
                )?;
                break;
            }
            checkpoint = add(checkpoint, 1, Resource::Boundaries)?;
        }

        for replay_position in (position..checkpoint).rev() {
            core::mem::swap(&mut self.replay_current, &mut self.replay_next);
            let symbol = cached_boundary_symbol(
                program,
                assertions,
                haystack,
                replay_position,
                self.used_assertions,
                accounting,
                admitted_work_bound,
            )?;
            cached_compute_row(
                program,
                symbol,
                &self.replay_next,
                &mut self.replay_current,
                accounting,
                admitted_work_bound,
            )?;
        }
        Ok(())
    }
}

fn cached_transition_lookup(
    slots: &[CachedTransitionSlot],
    next_state: u16,
    symbol: u64,
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
) -> Result<(Option<u16>, usize), Error> {
    try_charge_frontier_amount(accounting, admitted_work_bound, 1)?;
    let mask = slots
        .len()
        .checked_sub(1)
        .ok_or(Error::InternalInvariant("empty cached transition table"))?;
    let mut index = cached_transition_hash(next_state, symbol) & mask;
    for _ in 0..slots.len() {
        try_charge_frontier_amount(accounting, admitted_work_bound, 1)?;
        let slot = slots[index];
        if !slot.occupied {
            return Ok((None, index));
        }
        if slot.next_state == next_state && slot.symbol == symbol {
            return Ok((Some(slot.result_state), index));
        }
        index = index.wrapping_add(1) & mask;
    }
    Err(Error::InternalInvariant(
        "cached transition table has no empty slot",
    ))
}

fn cached_transition_hash(next_state: u16, symbol: u64) -> usize {
    let key = symbol ^ (u64::from(next_state) << 48);
    let mixed = key.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    usize::try_from(mixed ^ (mixed >> 32)).unwrap_or(0)
}

fn cached_row_hash(
    words: &[u64],
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
) -> Result<u64, Error> {
    let mut hash = 0xCBF2_9CE4_8422_2325_u64;
    for &word in words {
        try_charge_frontier_amount(accounting, admitted_work_bound, 1)?;
        hash ^= word;
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    Ok(hash)
}

const CACHED_ASSERTIONS: [Assertion; 18] = [
    Assertion::StartText,
    Assertion::EndText,
    Assertion::StartLf,
    Assertion::EndLf,
    Assertion::StartCrlf,
    Assertion::EndCrlf,
    Assertion::WordAscii,
    Assertion::WordAsciiNegate,
    Assertion::WordStartAscii,
    Assertion::WordEndAscii,
    Assertion::WordStartHalfAscii,
    Assertion::WordEndHalfAscii,
    Assertion::WordUnicode,
    Assertion::WordUnicodeNegate,
    Assertion::WordStartUnicode,
    Assertion::WordEndUnicode,
    Assertion::WordStartHalfUnicode,
    Assertion::WordEndHalfUnicode,
];

const CACHED_ASSERTION_SHIFT: u32 = 9;
const CACHED_SEED_SHIFT: u32 = CACHED_ASSERTION_SHIFT + 18;
const CACHED_SCALAR_SHIFT: u32 = CACHED_SEED_SHIFT + 1;
const CACHED_SCALAR_NONE: u32 = 0x11_0000;

fn cached_boundary_symbol(
    program: &Program,
    assertions: AssertionContext<'_>,
    haystack: &[u8],
    position: usize,
    used_assertions: u32,
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
) -> Result<u64, Error> {
    try_charge_frontier_amount(accounting, admitted_work_bound, 1)?;
    let mut assertion_mask = 0_u64;
    for assertion in CACHED_ASSERTIONS {
        try_charge_frontier_amount(accounting, admitted_work_bound, 1)?;
        let bit = 1_u32 << assertion.identity_tag();
        if used_assertions & bit == 0 {
            continue;
        }
        try_charge_assertion(accounting, admitted_work_bound)?;
        if assertions.is_match(assertion, position)? {
            assertion_mask |= 1_u64 << assertion.identity_tag();
        }
    }
    let seeded = true;
    let byte = if let Some(byte) = haystack.get(position) {
        accounting.random_access_bytes_read = add(
            accounting.random_access_bytes_read,
            1,
            Resource::RandomAccessBytes,
        )?;
        u64::from(*byte)
    } else {
        256_u64
    };
    let scalar = if program.contains_scalar_transition() {
        try_charge_transition(accounting, admitted_work_bound)?;
        let source = haystack.get(position..).unwrap_or_default();
        accounting.random_access_bytes_read = add(
            accounting.random_access_bytes_read,
            cached_scalar_source_accesses(source),
            Resource::RandomAccessBytes,
        )?;
        decode_first_scalar(source).map_or(CACHED_SCALAR_NONE, u32::from)
    } else {
        CACHED_SCALAR_NONE
    };
    Ok(byte
        | (assertion_mask << CACHED_ASSERTION_SHIFT)
        | (u64::from(seeded) << CACHED_SEED_SHIFT)
        | (u64::from(scalar) << CACHED_SCALAR_SHIFT))
}

fn cached_scalar_source_accesses(bytes: &[u8]) -> usize {
    let Some(&first) = bytes.first() else {
        return 0;
    };
    let width = match first {
        0x00..=0x7F => 1,
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => return 1,
    };
    if bytes.len() < width { 1 } else { width }
}

fn cached_program_assertion_mask(
    program: &Program,
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
) -> Result<u32, Error> {
    let mut mask = 0_u32;
    for inst in &program.insts {
        try_charge_frontier_amount(accounting, admitted_work_bound, 1)?;
        if let Inst::Assert { assertion, .. } = inst {
            mask |= 1_u32 << assertion.identity_tag();
        }
    }
    Ok(mask)
}

fn cached_symbol_byte(symbol: u64) -> Option<u8> {
    u8::try_from(symbol & 0x1ff).ok()
}

fn cached_symbol_assertion(symbol: u64, assertion: Assertion) -> bool {
    symbol & (1_u64 << (CACHED_ASSERTION_SHIFT + u32::from(assertion.identity_tag()))) != 0
}

fn cached_symbol_seeded(symbol: u64) -> bool {
    symbol & (1_u64 << CACHED_SEED_SHIFT) != 0
}

fn cached_symbol_scalar(symbol: u64) -> Option<char> {
    let encoded = u32::try_from((symbol >> CACHED_SCALAR_SHIFT) & 0x1f_ffff).ok()?;
    if encoded == CACHED_SCALAR_NONE {
        return None;
    }
    char::from_u32(encoded)
}

fn cached_copy_retained_row(
    rows: &[u64],
    words: usize,
    state: u16,
    target: &mut [u64],
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
) -> Result<(), Error> {
    let start = mul(usize::from(state), words, Resource::ScratchBytes)?;
    let end = add(start, words, Resource::ScratchBytes)?;
    try_charge_frontier_amount(accounting, admitted_work_bound, words)?;
    target.copy_from_slice(rows.get(start..end).ok_or(Error::InternalInvariant(
        "cached frontier state outside store",
    ))?);
    Ok(())
}

fn cached_candidate_bit(row: &[u64], pc: usize) -> Result<bool, Error> {
    row.get(pc / 64)
        .map(|bits| bits & (1_u64 << (pc % 64)) != 0)
        .ok_or(Error::InternalInvariant(
            "cached frontier bit outside candidate row",
        ))
}

fn cached_set_candidate_bit(row: &mut [u64], pc: usize) -> Result<(), Error> {
    let word = row.get_mut(pc / 64).ok_or(Error::InternalInvariant(
        "cached frontier bit outside candidate row",
    ))?;
    *word |= 1_u64 << (pc % 64);
    Ok(())
}

impl RowStore {
    #[allow(
        clippy::too_many_lines,
        reason = "row construction keeps fixed-buffer lifetime and accounting in one audit unit"
    )]
    fn build<const OBSERVED_WORK: bool>(
        program: &Program,
        haystack: &[u8],
        assertions: AssertionContext<'_>,
        requirements: Requirements,
        limits: OperationLimits,
        accounting: &mut ExecutionAccounting,
    ) -> Result<Self, Error> {
        let storage = requirements.row_storage.ok_or(Error::InternalInvariant(
            "reverse rows have no selected record storage",
        ))?;
        let mut store = zeroed_bytes(requirements.requested_log_bytes, Resource::LogBytes)?;
        let allocated_store = store.capacity();
        enforce(allocated_store, limits.max_log_bytes, Resource::LogBytes)?;
        let states = program.insts.len();
        let row_count = 2;
        let mut rows = [Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new()];
        let mut row_words = 0_usize;
        for row in &mut rows[..row_count] {
            *row = zeroed_usizes(states, Resource::RandomAccessBytes)?;
            row_words = add(row_words, row.capacity(), Resource::RandomAccessBytes)?;
        }
        let row_bytes = mul(
            row_words,
            core::mem::size_of::<usize>(),
            Resource::RandomAccessBytes,
        )?;
        let build_scratch = row_bytes;
        enforce(
            build_scratch,
            limits.max_random_access_bytes,
            Resource::RandomAccessBytes,
        )?;
        enforce(
            build_scratch,
            limits.max_scratch_bytes,
            Resource::ScratchBytes,
        )?;
        enforce(
            add(allocated_store, build_scratch, Resource::PeakBytes)?,
            limits.max_peak_bytes,
            Resource::PeakBytes,
        )?;
        // Build the sole boundary without an input byte separately. Every
        // remaining row then has a byte, so every consuming state avoids an
        // `Option` discriminant check in the Q-by-N construction loop.
        let mut write_offset = requirements.record_bytes;
        {
            let terminal_record = store
                .get_mut(..write_offset)
                .ok_or(Error::InternalInvariant("terminal row outside row log"))?;
            let (row, future_rows) = rows[..row_count]
                .split_first_mut()
                .ok_or(Error::InternalInvariant("row ring is empty"))?;
            Self::build_row::<false, OBSERVED_WORK>(
                program,
                haystack,
                assertions,
                haystack.len(),
                0,
                row,
                future_rows,
                terminal_record,
                storage,
                accounting,
                requirements.work_bound,
                limits.max_work,
            )?;
        }
        accounting.sequential_bytes_written = add(
            accounting.sequential_bytes_written,
            requirements.record_bytes,
            Resource::SequentialBytes,
        )?;
        rows[..row_count].rotate_right(1);

        for (position, input) in haystack.iter().copied().enumerate().rev() {
            let end = add(write_offset, requirements.record_bytes, Resource::LogBytes)?;
            let record = store
                .get_mut(write_offset..end)
                .ok_or(Error::InternalInvariant("row-log write outside store"))?;
            let (row, future_rows) = rows[..row_count]
                .split_first_mut()
                .ok_or(Error::InternalInvariant("row ring is empty"))?;
            Self::build_row::<true, OBSERVED_WORK>(
                program,
                haystack,
                assertions,
                position,
                input,
                row,
                future_rows,
                record,
                storage,
                accounting,
                requirements.work_bound,
                limits.max_work,
            )?;
            accounting.sequential_bytes_written = add(
                accounting.sequential_bytes_written,
                requirements.record_bytes,
                Resource::SequentialBytes,
            )?;
            write_offset = end;
            rows[..row_count].rotate_right(1);
        }
        if write_offset != store.len() {
            return Err(Error::InternalInvariant("row-log store length mismatch"));
        }
        accounting.random_access_peak_bytes = build_scratch;
        accounting.scratch_peak_bytes = build_scratch;
        accounting.log_bytes = allocated_store;
        Ok(Self {
            bytes: store,
            storage,
            record_bytes: requirements.record_bytes,
            allocated_store_bytes: allocated_store,
            build_scratch_bytes: build_scratch,
            root_rank: program.split_count,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "sparse reverse construction keeps its complete storage and work certificate local"
    )]
    fn build_sparse(
        program: &Program,
        haystack: &[u8],
        assertions: AssertionContext<'_>,
        requirements: Requirements,
        seed: &RequiredSuffixes,
        limits: OperationLimits,
        accounting: &mut ExecutionAccounting,
    ) -> Result<Self, Error> {
        if seed.is_empty() {
            return Err(Error::InternalInvariant("sparse continuation has no seed"));
        }
        let storage = requirements.row_storage.ok_or(Error::InternalInvariant(
            "sparse continuation has no row storage",
        ))?;
        let mut store = zeroed_bytes(requirements.requested_log_bytes, Resource::LogBytes)?;
        let allocated_store = store.capacity();
        enforce(allocated_store, limits.max_log_bytes, Resource::LogBytes)?;
        let states = program.insts.len();
        let row_words = add(states, states, Resource::RandomAccessBytes)?;
        let mut rows = zeroed_usizes(row_words, Resource::RandomAccessBytes)?;
        let row_bytes = mul(
            rows.capacity(),
            core::mem::size_of::<usize>(),
            Resource::RandomAccessBytes,
        )?;
        let (mut row, mut next_row) = rows.split_at_mut(states);
        let build_scratch = row_bytes;
        enforce(
            build_scratch,
            limits.max_random_access_bytes,
            Resource::RandomAccessBytes,
        )?;
        enforce(
            build_scratch,
            limits.max_scratch_bytes,
            Resource::ScratchBytes,
        )?;
        enforce(
            add(allocated_store, build_scratch, Resource::PeakBytes)?,
            limits.max_peak_bytes,
            Resource::PeakBytes,
        )?;

        let mut write_offset = requirements.record_bytes;
        let mut next_any = {
            let terminal_record = store
                .get_mut(..write_offset)
                .ok_or(Error::InternalInvariant(
                    "terminal row outside sparse row log",
                ))?;
            Self::build_sparse_row(
                program,
                haystack,
                assertions,
                haystack.len(),
                None,
                seed,
                row,
                next_row,
                false,
                terminal_record,
                storage,
                accounting,
                requirements.work_bound,
            )?
        };
        accounting.sequential_bytes_written = add(
            accounting.sequential_bytes_written,
            requirements.record_bytes,
            Resource::SequentialBytes,
        )?;
        core::mem::swap(&mut row, &mut next_row);

        for (position, input) in haystack.iter().copied().enumerate().rev() {
            let end = add(write_offset, requirements.record_bytes, Resource::LogBytes)?;
            let record = store
                .get_mut(write_offset..end)
                .ok_or(Error::InternalInvariant(
                    "sparse row-log write outside store",
                ))?;
            let row_any = Self::build_sparse_row(
                program,
                haystack,
                assertions,
                position,
                Some(input),
                seed,
                row,
                next_row,
                next_any,
                record,
                storage,
                accounting,
                requirements.work_bound,
            )?;
            accounting.sequential_bytes_written = add(
                accounting.sequential_bytes_written,
                requirements.record_bytes,
                Resource::SequentialBytes,
            )?;
            write_offset = end;
            core::mem::swap(&mut row, &mut next_row);
            next_any = row_any;
        }
        if write_offset != store.len() {
            return Err(Error::InternalInvariant(
                "sparse row-log store length mismatch",
            ));
        }
        accounting.random_access_peak_bytes = build_scratch;
        accounting.scratch_peak_bytes = build_scratch;
        accounting.log_bytes = allocated_store;
        Ok(Self {
            bytes: store,
            storage,
            record_bytes: requirements.record_bytes,
            allocated_store_bytes: allocated_store,
            build_scratch_bytes: build_scratch,
            root_rank: program.split_count,
        })
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "one sparse-row boundary exposes every proof input and owned buffer"
    )]
    fn build_sparse_row(
        program: &Program,
        haystack: &[u8],
        assertions: AssertionContext<'_>,
        position: usize,
        input: Option<u8>,
        seed: &RequiredSuffixes,
        row: &mut [usize],
        next_row: &[usize],
        next_any: bool,
        record: &mut [u8],
        storage: RowStorage,
        accounting: &mut ExecutionAccounting,
        admitted_work_bound: usize,
    ) -> Result<bool, Error> {
        let seeded =
            sparse_seed_matches(seed, haystack, position, accounting, admitted_work_bound)?;
        // A required suffix can only make Match live at a suffix-ending
        // boundary. If neither that seed nor the successor row is live, this
        // entire row is provably zero. The row buffer may retain old values,
        // but every state is overwritten before a later nonempty row reads it.
        if !seeded && !next_any {
            return Ok(false);
        }
        let scalar = if next_any && program.contains_scalar_transition() {
            try_charge_transition(accounting, admitted_work_bound)?;
            haystack.get(position..).and_then(decode_first_scalar)
        } else {
            None
        };
        let mut row_any = false;
        for &pc in &program.epsilon_order {
            try_charge_state(accounting, admitted_work_bound)?;
            let value =
                match program.instruction(pc)? {
                    Inst::Unfilled => {
                        return Err(Error::InternalInvariant("unfilled sparse execution state"));
                    }
                    Inst::Fail => 0,
                    Inst::Match => {
                        if seeded {
                            encode(position)?
                        } else {
                            0
                        }
                    }
                    Inst::Consume { bytes, next } => {
                        try_charge_transition(accounting, admitted_work_bound)?;
                        if next_any && input.is_some_and(|byte| bytes.contains(byte)) {
                            next_row[*next]
                        } else {
                            0
                        }
                    }
                    Inst::ConsumeScalar {
                        scalars,
                        next_by_width,
                    } => {
                        try_charge_transition(accounting, admitted_work_bound)?;
                        if !next_any {
                            row[pc] = 0;
                            continue;
                        }
                        let Some(scalar) = scalar else {
                            row[pc] = 0;
                            continue;
                        };
                        let matches = scalars.contains_with(scalar, || {
                            try_charge_transition(accounting, admitted_work_bound)
                        })?;
                        if matches {
                            let width_index = scalar.len_utf8().checked_sub(1).ok_or(
                                Error::InternalInvariant("Unicode scalar has zero byte width"),
                            )?;
                            let next =
                                *next_by_width
                                    .get(width_index)
                                    .ok_or(Error::InternalInvariant(
                                        "Unicode scalar width outside dispatch",
                                    ))?;
                            *next_row.get(next).ok_or(Error::InternalInvariant(
                                "scalar successor state outside sparse row",
                            ))?
                        } else {
                            0
                        }
                    }
                    Inst::Assert { assertion, next } => {
                        try_charge_assertion(accounting, admitted_work_bound)?;
                        if assertions.is_match(*assertion, position)? {
                            row[*next]
                        } else {
                            0
                        }
                    }
                    Inst::Split {
                        preferred,
                        fallback,
                    } => {
                        try_charge_transition(accounting, admitted_work_bound)?;
                        let preferred_value = row[*preferred];
                        if preferred_value != 0 {
                            if storage == RowStorage::SplitDecisions {
                                let rank = program.split_rank[pc];
                                if rank == NO_SPLIT_RANK {
                                    return Err(Error::InternalInvariant(
                                        "sparse split state has no decision rank",
                                    ));
                                }
                                set_bit(record, rank)?;
                            }
                            preferred_value
                        } else {
                            try_charge_transition(accounting, admitted_work_bound)?;
                            row[*fallback]
                        }
                    }
                };
            row[pc] = value;
            row_any |= value != 0;
        }
        match storage {
            RowStorage::SplitDecisions => {
                if row[program.entry] != 0 {
                    set_bit(record, program.split_count)?;
                }
            }
            RowStorage::ReachableEndpoints => write_encoded(record, row[program.entry])?,
        }
        Ok(row_any)
    }

    #[inline]
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the specialized row loop keeps borrowed buffers and exact accounting explicit"
    )]
    fn build_row<const HAS_INPUT: bool, const OBSERVED_WORK: bool>(
        program: &Program,
        haystack: &[u8],
        assertions: AssertionContext<'_>,
        position: usize,
        input: u8,
        row: &mut [usize],
        future_rows: &[Vec<usize>],
        record: &mut [u8],
        storage: RowStorage,
        accounting: &mut ExecutionAccounting,
        admitted_work_bound: usize,
        caller_work_limit: usize,
    ) -> Result<(), Error> {
        let scalar = if program.contains_scalar_transition() {
            charge_transition::<OBSERVED_WORK>(accounting, admitted_work_bound, caller_work_limit)?;
            if HAS_INPUT {
                haystack.get(position..).and_then(decode_first_scalar)
            } else {
                None
            }
        } else {
            None
        };
        let next_row = future_rows.first().map(Vec::as_slice).unwrap_or_default();
        for &pc in &program.epsilon_order {
            charge_state::<OBSERVED_WORK>(accounting, admitted_work_bound, caller_work_limit)?;
            let value =
                match program.instruction(pc)? {
                    Inst::Unfilled => {
                        return Err(Error::InternalInvariant("unfilled execution state"));
                    }
                    Inst::Fail => 0,
                    Inst::Consume { bytes, next } => {
                        charge_transition::<OBSERVED_WORK>(
                            accounting,
                            admitted_work_bound,
                            caller_work_limit,
                        )?;
                        if HAS_INPUT && bytes.contains(input) {
                            next_row[*next]
                        } else {
                            0
                        }
                    }
                    Inst::ConsumeScalar {
                        scalars,
                        next_by_width,
                    } => {
                        charge_transition::<OBSERVED_WORK>(
                            accounting,
                            admitted_work_bound,
                            caller_work_limit,
                        )?;
                        let Some(scalar) = scalar else {
                            row[pc] = 0;
                            continue;
                        };
                        let matches = scalars.contains_with(scalar, || {
                            charge_transition::<OBSERVED_WORK>(
                                accounting,
                                admitted_work_bound,
                                caller_work_limit,
                            )
                        })?;
                        if matches {
                            let width_index = scalar.len_utf8().checked_sub(1).ok_or(
                                Error::InternalInvariant("Unicode scalar has zero byte width"),
                            )?;
                            let next =
                                *next_by_width
                                    .get(width_index)
                                    .ok_or(Error::InternalInvariant(
                                        "Unicode scalar width outside dispatch",
                                    ))?;
                            *next_row.get(next).ok_or(Error::InternalInvariant(
                                "scalar successor state outside row ring",
                            ))?
                        } else {
                            0
                        }
                    }
                    Inst::Match => encode(position)?,
                    Inst::Assert { assertion, next } => {
                        charge_assertion::<OBSERVED_WORK>(
                            accounting,
                            admitted_work_bound,
                            caller_work_limit,
                        )?;
                        if assertions.is_match(*assertion, position)? {
                            row[*next]
                        } else {
                            0
                        }
                    }
                    Inst::Split {
                        preferred,
                        fallback,
                    } => {
                        charge_transition::<OBSERVED_WORK>(
                            accounting,
                            admitted_work_bound,
                            caller_work_limit,
                        )?;
                        let preferred_value = row[*preferred];
                        let rank = program.split_rank[pc];
                        if rank == NO_SPLIT_RANK {
                            return Err(Error::InternalInvariant(
                                "split state has no decision rank",
                            ));
                        }
                        if preferred_value != 0 {
                            if storage == RowStorage::SplitDecisions {
                                set_bit(record, rank)?;
                            }
                            preferred_value
                        } else {
                            charge_transition::<OBSERVED_WORK>(
                                accounting,
                                admitted_work_bound,
                                caller_work_limit,
                            )?;
                            row[*fallback]
                        }
                    }
                };
            row[pc] = value;
        }
        match storage {
            RowStorage::SplitDecisions => {
                if row[program.entry] != 0 {
                    set_bit(record, program.split_count)?;
                }
            }
            RowStorage::ReachableEndpoints => write_encoded(record, row[program.entry])?,
        }
        Ok(())
    }

    fn reader(&self) -> RowReader<'_> {
        RowReader {
            store: &self.bytes,
            storage: self.storage,
            record_bytes: self.record_bytes,
            current_record: &[],
            current_position: None,
            current_start: self.bytes.len(),
            root_rank: self.root_rank,
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "structural and caller work limits stay explicit during sequential replay"
    )]
    fn replay<const OBSERVED_WORK: bool>(
        program: &Program,
        haystack: &[u8],
        assertions: AssertionContext<'_>,
        start: usize,
        reader: &mut RowReader<'_>,
        accounting: &mut ExecutionAccounting,
        admitted_work_bound: usize,
        caller_work_limit: usize,
    ) -> Result<usize, Error> {
        let mut pc = program.entry;
        let mut position = start;
        loop {
            charge_replay::<OBSERVED_WORK>(accounting, admitted_work_bound, caller_work_limit)?;
            match program.instruction(pc)? {
                Inst::Unfilled => {
                    return Err(Error::InternalInvariant("unfilled replay state"));
                }
                Inst::Fail => {
                    return Err(Error::InternalInvariant("row log replayed a failing state"));
                }
                Inst::Match => return Ok(position),
                Inst::Consume { bytes, next } => {
                    if position >= haystack.len() || !bytes.contains(haystack[position]) {
                        return Err(Error::InternalInvariant(
                            "row log selected failing byte path",
                        ));
                    }
                    position = add(position, 1, Resource::Boundaries)?;
                    pc = *next;
                }
                Inst::ConsumeScalar {
                    scalars,
                    next_by_width,
                } => {
                    let scalar = haystack
                        .get(position..)
                        .and_then(decode_first_scalar)
                        .ok_or(Error::InternalInvariant(
                            "row log selected invalid Unicode scalar path",
                        ))?;
                    let matches = scalars.contains_with(scalar, || {
                        charge_replay::<OBSERVED_WORK>(
                            accounting,
                            admitted_work_bound,
                            caller_work_limit,
                        )
                    })?;
                    if !matches {
                        return Err(Error::InternalInvariant(
                            "row log selected failing Unicode scalar path",
                        ));
                    }
                    let width_index =
                        scalar
                            .len_utf8()
                            .checked_sub(1)
                            .ok_or(Error::InternalInvariant(
                                "Unicode scalar has zero byte width",
                            ))?;
                    pc = *next_by_width
                        .get(width_index)
                        .ok_or(Error::InternalInvariant(
                            "Unicode scalar width outside dispatch",
                        ))?;
                    position = add(position, 1, Resource::Boundaries)?;
                }
                Inst::Assert { assertion, next } => {
                    charge_assertion::<OBSERVED_WORK>(
                        accounting,
                        admitted_work_bound,
                        caller_work_limit,
                    )?;
                    if !assertions.is_match(*assertion, position)? {
                        return Err(Error::InternalInvariant(
                            "row log selected failing assertion",
                        ));
                    }
                    pc = *next;
                }
                Inst::Split {
                    preferred,
                    fallback,
                } => {
                    let rank = program.split_rank[pc];
                    if rank == NO_SPLIT_RANK {
                        return Err(Error::InternalInvariant("split state has no decision rank"));
                    }
                    pc = if reader.decision(position, rank, accounting)? {
                        *preferred
                    } else {
                        *fallback
                    };
                }
            }
        }
    }

    fn replay_sparse(
        program: &Program,
        haystack: &[u8],
        assertions: AssertionContext<'_>,
        start: usize,
        reader: &mut RowReader<'_>,
        accounting: &mut ExecutionAccounting,
        admitted_work_bound: usize,
    ) -> Result<usize, Error> {
        let mut pc = program.entry;
        let mut position = start;
        loop {
            try_charge_replay(accounting, admitted_work_bound)?;
            match program.instruction(pc)? {
                Inst::Unfilled => {
                    return Err(Error::InternalInvariant("unfilled sparse replay state"));
                }
                Inst::Fail => {
                    return Err(Error::InternalInvariant(
                        "sparse row log replayed a failing state",
                    ));
                }
                Inst::Match => return Ok(position),
                Inst::Consume { bytes, next } => {
                    if position >= haystack.len() || !bytes.contains(haystack[position]) {
                        return Err(Error::InternalInvariant(
                            "sparse row log selected failing byte path",
                        ));
                    }
                    position = add(position, 1, Resource::Boundaries)?;
                    pc = *next;
                }
                Inst::ConsumeScalar {
                    scalars,
                    next_by_width,
                } => {
                    let scalar = haystack
                        .get(position..)
                        .and_then(decode_first_scalar)
                        .ok_or(Error::InternalInvariant(
                            "sparse row log selected invalid Unicode scalar path",
                        ))?;
                    let matches = scalars.contains_with(scalar, || {
                        try_charge_replay(accounting, admitted_work_bound)
                    })?;
                    if !matches {
                        return Err(Error::InternalInvariant(
                            "sparse row log selected failing Unicode scalar path",
                        ));
                    }
                    let width_index =
                        scalar
                            .len_utf8()
                            .checked_sub(1)
                            .ok_or(Error::InternalInvariant(
                                "Unicode scalar has zero byte width",
                            ))?;
                    pc = *next_by_width
                        .get(width_index)
                        .ok_or(Error::InternalInvariant(
                            "Unicode scalar width outside dispatch",
                        ))?;
                    position = add(position, 1, Resource::Boundaries)?;
                }
                Inst::Assert { assertion, next } => {
                    try_charge_assertion(accounting, admitted_work_bound)?;
                    if !assertions.is_match(*assertion, position)? {
                        return Err(Error::InternalInvariant(
                            "sparse row log selected failing assertion",
                        ));
                    }
                    pc = *next;
                }
                Inst::Split {
                    preferred,
                    fallback,
                } => {
                    let rank = program.split_rank[pc];
                    if rank == NO_SPLIT_RANK {
                        return Err(Error::InternalInvariant(
                            "sparse split state has no decision rank",
                        ));
                    }
                    pc = if reader.decision(position, rank, accounting)? {
                        *preferred
                    } else {
                        *fallback
                    };
                }
            }
        }
    }
}

struct RowReader<'a> {
    store: &'a [u8],
    storage: RowStorage,
    record_bytes: usize,
    current_record: &'a [u8],
    current_position: Option<usize>,
    current_start: usize,
    root_rank: usize,
}

impl RowReader<'_> {
    fn endpoint(
        &mut self,
        position: usize,
        accounting: &mut ExecutionAccounting,
    ) -> Result<Option<usize>, Error> {
        if self.storage != RowStorage::ReachableEndpoints {
            return Err(Error::InternalInvariant(
                "split-decision row read as reachable endpoint",
            ));
        }
        self.ensure(position, accounting)?;
        read_encoded(self.current_record).map(decode)
    }

    fn root(
        &mut self,
        position: usize,
        accounting: &mut ExecutionAccounting,
    ) -> Result<bool, Error> {
        if self.storage != RowStorage::SplitDecisions {
            return Err(Error::InternalInvariant(
                "reachable-endpoint row read as split decisions",
            ));
        }
        self.ensure(position, accounting)?;
        read_bit(self.current_record, self.root_rank)
    }

    fn decision(
        &mut self,
        position: usize,
        rank: usize,
        accounting: &mut ExecutionAccounting,
    ) -> Result<bool, Error> {
        if self.storage != RowStorage::SplitDecisions {
            return Err(Error::InternalInvariant(
                "reachable-endpoint row replayed as split decisions",
            ));
        }
        self.ensure(position, accounting)?;
        read_bit(self.current_record, rank)
    }

    fn ensure(
        &mut self,
        position: usize,
        accounting: &mut ExecutionAccounting,
    ) -> Result<(), Error> {
        if self.current_position == Some(position) {
            return Ok(());
        }
        if self
            .current_position
            .is_some_and(|current| position < current)
        {
            return Err(Error::InternalInvariant("row-log reader moved backward"));
        }
        let traversed_records = match self.current_position {
            Some(current) => position
                .checked_sub(current)
                .ok_or(Error::InternalInvariant("row-log position underflow"))?,
            None => add(position, 1, Resource::SequentialBytes)?,
        };
        let traversed = mul(
            traversed_records,
            self.record_bytes,
            Resource::SequentialBytes,
        )?;
        accounting.sequential_bytes_read = add(
            accounting.sequential_bytes_read,
            traversed,
            Resource::SequentialBytes,
        )?;
        let start = self
            .current_start
            .checked_sub(traversed)
            .ok_or(Error::InternalInvariant("row-log seek outside store"))?;
        let end = add(start, self.record_bytes, Resource::LogBytes)?;
        self.current_record = self
            .store
            .get(start..end)
            .ok_or(Error::InternalInvariant("row-log read outside store"))?;
        self.current_position = Some(position);
        self.current_start = start;
        Ok(())
    }
}

fn scan_sequence<const OBSERVED_WORK: bool>(
    haystack_len: usize,
    base: usize,
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
    caller_work_limit: usize,
    mut selected: impl FnMut(usize, &mut ExecutionAccounting) -> Result<Option<usize>, Error>,
    emit: &mut impl FnMut(Span) -> Result<(), Error>,
) -> Result<ScanSummary, Error> {
    let mut summary = ScanSummary::empty();
    let mut cursor = 0_usize;
    let mut previous_end = None;
    while cursor <= haystack_len {
        let mut start = cursor;
        let found = loop {
            if start > haystack_len {
                break None;
            }
            charge_root::<OBSERVED_WORK>(accounting, admitted_work_bound, caller_work_limit)?;
            if let Some(end) = selected(start, accounting)? {
                if end < start || end > haystack_len {
                    return Err(Error::InternalInvariant("selected endpoint outside input"));
                }
                break Some((start, end));
            }
            start = start.saturating_add(1);
        };
        let Some((start, end)) = found else {
            break;
        };
        charge_event::<OBSERVED_WORK>(accounting, admitted_work_bound, caller_work_limit)?;
        summary.events = add(summary.events, 1, Resource::MatchEvents)?;
        if start == end && previous_end == Some(start) {
            summary.suppressed = add(summary.suppressed, 1, Resource::MatchEvents)?;
            accounting.suppressed_empty =
                add(accounting.suppressed_empty, 1, Resource::MatchEvents)?;
            let Some(next) = start.checked_add(1) else {
                break;
            };
            cursor = next;
            continue;
        }
        let absolute_start = add(base, start, Resource::Boundaries)?;
        let absolute_end = add(base, end, Resource::Boundaries)?;
        let span = Span {
            start: absolute_start,
            end: absolute_end,
        };
        emit(span)?;
        summary.matches = add(summary.matches, 1, Resource::OutputMatches)?;
        let width = end
            .checked_sub(start)
            .ok_or(Error::InternalInvariant("match endpoint precedes start"))?;
        summary.span_sum = add(summary.span_sum, width, Resource::SpanSum)?;
        previous_end = Some(end);
        cursor = end;
    }
    Ok(summary)
}

fn scan_sequence_sparse(
    haystack_len: usize,
    base: usize,
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
    mut selected: impl FnMut(usize, &mut ExecutionAccounting) -> Result<Option<usize>, Error>,
    emit: &mut impl FnMut(Span) -> Result<(), Error>,
) -> Result<ScanSummary, Error> {
    let mut summary = ScanSummary::empty();
    let mut cursor = 0_usize;
    let mut previous_end = None;
    while cursor <= haystack_len {
        let mut start = cursor;
        let found = loop {
            if start > haystack_len {
                break None;
            }
            try_charge_root(accounting, admitted_work_bound)?;
            if let Some(end) = selected(start, accounting)? {
                if end < start || end > haystack_len {
                    return Err(Error::InternalInvariant(
                        "sparse selected endpoint outside input",
                    ));
                }
                break Some((start, end));
            }
            start = start.saturating_add(1);
        };
        let Some((start, end)) = found else {
            break;
        };
        try_charge_event(accounting, admitted_work_bound)?;
        summary.events = add(summary.events, 1, Resource::MatchEvents)?;
        if start == end && previous_end == Some(start) {
            summary.suppressed = add(summary.suppressed, 1, Resource::MatchEvents)?;
            accounting.suppressed_empty =
                add(accounting.suppressed_empty, 1, Resource::MatchEvents)?;
            let Some(next) = start.checked_add(1) else {
                break;
            };
            cursor = next;
            continue;
        }
        let absolute_start = add(base, start, Resource::Boundaries)?;
        let absolute_end = add(base, end, Resource::Boundaries)?;
        emit(Span {
            start: absolute_start,
            end: absolute_end,
        })?;
        summary.matches = add(summary.matches, 1, Resource::OutputMatches)?;
        summary.span_sum = add(
            summary.span_sum,
            end.checked_sub(start)
                .ok_or(Error::InternalInvariant("sparse endpoint precedes start"))?,
            Resource::SpanSum,
        )?;
        previous_end = Some(end);
        cursor = end;
    }
    Ok(summary)
}

fn sparse_seed_matches(
    seed: &RequiredSuffixes,
    haystack: &[u8],
    end: usize,
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
) -> Result<bool, Error> {
    for suffix in seed.iter() {
        try_charge_transition_amount(
            accounting,
            admitted_work_bound,
            add(suffix.len(), 1, Resource::ExecutionWork)?,
        )?;
        let start = end.checked_sub(suffix.len());
        if start
            .and_then(|start| haystack.get(start..end))
            .is_some_and(|got| got == suffix)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

// `Requirements::new` checked the sum of every possible construction, scan
// and replay charge before allocation. Consequently each actual counter and
// their sum fit in `usize` and cannot reach the structural bound's successor.
// Diagnostic result admission rejects a caller limit below that conservative
// bound before work starts. Value-only reducers instead check each exact
// observed charge against the caller limit; the const branch is erased from
// the established diagnostic path.
#[inline]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "the structural whole-operation bound proves every actual counter fits"
)]
fn charge<const OBSERVED_WORK: bool>(
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
    caller_work_limit: usize,
) -> Result<(), Error> {
    debug_assert!(accounting.work < admitted_work_bound);
    if OBSERVED_WORK {
        enforce(
            add(accounting.work, 1, Resource::ExecutionWork)?,
            caller_work_limit,
            Resource::ExecutionWork,
        )?;
    }
    accounting.work += 1;
    Ok(())
}

#[inline]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "state evaluations are a subset of the admitted whole-operation work bound"
)]
fn charge_state<const OBSERVED_WORK: bool>(
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
    caller_work_limit: usize,
) -> Result<(), Error> {
    charge::<OBSERVED_WORK>(accounting, admitted_work_bound, caller_work_limit)?;
    accounting.state_evaluations += 1;
    Ok(())
}

#[inline]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "transition checks are a subset of the admitted whole-operation work bound"
)]
fn charge_transition<const OBSERVED_WORK: bool>(
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
    caller_work_limit: usize,
) -> Result<(), Error> {
    charge::<OBSERVED_WORK>(accounting, admitted_work_bound, caller_work_limit)?;
    accounting.transition_checks += 1;
    Ok(())
}

#[inline]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "assertion checks are a subset of admitted transition checks"
)]
fn charge_assertion<const OBSERVED_WORK: bool>(
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
    caller_work_limit: usize,
) -> Result<(), Error> {
    charge_transition::<OBSERVED_WORK>(accounting, admitted_work_bound, caller_work_limit)?;
    accounting.assertion_checks += 1;
    Ok(())
}

#[inline]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "root probes are a subset of the admitted whole-operation work bound"
)]
fn charge_root<const OBSERVED_WORK: bool>(
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
    caller_work_limit: usize,
) -> Result<(), Error> {
    charge::<OBSERVED_WORK>(accounting, admitted_work_bound, caller_work_limit)?;
    accounting.root_probes += 1;
    Ok(())
}

#[inline]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "replay steps are a subset of the admitted whole-operation work bound"
)]
fn charge_replay<const OBSERVED_WORK: bool>(
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
    caller_work_limit: usize,
) -> Result<(), Error> {
    charge::<OBSERVED_WORK>(accounting, admitted_work_bound, caller_work_limit)?;
    accounting.replay_steps += 1;
    Ok(())
}

#[inline]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "successful paths are a subset of the admitted whole-operation work bound"
)]
fn charge_event<const OBSERVED_WORK: bool>(
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
    caller_work_limit: usize,
) -> Result<(), Error> {
    charge::<OBSERVED_WORK>(accounting, admitted_work_bound, caller_work_limit)?;
    accounting.successful_paths += 1;
    Ok(())
}

fn try_charge_amount(
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
    amount: usize,
) -> Result<(), Error> {
    let required = add(accounting.work, amount, Resource::ExecutionWork)?;
    enforce(required, admitted_work_bound, Resource::ExecutionWork)?;
    accounting.work = required;
    Ok(())
}

fn try_charge_frontier_amount(
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
    amount: usize,
) -> Result<(), Error> {
    accounting.frontier_bookkeeping = add(
        accounting.frontier_bookkeeping,
        amount,
        Resource::ExecutionWork,
    )?;
    try_charge_amount(accounting, admitted_work_bound, amount)
}

fn try_charge_state(
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
) -> Result<(), Error> {
    accounting.state_evaluations = add(accounting.state_evaluations, 1, Resource::ExecutionWork)?;
    try_charge_amount(accounting, admitted_work_bound, 1)
}

fn try_charge_transition(
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
) -> Result<(), Error> {
    try_charge_transition_amount(accounting, admitted_work_bound, 1)
}

fn try_charge_transition_amount(
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
    amount: usize,
) -> Result<(), Error> {
    accounting.transition_checks = add(
        accounting.transition_checks,
        amount,
        Resource::ExecutionWork,
    )?;
    try_charge_amount(accounting, admitted_work_bound, amount)
}

fn try_charge_assertion(
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
) -> Result<(), Error> {
    accounting.assertion_checks = add(accounting.assertion_checks, 1, Resource::ExecutionWork)?;
    try_charge_transition(accounting, admitted_work_bound)
}

fn try_charge_root(
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
) -> Result<(), Error> {
    accounting.root_probes = add(accounting.root_probes, 1, Resource::ExecutionWork)?;
    try_charge_amount(accounting, admitted_work_bound, 1)
}

fn try_charge_replay(
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
) -> Result<(), Error> {
    accounting.replay_steps = add(accounting.replay_steps, 1, Resource::ExecutionWork)?;
    try_charge_amount(accounting, admitted_work_bound, 1)
}

fn try_charge_event(
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
) -> Result<(), Error> {
    accounting.successful_paths = add(accounting.successful_paths, 1, Resource::ExecutionWork)?;
    try_charge_amount(accounting, admitted_work_bound, 1)
}

fn validate_admitted_work(
    accounting: &ExecutionAccounting,
    admitted_work_bound: usize,
    caller_limit: usize,
) -> Result<(), Error> {
    let observed = add(
        accounting.utf8_validation_work,
        add(
            add(
                add(
                    accounting.state_evaluations,
                    accounting.transition_checks,
                    Resource::ExecutionWork,
                )?,
                accounting.root_probes,
                Resource::ExecutionWork,
            )?,
            add(
                add(
                    accounting.replay_steps,
                    accounting.successful_paths,
                    Resource::ExecutionWork,
                )?,
                accounting.frontier_bookkeeping,
                Resource::ExecutionWork,
            )?,
            Resource::ExecutionWork,
        )?,
        Resource::ExecutionWork,
    )?;
    if observed != accounting.work {
        return Err(Error::InternalInvariant(
            "admitted work counters do not sum to observed work",
        ));
    }
    enforce(observed, admitted_work_bound, Resource::ExecutionWork)?;
    enforce(observed, caller_limit, Resource::ExecutionWork)
}

fn index(position: usize, state: usize, states: usize) -> Result<usize, Error> {
    add(
        mul(position, states, Resource::TableCells)?,
        state,
        Resource::TableCells,
    )
}

fn encode(end: usize) -> Result<usize, Error> {
    add(end, 1, Resource::Boundaries)
}

fn decode(encoded: usize) -> Option<usize> {
    encoded.checked_sub(1)
}

fn ceil_div(value: usize, divisor: usize) -> Result<usize, Error> {
    let adjustment = divisor
        .checked_sub(1)
        .ok_or(Error::InternalInvariant("zero row-log divisor"))?;
    add(value, adjustment, Resource::LogBytes)?
        .checked_div(divisor)
        .ok_or(Error::InternalInvariant("zero row-log divisor"))
}

fn encoded_width(maximum: usize) -> usize {
    maximum
        .to_le_bytes()
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(1, |index| index.saturating_add(1))
}

fn write_encoded(record: &mut [u8], value: usize) -> Result<(), Error> {
    let encoded = value.to_le_bytes();
    let source = encoded.get(..record.len()).ok_or(Error::InternalInvariant(
        "endpoint record exceeds word width",
    ))?;
    if encoded
        .get(record.len()..)
        .ok_or(Error::InternalInvariant(
            "endpoint record exceeds word width",
        ))?
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(Error::InternalInvariant(
            "reachable endpoint exceeds admitted record width",
        ));
    }
    record.copy_from_slice(source);
    Ok(())
}

fn read_encoded(record: &[u8]) -> Result<usize, Error> {
    let mut encoded = [0_u8; core::mem::size_of::<usize>()];
    let target = encoded
        .get_mut(..record.len())
        .ok_or(Error::InternalInvariant(
            "endpoint record exceeds word width",
        ))?;
    target.copy_from_slice(record);
    Ok(usize::from_le_bytes(encoded))
}

fn set_bit(bytes: &mut [u8], index: usize) -> Result<(), Error> {
    let byte = bytes
        .get_mut(index / 8)
        .ok_or(Error::InternalInvariant("decision bit outside row"))?;
    *byte |= 1_u8 << (index % 8);
    Ok(())
}

fn read_bit(bytes: &[u8], index: usize) -> Result<bool, Error> {
    let byte = bytes
        .get(index / 8)
        .ok_or(Error::InternalInvariant("decision bit outside row"))?;
    Ok(byte & (1_u8 << (index % 8)) != 0)
}

fn zeroed_usizes(length: usize, resource: Resource) -> Result<Vec<usize>, Error> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(length)
        .map_err(|_| Error::AllocationFailed {
            resource,
            items: length,
        })?;
    values.resize(length, 0);
    Ok(values)
}

fn zeroed_bytes(length: usize, resource: Resource) -> Result<Vec<u8>, Error> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(length)
        .map_err(|_| Error::AllocationFailed {
            resource,
            items: length,
        })?;
    values.resize(length, 0);
    Ok(values)
}

fn operation_identity(
    plan: PlanId,
    strategy: Strategy,
    kind: OperationKind,
    terminal_frontier: bool,
) -> OperationId {
    let strategy_tag = match strategy {
        Strategy::FullTable => 1_u8,
        Strategy::ReverseSequentialRows => 2,
    };
    let kind_tag = match kind {
        OperationKind::Spans => 1_u8,
        OperationKind::Count => 2,
        OperationKind::Sum => 3,
    };
    let route_tag = u8::from(terminal_frontier).wrapping_mul(43);
    let mut bytes = plan.bytes();
    for (index, byte) in bytes.iter_mut().enumerate() {
        let ordinal = u8::try_from(index).unwrap_or(0);
        *byte = byte
            .wrapping_add(strategy_tag.wrapping_mul(17))
            .wrapping_add(route_tag)
            .rotate_left(u32::from(kind_tag % 8))
            ^ ordinal.wrapping_mul(29);
    }
    OperationId(bytes)
}

#[cfg(test)]
mod tests {
    use crate::accounting::ExecutionAccounting;
    use crate::program::AssertionContext;
    use crate::{CompileLimits, CompiledRegex, Error, OperationLimits, Resource, RustByteProfile};

    use super::{
        CachedFrontierRequirements, CachedFrontierStore, CachedTransitionSlot, RowReader,
        RowStorage, UNCACHED_FRONTIER, cached_boundary_symbol, cached_compute_row,
        cached_frontier_words, cached_program_assertion_mask, decode, encoded_width, exact_filled,
        read_encoded, write_encoded,
    };

    #[test]
    fn uncached_checkpoint_recomputes_and_preserves_preferred_alternation() {
        let hir = regex_syntax::ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse("a|ab")
            .unwrap();
        let compiled = CompiledRegex::from_hir(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        let program = &compiled.program;
        let haystack = b"ab";
        let assertions = AssertionContext::new(haystack, 0, haystack.len()).unwrap();
        let words = cached_frontier_words(program.insts.len()).unwrap();
        let admitted = usize::MAX;
        let mut accounting = ExecutionAccounting::default();
        let used_assertions =
            cached_program_assertion_mask(program, &mut accounting, admitted).unwrap();

        let zero = vec![0_u64; words];
        let mut terminal = vec![0_u64; words];
        let terminal_symbol = cached_boundary_symbol(
            program,
            assertions,
            haystack,
            haystack.len(),
            used_assertions,
            &mut accounting,
            admitted,
        )
        .unwrap();
        cached_compute_row(
            program,
            terminal_symbol,
            &zero,
            &mut terminal,
            &mut accounting,
            admitted,
        )
        .unwrap();
        let mut row_one = vec![0_u64; words];
        let row_one_symbol = cached_boundary_symbol(
            program,
            assertions,
            haystack,
            1,
            used_assertions,
            &mut accounting,
            admitted,
        )
        .unwrap();
        cached_compute_row(
            program,
            row_one_symbol,
            &terminal,
            &mut row_one,
            &mut accounting,
            admitted,
        )
        .unwrap();

        let mut state_bits = exact_filled(words * 3, 0_u64, Resource::ScratchBytes).unwrap();
        state_bits[words..words * 2].copy_from_slice(&terminal);
        state_bits[words * 2..words * 3].copy_from_slice(&row_one);
        let mut boundary_states = exact_filled(3, UNCACHED_FRONTIER, Resource::LogBytes).unwrap();
        boundary_states[1] = 2;
        boundary_states[2] = 1;
        let mut store = CachedFrontierStore {
            boundary_states,
            state_bits,
            replay_current: exact_filled(words, 0_u64, Resource::ScratchBytes).unwrap(),
            replay_next: exact_filled(words, 0_u64, Resource::ScratchBytes).unwrap(),
            words,
            used_assertions,
            checkpoint_log_bytes_read: 0,
            build_peak_bytes: 0,
            replay_bytes: 0,
        };
        let before_random = accounting.random_access_bytes_read;
        assert_eq!(
            store
                .selected(program, haystack, assertions, 0, &mut accounting, admitted,)
                .unwrap(),
            Some(1)
        );
        assert_eq!(accounting.random_access_bytes_read - before_random, 1);
        assert_eq!(store.checkpoint_log_bytes_read, core::mem::size_of::<u16>());
    }

    #[test]
    fn cached_frontier_exact_capacity_and_every_one_below_limit() {
        let requirements = CachedFrontierRequirements::new(65, 11, 1).unwrap();
        assert_eq!(core::mem::size_of::<CachedTransitionSlot>(), 16);
        assert_eq!(requirements.words, 2);
        assert_eq!(requirements.record_bytes, 2);
        assert_eq!(requirements.state_word_capacity, 8_192);
        assert_eq!(requirements.boundary_count, 11);
        assert_eq!(requirements.log_bytes, 22);
        assert_eq!(requirements.random_bytes, 2_195_488);
        assert_eq!(requirements.scratch_bytes, 2_195_488);
        assert_eq!(requirements.peak_bytes, 2_195_510);
        assert_eq!(requirements.sequential_bound, 88);
        assert_eq!(requirements.initialization_work().unwrap(), 143_381);

        let exact = OperationLimits {
            max_random_access_bytes: requirements.random_bytes,
            max_scratch_bytes: requirements.scratch_bytes,
            max_log_bytes: requirements.log_bytes,
            max_sequential_bytes: requirements.sequential_bound,
            max_peak_bytes: requirements.peak_bytes,
            ..OperationLimits::default()
        };
        requirements.enforce(exact).unwrap();
        for (resource, required, one_below) in [
            (
                Resource::RandomAccessBytes,
                requirements.random_bytes,
                OperationLimits {
                    max_random_access_bytes: requirements.random_bytes - 1,
                    ..exact
                },
            ),
            (
                Resource::ScratchBytes,
                requirements.scratch_bytes,
                OperationLimits {
                    max_scratch_bytes: requirements.scratch_bytes - 1,
                    ..exact
                },
            ),
            (
                Resource::LogBytes,
                requirements.log_bytes,
                OperationLimits {
                    max_log_bytes: requirements.log_bytes - 1,
                    ..exact
                },
            ),
            (
                Resource::SequentialBytes,
                requirements.sequential_bound,
                OperationLimits {
                    max_sequential_bytes: requirements.sequential_bound - 1,
                    ..exact
                },
            ),
            (
                Resource::PeakBytes,
                requirements.peak_bytes,
                OperationLimits {
                    max_peak_bytes: requirements.peak_bytes - 1,
                    ..exact
                },
            ),
        ] {
            assert_eq!(
                requirements.enforce(one_below),
                Err(Error::ResourceLimit {
                    resource,
                    required,
                    limit: required - 1,
                })
            );
        }
    }

    #[test]
    fn cached_frontier_capacity_is_input_independent_and_overflow_checked() {
        let short = CachedFrontierRequirements::new(257, 19, 1).unwrap();
        let long = CachedFrontierRequirements::new(257, 19_000, 1).unwrap();
        assert_eq!(short.words, long.words);
        assert_eq!(short.state_word_capacity, long.state_word_capacity);
        assert_eq!(short.random_bytes, long.random_bytes);
        assert_eq!(short.scratch_bytes, long.scratch_bytes);
        assert!(short.log_bytes < long.log_bytes);
        assert!(short.peak_bytes < long.peak_bytes);

        assert_eq!(
            CachedFrontierRequirements::new(usize::MAX, 0, 1),
            Err(Error::ArithmeticOverflow {
                resource: Resource::ScratchBytes,
            })
        );
        assert_eq!(
            CachedFrontierRequirements::new(1, usize::MAX, 1),
            Err(Error::ArithmeticOverflow {
                resource: Resource::LogBytes,
            })
        );
        assert_eq!(
            CachedFrontierRequirements::new(1, 1, usize::MAX),
            Err(Error::ArithmeticOverflow {
                resource: Resource::SequentialBytes,
            })
        );
    }

    #[test]
    fn reachable_endpoint_encoding_covers_arbitrary_word_widths() {
        let cases = [
            (0_usize, 1_usize),
            (1, 1),
            (255, 1),
            (256, 2),
            (65_535, 2),
            (65_536, 3),
        ];
        for (value, width) in cases {
            assert_eq!(width, encoded_width(value));
            let mut record = vec![0_u8; width];
            write_encoded(&mut record, value).unwrap();
            assert_eq!(value, read_encoded(&record).unwrap());
        }
        assert!(write_encoded(&mut [0_u8], 256).is_err());
        assert_eq!(None, decode(read_encoded(&[0]).unwrap()));
        assert_eq!(Some(0), decode(read_encoded(&[1]).unwrap()));
    }

    #[test]
    fn row_reader_advances_from_its_authenticated_offset() {
        let store = [30_u8, 31, 20, 21, 10, 11, 0, 1];
        let mut reader = RowReader {
            store: &store,
            storage: RowStorage::SplitDecisions,
            record_bytes: 2,
            current_record: &[],
            current_position: None,
            current_start: store.len(),
            root_rank: 0,
        };
        let mut accounting = ExecutionAccounting::default();

        reader.ensure(0, &mut accounting).unwrap();
        assert_eq!(reader.current_record, [0, 1]);
        assert_eq!(accounting.sequential_bytes_read, 2);

        reader.ensure(1, &mut accounting).unwrap();
        assert_eq!(reader.current_record, [10, 11]);
        assert_eq!(accounting.sequential_bytes_read, 4);

        reader.ensure(3, &mut accounting).unwrap();
        assert_eq!(reader.current_record, [30, 31]);
        assert_eq!(accounting.sequential_bytes_read, 8);

        reader.ensure(3, &mut accounting).unwrap();
        assert_eq!(accounting.sequential_bytes_read, 8);
        assert!(reader.ensure(2, &mut accounting).is_err());
    }

    #[test]
    fn endpoint_row_reader_preserves_failure_and_empty() {
        let store = [0_u8, 1];
        let mut reader = RowReader {
            store: &store,
            storage: RowStorage::ReachableEndpoints,
            record_bytes: 1,
            current_record: &[],
            current_position: None,
            current_start: store.len(),
            root_rank: 0,
        };
        let mut accounting = ExecutionAccounting::default();

        assert_eq!(Some(0), reader.endpoint(0, &mut accounting).unwrap());
        assert_eq!(None, reader.endpoint(1, &mut accounting).unwrap());
        assert_eq!(2, accounting.sequential_bytes_read);
        assert!(reader.root(1, &mut accounting).is_err());
    }
}
