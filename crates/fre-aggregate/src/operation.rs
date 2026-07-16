use core::marker::PhantomData;
use core::ops::Range;

use crate::accounting::ExecutionAccounting;
use crate::compile::{CompiledRegex, PlanId};
use crate::error::{add, enforce, mul};
use crate::program::{AssertionContext, Inst, NO_SPLIT_RANK, Program};
use crate::{Error, OperationLimits, Resource};

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
    /// Materialize fixed-size split/root rows in reverse boundary order and
    /// replay them through a forward-only sequential reader.
    ReverseSequentialRows,
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
        let result = self.execute(haystack, range, strategy, OperationKind::Spans, limits)?;
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
        let result = self.execute(haystack, range, strategy, OperationKind::Count, limits)?;
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
        let result = self.execute(haystack, range, strategy, OperationKind::Sum, limits)?;
        Ok(AdmittedSpanSum {
            value: result.summary.span_sum,
            common: Common {
                certificate: result.certificate,
                accounting: result.accounting,
                marker: PhantomData,
            },
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "whole-operation admission keeps failure-before-publication ordering auditable"
    )]
    fn execute(
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
        if self.program.contains_unicode_word_boundary() && core::str::from_utf8(haystack).is_err()
        {
            return Err(Error::InvalidUtf8ForUnicodeWordBoundary);
        }
        let local = &haystack[range.clone()];
        let assertion_context = AssertionContext::new(haystack, range.start, local.len())?;
        let boundaries = add(local.len(), 1, Resource::Boundaries)?;
        enforce(boundaries, limits.max_boundaries, Resource::Boundaries)?;
        let passes = if kind == OperationKind::Spans { 2 } else { 1 };
        let requirements = Requirements::new(&self.program, boundaries, strategy, passes, limits)?;
        let mut accounting = ExecutionAccounting::default();
        let mut engine = Engine::build(
            &self.program,
            local,
            assertion_context,
            strategy,
            requirements,
            limits,
            &mut accounting,
        )?;
        let summary = engine.scan(
            &self.program,
            local,
            assertion_context,
            requirements.work_bound,
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
            let repeated = engine.scan(
                &self.program,
                local,
                assertion_context,
                requirements.work_bound,
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
        validate_admitted_work(accounting, requirements.work_bound, limits.max_work)?;
        accounting.emitted_matches = summary.matches;
        let certificate = OperationCertificate {
            regex_plan_id: self.plan_id(),
            operation_id: operation_identity(self.plan_id(), strategy, kind),
            strategy,
            range,
            states: self.program.insts.len(),
            boundaries,
            table_cells: requirements.table_cells,
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

#[derive(Clone, Copy, Debug)]
struct Requirements {
    table_cells: usize,
    record_bytes: usize,
    requested_log_bytes: usize,
    sequential_bound: usize,
    work_bound: usize,
}

impl Requirements {
    fn new(
        program: &Program,
        boundaries: usize,
        strategy: Strategy,
        passes: usize,
        limits: OperationLimits,
    ) -> Result<Self, Error> {
        let states = program.insts.len();
        let per_boundary = program.insts.iter().try_fold(0_usize, |total, inst| {
            let transitions = match inst {
                Inst::Unfilled => {
                    return Err(Error::InternalInvariant("unfilled execution state"));
                }
                Inst::Fail | Inst::Match => 0,
                Inst::Consume { .. } | Inst::Assert { .. } => 1,
                Inst::Split { .. } => 2,
            };
            add(
                add(total, 1, Resource::ExecutionWork)?,
                transitions,
                Resource::ExecutionWork,
            )
        })?;
        let build_work = mul(per_boundary, boundaries, Resource::ExecutionWork)?;
        let scan_base = mul(
            mul(boundaries, 4, Resource::ExecutionWork)?,
            passes,
            Resource::ExecutionWork,
        )?;
        let (table_cells, record_bytes, random, scratch, log, sequential, replay) = match strategy {
            Strategy::FullTable => {
                let cells = mul(states, boundaries, Resource::TableCells)?;
                enforce(cells, limits.max_table_cells, Resource::TableCells)?;
                let bytes = mul(
                    cells,
                    core::mem::size_of::<usize>(),
                    Resource::RandomAccessBytes,
                )?;
                (cells, 0, bytes, bytes, 0, 0, 0)
            }
            Strategy::ReverseSequentialRows => {
                let bits = add(program.split_count, 1, Resource::LogBytes)?;
                let record = ceil_div(bits, 8)?;
                let log = mul(record, boundaries, Resource::LogBytes)?;
                let row_words = mul(states, 2, Resource::RandomAccessBytes)?;
                let row_bytes = mul(
                    row_words,
                    core::mem::size_of::<usize>(),
                    Resource::RandomAccessBytes,
                )?;
                let sequential = mul(
                    log,
                    add(passes, 1, Resource::SequentialBytes)?,
                    Resource::SequentialBytes,
                )?;
                let replay = mul(
                    mul(
                        mul(states, boundaries, Resource::ExecutionWork)?,
                        4,
                        Resource::ExecutionWork,
                    )?,
                    passes,
                    Resource::ExecutionWork,
                )?;
                (0, record, row_bytes, row_bytes, log, sequential, replay)
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
        enforce(work_bound, limits.max_work, Resource::ExecutionWork)?;
        Ok(Self {
            table_cells,
            record_bytes,
            requested_log_bytes: log,
            sequential_bound: sequential,
            work_bound,
        })
    }
}

enum Engine {
    Full(FullTable),
    Rows(RowStore),
}

impl Engine {
    fn build(
        program: &Program,
        haystack: &[u8],
        assertions: AssertionContext<'_>,
        strategy: Strategy,
        requirements: Requirements,
        limits: OperationLimits,
        accounting: &mut ExecutionAccounting,
    ) -> Result<Self, Error> {
        match strategy {
            Strategy::FullTable => FullTable::build(
                program,
                haystack,
                assertions,
                requirements,
                limits,
                accounting,
            )
            .map(Self::Full),
            Strategy::ReverseSequentialRows => RowStore::build(
                program,
                haystack,
                assertions,
                requirements,
                limits,
                accounting,
            )
            .map(Self::Rows),
        }
    }

    fn scan(
        &mut self,
        program: &Program,
        haystack: &[u8],
        assertions: AssertionContext<'_>,
        admitted_work_bound: usize,
        accounting: &mut ExecutionAccounting,
        mut emit: impl FnMut(Span) -> Result<(), Error>,
    ) -> Result<ScanSummary, Error> {
        match self {
            Self::Full(table) => scan_sequence(
                haystack.len(),
                assertions.base(),
                accounting,
                admitted_work_bound,
                |start, _| table.selected(program, start),
                &mut emit,
            ),
            Self::Rows(store) => {
                let mut reader = store.reader();
                scan_sequence(
                    haystack.len(),
                    assertions.base(),
                    accounting,
                    admitted_work_bound,
                    |start, accounting| {
                        if !reader.root(start, accounting)? {
                            return Ok(None);
                        }
                        RowStore::replay(
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
        }
    }

    fn peak_with_output(&self, output_bytes: usize) -> Result<usize, Error> {
        match self {
            Self::Full(table) => add(table.allocated_bytes, output_bytes, Resource::PeakBytes),
            Self::Rows(store) => {
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
        }
    }
}

struct FullTable {
    values: Vec<usize>,
    allocated_bytes: usize,
}

impl FullTable {
    fn build(
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
        for position in (0..boundaries).rev() {
            let row = mul(position, states, Resource::TableCells)?;
            for &pc in &program.epsilon_order {
                charge_state(accounting, requirements.work_bound);
                let value = match program.instruction(pc)? {
                    Inst::Unfilled => {
                        return Err(Error::InternalInvariant("unfilled execution state"));
                    }
                    Inst::Fail => 0,
                    Inst::Match => encode(position)?,
                    Inst::Consume { bytes, next } => {
                        charge_transition(accounting, requirements.work_bound);
                        if position < haystack.len() && bytes.contains(haystack[position]) {
                            let next_position = add(position, 1, Resource::Boundaries)?;
                            values[index(next_position, *next, states)?]
                        } else {
                            0
                        }
                    }
                    Inst::Assert { assertion, next } => {
                        charge_assertion(accounting, requirements.work_bound);
                        if assertions.is_match(*assertion, position)? {
                            values[add(row, *next, Resource::TableCells)?]
                        } else {
                            0
                        }
                    }
                    Inst::Split {
                        preferred,
                        fallback,
                    } => {
                        charge_transition(accounting, requirements.work_bound);
                        let selected = values[add(row, *preferred, Resource::TableCells)?];
                        if selected != 0 {
                            selected
                        } else {
                            charge_transition(accounting, requirements.work_bound);
                            values[add(row, *fallback, Resource::TableCells)?]
                        }
                    }
                };
                values[add(row, pc, Resource::TableCells)?] = value;
            }
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
    record_bytes: usize,
    allocated_store_bytes: usize,
    build_scratch_bytes: usize,
    root_rank: usize,
}

impl RowStore {
    #[allow(
        clippy::too_many_lines,
        reason = "row construction keeps fixed-buffer lifetime and accounting in one audit unit"
    )]
    fn build(
        program: &Program,
        haystack: &[u8],
        assertions: AssertionContext<'_>,
        requirements: Requirements,
        limits: OperationLimits,
        accounting: &mut ExecutionAccounting,
    ) -> Result<Self, Error> {
        let mut store = zeroed_bytes(requirements.requested_log_bytes, Resource::LogBytes)?;
        let allocated_store = store.capacity();
        enforce(allocated_store, limits.max_log_bytes, Resource::LogBytes)?;
        let mut row = zeroed_usizes(program.insts.len(), Resource::RandomAccessBytes)?;
        let mut next_row = zeroed_usizes(program.insts.len(), Resource::RandomAccessBytes)?;
        let row_bytes = mul(
            add(
                row.capacity(),
                next_row.capacity(),
                Resource::RandomAccessBytes,
            )?,
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
        let boundaries = add(haystack.len(), 1, Resource::Boundaries)?;
        let mut write_offset = 0_usize;
        for position in (0..boundaries).rev() {
            let end = add(write_offset, requirements.record_bytes, Resource::LogBytes)?;
            let record = store
                .get_mut(write_offset..end)
                .ok_or(Error::InternalInvariant("row-log write outside store"))?;
            let input = haystack.get(position).copied();
            for &pc in &program.epsilon_order {
                charge_state(accounting, requirements.work_bound);
                let value = match program.instruction(pc)? {
                    Inst::Unfilled => {
                        return Err(Error::InternalInvariant("unfilled execution state"));
                    }
                    Inst::Fail => 0,
                    Inst::Match => encode(position)?,
                    Inst::Consume { bytes, next } => {
                        charge_transition(accounting, requirements.work_bound);
                        if input.is_some_and(|byte| bytes.contains(byte)) {
                            next_row[*next]
                        } else {
                            0
                        }
                    }
                    Inst::Assert { assertion, next } => {
                        charge_assertion(accounting, requirements.work_bound);
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
                        charge_transition(accounting, requirements.work_bound);
                        let preferred_value = row[*preferred];
                        let rank = program.split_rank[pc];
                        if rank == NO_SPLIT_RANK {
                            return Err(Error::InternalInvariant(
                                "split state has no decision rank",
                            ));
                        }
                        if preferred_value != 0 {
                            set_bit(record, rank)?;
                            preferred_value
                        } else {
                            charge_transition(accounting, requirements.work_bound);
                            row[*fallback]
                        }
                    }
                };
                row[pc] = value;
            }
            if row[program.entry] != 0 {
                set_bit(record, program.split_count)?;
            }
            accounting.sequential_bytes_written = add(
                accounting.sequential_bytes_written,
                requirements.record_bytes,
                Resource::SequentialBytes,
            )?;
            write_offset = end;
            row.swap_with_slice(&mut next_row);
        }
        if write_offset != store.len() {
            return Err(Error::InternalInvariant("row-log store length mismatch"));
        }
        drop(row);
        drop(next_row);
        accounting.random_access_peak_bytes = build_scratch;
        accounting.scratch_peak_bytes = build_scratch;
        accounting.log_bytes = allocated_store;
        Ok(Self {
            bytes: store,
            record_bytes: requirements.record_bytes,
            allocated_store_bytes: allocated_store,
            build_scratch_bytes: build_scratch,
            root_rank: program.split_count,
        })
    }

    fn reader(&self) -> RowReader<'_> {
        RowReader {
            store: &self.bytes,
            record_bytes: self.record_bytes,
            current_record: &[],
            current_position: None,
            root_rank: self.root_rank,
        }
    }

    fn replay(
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
            charge_replay(accounting, admitted_work_bound);
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
                Inst::Assert { assertion, next } => {
                    charge_assertion(accounting, admitted_work_bound);
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
}

struct RowReader<'a> {
    store: &'a [u8],
    record_bytes: usize,
    current_record: &'a [u8],
    current_position: Option<usize>,
    root_rank: usize,
}

impl RowReader<'_> {
    fn root(
        &mut self,
        position: usize,
        accounting: &mut ExecutionAccounting,
    ) -> Result<bool, Error> {
        self.ensure(position, accounting)?;
        read_bit(self.current_record, self.root_rank)
    }

    fn decision(
        &mut self,
        position: usize,
        rank: usize,
        accounting: &mut ExecutionAccounting,
    ) -> Result<bool, Error> {
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
        let ordinal = add(position, 1, Resource::LogBytes)?;
        let from_end = mul(ordinal, self.record_bytes, Resource::LogBytes)?;
        let start = self
            .store
            .len()
            .checked_sub(from_end)
            .ok_or(Error::InternalInvariant("row-log seek outside store"))?;
        let end = add(start, self.record_bytes, Resource::LogBytes)?;
        self.current_record = self
            .store
            .get(start..end)
            .ok_or(Error::InternalInvariant("row-log read outside store"))?;
        self.current_position = Some(position);
        Ok(())
    }
}

fn scan_sequence(
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
            charge_root(accounting, admitted_work_bound);
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
        charge_event(accounting, admitted_work_bound);
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

// `Requirements::new` checked the sum of every possible construction, scan
// and replay charge before allocation. Consequently each actual counter and
// their sum fit in `usize` and cannot reach the admitted bound's successor.
// Keeping that theorem at the operation boundary avoids checked arithmetic and
// a resource-limit branch in every continuation hot-loop step. Debug builds
// retain a per-step assertion; every build validates the exact observed sum
// with checked arithmetic before publishing a result.
#[inline]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "whole-operation admission proves every actual work counter and their sum fit"
)]
fn charge(accounting: &mut ExecutionAccounting, admitted_work_bound: usize) {
    debug_assert!(accounting.work < admitted_work_bound);
    accounting.work += 1;
}

#[inline]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "state evaluations are a subset of the admitted whole-operation work bound"
)]
fn charge_state(accounting: &mut ExecutionAccounting, admitted_work_bound: usize) {
    accounting.state_evaluations += 1;
    charge(accounting, admitted_work_bound);
}

#[inline]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "transition checks are a subset of the admitted whole-operation work bound"
)]
fn charge_transition(accounting: &mut ExecutionAccounting, admitted_work_bound: usize) {
    accounting.transition_checks += 1;
    charge(accounting, admitted_work_bound);
}

#[inline]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "assertion checks are a subset of admitted transition checks"
)]
fn charge_assertion(accounting: &mut ExecutionAccounting, admitted_work_bound: usize) {
    accounting.assertion_checks += 1;
    charge_transition(accounting, admitted_work_bound);
}

#[inline]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "root probes are a subset of the admitted whole-operation work bound"
)]
fn charge_root(accounting: &mut ExecutionAccounting, admitted_work_bound: usize) {
    accounting.root_probes += 1;
    charge(accounting, admitted_work_bound);
}

#[inline]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "replay steps are a subset of the admitted whole-operation work bound"
)]
fn charge_replay(accounting: &mut ExecutionAccounting, admitted_work_bound: usize) {
    accounting.replay_steps += 1;
    charge(accounting, admitted_work_bound);
}

#[inline]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "successful paths are a subset of the admitted whole-operation work bound"
)]
fn charge_event(accounting: &mut ExecutionAccounting, admitted_work_bound: usize) {
    accounting.successful_paths += 1;
    charge(accounting, admitted_work_bound);
}

fn validate_admitted_work(
    accounting: ExecutionAccounting,
    admitted_work_bound: usize,
    caller_limit: usize,
) -> Result<(), Error> {
    let observed = add(
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
            accounting.replay_steps,
            accounting.successful_paths,
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

fn operation_identity(plan: PlanId, strategy: Strategy, kind: OperationKind) -> OperationId {
    let strategy_tag = match strategy {
        Strategy::FullTable => 1_u8,
        Strategy::ReverseSequentialRows => 2,
    };
    let kind_tag = match kind {
        OperationKind::Spans => 1_u8,
        OperationKind::Count => 2,
        OperationKind::Sum => 3,
    };
    let mut bytes = plan.bytes();
    for (index, byte) in bytes.iter_mut().enumerate() {
        let ordinal = u8::try_from(index).unwrap_or(0);
        *byte = byte
            .wrapping_add(strategy_tag.wrapping_mul(17))
            .rotate_left(u32::from(kind_tag % 8))
            ^ ordinal.wrapping_mul(29);
    }
    OperationId(bytes)
}
