//! Ordered multi-pattern compilation and caller-owned match tracing.
//!
//! This is deliberately a separate operation from [`crate::OutputContract`].
//! A single-search output contract cannot describe a non-overlapping stream
//! whose selected row is observable. It is also distinct from `RegexSet`
//! semantics: at each leftmost start exactly one row wins, with source-row
//! order breaking ties, and the selected row's own leftmost-first endpoint is
//! retained. Every row is compiled and validated before shared selection is
//! attempted. A successfully published tagged selector retains only caller IDs
//! and releases the now-redundant scalar programs; every fallback retains all
//! scalar owners.

use core::fmt;

use fre_automata::{
    Automaton, DirectCount, DirectReduceLimits, PriorityMatch, ReduceError,
    TaggedManyBuildAccounting, TaggedManyBuildError, TaggedManyBuildLimits, TaggedManyPlan,
    TaggedManyStats, TaggedManyTraceSession,
};
use fre_lower::{LowerLimits, OperationSemantics};
use fre_syntax::{
    CanonicalPattern, CompatibilityProfile, ParseRequest, RustConstructor, RustMatchKind,
    RustProfile,
};

use crate::{
    CompileError, CompileMode, DeterminizeLimits, MatchResult, OutputContract, ProgramWorkspace,
    SearchWindow, program::CompiledProgram,
};

/// Maximum owner count represented by the current tagged quotient.
pub const ORDERED_MANY_TAGGED_MAX_ROWS: usize = 128;

/// Caller-defined pattern identifier returned with each selected row.
///
/// Identifier values are payload only. They never participate in matching or
/// priority, so duplicate and out-of-source-order identifiers are preserved.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct OrderedManyPatternId(u32);

impl OrderedManyPatternId {
    /// Construct a caller-defined identifier.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Return the caller-defined integer identifier.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// One source-ordered compilation row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrderedManyRow {
    pattern_id: OrderedManyPatternId,
    pattern: String,
}

impl OrderedManyRow {
    /// Bind a caller identifier to one Rust byte-regex source row.
    #[must_use]
    pub fn new(pattern_id: OrderedManyPatternId, pattern: impl Into<String>) -> Self {
        Self {
            pattern_id,
            pattern: pattern.into(),
        }
    }

    /// Caller-defined identifier returned for this row.
    #[must_use]
    pub const fn pattern_id(&self) -> OrderedManyPatternId {
        self.pattern_id
    }

    /// Rust byte-regex source for this row.
    #[must_use]
    pub fn pattern(&self) -> &str {
        &self.pattern
    }
}

/// Hard limits for one ordered-many compilation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderedManyCompileLimits {
    /// Maximum number of source rows, including rows using the semantic
    /// fallback beyond the tagged owner ceiling.
    pub max_rows: usize,
    /// Maximum sum of source bytes over every row.
    pub max_pattern_bytes: usize,
    /// Per-row Thompson lowering and validation limits.
    pub lower: LowerLimits,
    /// Per-row ordered determinization limits.
    pub determinize: DeterminizeLimits,
    /// Optional shared tagged-quotient construction limits.
    pub tagged: TaggedManyBuildLimits,
    /// Maximum stable semantic-program bytes for any one row.
    pub max_program_bytes_per_row: usize,
    /// Maximum sum of stable semantic-program bytes over every row.
    pub max_total_program_bytes: usize,
}

impl Default for OrderedManyCompileLimits {
    fn default() -> Self {
        Self {
            max_rows: 4_096,
            max_pattern_bytes: 4 * 1_048_576,
            lower: LowerLimits::default(),
            determinize: DeterminizeLimits::default(),
            tagged: TaggedManyBuildLimits::default(),
            max_program_bytes_per_row: 256 * 1_048_576,
            max_total_program_bytes: 512 * 1_048_576,
        }
    }
}

/// Complete source-ordered request for an ordered many-pattern program.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrderedManyCompileRequest {
    pub rows: Vec<OrderedManyRow>,
    pub profile: RustProfile,
    pub mode: CompileMode,
    pub limits: OrderedManyCompileLimits,
}

impl OrderedManyCompileRequest {
    /// Construct a generic Rust-bytes request.
    #[must_use]
    pub fn new(rows: Vec<OrderedManyRow>) -> Self {
        Self {
            rows,
            profile: RustProfile::default(),
            mode: CompileMode::Optimizing,
            limits: OrderedManyCompileLimits::default(),
        }
    }

    /// Select an explicit Rust byte-regex compatibility profile.
    #[must_use]
    pub fn profile(mut self, profile: RustProfile) -> Self {
        self.profile = profile;
        self
    }

    /// Select the per-row semantic compilation mode.
    #[must_use]
    pub const fn mode(mut self, mode: CompileMode) -> Self {
        self.mode = mode;
        self
    }

    /// Select explicit construction limits.
    #[must_use]
    pub const fn limits(mut self, limits: OrderedManyCompileLimits) -> Self {
        self.limits = limits;
        self
    }
}

/// Exact semantic route published by an ordered-many program.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OrderedManyStrategy {
    /// The successful empty request has no selector or row workspaces.
    Empty,
    /// A shared owner-tagged quotient selects all row ordinals in one pass.
    TaggedMany,
    /// Independent compiled rows participate in exact global k-way selection.
    SemanticFallback,
}

/// Why a nonempty program retained exact independent-row execution.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OrderedManyFallbackReason {
    /// The request exceeded the representation's fixed owner-bit ceiling.
    TaggedOwnerLimit { needed: usize, limit: usize },
    /// Tagged construction declined; the complete independent programs remain
    /// authoritative for semantics.
    TaggedBuild(TaggedManyBuildError),
}

/// Aggregate dimensions of one successfully compiled program.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderedManyProgramStats {
    pub rows: usize,
    pub pattern_bytes: usize,
    /// Sum of stable semantic-program bytes compiled, validated, and charged
    /// across all rows. A successful tagged selector may release those scalar
    /// owners after this compilation envelope closes.
    pub serialized_program_bytes: usize,
}

/// Failure before an ordered-many program is published.
#[derive(Debug)]
#[non_exhaustive]
pub enum OrderedManyCompileError {
    RowsLimit {
        needed: usize,
        limit: usize,
    },
    PatternBytesLimit {
        row: usize,
        pattern_id: OrderedManyPatternId,
        needed: usize,
        limit: usize,
    },
    PatternOrdinalOverflow {
        row: usize,
        pattern_id: OrderedManyPatternId,
    },
    UnsupportedProfile {
        requirement: &'static str,
    },
    Row {
        row: usize,
        pattern_id: OrderedManyPatternId,
        source: CompileError,
    },
    TotalProgramBytesLimit {
        row: usize,
        pattern_id: OrderedManyPatternId,
        needed: usize,
        limit: usize,
    },
    /// An unexpected tagged malformed, arithmetic, allocation, or invariant
    /// failure after all independent rows compiled successfully.
    Tagged(TaggedManyBuildError),
    ArithmeticOverflow {
        computation: &'static str,
    },
    AllocationFailed {
        structure: &'static str,
        entries: usize,
    },
    InternalInvariant(&'static str),
}

impl fmt::Display for OrderedManyCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RowsLimit { needed, limit } => write!(
                formatter,
                "ordered-many compilation needs {needed} rows, limit is {limit}"
            ),
            Self::PatternBytesLimit {
                row,
                pattern_id,
                needed,
                limit,
            } => write!(
                formatter,
                "ordered-many row {row} (pattern ID {}) raises source bytes to {needed}, limit is {limit}",
                pattern_id.get()
            ),
            Self::PatternOrdinalOverflow { row, pattern_id } => write!(
                formatter,
                "ordered-many row {row} (pattern ID {}) does not fit the source-ordinal representation",
                pattern_id.get()
            ),
            Self::UnsupportedProfile { requirement } => {
                write!(formatter, "unsupported ordered-many profile: {requirement}")
            }
            Self::Row {
                row,
                pattern_id,
                source,
            } => write!(
                formatter,
                "ordered-many row {row} (pattern ID {}): {source}",
                pattern_id.get()
            ),
            Self::TotalProgramBytesLimit {
                row,
                pattern_id,
                needed,
                limit,
            } => write!(
                formatter,
                "ordered-many row {row} (pattern ID {}) raises stable program bytes to {needed}, limit is {limit}",
                pattern_id.get()
            ),
            Self::Tagged(source) => {
                write!(
                    formatter,
                    "ordered-many tagged construction failed: {source}"
                )
            }
            Self::ArithmeticOverflow { computation } => {
                write!(formatter, "ordered-many overflow computing {computation}")
            }
            Self::AllocationFailed { structure, entries } => write!(
                formatter,
                "ordered-many could not reserve {entries} entries for {structure}"
            ),
            Self::InternalInvariant(detail) => {
                write!(formatter, "ordered-many invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for OrderedManyCompileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Row { source, .. } => Some(source),
            Self::Tagged(source) => Some(source),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
struct CompiledOrderedManyRow {
    pattern_id: OrderedManyPatternId,
    program: Option<CompiledProgram>,
}

#[allow(
    dead_code,
    reason = "this private mirror freezes the pre-retention row layout for compile-time comparison"
)]
struct CompiledOrderedManyRowRequiredOwnerLayout {
    pattern_id: OrderedManyPatternId,
    program: CompiledProgram,
}

const _: () = {
    assert!(
        core::mem::size_of::<Option<CompiledProgram>>() == core::mem::size_of::<CompiledProgram>()
    );
    assert!(
        core::mem::align_of::<Option<CompiledProgram>>()
            == core::mem::align_of::<CompiledProgram>()
    );
    assert!(
        core::mem::size_of::<CompiledOrderedManyRow>()
            == core::mem::size_of::<CompiledOrderedManyRowRequiredOwnerLayout>()
    );
    assert!(
        core::mem::align_of::<CompiledOrderedManyRow>()
            == core::mem::align_of::<CompiledOrderedManyRowRequiredOwnerLayout>()
    );
};

#[derive(Clone, Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "boxing the tagged plan would add an unaccounted compiler allocation after its exact construction receipt closes"
)]
enum OrderedManySelector {
    Empty,
    Tagged(TaggedManyPlan<DirectCount>),
    Fallback(OrderedManyFallbackReason),
}

/// Immutable target-neutral ordered many-pattern program.
///
/// Every nonempty row is first compiled into a complete Span semantic program.
/// A successful shared tagged selector makes those scalar owners redundant and
/// releases them before publication while retaining every caller ID. A tagged
/// refusal keeps every complete row program as the exact semantic fallback, so
/// shared construction remains an optimization rather than an eligibility
/// condition.
#[derive(Clone, Debug)]
pub struct OrderedManyProgram {
    rows: Box<[CompiledOrderedManyRow]>,
    selector: OrderedManySelector,
    profile: RustProfile,
    mode: CompileMode,
    line_terminator: u8,
    stats: OrderedManyProgramStats,
}

impl OrderedManyProgram {
    /// Number of source rows. Zero is a valid, always-empty program.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether this program has no source rows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Exact published semantic route.
    #[must_use]
    pub const fn strategy(&self) -> OrderedManyStrategy {
        match &self.selector {
            OrderedManySelector::Empty => OrderedManyStrategy::Empty,
            OrderedManySelector::Tagged(_) => OrderedManyStrategy::TaggedMany,
            OrderedManySelector::Fallback(_) => OrderedManyStrategy::SemanticFallback,
        }
    }

    /// Exact reason the shared tagged route was not published.
    #[must_use]
    pub const fn fallback_reason(&self) -> Option<&OrderedManyFallbackReason> {
        match &self.selector {
            OrderedManySelector::Fallback(reason) => Some(reason),
            OrderedManySelector::Empty | OrderedManySelector::Tagged(_) => None,
        }
    }

    /// Tagged graph dimensions, if that optimization was published.
    #[must_use]
    pub const fn tagged_stats(&self) -> Option<TaggedManyStats> {
        match &self.selector {
            OrderedManySelector::Tagged(plan) => Some(plan.stats()),
            OrderedManySelector::Empty | OrderedManySelector::Fallback(_) => None,
        }
    }

    /// Tagged construction accounting, if that optimization was published.
    #[must_use]
    pub const fn tagged_build_accounting(&self) -> Option<TaggedManyBuildAccounting> {
        match &self.selector {
            OrderedManySelector::Tagged(plan) => Some(plan.build_accounting()),
            OrderedManySelector::Empty | OrderedManySelector::Fallback(_) => None,
        }
    }

    /// Aggregate compilation dimensions.
    #[must_use]
    pub const fn stats(&self) -> OrderedManyProgramStats {
        self.stats
    }

    /// Rust byte-regex profile used to parse every row.
    #[must_use]
    pub const fn profile(&self) -> &RustProfile {
        &self.profile
    }

    /// Per-row semantic compilation mode.
    #[must_use]
    pub const fn mode(&self) -> CompileMode {
        self.mode
    }

    /// Configured line terminator shared by all rows.
    #[must_use]
    pub const fn line_terminator(&self) -> u8 {
        self.line_terminator
    }

    /// Caller identifier bound to one source ordinal.
    #[must_use]
    pub fn pattern_id(&self, source_ordinal: usize) -> Option<OrderedManyPatternId> {
        self.rows.get(source_ordinal).map(|row| row.pattern_id)
    }

    #[cfg(test)]
    fn retained_scalar_programs_for_test(&self) -> usize {
        self.rows.iter().filter(|row| row.program.is_some()).count()
    }

    /// Prepare all source-independent storage for one fixed haystack length.
    ///
    /// Repeated [`OrderedManySession::fill`] operations at that exact length
    /// make no dynamic allocations in either the tagged or semantic-fallback
    /// route.
    pub fn prepare_session(
        &self,
        source_bytes: usize,
        limits: OrderedManySessionLimits,
    ) -> Result<OrderedManySession<'_>, OrderedManyPrepareError> {
        if source_bytes > limits.max_source_bytes {
            return Err(OrderedManyPrepareError::SourceBytesLimit {
                needed: source_bytes,
                limit: limits.max_source_bytes,
            });
        }
        let execution = match &self.selector {
            OrderedManySelector::Empty => OrderedManySessionExecution::Empty,
            OrderedManySelector::Tagged(plan) => OrderedManySessionExecution::Tagged(
                plan.prepare_trace_session(source_bytes, limits.tagged)
                    .map_err(OrderedManyPrepareError::Tagged)?,
            ),
            OrderedManySelector::Fallback(_) => {
                if self.rows.len() > limits.max_fallback_workspaces {
                    return Err(OrderedManyPrepareError::FallbackWorkspaceLimit {
                        needed: self.rows.len(),
                        limit: limits.max_fallback_workspaces,
                    });
                }
                let mut workspaces = reserve_exact(
                    self.rows.len(),
                    "fallback program workspaces",
                    |structure, entries| OrderedManyPrepareError::AllocationFailed {
                        structure,
                        entries,
                    },
                )?;
                for (row, compiled) in self.rows.iter().enumerate() {
                    let Some(program) = compiled.program.as_ref() else {
                        return Err(OrderedManyPrepareError::InternalInvariant(
                            "semantic fallback row lost its scalar program",
                        ));
                    };
                    let workspace = program.prepare_workspace().map_err(|source| {
                        OrderedManyPrepareError::RowWorkspace {
                            row,
                            pattern_id: compiled.pattern_id,
                            source,
                        }
                    })?;
                    workspaces.push(workspace);
                }
                OrderedManySessionExecution::Fallback(workspaces.into_boxed_slice())
            }
        };
        Ok(OrderedManySession {
            program: self,
            source_bytes,
            max_match_events: limits.max_match_events,
            execution,
        })
    }
}

/// One selected ordered-many match.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OrderedManyMatch {
    pattern_id: OrderedManyPatternId,
    source_ordinal: u32,
    start: usize,
    end: usize,
}

impl OrderedManyMatch {
    const fn from_parts(
        pattern_id: OrderedManyPatternId,
        source_ordinal: u32,
        start: usize,
        end: usize,
    ) -> Self {
        Self {
            pattern_id,
            source_ordinal,
            start,
            end,
        }
    }

    /// Caller-defined identifier. Duplicate values are preserved.
    #[must_use]
    pub const fn pattern_id(self) -> OrderedManyPatternId {
        self.pattern_id
    }

    /// Zero-based source-row ordinal that determined priority.
    #[must_use]
    pub const fn source_ordinal(self) -> u32 {
        self.source_ordinal
    }

    /// Inclusive start of the selected half-open byte span.
    #[must_use]
    pub const fn start(self) -> usize {
        self.start
    }

    /// Exclusive end of the selected half-open byte span.
    #[must_use]
    pub const fn end(self) -> usize {
        self.end
    }

    /// Length in bytes.
    #[must_use]
    pub const fn len(self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Whether this is an empty match.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }
}

/// Limits applied while preparing and reusing one fixed-length session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderedManySessionLimits {
    /// Shared tagged-session resource limits.
    pub tagged: DirectReduceLimits,
    /// Maximum admitted haystack length.
    pub max_source_bytes: usize,
    /// Maximum independently prepared fallback workspaces.
    pub max_fallback_workspaces: usize,
    /// Maximum selected matches in one complete fill operation.
    pub max_match_events: usize,
}

impl OrderedManySessionLimits {
    /// Disable caller-selected limits while retaining checked arithmetic.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            tagged: DirectReduceLimits::unlimited(),
            max_source_bytes: usize::MAX,
            max_fallback_workspaces: usize::MAX,
            max_match_events: usize::MAX,
        }
    }
}

impl Default for OrderedManySessionLimits {
    fn default() -> Self {
        Self {
            tagged: DirectReduceLimits::default(),
            max_source_bytes: 128 * 1_048_576,
            max_fallback_workspaces: 4_096,
            max_match_events: 134_217_729,
        }
    }
}

/// Failure while preparing caller-owned session storage.
#[derive(Debug)]
#[non_exhaustive]
pub enum OrderedManyPrepareError {
    SourceBytesLimit {
        needed: usize,
        limit: usize,
    },
    FallbackWorkspaceLimit {
        needed: usize,
        limit: usize,
    },
    Tagged(ReduceError),
    RowWorkspace {
        row: usize,
        pattern_id: OrderedManyPatternId,
        source: CompileError,
    },
    AllocationFailed {
        structure: &'static str,
        entries: usize,
    },
    InternalInvariant(&'static str),
}

impl fmt::Display for OrderedManyPrepareError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceBytesLimit { needed, limit } => write!(
                formatter,
                "ordered-many session needs {needed} source bytes, limit is {limit}"
            ),
            Self::FallbackWorkspaceLimit { needed, limit } => write!(
                formatter,
                "ordered-many fallback needs {needed} row workspaces, limit is {limit}"
            ),
            Self::Tagged(source) => write!(formatter, "ordered-many tagged session: {source}"),
            Self::RowWorkspace {
                row,
                pattern_id,
                source,
            } => write!(
                formatter,
                "ordered-many row {row} (pattern ID {}) workspace: {source}",
                pattern_id.get()
            ),
            Self::AllocationFailed { structure, entries } => write!(
                formatter,
                "ordered-many could not reserve {entries} entries for {structure}"
            ),
            Self::InternalInvariant(detail) => {
                write!(formatter, "ordered-many session invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for OrderedManyPrepareError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Tagged(source) => Some(source),
            Self::RowWorkspace { source, .. } => Some(source),
            Self::SourceBytesLimit { .. }
            | Self::FallbackWorkspaceLimit { .. }
            | Self::AllocationFailed { .. }
            | Self::InternalInvariant(_) => None,
        }
    }
}

/// Successful caller-buffer publication status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderedManyFillReport {
    strategy: OrderedManyStrategy,
    selected: usize,
    written: usize,
}

impl OrderedManyFillReport {
    /// Semantic route used for this run.
    #[must_use]
    pub const fn strategy(self) -> OrderedManyStrategy {
        self.strategy
    }

    /// Exact total selected matches, including entries beyond the output
    /// buffer. This is the capacity needed for a complete replay.
    #[must_use]
    pub const fn selected(self) -> usize {
        self.selected
    }

    /// Number of entries written to the caller buffer.
    #[must_use]
    pub const fn written(self) -> usize {
        self.written
    }

    /// Whether the caller buffer omitted a selected suffix.
    #[must_use]
    pub const fn truncated(self) -> bool {
        self.written != self.selected
    }
}

/// Failure while running a prepared ordered-many session.
#[derive(Debug)]
#[non_exhaustive]
pub enum OrderedManyRunError {
    SourceLength {
        expected: usize,
        actual: usize,
    },
    MatchEventLimit {
        needed: usize,
        limit: usize,
    },
    Tagged(ReduceError),
    RowSearch {
        row: usize,
        pattern_id: OrderedManyPatternId,
        source: CompileError,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    InternalInvariant(&'static str),
}

impl fmt::Display for OrderedManyRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceLength { expected, actual } => write!(
                formatter,
                "ordered-many session expects {expected} source bytes, got {actual}"
            ),
            Self::MatchEventLimit { needed, limit } => write!(
                formatter,
                "ordered-many fill needs at least {needed} match events, limit is {limit}"
            ),
            Self::Tagged(source) => write!(formatter, "ordered-many tagged execution: {source}"),
            Self::RowSearch {
                row,
                pattern_id,
                source,
            } => write!(
                formatter,
                "ordered-many row {row} (pattern ID {}) search: {source}",
                pattern_id.get()
            ),
            Self::ArithmeticOverflow { computation } => {
                write!(formatter, "ordered-many overflow computing {computation}")
            }
            Self::InternalInvariant(detail) => {
                write!(formatter, "ordered-many invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for OrderedManyRunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Tagged(source) => Some(source),
            Self::RowSearch { source, .. } => Some(source),
            Self::SourceLength { .. }
            | Self::MatchEventLimit { .. }
            | Self::ArithmeticOverflow { .. }
            | Self::InternalInvariant(_) => None,
        }
    }
}

#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "boxing the tagged session would add an allocation outside its exact pre-source setup receipt"
)]
enum OrderedManySessionExecution<'program> {
    Empty,
    Tagged(TaggedManyTraceSession<'program, DirectCount>),
    Fallback(Box<[ProgramWorkspace]>),
}

/// Caller-owned reusable execution storage for one fixed source length.
#[derive(Debug)]
pub struct OrderedManySession<'program> {
    program: &'program OrderedManyProgram,
    source_bytes: usize,
    max_match_events: usize,
    execution: OrderedManySessionExecution<'program>,
}

impl OrderedManySession<'_> {
    /// Fixed haystack length admitted at construction.
    #[must_use]
    pub const fn source_bytes(&self) -> usize {
        self.source_bytes
    }

    /// Route whose storage this session owns.
    #[must_use]
    pub const fn strategy(&self) -> OrderedManyStrategy {
        self.program.strategy()
    }

    /// Fill a caller-owned prefix with selected matches and still traverse the
    /// complete haystack to report the exact total.
    ///
    /// On success, exactly `report.written()` entries at the start of
    /// `output` are overwritten in encounter order; every remaining entry is
    /// left unchanged. `report.truncated()` means a selected suffix was not
    /// written, while `report.selected()` is the exact capacity needed on a
    /// replay. On error, a semantic-fallback run may have overwritten a valid
    /// prefix and the caller must ignore the buffer; tagged execution
    /// publishes only after its complete trace succeeds.
    pub fn fill(
        &mut self,
        haystack: &[u8],
        output: &mut [OrderedManyMatch],
    ) -> Result<OrderedManyFillReport, OrderedManyRunError> {
        if haystack.len() != self.source_bytes {
            return Err(OrderedManyRunError::SourceLength {
                expected: self.source_bytes,
                actual: haystack.len(),
            });
        }
        match &mut self.execution {
            OrderedManySessionExecution::Empty => Ok(OrderedManyFillReport {
                strategy: OrderedManyStrategy::Empty,
                selected: 0,
                written: 0,
            }),
            OrderedManySessionExecution::Tagged(session) => {
                let trace = session
                    .execute_trace(haystack)
                    .map_err(OrderedManyRunError::Tagged)?;
                publish_tagged_trace(self.program, &trace, output, self.max_match_events)
            }
            OrderedManySessionExecution::Fallback(workspaces) => execute_fallback(
                self.program,
                workspaces,
                haystack,
                output,
                self.max_match_events,
            ),
        }
    }
}

/// Compile source rows into a reusable target-neutral ordered-many program.
///
/// The optional tagged selector is attempted only after every independent row
/// program is complete. Any tagged construction refusal preserves those rows
/// as the exact fallback instead of changing operation eligibility. Successful
/// tagged publication releases the redundant scalar owners only after shared
/// construction has completed without changing compilation or error order.
#[allow(
    clippy::too_many_lines,
    reason = "the row-indexed parse, lower, stable-program, and monotone tagged publication transaction stays adjacent"
)]
pub fn compile_ordered_many(
    request: OrderedManyCompileRequest,
) -> Result<OrderedManyProgram, OrderedManyCompileError> {
    let OrderedManyCompileRequest {
        rows,
        profile,
        mode,
        limits,
    } = request;
    if rows.len() > limits.max_rows {
        return Err(OrderedManyCompileError::RowsLimit {
            needed: rows.len(),
            limit: limits.max_rows,
        });
    }
    if rows.is_empty() {
        return Ok(OrderedManyProgram {
            rows: Box::default(),
            selector: OrderedManySelector::Empty,
            line_terminator: profile.options.line_terminator,
            profile,
            mode,
            stats: OrderedManyProgramStats {
                rows: 0,
                pattern_bytes: 0,
                serialized_program_bytes: 0,
            },
        });
    }
    validate_profile(&profile)?;

    let row_count = rows.len();
    let line_terminator = profile.options.line_terminator;
    let compatibility = CompatibilityProfile::RustBytes(profile.clone());
    let collect_tagged = row_count <= ORDERED_MANY_TAGGED_MAX_ROWS;
    let mut compiled_rows = reserve_exact(row_count, "compiled rows", |structure, entries| {
        OrderedManyCompileError::AllocationFailed { structure, entries }
    })?;
    let mut tagged_raw = collect_tagged
        .then(|| {
            reserve_exact(row_count, "tagged raw rows", |structure, entries| {
                OrderedManyCompileError::AllocationFailed { structure, entries }
            })
        })
        .transpose()?;
    let mut pattern_bytes = 0usize;
    let mut total_program_bytes = 0usize;

    for (row, source) in rows.into_iter().enumerate() {
        let pattern_id = source.pattern_id;
        if u32::try_from(row).is_err() {
            return Err(OrderedManyCompileError::PatternOrdinalOverflow { row, pattern_id });
        }
        pattern_bytes = pattern_bytes.checked_add(source.pattern.len()).ok_or(
            OrderedManyCompileError::ArithmeticOverflow {
                computation: "source byte sum",
            },
        )?;
        if pattern_bytes > limits.max_pattern_bytes {
            return Err(OrderedManyCompileError::PatternBytesLimit {
                row,
                pattern_id,
                needed: pattern_bytes,
                limit: limits.max_pattern_bytes,
            });
        }
        let parsed = fre_syntax::parse(ParseRequest::rust(source.pattern, compatibility.clone()))
            .map_err(CompileError::from)
            .map_err(|source| OrderedManyCompileError::Row {
                row,
                pattern_id,
                source,
            })?;
        let CanonicalPattern::Rust(parsed) = parsed.pattern else {
            return Err(OrderedManyCompileError::Row {
                row,
                pattern_id,
                source: CompileError::InternalInvariant(
                    "Rust byte request produced a non-Rust syntax tree",
                ),
            });
        };
        let raw =
            fre_lower::lower_raw_general(&parsed, OperationSemantics::CaptureFree, limits.lower)
                .map_err(CompileError::from)
                .map_err(|source| OrderedManyCompileError::Row {
                    row,
                    pattern_id,
                    source,
                })?
                .into_plan();
        let automaton = Automaton::from_raw(raw.clone(), limits.lower.automata)
            .map_err(CompileError::from)
            .map_err(|source| OrderedManyCompileError::Row {
                row,
                pattern_id,
                source,
            })?
            .with_line_terminator(line_terminator);
        let program = CompiledProgram::build(
            raw.clone(),
            automaton,
            OutputContract::Span,
            mode,
            limits.determinize,
            limits.max_program_bytes_per_row,
        )
        .map_err(|source| OrderedManyCompileError::Row {
            row,
            pattern_id,
            source,
        })?;
        let program_bytes =
            program
                .serialized_len()
                .map_err(|source| OrderedManyCompileError::Row {
                    row,
                    pattern_id,
                    source,
                })?;
        total_program_bytes = total_program_bytes.checked_add(program_bytes).ok_or(
            OrderedManyCompileError::ArithmeticOverflow {
                computation: "stable semantic-program byte sum",
            },
        )?;
        if total_program_bytes > limits.max_total_program_bytes {
            return Err(OrderedManyCompileError::TotalProgramBytesLimit {
                row,
                pattern_id,
                needed: total_program_bytes,
                limit: limits.max_total_program_bytes,
            });
        }
        if let Some(tagged_raw) = tagged_raw.as_mut() {
            tagged_raw.push(raw);
        }
        compiled_rows.push(CompiledOrderedManyRow {
            pattern_id,
            program: Some(program),
        });
    }

    if compiled_rows.len() != row_count
        || tagged_raw
            .as_ref()
            .is_some_and(|tagged_raw| tagged_raw.len() != row_count)
    {
        return Err(OrderedManyCompileError::InternalInvariant(
            "compiled row tables lost source order",
        ));
    }
    let selector = match tagged_raw {
        None => OrderedManySelector::Fallback(OrderedManyFallbackReason::TaggedOwnerLimit {
            needed: row_count,
            limit: ORDERED_MANY_TAGGED_MAX_ROWS,
        }),
        Some(raw) => {
            match TaggedManyPlan::<DirectCount>::from_raw(
                raw,
                line_terminator,
                limits.lower.automata,
                limits.tagged,
            ) {
                Ok(plan) => OrderedManySelector::Tagged(plan),
                Err(source) if tagged_build_may_decline(&source) => {
                    OrderedManySelector::Fallback(OrderedManyFallbackReason::TaggedBuild(source))
                }
                Err(source) => return Err(OrderedManyCompileError::Tagged(source)),
            }
        }
    };
    let mut compiled_rows = compiled_rows.into_boxed_slice();
    if matches!(&selector, OrderedManySelector::Tagged(_)) {
        // Preserve the incumbent Vec-to-boxed-slice publication tail before
        // changing only the redundant scalar owners' deallocation timing.
        for compiled in &mut compiled_rows {
            drop(compiled.program.take());
        }
    }
    Ok(OrderedManyProgram {
        rows: compiled_rows,
        selector,
        profile,
        mode,
        line_terminator,
        stats: OrderedManyProgramStats {
            rows: row_count,
            pattern_bytes,
            serialized_program_bytes: total_program_bytes,
        },
    })
}

/// Only bounded representation and cost refusals may select the already
/// complete semantic fallback. Malformed or internally inconsistent tagged
/// construction remains a terminal compiler failure.
fn tagged_build_may_decline(source: &TaggedManyBuildError) -> bool {
    matches!(
        source,
        TaggedManyBuildError::PatternLimit { .. }
            | TaggedManyBuildError::SourceStatesLimit { .. }
            | TaggedManyBuildError::SourceEdgesLimit { .. }
            | TaggedManyBuildError::SharedStatesLimit { .. }
            | TaggedManyBuildError::SharedEdgesLimit { .. }
            | TaggedManyBuildError::OwnerStateMembershipLimit { .. }
            | TaggedManyBuildError::OwnerEdgeMembershipLimit { .. }
            | TaggedManyBuildError::WorkLimit { .. }
            | TaggedManyBuildError::PersistentLimit { .. }
            | TaggedManyBuildError::PeakLimit { .. }
            | TaggedManyBuildError::AllocationAttemptsLimit { .. }
            | TaggedManyBuildError::ZeroWidthCycle { .. }
            | TaggedManyBuildError::SignatureCollisionLimit { .. }
    )
}

fn validate_profile(profile: &RustProfile) -> Result<(), OrderedManyCompileError> {
    let compatible = match &profile.constructor {
        RustConstructor::RegexBuilder {
            bytes_syntax_utf8,
            bytes_utf8_empty,
            match_kind,
            ..
        } => {
            !*bytes_syntax_utf8 && !*bytes_utf8_empty && *match_kind == RustMatchKind::LeftmostFirst
        }
        RustConstructor::RebarMeta {
            syntax_utf8,
            utf8_empty,
            match_kind,
            build_many_ordered,
            ..
        } => {
            !*syntax_utf8
                && !*utf8_empty
                && *match_kind == RustMatchKind::LeftmostFirst
                && *build_many_ordered
        }
        RustConstructor::RegexSetBuilder { .. } => false,
    };
    if compatible {
        Ok(())
    } else {
        Err(OrderedManyCompileError::UnsupportedProfile {
            requirement: "leftmost-first Rust bytes with byte-progress empty matches and ordered rows",
        })
    }
}

fn publish_tagged_trace(
    program: &OrderedManyProgram,
    trace: &fre_automata::TaggedManyTraceSessionReport<'_, u64>,
    output: &mut [OrderedManyMatch],
    max_match_events: usize,
) -> Result<OrderedManyFillReport, OrderedManyRunError> {
    if !trace.closes() {
        return Err(OrderedManyRunError::InternalInvariant(
            "tagged trace receipt did not close",
        ));
    }
    let selected = trace.matches().len();
    if selected > max_match_events {
        return Err(OrderedManyRunError::MatchEventLimit {
            needed: selected,
            limit: max_match_events,
        });
    }
    let reduced = usize::try_from(*trace.report().output()).map_err(|_| {
        OrderedManyRunError::ArithmeticOverflow {
            computation: "tagged match-count output",
        }
    })?;
    if reduced != selected {
        return Err(OrderedManyRunError::InternalInvariant(
            "tagged count differed from its ordinal trace",
        ));
    }
    // Authenticate every source ordinal before the first caller slot is
    // changed. The immutable program makes the second mapping pass infallible
    // unless an internal invariant has changed concurrently, which Rust's
    // shared borrow excludes.
    for &matched in trace.matches() {
        let _ = map_priority_match(program, matched)?;
    }
    let written = selected.min(output.len());
    for (slot, selected) in output.iter_mut().zip(trace.matches()).take(written) {
        *slot = map_priority_match(program, *selected)?;
    }
    Ok(OrderedManyFillReport {
        strategy: OrderedManyStrategy::TaggedMany,
        selected,
        written,
    })
}

fn map_priority_match(
    program: &OrderedManyProgram,
    selected: PriorityMatch,
) -> Result<OrderedManyMatch, OrderedManyRunError> {
    let ordinal = selected.ordinal().get();
    let row = usize::try_from(ordinal).map_err(|_| OrderedManyRunError::ArithmeticOverflow {
        computation: "tagged source ordinal",
    })?;
    let pattern_id = program
        .rows
        .get(row)
        .ok_or(OrderedManyRunError::InternalInvariant(
            "tagged source ordinal exceeded compiled rows",
        ))?
        .pattern_id;
    Ok(OrderedManyMatch::from_parts(
        pattern_id,
        ordinal,
        selected.start(),
        selected.end(),
    ))
}

#[derive(Clone, Copy, Debug)]
struct FallbackCandidate {
    row: usize,
    start: usize,
    end: usize,
}

#[allow(
    clippy::too_many_lines,
    reason = "global k-way selection, empty suppression, caller-prefix publication, and terminal progress remain one auditable loop"
)]
fn execute_fallback(
    program: &OrderedManyProgram,
    workspaces: &mut [ProgramWorkspace],
    haystack: &[u8],
    output: &mut [OrderedManyMatch],
    max_match_events: usize,
) -> Result<OrderedManyFillReport, OrderedManyRunError> {
    if workspaces.len() != program.rows.len() {
        return Err(OrderedManyRunError::InternalInvariant(
            "fallback workspace table lost source-row shape",
        ));
    }
    let mut cursor = 0usize;
    let mut suppress_empty_at = None::<usize>;
    let mut selected = 0usize;
    let mut written = 0usize;
    while cursor <= haystack.len() {
        let mut best = None::<FallbackCandidate>;
        for (row, compiled) in program.rows.iter().enumerate() {
            let workspace =
                workspaces
                    .get_mut(row)
                    .ok_or(OrderedManyRunError::InternalInvariant(
                        "fallback row omitted its workspace",
                    ))?;
            let Some(program) = compiled.program.as_ref() else {
                return Err(OrderedManyRunError::InternalInvariant(
                    "semantic fallback row lost its scalar program",
                ));
            };
            let result = program
                .search_with_workspace(
                    haystack,
                    SearchWindow::new(cursor, haystack.len()),
                    workspace,
                )
                .map_err(|source| OrderedManyRunError::RowSearch {
                    row,
                    pattern_id: compiled.pattern_id,
                    source,
                })?;
            let MatchResult::Span(found) = result else {
                return Err(OrderedManyRunError::InternalInvariant(
                    "fallback row lost its Span contract",
                ));
            };
            let Some((start, end)) = found else {
                continue;
            };
            // Source row is the implicit secondary key. Iteration is already
            // in source order, so equal starts never replace the incumbent.
            if best.is_none_or(|candidate| start < candidate.start) {
                best = Some(FallbackCandidate { row, start, end });
            }
        }
        let Some(candidate) = best else {
            break;
        };
        if candidate.start == candidate.end && suppress_empty_at == Some(candidate.start) {
            if candidate.start == haystack.len() {
                break;
            }
            cursor =
                candidate
                    .start
                    .checked_add(1)
                    .ok_or(OrderedManyRunError::ArithmeticOverflow {
                        computation: "suppressed empty-match progress",
                    })?;
            continue;
        }
        let needed = selected
            .checked_add(1)
            .ok_or(OrderedManyRunError::ArithmeticOverflow {
                computation: "selected match count",
            })?;
        if needed > max_match_events {
            return Err(OrderedManyRunError::MatchEventLimit {
                needed,
                limit: max_match_events,
            });
        }
        let ordinal =
            u32::try_from(candidate.row).map_err(|_| OrderedManyRunError::ArithmeticOverflow {
                computation: "fallback source ordinal",
            })?;
        if let Some(slot) = output.get_mut(selected) {
            *slot = OrderedManyMatch::from_parts(
                program.rows[candidate.row].pattern_id,
                ordinal,
                candidate.start,
                candidate.end,
            );
            written = written
                .checked_add(1)
                .ok_or(OrderedManyRunError::ArithmeticOverflow {
                    computation: "written match count",
                })?;
        }
        selected = needed;
        if candidate.start == candidate.end {
            if candidate.start == haystack.len() {
                break;
            }
            cursor =
                candidate
                    .start
                    .checked_add(1)
                    .ok_or(OrderedManyRunError::ArithmeticOverflow {
                        computation: "empty-match progress",
                    })?;
        } else {
            suppress_empty_at = Some(candidate.end);
            cursor = candidate.end;
        }
    }
    Ok(OrderedManyFillReport {
        strategy: OrderedManyStrategy::SemanticFallback,
        selected,
        written,
    })
}

fn reserve_exact<T, E>(
    entries: usize,
    structure: &'static str,
    error: impl Fn(&'static str, usize) -> E,
) -> Result<Vec<T>, E> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(entries)
        .map_err(|_| error(structure, entries))?;
    if values.capacity() != entries {
        return Err(error(structure, values.capacity()));
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::{
        OrderedManyCompileLimits, OrderedManyCompileRequest, OrderedManyMatch,
        OrderedManyPatternId, OrderedManyProgram, OrderedManyRow, OrderedManySessionLimits,
        OrderedManyStrategy, compile_ordered_many, reserve_exact, tagged_build_may_decline,
    };
    use crate::CompileMode;
    use fre_automata::{CompileError, TaggedManyBuildError};

    fn retention_fixture(force_fallback: bool) -> OrderedManyProgram {
        let patterns = ["a", "", "a", "ab"];
        let ids = [700, 5, 900, 3];
        let rows = patterns
            .into_iter()
            .zip(ids)
            .map(|(pattern, id)| OrderedManyRow::new(OrderedManyPatternId::new(id), pattern))
            .collect();
        let mut limits = OrderedManyCompileLimits::default();
        if force_fallback {
            limits.tagged.max_patterns = 0;
        }
        compile_ordered_many(
            OrderedManyCompileRequest::new(rows)
                .mode(CompileMode::Fast)
                .limits(limits),
        )
        .expect("retention fixture")
    }

    fn retention_trace(program: &OrderedManyProgram) -> Vec<(u32, u32, usize, usize)> {
        let haystack = b"axxa";
        let mut session = program
            .prepare_session(haystack.len(), OrderedManySessionLimits::unlimited())
            .expect("retention session");
        let mut output = [OrderedManyMatch::default(); 5];
        let report = session.fill(haystack, &mut output).expect("retention fill");
        assert!(!report.truncated());
        output[..report.written()]
            .iter()
            .map(|matched| {
                (
                    matched.source_ordinal(),
                    matched.pattern_id().get(),
                    matched.start(),
                    matched.end(),
                )
            })
            .collect()
    }

    #[test]
    fn tagged_releases_scalar_owners_while_fallback_retains_them() {
        let tagged = retention_fixture(false);
        let fallback = retention_fixture(true);
        assert_eq!(OrderedManyStrategy::TaggedMany, tagged.strategy());
        assert_eq!(OrderedManyStrategy::SemanticFallback, fallback.strategy());
        assert_eq!(0, tagged.retained_scalar_programs_for_test());
        assert_eq!(4, fallback.retained_scalar_programs_for_test());
        assert!(tagged.stats().serialized_program_bytes > 0);
        assert_eq!(
            [700, 5, 900, 3],
            core::array::from_fn(|ordinal| tagged.pattern_id(ordinal).unwrap().get())
        );

        let expected = vec![(0, 700, 0, 1), (1, 5, 2, 2), (0, 700, 3, 4)];
        assert_eq!(expected, retention_trace(&tagged));
        assert_eq!(expected, retention_trace(&fallback));
    }

    #[test]
    fn fallback_rejects_a_missing_scalar_owner_as_an_invariant() {
        let mut fallback = retention_fixture(true);
        fallback.rows[2].program = None;
        assert!(matches!(
            fallback.prepare_session(4, OrderedManySessionLimits::unlimited()),
            Err(super::OrderedManyPrepareError::InternalInvariant(
                "semantic fallback row lost its scalar program"
            ))
        ));
    }

    #[test]
    fn tagged_decline_classification_is_monotone() {
        let declines = [
            TaggedManyBuildError::PatternLimit {
                needed: 2,
                limit: 1,
            },
            TaggedManyBuildError::SourceStatesLimit {
                needed: 2,
                limit: 1,
            },
            TaggedManyBuildError::SourceEdgesLimit {
                needed: 2,
                limit: 1,
            },
            TaggedManyBuildError::SharedStatesLimit {
                needed: 2,
                limit: 1,
            },
            TaggedManyBuildError::SharedEdgesLimit {
                needed: 2,
                limit: 1,
            },
            TaggedManyBuildError::OwnerStateMembershipLimit {
                needed: 2,
                limit: 1,
            },
            TaggedManyBuildError::OwnerEdgeMembershipLimit {
                needed: 2,
                limit: 1,
            },
            TaggedManyBuildError::WorkLimit {
                needed: 2,
                limit: 1,
            },
            TaggedManyBuildError::PersistentLimit {
                needed: 2,
                limit: 1,
            },
            TaggedManyBuildError::PeakLimit {
                needed: 2,
                limit: 1,
            },
            TaggedManyBuildError::AllocationAttemptsLimit {
                needed: 2,
                limit: 1,
            },
            TaggedManyBuildError::ZeroWidthCycle { pattern: 0 },
            TaggedManyBuildError::SignatureCollisionLimit {
                probes: 65,
                chain: 257,
            },
        ];
        assert!(declines.iter().all(tagged_build_may_decline));

        let terminal = [
            TaggedManyBuildError::EmptyPatternSet,
            TaggedManyBuildError::SourceCompile {
                pattern: 0,
                source: CompileError::ArithmeticOverflow {
                    computation: "test",
                },
            },
            TaggedManyBuildError::NonExactSourceCollectionCapacity {
                length: 1,
                capacity: 2,
            },
            TaggedManyBuildError::NonExactSourceCapacity {
                pattern: 0,
                table: "roles",
                length: 1,
                capacity: 2,
            },
            TaggedManyBuildError::MalformedSourceShape {
                pattern: 0,
                table: "roles",
                expected: 1,
                actual: 2,
            },
            TaggedManyBuildError::InvalidAcceptTerminalCount {
                pattern: 0,
                terminals: 2,
            },
            TaggedManyBuildError::ProjectionMismatch {
                pattern: 0,
                state: 0,
                edge: None,
            },
            TaggedManyBuildError::ArithmeticOverflow {
                computation: "test",
            },
            TaggedManyBuildError::AllocationFailed {
                structure: "test",
                entries: 1,
            },
            TaggedManyBuildError::InternalInvariant { detail: "test" },
        ];
        assert!(
            terminal
                .iter()
                .all(|source| !tagged_build_may_decline(source))
        );
    }

    #[test]
    fn bridge_reservations_have_exact_capacity_including_zero() {
        let empty =
            reserve_exact::<u8, _>(0, "empty", |structure, entries| (structure, entries)).unwrap();
        let nonempty =
            reserve_exact::<u8, _>(17, "nonempty", |structure, entries| (structure, entries))
                .unwrap();
        assert_eq!((0, 0), (empty.len(), empty.capacity()));
        assert_eq!((0, 17), (nonempty.len(), nonempty.capacity()));
    }
}
