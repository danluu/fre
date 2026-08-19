use fre_exact_alloc::{CopyError, ExactBoxOrUsize};
use fre_kernels::{
    AsciiByteSet, AsciiByteSetRunScanner, DirectBuildAttemptActual, DispatchPolicy,
    SimdDispatchContext,
};
use regex_syntax::{
    ParserBuilder,
    hir::{Class, Hir, HirKind, Look, Repetition},
};

use crate::{
    Match, SearchLimits, SearchWindow, aggregate_construction::AggregateInspectionAttemptError,
};

pub const UNICODE_PLAN_ID: &str = "unicode-word-run-linear-v1";
pub const ASCII_PLAN_ID: &str = "ascii-word-run-linear-v1";
pub const ASCII_WORD_BOUNDARY_PLAN_ID: &str = "ascii-word-boundary-linear-v1";
pub const AGGREGATE_COUNT_OPERATION_ID: &str = "word-run.count.v1";
pub const AGGREGATE_SPAN_SUM_OPERATION_ID: &str = "word-run.span-sum.v1";
pub const ASCII_WORD_BOUNDARY_COUNT_OPERATION_ID: &str = "ascii-word-boundary.count.v1";
pub const ASCII_WORD_BOUNDARY_SPAN_SUM_OPERATION_ID: &str =
    "ascii-word-boundary.span-sum.v1";
pub const FIXED_CLASS_CHUNKS_PLAN_ID: &str = "fixed-byte-class-chunks-linear-v1";
pub const FIXED_CLASS_CHUNKS_COUNT_OPERATION_ID: &str = "fixed-byte-class-chunks.count.v1";
pub const FIXED_CLASS_CHUNKS_SPAN_SUM_OPERATION_ID: &str = "fixed-byte-class-chunks.span-sum.v1";

const FIXED_BUILD_WORK: usize = 1;
// The scanner compiles both run-table representations in one complete
// 128-byte-domain pass and makes one paired-direction dispatch choice.
const ASCII_RUN_SCANNER_BUILD_WORK: usize = 128 + 1 + 1;
const FIXED_REDUCE_WORK: usize = 8;
const UNIT_WORK: usize = 4;
const RUN_WORK: usize = 2;
const MATCH_WORK: usize = 4;
// regex-syntax 0.8.11 is exact-pinned and lowers Unicode 16.0's Perl word
// property to this many canonical maximal ranges.
const UNICODE_WORD_RANGE_COUNT: usize = 796;
const ASCII_WORD_RANGES: [(u8, u8); 4] = [(b'0', b'9'), (b'A', b'Z'), (b'_', b'_'), (b'a', b'z')];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WordMode {
    Ascii,
    Unicode,
}

/// Source-derived match topology retained by the direct word-run operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WordRunTopology {
    /// The canonical HIR proved matching word-boundary assertions at both
    /// endpoints.
    CompleteWordBoundaries,
    /// The canonical HIR proved one bare greedy nonempty unbounded root word
    /// repetition. Whole-input aggregate iteration therefore emits the same
    /// maximal runs without asserting either endpoint.
    BareGreedyRoot,
    /// One canonical Unicode-off ASCII word-boundary assertion. Every maximal
    /// ASCII word run contributes its two zero-width boundary matches.
    AsciiBoundaryOnly,
    /// One exact-width canonical byte-class repetition emits consecutive
    /// chunks from each maximal admitted run.
    FixedClassChunks,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Plan {
    Word {
        minimum_scalars: usize,
        mode: WordMode,
        topology: WordRunTopology,
    },
    FixedClassChunks {
        chunk_bytes: usize,
        class_words: [u64; 4],
    },
}

/// Production owner for the ASCII word-run shape.
///
/// Keeping this distinct from [`Plan`] leaves the Unicode and fixed-class
/// artifacts at their established exact storage while the ASCII route retains
/// its immutable automatic dispatch choice.
#[derive(Debug)]
pub(crate) struct AsciiPlan {
    owner: ExactBoxOrUsize<AsciiPlanOwner>,
}

#[derive(Debug)]
struct AsciiPlanOwner {
    plan: Plan,
    run_scanner: AsciiByteSetRunScanner,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Accounting {
    pub(crate) work: u64,
    pub(crate) bytes_examined: usize,
    pub(crate) scalars_decoded: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each boolean is an independently authenticated regex semantic, not mutable state"
)]
pub struct AggregateOperationIdentity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub minimum_scalars: usize,
    pub fixed_chunk_bytes: Option<usize>,
    pub canonical_class_words: [u64; 4],
    pub unicode: bool,
    pub greedy: bool,
    pub topology: WordRunTopology,
    pub complete_word_boundaries: bool,
    pub invalid_bytes_are_non_word: bool,
    pub arbitrary_bytes_are_classified: bool,
    pub non_overlapping: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateBuildLimits {
    pub max_build_work: usize,
    pub max_scratch_bytes: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl AggregateBuildLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_build_work: usize::MAX,
            max_scratch_bytes: usize::MAX,
            max_persistent_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for AggregateBuildLimits {
    fn default() -> Self {
        Self {
            max_build_work: 4_096,
            max_scratch_bytes: 0,
            max_persistent_bytes: 4_096,
            max_peak_bytes: 4_096,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateBuildAccounting {
    pub work_upper_bound: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Authenticate build accounting against the storage and scanner retained by
/// an operation identity.
///
/// Keeping this check beside the private owner layouts prevents adapters from
/// freezing the pre-dispatch scalar work or storage formula.
#[must_use]
pub fn aggregate_build_accounting_matches(
    identity: AggregateOperationIdentity,
    accounting: AggregateBuildAccounting,
) -> bool {
    let (scanner_work, persistent_bytes) = match identity.plan_id {
        ASCII_PLAN_ID | ASCII_WORD_BOUNDARY_PLAN_ID => {
            (ASCII_RUN_SCANNER_BUILD_WORK, AsciiPlan::persistent_bytes())
        }
        UNICODE_PLAN_ID | FIXED_CLASS_CHUNKS_PLAN_ID => (0, core::mem::size_of::<Plan>()),
        _ => return false,
    };
    FIXED_BUILD_WORK
        .checked_add(scanner_work)
        .is_some_and(|work_upper_bound| {
            accounting
                == AggregateBuildAccounting {
                    work_upper_bound,
                    scratch_bytes: 0,
                    persistent_bytes,
                    peak_bytes: persistent_bytes,
                }
        })
}

#[derive(Debug)]
pub(crate) struct AggregateBuildAttempt {
    accounting: AggregateBuildAccounting,
    actual: DirectBuildAttemptActual,
}

impl AggregateBuildAttempt {
    pub(crate) const fn into_parts(self) -> (AggregateBuildAccounting, DirectBuildAttemptActual) {
        (self.accounting, self.actual)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AggregateBuildAttemptError {
    source: AggregateBuildError,
    actual: DirectBuildAttemptActual,
}

impl AggregateBuildAttemptError {
    pub(crate) const fn actual(&self) -> DirectBuildAttemptActual {
        self.actual
    }

    pub(crate) const fn into_source(self) -> AggregateBuildError {
        self.source
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateReduceLimits {
    pub max_input_bytes: usize,
    pub max_source_reads: usize,
    pub max_work: usize,
    pub max_unit_events: usize,
    pub max_run_events: usize,
    pub max_match_events: usize,
    pub max_count: u64,
    pub max_span_sum: u64,
    pub max_scratch_bytes: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl AggregateReduceLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_input_bytes: usize::MAX,
            max_source_reads: usize::MAX,
            max_work: usize::MAX,
            max_unit_events: usize::MAX,
            max_run_events: usize::MAX,
            max_match_events: usize::MAX,
            max_count: u64::MAX,
            max_span_sum: u64::MAX,
            max_scratch_bytes: usize::MAX,
            max_persistent_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for AggregateReduceLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 512 * 1024 * 1024,
            max_source_reads: 512 * 1024 * 1024,
            max_work: 16 * 1024 * 1024 * 1024,
            max_unit_events: 512 * 1024 * 1024,
            max_run_events: 512 * 1024 * 1024,
            max_match_events: 512 * 1024 * 1024,
            max_count: 512 * 1024 * 1024,
            max_span_sum: u64::MAX,
            max_scratch_bytes: 0,
            max_persistent_bytes: 4_096,
            max_peak_bytes: 4_096,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateReduceUpperBounds {
    pub input_bytes: usize,
    pub source_reads: usize,
    pub work: usize,
    pub unit_events: usize,
    pub run_events: usize,
    pub match_events: usize,
    pub count: u64,
    pub span_sum: u64,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateReduceActual {
    pub source_reads: usize,
    pub work: usize,
    pub units: usize,
    pub runs: usize,
    pub matches: usize,
    pub count: u64,
    pub span_sum: u64,
    pub scratch_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateReduceAccounting {
    pub identity: AggregateOperationIdentity,
    pub upper_bounds: AggregateReduceUpperBounds,
    pub actual: AggregateReduceActual,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateCountResult {
    pub count: u64,
    pub accounting: AggregateReduceAccounting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateSpanSumResult {
    pub span_sum: u64,
    pub accounting: AggregateReduceAccounting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AggregateBuildError {
    WorkLimit { needed: usize, limit: usize },
    ScratchLimit { needed: usize, limit: usize },
    PersistentLimit { needed: usize, limit: usize },
    PeakLimit { needed: usize, limit: usize },
    AllocationFailed { bytes: usize },
    ArithmeticOverflow { computation: &'static str },
}

impl core::fmt::Display for AggregateBuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "word-run aggregate build failed: {self:?}")
    }
}

impl std::error::Error for AggregateBuildError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateReduceResource {
    SourceReads,
    Work,
    UnitEvents,
    RunEvents,
    MatchEvents,
    Count,
    SpanSum,
    ScratchBytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AggregateReduceError {
    InputBytesLimit {
        needed: usize,
        limit: usize,
    },
    SourceReadsLimit {
        needed: usize,
        limit: usize,
    },
    WorkLimit {
        needed: usize,
        limit: usize,
    },
    UnitEventsLimit {
        needed: usize,
        limit: usize,
    },
    RunEventsLimit {
        needed: usize,
        limit: usize,
    },
    MatchEventsLimit {
        needed: usize,
        limit: usize,
    },
    CountLimit {
        needed: u64,
        limit: u64,
    },
    SpanSumLimit {
        needed: u64,
        limit: u64,
    },
    ScratchLimit {
        needed: usize,
        limit: usize,
    },
    PersistentLimit {
        needed: usize,
        limit: usize,
    },
    PeakLimit {
        needed: usize,
        limit: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    AccountingInvariant {
        resource: AggregateReduceResource,
        actual: u64,
        upper: u64,
    },
}

impl core::fmt::Display for AggregateReduceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "word-run aggregate reduction failed: {self:?}")
    }
}

impl std::error::Error for AggregateReduceError {}

#[derive(Clone, Copy, Debug)]
pub(crate) struct AggregateInspection {
    pub(crate) plan: Plan,
    pub(crate) work: usize,
    pub(crate) hir_nodes: usize,
    pub(crate) captures: usize,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum AggregateInspectionOutcome {
    Eligible(AggregateInspection),
    Ineligible { work: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AggregateInspectionError {
    WorkLimit { needed: usize, limit: usize },
    Overflow,
}

impl Accounting {
    #[must_use]
    pub const fn work(self) -> u64 {
        self.work
    }

    #[must_use]
    pub const fn bytes_examined(self) -> usize {
        self.bytes_examined
    }

    #[must_use]
    pub const fn scalars_decoded(self) -> usize {
        self.scalars_decoded
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidWindow {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
    WorkLimitExceeded {
        needed: u64,
        limit: u64,
    },
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::InvalidWindow {
                start,
                end,
                haystack_len,
            } => write!(
                f,
                "word-run window {start}..{end} exceeds haystack length {haystack_len}"
            ),
            Self::WorkLimitExceeded { needed, limit } => write!(
                f,
                "word-run search needs {needed} work units, exceeding {limit}"
            ),
        }
    }
}

impl std::error::Error for Error {}

impl AsciiPlan {
    #[inline(never)]
    pub(crate) fn build_auto(plan: Plan) -> Result<Self, CopyError> {
        debug_assert!(plan.is_ascii_word());
        let run_scanner = SimdDispatchContext::capture()
            .ascii_byte_set_run_scanner(ascii_word_set(), DispatchPolicy::Auto)
            .expect("automatic ASCII run dispatch always retains a scalar fallback");
        ExactBoxOrUsize::try_from_boxed(AsciiPlanOwner { plan, run_scanner })
            .map(|owner| Self { owner })
    }

    const fn persistent_bytes() -> usize {
        core::mem::size_of::<Self>()
            .checked_add(core::mem::size_of::<AsciiPlanOwner>())
            .expect("the fixed ASCII plan layouts fit usize")
    }

    pub(crate) const fn allocation_bytes() -> usize {
        core::mem::size_of::<AsciiPlanOwner>()
    }

    fn owner(&self) -> &AsciiPlanOwner {
        self.owner
            .boxed()
            .expect("the ASCII plan retains its exact owner allocation")
    }

    fn run_scanner(&self) -> &AsciiByteSetRunScanner {
        &self.owner().run_scanner
    }

    pub(crate) fn aggregate_count(
        &self,
        haystack: &[u8],
        limits: AggregateReduceLimits,
    ) -> Result<AggregateCountResult, AggregateReduceError> {
        self.owner().plan.aggregate_count_with_ascii_scanner(
            haystack,
            limits,
            self.run_scanner(),
            Self::persistent_bytes(),
        )
    }

    /// Return only a successfully admitted count without materializing exact
    /// execution accounting.
    ///
    /// `None` deliberately carries no terminal error. A caller that publishes
    /// errors must replay [`Self::aggregate_count`] with the same arguments.
    #[must_use]
    #[inline]
    pub(crate) fn aggregate_count_value_success(
        &self,
        haystack: &[u8],
        limits: AggregateReduceLimits,
    ) -> Option<u64> {
        self.owner()
            .plan
            .aggregate_count_value_success_with_ascii_scanner(
                haystack,
                limits,
                self.run_scanner(),
                Self::persistent_bytes(),
            )
    }

    pub(crate) fn aggregate_span_sum(
        &self,
        haystack: &[u8],
        limits: AggregateReduceLimits,
    ) -> Result<AggregateSpanSumResult, AggregateReduceError> {
        self.owner().plan.aggregate_span_sum_with_ascii_scanner(
            haystack,
            limits,
            self.run_scanner(),
            Self::persistent_bytes(),
        )
    }

    /// Return only a successfully admitted span sum without materializing
    /// exact execution accounting.
    ///
    /// `None` deliberately carries no terminal error. A caller that publishes
    /// errors must replay [`Self::aggregate_span_sum`] with the same arguments.
    #[must_use]
    #[inline]
    pub(crate) fn aggregate_span_sum_value_success(
        &self,
        haystack: &[u8],
        limits: AggregateReduceLimits,
    ) -> Option<u64> {
        self.owner()
            .plan
            .aggregate_span_sum_value_success_with_ascii_scanner(
                haystack,
                limits,
                self.run_scanner(),
                Self::persistent_bytes(),
            )
    }

    pub(crate) fn find_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, Accounting), Error> {
        validate_window(haystack, window)?;
        self.owner().plan.find_ascii_window_with_scanner(
            haystack,
            window,
            limits,
            self.run_scanner(),
        )
    }

    pub(crate) fn is_match_window_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<bool, Error> {
        if full_window_value_scan_is_prepaid(haystack, window, limits) {
            return Ok(ascii_word_run_exists(
                haystack,
                self.owner().plan.word_minimum_scalars(),
            ));
        }
        self.find_window(haystack, window, limits)
            .map(|(matched, _accounting)| matched.is_some())
    }
}

impl Plan {
    const fn new(minimum_scalars: usize, mode: WordMode) -> Self {
        Self::Word {
            minimum_scalars,
            mode,
            topology: WordRunTopology::CompleteWordBoundaries,
        }
    }

    const fn bare_greedy(minimum_scalars: usize, mode: WordMode) -> Self {
        Self::Word {
            minimum_scalars,
            mode,
            topology: WordRunTopology::BareGreedyRoot,
        }
    }

    const fn ascii_boundary_only() -> Self {
        Self::Word {
            minimum_scalars: 0,
            mode: WordMode::Ascii,
            topology: WordRunTopology::AsciiBoundaryOnly,
        }
    }

    const fn fixed_class_chunks(chunk_bytes: usize, class_words: [u64; 4]) -> Self {
        Self::FixedClassChunks {
            chunk_bytes,
            class_words,
        }
    }

    pub(crate) const fn plan_id(self) -> &'static str {
        match self {
            Self::Word {
                mode: WordMode::Ascii,
                topology: WordRunTopology::AsciiBoundaryOnly,
                ..
            } => ASCII_WORD_BOUNDARY_PLAN_ID,
            Self::Word {
                mode: WordMode::Ascii,
                ..
            } => ASCII_PLAN_ID,
            Self::Word {
                mode: WordMode::Unicode,
                ..
            } => UNICODE_PLAN_ID,
            Self::FixedClassChunks { .. } => FIXED_CLASS_CHUNKS_PLAN_ID,
        }
    }

    pub(crate) const fn is_ascii_word(self) -> bool {
        matches!(
            self,
            Self::Word {
                mode: WordMode::Ascii,
                ..
            }
        )
    }

    pub(crate) const fn is_fixed_class_chunks(self) -> bool {
        matches!(self, Self::FixedClassChunks { .. })
    }

    pub(crate) const fn portable_build_work(self) -> usize {
        let scanner_work = if self.is_ascii_word() {
            ASCII_RUN_SCANNER_BUILD_WORK
        } else {
            0
        };
        FIXED_BUILD_WORK
            .checked_add(scanner_work)
            .expect("the fixed word-run build work fits usize")
    }

    pub(crate) const fn portable_storage_bytes(self) -> usize {
        if self.is_ascii_word() {
            AsciiPlan::persistent_bytes()
        } else {
            core::mem::size_of::<Self>()
        }
    }

    /// Execute one full-window existence query after the caller has admitted
    /// the complete source-independent work envelope.
    #[must_use]
    pub(crate) fn is_match_full_prepared(self, haystack: &[u8]) -> bool {
        debug_assert!(matches!(
            self,
            Self::Word {
                mode: WordMode::Unicode,
                ..
            }
        ));
        self.is_match_unicode_full_prepared(haystack)
    }

    fn is_match_unicode_full_prepared(self, haystack: &[u8]) -> bool {
        debug_assert!(matches!(
            self,
            Self::Word {
                mode: WordMode::Unicode,
                ..
            }
        ));
        let minimum_scalars = self.word_minimum_scalars();
        // This value-only route is entered only after the caller has
        // authenticated the retained plan and admitted the complete finite
        // input/work envelope. Every Unicode scalar occupies at least one
        // byte, while malformed bytes are non-word context, so a shorter byte
        // domain cannot contain the required scalar run and needs no source
        // inspection.
        if haystack.len() < minimum_scalars {
            return false;
        }
        let complete_word_boundaries = self.has_complete_word_boundaries();
        let mut run_scalars = 0_usize;
        let mut run_start_is_boundary = false;
        let mut position = 0_usize;
        while position < haystack.len() {
            let byte = haystack[position];
            if byte.is_ascii() {
                if is_ascii_word(byte) {
                    if run_scalars == 0 {
                        run_start_is_boundary = !complete_word_boundaries
                            || unicode_word_boundary_before(haystack, position);
                    }
                    run_scalars += 1;
                    if !complete_word_boundaries && run_scalars >= minimum_scalars {
                        return true;
                    }
                } else {
                    if complete_word_boundaries
                        && run_start_is_boundary
                        && run_scalars >= minimum_scalars
                    {
                        return true;
                    }
                    run_scalars = 0;
                    run_start_is_boundary = false;
                }
                position += 1;
                continue;
            }

            let Some((scalar, width)) = decode_first(&haystack[position..]) else {
                // A malformed byte is non-word right context, so it may close
                // the preceding valid run. The reverse boundary decoder below
                // determines the exact context seen by a following run.
                if complete_word_boundaries
                    && run_start_is_boundary
                    && run_scalars >= minimum_scalars
                {
                    return true;
                }
                run_scalars = 0;
                run_start_is_boundary = false;
                position += 1;
                continue;
            };
            if is_unicode_word(scalar) {
                if run_scalars == 0 {
                    run_start_is_boundary = !complete_word_boundaries
                        || unicode_word_boundary_before(haystack, position);
                }
                run_scalars += 1;
                if !complete_word_boundaries && run_scalars >= minimum_scalars {
                    return true;
                }
            } else {
                if complete_word_boundaries
                    && run_start_is_boundary
                    && run_scalars >= minimum_scalars
                {
                    return true;
                }
                run_scalars = 0;
                run_start_is_boundary = false;
            }
            position += width;
        }
        complete_word_boundaries
            && run_start_is_boundary
            && run_scalars >= minimum_scalars
            && unicode_word_boundary_after(haystack, position)
    }

    const fn minimum_match_units(self) -> usize {
        match self {
            Self::Word {
                minimum_scalars, ..
            } => minimum_scalars,
            Self::FixedClassChunks { chunk_bytes, .. } => chunk_bytes,
        }
    }

    const fn is_ascii_boundary_only(self) -> bool {
        matches!(
            self,
            Self::Word {
                mode: WordMode::Ascii,
                topology: WordRunTopology::AsciiBoundaryOnly,
                ..
            }
        )
    }

    fn word_minimum_scalars(self) -> usize {
        match self {
            Self::Word {
                minimum_scalars, ..
            } => minimum_scalars,
            Self::FixedClassChunks { .. } => {
                unreachable!("fixed-class chunk plans never enter word search")
            }
        }
    }

    fn has_complete_word_boundaries(self) -> bool {
        match self {
            Self::Word { topology, .. } => {
                matches!(topology, WordRunTopology::CompleteWordBoundaries)
            }
            Self::FixedClassChunks { .. } => {
                unreachable!("fixed-class chunk plans never enter word search")
            }
        }
    }

    pub(crate) fn aggregate_build_attempt(
        self,
        limits: AggregateBuildLimits,
    ) -> Result<AggregateBuildAttempt, AggregateBuildAttemptError> {
        let attempt = || -> Result<AggregateBuildAttempt, AggregateBuildError> {
            let retains_ascii_scanner = self.is_ascii_word();
            let scanner_work = if retains_ascii_scanner {
                ASCII_RUN_SCANNER_BUILD_WORK
            } else {
                0
            };
            let work_upper_bound = FIXED_BUILD_WORK.checked_add(scanner_work).ok_or(
                AggregateBuildError::ArithmeticOverflow {
                    computation: "word-run build work",
                },
            )?;
            let persistent_bytes = self.portable_storage_bytes();
            let accounting = AggregateBuildAccounting {
                work_upper_bound,
                scratch_bytes: 0,
                persistent_bytes,
                peak_bytes: persistent_bytes,
            };
            enforce_build(
                accounting.work_upper_bound,
                limits.max_build_work,
                AggregateBuildResource::Work,
            )?;
            enforce_build(
                accounting.scratch_bytes,
                limits.max_scratch_bytes,
                AggregateBuildResource::Scratch,
            )?;
            enforce_build(
                accounting.persistent_bytes,
                limits.max_persistent_bytes,
                AggregateBuildResource::Persistent,
            )?;
            enforce_build(
                accounting.peak_bytes,
                limits.max_peak_bytes,
                AggregateBuildResource::Peak,
            )?;
            let work = u64::try_from(work_upper_bound).map_err(|_| {
                AggregateBuildError::ArithmeticOverflow {
                    computation: "word-run build work as u64",
                }
            })?;
            Ok(AggregateBuildAttempt {
                accounting,
                actual: DirectBuildAttemptActual {
                    work,
                    allocations: usize::from(retains_ascii_scanner),
                    allocated_bytes: if retains_ascii_scanner {
                        core::mem::size_of::<AsciiPlanOwner>()
                    } else {
                        0
                    },
                    copied_bytes: 0,
                    initialized_bytes: accounting.persistent_bytes,
                    live_persistent_bytes: accounting.persistent_bytes,
                    peak_bytes: accounting.peak_bytes,
                },
            })
        };
        attempt().map_err(|source| AggregateBuildAttemptError {
            source,
            actual: DirectBuildAttemptActual::default(),
        })
    }

    pub(crate) const fn aggregate_count_identity(self) -> AggregateOperationIdentity {
        self.aggregate_identity(match self {
            Self::Word {
                topology: WordRunTopology::AsciiBoundaryOnly,
                ..
            } => ASCII_WORD_BOUNDARY_COUNT_OPERATION_ID,
            Self::Word { .. } => AGGREGATE_COUNT_OPERATION_ID,
            Self::FixedClassChunks { .. } => FIXED_CLASS_CHUNKS_COUNT_OPERATION_ID,
        })
    }

    pub(crate) const fn aggregate_span_sum_identity(self) -> AggregateOperationIdentity {
        self.aggregate_identity(match self {
            Self::Word {
                topology: WordRunTopology::AsciiBoundaryOnly,
                ..
            } => ASCII_WORD_BOUNDARY_SPAN_SUM_OPERATION_ID,
            Self::Word { .. } => AGGREGATE_SPAN_SUM_OPERATION_ID,
            Self::FixedClassChunks { .. } => FIXED_CLASS_CHUNKS_SPAN_SUM_OPERATION_ID,
        })
    }

    const fn aggregate_identity(self, operation_id: &'static str) -> AggregateOperationIdentity {
        let (
            minimum_scalars,
            fixed_chunk_bytes,
            canonical_class_words,
            unicode,
            topology,
            complete_word_boundaries,
            invalid_bytes_are_non_word,
            arbitrary_bytes_are_classified,
        ) = match self {
            Self::Word {
                minimum_scalars,
                mode,
                topology,
            } => (
                minimum_scalars,
                None,
                [0; 4],
                matches!(mode, WordMode::Unicode),
                topology,
                matches!(topology, WordRunTopology::CompleteWordBoundaries),
                true,
                false,
            ),
            Self::FixedClassChunks {
                chunk_bytes,
                class_words,
            } => (
                0,
                Some(chunk_bytes),
                class_words,
                false,
                WordRunTopology::FixedClassChunks,
                false,
                false,
                true,
            ),
        };
        AggregateOperationIdentity {
            plan_id: self.plan_id(),
            operation_id,
            minimum_scalars,
            fixed_chunk_bytes,
            canonical_class_words,
            unicode,
            greedy: !matches!(topology, WordRunTopology::AsciiBoundaryOnly),
            topology,
            complete_word_boundaries,
            invalid_bytes_are_non_word,
            arbitrary_bytes_are_classified,
            non_overlapping: true,
        }
    }

    pub(crate) fn aggregate_count(
        self,
        haystack: &[u8],
        limits: AggregateReduceLimits,
    ) -> Result<AggregateCountResult, AggregateReduceError> {
        let upper = self.aggregate_preflight(
            haystack.len(),
            AggregateOperation::Count,
            limits,
            core::mem::size_of::<Self>(),
        )?;
        let actual = self.aggregate_scan(haystack, AggregateOperation::Count, upper)?;
        Ok(AggregateCountResult {
            count: actual.count,
            accounting: AggregateReduceAccounting {
                identity: self.aggregate_count_identity(),
                upper_bounds: upper,
                actual,
            },
        })
    }

    /// Return only a successfully admitted fixed-width byte-class chunk count
    /// without materializing exact execution accounting.
    ///
    /// `None` deliberately carries no terminal error. A caller that publishes
    /// errors must replay [`Self::aggregate_count`] with the same arguments.
    #[must_use]
    #[inline]
    pub(crate) fn aggregate_fixed_chunk_count_value_success(
        self,
        haystack: &[u8],
        limits: AggregateReduceLimits,
    ) -> Option<u64> {
        debug_assert!(self.is_fixed_class_chunks());
        let upper = self
            .aggregate_preflight(
                haystack.len(),
                AggregateOperation::Count,
                limits,
                core::mem::size_of::<Self>(),
            )
            .ok()?;
        self.aggregate_scan_fixed_chunk_count_value(haystack, upper)
    }

    pub(crate) fn aggregate_span_sum(
        self,
        haystack: &[u8],
        limits: AggregateReduceLimits,
    ) -> Result<AggregateSpanSumResult, AggregateReduceError> {
        let upper = self.aggregate_preflight(
            haystack.len(),
            AggregateOperation::SpanSum,
            limits,
            core::mem::size_of::<Self>(),
        )?;
        let actual = self.aggregate_scan(haystack, AggregateOperation::SpanSum, upper)?;
        Ok(AggregateSpanSumResult {
            span_sum: actual.span_sum,
            accounting: AggregateReduceAccounting {
                identity: self.aggregate_span_sum_identity(),
                upper_bounds: upper,
                actual,
            },
        })
    }

    /// Return only a successfully admitted fixed-width byte-class chunk span
    /// sum without materializing exact execution accounting.
    ///
    /// `None` deliberately carries no terminal error. A caller that publishes
    /// errors must replay [`Self::aggregate_span_sum`] with the same arguments.
    #[must_use]
    #[inline]
    pub(crate) fn aggregate_fixed_chunk_span_sum_value_success(
        self,
        haystack: &[u8],
        limits: AggregateReduceLimits,
    ) -> Option<u64> {
        debug_assert!(self.is_fixed_class_chunks());
        let upper = self
            .aggregate_preflight(
                haystack.len(),
                AggregateOperation::SpanSum,
                limits,
                core::mem::size_of::<Self>(),
            )
            .ok()?;
        self.aggregate_scan_fixed_chunk_span_sum_value(haystack, upper)
    }

    fn aggregate_count_with_ascii_scanner(
        self,
        haystack: &[u8],
        limits: AggregateReduceLimits,
        scanner: &AsciiByteSetRunScanner,
        persistent_bytes: usize,
    ) -> Result<AggregateCountResult, AggregateReduceError> {
        let upper = self.aggregate_preflight(
            haystack.len(),
            AggregateOperation::Count,
            limits,
            persistent_bytes,
        )?;
        let actual =
            self.aggregate_scan_ascii(haystack, AggregateOperation::Count, upper, scanner)?;
        Ok(AggregateCountResult {
            count: actual.count,
            accounting: AggregateReduceAccounting {
                identity: self.aggregate_count_identity(),
                upper_bounds: upper,
                actual,
            },
        })
    }

    #[inline]
    fn aggregate_count_value_success_with_ascii_scanner(
        self,
        haystack: &[u8],
        limits: AggregateReduceLimits,
        scanner: &AsciiByteSetRunScanner,
        persistent_bytes: usize,
    ) -> Option<u64> {
        let upper = self
            .aggregate_preflight(
                haystack.len(),
                AggregateOperation::Count,
                limits,
                persistent_bytes,
            )
            .ok()?;
        self.aggregate_scan_ascii_count_value(haystack, upper, scanner)
    }

    fn aggregate_span_sum_with_ascii_scanner(
        self,
        haystack: &[u8],
        limits: AggregateReduceLimits,
        scanner: &AsciiByteSetRunScanner,
        persistent_bytes: usize,
    ) -> Result<AggregateSpanSumResult, AggregateReduceError> {
        let upper = self.aggregate_preflight(
            haystack.len(),
            AggregateOperation::SpanSum,
            limits,
            persistent_bytes,
        )?;
        let actual =
            self.aggregate_scan_ascii(haystack, AggregateOperation::SpanSum, upper, scanner)?;
        Ok(AggregateSpanSumResult {
            span_sum: actual.span_sum,
            accounting: AggregateReduceAccounting {
                identity: self.aggregate_span_sum_identity(),
                upper_bounds: upper,
                actual,
            },
        })
    }

    #[inline]
    fn aggregate_span_sum_value_success_with_ascii_scanner(
        self,
        haystack: &[u8],
        limits: AggregateReduceLimits,
        scanner: &AsciiByteSetRunScanner,
        persistent_bytes: usize,
    ) -> Option<u64> {
        let upper = self
            .aggregate_preflight(
                haystack.len(),
                AggregateOperation::SpanSum,
                limits,
                persistent_bytes,
            )
            .ok()?;
        self.aggregate_scan_ascii_span_sum_value(haystack, upper, scanner)
    }

    fn aggregate_preflight(
        self,
        input_bytes: usize,
        operation: AggregateOperation,
        limits: AggregateReduceLimits,
        persistent_bytes: usize,
    ) -> Result<AggregateReduceUpperBounds, AggregateReduceError> {
        let upper = self.aggregate_upper_bounds(input_bytes, operation, persistent_bytes)?;
        enforce_reduce(upper, limits)?;
        Ok(upper)
    }

    fn aggregate_upper_bounds(
        self,
        input_bytes: usize,
        operation: AggregateOperation,
        persistent_bytes: usize,
    ) -> Result<AggregateReduceUpperBounds, AggregateReduceError> {
        let unit_events = input_bytes;
        let run_events = input_bytes;
        let match_events = if self.is_ascii_boundary_only() {
            input_bytes
                .checked_add(1)
                .ok_or(AggregateReduceError::ArithmeticOverflow {
                    computation: "input bytes plus terminal word boundary",
                })?
        } else {
            input_bytes.checked_div(self.minimum_match_units()).ok_or(
                AggregateReduceError::ArithmeticOverflow {
                    computation: "input bytes divided by minimum match units",
                },
            )?
        };
        let count =
            u64::try_from(match_events).map_err(|_| AggregateReduceError::ArithmeticOverflow {
                computation: "match-event bound as u64",
            })?;
        let span_sum = match operation {
            AggregateOperation::Count => 0,
            AggregateOperation::SpanSum if self.is_ascii_boundary_only() => 0,
            AggregateOperation::SpanSum => u64::try_from(input_bytes).map_err(|_| {
                AggregateReduceError::ArithmeticOverflow {
                    computation: "input length as span-sum bound",
                }
            })?,
        };
        let work = input_bytes
            .checked_mul(UNIT_WORK)
            .and_then(|value| {
                run_events
                    .checked_mul(RUN_WORK)
                    .and_then(|runs| value.checked_add(runs))
            })
            .and_then(|value| {
                match_events
                    .checked_mul(MATCH_WORK)
                    .and_then(|matches| value.checked_add(matches))
            })
            .and_then(|value| value.checked_add(FIXED_REDUCE_WORK))
            .ok_or(AggregateReduceError::ArithmeticOverflow {
                computation: "complete reduction work bound",
            })?;
        Ok(AggregateReduceUpperBounds {
            input_bytes,
            source_reads: input_bytes,
            work,
            unit_events,
            run_events,
            match_events,
            count,
            span_sum,
            scratch_bytes: 0,
            persistent_bytes,
            peak_bytes: persistent_bytes,
        })
    }

    fn aggregate_scan(
        self,
        haystack: &[u8],
        operation: AggregateOperation,
        upper: AggregateReduceUpperBounds,
    ) -> Result<AggregateReduceActual, AggregateReduceError> {
        let mut actual = AggregateReduceActual {
            source_reads: 0,
            work: FIXED_REDUCE_WORK,
            units: 0,
            runs: 0,
            matches: 0,
            count: 0,
            span_sum: 0,
            scratch_bytes: 0,
        };
        let mut position = 0_usize;
        let mut run_start = 0_usize;
        let mut run_scalars = 0_usize;
        let mut run_start_is_boundary = true;
        let complete_unicode_word_boundaries = matches!(
            self,
            Self::Word {
                mode: WordMode::Unicode,
                topology: WordRunTopology::CompleteWordBoundaries,
                ..
            }
        );
        let mut reverse_word_context = ReverseUnicodeWordContext::default();
        while position < haystack.len() {
            let first_byte = haystack[position];
            let (admitted, width) = match self {
                Self::Word {
                    mode: WordMode::Ascii,
                    ..
                } => (is_ascii_word(first_byte), 1),
                Self::Word {
                    mode: WordMode::Unicode,
                    ..
                } => decode_first(&haystack[position..]).map_or((false, 1), |(scalar, width)| {
                    (is_unicode_word(scalar), width)
                }),
                Self::FixedClassChunks { class_words, .. } => {
                    (class_contains(class_words, first_byte), 1)
                }
            };
            let word_before = complete_unicode_word_boundaries && reverse_word_context.is_word();
            actual.source_reads = checked_add(actual.source_reads, width, "actual source reads")?;
            actual.units = checked_add(actual.units, 1, "actual decoded units")?;
            actual.work = checked_add(actual.work, UNIT_WORK, "actual unit work")?;
            if admitted {
                if run_scalars == 0 {
                    run_start = position;
                    run_start_is_boundary = !word_before;
                }
                run_scalars = checked_add(run_scalars, 1, "actual admitted-run unit length")?;
            } else if run_scalars != 0 {
                self.aggregate_finish_run(
                    run_start,
                    position,
                    run_scalars,
                    run_start_is_boundary
                        && (!complete_unicode_word_boundaries || word_before),
                    operation,
                    &mut actual,
                )?;
                run_scalars = 0;
                run_start_is_boundary = true;
            }
            if complete_unicode_word_boundaries {
                reverse_word_context.consume(first_byte, width, admitted);
            }
            position = checked_add(position, width, "actual input cursor")?;
        }
        if run_scalars != 0 {
            self.aggregate_finish_run(
                run_start,
                haystack.len(),
                run_scalars,
                run_start_is_boundary,
                operation,
                &mut actual,
            )?;
        }
        verify_aggregate_actual(actual, upper)?;
        Ok(actual)
    }

    fn aggregate_scan_ascii(
        self,
        haystack: &[u8],
        operation: AggregateOperation,
        upper: AggregateReduceUpperBounds,
        scanner: &AsciiByteSetRunScanner,
    ) -> Result<AggregateReduceActual, AggregateReduceError> {
        debug_assert!(self.is_ascii_word());
        let mut actual = AggregateReduceActual {
            source_reads: 0,
            work: FIXED_REDUCE_WORK,
            units: 0,
            runs: 0,
            matches: 0,
            count: 0,
            span_sum: 0,
            scratch_bytes: 0,
        };
        let mut position = 0_usize;
        while position < haystack.len() {
            if !is_ascii_word(haystack[position]) {
                aggregate_charge_units(&mut actual, 1)?;
                position = checked_add(position, 1, "actual ASCII input cursor")?;
                continue;
            }
            // This authenticated ledger is logical: every source byte is
            // charged exactly once. A leaf's possible failed-block recovery
            // remains an implementation detail of the retained scanner.
            let run = scanner.scan_forward(&haystack[position..]).member_run_len();
            if run == 0 {
                return Err(AggregateReduceError::AccountingInvariant {
                    resource: AggregateReduceResource::UnitEvents,
                    actual: 0,
                    upper: 1,
                });
            }
            aggregate_charge_units(&mut actual, run)?;
            let end = checked_add(position, run, "actual ASCII run boundary")?;
            self.aggregate_finish_run(position, end, run, true, operation, &mut actual)?;
            position = end;
        }
        verify_aggregate_actual(actual, upper)?;
        Ok(actual)
    }

    #[inline]
    fn aggregate_scan_ascii_count_value(
        self,
        haystack: &[u8],
        upper: AggregateReduceUpperBounds,
        scanner: &AsciiByteSetRunScanner,
    ) -> Option<u64> {
        debug_assert!(self.is_ascii_word());
        let minimum_scalars = self.word_minimum_scalars();
        let mut count = 0_u64;
        let mut position = 0_usize;
        while position < haystack.len() {
            if !is_ascii_word(haystack[position]) {
                position = position.checked_add(1)?;
                continue;
            }
            let run = scanner.scan_forward(&haystack[position..]).member_run_len();
            if run == 0 {
                return None;
            }
            let end = position.checked_add(run)?;
            if end > haystack.len() {
                return None;
            }
            if self.is_ascii_boundary_only() {
                count = count.checked_add(2)?;
            } else if run >= minimum_scalars {
                count = count.checked_add(1)?;
            }
            position = end;
        }
        (count <= upper.count).then_some(count)
    }

    #[inline]
    fn aggregate_scan_fixed_chunk_count_value(
        self,
        haystack: &[u8],
        upper: AggregateReduceUpperBounds,
    ) -> Option<u64> {
        let Self::FixedClassChunks {
            chunk_bytes,
            class_words,
        } = self
        else {
            return None;
        };
        let mut count = 0_u64;
        let mut position = 0_usize;
        let mut run_bytes = 0_usize;
        while position < haystack.len() {
            if class_contains(class_words, haystack[position]) {
                run_bytes = run_bytes.checked_add(1)?;
            } else if run_bytes != 0 {
                let matches = run_bytes.checked_div(chunk_bytes)?;
                count = count.checked_add(u64::try_from(matches).ok()?)?;
                run_bytes = 0;
            }
            position = position.checked_add(1)?;
        }
        if run_bytes != 0 {
            let matches = run_bytes.checked_div(chunk_bytes)?;
            count = count.checked_add(u64::try_from(matches).ok()?)?;
        }
        (count <= upper.count).then_some(count)
    }

    #[inline]
    fn aggregate_scan_ascii_span_sum_value(
        self,
        haystack: &[u8],
        upper: AggregateReduceUpperBounds,
        scanner: &AsciiByteSetRunScanner,
    ) -> Option<u64> {
        debug_assert!(self.is_ascii_word());
        let minimum_scalars = self.word_minimum_scalars();
        let mut count = 0_u64;
        let mut span_sum = 0_u64;
        let mut position = 0_usize;
        while position < haystack.len() {
            if !is_ascii_word(haystack[position]) {
                position = position.checked_add(1)?;
                continue;
            }
            let run = scanner.scan_forward(&haystack[position..]).member_run_len();
            if run == 0 {
                return None;
            }
            let end = position.checked_add(run)?;
            if end > haystack.len() {
                return None;
            }
            if self.is_ascii_boundary_only() {
                count = count.checked_add(2)?;
            } else if run >= minimum_scalars {
                count = count.checked_add(1)?;
                span_sum = span_sum.checked_add(u64::try_from(run).ok()?)?;
            }
            position = end;
        }
        (count <= upper.count && span_sum <= upper.span_sum).then_some(span_sum)
    }

    #[inline]
    fn aggregate_scan_fixed_chunk_span_sum_value(
        self,
        haystack: &[u8],
        upper: AggregateReduceUpperBounds,
    ) -> Option<u64> {
        let Self::FixedClassChunks {
            chunk_bytes,
            class_words,
        } = self
        else {
            return None;
        };
        let mut count = 0_u64;
        let mut span_sum = 0_u64;
        let mut position = 0_usize;
        let mut run_bytes = 0_usize;
        while position < haystack.len() {
            if class_contains(class_words, haystack[position]) {
                run_bytes = run_bytes.checked_add(1)?;
            } else if run_bytes != 0 {
                Self::aggregate_add_fixed_chunk_span_sum_value(
                    chunk_bytes,
                    run_bytes,
                    &mut count,
                    &mut span_sum,
                )?;
                run_bytes = 0;
            }
            position = position.checked_add(1)?;
        }
        if run_bytes != 0 {
            Self::aggregate_add_fixed_chunk_span_sum_value(
                chunk_bytes,
                run_bytes,
                &mut count,
                &mut span_sum,
            )?;
        }
        (count <= upper.count && span_sum <= upper.span_sum).then_some(span_sum)
    }

    #[inline]
    fn aggregate_add_fixed_chunk_span_sum_value(
        chunk_bytes: usize,
        run_bytes: usize,
        count: &mut u64,
        span_sum: &mut u64,
    ) -> Option<()> {
        let matches = run_bytes.checked_div(chunk_bytes)?;
        if matches == 0 {
            return Some(());
        }
        *count = (*count).checked_add(u64::try_from(matches).ok()?)?;
        let width = matches.checked_mul(chunk_bytes)?;
        *span_sum = (*span_sum).checked_add(u64::try_from(width).ok()?)?;
        Some(())
    }

    fn aggregate_finish_run(
        self,
        start: usize,
        end: usize,
        scalars: usize,
        boundaries_admitted: bool,
        operation: AggregateOperation,
        actual: &mut AggregateReduceActual,
    ) -> Result<(), AggregateReduceError> {
        actual.runs = checked_add(actual.runs, 1, "actual word-run events")?;
        actual.work = checked_add(actual.work, RUN_WORK, "actual word-run work")?;
        let matches = match self {
            Self::Word {
                topology: WordRunTopology::AsciiBoundaryOnly,
                ..
            } => 2,
            Self::Word {
                minimum_scalars, ..
            } => usize::from(boundaries_admitted && scalars >= minimum_scalars),
            Self::FixedClassChunks { chunk_bytes, .. } => scalars.checked_div(chunk_bytes).ok_or(
                AggregateReduceError::ArithmeticOverflow {
                    computation: "admitted run divided by fixed chunk width",
                },
            )?,
        };
        if matches == 0 {
            return Ok(());
        }
        actual.matches = checked_add(actual.matches, matches, "actual match events")?;
        let matches_u64 =
            u64::try_from(matches).map_err(|_| AggregateReduceError::ArithmeticOverflow {
                computation: "actual match count as u64",
            })?;
        actual.count = actual.count.checked_add(matches_u64).ok_or(
            AggregateReduceError::ArithmeticOverflow {
                computation: "actual match count",
            },
        )?;
        let match_work =
            matches
                .checked_mul(MATCH_WORK)
                .ok_or(AggregateReduceError::ArithmeticOverflow {
                    computation: "actual match work",
                })?;
        actual.work = checked_add(actual.work, match_work, "actual match work")?;
        if operation == AggregateOperation::SpanSum {
            let width = match self {
                Self::Word {
                    topology: WordRunTopology::AsciiBoundaryOnly,
                    ..
                } => 0,
                Self::Word { .. } => {
                    end.checked_sub(start)
                        .ok_or(AggregateReduceError::ArithmeticOverflow {
                            computation: "actual word-run match width",
                        })?
                }
                Self::FixedClassChunks { chunk_bytes, .. } => matches
                    .checked_mul(chunk_bytes)
                    .ok_or(AggregateReduceError::ArithmeticOverflow {
                        computation: "actual fixed-class chunk span sum",
                    })?,
            };
            actual.span_sum = actual
                .span_sum
                .checked_add(u64::try_from(width).map_err(|_| {
                    AggregateReduceError::ArithmeticOverflow {
                        computation: "actual match width as u64",
                    }
                })?)
                .ok_or(AggregateReduceError::ArithmeticOverflow {
                    computation: "actual span sum",
                })?;
        }
        Ok(())
    }

    pub(crate) fn find_window(
        self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, Accounting), Error> {
        validate_window(haystack, window)?;
        match self {
            Self::Word {
                mode: WordMode::Ascii,
                ..
            } => self.find_ascii_window(haystack, window, limits),
            Self::Word {
                mode: WordMode::Unicode,
                ..
            } => self.find_unicode_window(haystack, window, limits),
            Self::FixedClassChunks { .. } => {
                self.find_fixed_class_chunk_window(haystack, window, limits)
            }
        }
    }

    fn find_ascii_window(
        self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, Accounting), Error> {
        let minimum_scalars = self.word_minimum_scalars();
        let complete_word_boundaries = self.has_complete_word_boundaries();
        let mut accounting = Accounting {
            work: 0,
            bytes_examined: 0,
            scalars_decoded: 0,
        };
        let mut position = window.start();
        while position < window.end() {
            charge(&mut accounting, limits)?;
            let byte = haystack[position];
            accounting.bytes_examined = accounting.bytes_examined.saturating_add(1);
            accounting.scalars_decoded = accounting.scalars_decoded.saturating_add(1);
            if !is_ascii_word(byte)
                || (complete_word_boundaries
                    && position
                        .checked_sub(1)
                        .is_some_and(|before| is_ascii_word(haystack[before])))
            {
                position = position.checked_add(1).ok_or(Error::WorkLimitExceeded {
                    needed: u64::MAX,
                    limit: limits.max_work,
                })?;
                continue;
            }

            let start = position;
            position = position.checked_add(1).ok_or(Error::WorkLimitExceeded {
                needed: u64::MAX,
                limit: limits.max_work,
            })?;
            while position < window.end() && is_ascii_word(haystack[position]) {
                charge(&mut accounting, limits)?;
                accounting.bytes_examined = accounting.bytes_examined.saturating_add(1);
                accounting.scalars_decoded = accounting.scalars_decoded.saturating_add(1);
                position = position.checked_add(1).ok_or(Error::WorkLimitExceeded {
                    needed: u64::MAX,
                    limit: limits.max_work,
                })?;
            }
            if position.saturating_sub(start) >= minimum_scalars
                && (!complete_word_boundaries
                    || !haystack
                        .get(position)
                        .is_some_and(|&byte| is_ascii_word(byte)))
            {
                return Ok((
                    Some(Match {
                        start,
                        end: position,
                    }),
                    accounting,
                ));
            }
        }
        Ok((None, accounting))
    }

    fn find_ascii_window_with_scanner(
        self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
        scanner: &AsciiByteSetRunScanner,
    ) -> Result<(Option<Match>, Accounting), Error> {
        debug_assert!(self.is_ascii_word());
        let minimum_scalars = self.word_minimum_scalars();
        let complete_word_boundaries = self.has_complete_word_boundaries();
        let mut accounting = Accounting {
            work: 0,
            bytes_examined: 0,
            scalars_decoded: 0,
        };
        let mut position = window.start();
        while position < window.end() {
            charge(&mut accounting, limits)?;
            let byte = haystack[position];
            accounting.bytes_examined = accounting.bytes_examined.saturating_add(1);
            accounting.scalars_decoded = accounting.scalars_decoded.saturating_add(1);
            if !is_ascii_word(byte)
                || (complete_word_boundaries
                    && position
                        .checked_sub(1)
                        .is_some_and(|before| is_ascii_word(haystack[before])))
            {
                position = position.checked_add(1).ok_or(Error::WorkLimitExceeded {
                    needed: u64::MAX,
                    limit: limits.max_work,
                })?;
                continue;
            }

            let start = position;
            position = position.checked_add(1).ok_or(Error::WorkLimitExceeded {
                needed: u64::MAX,
                limit: limits.max_work,
            })?;
            let continuation = scanner
                .scan_forward(&haystack[position..window.end()])
                .member_run_len();
            // Preserve the incumbent SearchLimits contract by charging the
            // logically consumed continuation, not physical recovery probes.
            charge_many(&mut accounting, continuation, limits)?;
            accounting.bytes_examined = accounting.bytes_examined.saturating_add(continuation);
            accounting.scalars_decoded = accounting.scalars_decoded.saturating_add(continuation);
            position = position
                .checked_add(continuation)
                .ok_or(Error::WorkLimitExceeded {
                    needed: u64::MAX,
                    limit: limits.max_work,
                })?;
            if position.saturating_sub(start) >= minimum_scalars
                && (!complete_word_boundaries
                    || !haystack
                        .get(position)
                        .is_some_and(|&byte| is_ascii_word(byte)))
            {
                return Ok((
                    Some(Match {
                        start,
                        end: position,
                    }),
                    accounting,
                ));
            }
        }
        Ok((None, accounting))
    }

    fn find_unicode_window(
        self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, Accounting), Error> {
        let minimum_scalars = self.word_minimum_scalars();
        let complete_word_boundaries = self.has_complete_word_boundaries();
        let mut accounting = Accounting {
            work: 0,
            bytes_examined: 0,
            scalars_decoded: 0,
        };
        let mut position = window.start();
        while position < window.end() {
            charge(&mut accounting, limits)?;
            let Some((scalar, width)) = decode_first(&haystack[position..window.end()]) else {
                position = position.checked_add(1).ok_or(Error::WorkLimitExceeded {
                    needed: u64::MAX,
                    limit: limits.max_work,
                })?;
                accounting.bytes_examined = accounting.bytes_examined.saturating_add(1);
                continue;
            };
            accounting.scalars_decoded = accounting.scalars_decoded.saturating_add(1);
            accounting.bytes_examined = accounting.bytes_examined.saturating_add(width);
            if !is_unicode_word(scalar)
                || (complete_word_boundaries
                    && !unicode_word_boundary_before(haystack, position))
            {
                position = position
                    .checked_add(width)
                    .ok_or(Error::WorkLimitExceeded {
                        needed: u64::MAX,
                        limit: limits.max_work,
                    })?;
                continue;
            }

            let start = position;
            let mut count = 1_usize;
            position = position
                .checked_add(width)
                .ok_or(Error::WorkLimitExceeded {
                    needed: u64::MAX,
                    limit: limits.max_work,
                })?;
            while position < window.end() {
                charge(&mut accounting, limits)?;
                let Some((next, next_width)) = decode_first(&haystack[position..window.end()])
                else {
                    break;
                };
                accounting.scalars_decoded = accounting.scalars_decoded.saturating_add(1);
                accounting.bytes_examined = accounting.bytes_examined.saturating_add(next_width);
                if !is_unicode_word(next) {
                    break;
                }
                count = count.saturating_add(1);
                position = position
                    .checked_add(next_width)
                    .ok_or(Error::WorkLimitExceeded {
                        needed: u64::MAX,
                        limit: limits.max_work,
                    })?;
            }
            if count >= minimum_scalars
                && (!complete_word_boundaries
                    || unicode_word_boundary_after(haystack, position))
            {
                return Ok((
                    Some(Match {
                        start,
                        end: position,
                    }),
                    accounting,
                ));
            }
        }
        Ok((None, accounting))
    }

    fn find_fixed_class_chunk_window(
        self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, Accounting), Error> {
        let Self::FixedClassChunks {
            chunk_bytes,
            class_words,
        } = self
        else {
            unreachable!("word plans never enter fixed-class chunk search");
        };
        let mut accounting = Accounting {
            work: 0,
            bytes_examined: 0,
            scalars_decoded: 0,
        };
        let mut position = window.start();
        while position < window.end() {
            charge(&mut accounting, limits)?;
            accounting.bytes_examined = accounting.bytes_examined.saturating_add(1);
            accounting.scalars_decoded = accounting.scalars_decoded.saturating_add(1);
            if !class_contains(class_words, haystack[position]) {
                position = position.checked_add(1).ok_or(Error::WorkLimitExceeded {
                    needed: u64::MAX,
                    limit: limits.max_work,
                })?;
                continue;
            }
            let start = position;
            while position < window.end() && class_contains(class_words, haystack[position]) {
                if position != start {
                    charge(&mut accounting, limits)?;
                    accounting.bytes_examined = accounting.bytes_examined.saturating_add(1);
                    accounting.scalars_decoded = accounting.scalars_decoded.saturating_add(1);
                }
                position = position.checked_add(1).ok_or(Error::WorkLimitExceeded {
                    needed: u64::MAX,
                    limit: limits.max_work,
                })?;
                if position.saturating_sub(start) == chunk_bytes {
                    return Ok((
                        Some(Match {
                            start,
                            end: position,
                        }),
                        accounting,
                    ));
                }
            }
        }
        Ok((None, accounting))
    }
}

pub(crate) fn extract(hir: &Hir) -> Option<Plan> {
    let HirKind::Concat(parts) = transparent(hir).kind() else {
        return None;
    };
    let [start, repeated, end] = parts.as_slice() else {
        return None;
    };
    let mode = match (transparent(start).kind(), transparent(end).kind()) {
        (HirKind::Look(Look::WordAscii), HirKind::Look(Look::WordAscii)) => WordMode::Ascii,
        (HirKind::Look(Look::WordUnicode), HirKind::Look(Look::WordUnicode)) => WordMode::Unicode,
        _ => return None,
    };
    let HirKind::Repetition(repetition) = transparent(repeated).kind() else {
        return None;
    };
    if repetition.min == 0 || repetition.max.is_some() || !repetition.greedy {
        return None;
    }
    match (mode, transparent(&repetition.sub).kind()) {
        (WordMode::Ascii, HirKind::Class(Class::Bytes(class)))
            if class == &parse_ascii_word_class()? => {}
        (WordMode::Unicode, HirKind::Class(Class::Unicode(class)))
            if class == &parse_unicode_word_class()? => {}
        _ => return None,
    }
    Some(Plan::new(usize::try_from(repetition.min).ok()?, mode))
}

pub(crate) fn inspect_aggregate_attempt(
    hir: &Hir,
    limit: usize,
) -> Result<AggregateInspectionOutcome, AggregateInspectionAttemptError<AggregateInspectionError>> {
    let mut accounting = InspectionAccounting::default();
    inspect_aggregate_with_accounting(hir, limit, &mut accounting)
        .map_err(|source| AggregateInspectionAttemptError::new(source, accounting.work))
}

fn inspect_bare_word_repetition(
    repetition: &Repetition,
    limit: usize,
    accounting: &mut InspectionAccounting,
) -> Result<Option<Plan>, AggregateInspectionError> {
    if repetition.min == 0 || repetition.max.is_some() || !repetition.greedy {
        return Ok(None);
    }
    let class_hir = peel_captures_accounted(&repetition.sub, limit, accounting)?;
    let mode = match class_hir.kind() {
        HirKind::Class(Class::Bytes(class)) => {
            accounting.charge(class.ranges().len(), limit)?;
            if !is_exact_ascii_word_class(class) {
                return Ok(None);
            }
            WordMode::Ascii
        }
        HirKind::Class(Class::Unicode(class)) => {
            accounting.charge(class.ranges().len(), limit)?;
            if !is_exact_unicode_word_class(class, limit, accounting)? {
                return Ok(None);
            }
            WordMode::Unicode
        }
        _ => return Ok(None),
    };
    let minimum_scalars =
        usize::try_from(repetition.min).map_err(|_| AggregateInspectionError::Overflow)?;
    Ok(Some(Plan::bare_greedy(minimum_scalars, mode)))
}

fn inspect_aggregate_with_accounting(
    hir: &Hir,
    limit: usize,
    accounting: &mut InspectionAccounting,
) -> Result<AggregateInspectionOutcome, AggregateInspectionError> {
    let root = peel_captures_accounted(hir, limit, accounting)?;
    if matches!(root.kind(), HirKind::Look(Look::WordAscii)) {
        return Ok(AggregateInspectionOutcome::Eligible(AggregateInspection {
            plan: Plan::ascii_boundary_only(),
            work: accounting.work,
            hir_nodes: accounting.hir_nodes,
            captures: accounting.captures,
        }));
    }
    if let HirKind::Repetition(repetition) = root.kind() {
        accounting.charge(3, limit)?;
        if let Some(plan) = inspect_bare_word_repetition(repetition, limit, accounting)? {
            return Ok(AggregateInspectionOutcome::Eligible(AggregateInspection {
                plan,
                work: accounting.work,
                hir_nodes: accounting.hir_nodes,
                captures: accounting.captures,
            }));
        }
        let exact = repetition.max == Some(repetition.min);
        let chunk_bytes =
            usize::try_from(repetition.min).map_err(|_| AggregateInspectionError::Overflow)?;
        // Widths up to 64 retain the established finite/fixed-predicate route
        // ordering. This run reducer is the general fallback for exact class
        // repetitions that otherwise expand into continuation states.
        if !exact || chunk_bytes <= 64 {
            return Ok(accounting.ineligible());
        }
        let class_hir = peel_captures_accounted(&repetition.sub, limit, accounting)?;
        let HirKind::Class(Class::Bytes(class)) = class_hir.kind() else {
            return Ok(accounting.ineligible());
        };
        accounting.charge(class.ranges().len(), limit)?;
        let mut class_words = [0_u64; 4];
        for range in class.ranges() {
            let mut byte = range.start();
            loop {
                accounting.charge(1, limit)?;
                let word = usize::from(byte) / 64;
                let bit = usize::from(byte) % 64;
                class_words[word] |= 1_u64 << bit;
                if byte == range.end() {
                    break;
                }
                byte = byte
                    .checked_add(1)
                    .ok_or(AggregateInspectionError::Overflow)?;
            }
        }
        return Ok(AggregateInspectionOutcome::Eligible(AggregateInspection {
            plan: Plan::fixed_class_chunks(chunk_bytes, class_words),
            work: accounting.work,
            hir_nodes: accounting.hir_nodes,
            captures: accounting.captures,
        }));
    }
    let HirKind::Concat(parts) = root.kind() else {
        return Ok(accounting.ineligible());
    };
    accounting.charge(parts.len(), limit)?;
    let [start, repeated, end] = parts.as_slice() else {
        return Ok(accounting.ineligible());
    };
    let start = peel_captures_accounted(start, limit, accounting)?;
    let end = peel_captures_accounted(end, limit, accounting)?;
    let mode = match (start.kind(), end.kind()) {
        (HirKind::Look(Look::WordAscii), HirKind::Look(Look::WordAscii)) => WordMode::Ascii,
        (HirKind::Look(Look::WordUnicode), HirKind::Look(Look::WordUnicode)) => WordMode::Unicode,
        _ => return Ok(accounting.ineligible()),
    };
    let repeated = peel_captures_accounted(repeated, limit, accounting)?;
    let HirKind::Repetition(repetition) = repeated.kind() else {
        return Ok(accounting.ineligible());
    };
    accounting.charge(3, limit)?;
    if repetition.min == 0 || repetition.max.is_some() || !repetition.greedy {
        return Ok(accounting.ineligible());
    }
    let class = peel_captures_accounted(&repetition.sub, limit, accounting)?;
    match (mode, class.kind()) {
        (WordMode::Ascii, HirKind::Class(Class::Bytes(class))) => {
            accounting.charge(class.ranges().len(), limit)?;
            if !is_exact_ascii_word_class(class) {
                return Ok(accounting.ineligible());
            }
        }
        (WordMode::Unicode, HirKind::Class(Class::Unicode(class))) => {
            accounting.charge(class.ranges().len(), limit)?;
            if !is_exact_unicode_word_class(class, limit, accounting)? {
                return Ok(accounting.ineligible());
            }
        }
        _ => return Ok(accounting.ineligible()),
    }
    let minimum_scalars =
        usize::try_from(repetition.min).map_err(|_| AggregateInspectionError::Overflow)?;
    Ok(AggregateInspectionOutcome::Eligible(AggregateInspection {
        plan: Plan::new(minimum_scalars, mode),
        work: accounting.work,
        hir_nodes: accounting.hir_nodes,
        captures: accounting.captures,
    }))
}

#[derive(Default)]
struct InspectionAccounting {
    work: usize,
    hir_nodes: usize,
    captures: usize,
}

impl InspectionAccounting {
    fn charge(&mut self, units: usize, limit: usize) -> Result<(), AggregateInspectionError> {
        let needed = self
            .work
            .checked_add(units)
            .ok_or(AggregateInspectionError::Overflow)?;
        if needed > limit {
            return Err(AggregateInspectionError::WorkLimit { needed, limit });
        }
        self.work = needed;
        Ok(())
    }

    fn visit(&mut self, limit: usize) -> Result<(), AggregateInspectionError> {
        self.charge(1, limit)?;
        self.hir_nodes = self
            .hir_nodes
            .checked_add(1)
            .ok_or(AggregateInspectionError::Overflow)?;
        Ok(())
    }

    const fn ineligible(&self) -> AggregateInspectionOutcome {
        AggregateInspectionOutcome::Ineligible { work: self.work }
    }
}

fn peel_captures_accounted<'a>(
    mut hir: &'a Hir,
    limit: usize,
    accounting: &mut InspectionAccounting,
) -> Result<&'a Hir, AggregateInspectionError> {
    loop {
        accounting.visit(limit)?;
        let HirKind::Capture(capture) = hir.kind() else {
            return Ok(hir);
        };
        accounting.captures = accounting
            .captures
            .checked_add(1)
            .ok_or(AggregateInspectionError::Overflow)?;
        hir = &capture.sub;
    }
}

fn is_exact_ascii_word_class(class: &regex_syntax::hir::ClassBytes) -> bool {
    class.ranges().len() == ASCII_WORD_RANGES.len()
        && class
            .ranges()
            .iter()
            .zip(ASCII_WORD_RANGES)
            .all(|(actual, (start, end))| actual.start() == start && actual.end() == end)
}

fn is_exact_unicode_word_class(
    class: &regex_syntax::hir::ClassUnicode,
    limit: usize,
    accounting: &mut InspectionAccounting,
) -> Result<bool, AggregateInspectionError> {
    if class.ranges().len() != UNICODE_WORD_RANGE_COUNT {
        return Ok(false);
    }
    for range in class.ranges() {
        if !charged_is_unicode_word(range.start(), limit, accounting)?
            || !charged_is_unicode_word(range.end(), limit, accounting)?
        {
            return Ok(false);
        }
        if let Some(previous) = previous_scalar(range.start())
            && charged_is_unicode_word(previous, limit, accounting)?
        {
            return Ok(false);
        }
        if let Some(next) = next_scalar(range.end())
            && charged_is_unicode_word(next, limit, accounting)?
        {
            return Ok(false);
        }
    }
    // Every admitted range is therefore one complete maximal interval of the
    // pinned word property. Equal cardinality proves that none is merged,
    // split, duplicated or omitted without retaining a second range table.
    Ok(true)
}

fn charged_is_unicode_word(
    scalar: char,
    limit: usize,
    accounting: &mut InspectionAccounting,
) -> Result<bool, AggregateInspectionError> {
    accounting.charge(1, limit)?;
    Ok(is_unicode_word(scalar))
}

fn previous_scalar(scalar: char) -> Option<char> {
    let codepoint = u32::from(scalar).checked_sub(1)?;
    if codepoint == 0xDFFF {
        Some('\u{D7FF}')
    } else {
        char::from_u32(codepoint)
    }
}

fn next_scalar(scalar: char) -> Option<char> {
    let codepoint = u32::from(scalar).checked_add(1)?;
    if codepoint == 0xD800 {
        Some('\u{E000}')
    } else {
        char::from_u32(codepoint)
    }
}

fn transparent(mut hir: &Hir) -> &Hir {
    while let HirKind::Capture(capture) = hir.kind() {
        hir = &capture.sub;
    }
    hir
}

fn parse_ascii_word_class() -> Option<regex_syntax::hir::ClassBytes> {
    let hir = ParserBuilder::new()
        .unicode(false)
        .utf8(false)
        .build()
        .parse(r"\w")
        .ok()?;
    let HirKind::Class(Class::Bytes(class)) = hir.kind() else {
        return None;
    };
    Some(class.clone())
}

fn parse_unicode_word_class() -> Option<regex_syntax::hir::ClassUnicode> {
    let hir = ParserBuilder::new()
        .unicode(true)
        .utf8(false)
        .build()
        .parse(r"\w")
        .ok()?;
    let HirKind::Class(Class::Unicode(class)) = hir.kind() else {
        return None;
    };
    Some(class.clone())
}

const fn ascii_word_set() -> AsciiByteSet {
    // 0..=63 contains 0-9; 64..=127 contains A-Z, _, and a-z.
    AsciiByteSet::from_words([0x03ff_0000_0000_0000, 0x07ff_fffe_87ff_fffe])
}

fn validate_window(haystack: &[u8], window: SearchWindow) -> Result<(), Error> {
    if window.start() > window.end() || window.end() > haystack.len() {
        return Err(Error::InvalidWindow {
            start: window.start(),
            end: window.end(),
            haystack_len: haystack.len(),
        });
    }
    Ok(())
}

fn full_window_value_scan_is_prepaid(
    haystack: &[u8],
    window: SearchWindow,
    limits: SearchLimits,
) -> bool {
    window.start() == 0
        && window.end() == haystack.len()
        && u64::try_from(haystack.len()).is_ok_and(|work| work <= limits.max_work)
}

fn ascii_word_run_exists(haystack: &[u8], minimum: usize) -> bool {
    // This helper's sole caller has already authenticated the exact ASCII
    // word-run owner, validated a complete window and prepaid one work unit
    // for every input byte. A shorter byte domain cannot contain the required
    // ASCII run, so it needs no source inspection. Keeping the check here
    // leaves invalid-window and finite-work refusals on the incumbent path.
    if haystack.len() < minimum {
        return false;
    }
    let mut run = 0_usize;
    for &byte in haystack {
        if is_ascii_word(byte) {
            run = run.saturating_add(1);
            if run >= minimum {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn charge(accounting: &mut Accounting, limits: SearchLimits) -> Result<(), Error> {
    let needed = accounting.work.saturating_add(1);
    if needed > limits.max_work {
        return Err(Error::WorkLimitExceeded {
            needed,
            limit: limits.max_work,
        });
    }
    accounting.work = needed;
    Ok(())
}

fn charge_many(
    accounting: &mut Accounting,
    units: usize,
    limits: SearchLimits,
) -> Result<(), Error> {
    if units == 0 {
        return Ok(());
    }
    let units = u64::try_from(units).unwrap_or(u64::MAX);
    let needed = accounting.work.saturating_add(units);
    if needed > limits.max_work {
        return Err(Error::WorkLimitExceeded {
            // The established scalar loop refuses at the first inadmissible
            // unit, rather than reporting the end of a batched run.
            needed: limits.max_work.saturating_add(1),
            limit: limits.max_work,
        });
    }
    accounting.work = needed;
    Ok(())
}

fn aggregate_charge_units(
    actual: &mut AggregateReduceActual,
    units: usize,
) -> Result<(), AggregateReduceError> {
    actual.source_reads = checked_add(actual.source_reads, units, "actual source reads")?;
    actual.units = checked_add(actual.units, units, "actual decoded units")?;
    let work = units
        .checked_mul(UNIT_WORK)
        .ok_or(AggregateReduceError::ArithmeticOverflow {
            computation: "actual ASCII unit work",
        })?;
    actual.work = checked_add(actual.work, work, "actual unit work")?;
    Ok(())
}

/// Reverse Unicode-word context retained from bytes already charged to the
/// aggregate scan. This mirrors regex-automata's reverse decoder without
/// rereading the source: up to three stray continuation bytes still expose
/// the nearest preceding scalar, while four or more hide its leader.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ReverseUnicodeWordContext {
    leader_is_word: bool,
    trailing_continuations: u8,
}

impl ReverseUnicodeWordContext {
    const fn is_word(self) -> bool {
        self.leader_is_word && self.trailing_continuations <= 3
    }

    fn consume(&mut self, first_byte: u8, width: usize, is_word: bool) {
        if width > 1 {
            self.leader_is_word = is_word;
            self.trailing_continuations =
                u8::try_from(width.saturating_sub(1).min(4)).unwrap_or(4);
        } else if matches!(first_byte, 0x80..=0xBF) {
            self.trailing_continuations = self.trailing_continuations.saturating_add(1).min(4);
        } else {
            self.leader_is_word = is_word;
            self.trailing_continuations = 0;
        }
    }
}

fn unicode_word_boundary_before(haystack: &[u8], position: usize) -> bool {
    position == 0
        || decode_last(&haystack[..position])
            .is_none_or(|(scalar, _)| !is_unicode_word(scalar))
}

fn unicode_word_boundary_after(haystack: &[u8], position: usize) -> bool {
    position == haystack.len()
        || decode_first(&haystack[position..])
            .is_none_or(|(scalar, _)| !is_unicode_word(scalar))
}

fn is_ascii_word(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn class_contains(class_words: [u64; 4], byte: u8) -> bool {
    let word = usize::from(byte) / 64;
    let bit = usize::from(byte) % 64;
    class_words[word] & (1_u64 << bit) != 0
}

fn is_unicode_word(scalar: char) -> bool {
    if scalar.is_ascii() {
        return scalar == '_' || scalar.is_ascii_alphanumeric();
    }
    regex_syntax::try_is_word_character(scalar)
        .expect("fre enables regex-syntax's Unicode Perl tables")
}

fn decode_first(bytes: &[u8]) -> Option<(char, usize)> {
    let first = *bytes.first()?;
    if first.is_ascii() {
        return Some((char::from(first), 1));
    }
    let width = match first {
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => return None,
    };
    let scalar = core::str::from_utf8(bytes.get(..width)?)
        .ok()?
        .chars()
        .next()?;
    Some((scalar, width))
}

fn decode_last(bytes: &[u8]) -> Option<(char, usize)> {
    let mut start = bytes.len().checked_sub(1)?;
    let lower = bytes.len().saturating_sub(4);
    while start > lower && matches!(bytes[start], 0x80..=0xBF) {
        start = start.checked_sub(1)?;
    }
    // Match regex-automata's reverse context decoder: once the nearest
    // leading-or-invalid byte is found, classify the code point beginning
    // there. In particular, an ASCII word byte followed by a stray
    // continuation byte remains the reverse word context at the next
    // position, even though the whole suffix is not valid UTF-8.
    decode_first(&bytes[start..])
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AggregateOperation {
    Count,
    SpanSum,
}

#[derive(Clone, Copy)]
enum AggregateBuildResource {
    Work,
    Scratch,
    Persistent,
    Peak,
}

fn enforce_build(
    needed: usize,
    limit: usize,
    resource: AggregateBuildResource,
) -> Result<(), AggregateBuildError> {
    if needed <= limit {
        return Ok(());
    }
    Err(match resource {
        AggregateBuildResource::Work => AggregateBuildError::WorkLimit { needed, limit },
        AggregateBuildResource::Scratch => AggregateBuildError::ScratchLimit { needed, limit },
        AggregateBuildResource::Persistent => {
            AggregateBuildError::PersistentLimit { needed, limit }
        }
        AggregateBuildResource::Peak => AggregateBuildError::PeakLimit { needed, limit },
    })
}

fn enforce_reduce(
    upper: AggregateReduceUpperBounds,
    limits: AggregateReduceLimits,
) -> Result<(), AggregateReduceError> {
    macro_rules! enforce {
        ($needed:expr, $limit:expr, $variant:ident) => {
            if $needed > $limit {
                return Err(AggregateReduceError::$variant {
                    needed: $needed,
                    limit: $limit,
                });
            }
        };
    }
    enforce!(upper.input_bytes, limits.max_input_bytes, InputBytesLimit);
    enforce!(
        upper.source_reads,
        limits.max_source_reads,
        SourceReadsLimit
    );
    enforce!(upper.work, limits.max_work, WorkLimit);
    enforce!(upper.unit_events, limits.max_unit_events, UnitEventsLimit);
    enforce!(upper.run_events, limits.max_run_events, RunEventsLimit);
    enforce!(
        upper.match_events,
        limits.max_match_events,
        MatchEventsLimit
    );
    enforce!(upper.count, limits.max_count, CountLimit);
    enforce!(upper.span_sum, limits.max_span_sum, SpanSumLimit);
    enforce!(upper.scratch_bytes, limits.max_scratch_bytes, ScratchLimit);
    enforce!(
        upper.persistent_bytes,
        limits.max_persistent_bytes,
        PersistentLimit
    );
    enforce!(upper.peak_bytes, limits.max_peak_bytes, PeakLimit);
    Ok(())
}

fn checked_add(
    left: usize,
    right: usize,
    computation: &'static str,
) -> Result<usize, AggregateReduceError> {
    left.checked_add(right)
        .ok_or(AggregateReduceError::ArithmeticOverflow { computation })
}

fn verify_aggregate_actual(
    actual: AggregateReduceActual,
    upper: AggregateReduceUpperBounds,
) -> Result<(), AggregateReduceError> {
    verify_resource(
        AggregateReduceResource::SourceReads,
        actual.source_reads,
        upper.source_reads,
    )?;
    verify_resource(AggregateReduceResource::Work, actual.work, upper.work)?;
    verify_resource(
        AggregateReduceResource::UnitEvents,
        actual.units,
        upper.unit_events,
    )?;
    verify_resource(
        AggregateReduceResource::RunEvents,
        actual.runs,
        upper.run_events,
    )?;
    verify_resource(
        AggregateReduceResource::MatchEvents,
        actual.matches,
        upper.match_events,
    )?;
    verify_resource(AggregateReduceResource::Count, actual.count, upper.count)?;
    verify_resource(
        AggregateReduceResource::SpanSum,
        actual.span_sum,
        upper.span_sum,
    )?;
    verify_resource(
        AggregateReduceResource::ScratchBytes,
        actual.scratch_bytes,
        upper.scratch_bytes,
    )?;
    Ok(())
}

fn verify_resource<T>(
    resource: AggregateReduceResource,
    actual: T,
    upper: T,
) -> Result<(), AggregateReduceError>
where
    T: Copy + Ord + TryInto<u64>,
{
    if actual <= upper {
        return Ok(());
    }
    Err(AggregateReduceError::AccountingInvariant {
        resource,
        actual: actual.try_into().unwrap_or(u64::MAX),
        upper: upper.try_into().unwrap_or(u64::MAX),
    })
}

#[cfg(test)]
mod tests {
    use std::{
        hint::black_box,
        time::{Duration, Instant},
    };

    use regex::bytes::RegexBuilder;
    use regex_syntax::ParserBuilder;

    use super::{
        ASCII_RUN_SCANNER_BUILD_WORK, AggregateBuildAccounting, AggregateBuildLimits,
        AggregateInspectionError, AggregateInspectionOutcome, AggregateOperationIdentity,
        AggregateReduceError, AggregateReduceLimits, AsciiPlan, AsciiPlanOwner, Error,
        FIXED_BUILD_WORK, Plan, WordMode, WordRunTopology, aggregate_build_accounting_matches,
        ascii_word_set, inspect_aggregate_attempt,
    };
    use crate::{SearchLimits, SearchWindow};

    fn class_words(bytes: &[u8]) -> [u64; 4] {
        let mut words = [0_u64; 4];
        for &byte in bytes {
            words[usize::from(byte) / 64] |= 1_u64 << (usize::from(byte) % 64);
        }
        words
    }

    fn oracle_with_unicode(pattern: &str, haystack: &[u8], unicode: bool) -> (u64, u64) {
        let regex = RegexBuilder::new(pattern)
            .unicode(unicode)
            .build()
            .expect("oracle pattern");
        regex
            .find_iter(haystack)
            .map(|matched| {
                (
                    1_u64,
                    u64::try_from(
                        matched
                            .end()
                            .checked_sub(matched.start())
                            .expect("ordered match"),
                    )
                    .expect("match width"),
                )
            })
            .fold((0_u64, 0_u64), |(count, sum), (one, width)| {
                (
                    count.checked_add(one).expect("count"),
                    sum.checked_add(width).expect("span sum"),
                )
            })
    }

    fn oracle(pattern: &str, haystack: &[u8]) -> (u64, u64) {
        oracle_with_unicode(pattern, haystack, false)
    }

    fn assert_plan_matches(pattern: &str, plan: Plan, haystack: &[u8]) {
        assert_plan_matches_with_unicode(pattern, plan, haystack, false);
    }

    fn assert_plan_matches_with_unicode(
        pattern: &str,
        plan: Plan,
        haystack: &[u8],
        unicode: bool,
    ) {
        let expected = oracle_with_unicode(pattern, haystack, unicode);
        let counted = plan
            .aggregate_count(haystack, AggregateReduceLimits::unlimited())
            .expect("count");
        let summed = plan
            .aggregate_span_sum(haystack, AggregateReduceLimits::unlimited())
            .expect("span sum");
        assert_eq!((counted.count, summed.span_sum), expected, "{haystack:?}");
        if plan.is_fixed_class_chunks() {
            assert_eq!(
                plan.aggregate_fixed_chunk_count_value_success(
                    haystack,
                    AggregateReduceLimits::unlimited(),
                ),
                Some(expected.0),
                "compact fixed-chunk count {haystack:?}",
            );
            assert_eq!(
                plan.aggregate_fixed_chunk_span_sum_value_success(
                    haystack,
                    AggregateReduceLimits::unlimited(),
                ),
                Some(expected.1),
                "compact fixed-chunk span sum {haystack:?}",
            );
        }
        assert_eq!(counted.accounting.actual.source_reads, haystack.len());
        assert_eq!(summed.accounting.actual.source_reads, haystack.len());
        assert_eq!(counted.accounting.actual.scratch_bytes, 0);
        assert_eq!(summed.accounting.actual.scratch_bytes, 0);
    }

    fn assert_fixed_chunk_compact_count_limit_parity(plan: Plan, haystack: &[u8]) {
        let baseline = plan
            .aggregate_count(haystack, AggregateReduceLimits::unlimited())
            .expect("unlimited fixed-chunk count");
        let upper = baseline.accounting.upper_bounds;
        let exact = AggregateReduceLimits {
            max_input_bytes: upper.input_bytes,
            max_source_reads: upper.source_reads,
            max_work: upper.work,
            max_unit_events: upper.unit_events,
            max_run_events: upper.run_events,
            max_match_events: upper.match_events,
            max_count: upper.count,
            max_span_sum: upper.span_sum,
            max_scratch_bytes: upper.scratch_bytes,
            max_persistent_bytes: upper.persistent_bytes,
            max_peak_bytes: upper.peak_bytes,
        };
        assert_eq!(
            plan.aggregate_fixed_chunk_count_value_success(haystack, exact),
            Some(baseline.count),
        );

        macro_rules! one_below {
            ($upper_field:ident, $limit_field:ident, $error:ident) => {
                if upper.$upper_field > 0 {
                    let mut limits = AggregateReduceLimits::unlimited();
                    limits.$limit_field = upper.$upper_field - 1;
                    assert_eq!(
                        plan.aggregate_fixed_chunk_count_value_success(haystack, limits),
                        None,
                        "compact fixed-chunk count one-below {}",
                        stringify!($limit_field),
                    );
                    assert_eq!(
                        plan.aggregate_count(haystack, limits)
                            .expect_err("one-below fixed-chunk count limit"),
                        AggregateReduceError::$error {
                            needed: upper.$upper_field,
                            limit: upper.$upper_field - 1,
                        },
                        "authoritative fixed-chunk count one-below {}",
                        stringify!($limit_field),
                    );
                }
            };
        }
        one_below!(input_bytes, max_input_bytes, InputBytesLimit);
        one_below!(source_reads, max_source_reads, SourceReadsLimit);
        one_below!(work, max_work, WorkLimit);
        one_below!(unit_events, max_unit_events, UnitEventsLimit);
        one_below!(run_events, max_run_events, RunEventsLimit);
        one_below!(match_events, max_match_events, MatchEventsLimit);
        one_below!(count, max_count, CountLimit);
        one_below!(span_sum, max_span_sum, SpanSumLimit);
        one_below!(scratch_bytes, max_scratch_bytes, ScratchLimit);
        one_below!(persistent_bytes, max_persistent_bytes, PersistentLimit);
        one_below!(peak_bytes, max_peak_bytes, PeakLimit);
    }

    fn assert_fixed_chunk_compact_span_sum_limit_parity(plan: Plan, haystack: &[u8]) {
        let baseline = plan
            .aggregate_span_sum(haystack, AggregateReduceLimits::unlimited())
            .expect("unlimited fixed-chunk span sum");
        let upper = baseline.accounting.upper_bounds;
        let exact = AggregateReduceLimits {
            max_input_bytes: upper.input_bytes,
            max_source_reads: upper.source_reads,
            max_work: upper.work,
            max_unit_events: upper.unit_events,
            max_run_events: upper.run_events,
            max_match_events: upper.match_events,
            max_count: upper.count,
            max_span_sum: upper.span_sum,
            max_scratch_bytes: upper.scratch_bytes,
            max_persistent_bytes: upper.persistent_bytes,
            max_peak_bytes: upper.peak_bytes,
        };
        assert_eq!(
            plan.aggregate_fixed_chunk_span_sum_value_success(haystack, exact),
            Some(baseline.span_sum),
        );

        macro_rules! one_below {
            ($upper_field:ident, $limit_field:ident, $error:ident) => {
                if upper.$upper_field > 0 {
                    let mut limits = AggregateReduceLimits::unlimited();
                    limits.$limit_field = upper.$upper_field - 1;
                    assert_eq!(
                        plan.aggregate_fixed_chunk_span_sum_value_success(haystack, limits),
                        None,
                        "compact fixed-chunk span sum one-below {}",
                        stringify!($limit_field),
                    );
                    assert_eq!(
                        plan.aggregate_span_sum(haystack, limits)
                            .expect_err("one-below fixed-chunk span-sum limit"),
                        AggregateReduceError::$error {
                            needed: upper.$upper_field,
                            limit: upper.$upper_field - 1,
                        },
                        "authoritative fixed-chunk span sum one-below {}",
                        stringify!($limit_field),
                    );
                }
            };
        }
        one_below!(input_bytes, max_input_bytes, InputBytesLimit);
        one_below!(source_reads, max_source_reads, SourceReadsLimit);
        one_below!(work, max_work, WorkLimit);
        one_below!(unit_events, max_unit_events, UnitEventsLimit);
        one_below!(run_events, max_run_events, RunEventsLimit);
        one_below!(match_events, max_match_events, MatchEventsLimit);
        one_below!(count, max_count, CountLimit);
        one_below!(span_sum, max_span_sum, SpanSumLimit);
        one_below!(scratch_bytes, max_scratch_bytes, ScratchLimit);
        one_below!(persistent_bytes, max_persistent_bytes, PersistentLimit);
        one_below!(peak_bytes, max_peak_bytes, PeakLimit);
    }

    fn assert_build_accounting_closes_every_operation(
        plan: Plan,
        accounting: AggregateBuildAccounting,
    ) {
        for identity in [
            plan.aggregate_count_identity(),
            plan.aggregate_span_sum_identity(),
        ] {
            assert!(aggregate_build_accounting_matches(identity, accounting));
            for field in 0..4 {
                let mut forged = accounting;
                match field {
                    0 => {
                        forged.work_upper_bound = forged
                            .work_upper_bound
                            .checked_sub(1)
                            .expect("word-run build work is positive");
                    }
                    1 => {
                        forged.scratch_bytes = forged
                            .scratch_bytes
                            .checked_add(1)
                            .expect("test scratch mutation fits");
                    }
                    2 => {
                        forged.persistent_bytes = forged
                            .persistent_bytes
                            .checked_sub(1)
                            .expect("word-run persistent storage is positive");
                    }
                    3 => {
                        forged.peak_bytes = forged
                            .peak_bytes
                            .checked_sub(1)
                            .expect("word-run peak storage is positive");
                    }
                    _ => unreachable!(),
                }
                assert!(!aggregate_build_accounting_matches(identity, forged));
            }
            assert!(!aggregate_build_accounting_matches(
                AggregateOperationIdentity {
                    plan_id: "forged-word-run-plan",
                    ..identity
                },
                accounting,
            ));
        }
    }

    #[test]
    fn fixed_class_chunks_exhaust_small_alphabet_and_widths() {
        for (width, pattern) in [(1, "[ab]{1}"), (2, "[ab]{2}"), (4, "[ab]{4}")] {
            let plan = Plan::fixed_class_chunks(width, class_words(b"ab"));
            for len in 0_u32..=8 {
                let cases = 3_usize.pow(len);
                for mut encoded in 0..cases {
                    let mut haystack =
                        Vec::with_capacity(usize::try_from(len).expect("small length"));
                    for _ in 0..len {
                        haystack.push(match encoded % 3 {
                            0 => b'a',
                            1 => b'b',
                            _ => b'x',
                        });
                        encoded /= 3;
                    }
                    assert_plan_matches(pattern, plan, &haystack);
                }
            }
        }
    }

    #[test]
    fn fixed_class_chunks_preserve_ranges_and_malformed_bytes() {
        let plan = Plan::fixed_class_chunks(3, class_words(&[b'a', b'b', b'c', 0x80, 0xFF]));
        for haystack in [
            b"abcabcxabc".as_slice(),
            &[0x80, 0xFF, b'a', b'b', b'x', 0x80, 0x80, 0x80],
            &[0xFF; 13],
            &[0xC3, 0x28, 0xFF, b'a', b'c', b'x'],
        ] {
            assert_plan_matches(r"[\x61-\x63\x80\xff]{3}", plan, haystack);
        }
    }

    #[test]
    fn compact_fixed_chunk_count_preserves_every_preflight_fence() {
        assert_fixed_chunk_compact_count_limit_parity(
            Plan::fixed_class_chunks(3, class_words(&[b'a', b'b', 0xFF])),
            &[b'a', b'b', 0xFF, b'a', b'x', 0xFF, b'a', b'b', 0xFF],
        );
    }

    #[test]
    fn compact_fixed_chunk_span_sum_preserves_every_preflight_fence() {
        assert_fixed_chunk_compact_span_sum_limit_parity(
            Plan::fixed_class_chunks(3, class_words(&[b'a', b'b', 0xFF])),
            &[b'a', b'b', 0xFF, b'a', b'x', 0xFF, b'a', b'b', 0xFF],
        );
    }

    #[test]
    fn bare_ascii_word_runs_exhaust_short_malformed_sources() {
        let cases = [
            (r"\w+", Plan::bare_greedy(1, WordMode::Ascii)),
            (r"\w{2,}", Plan::bare_greedy(2, WordMode::Ascii)),
        ];
        for (pattern, plan) in cases {
            let auto = AsciiPlan::build_auto(plan).expect("exact ASCII owner");
            for len in 0_u32..=6 {
                for mut encoded in 0..4_usize.pow(len) {
                    let mut haystack =
                        Vec::with_capacity(usize::try_from(len).expect("small length"));
                    for _ in 0..len {
                        haystack.push(match encoded % 4 {
                            0 => b'a',
                            1 => b'_',
                            2 => b'!',
                            _ => 0xff,
                        });
                        encoded /= 4;
                    }
                    assert_plan_matches(pattern, plan, &haystack);
                    assert_eq!(
                        auto.aggregate_count_value_success(
                            &haystack,
                            AggregateReduceLimits::unlimited(),
                        ),
                        plan.aggregate_count(&haystack, AggregateReduceLimits::unlimited())
                            .ok()
                            .map(|result| result.count),
                        "compact ASCII count {haystack:?}",
                    );
                    assert_eq!(
                        auto.aggregate_span_sum_value_success(
                            &haystack,
                            AggregateReduceLimits::unlimited(),
                        ),
                        plan.aggregate_span_sum(&haystack, AggregateReduceLimits::unlimited())
                            .ok()
                            .map(|result| result.span_sum),
                        "compact ASCII span sum {haystack:?}",
                    );
                }
            }
        }
    }

    #[test]
    fn prepared_unicode_word_existence_matches_bytes_regex_on_malformed_sources() {
        let mut explicit = vec![
            Vec::new(),
            b"!".to_vec(),
            vec![b'a'; 24],
            vec![b'a'; 25],
            vec![b'a'; 4_096],
            b"a!a!a!a!a!a!a!a!a!a!a!a!a!a!a!a!a!a!a!a!a!a!a!a!a".to_vec(),
            "abcdefghijklmnopqrstuvwx\u{e9}".as_bytes().to_vec(),
            "αβγδεζηθικλμνξοπρστυφχψωα".as_bytes().to_vec(),
            [vec![b'a'; 13], vec![0xff], vec![b'a'; 13]].concat(),
            b"a\x80aa".to_vec(),
            b"!\x80aa".to_vec(),
            vec![b'a', 0x80, 0x80, 0x80, b'a', b'a'],
            vec![b'a', 0x80, 0x80, 0x80, 0x80, b'a', b'a'],
            vec![0x80, 0xbf, 0xc2, b'a', 0xe2, 0x82, b'_', 0xf4, 0x90, 0x80, 0x80],
        ];
        // This dense short-word input is hostile to the former two-loop
        // implementation: every separator followed a word run and was
        // therefore decoded and classified twice.
        explicit.push(b"ab!".repeat(8_192));

        for minimum in [1_usize, 2, 3, 25] {
            for (pattern, plan) in [
                (
                    format!(r"\b\w{{{minimum},}}\b"),
                    Plan::new(minimum, WordMode::Unicode),
                ),
                (
                    format!(r"\w{{{minimum},}}"),
                    Plan::bare_greedy(minimum, WordMode::Unicode),
                ),
            ] {
                let oracle = RegexBuilder::new(&pattern)
                    .unicode(true)
                    .build()
                    .expect("Unicode bytes-regex oracle");
                for haystack in &explicit {
                    assert_eq!(
                        plan.is_match_full_prepared(haystack),
                        oracle.is_match(haystack),
                        "pattern={pattern:?} haystack={haystack:?}",
                    );
                    assert_plan_matches_with_unicode(&pattern, plan, haystack, true);
                }

                // Exhaust short arbitrary byte strings containing ASCII word
                // and separator bytes, valid UTF-8 alpha pairs, and malformed
                // lead/continuation bytes.
                let alphabet = [b'a', b'_', b'!', 0xff, 0xce, 0xb1];
                for len in 0_u32..=6 {
                    for mut encoded in 0..alphabet.len().pow(len) {
                        let mut haystack =
                            Vec::with_capacity(usize::try_from(len).expect("small length"));
                        for _ in 0..len {
                            haystack.push(alphabet[encoded % alphabet.len()]);
                            encoded /= alphabet.len();
                        }
                        assert_eq!(
                            plan.is_match_full_prepared(&haystack),
                            oracle.is_match(&haystack),
                            "pattern={pattern:?} haystack={haystack:?}",
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn prepared_unicode_word_minimum_byte_domain_is_exact_at_the_boundary() {
        let plan = Plan::new(25, WordMode::Unicode);

        assert!(!plan.is_match_full_prepared(&vec![b'a'; 24]));
        assert!(!plan.is_match_full_prepared("abcdefghijklmnopqrstuvé".as_bytes()));
        assert!(!plan.is_match_full_prepared(&vec![0xff; 24]));

        assert!(plan.is_match_full_prepared(&vec![b'a'; 25]));
        assert!(plan.is_match_full_prepared("abcdefghijklmnopqrstuvwxyzα".as_bytes()));

        let exact_bytes_but_broken_run = [vec![b'a'; 24], vec![0xff]].concat();
        assert_eq!(exact_bytes_but_broken_run.len(), 25);
        assert!(!plan.is_match_full_prepared(&exact_bytes_but_broken_run));

        let multibyte_but_too_few_scalars = "α".repeat(13);
        assert!(multibyte_but_too_few_scalars.len() >= 25);
        let multibyte_bytes = multibyte_but_too_few_scalars.as_bytes();
        assert!(!plan.is_match_full_prepared(multibyte_bytes));
    }

    #[test]
    fn prepaid_ascii_word_minimum_byte_domain_is_exact_and_refusal_safe() {
        let plan = AsciiPlan::build_auto(Plan::new(25, WordMode::Ascii))
            .expect("ASCII word-run plan");
        let short = vec![b'a'; 24];
        let short_window = SearchWindow::full(&short);

        assert_eq!(
            plan.is_match_window_value(
                &short,
                short_window,
                SearchLimits {
                    max_work: 24,
                    max_scratch_bytes: 0,
                },
            ),
            Ok(false),
        );
        assert_eq!(
            plan.is_match_window_value(
                &short,
                short_window,
                SearchLimits {
                    max_work: 23,
                    max_scratch_bytes: 0,
                },
            ),
            Err(Error::WorkLimitExceeded {
                needed: 24,
                limit: 23,
            }),
        );
        assert_eq!(
            plan.is_match_window_value(
                &short,
                SearchWindow::new(1, short.len()),
                SearchLimits {
                    max_work: 22,
                    max_scratch_bytes: 0,
                },
            ),
            Err(Error::WorkLimitExceeded {
                needed: 23,
                limit: 22,
            }),
        );
        let malformed_short = [vec![b'a'; 23], vec![0xff]].concat();
        assert_eq!(malformed_short.len(), 24);
        assert_eq!(
            plan.is_match_window_value(
                &malformed_short,
                SearchWindow::full(&malformed_short),
                SearchLimits {
                    max_work: 24,
                    max_scratch_bytes: 0,
                },
            ),
            Ok(false),
        );

        let boundary = vec![b'a'; 25];
        assert_eq!(
            plan.is_match_window_value(
                &boundary,
                SearchWindow::full(&boundary),
                SearchLimits {
                    max_work: 25,
                    max_scratch_bytes: 0,
                },
            ),
            Ok(true),
        );
        let broken = [vec![b'a'; 24], vec![b'-']].concat();
        assert_eq!(broken.len(), 25);
        assert_eq!(
            plan.is_match_window_value(
                &broken,
                SearchWindow::full(&broken),
                SearchLimits {
                    max_work: 25,
                    max_scratch_bytes: 0,
                },
            ),
            Ok(false),
        );

        let invalid = SearchWindow::new(1, 0);
        assert_eq!(
            plan.is_match_window_value(&short, invalid, SearchLimits::unlimited()),
            Err(Error::InvalidWindow {
                start: 1,
                end: 0,
                haystack_len: short.len(),
            }),
        );
    }

    #[test]
    fn ascii_word_boundary_only_exhausts_short_malformed_sources_and_closes_limits() {
        let parsed = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(r"\b")
            .expect("ASCII boundary HIR");
        let AggregateInspectionOutcome::Eligible(inspection) =
            inspect_aggregate_attempt(&parsed, usize::MAX).expect("boundary inspection")
        else {
            panic!("ASCII word boundary was not selected");
        };
        let plan = inspection.plan;
        assert_eq!(plan, Plan::ascii_boundary_only());
        let auto = AsciiPlan::build_auto(plan).expect("exact ASCII boundary owner");
        for len in 0_u32..=6 {
            for mut encoded in 0..4_usize.pow(len) {
                let mut haystack = Vec::with_capacity(usize::try_from(len).expect("small length"));
                for _ in 0..len {
                    haystack.push(match encoded % 4 {
                        0 => b'a',
                        1 => b'_',
                        2 => b'!',
                        _ => 0xff,
                    });
                    encoded /= 4;
                }
                let expected = oracle(r"\b", &haystack);
                assert_plan_matches(r"\b", plan, &haystack);
                assert_eq!(
                    auto.aggregate_count_value_success(
                        &haystack,
                        AggregateReduceLimits::unlimited(),
                    ),
                    Some(expected.0),
                    "compact ASCII boundary count {haystack:?}",
                );
                assert_eq!(
                    auto.aggregate_span_sum_value_success(
                        &haystack,
                        AggregateReduceLimits::unlimited(),
                    ),
                    Some(0),
                    "compact ASCII boundary span sum {haystack:?}",
                );
            }
        }

        let counted = auto
            .aggregate_count(b"a!b", AggregateReduceLimits::unlimited())
            .expect("boundary count accounting");
        assert_eq!(counted.count, 4);
        assert_eq!(counted.accounting.actual.matches, 4);
        assert_eq!(counted.accounting.upper_bounds.match_events, 4);
        assert_eq!(counted.accounting.identity.topology, WordRunTopology::AsciiBoundaryOnly);
        assert!(!counted.accounting.identity.greedy);
        let mut refused = AggregateReduceLimits::unlimited();
        refused.max_match_events = counted.accounting.upper_bounds.match_events - 1;
        assert_eq!(
            auto.aggregate_count_value_success(b"a!b", refused),
            None,
        );
        assert_eq!(
            auto.aggregate_count(b"a!b", refused)
                .expect_err("one-below boundary match-event limit"),
            AggregateReduceError::MatchEventsLimit {
                needed: 4,
                limit: 3,
            },
        );

        for pattern in [r"\B", r"a\b"] {
            let hir = ParserBuilder::new()
                .unicode(false)
                .utf8(false)
                .build()
                .parse(pattern)
                .expect("nearby ASCII HIR");
            assert!(matches!(
                inspect_aggregate_attempt(&hir, usize::MAX).expect("nearby inspection"),
                AggregateInspectionOutcome::Ineligible { .. }
            ));
        }
        let unicode = ParserBuilder::new()
            .unicode(true)
            .utf8(false)
            .build()
            .parse(r"\b")
            .expect("Unicode boundary HIR");
        assert!(matches!(
            inspect_aggregate_attempt(&unicode, usize::MAX).expect("Unicode inspection"),
            AggregateInspectionOutcome::Ineligible { .. }
        ));
    }

    #[test]
    fn bare_search_windows_do_not_invent_boundary_assertions() {
        let window = SearchWindow::new(1, 3);
        let bare = Plan::bare_greedy(2, WordMode::Ascii);
        let complete = Plan::new(2, WordMode::Ascii);
        assert_eq!(
            bare.find_window(b"abcd", window, SearchLimits::unlimited())
                .expect("bare ASCII search")
                .0,
            Some(crate::Match { start: 1, end: 3 })
        );
        assert_eq!(
            complete
                .find_window(b"abcd", window, SearchLimits::unlimited())
                .expect("complete ASCII search")
                .0,
            None
        );
        assert_eq!(
            AsciiPlan::build_auto(bare)
                .expect("bare ASCII owner")
                .find_window(b"abcd", window, SearchLimits::unlimited())
                .expect("dispatched bare ASCII search")
                .0,
            Some(crate::Match { start: 1, end: 3 })
        );

        let unicode_haystack = "αβγ".as_bytes();
        let unicode_window = SearchWindow::new("α".len(), unicode_haystack.len());
        assert_eq!(
            Plan::bare_greedy(2, WordMode::Unicode)
                .find_window(unicode_haystack, unicode_window, SearchLimits::unlimited())
                .expect("bare Unicode search")
                .0,
            Some(crate::Match {
                start: "α".len(),
                end: unicode_haystack.len(),
            })
        );
        assert_eq!(
            Plan::new(2, WordMode::Unicode)
                .find_window(unicode_haystack, unicode_window, SearchLimits::unlimited())
                .expect("complete Unicode search")
                .0,
            None
        );
    }

    #[test]
    fn bare_greedy_word_inspection_is_exact_and_refuses_nearby_shapes() {
        let ascii = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(r"(\w+)")
            .expect("ASCII word HIR");
        let inspected = inspect_aggregate_attempt(&ascii, usize::MAX).expect("inspection");
        let AggregateInspectionOutcome::Eligible(inspection) = inspected else {
            panic!("bare greedy ASCII word run was not selected");
        };
        assert_eq!(inspection.plan, Plan::bare_greedy(1, WordMode::Ascii));
        assert_eq!(inspection.captures, 1);
        assert_eq!(inspection.hir_nodes, 3);
        for identity in [
            inspection.plan.aggregate_count_identity(),
            inspection.plan.aggregate_span_sum_identity(),
        ] {
            assert_eq!(identity.topology, WordRunTopology::BareGreedyRoot);
            assert!(!identity.complete_word_boundaries);
        }
        let refusal = inspect_aggregate_attempt(&ascii, inspection.work - 1)
            .expect_err("one-below planner work");
        assert_eq!(
            *refusal.source(),
            AggregateInspectionError::WorkLimit {
                needed: inspection.work,
                limit: inspection.work - 1,
            }
        );
        assert!(refusal.work() < inspection.work);

        let unicode = ParserBuilder::new()
            .unicode(true)
            .utf8(false)
            .build()
            .parse(r"\w{2,}")
            .expect("Unicode word HIR");
        let AggregateInspectionOutcome::Eligible(inspection) =
            inspect_aggregate_attempt(&unicode, usize::MAX).expect("Unicode inspection")
        else {
            panic!("bare greedy Unicode word run was not selected");
        };
        assert_eq!(inspection.plan, Plan::bare_greedy(2, WordMode::Unicode));
        assert_eq!(
            inspection.plan.aggregate_count_identity().topology,
            WordRunTopology::BareGreedyRoot
        );
        assert!(
            !inspection
                .plan
                .aggregate_count_identity()
                .complete_word_boundaries
        );

        let explicit = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(r"\b\w{2,}\b")
            .expect("explicit-boundary ASCII word HIR");
        let AggregateInspectionOutcome::Eligible(inspection) =
            inspect_aggregate_attempt(&explicit, usize::MAX).expect("explicit inspection")
        else {
            panic!("explicit-boundary ASCII word run was not selected");
        };
        assert_eq!(inspection.plan, Plan::new(2, WordMode::Ascii));
        for identity in [
            inspection.plan.aggregate_count_identity(),
            inspection.plan.aggregate_span_sum_identity(),
        ] {
            assert_eq!(identity.topology, WordRunTopology::CompleteWordBoundaries);
            assert!(identity.complete_word_boundaries);
        }

        for pattern in [r"\w*", r"\w+?", r"\w{1,3}", r"[A-Z]+"] {
            let hir = ParserBuilder::new()
                .unicode(false)
                .utf8(false)
                .build()
                .parse(pattern)
                .expect("nearby ASCII HIR");
            assert!(matches!(
                inspect_aggregate_attempt(&hir, usize::MAX).expect("ineligible inspection"),
                AggregateInspectionOutcome::Ineligible { .. }
            ));
        }
    }

    #[test]
    fn ascii_auto_scanner_preserves_scalar_windows_limits_and_accounting() {
        let scalar = Plan::new(3, WordMode::Ascii);
        let auto = AsciiPlan::build_auto(scalar).expect("exact ASCII owner");
        assert_eq!(auto.run_scanner().set(), ascii_word_set());
        let haystacks: &[&[u8]] = &[
            b"",
            b"---abc---",
            b"a_b 012345 x",
            &[0xFF, b'a', b'b', b'c', 0x80, b'd', b'e', b'f'],
            b"word_that_crosses_several_fixed_blocks!",
        ];
        for &haystack in haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let window = SearchWindow::new(start, end);
                    let scalar_result = scalar
                        .find_window(haystack, window, SearchLimits::unlimited())
                        .expect("scalar search");
                    let auto_result = auto
                        .find_window(haystack, window, SearchLimits::unlimited())
                        .expect("automatic search");
                    assert_eq!(auto_result, scalar_result, "{haystack:?}/{start}..{end}");
                    let work = scalar_result.1.work();
                    for limit in [0, work.saturating_sub(1), work, work.saturating_add(1)] {
                        let limits = SearchLimits {
                            max_work: limit,
                            max_scratch_bytes: usize::MAX,
                        };
                        assert_eq!(
                            auto.find_window(haystack, window, limits),
                            scalar.find_window(haystack, window, limits),
                            "limit={limit} {haystack:?}/{start}..{end}"
                        );
                    }
                }
            }
        }
        let invalid = SearchWindow::new(2, 1);
        assert_eq!(
            auto.find_window(b"abc", invalid, SearchLimits::unlimited()),
            scalar.find_window(b"abc", invalid, SearchLimits::unlimited())
        );
    }

    #[test]
    fn ascii_auto_scanner_preserves_aggregate_results_and_logical_ledgers() {
        let scalar = Plan::new(12, WordMode::Ascii);
        let auto = AsciiPlan::build_auto(scalar).expect("exact ASCII owner");
        let mut long = Vec::new();
        long.extend(std::iter::repeat_n(b'a', 4_097));
        long.push(b'!');
        long.extend(std::iter::repeat_n(b'7', 257));
        long.extend_from_slice(&[0xFF, b'_', b'x']);
        for haystack in [
            b"---abcdefghijkl---123456789012---".as_slice(),
            &[0x80, b'a', b'b', b'c', b'_', b'1', 0xFF],
            long.as_slice(),
        ] {
            let scalar_count = scalar
                .aggregate_count(haystack, AggregateReduceLimits::unlimited())
                .expect("scalar count");
            let auto_count = auto
                .aggregate_count(haystack, AggregateReduceLimits::unlimited())
                .expect("automatic count");
            assert_eq!(auto_count.count, scalar_count.count);
            assert_eq!(
                auto.aggregate_count_value_success(haystack, AggregateReduceLimits::unlimited()),
                Some(scalar_count.count),
            );
            assert_eq!(auto_count.accounting.actual, scalar_count.accounting.actual);
            assert_eq!(auto_count.accounting.actual.source_reads, haystack.len());

            let scalar_sum = scalar
                .aggregate_span_sum(haystack, AggregateReduceLimits::unlimited())
                .expect("scalar span sum");
            let auto_sum = auto
                .aggregate_span_sum(haystack, AggregateReduceLimits::unlimited())
                .expect("automatic span sum");
            assert_eq!(auto_sum.span_sum, scalar_sum.span_sum);
            assert_eq!(
                auto.aggregate_span_sum_value_success(
                    haystack,
                    AggregateReduceLimits::unlimited(),
                ),
                Some(scalar_sum.span_sum),
            );
            assert_eq!(auto_sum.accounting.actual, scalar_sum.accounting.actual);
            assert_eq!(auto_sum.accounting.actual.source_reads, haystack.len());
        }
    }

    #[test]
    fn ascii_compact_count_preserves_every_preflight_fence() {
        let plan = AsciiPlan::build_auto(Plan::new(2, WordMode::Ascii)).expect("exact ASCII owner");
        let haystack = b"--ab--word_7--x--block_crossing_0123456789--";
        let baseline = plan
            .aggregate_count(haystack, AggregateReduceLimits::unlimited())
            .expect("unlimited count");
        let upper = baseline.accounting.upper_bounds;
        let exact = AggregateReduceLimits {
            max_input_bytes: upper.input_bytes,
            max_source_reads: upper.source_reads,
            max_work: upper.work,
            max_unit_events: upper.unit_events,
            max_run_events: upper.run_events,
            max_match_events: upper.match_events,
            max_count: upper.count,
            max_span_sum: upper.span_sum,
            max_scratch_bytes: upper.scratch_bytes,
            max_persistent_bytes: upper.persistent_bytes,
            max_peak_bytes: upper.peak_bytes,
        };
        assert_eq!(
            plan.aggregate_count_value_success(haystack, exact),
            Some(baseline.count),
        );

        macro_rules! one_below {
            ($upper_field:ident, $limit_field:ident, $error:ident) => {
                if upper.$upper_field > 0 {
                    let mut limits = AggregateReduceLimits::unlimited();
                    limits.$limit_field = upper.$upper_field - 1;
                    assert_eq!(plan.aggregate_count_value_success(haystack, limits), None);
                    assert_eq!(
                        plan.aggregate_count(haystack, limits)
                            .expect_err("one-below ASCII count limit"),
                        AggregateReduceError::$error {
                            needed: upper.$upper_field,
                            limit: upper.$upper_field - 1,
                        },
                    );
                }
            };
        }
        one_below!(input_bytes, max_input_bytes, InputBytesLimit);
        one_below!(source_reads, max_source_reads, SourceReadsLimit);
        one_below!(work, max_work, WorkLimit);
        one_below!(unit_events, max_unit_events, UnitEventsLimit);
        one_below!(run_events, max_run_events, RunEventsLimit);
        one_below!(match_events, max_match_events, MatchEventsLimit);
        one_below!(count, max_count, CountLimit);
        one_below!(span_sum, max_span_sum, SpanSumLimit);
        one_below!(scratch_bytes, max_scratch_bytes, ScratchLimit);
        one_below!(persistent_bytes, max_persistent_bytes, PersistentLimit);
        one_below!(peak_bytes, max_peak_bytes, PeakLimit);
    }

    #[test]
    fn ascii_compact_span_sum_preserves_every_preflight_fence() {
        let plan = AsciiPlan::build_auto(Plan::new(2, WordMode::Ascii)).expect("exact ASCII owner");
        let haystack = b"--ab--word_7--x--block_crossing_0123456789--";
        let baseline = plan
            .aggregate_span_sum(haystack, AggregateReduceLimits::unlimited())
            .expect("unlimited span sum");
        let upper = baseline.accounting.upper_bounds;
        let exact = AggregateReduceLimits {
            max_input_bytes: upper.input_bytes,
            max_source_reads: upper.source_reads,
            max_work: upper.work,
            max_unit_events: upper.unit_events,
            max_run_events: upper.run_events,
            max_match_events: upper.match_events,
            max_count: upper.count,
            max_span_sum: upper.span_sum,
            max_scratch_bytes: upper.scratch_bytes,
            max_persistent_bytes: upper.persistent_bytes,
            max_peak_bytes: upper.peak_bytes,
        };
        assert_eq!(
            plan.aggregate_span_sum_value_success(haystack, exact),
            Some(baseline.span_sum),
        );

        macro_rules! one_below {
            ($upper_field:ident, $limit_field:ident, $error:ident) => {
                if upper.$upper_field > 0 {
                    let mut limits = AggregateReduceLimits::unlimited();
                    limits.$limit_field = upper.$upper_field - 1;
                    assert_eq!(
                        plan.aggregate_span_sum_value_success(haystack, limits),
                        None,
                    );
                    assert_eq!(
                        plan.aggregate_span_sum(haystack, limits)
                            .expect_err("one-below ASCII span-sum limit"),
                        AggregateReduceError::$error {
                            needed: upper.$upper_field,
                            limit: upper.$upper_field - 1,
                        },
                    );
                }
            };
        }
        one_below!(input_bytes, max_input_bytes, InputBytesLimit);
        one_below!(source_reads, max_source_reads, SourceReadsLimit);
        one_below!(work, max_work, WorkLimit);
        one_below!(unit_events, max_unit_events, UnitEventsLimit);
        one_below!(run_events, max_run_events, RunEventsLimit);
        one_below!(match_events, max_match_events, MatchEventsLimit);
        one_below!(count, max_count, CountLimit);
        one_below!(span_sum, max_span_sum, SpanSumLimit);
        one_below!(scratch_bytes, max_scratch_bytes, ScratchLimit);
        one_below!(persistent_bytes, max_persistent_bytes, PersistentLimit);
        one_below!(peak_bytes, max_peak_bytes, PeakLimit);
    }

    #[test]
    fn aggregate_build_accounting_is_exact_for_every_plan_and_operation() {
        let ascii = Plan::new(3, WordMode::Ascii);
        let ascii_attempt = ascii
            .aggregate_build_attempt(AggregateBuildLimits::unlimited())
            .expect("ASCII build");
        let (accounting, actual) = ascii_attempt.into_parts();
        let built = AsciiPlan::build_auto(ascii).expect("exact ASCII owner");
        assert_eq!(built.run_scanner().set(), ascii_word_set());
        assert_eq!(
            accounting.work_upper_bound,
            FIXED_BUILD_WORK + ASCII_RUN_SCANNER_BUILD_WORK
        );
        assert_eq!(accounting.persistent_bytes, AsciiPlan::persistent_bytes());
        assert_eq!(accounting.peak_bytes, accounting.persistent_bytes);
        assert_build_accounting_closes_every_operation(ascii, accounting);
        assert_eq!(
            actual.work,
            u64::try_from(accounting.work_upper_bound).expect("small fixed work")
        );
        assert_eq!(actual.initialized_bytes, accounting.persistent_bytes);
        assert_eq!(actual.live_persistent_bytes, accounting.persistent_bytes);
        assert_eq!(actual.allocations, 1);
        assert_eq!(
            actual.allocated_bytes,
            core::mem::size_of::<AsciiPlanOwner>()
        );

        let unicode = Plan::new(3, WordMode::Unicode);
        let unicode_attempt = unicode
            .aggregate_build_attempt(AggregateBuildLimits::unlimited())
            .expect("Unicode build");
        let (accounting, actual) = unicode_attempt.into_parts();
        assert_eq!(accounting.work_upper_bound, FIXED_BUILD_WORK);
        assert_eq!(accounting.persistent_bytes, core::mem::size_of::<Plan>());
        assert_build_accounting_closes_every_operation(unicode, accounting);
        assert_eq!(actual.allocations, 0);
        assert_eq!(actual.initialized_bytes, core::mem::size_of::<Plan>());

        let fixed = Plan::fixed_class_chunks(256, class_words(b"0_az"));
        let fixed_attempt = fixed
            .aggregate_build_attempt(AggregateBuildLimits::unlimited())
            .expect("fixed-class build");
        let (accounting, actual) = fixed_attempt.into_parts();
        assert_eq!(accounting.work_upper_bound, FIXED_BUILD_WORK);
        assert_eq!(accounting.persistent_bytes, core::mem::size_of::<Plan>());
        assert_build_accounting_closes_every_operation(fixed, accounting);
        assert_eq!(actual.allocations, 0);
        assert_eq!(actual.initialized_bytes, core::mem::size_of::<Plan>());
    }

    fn measure_ascii_search(
        mut search: impl FnMut() -> Result<(Option<crate::Match>, super::Accounting), super::Error>,
        iterations: u32,
    ) -> (Duration, u64) {
        let started = Instant::now();
        let mut checksum = 0_u64;
        for _ in 0..iterations {
            let (matched, accounting) = black_box(search()).expect("benchmark search");
            checksum = checksum.wrapping_add(accounting.work());
            checksum = checksum.wrapping_add(
                u64::try_from(matched.map_or(0, crate::Match::end)).expect("match end fits u64"),
            );
        }
        (started.elapsed(), checksum)
    }

    #[test]
    #[ignore = "manual release benchmark for the retained automatic ASCII run scanner"]
    fn benchmark_unicode_word_run_ascii_auto_against_scalar() {
        let scalar = Plan::new(1, WordMode::Ascii);
        let auto = AsciiPlan::build_auto(scalar).expect("exact ASCII owner");
        let mut haystack = Vec::with_capacity((256 << 10) + 2);
        haystack.push(b'!');
        haystack.extend(std::iter::repeat_n(b'a', 256 << 10));
        haystack.push(b'!');
        let window = SearchWindow::full(&haystack);
        let limits = SearchLimits::unlimited();
        assert_eq!(
            auto.find_window(&haystack, window, limits),
            scalar.find_window(&haystack, window, limits)
        );
        let iterations =
            std::env::var("FRE_UNICODE_WORD_RUN_ASCII_BENCH_ITERS").map_or(256, |raw| {
                raw.parse::<u32>().unwrap_or_else(|error| {
                    panic!("FRE_UNICODE_WORD_RUN_ASCII_BENCH_ITERS: {error}")
                })
            });
        assert!(iterations > 0);
        let _ = measure_ascii_search(
            || scalar.find_window(black_box(&haystack), window, limits),
            2,
        );
        let _ = measure_ascii_search(|| auto.find_window(black_box(&haystack), window, limits), 2);
        let (scalar_elapsed, scalar_checksum) = measure_ascii_search(
            || scalar.find_window(black_box(&haystack), window, limits),
            iterations,
        );
        let (auto_elapsed, auto_checksum) = measure_ascii_search(
            || auto.find_window(black_box(&haystack), window, limits),
            iterations,
        );
        assert_eq!(auto_checksum, scalar_checksum);
        let scalar_ns = scalar_elapsed.as_secs_f64() * 1_000_000_000.0 / f64::from(iterations);
        let auto_ns = auto_elapsed.as_secs_f64() * 1_000_000_000.0 / f64::from(iterations);
        eprintln!(
            "UNICODE_WORD_RUN_ASCII_BENCH iterations={iterations} bytes={} \
             scalar_ns={scalar_ns:.9} auto_ns={auto_ns:.9} auto_over_scalar={:.9} \
             variant={}",
            haystack.len(),
            auto_ns / scalar_ns,
            auto.run_scanner().selection().variant_id,
        );
    }
}
