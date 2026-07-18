//! Bounded scalar-stream reducer for the accepted `wild/grapheme` shape.
//!
//! Construction overlays canonical Unicode-property ranges into disjoint
//! role-bit segments and proves the derived classes used by the exact HIR
//! skeleton. Execution decodes and classifies every valid scalar once. A
//! single retained lookahead drives the ordered, greedy cluster machine, so
//! count and span-sum reduction are linear and allocate no search scratch.

use core::{fmt, mem::size_of};

use fre_exact_alloc::{CopyError, ExactVec};

/// Stable identity for the exact ordered grapheme scalar machine.
pub const PLAN_ID: &str = "grapheme-scalar-dfa.utf8-role-segments.v1";
/// Stable identity for match counting.
pub const COUNT_OPERATION_ID: &str = "grapheme-scalar-dfa.count.non-overlapping.v1";
/// Stable identity for matched-byte summation.
pub const SPAN_SUM_OPERATION_ID: &str = "grapheme-scalar-dfa.span-sum.non-overlapping.v1";

const MAX_SCALAR: u32 = 0x10_FFFF;
const AFTER_MAX_SCALAR: u32 = MAX_SCALAR + 1;
const SURROGATE_START: u32 = 0xD800;
const SURROGATE_END: u32 = 0xDFFF;
const ROLE_COUNT: usize = 17;
// Build work units dominate all scalar operations in each named path. Range
// validation covers iteration, role dispatch, ordering tests and table writes.
// Each sort comparison term covers key decoding, both key comparisons, heap
// branches and a possible swap; the event overhead covers heap roots and loop
// exits. Sweep and semantic terms cover every event/segment probe and write.
const BUILD_ALLOCATIONS: usize = 2;
const BUILD_FIXED_WORK: usize = 128;
const RANGE_VALIDATION_WORK: usize = 32;
const EVENT_WRITE_WORK: usize = 8;
const SORT_COMPARISON_WORK: usize = 16;
const SORT_EVENT_OVERHEAD_WORK: usize = 32;
const SWEEP_EVENT_WORK: usize = 32;
const SEGMENT_WRITE_WORK: usize = 8;
const SEMANTIC_SEGMENT_WORK: usize = 64;
const ALLOCATION_WORK: usize = 16;
// A role probe charges the lookahead access, option test, mask read and bit
// comparison. Branch and repetition counters separately charge their control
// decisions; all three are bounded from input bytes before traversal.
const ROLE_PROBES_PER_INPUT_BYTE: usize = 16;
const BRANCH_CHECKS_PER_INPUT_BYTE: usize = 24;
const REPETITION_TESTS_PER_INPUT_BYTE: usize = 8;
const ROLE_PROBE_WORK: usize = 4;
const EXECUTION_TERMINAL_CHECKS: usize = 1;
const EXECUTION_SCRATCH_BYTES: usize = 512;

/// One exact class role in the accepted HIR skeleton.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum GraphemeScalarClassRole {
    Cr,
    Lf,
    Control,
    Prepend,
    L,
    V,
    Lv,
    Lvt,
    T,
    Ri,
    Extend,
    Zwj,
    SpacingMark,
    ExtendedPictographic,
    /// Exact complement of `Control | Cr | Lf` over Unicode scalar values.
    GenericCore,
    /// Exact union of `Extend | Zwj | SpacingMark`.
    Tail,
    /// Every Unicode scalar value.
    Any,
}

impl GraphemeScalarClassRole {
    const fn index(self) -> usize {
        match self {
            Self::Cr => 0,
            Self::Lf => 1,
            Self::Control => 2,
            Self::Prepend => 3,
            Self::L => 4,
            Self::V => 5,
            Self::Lv => 6,
            Self::Lvt => 7,
            Self::T => 8,
            Self::Ri => 9,
            Self::Extend => 10,
            Self::Zwj => 11,
            Self::SpacingMark => 12,
            Self::ExtendedPictographic => 13,
            Self::GenericCore => 14,
            Self::Tail => 15,
            Self::Any => 16,
        }
    }

    const fn bit(self) -> u32 {
        match self {
            Self::Cr => 1 << 0,
            Self::Lf => 1 << 1,
            Self::Control => 1 << 2,
            Self::Prepend => 1 << 3,
            Self::L => 1 << 4,
            Self::V => 1 << 5,
            Self::Lv => 1 << 6,
            Self::Lvt => 1 << 7,
            Self::T => 1 << 8,
            Self::Ri => 1 << 9,
            Self::Extend => 1 << 10,
            Self::Zwj => 1 << 11,
            Self::SpacingMark => 1 << 12,
            Self::ExtendedPictographic => 1 << 13,
            Self::GenericCore => 1 << 14,
            Self::Tail => 1 << 15,
            Self::Any => 1 << 16,
        }
    }
}

const GCB_MASK: u32 = GraphemeScalarClassRole::Cr.bit()
    | GraphemeScalarClassRole::Lf.bit()
    | GraphemeScalarClassRole::Control.bit()
    | GraphemeScalarClassRole::Prepend.bit()
    | GraphemeScalarClassRole::L.bit()
    | GraphemeScalarClassRole::V.bit()
    | GraphemeScalarClassRole::Lv.bit()
    | GraphemeScalarClassRole::Lvt.bit()
    | GraphemeScalarClassRole::T.bit()
    | GraphemeScalarClassRole::Ri.bit()
    | GraphemeScalarClassRole::Extend.bit()
    | GraphemeScalarClassRole::Zwj.bit()
    | GraphemeScalarClassRole::SpacingMark.bit();

/// Complete operation selected for one traversal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Count,
    SpanSum,
}

/// UTF-8 and iteration semantics certified by this plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Semantics {
    /// Rust `regex::bytes` Unicode semantics: valid scalars participate;
    /// malformed bytes advance by one byte and never match.
    RustBytesUnicodeUtf8False,
}

/// Stable semantic and implementation identity for one operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationIdentity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub operation: Operation,
    pub semantics: Semantics,
    pub non_overlapping: bool,
    pub ordered_alternation: bool,
}

impl OperationIdentity {
    #[must_use]
    pub const fn for_operation(operation: Operation) -> Self {
        Self {
            plan_id: PLAN_ID,
            operation_id: match operation {
                Operation::Count => COUNT_OPERATION_ID,
                Operation::SpanSum => SPAN_SUM_OPERATION_ID,
            },
            operation,
            semantics: Semantics::RustBytesUnicodeUtf8False,
            non_overlapping: true,
            ordered_alternation: true,
        }
    }
}

/// Limits checked while constructing one role-segment plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    pub max_source_ranges: usize,
    pub max_events: usize,
    pub max_segments: usize,
    pub max_sort_comparisons: usize,
    pub max_allocations: usize,
    pub max_event_writes: usize,
    pub max_segment_writes: usize,
    pub max_build_work: usize,
    pub max_scratch_bytes: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl BuildLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_source_ranges: usize::MAX,
            max_events: usize::MAX,
            max_segments: usize::MAX,
            max_sort_comparisons: usize::MAX,
            max_allocations: usize::MAX,
            max_event_writes: usize::MAX,
            max_segment_writes: usize::MAX,
            max_build_work: usize::MAX,
            max_scratch_bytes: usize::MAX,
            max_persistent_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for BuildLimits {
    fn default() -> Self {
        Self {
            max_source_ranges: 1 << 14,
            max_events: 1 << 15,
            max_segments: 1 << 15,
            max_sort_comparisons: 1 << 22,
            max_allocations: BUILD_ALLOCATIONS,
            max_event_writes: 1 << 15,
            max_segment_writes: 1 << 15,
            max_build_work: 1 << 25,
            max_scratch_bytes: 1 << 20,
            max_persistent_bytes: 1 << 20,
            max_peak_bytes: 2 << 20,
        }
    }
}

/// Auditable construction certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    pub source_ranges: usize,
    pub events: usize,
    pub event_capacity: usize,
    pub segment_capacity: usize,
    pub retained_segments: usize,
    pub sort_comparisons_upper: usize,
    pub sort_comparisons_actual: usize,
    pub allocations: usize,
    pub event_writes: usize,
    pub segment_writes: usize,
    pub copy_bytes: usize,
    pub binary_search_comparisons_per_scalar: usize,
    pub work: usize,
    pub actual_work: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Limits checked before traversal begins.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceLimits {
    pub max_input_bytes: usize,
    pub max_decode_byte_checks: usize,
    pub max_classifications: usize,
    pub max_range_comparisons: usize,
    pub max_scanner_steps: usize,
    pub max_role_probes: usize,
    pub max_branch_checks: usize,
    pub max_repetition_tests: usize,
    pub max_match_events: usize,
    pub max_count: u64,
    pub max_span_sum: u64,
    pub max_work: usize,
    pub max_scratch_bytes: usize,
    pub max_peak_bytes: usize,
}

impl ReduceLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_input_bytes: usize::MAX,
            max_decode_byte_checks: usize::MAX,
            max_classifications: usize::MAX,
            max_range_comparisons: usize::MAX,
            max_scanner_steps: usize::MAX,
            max_role_probes: usize::MAX,
            max_branch_checks: usize::MAX,
            max_repetition_tests: usize::MAX,
            max_match_events: usize::MAX,
            max_count: u64::MAX,
            max_span_sum: u64::MAX,
            max_work: usize::MAX,
            max_scratch_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for ReduceLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 1 << 30,
            max_decode_byte_checks: usize::MAX,
            max_classifications: 1 << 30,
            max_range_comparisons: usize::MAX,
            max_scanner_steps: (1 << 30) + 1,
            max_role_probes: usize::MAX,
            max_branch_checks: usize::MAX,
            max_repetition_tests: usize::MAX,
            max_match_events: 1 << 30,
            max_count: 1 << 30,
            max_span_sum: 1 << 30,
            max_work: usize::MAX,
            max_scratch_bytes: EXECUTION_SCRATCH_BYTES,
            max_peak_bytes: 2 << 20,
        }
    }
}

/// Bounds checked before traversal and attached to a successful result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceUpperBounds {
    pub input_bytes: usize,
    pub decode_byte_checks: usize,
    pub valid_scalars: usize,
    pub invalid_bytes: usize,
    pub classifications: usize,
    pub range_comparisons: usize,
    pub binary_search_comparisons_per_scalar: usize,
    pub scanner_steps: usize,
    pub role_probes: usize,
    pub branch_checks: usize,
    pub repetition_tests: usize,
    pub match_events: usize,
    pub count: u64,
    pub span_sum: u64,
    pub work: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Exact structural counters after a successful traversal.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReduceActualCounters {
    pub input_bytes_advanced: usize,
    pub decode_byte_checks: usize,
    pub valid_scalars: usize,
    pub invalid_bytes: usize,
    pub classifications: usize,
    pub range_comparisons: usize,
    pub scanner_steps: usize,
    pub role_probes: usize,
    pub branch_checks: usize,
    pub repetition_tests: usize,
    pub match_events: usize,
    pub count: u64,
    pub matched_bytes: u64,
    pub work: usize,
    pub scratch_bytes: usize,
}

/// Upper bounds and exact counters for one result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceAccounting {
    pub identity: OperationIdentity,
    pub upper_bounds: ReduceUpperBounds,
    pub actual: ReduceActualCounters,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountResult {
    pub count: u64,
    pub accounting: ReduceAccounting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanSumResult {
    pub span_sum: u64,
    pub accounting: ReduceAccounting,
}

/// Checked construction failure. No partial plan is published.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    MissingRole {
        role: GraphemeScalarClassRole,
    },
    ReversedRange {
        role: GraphemeScalarClassRole,
        start: char,
        end: char,
    },
    NonCanonicalRanges {
        role: GraphemeScalarClassRole,
    },
    DerivedClassMismatch {
        role: GraphemeScalarClassRole,
    },
    OverlappingProperties,
    RangeLimit {
        needed: usize,
        limit: usize,
    },
    EventLimit {
        needed: usize,
        limit: usize,
    },
    SegmentLimit {
        needed: usize,
        limit: usize,
    },
    SortComparisonsLimit {
        needed: usize,
        limit: usize,
    },
    AllocationLimit {
        needed: usize,
        limit: usize,
    },
    EventWritesLimit {
        needed: usize,
        limit: usize,
    },
    SegmentWritesLimit {
        needed: usize,
        limit: usize,
    },
    WorkLimit {
        needed: usize,
        limit: usize,
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
    AllocationFailed {
        additional: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRole { role } => write!(f, "missing grapheme role {role:?}"),
            Self::ReversedRange { role, start, end } => {
                write!(
                    f,
                    "grapheme role {role:?} range {start:?}..={end:?} is reversed"
                )
            }
            Self::NonCanonicalRanges { role } => {
                write!(f, "grapheme role {role:?} ranges are not canonical")
            }
            Self::DerivedClassMismatch { role } => {
                write!(
                    f,
                    "grapheme derived class {role:?} does not match its proof identity"
                )
            }
            Self::OverlappingProperties => {
                f.write_str("grapheme GCB/extended-pictographic properties overlap")
            }
            Self::RangeLimit { needed, limit } => write!(
                f,
                "grapheme build needs {needed} source ranges, limit is {limit}"
            ),
            Self::EventLimit { needed, limit } => {
                write!(f, "grapheme build needs {needed} events, limit is {limit}")
            }
            Self::SegmentLimit { needed, limit } => write!(
                f,
                "grapheme build needs {needed} segments, limit is {limit}"
            ),
            Self::SortComparisonsLimit { needed, limit } => write!(
                f,
                "grapheme build may need {needed} sort comparisons, limit is {limit}"
            ),
            Self::AllocationLimit { needed, limit } => write!(
                f,
                "grapheme build needs {needed} allocations, limit is {limit}"
            ),
            Self::EventWritesLimit { needed, limit } => write!(
                f,
                "grapheme build needs {needed} event writes, limit is {limit}"
            ),
            Self::SegmentWritesLimit { needed, limit } => write!(
                f,
                "grapheme build may need {needed} segment writes, limit is {limit}"
            ),
            Self::WorkLimit { needed, limit } => {
                write!(f, "grapheme build needs {needed} work, limit is {limit}")
            }
            Self::ScratchLimit { needed, limit } => write!(
                f,
                "grapheme build needs {needed} scratch bytes, limit is {limit}"
            ),
            Self::PersistentLimit { needed, limit } => {
                write!(f, "grapheme plan needs {needed} bytes, limit is {limit}")
            }
            Self::PeakLimit { needed, limit } => {
                write!(f, "grapheme build peak is {needed} bytes, limit is {limit}")
            }
            Self::AllocationFailed { additional } => {
                write!(f, "failed to reserve {additional} grapheme build entries")
            }
            Self::ArithmeticOverflow { computation } => {
                write!(f, "arithmetic overflow while computing {computation}")
            }
        }
    }
}

impl std::error::Error for BuildError {}

/// Checked operation failure. No partial result is published.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReduceError {
    InputBytesLimit { needed: usize, limit: usize },
    DecodeByteChecksLimit { needed: usize, limit: usize },
    ClassificationsLimit { needed: usize, limit: usize },
    RangeComparisonsLimit { needed: usize, limit: usize },
    ScannerStepsLimit { needed: usize, limit: usize },
    RoleProbesLimit { needed: usize, limit: usize },
    BranchChecksLimit { needed: usize, limit: usize },
    RepetitionTestsLimit { needed: usize, limit: usize },
    MatchEventsLimit { needed: usize, limit: usize },
    CountLimit { needed: u64, limit: u64 },
    SpanSumLimit { needed: u64, limit: u64 },
    WorkLimit { needed: usize, limit: usize },
    ScratchLimit { needed: usize, limit: usize },
    PeakLimit { needed: usize, limit: usize },
    ArithmeticOverflow { computation: &'static str },
}

impl fmt::Display for ReduceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputBytesLimit { needed, limit } => write!(
                f,
                "grapheme scan needs {needed} input bytes, limit is {limit}"
            ),
            Self::DecodeByteChecksLimit { needed, limit } => write!(
                f,
                "grapheme scan may need {needed} decode checks, limit is {limit}"
            ),
            Self::ClassificationsLimit { needed, limit } => write!(
                f,
                "grapheme scan may need {needed} classifications, limit is {limit}"
            ),
            Self::RangeComparisonsLimit { needed, limit } => write!(
                f,
                "grapheme scan may need {needed} range comparisons, limit is {limit}"
            ),
            Self::ScannerStepsLimit { needed, limit } => write!(
                f,
                "grapheme scan may need {needed} scanner steps, limit is {limit}"
            ),
            Self::RoleProbesLimit { needed, limit } => write!(
                f,
                "grapheme scan may need {needed} role probes, limit is {limit}"
            ),
            Self::BranchChecksLimit { needed, limit } => write!(
                f,
                "grapheme scan may need {needed} branch checks, limit is {limit}"
            ),
            Self::RepetitionTestsLimit { needed, limit } => write!(
                f,
                "grapheme scan may need {needed} repetition tests, limit is {limit}"
            ),
            Self::MatchEventsLimit { needed, limit } => write!(
                f,
                "grapheme scan may emit {needed} matches, limit is {limit}"
            ),
            Self::CountLimit { needed, limit } => {
                write!(f, "grapheme count may be {needed}, limit is {limit}")
            }
            Self::SpanSumLimit { needed, limit } => {
                write!(f, "grapheme span sum may be {needed}, limit is {limit}")
            }
            Self::WorkLimit { needed, limit } => {
                write!(f, "grapheme scan may need {needed} work, limit is {limit}")
            }
            Self::ScratchLimit { needed, limit } => write!(
                f,
                "grapheme scan needs {needed} scratch bytes, limit is {limit}"
            ),
            Self::PeakLimit { needed, limit } => {
                write!(f, "grapheme scan peak is {needed} bytes, limit is {limit}")
            }
            Self::ArithmeticOverflow { computation } => {
                write!(f, "arithmetic overflow while computing {computation}")
            }
        }
    }
}

impl std::error::Error for ReduceError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Event {
    point: u32,
    role: GraphemeScalarClassRole,
    add: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RoleSegment {
    start: u32,
    end: u32,
    roles: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BuildPreflight {
    source_ranges: usize,
    events: usize,
    segment_capacity: usize,
    sort_comparisons: usize,
    allocations: usize,
    event_writes: usize,
    segment_writes: usize,
    work: usize,
    scratch_bytes: usize,
    persistent_bytes: usize,
    peak_bytes: usize,
}

impl BuildPreflight {
    fn for_range_count(source_ranges: usize) -> Result<Self, BuildError> {
        let events = checked_build_mul(source_ranges, 2, "event count")?;
        let segment_capacity = events;
        let sort_comparisons = sort_comparison_bound(events)?;
        let allocations = if events == 0 { 0 } else { BUILD_ALLOCATIONS };
        let (event_bytes, persistent_bytes, peak_bytes) =
            build_memory_bounds(events, segment_capacity)?;
        let work = prospective_build_work(
            source_ranges,
            events,
            segment_capacity,
            sort_comparisons,
            allocations,
        )?;
        Ok(Self {
            source_ranges,
            events,
            segment_capacity,
            sort_comparisons,
            allocations,
            event_writes: events,
            segment_writes: segment_capacity,
            work,
            scratch_bytes: event_bytes,
            persistent_bytes,
            peak_bytes,
        })
    }

    fn enforce(self, limits: BuildLimits) -> Result<(), BuildError> {
        enforce_build(
            self.source_ranges,
            limits.max_source_ranges,
            BuildResource::Ranges,
        )?;
        enforce_build(self.events, limits.max_events, BuildResource::Events)?;
        enforce_build(
            self.segment_capacity,
            limits.max_segments,
            BuildResource::Segments,
        )?;
        enforce_build(
            self.sort_comparisons,
            limits.max_sort_comparisons,
            BuildResource::SortComparisons,
        )?;
        enforce_build(
            self.allocations,
            limits.max_allocations,
            BuildResource::Allocations,
        )?;
        enforce_build(
            self.event_writes,
            limits.max_event_writes,
            BuildResource::EventWrites,
        )?;
        enforce_build(
            self.segment_writes,
            limits.max_segment_writes,
            BuildResource::SegmentWrites,
        )?;
        enforce_build(self.work, limits.max_build_work, BuildResource::Work)?;
        enforce_build(
            self.scratch_bytes,
            limits.max_scratch_bytes,
            BuildResource::Scratch,
        )?;
        enforce_build(
            self.persistent_bytes,
            limits.max_persistent_bytes,
            BuildResource::Persistent,
        )?;
        enforce_build(self.peak_bytes, limits.max_peak_bytes, BuildResource::Peak)
    }
}

fn build_memory_bounds(
    events: usize,
    segment_capacity: usize,
) -> Result<(usize, usize, usize), BuildError> {
    let event_bytes = checked_build_mul(events, size_of::<Event>(), "event bytes")?;
    let segment_bytes =
        checked_build_mul(segment_capacity, size_of::<RoleSegment>(), "segment bytes")?;
    let persistent_bytes = checked_build_add(
        size_of::<GraphemeScalarDfaPlan>(),
        segment_bytes,
        "persistent plan bytes",
    )?;
    let peak_bytes = checked_build_add(event_bytes, persistent_bytes, "build peak bytes")?;
    Ok((event_bytes, persistent_bytes, peak_bytes))
}

fn admitted_build_preflight(
    source_ranges: usize,
    limits: BuildLimits,
) -> Result<BuildPreflight, BuildError> {
    enforce_build(
        source_ranges,
        limits.max_source_ranges,
        BuildResource::Ranges,
    )?;
    let preflight = BuildPreflight::for_range_count(source_ranges)?;
    preflight.enforce(limits)?;
    Ok(preflight)
}

#[derive(Debug)]
struct BuildTransaction {
    events: ExactVec<Event>,
    segments: ExactVec<RoleSegment>,
    preflight: BuildPreflight,
    sort_comparisons: usize,
}

impl BuildTransaction {
    fn allocate(preflight: BuildPreflight) -> Result<Self, BuildError> {
        let events = ExactVec::try_with_capacity(preflight.events)
            .map_err(|error| map_exact_allocation(error, preflight.events))?;
        let segments = ExactVec::try_with_capacity(preflight.segment_capacity)
            .map_err(|error| map_exact_allocation(error, preflight.segment_capacity))?;
        Ok(Self {
            events,
            segments,
            preflight,
            sort_comparisons: 0,
        })
    }

    fn populate_checked(
        &mut self,
        ranges: impl IntoIterator<Item = (GraphemeScalarClassRole, char, char)>,
    ) -> Result<(), BuildError> {
        let mut previous = [None::<u32>; ROLE_COUNT];
        let mut seen = [false; ROLE_COUNT];
        let mut source_ranges = 0_usize;
        for (role, start, end) in ranges {
            if start > end {
                return Err(BuildError::ReversedRange { role, start, end });
            }
            let start_u32 = u32::from(start);
            let end_u32 = u32::from(end);
            if previous[role.index()].is_some_and(|prior| start_u32 <= prior.saturating_add(1)) {
                return Err(BuildError::NonCanonicalRanges { role });
            }
            previous[role.index()] = Some(end_u32);
            seen[role.index()] = true;
            source_ranges = checked_build_add(source_ranges, 1, "source range count")?;
            self.events
                .try_push(Event {
                    point: start_u32,
                    role,
                    add: true,
                })
                .map_err(|_| BuildError::ArithmeticOverflow {
                    computation: "preflight event capacity",
                })?;
            self.events
                .try_push(Event {
                    point: end_u32
                        .checked_add(1)
                        .ok_or(BuildError::ArithmeticOverflow {
                            computation: "range end event",
                        })?,
                    role,
                    add: false,
                })
                .map_err(|_| BuildError::ArithmeticOverflow {
                    computation: "preflight event capacity",
                })?;
        }
        if source_ranges != self.preflight.source_ranges {
            return Err(BuildError::ArithmeticOverflow {
                computation: "preflight source range count",
            });
        }
        for (index, role_seen) in seen.into_iter().enumerate() {
            if !role_seen {
                return Err(BuildError::MissingRole {
                    role: role_from_index(index),
                });
            }
        }
        Ok(())
    }

    fn sort(&mut self) -> Result<(), BuildError> {
        self.sort_comparisons = sort_events(self.events.as_mut_slice())?;
        if self.sort_comparisons > self.preflight.sort_comparisons {
            return Err(BuildError::ArithmeticOverflow {
                computation: "sort comparison proof",
            });
        }
        Ok(())
    }

    fn sweep(&mut self) -> Result<(), BuildError> {
        let mut active = 0_u32;
        let mut cursor = 0_u32;
        let mut event_index = 0_usize;
        while event_index < self.events.len() {
            let point = self.events[event_index].point;
            if cursor < point && active != 0 {
                push_segment(
                    &mut self.segments,
                    RoleSegment {
                        start: cursor,
                        end: point.checked_sub(1).ok_or(BuildError::ArithmeticOverflow {
                            computation: "segment end",
                        })?,
                        roles: active,
                    },
                )?;
            }
            while event_index < self.events.len() && self.events[event_index].point == point {
                let event = self.events[event_index];
                if event.add {
                    active |= event.role.bit();
                } else {
                    active &= !event.role.bit();
                }
                event_index = event_index
                    .checked_add(1)
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "event cursor",
                    })?;
            }
            cursor = point;
        }
        if cursor < AFTER_MAX_SCALAR && active != 0 {
            push_segment(
                &mut self.segments,
                RoleSegment {
                    start: cursor,
                    end: MAX_SCALAR,
                    roles: active,
                },
            )?;
        }
        validate_semantics(&self.segments)
    }

    fn accounting(&self) -> Result<BuildAccounting, BuildError> {
        let actual_work = prospective_build_work(
            self.preflight.source_ranges,
            self.preflight.events,
            self.segments.len(),
            self.sort_comparisons,
            self.preflight.allocations,
        )?;
        if actual_work > self.preflight.work {
            return Err(BuildError::ArithmeticOverflow {
                computation: "actual build work proof",
            });
        }
        Ok(BuildAccounting {
            source_ranges: self.preflight.source_ranges,
            events: self.events.len(),
            event_capacity: self.events.capacity(),
            segment_capacity: self.segments.capacity(),
            retained_segments: self.segments.len(),
            sort_comparisons_upper: self.preflight.sort_comparisons,
            sort_comparisons_actual: self.sort_comparisons,
            allocations: self.preflight.allocations,
            event_writes: self.preflight.event_writes,
            segment_writes: self.segments.len(),
            copy_bytes: 0,
            binary_search_comparisons_per_scalar: binary_search_comparison_bound(
                self.segments.len(),
            ),
            work: self.preflight.work,
            actual_work,
            scratch_bytes: self.preflight.scratch_bytes,
            persistent_bytes: self.preflight.persistent_bytes,
            peak_bytes: self.preflight.peak_bytes,
        })
    }
}

fn prospective_build_work(
    source_ranges: usize,
    events: usize,
    segment_writes: usize,
    sort_comparisons: usize,
    allocations: usize,
) -> Result<usize, BuildError> {
    let terms = [
        checked_build_mul(
            source_ranges,
            RANGE_VALIDATION_WORK,
            "range validation work",
        )?,
        checked_build_mul(events, EVENT_WRITE_WORK, "event write work")?,
        checked_build_mul(
            sort_comparisons,
            SORT_COMPARISON_WORK,
            "sort comparison work",
        )?,
        checked_build_mul(events, SORT_EVENT_OVERHEAD_WORK, "sort overhead work")?,
        checked_build_mul(events, SWEEP_EVENT_WORK, "event sweep work")?,
        checked_build_mul(segment_writes, SEGMENT_WRITE_WORK, "segment write work")?,
        checked_build_mul(segment_writes, SEMANTIC_SEGMENT_WORK, "semantic proof work")?,
        checked_build_mul(allocations, ALLOCATION_WORK, "allocation work")?,
    ];
    let mut work = BUILD_FIXED_WORK;
    for term in terms {
        work = checked_build_add(work, term, "build work")?;
    }
    Ok(work)
}

fn sort_comparison_bound(events: usize) -> Result<usize, BuildError> {
    if events < 2 {
        return Ok(0);
    }
    let mut width = events
        .checked_sub(1)
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "sort logarithm",
        })?;
    let mut levels = 0_usize;
    while width != 0 {
        levels = checked_build_add(levels, 1, "sort logarithm")?;
        width /= 2;
    }
    let levels = checked_build_add(levels, 1, "sort comparison bound")?;
    checked_build_mul(
        checked_build_mul(events, 4, "sort comparison bound")?,
        levels,
        "sort comparison bound",
    )
}

fn sort_events(events: &mut [Event]) -> Result<usize, BuildError> {
    let mut comparisons = 0_usize;
    let mut start = events.len() / 2;
    while start != 0 {
        start = start.checked_sub(1).ok_or(BuildError::ArithmeticOverflow {
            computation: "heap start",
        })?;
        sift_events(events, start, events.len(), &mut comparisons)?;
    }
    let mut end = events.len();
    while end > 1 {
        end = end.checked_sub(1).ok_or(BuildError::ArithmeticOverflow {
            computation: "heap end",
        })?;
        events.swap(0, end);
        sift_events(events, 0, end, &mut comparisons)?;
    }
    Ok(comparisons)
}

fn sift_events(
    events: &mut [Event],
    mut root: usize,
    end: usize,
    comparisons: &mut usize,
) -> Result<(), BuildError> {
    loop {
        let left = root
            .checked_mul(2)
            .and_then(|value| value.checked_add(1))
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "heap child",
            })?;
        if left >= end {
            return Ok(());
        }
        let right = checked_build_add(left, 1, "heap sibling")?;
        let mut child = left;
        if right < end && event_less(events[child], events[right], comparisons)? {
            child = right;
        }
        if !event_less(events[root], events[child], comparisons)? {
            return Ok(());
        }
        events.swap(root, child);
        root = child;
    }
}

fn event_less(left: Event, right: Event, comparisons: &mut usize) -> Result<bool, BuildError> {
    *comparisons = checked_build_add(*comparisons, 1, "sort comparisons")?;
    Ok(left.point < right.point || (left.point == right.point && !left.add && right.add))
}

/// Owned, non-`Clone` plan for the exact grapheme scalar machine.
#[derive(Debug)]
pub struct GraphemeScalarDfaPlan {
    segments: ExactVec<RoleSegment>,
    build: BuildAccounting,
}

impl GraphemeScalarDfaPlan {
    /// Overlay canonical inclusive ranges for all exact class roles.
    pub fn build(
        ranges: &[(GraphemeScalarClassRole, char, char)],
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        Self::build_from_counted_iter(ranges.len(), ranges.iter().copied(), limits)
    }

    /// Overlay a prospectively counted canonical range stream without
    /// materializing a second facade-owned range collection. A stream whose
    /// actual length differs from `source_ranges` fails before publication.
    pub fn build_from_counted_iter(
        source_ranges: usize,
        ranges: impl IntoIterator<Item = (GraphemeScalarClassRole, char, char)>,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        let preflight = admitted_build_preflight(source_ranges, limits)?;
        let mut transaction = BuildTransaction::allocate(preflight)?;
        transaction.populate_checked(ranges)?;
        transaction.sort()?;
        transaction.sweep()?;
        let build = transaction.accounting()?;
        Ok(Self {
            segments: transaction.segments,
            build,
        })
    }

    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.build
    }

    #[must_use]
    pub const fn count_identity(&self) -> OperationIdentity {
        OperationIdentity::for_operation(Operation::Count)
    }

    #[must_use]
    pub const fn span_sum_identity(&self) -> OperationIdentity {
        OperationIdentity::for_operation(Operation::SpanSum)
    }

    pub fn count(&self, haystack: &[u8], limits: ReduceLimits) -> Result<CountResult, ReduceError> {
        let upper_bounds = self.preflight(haystack.len(), Operation::Count, limits)?;
        let actual = self.execute(haystack)?;
        reconcile_actual(actual, upper_bounds)?;
        Ok(CountResult {
            count: actual.count,
            accounting: ReduceAccounting {
                identity: self.count_identity(),
                upper_bounds,
                actual,
            },
        })
    }

    pub fn span_sum(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<SpanSumResult, ReduceError> {
        let upper_bounds = self.preflight(haystack.len(), Operation::SpanSum, limits)?;
        let actual = self.execute(haystack)?;
        reconcile_actual(actual, upper_bounds)?;
        Ok(SpanSumResult {
            span_sum: actual.matched_bytes,
            accounting: ReduceAccounting {
                identity: self.span_sum_identity(),
                upper_bounds,
                actual,
            },
        })
    }

    fn preflight(
        &self,
        input_bytes: usize,
        operation: Operation,
        limits: ReduceLimits,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        enforce_reduce(
            input_bytes,
            limits.max_input_bytes,
            ReduceResource::InputBytes,
        )?;
        let upper = reduce_upper_bounds(input_bytes, self.build)?;
        enforce_upper_bounds(upper, operation, limits)?;
        Ok(upper)
    }

    fn execute(&self, haystack: &[u8]) -> Result<ReduceActualCounters, ReduceError> {
        let mut cursor = ScalarCursor {
            plan: self,
            haystack,
            offset: 0,
            lookahead: None,
            actual: ReduceActualCounters {
                scratch_bytes: EXECUTION_SCRATCH_BYTES,
                ..ReduceActualCounters::default()
            },
        };
        loop {
            cursor.repetition_test()?;
            let token = cursor.peek()?;
            cursor.branch_check()?;
            let Some(token) = token else {
                break;
            };
            cursor.branch_check()?;
            if token.scalar.is_none() {
                cursor.take()?.ok_or(ReduceError::ArithmeticOverflow {
                    computation: "invalid-byte lookahead",
                })?;
                continue;
            }
            let matched_bytes = match_one(&mut cursor)?;
            cursor.actual.match_events =
                checked_reduce_add(cursor.actual.match_events, 1, "match events")?;
            cursor.actual.count =
                cursor
                    .actual
                    .count
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "match count",
                    })?;
            cursor.actual.matched_bytes = cursor
                .actual
                .matched_bytes
                .checked_add(matched_bytes)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "matched bytes",
                })?;
        }
        cursor.actual.scanner_steps =
            checked_reduce_add(cursor.actual.scanner_steps, 1, "terminal scanner step")?;
        cursor.actual.work = cursor
            .actual
            .decode_byte_checks
            .checked_add(cursor.actual.classifications)
            .and_then(|value| value.checked_add(cursor.actual.range_comparisons))
            .and_then(|value| value.checked_add(cursor.actual.scanner_steps))
            .and_then(|value| {
                cursor
                    .actual
                    .role_probes
                    .checked_mul(ROLE_PROBE_WORK)
                    .and_then(|term| value.checked_add(term))
            })
            .and_then(|value| value.checked_add(cursor.actual.branch_checks))
            .and_then(|value| value.checked_add(cursor.actual.repetition_tests))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual execution work",
            })?;
        Ok(cursor.actual)
    }

    fn classify(&self, scalar: u32) -> Result<(u32, usize), ReduceError> {
        let mut low = 0_usize;
        let mut high = self.segments.len();
        let mut comparisons = 0_usize;
        while low < high {
            comparisons = checked_reduce_add(comparisons, 1, "binary search comparisons")?;
            let width = high
                .checked_sub(low)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "binary search width",
                })?;
            let middle = low
                .checked_add(width / 2)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "binary search midpoint",
                })?;
            let segment = self
                .segments
                .get(middle)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "segment access",
                })?;
            if scalar < segment.start {
                high = middle;
            } else if scalar > segment.end {
                low = middle
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "binary search successor",
                    })?;
            } else {
                return Ok((segment.roles, comparisons));
            }
        }
        Err(ReduceError::ArithmeticOverflow {
            computation: "proved Any classification coverage",
        })
    }
}

fn reduce_upper_bounds(
    input_bytes: usize,
    build: BuildAccounting,
) -> Result<ReduceUpperBounds, ReduceError> {
    let decode_byte_checks = input_bytes
        .checked_mul(4)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "decode check upper bound",
        })?;
    let classifications = input_bytes;
    let comparisons_per_scalar = build.binary_search_comparisons_per_scalar;
    let range_comparisons = classifications.checked_mul(comparisons_per_scalar).ok_or(
        ReduceError::ArithmeticOverflow {
            computation: "comparison upper bound",
        },
    )?;
    let scanner_steps = input_bytes
        .checked_add(1)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "scanner step upper bound",
        })?;
    let role_probes = input_bytes.checked_mul(ROLE_PROBES_PER_INPUT_BYTE).ok_or(
        ReduceError::ArithmeticOverflow {
            computation: "role probe upper bound",
        },
    )?;
    let branch_checks = input_bytes
        .checked_mul(BRANCH_CHECKS_PER_INPUT_BYTE)
        .and_then(|value| value.checked_add(EXECUTION_TERMINAL_CHECKS))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "branch check upper bound",
        })?;
    let repetition_tests = input_bytes
        .checked_mul(REPETITION_TESTS_PER_INPUT_BYTE)
        .and_then(|value| value.checked_add(EXECUTION_TERMINAL_CHECKS))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "repetition test upper bound",
        })?;
    let role_probe_work = checked_reduce_mul(role_probes, ROLE_PROBE_WORK, "role probe work")?;
    let count = u64::try_from(input_bytes).map_err(|_| ReduceError::ArithmeticOverflow {
        computation: "count upper bound",
    })?;
    let work = decode_byte_checks
        .checked_add(classifications)
        .and_then(|value| value.checked_add(range_comparisons))
        .and_then(|value| value.checked_add(scanner_steps))
        .and_then(|value| value.checked_add(role_probe_work))
        .and_then(|value| value.checked_add(branch_checks))
        .and_then(|value| value.checked_add(repetition_tests))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "execution work upper bound",
        })?;
    Ok(ReduceUpperBounds {
        input_bytes,
        decode_byte_checks,
        valid_scalars: input_bytes,
        invalid_bytes: input_bytes,
        classifications,
        range_comparisons,
        binary_search_comparisons_per_scalar: comparisons_per_scalar,
        scanner_steps,
        role_probes,
        branch_checks,
        repetition_tests,
        match_events: input_bytes,
        count,
        span_sum: count,
        work,
        scratch_bytes: EXECUTION_SCRATCH_BYTES,
        persistent_bytes: build.persistent_bytes,
        peak_bytes: build
            .persistent_bytes
            .checked_add(EXECUTION_SCRATCH_BYTES)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "execution peak bytes",
            })?,
    })
}

fn enforce_upper_bounds(
    upper: ReduceUpperBounds,
    operation: Operation,
    limits: ReduceLimits,
) -> Result<(), ReduceError> {
    enforce_reduce(
        upper.input_bytes,
        limits.max_input_bytes,
        ReduceResource::InputBytes,
    )?;
    enforce_reduce(
        upper.decode_byte_checks,
        limits.max_decode_byte_checks,
        ReduceResource::DecodeChecks,
    )?;
    enforce_reduce(
        upper.classifications,
        limits.max_classifications,
        ReduceResource::Classifications,
    )?;
    enforce_reduce(
        upper.range_comparisons,
        limits.max_range_comparisons,
        ReduceResource::RangeComparisons,
    )?;
    enforce_reduce(
        upper.scanner_steps,
        limits.max_scanner_steps,
        ReduceResource::ScannerSteps,
    )?;
    enforce_reduce(
        upper.role_probes,
        limits.max_role_probes,
        ReduceResource::RoleProbes,
    )?;
    enforce_reduce(
        upper.branch_checks,
        limits.max_branch_checks,
        ReduceResource::BranchChecks,
    )?;
    enforce_reduce(
        upper.repetition_tests,
        limits.max_repetition_tests,
        ReduceResource::RepetitionTests,
    )?;
    enforce_reduce(
        upper.match_events,
        limits.max_match_events,
        ReduceResource::MatchEvents,
    )?;
    if upper.count > limits.max_count {
        return Err(ReduceError::CountLimit {
            needed: upper.count,
            limit: limits.max_count,
        });
    }
    if operation == Operation::SpanSum && upper.span_sum > limits.max_span_sum {
        return Err(ReduceError::SpanSumLimit {
            needed: upper.span_sum,
            limit: limits.max_span_sum,
        });
    }
    enforce_reduce(upper.work, limits.max_work, ReduceResource::Work)?;
    enforce_reduce(
        upper.scratch_bytes,
        limits.max_scratch_bytes,
        ReduceResource::Scratch,
    )?;
    enforce_reduce(
        upper.peak_bytes,
        limits.max_peak_bytes,
        ReduceResource::Peak,
    )
}

fn reconcile_actual(
    actual: ReduceActualCounters,
    upper: ReduceUpperBounds,
) -> Result<(), ReduceError> {
    let within = actual.input_bytes_advanced <= upper.input_bytes
        && actual.decode_byte_checks <= upper.decode_byte_checks
        && actual.valid_scalars <= upper.valid_scalars
        && actual.invalid_bytes <= upper.invalid_bytes
        && actual.classifications <= upper.classifications
        && actual.range_comparisons <= upper.range_comparisons
        && actual.scanner_steps <= upper.scanner_steps
        && actual.role_probes <= upper.role_probes
        && actual.branch_checks <= upper.branch_checks
        && actual.repetition_tests <= upper.repetition_tests
        && actual.match_events <= upper.match_events
        && actual.count <= upper.count
        && actual.matched_bytes <= upper.span_sum
        && actual.work <= upper.work
        && actual.scratch_bytes <= upper.scratch_bytes;
    let classified_inputs = actual
        .valid_scalars
        .checked_add(actual.invalid_bytes)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "actual classified input count",
        })?;
    if within && classified_inputs <= actual.input_bytes_advanced {
        Ok(())
    } else {
        Err(ReduceError::ArithmeticOverflow {
            computation: "actual counters exceeded prospective bounds",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Token {
    scalar: Option<u32>,
    width: usize,
    roles: u32,
}

#[derive(Debug)]
struct ScalarCursor<'a> {
    plan: &'a GraphemeScalarDfaPlan,
    haystack: &'a [u8],
    offset: usize,
    lookahead: Option<Token>,
    actual: ReduceActualCounters,
}

impl ScalarCursor<'_> {
    fn peek(&mut self) -> Result<Option<Token>, ReduceError> {
        if self.lookahead.is_none() && self.offset < self.haystack.len() {
            let decoded = decode_scalar(&self.haystack[self.offset..]);
            self.offset = checked_reduce_add(self.offset, decoded.width, "input cursor")?;
            self.actual.input_bytes_advanced = checked_reduce_add(
                self.actual.input_bytes_advanced,
                decoded.width,
                "input bytes advanced",
            )?;
            self.actual.decode_byte_checks = checked_reduce_add(
                self.actual.decode_byte_checks,
                decoded.byte_checks,
                "decode byte checks",
            )?;
            let roles = if let Some(scalar) = decoded.scalar {
                let (roles, comparisons) = self.plan.classify(scalar)?;
                self.actual.valid_scalars =
                    checked_reduce_add(self.actual.valid_scalars, 1, "valid scalars")?;
                self.actual.classifications =
                    checked_reduce_add(self.actual.classifications, 1, "classifications")?;
                self.actual.range_comparisons = checked_reduce_add(
                    self.actual.range_comparisons,
                    comparisons,
                    "range comparisons",
                )?;
                roles
            } else {
                self.actual.invalid_bytes =
                    checked_reduce_add(self.actual.invalid_bytes, 1, "invalid bytes")?;
                0
            };
            self.lookahead = Some(Token {
                scalar: decoded.scalar,
                width: decoded.width,
                roles,
            });
        }
        Ok(self.lookahead)
    }

    fn take(&mut self) -> Result<Option<Token>, ReduceError> {
        let token = self.peek()?;
        if token.is_some() {
            self.lookahead = None;
            self.actual.scanner_steps =
                checked_reduce_add(self.actual.scanner_steps, 1, "scanner steps")?;
        }
        Ok(token)
    }

    fn has(&mut self, role: GraphemeScalarClassRole) -> Result<bool, ReduceError> {
        self.actual.role_probes = checked_reduce_add(self.actual.role_probes, 1, "role probes")?;
        self.branch_check()?;
        Ok(self
            .peek()?
            .is_some_and(|token| token.roles & role.bit() != 0))
    }

    fn branch_check(&mut self) -> Result<(), ReduceError> {
        self.actual.branch_checks =
            checked_reduce_add(self.actual.branch_checks, 1, "branch checks")?;
        Ok(())
    }

    fn repetition_test(&mut self) -> Result<(), ReduceError> {
        self.actual.repetition_tests =
            checked_reduce_add(self.actual.repetition_tests, 1, "repetition tests")?;
        Ok(())
    }

    fn consume(&mut self) -> Result<u64, ReduceError> {
        let token = self.take()?.ok_or(ReduceError::ArithmeticOverflow {
            computation: "required token",
        })?;
        u64::try_from(token.width).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "token byte width",
        })
    }
}

fn match_one(cursor: &mut ScalarCursor<'_>) -> Result<u64, ReduceError> {
    if cursor.has(GraphemeScalarClassRole::Cr)? {
        let mut bytes = cursor.consume()?;
        if cursor.has(GraphemeScalarClassRole::Lf)? {
            bytes = checked_u64_add(bytes, cursor.consume()?, "CRLF match bytes")?;
        }
        return Ok(bytes);
    }
    if cursor.has(GraphemeScalarClassRole::Control)? {
        return cursor.consume();
    }

    let mut bytes = consume_while(cursor, GraphemeScalarClassRole::Prepend)?;
    if cursor.has(GraphemeScalarClassRole::GenericCore)? {
        bytes = checked_u64_add(bytes, consume_core(cursor)?, "core bytes")?;
        bytes = checked_u64_add(
            bytes,
            consume_while(cursor, GraphemeScalarClassRole::Tail)?,
            "tail bytes",
        )?;
        return Ok(bytes);
    }
    cursor.branch_check()?;
    if bytes != 0 {
        // Greedy `Prepend*` backs off once so its last scalar is the generic
        // core. The byte extent remains the whole already-consumed run.
        return Ok(bytes);
    }
    cursor.consume()
}

fn consume_core(cursor: &mut ScalarCursor<'_>) -> Result<u64, ReduceError> {
    if cursor.has(GraphemeScalarClassRole::L)? {
        let mut bytes = consume_while(cursor, GraphemeScalarClassRole::L)?;
        if cursor.has(GraphemeScalarClassRole::V)? {
            bytes = checked_u64_add(
                bytes,
                consume_while(cursor, GraphemeScalarClassRole::V)?,
                "Hangul V bytes",
            )?;
            return consume_hangul_tail(cursor, bytes);
        }
        if cursor.has(GraphemeScalarClassRole::Lv)? {
            bytes = checked_u64_add(bytes, cursor.consume()?, "Hangul LV bytes")?;
            bytes = checked_u64_add(
                bytes,
                consume_while(cursor, GraphemeScalarClassRole::V)?,
                "Hangul V bytes",
            )?;
            return consume_hangul_tail(cursor, bytes);
        }
        if cursor.has(GraphemeScalarClassRole::Lvt)? {
            bytes = checked_u64_add(bytes, cursor.consume()?, "Hangul LVT bytes")?;
            return consume_hangul_tail(cursor, bytes);
        }
        return Ok(bytes);
    }
    if cursor.has(GraphemeScalarClassRole::V)? {
        let bytes = consume_while(cursor, GraphemeScalarClassRole::V)?;
        return consume_hangul_tail(cursor, bytes);
    }
    if cursor.has(GraphemeScalarClassRole::Lv)? {
        let mut bytes = cursor.consume()?;
        bytes = checked_u64_add(
            bytes,
            consume_while(cursor, GraphemeScalarClassRole::V)?,
            "Hangul V bytes",
        )?;
        return consume_hangul_tail(cursor, bytes);
    }
    if cursor.has(GraphemeScalarClassRole::Lvt)? {
        let bytes = cursor.consume()?;
        return consume_hangul_tail(cursor, bytes);
    }
    if cursor.has(GraphemeScalarClassRole::T)? {
        return consume_while(cursor, GraphemeScalarClassRole::T);
    }
    if cursor.has(GraphemeScalarClassRole::Ri)? {
        let mut bytes = cursor.consume()?;
        if cursor.has(GraphemeScalarClassRole::Ri)? {
            bytes = checked_u64_add(bytes, cursor.consume()?, "regional-indicator pair bytes")?;
        }
        return Ok(bytes);
    }
    if cursor.has(GraphemeScalarClassRole::ExtendedPictographic)? {
        return consume_extended_pictographic(cursor);
    }
    cursor.consume()
}

fn consume_hangul_tail(cursor: &mut ScalarCursor<'_>, bytes: u64) -> Result<u64, ReduceError> {
    checked_u64_add(
        bytes,
        consume_while(cursor, GraphemeScalarClassRole::T)?,
        "Hangul T bytes",
    )
}

fn consume_extended_pictographic(cursor: &mut ScalarCursor<'_>) -> Result<u64, ReduceError> {
    let mut bytes = cursor.consume()?;
    loop {
        cursor.repetition_test()?;
        bytes = checked_u64_add(
            bytes,
            consume_while(cursor, GraphemeScalarClassRole::Extend)?,
            "pictographic Extend bytes",
        )?;
        if !cursor.has(GraphemeScalarClassRole::Zwj)? {
            return Ok(bytes);
        }
        bytes = checked_u64_add(bytes, cursor.consume()?, "pictographic ZWJ bytes")?;
        if !cursor.has(GraphemeScalarClassRole::ExtendedPictographic)? {
            return Ok(bytes);
        }
        bytes = checked_u64_add(bytes, cursor.consume()?, "pictographic bridge bytes")?;
    }
}

fn consume_while(
    cursor: &mut ScalarCursor<'_>,
    role: GraphemeScalarClassRole,
) -> Result<u64, ReduceError> {
    let mut bytes = 0_u64;
    loop {
        cursor.repetition_test()?;
        if !cursor.has(role)? {
            break;
        }
        bytes = checked_u64_add(bytes, cursor.consume()?, "repetition bytes")?;
    }
    Ok(bytes)
}

fn validate_semantics(segments: &[RoleSegment]) -> Result<(), BuildError> {
    let mut cursor = 0_u32;
    for segment in segments {
        if cursor < segment.start
            && interval_has_scalar(
                cursor,
                segment
                    .start
                    .checked_sub(1)
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "semantic proof gap end",
                    })?,
            )
        {
            return Err(BuildError::DerivedClassMismatch {
                role: GraphemeScalarClassRole::Any,
            });
        }
        if interval_has_scalar(segment.start, segment.end) {
            validate_mask(segment.roles)?;
        }
        cursor = segment
            .end
            .checked_add(1)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "semantic proof cursor",
            })?;
    }
    if cursor <= MAX_SCALAR && interval_has_scalar(cursor, MAX_SCALAR) {
        return Err(BuildError::DerivedClassMismatch {
            role: GraphemeScalarClassRole::Any,
        });
    }
    Ok(())
}

fn validate_mask(mask: u32) -> Result<(), BuildError> {
    if mask & GraphemeScalarClassRole::Any.bit() == 0 {
        return Err(BuildError::DerivedClassMismatch {
            role: GraphemeScalarClassRole::Any,
        });
    }
    let gcb = mask & GCB_MASK;
    if gcb.count_ones() > 1
        || (gcb != 0 && mask & GraphemeScalarClassRole::ExtendedPictographic.bit() != 0)
    {
        return Err(BuildError::OverlappingProperties);
    }
    let expected_generic = mask
        & (GraphemeScalarClassRole::Control.bit()
            | GraphemeScalarClassRole::Cr.bit()
            | GraphemeScalarClassRole::Lf.bit())
        == 0;
    if (mask & GraphemeScalarClassRole::GenericCore.bit() != 0) != expected_generic {
        return Err(BuildError::DerivedClassMismatch {
            role: GraphemeScalarClassRole::GenericCore,
        });
    }
    let expected_tail = mask
        & (GraphemeScalarClassRole::Extend.bit()
            | GraphemeScalarClassRole::Zwj.bit()
            | GraphemeScalarClassRole::SpacingMark.bit())
        != 0;
    if (mask & GraphemeScalarClassRole::Tail.bit() != 0) != expected_tail {
        return Err(BuildError::DerivedClassMismatch {
            role: GraphemeScalarClassRole::Tail,
        });
    }
    Ok(())
}

const fn interval_has_scalar(start: u32, end: u32) -> bool {
    start <= end && !(start >= SURROGATE_START && end <= SURROGATE_END)
}

fn push_segment(
    segments: &mut ExactVec<RoleSegment>,
    segment: RoleSegment,
) -> Result<(), BuildError> {
    segments
        .try_push(segment)
        .map_err(|_| BuildError::ArithmeticOverflow {
            computation: "preflight segment capacity",
        })
}

const fn map_exact_allocation(error: CopyError, additional: usize) -> BuildError {
    match error {
        CopyError::LayoutOverflow => BuildError::ArithmeticOverflow {
            computation: "exact typed allocation layout",
        },
        CopyError::AllocationFailed => BuildError::AllocationFailed { additional },
    }
}

const fn role_from_index(index: usize) -> GraphemeScalarClassRole {
    match index {
        0 => GraphemeScalarClassRole::Cr,
        1 => GraphemeScalarClassRole::Lf,
        2 => GraphemeScalarClassRole::Control,
        3 => GraphemeScalarClassRole::Prepend,
        4 => GraphemeScalarClassRole::L,
        5 => GraphemeScalarClassRole::V,
        6 => GraphemeScalarClassRole::Lv,
        7 => GraphemeScalarClassRole::Lvt,
        8 => GraphemeScalarClassRole::T,
        9 => GraphemeScalarClassRole::Ri,
        10 => GraphemeScalarClassRole::Extend,
        11 => GraphemeScalarClassRole::Zwj,
        12 => GraphemeScalarClassRole::SpacingMark,
        13 => GraphemeScalarClassRole::ExtendedPictographic,
        14 => GraphemeScalarClassRole::GenericCore,
        15 => GraphemeScalarClassRole::Tail,
        _ => GraphemeScalarClassRole::Any,
    }
}

#[derive(Clone, Copy)]
enum BuildResource {
    Ranges,
    Events,
    Segments,
    SortComparisons,
    Allocations,
    EventWrites,
    SegmentWrites,
    Work,
    Scratch,
    Persistent,
    Peak,
}

fn enforce_build(needed: usize, limit: usize, resource: BuildResource) -> Result<(), BuildError> {
    if needed <= limit {
        return Ok(());
    }
    Err(match resource {
        BuildResource::Ranges => BuildError::RangeLimit { needed, limit },
        BuildResource::Events => BuildError::EventLimit { needed, limit },
        BuildResource::Segments => BuildError::SegmentLimit { needed, limit },
        BuildResource::SortComparisons => BuildError::SortComparisonsLimit { needed, limit },
        BuildResource::Allocations => BuildError::AllocationLimit { needed, limit },
        BuildResource::EventWrites => BuildError::EventWritesLimit { needed, limit },
        BuildResource::SegmentWrites => BuildError::SegmentWritesLimit { needed, limit },
        BuildResource::Work => BuildError::WorkLimit { needed, limit },
        BuildResource::Scratch => BuildError::ScratchLimit { needed, limit },
        BuildResource::Persistent => BuildError::PersistentLimit { needed, limit },
        BuildResource::Peak => BuildError::PeakLimit { needed, limit },
    })
}

#[derive(Clone, Copy)]
enum ReduceResource {
    InputBytes,
    DecodeChecks,
    Classifications,
    RangeComparisons,
    ScannerSteps,
    RoleProbes,
    BranchChecks,
    RepetitionTests,
    MatchEvents,
    Work,
    Scratch,
    Peak,
}

fn enforce_reduce(
    needed: usize,
    limit: usize,
    resource: ReduceResource,
) -> Result<(), ReduceError> {
    if needed <= limit {
        return Ok(());
    }
    Err(match resource {
        ReduceResource::InputBytes => ReduceError::InputBytesLimit { needed, limit },
        ReduceResource::DecodeChecks => ReduceError::DecodeByteChecksLimit { needed, limit },
        ReduceResource::Classifications => ReduceError::ClassificationsLimit { needed, limit },
        ReduceResource::RangeComparisons => ReduceError::RangeComparisonsLimit { needed, limit },
        ReduceResource::ScannerSteps => ReduceError::ScannerStepsLimit { needed, limit },
        ReduceResource::RoleProbes => ReduceError::RoleProbesLimit { needed, limit },
        ReduceResource::BranchChecks => ReduceError::BranchChecksLimit { needed, limit },
        ReduceResource::RepetitionTests => ReduceError::RepetitionTestsLimit { needed, limit },
        ReduceResource::MatchEvents => ReduceError::MatchEventsLimit { needed, limit },
        ReduceResource::Work => ReduceError::WorkLimit { needed, limit },
        ReduceResource::Scratch => ReduceError::ScratchLimit { needed, limit },
        ReduceResource::Peak => ReduceError::PeakLimit { needed, limit },
    })
}

fn checked_build_add(
    left: usize,
    right: usize,
    computation: &'static str,
) -> Result<usize, BuildError> {
    left.checked_add(right)
        .ok_or(BuildError::ArithmeticOverflow { computation })
}

fn checked_build_mul(
    left: usize,
    right: usize,
    computation: &'static str,
) -> Result<usize, BuildError> {
    left.checked_mul(right)
        .ok_or(BuildError::ArithmeticOverflow { computation })
}

fn checked_reduce_add(
    left: usize,
    right: usize,
    computation: &'static str,
) -> Result<usize, ReduceError> {
    left.checked_add(right)
        .ok_or(ReduceError::ArithmeticOverflow { computation })
}

fn checked_reduce_mul(
    left: usize,
    right: usize,
    computation: &'static str,
) -> Result<usize, ReduceError> {
    left.checked_mul(right)
        .ok_or(ReduceError::ArithmeticOverflow { computation })
}

fn checked_u64_add(left: u64, right: u64, computation: &'static str) -> Result<u64, ReduceError> {
    left.checked_add(right)
        .ok_or(ReduceError::ArithmeticOverflow { computation })
}

const fn binary_search_comparison_bound(mut segments: usize) -> usize {
    let mut comparisons = 0_usize;
    while segments != 0 {
        comparisons = comparisons.saturating_add(1);
        segments /= 2;
    }
    comparisons
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DecodedScalar {
    scalar: Option<u32>,
    width: usize,
    byte_checks: usize,
}

fn decode_scalar(bytes: &[u8]) -> DecodedScalar {
    let Some(&first) = bytes.first() else {
        return invalid(0);
    };
    if first <= 0x7F {
        return DecodedScalar {
            scalar: Some(u32::from(first)),
            width: 1,
            byte_checks: 1,
        };
    }
    if (0xC2..=0xDF).contains(&first) {
        let Some(&second) = bytes.get(1) else {
            return invalid(bytes.len().min(2));
        };
        if !is_continuation(second) {
            return invalid(2);
        }
        return DecodedScalar {
            scalar: Some((u32::from(first & 0x1F) << 6) | u32::from(second & 0x3F)),
            width: 2,
            byte_checks: 2,
        };
    }
    if (0xE0..=0xEF).contains(&first) {
        let Some(&second) = bytes.get(1) else {
            return invalid(bytes.len().min(3));
        };
        let second_ok = match first {
            0xE0 => (0xA0..=0xBF).contains(&second),
            0xED => (0x80..=0x9F).contains(&second),
            _ => is_continuation(second),
        };
        if !second_ok {
            return invalid(2);
        }
        let Some(&third) = bytes.get(2) else {
            return invalid(bytes.len().min(3));
        };
        if !is_continuation(third) {
            return invalid(3);
        }
        return DecodedScalar {
            scalar: Some(
                (u32::from(first & 0x0F) << 12)
                    | (u32::from(second & 0x3F) << 6)
                    | u32::from(third & 0x3F),
            ),
            width: 3,
            byte_checks: 3,
        };
    }
    if (0xF0..=0xF4).contains(&first) {
        let Some(&second) = bytes.get(1) else {
            return invalid(bytes.len().min(4));
        };
        let second_ok = match first {
            0xF0 => (0x90..=0xBF).contains(&second),
            0xF4 => (0x80..=0x8F).contains(&second),
            _ => is_continuation(second),
        };
        if !second_ok {
            return invalid(2);
        }
        let Some(&third) = bytes.get(2) else {
            return invalid(bytes.len().min(4));
        };
        if !is_continuation(third) {
            return invalid(3);
        }
        let Some(&fourth) = bytes.get(3) else {
            return invalid(bytes.len().min(4));
        };
        if !is_continuation(fourth) {
            return invalid(4);
        }
        return DecodedScalar {
            scalar: Some(
                (u32::from(first & 0x07) << 18)
                    | (u32::from(second & 0x3F) << 12)
                    | (u32::from(third & 0x3F) << 6)
                    | u32::from(fourth & 0x3F),
            ),
            width: 4,
            byte_checks: 4,
        };
    }
    invalid(1)
}

const fn invalid(byte_checks: usize) -> DecodedScalar {
    DecodedScalar {
        scalar: None,
        width: 1,
        byte_checks,
    }
}

const fn is_continuation(byte: u8) -> bool {
    byte & 0xC0 == 0x80
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::{
        BuildAccounting, BuildError, BuildLimits, BuildPreflight, EXECUTION_SCRATCH_BYTES, Event,
        GraphemeScalarClassRole as Role, GraphemeScalarDfaPlan, Operation, ReduceActualCounters,
        ReduceError, ReduceLimits, ReduceUpperBounds, RoleSegment, admitted_build_preflight,
        build_memory_bounds, prospective_build_work, reconcile_actual, reduce_upper_bounds,
        sort_comparison_bound,
    };

    #[derive(Clone, Copy)]
    enum BuildGate {
        Ranges,
        Events,
        Segments,
        SortComparisons,
        Allocations,
        EventWrites,
        SegmentWrites,
        Work,
        Scratch,
        Persistent,
        Peak,
    }

    #[derive(Clone, Copy)]
    enum ReduceGate {
        Input,
        Decode,
        Classifications,
        RangeComparisons,
        ScannerSteps,
        RoleProbes,
        BranchChecks,
        RepetitionTests,
        MatchEvents,
        Count,
        SpanSum,
        Work,
        Scratch,
        Peak,
    }

    fn ranges() -> Vec<(Role, char, char)> {
        let mut ranges = vec![
            (Role::Cr, '\r', '\r'),
            (Role::Lf, '\n', '\n'),
            (Role::Control, '\0', '\0'),
            (Role::Prepend, 'p', 'p'),
            (Role::L, 'l', 'l'),
            (Role::V, 'v', 'v'),
            (Role::Lv, 'a', 'a'),
            (Role::Lvt, 'b', 'b'),
            (Role::T, 't', 't'),
            (Role::Ri, 'r', 'r'),
            (Role::Extend, 'e', 'e'),
            (Role::Zwj, 'z', 'z'),
            (Role::SpacingMark, 's', 's'),
            (Role::ExtendedPictographic, 'x', 'x'),
            (Role::Tail, 'e', 'e'),
            (Role::Tail, 's', 's'),
            (Role::Tail, 'z', 'z'),
            (Role::Any, '\0', '\u{10FFFF}'),
        ];
        ranges.extend([
            (Role::GenericCore, '\u{1}', '\t'),
            (Role::GenericCore, '\u{b}', '\u{c}'),
            (Role::GenericCore, '\u{e}', '\u{10FFFF}'),
        ]);
        ranges
    }

    fn plan() -> GraphemeScalarDfaPlan {
        let ranges = ranges();
        GraphemeScalarDfaPlan::build(&ranges, BuildLimits::unlimited()).unwrap()
    }

    fn exact_build_limits(preflight: BuildPreflight) -> BuildLimits {
        BuildLimits {
            max_source_ranges: preflight.source_ranges,
            max_events: preflight.events,
            max_segments: preflight.segment_capacity,
            max_sort_comparisons: preflight.sort_comparisons,
            max_allocations: preflight.allocations,
            max_event_writes: preflight.event_writes,
            max_segment_writes: preflight.segment_writes,
            max_build_work: preflight.work,
            max_scratch_bytes: preflight.scratch_bytes,
            max_persistent_bytes: preflight.persistent_bytes,
            max_peak_bytes: preflight.peak_bytes,
        }
    }

    fn hand_build_preflight() -> BuildPreflight {
        BuildPreflight {
            source_ranges: 21,
            events: 42,
            segment_capacity: 42,
            sort_comparisons: 1_176,
            allocations: 2,
            event_writes: 42,
            segment_writes: 42,
            work: 25_696,
            scratch_bytes: 336,
            persistent_bytes: 664,
            peak_bytes: 1_000,
        }
    }

    fn hand_reduce_upper() -> ReduceUpperBounds {
        ReduceUpperBounds {
            input_bytes: 6,
            decode_byte_checks: 24,
            valid_scalars: 6,
            invalid_bytes: 6,
            classifications: 6,
            range_comparisons: 30,
            binary_search_comparisons_per_scalar: 5,
            scanner_steps: 7,
            role_probes: 96,
            branch_checks: 145,
            repetition_tests: 49,
            match_events: 6,
            count: 6,
            span_sum: 6,
            work: 645,
            scratch_bytes: 512,
            persistent_bytes: 664,
            peak_bytes: 1_176,
        }
    }

    fn exact_reduce_limits(upper: ReduceUpperBounds) -> ReduceLimits {
        ReduceLimits {
            max_input_bytes: upper.input_bytes,
            max_decode_byte_checks: upper.decode_byte_checks,
            max_classifications: upper.classifications,
            max_range_comparisons: upper.range_comparisons,
            max_scanner_steps: upper.scanner_steps,
            max_role_probes: upper.role_probes,
            max_branch_checks: upper.branch_checks,
            max_repetition_tests: upper.repetition_tests,
            max_match_events: upper.match_events,
            max_count: upper.count,
            max_span_sum: upper.span_sum,
            max_work: upper.work,
            max_scratch_bytes: upper.scratch_bytes,
            max_peak_bytes: upper.peak_bytes,
        }
    }

    fn one_below(value: usize) -> usize {
        value.checked_sub(1).unwrap()
    }

    fn one_below_u64(value: u64) -> u64 {
        value.checked_sub(1).unwrap()
    }

    fn limits_one_below(upper: ReduceUpperBounds, gate: ReduceGate) -> ReduceLimits {
        let mut limited = exact_reduce_limits(upper);
        match gate {
            ReduceGate::Input => limited.max_input_bytes = one_below(upper.input_bytes),
            ReduceGate::Decode => {
                limited.max_decode_byte_checks = one_below(upper.decode_byte_checks);
            }
            ReduceGate::Classifications => {
                limited.max_classifications = one_below(upper.classifications);
            }
            ReduceGate::RangeComparisons => {
                limited.max_range_comparisons = one_below(upper.range_comparisons);
            }
            ReduceGate::ScannerSteps => {
                limited.max_scanner_steps = one_below(upper.scanner_steps);
            }
            ReduceGate::RoleProbes => limited.max_role_probes = one_below(upper.role_probes),
            ReduceGate::BranchChecks => {
                limited.max_branch_checks = one_below(upper.branch_checks);
            }
            ReduceGate::RepetitionTests => {
                limited.max_repetition_tests = one_below(upper.repetition_tests);
            }
            ReduceGate::MatchEvents => limited.max_match_events = one_below(upper.match_events),
            ReduceGate::Count => limited.max_count = one_below_u64(upper.count),
            ReduceGate::SpanSum => limited.max_span_sum = one_below_u64(upper.span_sum),
            ReduceGate::Work => limited.max_work = one_below(upper.work),
            ReduceGate::Scratch => limited.max_scratch_bytes = one_below(upper.scratch_bytes),
            ReduceGate::Peak => limited.max_peak_bytes = one_below(upper.peak_bytes),
        }
        limited
    }

    fn assert_actual_within(actual: ReduceActualCounters, upper: ReduceUpperBounds) {
        assert!(actual.input_bytes_advanced <= upper.input_bytes);
        assert!(actual.decode_byte_checks <= upper.decode_byte_checks);
        assert!(actual.valid_scalars <= upper.valid_scalars);
        assert!(actual.invalid_bytes <= upper.invalid_bytes);
        assert!(actual.classifications <= upper.classifications);
        assert!(actual.range_comparisons <= upper.range_comparisons);
        assert!(actual.scanner_steps <= upper.scanner_steps);
        assert!(actual.role_probes <= upper.role_probes);
        assert!(actual.branch_checks <= upper.branch_checks);
        assert!(actual.repetition_tests <= upper.repetition_tests);
        assert!(actual.match_events <= upper.match_events);
        assert!(actual.count <= upper.count);
        assert!(actual.matched_bytes <= upper.span_sum);
        assert!(actual.work <= upper.work);
        assert!(actual.scratch_bytes <= upper.scratch_bytes);
        assert!(
            actual
                .valid_scalars
                .checked_add(actual.invalid_bytes)
                .is_some_and(|classified| classified <= actual.input_bytes_advanced)
        );
    }

    fn build_gate_matches(gate: BuildGate, error: &BuildError) -> bool {
        matches!(
            (gate, error),
            (BuildGate::Ranges, BuildError::RangeLimit { .. })
                | (BuildGate::Events, BuildError::EventLimit { .. })
                | (BuildGate::Segments, BuildError::SegmentLimit { .. })
                | (
                    BuildGate::SortComparisons,
                    BuildError::SortComparisonsLimit { .. }
                )
                | (BuildGate::Allocations, BuildError::AllocationLimit { .. })
                | (BuildGate::EventWrites, BuildError::EventWritesLimit { .. })
                | (
                    BuildGate::SegmentWrites,
                    BuildError::SegmentWritesLimit { .. }
                )
                | (BuildGate::Work, BuildError::WorkLimit { .. })
                | (BuildGate::Scratch, BuildError::ScratchLimit { .. })
                | (BuildGate::Persistent, BuildError::PersistentLimit { .. })
                | (BuildGate::Peak, BuildError::PeakLimit { .. })
        )
    }

    fn reduce_gate_matches(gate: ReduceGate, error: &ReduceError) -> bool {
        matches!(
            (gate, error),
            (ReduceGate::Input, ReduceError::InputBytesLimit { .. })
                | (
                    ReduceGate::Decode,
                    ReduceError::DecodeByteChecksLimit { .. }
                )
                | (
                    ReduceGate::Classifications,
                    ReduceError::ClassificationsLimit { .. }
                )
                | (
                    ReduceGate::RangeComparisons,
                    ReduceError::RangeComparisonsLimit { .. }
                )
                | (
                    ReduceGate::ScannerSteps,
                    ReduceError::ScannerStepsLimit { .. }
                )
                | (ReduceGate::RoleProbes, ReduceError::RoleProbesLimit { .. })
                | (
                    ReduceGate::BranchChecks,
                    ReduceError::BranchChecksLimit { .. }
                )
                | (
                    ReduceGate::RepetitionTests,
                    ReduceError::RepetitionTestsLimit { .. }
                )
                | (
                    ReduceGate::MatchEvents,
                    ReduceError::MatchEventsLimit { .. }
                )
                | (ReduceGate::Count, ReduceError::CountLimit { .. })
                | (ReduceGate::SpanSum, ReduceError::SpanSumLimit { .. })
                | (ReduceGate::Work, ReduceError::WorkLimit { .. })
                | (ReduceGate::Scratch, ReduceError::ScratchLimit { .. })
                | (ReduceGate::Peak, ReduceError::PeakLimit { .. })
        )
    }

    #[test]
    fn every_build_resource_is_exact_and_one_below() {
        let ranges = ranges();
        assert_eq!(size_of::<Event>(), 8);
        assert_eq!(size_of::<RoleSegment>(), 12);
        assert_eq!(size_of::<GraphemeScalarDfaPlan>(), 160);
        let expected = hand_build_preflight();
        assert_eq!(
            BuildPreflight::for_range_count(ranges.len()).unwrap(),
            expected
        );
        let plan = GraphemeScalarDfaPlan::build(&ranges, BuildLimits::unlimited()).unwrap();
        let accounting = plan.build_accounting();
        assert_eq!(accounting.source_ranges, expected.source_ranges);
        assert_eq!(accounting.events, expected.events);
        assert_eq!(accounting.event_capacity, expected.events);
        assert_eq!(accounting.segment_capacity, expected.segment_capacity);
        assert_eq!(accounting.retained_segments, 25);
        assert_eq!(accounting.sort_comparisons_upper, expected.sort_comparisons);
        assert_eq!(accounting.allocations, expected.allocations);
        assert_eq!(accounting.event_writes, expected.event_writes);
        assert_eq!(accounting.copy_bytes, 0);
        assert_eq!(accounting.binary_search_comparisons_per_scalar, 5);
        assert_eq!(accounting.work, expected.work);
        assert_eq!(accounting.scratch_bytes, expected.scratch_bytes);
        assert_eq!(accounting.persistent_bytes, expected.persistent_bytes);
        assert_eq!(accounting.peak_bytes, expected.peak_bytes);
        assert!(accounting.sort_comparisons_actual <= accounting.sort_comparisons_upper);
        assert!(accounting.segment_writes <= accounting.segment_capacity);
        assert!(accounting.actual_work <= accounting.work);
        assert_eq!(accounting.event_capacity, accounting.events);
        assert_eq!(accounting.segment_capacity, accounting.events);
        assert_eq!(plan.segments.capacity(), accounting.segment_capacity);
        let exact = exact_build_limits(expected);
        GraphemeScalarDfaPlan::build(&ranges, exact).unwrap();
        for gate in [
            BuildGate::Ranges,
            BuildGate::Events,
            BuildGate::Segments,
            BuildGate::SortComparisons,
            BuildGate::Allocations,
            BuildGate::EventWrites,
            BuildGate::SegmentWrites,
            BuildGate::Work,
            BuildGate::Scratch,
            BuildGate::Persistent,
            BuildGate::Peak,
        ] {
            let mut limited = exact;
            match gate {
                BuildGate::Ranges => limited.max_source_ranges = one_below(expected.source_ranges),
                BuildGate::Events => limited.max_events = one_below(expected.events),
                BuildGate::Segments => {
                    limited.max_segments = one_below(expected.segment_capacity);
                }
                BuildGate::SortComparisons => {
                    limited.max_sort_comparisons = one_below(expected.sort_comparisons);
                }
                BuildGate::Allocations => {
                    limited.max_allocations = one_below(expected.allocations);
                }
                BuildGate::EventWrites => {
                    limited.max_event_writes = one_below(expected.event_writes);
                }
                BuildGate::SegmentWrites => {
                    limited.max_segment_writes = one_below(expected.segment_writes);
                }
                BuildGate::Work => limited.max_build_work = one_below(expected.work),
                BuildGate::Scratch => {
                    limited.max_scratch_bytes = one_below(expected.scratch_bytes);
                }
                BuildGate::Persistent => {
                    limited.max_persistent_bytes = one_below(expected.persistent_bytes);
                }
                BuildGate::Peak => limited.max_peak_bytes = one_below(expected.peak_bytes),
            }
            let error = GraphemeScalarDfaPlan::build(&ranges, limited).unwrap_err();
            assert!(
                build_gate_matches(gate, &error),
                "unexpected error: {error:?}"
            );
        }
    }

    #[test]
    fn every_span_sum_resource_is_exact_and_one_below() {
        let plan = plan();
        let haystack = b"xezxse";
        let baseline = plan.span_sum(haystack, ReduceLimits::unlimited()).unwrap();
        let upper = hand_reduce_upper();
        assert_eq!(baseline.accounting.upper_bounds, upper);
        assert_actual_within(baseline.accounting.actual, upper);
        let exact = exact_reduce_limits(upper);
        plan.span_sum(haystack, exact).unwrap();
        for gate in [
            ReduceGate::Input,
            ReduceGate::Decode,
            ReduceGate::Classifications,
            ReduceGate::RangeComparisons,
            ReduceGate::ScannerSteps,
            ReduceGate::RoleProbes,
            ReduceGate::BranchChecks,
            ReduceGate::RepetitionTests,
            ReduceGate::MatchEvents,
            ReduceGate::Count,
            ReduceGate::SpanSum,
            ReduceGate::Work,
            ReduceGate::Scratch,
            ReduceGate::Peak,
        ] {
            let limited = limits_one_below(upper, gate);
            let error = plan.span_sum(haystack, limited).unwrap_err();
            assert!(
                reduce_gate_matches(gate, &error),
                "unexpected error: {error:?}"
            );
        }
    }

    #[test]
    fn every_count_resource_is_exact_and_one_below() {
        let plan = plan();
        let haystack = b"xezxse";
        let baseline = plan.count(haystack, ReduceLimits::unlimited()).unwrap();
        let upper = hand_reduce_upper();
        assert_eq!(baseline.accounting.upper_bounds, upper);
        assert_actual_within(baseline.accounting.actual, upper);
        let exact = exact_reduce_limits(upper);
        plan.count(haystack, exact).unwrap();
        for gate in [
            ReduceGate::Input,
            ReduceGate::Decode,
            ReduceGate::Classifications,
            ReduceGate::RangeComparisons,
            ReduceGate::ScannerSteps,
            ReduceGate::RoleProbes,
            ReduceGate::BranchChecks,
            ReduceGate::RepetitionTests,
            ReduceGate::MatchEvents,
            ReduceGate::Count,
            ReduceGate::Work,
            ReduceGate::Scratch,
            ReduceGate::Peak,
        ] {
            let limited = limits_one_below(upper, gate);
            let error = plan.count(haystack, limited).unwrap_err();
            assert!(
                reduce_gate_matches(gate, &error),
                "unexpected error: {error:?}"
            );
        }
        let span_only = limits_one_below(upper, ReduceGate::SpanSum);
        plan.count(haystack, span_only).unwrap();
    }

    #[test]
    fn default_empty_reductions_admit_exact_fixed_scratch() {
        let plan = plan();
        let defaults = ReduceLimits::default();
        assert_eq!(defaults.max_scratch_bytes, EXECUTION_SCRATCH_BYTES);
        assert_eq!(plan.count(b"", defaults).unwrap().count, 0);
        assert_eq!(plan.span_sum(b"", defaults).unwrap().span_sum, 0);

        let one_below = ReduceLimits {
            max_scratch_bytes: EXECUTION_SCRATCH_BYTES.checked_sub(1).unwrap(),
            ..defaults
        };
        assert!(matches!(
            plan.count(b"", one_below),
            Err(ReduceError::ScratchLimit { .. })
        ));
        assert!(matches!(
            plan.span_sum(b"", one_below),
            Err(ReduceError::ScratchLimit { .. })
        ));
    }

    #[test]
    fn max_event_preflight_and_role_probe_adversaries_stay_bounded() {
        let preflight = BuildPreflight::for_range_count(4_096).unwrap();
        assert_eq!(preflight.events, 8_192);
        assert!(preflight.sort_comparisons > preflight.events);
        assert!(matches!(
            BuildPreflight::for_range_count(usize::MAX),
            Err(BuildError::ArithmeticOverflow {
                computation: "event count"
            })
        ));

        let plan = plan();
        let mut observed_role_probes = 0_usize;
        for haystack in [
            &b"q"[..],
            &b"x"[..],
            &b"xezxse"[..],
            &b"lllvvttq"[..],
            &b"ppppppq"[..],
            &b"rzxezxezx"[..],
        ] {
            let result = plan.count(haystack, ReduceLimits::unlimited()).unwrap();
            let actual = result.accounting.actual;
            let upper = result.accounting.upper_bounds;
            observed_role_probes = observed_role_probes.max(actual.role_probes);
            assert!(actual.role_probes <= upper.role_probes);
            assert!(actual.branch_checks <= upper.branch_checks);
            assert!(actual.repetition_tests <= upper.repetition_tests);
            assert!(actual.work <= upper.work);
        }
        assert!(observed_role_probes > 16);
    }

    #[test]
    fn hand_calculated_q_scaling() {
        for (source_ranges, expected) in [
            (
                1,
                BuildPreflight {
                    source_ranges: 1,
                    events: 2,
                    segment_capacity: 2,
                    sort_comparisons: 16,
                    allocations: 2,
                    event_writes: 2,
                    segment_writes: 2,
                    work: 736,
                    scratch_bytes: 16,
                    persistent_bytes: 184,
                    peak_bytes: 200,
                },
            ),
            (
                2,
                BuildPreflight {
                    source_ranges: 2,
                    events: 4,
                    segment_capacity: 4,
                    sort_comparisons: 48,
                    allocations: 2,
                    event_writes: 4,
                    segment_writes: 4,
                    work: 1_568,
                    scratch_bytes: 32,
                    persistent_bytes: 208,
                    peak_bytes: 240,
                },
            ),
            (
                4,
                BuildPreflight {
                    source_ranges: 4,
                    events: 8,
                    segment_capacity: 8,
                    sort_comparisons: 128,
                    allocations: 2,
                    event_writes: 8,
                    segment_writes: 8,
                    work: 3_488,
                    scratch_bytes: 64,
                    persistent_bytes: 256,
                    peak_bytes: 320,
                },
            ),
        ] {
            assert_eq!(
                BuildPreflight::for_range_count(source_ranges).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn hand_calculated_n_scaling() {
        let build = plan().build_accounting();
        assert_eq!(build.binary_search_comparisons_per_scalar, 5);
        assert_eq!(build.persistent_bytes, 664);
        for (input_bytes, expected) in [
            (
                8,
                ReduceUpperBounds {
                    input_bytes: 8,
                    decode_byte_checks: 32,
                    valid_scalars: 8,
                    invalid_bytes: 8,
                    classifications: 8,
                    range_comparisons: 40,
                    binary_search_comparisons_per_scalar: 5,
                    scanner_steps: 9,
                    role_probes: 128,
                    branch_checks: 193,
                    repetition_tests: 65,
                    match_events: 8,
                    count: 8,
                    span_sum: 8,
                    work: 859,
                    scratch_bytes: 512,
                    persistent_bytes: 664,
                    peak_bytes: 1_176,
                },
            ),
            (
                16,
                ReduceUpperBounds {
                    input_bytes: 16,
                    decode_byte_checks: 64,
                    valid_scalars: 16,
                    invalid_bytes: 16,
                    classifications: 16,
                    range_comparisons: 80,
                    binary_search_comparisons_per_scalar: 5,
                    scanner_steps: 17,
                    role_probes: 256,
                    branch_checks: 385,
                    repetition_tests: 129,
                    match_events: 16,
                    count: 16,
                    span_sum: 16,
                    work: 1_715,
                    scratch_bytes: 512,
                    persistent_bytes: 664,
                    peak_bytes: 1_176,
                },
            ),
            (
                32,
                ReduceUpperBounds {
                    input_bytes: 32,
                    decode_byte_checks: 128,
                    valid_scalars: 32,
                    invalid_bytes: 32,
                    classifications: 32,
                    range_comparisons: 160,
                    binary_search_comparisons_per_scalar: 5,
                    scanner_steps: 33,
                    role_probes: 512,
                    branch_checks: 769,
                    repetition_tests: 257,
                    match_events: 32,
                    count: 32,
                    span_sum: 32,
                    work: 3_427,
                    scratch_bytes: 512,
                    persistent_bytes: 664,
                    peak_bytes: 1_176,
                },
            ),
        ] {
            assert_eq!(reduce_upper_bounds(input_bytes, build).unwrap(), expected);
        }
    }

    #[test]
    fn every_published_actual_counter_is_reconciled() {
        let plan = plan();
        let result = plan.count(b"xezxse", ReduceLimits::unlimited()).unwrap();
        let upper = hand_reduce_upper();
        let actual = result.accounting.actual;
        assert_actual_within(actual, upper);

        let mut excessive_valid = actual;
        excessive_valid.valid_scalars = upper.valid_scalars + 1;
        assert!(matches!(
            reconcile_actual(excessive_valid, upper),
            Err(ReduceError::ArithmeticOverflow {
                computation: "actual counters exceeded prospective bounds"
            })
        ));

        let mut excessive_invalid = actual;
        excessive_invalid.invalid_bytes = upper.invalid_bytes + 1;
        assert!(matches!(
            reconcile_actual(excessive_invalid, upper),
            Err(ReduceError::ArithmeticOverflow {
                computation: "actual counters exceeded prospective bounds"
            })
        ));

        let mut inconsistent_partition = actual;
        inconsistent_partition.invalid_bytes = 1;
        assert!(inconsistent_partition.valid_scalars <= upper.valid_scalars);
        assert!(inconsistent_partition.invalid_bytes <= upper.invalid_bytes);
        assert!(matches!(
            reconcile_actual(inconsistent_partition, upper),
            Err(ReduceError::ArithmeticOverflow {
                computation: "actual counters exceeded prospective bounds"
            })
        ));
    }

    #[test]
    fn arithmetic_overflow_paths_are_named_and_fail_closed() {
        assert!(matches!(
            sort_comparison_bound(usize::MAX),
            Err(BuildError::ArithmeticOverflow {
                computation: "sort comparison bound"
            })
        ));
        assert!(matches!(
            prospective_build_work(usize::MAX / 32, 0, 0, 0, 0),
            Err(BuildError::ArithmeticOverflow {
                computation: "build work"
            })
        ));
        assert!(matches!(
            build_memory_bounds(usize::MAX, 0),
            Err(BuildError::ArithmeticOverflow {
                computation: "event bytes"
            })
        ));
        assert!(matches!(
            build_memory_bounds(0, usize::MAX),
            Err(BuildError::ArithmeticOverflow {
                computation: "segment bytes"
            })
        ));
        assert!(matches!(
            build_memory_bounds(0, usize::MAX / 12),
            Err(BuildError::ArithmeticOverflow {
                computation: "persistent plan bytes"
            })
        ));
        assert!(matches!(
            build_memory_bounds(usize::MAX / 8, 0),
            Err(BuildError::ArithmeticOverflow {
                computation: "build peak bytes"
            })
        ));

        let build = plan().build_accounting();
        assert!(matches!(
            reduce_upper_bounds(usize::MAX / 107 + 1, build),
            Err(ReduceError::ArithmeticOverflow {
                computation: "execution work upper bound"
            })
        ));
        let peak_overflow = BuildAccounting {
            persistent_bytes: usize::MAX,
            ..build
        };
        assert!(matches!(
            reduce_upper_bounds(0, peak_overflow),
            Err(ReduceError::ArithmeticOverflow {
                computation: "execution peak bytes"
            })
        ));
    }

    #[test]
    fn direct_limits_precede_overflow_prone_derived_bounds() {
        assert!(matches!(
            admitted_build_preflight(
                usize::MAX,
                BuildLimits {
                    max_source_ranges: 0,
                    ..BuildLimits::unlimited()
                }
            ),
            Err(BuildError::RangeLimit {
                needed: usize::MAX,
                limit: 0
            })
        ));
        let plan = plan();
        assert!(matches!(
            plan.preflight(
                usize::MAX,
                Operation::Count,
                ReduceLimits {
                    max_input_bytes: 0,
                    ..ReduceLimits::unlimited()
                }
            ),
            Err(ReduceError::InputBytesLimit {
                needed: usize::MAX,
                limit: 0
            })
        ));
        assert!(matches!(
            plan.preflight(usize::MAX, Operation::Count, ReduceLimits::unlimited()),
            Err(ReduceError::ArithmeticOverflow {
                computation: "decode check upper bound"
            })
        ));
    }

    fn result(haystack: &[u8]) -> (u64, u64) {
        let plan = plan();
        (
            plan.count(haystack, ReduceLimits::unlimited())
                .unwrap()
                .count,
            plan.span_sum(haystack, ReduceLimits::unlimited())
                .unwrap()
                .span_sum,
        )
    }

    #[test]
    fn ordered_cluster_traps() {
        assert_eq!(result(b"\r\n\r\n"), (2, 4));
        assert_eq!(result(b"ppp\0"), (2, 4));
        assert_eq!(result(b"lllvvttq"), (2, 8));
        assert_eq!(result(b"lllq"), (2, 4));
        assert_eq!(result(b"rrr"), (2, 3));
        assert_eq!(result(b"xezxse"), (1, 6));
        assert_eq!(result(b"xzzx"), (2, 4));
        assert_eq!(result(b"peeesq"), (2, 6));
    }

    #[test]
    fn malformed_utf8_advances_one_byte_without_matching() {
        let plan = plan();
        let haystack = b"a\xFFb\xC0\x80x";
        let counted = plan.count(haystack, ReduceLimits::unlimited()).unwrap();
        assert_eq!(counted.count, 3);
        assert_eq!(counted.accounting.actual.invalid_bytes, 3);
        assert_eq!(counted.accounting.actual.valid_scalars, 3);
        assert_eq!(counted.accounting.actual.classifications, 3);
        assert_eq!(
            counted.accounting.actual.input_bytes_advanced,
            haystack.len()
        );
        assert_eq!(
            plan.span_sum(haystack, ReduceLimits::unlimited())
                .unwrap()
                .span_sum,
            3
        );
    }

    #[test]
    fn exact_reduce_bounds_are_enforced_before_traversal() {
        let plan = plan();
        let baseline = plan.count(b"abc", ReduceLimits::unlimited()).unwrap();
        let upper = baseline.accounting.upper_bounds;
        let exact = ReduceLimits {
            max_input_bytes: upper.input_bytes,
            max_decode_byte_checks: upper.decode_byte_checks,
            max_classifications: upper.classifications,
            max_range_comparisons: upper.range_comparisons,
            max_scanner_steps: upper.scanner_steps,
            max_role_probes: upper.role_probes,
            max_branch_checks: upper.branch_checks,
            max_repetition_tests: upper.repetition_tests,
            max_match_events: upper.match_events,
            max_count: upper.count,
            max_span_sum: upper.span_sum,
            max_work: upper.work,
            max_scratch_bytes: upper.scratch_bytes,
            max_peak_bytes: upper.peak_bytes,
        };
        plan.count(b"abc", exact).unwrap();
        assert!(matches!(
            plan.count(
                b"abc",
                ReduceLimits {
                    max_range_comparisons: upper.range_comparisons - 1,
                    ..exact
                }
            ),
            Err(ReduceError::RangeComparisonsLimit { .. })
        ));
    }

    #[test]
    fn build_rejects_missing_and_inexact_derived_roles() {
        assert_eq!(
            GraphemeScalarDfaPlan::build(&[], BuildLimits::unlimited()).unwrap_err(),
            BuildError::MissingRole { role: Role::Cr }
        );
        let ranges = vec![
            (Role::Cr, '\r', '\r'),
            (Role::Lf, '\n', '\n'),
            (Role::Control, '\0', '\0'),
            (Role::Prepend, 'p', 'p'),
            (Role::L, 'l', 'l'),
            (Role::V, 'v', 'v'),
            (Role::Lv, 'a', 'a'),
            (Role::Lvt, 'b', 'b'),
            (Role::T, 't', 't'),
            (Role::Ri, 'r', 'r'),
            (Role::Extend, 'e', 'e'),
            (Role::Zwj, 'z', 'z'),
            (Role::SpacingMark, 's', 's'),
            (Role::ExtendedPictographic, 'x', 'x'),
            (Role::Tail, 'e', 'e'),
            (Role::Tail, 's', 's'),
            (Role::Tail, 'z', 'z'),
            (Role::Any, '\0', '\u{10FFFF}'),
            (Role::GenericCore, '\u{1}', '\u{9}'),
            (Role::GenericCore, '\u{b}', '\u{10FFFF}'),
        ];
        assert!(matches!(
            GraphemeScalarDfaPlan::build(&ranges, BuildLimits::unlimited()),
            Err(BuildError::DerivedClassMismatch {
                role: Role::GenericCore
            })
        ));
    }

    #[test]
    fn counted_stream_length_mismatch_fails_before_plan_publication() {
        let ranges = ranges();
        assert!(matches!(
            GraphemeScalarDfaPlan::build_from_counted_iter(
                ranges.len() + 1,
                ranges.iter().copied(),
                BuildLimits::unlimited(),
            ),
            Err(BuildError::ArithmeticOverflow {
                computation: "preflight source range count"
            })
        ));
        assert!(matches!(
            GraphemeScalarDfaPlan::build_from_counted_iter(
                ranges.len() - 1,
                ranges.iter().copied(),
                BuildLimits::unlimited(),
            ),
            Err(BuildError::ArithmeticOverflow {
                computation: "preflight event capacity"
            })
        ));
    }
}
