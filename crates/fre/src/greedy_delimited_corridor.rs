//! Complete-span visitation for a symmetric bounded greedy corridor.
//!
//! The admitted byte HIR is
//! `A (W* D+ W*){0,N} B | B (W* D+ W*){0,N} A`, where `A` and `B` are
//! distinct, nonempty, self-unbordered literals, `D` contains every byte but
//! one barrier, and `W` contains that barrier. For a gap between the two
//! literals, the minimum number of corridor repetitions is the number of
//! barrier-delimited regions containing a byte outside `W`, or one for a
//! nonempty gap containing only `W` and at least one non-barrier byte. A gap
//! made only of barriers is impossible. Thus membership and the greedy latest
//! suffix are decided from two ordered region indexes.
//!
//! Execution first indexes both literals and the two region families, then
//! emits the exact non-overlapping leftmost-first stream. All four exact
//! scratch allocations and the complete work envelope are admitted before a
//! source read, and every allocation completes before the first callback.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "runtime arithmetic is dominated by the checked preflight envelope"
)]

use core::{fmt, mem::size_of};

use fre_exact_alloc::{CopyError, ExactVec};
use memchr::memmem::Finder;
use regex_syntax::hir::{Class, ClassBytes, Hir, HirKind};

/// Stable identity of the construction-proved symmetric corridor sidecar.
pub const PLAN_ID: &str = "greedy-delimited-corridor.complete-spans.v1";
/// Stable identity of indexed complete-span visitation.
pub const SPAN_VISIT_OPERATION_ID: &str = "greedy-delimited-corridor.span-visit.unicode-off.v1";

const FIXED_WORK: u64 = 64;
const FINDER_CALL_WORK: u64 = 4;
const CLASSIFICATION_WORK: u64 = 2;
const QUERY_PROBE_WORK: u64 = 2;
const MATCH_WORK: u64 = 8;
const MAX_LITERAL_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ByteClass {
    words: [u64; 4],
    ranges: usize,
}

impl ByteClass {
    fn from_hir(class: &ClassBytes) -> Self {
        let mut words = [0_u64; 4];
        for range in class.ranges() {
            for byte in range.start()..=range.end() {
                let word = usize::from(byte >> 6);
                let bit = u32::from(byte & 63);
                words[word] |= 1_u64 << bit;
            }
        }
        Self {
            words,
            ranges: class.ranges().len(),
        }
    }

    #[inline]
    fn contains(self, byte: u8) -> bool {
        let word = usize::from(byte >> 6);
        let bit = u32::from(byte & 63);
        self.words[word] & (1_u64 << bit) != 0
    }
}

/// Source-proved language geometry retained by the sidecar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub left_literal_bytes: usize,
    pub right_literal_bytes: usize,
    pub whitespace_class_words: [u64; 4],
    pub whitespace_class_ranges: usize,
    pub barrier: u8,
    pub max_groups: usize,
    pub greedy: bool,
    pub symmetric: bool,
    pub non_overlapping: bool,
    pub unicode: bool,
}

/// Complete prospective resource envelope derived without a haystack read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpperBounds {
    pub input_bytes: usize,
    pub source_reads: u64,
    pub work: u64,
    pub finder_calls: usize,
    pub finder_service_bytes: usize,
    pub classification_bytes: usize,
    pub anchor_events: usize,
    pub region_events: usize,
    pub query_probes: usize,
    pub match_events: usize,
    pub count: u64,
    pub span_sum: u64,
    pub scratch_allocations: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Exact no-clock counters from one completed traversal.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Actual {
    pub source_reads: u64,
    pub work: u64,
    pub finder_calls: usize,
    pub finder_service_bytes: usize,
    pub classification_bytes: usize,
    pub anchor_events: usize,
    pub nonbarrier_regions: usize,
    pub forced_regions: usize,
    pub query_probes: usize,
    pub matches: usize,
    pub span_sum: u64,
    pub scratch_allocations: usize,
    pub scratch_bytes: usize,
}

/// Closed receipt for one complete traversal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Accounting {
    pub identity: Identity,
    pub upper_bounds: UpperBounds,
    pub actual: Actual,
}

/// Hard limits checked before source access or callbacks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_input_bytes: usize,
    pub max_source_reads: u64,
    pub max_work: u64,
    pub max_finder_calls: usize,
    pub max_anchor_events: usize,
    pub max_region_events: usize,
    pub max_query_probes: usize,
    pub max_match_events: usize,
    pub max_count: u64,
    pub max_span_sum: u64,
    pub max_scratch_allocations: usize,
    pub max_scratch_bytes: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl Limits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_input_bytes: usize::MAX,
            max_source_reads: u64::MAX,
            max_work: u64::MAX,
            max_finder_calls: usize::MAX,
            max_anchor_events: usize::MAX,
            max_region_events: usize::MAX,
            max_query_probes: usize::MAX,
            max_match_events: usize::MAX,
            max_count: u64::MAX,
            max_span_sum: u64::MAX,
            max_scratch_allocations: usize::MAX,
            max_scratch_bytes: usize::MAX,
            max_persistent_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_input_bytes: 64 * 1024 * 1024,
            max_source_reads: 256 * 1024 * 1024,
            max_work: 1_500_000_000,
            max_finder_calls: 64 * 1024 * 1024,
            max_anchor_events: 64 * 1024 * 1024,
            max_region_events: 64 * 1024 * 1024,
            max_query_probes: 750_000_000,
            max_match_events: 64 * 1024 * 1024,
            max_count: 64 * 1024 * 1024,
            max_span_sum: 64 * 1024 * 1024,
            max_scratch_allocations: 4,
            max_scratch_bytes: 256 * 1024 * 1024,
            max_persistent_bytes: 1024 * 1024,
            max_peak_bytes: 257 * 1024 * 1024,
        }
    }
}

/// Checked refusal from complete-span visitation.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    ArithmeticOverflow { computation: &'static str },
    InputBytesLimit { needed: usize, limit: usize },
    SourceReadsLimit { needed: u64, limit: u64 },
    WorkLimit { needed: u64, limit: u64 },
    FinderCallLimit { needed: usize, limit: usize },
    AnchorEventLimit { needed: usize, limit: usize },
    RegionEventLimit { needed: usize, limit: usize },
    QueryProbeLimit { needed: usize, limit: usize },
    MatchEventLimit { needed: usize, limit: usize },
    CountLimit { needed: u64, limit: u64 },
    SpanSumLimit { needed: u64, limit: u64 },
    ScratchAllocationLimit { needed: usize, limit: usize },
    ScratchLimit { needed: usize, limit: usize },
    PersistentLimit { needed: usize, limit: usize },
    PeakLimit { needed: usize, limit: usize },
    AllocationFailed { storage: &'static str, bytes: usize },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArithmeticOverflow { computation } => {
                write!(
                    formatter,
                    "greedy delimited-corridor {computation} overflowed"
                )
            }
            Self::InputBytesLimit { needed, limit } => write!(
                formatter,
                "greedy delimited-corridor needs {needed} input bytes, limit is {limit}",
            ),
            Self::SourceReadsLimit { needed, limit } => write!(
                formatter,
                "greedy delimited-corridor needs {needed} source reads, limit is {limit}",
            ),
            Self::WorkLimit { needed, limit } => write!(
                formatter,
                "greedy delimited-corridor needs {needed} work, limit is {limit}",
            ),
            Self::FinderCallLimit { needed, limit } => write!(
                formatter,
                "greedy delimited-corridor needs {needed} finder calls, limit is {limit}",
            ),
            Self::AnchorEventLimit { needed, limit } => write!(
                formatter,
                "greedy delimited-corridor needs {needed} anchor events, limit is {limit}",
            ),
            Self::RegionEventLimit { needed, limit } => write!(
                formatter,
                "greedy delimited-corridor needs {needed} region events, limit is {limit}",
            ),
            Self::QueryProbeLimit { needed, limit } => write!(
                formatter,
                "greedy delimited-corridor needs {needed} query probes, limit is {limit}",
            ),
            Self::MatchEventLimit { needed, limit } => write!(
                formatter,
                "greedy delimited-corridor needs {needed} match events, limit is {limit}",
            ),
            Self::CountLimit { needed, limit } => write!(
                formatter,
                "greedy delimited-corridor needs count {needed}, limit is {limit}",
            ),
            Self::SpanSumLimit { needed, limit } => write!(
                formatter,
                "greedy delimited-corridor needs span sum {needed}, limit is {limit}",
            ),
            Self::ScratchAllocationLimit { needed, limit } => write!(
                formatter,
                "greedy delimited-corridor needs {needed} scratch allocations, limit is {limit}",
            ),
            Self::ScratchLimit { needed, limit } => write!(
                formatter,
                "greedy delimited-corridor needs {needed} scratch bytes, limit is {limit}",
            ),
            Self::PersistentLimit { needed, limit } => write!(
                formatter,
                "greedy delimited-corridor needs {needed} persistent bytes, limit is {limit}",
            ),
            Self::PeakLimit { needed, limit } => write!(
                formatter,
                "greedy delimited-corridor needs {needed} peak bytes, limit is {limit}",
            ),
            Self::AllocationFailed { storage, bytes } => write!(
                formatter,
                "greedy delimited-corridor failed to allocate {bytes} bytes for {storage}",
            ),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Span {
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Result {
    pub matches: usize,
    pub span_sum: u64,
    pub accounting: Accounting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Region {
    first: usize,
    last: usize,
}

/// Immutable owner built only from the certified HIR.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Plan {
    left: Vec<u8>,
    right: Vec<u8>,
    whitespace: ByteClass,
    barrier: u8,
    max_groups: usize,
}

impl Plan {
    pub(crate) const fn identity(&self) -> Identity {
        Identity {
            plan_id: PLAN_ID,
            operation_id: SPAN_VISIT_OPERATION_ID,
            left_literal_bytes: self.left.len(),
            right_literal_bytes: self.right.len(),
            whitespace_class_words: self.whitespace.words,
            whitespace_class_ranges: self.whitespace.ranges,
            barrier: self.barrier,
            max_groups: self.max_groups,
            greedy: true,
            symmetric: true,
            non_overlapping: true,
            unicode: false,
        }
    }

    pub(crate) fn storage_bytes(&self) -> usize {
        size_of::<Self>()
            .checked_add(self.left.len())
            .and_then(|bytes| bytes.checked_add(self.right.len()))
            .expect("published corridor storage was checked at construction")
    }

    fn upper_bounds(&self, input_bytes: usize) -> core::result::Result<UpperBounds, Error> {
        let left_events = input_bytes / self.left.len();
        let right_events = input_bytes / self.right.len();
        let anchor_events =
            left_events
                .checked_add(right_events)
                .ok_or(Error::ArithmeticOverflow {
                    computation: "anchor-event upper bound",
                })?;
        let finder_calls = anchor_events
            .checked_add(2)
            .ok_or(Error::ArithmeticOverflow {
                computation: "finder-call upper bound",
            })?;
        let finder_service_bytes = input_bytes
            .checked_mul(2)
            .ok_or(Error::ArithmeticOverflow {
                computation: "finder-service upper bound",
            })?;
        let classification_bytes = input_bytes;
        let source_reads = u64::try_from(finder_service_bytes)
            .ok()
            .and_then(|finder| {
                u64::try_from(classification_bytes)
                    .ok()
                    .and_then(|classes| finder.checked_add(classes))
            })
            .ok_or(Error::ArithmeticOverflow {
                computation: "source-read upper bound",
            })?;
        let region_events = input_bytes
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow {
                computation: "region-event upper bound",
            })?
            / 2;
        let position_log = ceil_log2(anchor_events.saturating_add(1));
        let region_log = ceil_log2(region_events.saturating_add(1));
        let query_probes_per_anchor = position_log
            .checked_mul(
                region_log
                    .checked_mul(2)
                    .and_then(|probes| probes.checked_add(4))
                    .ok_or(Error::ArithmeticOverflow {
                        computation: "query-probe per-anchor bound",
                    })?,
            )
            .and_then(|probes| {
                region_log
                    .checked_mul(4)
                    .and_then(|tail| probes.checked_add(tail))
            })
            .and_then(|probes| probes.checked_add(16))
            .ok_or(Error::ArithmeticOverflow {
                computation: "query-probe per-anchor bound",
            })?;
        let query_probes = anchor_events.checked_mul(query_probes_per_anchor).ok_or(
            Error::ArithmeticOverflow {
                computation: "query-probe upper bound",
            },
        )?;
        let minimum_match_bytes =
            self.left
                .len()
                .checked_add(self.right.len())
                .ok_or(Error::ArithmeticOverflow {
                    computation: "minimum match width",
                })?;
        let match_events = input_bytes / minimum_match_bytes;
        let count = u64::try_from(match_events).map_err(|_| Error::ArithmeticOverflow {
            computation: "match-event count",
        })?;
        let span_sum = u64::try_from(input_bytes).map_err(|_| Error::ArithmeticOverflow {
            computation: "span-sum upper bound",
        })?;
        let scratch_allocations = usize::from(left_events > 0)
            + usize::from(right_events > 0)
            + usize::from(region_events > 0) * 2;
        let scratch_bytes = left_events
            .checked_mul(size_of::<usize>())
            .and_then(|bytes| {
                right_events
                    .checked_mul(size_of::<usize>())
                    .and_then(|right| bytes.checked_add(right))
            })
            .and_then(|bytes| {
                region_events
                    .checked_mul(size_of::<Region>())
                    .and_then(|regions| regions.checked_mul(2))
                    .and_then(|regions| bytes.checked_add(regions))
            })
            .ok_or(Error::ArithmeticOverflow {
                computation: "scratch-byte upper bound",
            })?;
        let persistent_bytes = self.storage_bytes();
        let peak_bytes =
            persistent_bytes
                .checked_add(scratch_bytes)
                .ok_or(Error::ArithmeticOverflow {
                    computation: "peak-byte upper bound",
                })?;
        let work = FIXED_WORK
            .checked_add(u64::try_from(finder_service_bytes).unwrap_or(u64::MAX))
            .and_then(|work| {
                u64::try_from(finder_calls)
                    .ok()
                    .and_then(|calls| calls.checked_mul(FINDER_CALL_WORK))
                    .and_then(|calls| work.checked_add(calls))
            })
            .and_then(|work| {
                u64::try_from(classification_bytes)
                    .ok()
                    .and_then(|bytes| bytes.checked_mul(CLASSIFICATION_WORK))
                    .and_then(|bytes| work.checked_add(bytes))
            })
            .and_then(|work| {
                u64::try_from(query_probes)
                    .ok()
                    .and_then(|probes| probes.checked_mul(QUERY_PROBE_WORK))
                    .and_then(|probes| work.checked_add(probes))
            })
            .and_then(|work| {
                count
                    .checked_mul(MATCH_WORK)
                    .and_then(|matches| work.checked_add(matches))
            })
            .ok_or(Error::ArithmeticOverflow {
                computation: "work upper bound",
            })?;
        Ok(UpperBounds {
            input_bytes,
            source_reads,
            work,
            finder_calls,
            finder_service_bytes,
            classification_bytes,
            anchor_events,
            region_events,
            query_probes,
            match_events,
            count,
            span_sum,
            scratch_allocations,
            scratch_bytes,
            persistent_bytes,
            peak_bytes,
        })
    }

    fn preflight(
        &self,
        input_bytes: usize,
        limits: Limits,
    ) -> core::result::Result<UpperBounds, Error> {
        let upper = self.upper_bounds(input_bytes)?;
        macro_rules! refuse {
            ($field:ident, $limit:ident, $variant:ident) => {
                if upper.$field > limits.$limit {
                    return Err(Error::$variant {
                        needed: upper.$field,
                        limit: limits.$limit,
                    });
                }
            };
        }
        refuse!(input_bytes, max_input_bytes, InputBytesLimit);
        refuse!(source_reads, max_source_reads, SourceReadsLimit);
        refuse!(work, max_work, WorkLimit);
        refuse!(finder_calls, max_finder_calls, FinderCallLimit);
        refuse!(anchor_events, max_anchor_events, AnchorEventLimit);
        refuse!(region_events, max_region_events, RegionEventLimit);
        refuse!(query_probes, max_query_probes, QueryProbeLimit);
        refuse!(match_events, max_match_events, MatchEventLimit);
        refuse!(count, max_count, CountLimit);
        refuse!(span_sum, max_span_sum, SpanSumLimit);
        refuse!(
            scratch_allocations,
            max_scratch_allocations,
            ScratchAllocationLimit
        );
        refuse!(scratch_bytes, max_scratch_bytes, ScratchLimit);
        refuse!(persistent_bytes, max_persistent_bytes, PersistentLimit);
        refuse!(peak_bytes, max_peak_bytes, PeakLimit);
        Ok(upper)
    }

    pub(crate) fn visit_spans<F>(
        &self,
        haystack: &[u8],
        limits: Limits,
        mut visitor: F,
    ) -> core::result::Result<Result, Error>
    where
        F: FnMut(Span),
    {
        let upper = self.preflight(haystack.len(), limits)?;
        // Allocate every admitted byte before the source or callback is
        // touched. The exact-capacity vectors cannot grow during indexing.
        let mut left_positions =
            exact_scratch::<usize>(haystack.len() / self.left.len(), "left literal positions")?;
        let mut right_positions =
            exact_scratch::<usize>(haystack.len() / self.right.len(), "right literal positions")?;
        let region_capacity = haystack.len().saturating_add(1) / 2;
        let mut nonbarrier_regions =
            exact_scratch::<Region>(region_capacity, "non-barrier regions")?;
        let mut forced_regions = exact_scratch::<Region>(region_capacity, "forced regions")?;

        let mut actual = Actual {
            scratch_allocations: upper.scratch_allocations,
            scratch_bytes: upper.scratch_bytes,
            ..Actual::default()
        };
        index_literal(haystack, &self.left, &mut left_positions, &mut actual);
        index_literal(haystack, &self.right, &mut right_positions, &mut actual);
        index_regions(
            haystack,
            self.whitespace,
            self.barrier,
            &mut nonbarrier_regions,
            &mut forced_regions,
            &mut actual,
        );

        let left_positions = left_positions.as_slice();
        let right_positions = right_positions.as_slice();
        let nonbarrier_regions = nonbarrier_regions.as_slice();
        let forced_regions = forced_regions.as_slice();
        let mut cursor = 0_usize;
        let mut left_index = 0_usize;
        let mut right_index = 0_usize;
        loop {
            left_index += partition_point_counted(
                &left_positions[left_index..],
                |&position| position < cursor,
                &mut actual.query_probes,
            );
            right_index += partition_point_counted(
                &right_positions[right_index..],
                |&position| position < cursor,
                &mut actual.query_probes,
            );
            let next_left = left_positions.get(left_index).copied();
            let next_right = right_positions.get(right_index).copied();
            let (start, prefix_len, suffixes, suffix_len, left_branch) =
                match (next_left, next_right) {
                    (Some(left), Some(right)) if left <= right => (
                        left,
                        self.left.len(),
                        right_positions,
                        self.right.len(),
                        true,
                    ),
                    (Some(_), Some(right)) => (
                        right,
                        self.right.len(),
                        left_positions,
                        self.left.len(),
                        false,
                    ),
                    (Some(left), None) => (
                        left,
                        self.left.len(),
                        right_positions,
                        self.right.len(),
                        true,
                    ),
                    (None, Some(right)) => (
                        right,
                        self.right.len(),
                        left_positions,
                        self.left.len(),
                        false,
                    ),
                    (None, None) => break,
                };
            if let Some(end) = latest_end(
                suffixes,
                start + prefix_len,
                suffix_len,
                self.max_groups,
                nonbarrier_regions,
                forced_regions,
                &mut actual.query_probes,
            ) {
                let width = end - start;
                actual.matches += 1;
                actual.span_sum += u64::try_from(width)
                    .expect("preflight proves every visited span width fits u64");
                visitor(Span { start, end });
                cursor = end;
            } else if left_branch {
                left_index += 1;
            } else {
                right_index += 1;
            }
        }

        actual.anchor_events = left_positions.len() + right_positions.len();
        actual.nonbarrier_regions = nonbarrier_regions.len();
        actual.forced_regions = forced_regions.len();
        actual.source_reads = u64::try_from(actual.finder_service_bytes)
            .ok()
            .and_then(|finder| {
                u64::try_from(actual.classification_bytes)
                    .ok()
                    .and_then(|classes| finder.checked_add(classes))
            })
            .expect("preflight proves source-read accounting fits u64");
        actual.work = FIXED_WORK
            + u64::try_from(actual.finder_service_bytes).expect("finder service fits u64")
            + u64::try_from(actual.finder_calls).expect("finder calls fit u64") * FINDER_CALL_WORK
            + u64::try_from(actual.classification_bytes).expect("classifications fit u64")
                * CLASSIFICATION_WORK
            + u64::try_from(actual.query_probes).expect("query probes fit u64") * QUERY_PROBE_WORK
            + u64::try_from(actual.matches).expect("matches fit u64") * MATCH_WORK;
        debug_assert!(actual.source_reads <= upper.source_reads);
        debug_assert!(actual.work <= upper.work);
        debug_assert!(actual.finder_calls <= upper.finder_calls);
        debug_assert!(actual.finder_service_bytes <= upper.finder_service_bytes);
        debug_assert!(actual.classification_bytes <= upper.classification_bytes);
        debug_assert!(actual.anchor_events <= upper.anchor_events);
        debug_assert!(actual.nonbarrier_regions <= upper.region_events);
        debug_assert!(actual.forced_regions <= upper.region_events);
        debug_assert!(actual.query_probes <= upper.query_probes);
        debug_assert!(actual.matches <= upper.match_events);
        debug_assert!(actual.span_sum <= upper.span_sum);
        Ok(Result {
            matches: actual.matches,
            span_sum: actual.span_sum,
            accounting: Accounting {
                identity: self.identity(),
                upper_bounds: upper,
                actual,
            },
        })
    }
}

fn exact_scratch<T>(
    capacity: usize,
    storage: &'static str,
) -> core::result::Result<ExactVec<T>, Error> {
    ExactVec::try_with_capacity(capacity).map_err(|error| match error {
        CopyError::LayoutOverflow => Error::ArithmeticOverflow {
            computation: "scratch allocation layout",
        },
        CopyError::AllocationFailed => Error::AllocationFailed {
            storage,
            bytes: capacity.saturating_mul(size_of::<T>()),
        },
    })
}

fn index_literal(
    haystack: &[u8],
    literal: &[u8],
    positions: &mut ExactVec<usize>,
    actual: &mut Actual,
) {
    let finder = Finder::new(literal);
    let mut cursor = 0_usize;
    loop {
        actual.finder_calls += 1;
        let searched = &haystack[cursor..];
        let Some(relative) = finder.find(searched) else {
            actual.finder_service_bytes += searched.len();
            break;
        };
        let position = cursor + relative;
        actual.finder_service_bytes += relative + literal.len();
        positions
            .try_push(position)
            .expect("self-unbordered literal count fits its exact capacity");
        cursor = position + literal.len();
    }
}

fn index_regions(
    haystack: &[u8],
    whitespace: ByteClass,
    barrier: u8,
    nonbarrier: &mut ExactVec<Region>,
    forced: &mut ExactVec<Region>,
    actual: &mut Actual,
) {
    let mut first_nonbarrier = None;
    let mut last_nonbarrier = 0_usize;
    let mut first_forced = None;
    let mut last_forced = 0_usize;
    for (position, &byte) in haystack.iter().enumerate() {
        actual.classification_bytes += 1;
        if byte == barrier {
            push_region(nonbarrier, &mut first_nonbarrier, last_nonbarrier);
            push_region(forced, &mut first_forced, last_forced);
        } else {
            first_nonbarrier.get_or_insert(position);
            last_nonbarrier = position;
            if !whitespace.contains(byte) {
                first_forced.get_or_insert(position);
                last_forced = position;
            }
        }
    }
    push_region(nonbarrier, &mut first_nonbarrier, last_nonbarrier);
    push_region(forced, &mut first_forced, last_forced);
}

fn push_region(regions: &mut ExactVec<Region>, first: &mut Option<usize>, last: usize) {
    if let Some(first) = first.take() {
        regions
            .try_push(Region { first, last })
            .expect("barrier-delimited region count fits exact capacity");
    }
}

fn latest_end(
    opposite: &[usize],
    gap_start: usize,
    suffix_len: usize,
    max_groups: usize,
    nonbarrier: &[Region],
    forced: &[Region],
    probes: &mut usize,
) -> Option<usize> {
    let first = partition_point_counted(opposite, |&position| position < gap_start, probes);
    let candidates = &opposite[first..];
    let mut admissible_left = 0_usize;
    let mut admissible_right = candidates.len();
    while admissible_left < admissible_right {
        *probes += 1;
        let middle = admissible_left + (admissible_right - admissible_left) / 2;
        if region_count(forced, gap_start, candidates[middle], probes) <= max_groups {
            admissible_left = middle + 1;
        } else {
            admissible_right = middle;
        }
    }
    let admissible = admissible_left;
    if let Some(&position) = candidates[..admissible].last() {
        let forced_count = region_count(forced, gap_start, position, probes);
        if position == gap_start
            || (region_count(nonbarrier, gap_start, position, probes) > 0
                && forced_count.max(1) <= max_groups)
        {
            return Some(position + suffix_len);
        }
    }
    candidates
        .first()
        .filter(|&&position| position == gap_start)
        .map(|&position| position + suffix_len)
}

fn region_count(regions: &[Region], start: usize, end: usize, probes: &mut usize) -> usize {
    let first = partition_point_counted(regions, |region| region.last < start, probes);
    let past_last = partition_point_counted(regions, |region| region.first < end, probes);
    debug_assert!(first <= past_last);
    past_last - first
}

fn partition_point_counted<T, F>(slice: &[T], mut predicate: F, probes: &mut usize) -> usize
where
    F: FnMut(&T) -> bool,
{
    let mut left = 0_usize;
    let mut right = slice.len();
    while left < right {
        *probes += 1;
        let middle = left + (right - left) / 2;
        if predicate(&slice[middle]) {
            left = middle + 1;
        } else {
            right = middle;
        }
    }
    left
}

const fn ceil_log2(value: usize) -> usize {
    if value <= 1 {
        0
    } else {
        usize::BITS as usize - (value - 1).leading_zeros() as usize
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Inspection<'a> {
    left: &'a [u8],
    right: &'a [u8],
    whitespace: ByteClass,
    barrier: u8,
    max_groups: usize,
    pub(crate) planner_work: u64,
}

impl Inspection<'_> {
    pub(crate) fn storage_bytes(&self) -> Option<usize> {
        size_of::<Plan>()
            .checked_add(self.left.len())
            .and_then(|bytes| bytes.checked_add(self.right.len()))
    }

    pub(crate) fn build(self) -> core::result::Result<Plan, CopyError> {
        Ok(Plan {
            left: fre_exact_alloc::copy_exact(self.left)?,
            right: fre_exact_alloc::copy_exact(self.right)?,
            whitespace: self.whitespace,
            barrier: self.barrier,
            max_groups: self.max_groups,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum InspectionOutcome<'a> {
    Eligible(Inspection<'a>),
    Ineligible { planner_work: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InspectionError {
    WorkLimit {
        actual: u64,
        needed: u64,
        limit: u64,
    },
    ArithmeticOverflow,
}

struct Meter {
    work: u64,
    limit: u64,
}

impl Meter {
    const fn new(work: u64, limit: u64) -> Self {
        Self { work, limit }
    }

    fn charge(&mut self, units: usize) -> core::result::Result<(), InspectionError> {
        let units = u64::try_from(units).map_err(|_| InspectionError::ArithmeticOverflow)?;
        let needed = self
            .work
            .checked_add(units)
            .ok_or(InspectionError::ArithmeticOverflow)?;
        if needed > self.limit {
            return Err(InspectionError::WorkLimit {
                actual: self.work,
                needed,
                limit: self.limit,
            });
        }
        self.work = needed;
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Corridor {
    whitespace: ByteClass,
    barrier: u8,
    max_groups: usize,
}

#[derive(Clone, Copy)]
struct Branch<'a> {
    prefix: &'a [u8],
    corridor: Corridor,
    suffix: &'a [u8],
}

fn peel_captures<'h>(
    mut hir: &'h Hir,
    meter: &mut Meter,
) -> core::result::Result<&'h Hir, InspectionError> {
    loop {
        meter.charge(1)?;
        let HirKind::Capture(capture) = hir.kind() else {
            return Ok(hir);
        };
        hir = &capture.sub;
    }
}

fn literal<'h>(
    hir: &'h Hir,
    meter: &mut Meter,
) -> core::result::Result<Option<&'h [u8]>, InspectionError> {
    let hir = peel_captures(hir, meter)?;
    let HirKind::Literal(literal) = hir.kind() else {
        return Ok(None);
    };
    meter.charge(literal.0.len())?;
    Ok((!literal.0.is_empty()).then_some(&literal.0))
}

fn greedy_class_repeat(
    hir: &Hir,
    minimum: u32,
    meter: &mut Meter,
) -> core::result::Result<Option<ByteClass>, InspectionError> {
    let hir = peel_captures(hir, meter)?;
    let HirKind::Repetition(repetition) = hir.kind() else {
        return Ok(None);
    };
    meter.charge(1)?;
    if repetition.min != minimum || repetition.max.is_some() || !repetition.greedy {
        return Ok(None);
    }
    let sub = peel_captures(&repetition.sub, meter)?;
    let HirKind::Class(Class::Bytes(class)) = sub.kind() else {
        return Ok(None);
    };
    meter.charge(class.ranges().len())?;
    let members = class.ranges().iter().try_fold(0_usize, |members, range| {
        members.checked_add(usize::from(range.end() - range.start()) + 1)
    });
    meter.charge(members.ok_or(InspectionError::ArithmeticOverflow)?)?;
    Ok(Some(ByteClass::from_hir(class)))
}

fn one_byte_complement(
    class: ByteClass,
    meter: &mut Meter,
) -> core::result::Result<Option<u8>, InspectionError> {
    let mut missing = None;
    for byte in u8::MIN..=u8::MAX {
        meter.charge(1)?;
        if !class.contains(byte) {
            if missing.is_some() {
                return Ok(None);
            }
            missing = Some(byte);
        }
    }
    Ok(missing)
}

fn corridor(
    hir: &Hir,
    meter: &mut Meter,
) -> core::result::Result<Option<Corridor>, InspectionError> {
    let hir = peel_captures(hir, meter)?;
    let HirKind::Repetition(outer) = hir.kind() else {
        return Ok(None);
    };
    meter.charge(1)?;
    if outer.min != 0 || !outer.greedy {
        return Ok(None);
    }
    let Some(max_groups) = outer.max else {
        return Ok(None);
    };
    let max_groups =
        usize::try_from(max_groups).map_err(|_| InspectionError::ArithmeticOverflow)?;
    let unit = peel_captures(&outer.sub, meter)?;
    let HirKind::Concat(parts) = unit.kind() else {
        return Ok(None);
    };
    meter.charge(parts.len())?;
    let [leading, domain, trailing] = parts.as_slice() else {
        return Ok(None);
    };
    let Some(leading) = greedy_class_repeat(leading, 0, meter)? else {
        return Ok(None);
    };
    let Some(domain) = greedy_class_repeat(domain, 1, meter)? else {
        return Ok(None);
    };
    let Some(trailing) = greedy_class_repeat(trailing, 0, meter)? else {
        return Ok(None);
    };
    if leading != trailing {
        return Ok(None);
    }
    let Some(barrier) = one_byte_complement(domain, meter)? else {
        return Ok(None);
    };
    if !leading.contains(barrier) {
        return Ok(None);
    }
    Ok(Some(Corridor {
        whitespace: leading,
        barrier,
        max_groups,
    }))
}

fn branch<'h>(
    hir: &'h Hir,
    meter: &mut Meter,
) -> core::result::Result<Option<Branch<'h>>, InspectionError> {
    let hir = peel_captures(hir, meter)?;
    let HirKind::Concat(parts) = hir.kind() else {
        return Ok(None);
    };
    meter.charge(parts.len())?;
    let [prefix, middle, suffix] = parts.as_slice() else {
        return Ok(None);
    };
    let Some(prefix) = literal(prefix, meter)? else {
        return Ok(None);
    };
    let Some(corridor) = corridor(middle, meter)? else {
        return Ok(None);
    };
    let Some(suffix) = literal(suffix, meter)? else {
        return Ok(None);
    };
    Ok(Some(Branch {
        prefix,
        corridor,
        suffix,
    }))
}

fn self_unbordered(
    literal: &[u8],
    meter: &mut Meter,
) -> core::result::Result<bool, InspectionError> {
    if literal.len() > MAX_LITERAL_BYTES {
        return Ok(false);
    }
    for border in 1..literal.len() {
        meter.charge(border)?;
        if literal[..border] == literal[literal.len() - border..] {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) fn inspect(
    hir: &Hir,
    initial_work: u64,
    limit: u64,
) -> core::result::Result<InspectionOutcome<'_>, InspectionError> {
    let mut meter = Meter::new(initial_work, limit);
    let root = peel_captures(hir, &mut meter)?;
    let HirKind::Alternation(branches) = root.kind() else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: meter.work,
        });
    };
    meter.charge(branches.len())?;
    let [left_branch, right_branch] = branches.as_slice() else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: meter.work,
        });
    };
    let Some(left_branch) = branch(left_branch, &mut meter)? else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: meter.work,
        });
    };
    let Some(right_branch) = branch(right_branch, &mut meter)? else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: meter.work,
        });
    };
    if left_branch.prefix == left_branch.suffix
        || left_branch.prefix != right_branch.suffix
        || left_branch.suffix != right_branch.prefix
        || left_branch.corridor.whitespace != right_branch.corridor.whitespace
        || left_branch.corridor.barrier != right_branch.corridor.barrier
        || left_branch.corridor.max_groups != right_branch.corridor.max_groups
        || !self_unbordered(left_branch.prefix, &mut meter)?
        || !self_unbordered(left_branch.suffix, &mut meter)?
    {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: meter.work,
        });
    }
    Ok(InspectionOutcome::Eligible(Inspection {
        left: left_branch.prefix,
        right: left_branch.suffix,
        whitespace: left_branch.corridor.whitespace,
        barrier: left_branch.corridor.barrier,
        max_groups: left_branch.corridor.max_groups,
        planner_work: meter.work,
    }))
}

#[cfg(test)]
mod tests {
    use regex_syntax::ParserBuilder;

    use super::{InspectionOutcome, Limits, inspect};

    fn plan(pattern: &str) -> super::Plan {
        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(pattern)
            .unwrap();
        let InspectionOutcome::Eligible(inspection) = inspect(&hir, 0, u64::MAX).unwrap() else {
            panic!("pattern was ineligible: {pattern:?}");
        };
        inspection.build().unwrap()
    }

    fn oracle(pattern: &str, haystack: &[u8]) -> Vec<super::Span> {
        regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap()
            .find_iter(haystack)
            .map(|matched| super::Span {
                start: matched.start(),
                end: matched.end(),
            })
            .collect()
    }

    #[test]
    fn symmetric_bounded_corridor_shape_is_narrowly_admitted() {
        let admitted = plan(r"Holmes(?:\s*.+\s*){0,10}Watson|Watson(?:\s*.+\s*){0,10}Holmes");
        assert_eq!(admitted.identity().left_literal_bytes, 6);
        assert_eq!(admitted.identity().right_literal_bytes, 6);
        assert_eq!(admitted.identity().max_groups, 10);
        assert_eq!(admitted.identity().barrier, b'\n');
        for hostile in [
            r"Holmes(?:\s*.+\s*){0,10}Watson",
            r"Holmes(?:\s*.+\s*){0,10}Watson|Watson(?:\s*.+\s*){0,9}Holmes",
            r"Holmes(?:\s*.*\s*){0,10}Watson|Watson(?:\s*.*\s*){0,10}Holmes",
            r"Holmes(?:\s*.+?\s*){0,10}Watson|Watson(?:\s*.+?\s*){0,10}Holmes",
            r"Holmes(?:\s*.+\s*){0,10}Watson|Watson(?:\s*.+\s*){0,10}Sherlock",
            r"aba(?:[ \n]*[^\n]+[ \n]*){0,2}xyz|xyz(?:[ \n]*[^\n]+[ \n]*){0,2}aba",
        ] {
            let hir = ParserBuilder::new()
                .unicode(false)
                .utf8(false)
                .build()
                .parse(hostile)
                .unwrap();
            assert!(
                matches!(
                    inspect(&hir, 0, u64::MAX).unwrap(),
                    InspectionOutcome::Ineligible { .. }
                ),
                "hostile shape admitted: {hostile:?}",
            );
        }
    }

    #[test]
    fn exhaustive_small_byte_languages_match_the_oracle() {
        for (pattern, alphabet, maximum_len) in [
            (
                r"AB(?:[ \n]*[^\n]+[ \n]*){0,2}CD|CD(?:[ \n]*[^\n]+[ \n]*){0,2}AB",
                &[b'A', b'B', b'C', b'D', b'x', b' ', b'\n'][..],
                6,
            ),
            (
                r"A(?:[x|]*[^|]+[x|]*){0,2}AB|AB(?:[x|]*[^|]+[x|]*){0,2}A",
                &[b'A', b'B', b'x', b'|'][..],
                7,
            ),
        ] {
            let plan = plan(pattern);
            let mut haystack = Vec::new();
            for len in 0..=maximum_len {
                for mut case in 0..alphabet.len().pow(len as u32) {
                    haystack.clear();
                    for _ in 0..len {
                        haystack.push(alphabet[case % alphabet.len()]);
                        case /= alphabet.len();
                    }
                    let mut actual = Vec::new();
                    plan.visit_spans(&haystack, Limits::unlimited(), |span| actual.push(span))
                        .unwrap();
                    assert_eq!(actual, oracle(pattern, &haystack), "haystack={haystack:?}");
                }
            }
        }
    }

    #[test]
    fn limits_and_allocation_complete_before_callbacks() {
        let plan = plan(r"Holmes(?:\s*.+\s*){0,10}Watson|Watson(?:\s*.+\s*){0,10}Holmes");
        let mut callbacks = 0;
        let error = plan
            .visit_spans(
                b"Holmes and Watson",
                Limits {
                    max_scratch_bytes: 0,
                    ..Limits::unlimited()
                },
                |_| callbacks += 1,
            )
            .unwrap_err();
        assert!(matches!(error, super::Error::ScratchLimit { .. }));
        assert_eq!(callbacks, 0);
    }
}
