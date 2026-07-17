//! Linear whole-match counting for a literal with bounded byte context.
//!
//! The admitted byte language is
//! `HEAD{H} SEP+ ANY{0,A} LITERAL ANY{0,B} SEP+ TAIL{T}`. `HEAD`, `SEP`, and
//! `TAIL` are canonical inline byte classes, `H,T >= 2`, the separators are
//! disjoint from both fixed classes, and the literal is nonempty, starts
//! outside `SEP`, and cannot overlap itself. Those facts permit three linear
//! streams: suffix-interval discovery, one native literal-finder traversal,
//! and monotone prefix resolution. No input position is paired with program
//! states, so execution is `O(N + Q)`, never `O(N*Q)`.
//!
//! rebar-row:curated/10-bounded-repeat/context@rust/regex

use core::{fmt, mem::size_of};

use fre_exact_alloc::{CopyError, copy_exact, zeroed_exact};
use memchr::memmem::{Finder, FinderBuilder};

pub const PLAN_ID: &str = "bounded-context-count.literal-interval-stream.v1";
pub const COUNT_OPERATION_ID: &str = "bounded-context-count.count.v1";

const INTERVAL_BYTES: usize = 12;
const MIN_FIXED_WIDTH: u32 = 2;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ByteClass {
    words: [u64; 4],
}

impl ByteClass {
    fn from_ranges<I>(
        ranges: I,
        role: &'static str,
        budget: &mut BuildTraversalBudget,
    ) -> Result<(Self, usize), BuildError>
    where
        I: IntoIterator<Item = (u8, u8)>,
    {
        let mut class = Self::default();
        let mut previous_end = None;
        let mut range_count = 0_usize;
        for (start, end) in ranges {
            budget.charge_range()?;
            range_count = range_count
                .checked_add(1)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "per-class source range count",
                })?;
            if start > end {
                return Err(BuildError::ReversedRange { role, start, end });
            }
            if previous_end.is_some_and(|previous| previous >= start) {
                return Err(BuildError::NonCanonicalRanges { role });
            }
            previous_end = Some(end);
            let first_word = usize::from(start) >> 6;
            let last_word = usize::from(end) >> 6;
            for word in first_word..=last_word {
                let first_bit = if word == first_word {
                    u32::from(start) & 63
                } else {
                    0
                };
                let last_bit = if word == last_word {
                    u32::from(end) & 63
                } else {
                    63
                };
                let left =
                    u64::MAX
                        .checked_shl(first_bit)
                        .ok_or(BuildError::ArithmeticOverflow {
                            computation: "byte-class left mask",
                        })?;
                let right_shift =
                    63_u32
                        .checked_sub(last_bit)
                        .ok_or(BuildError::ArithmeticOverflow {
                            computation: "byte-class right shift",
                        })?;
                let right =
                    u64::MAX
                        .checked_shr(right_shift)
                        .ok_or(BuildError::ArithmeticOverflow {
                            computation: "byte-class right mask",
                        })?;
                class.words[word] |= left & right;
            }
        }
        Ok((class, range_count))
    }

    fn contains(self, byte: u8) -> bool {
        let word = usize::from(byte) >> 6;
        let bit = u32::from(byte) & 63;
        self.words[word] & (1_u64 << bit) != 0
    }

    fn overlaps(self, other: Self) -> bool {
        self.words
            .iter()
            .zip(other.words)
            .any(|(left, right)| left & right != 0)
    }

    fn is_empty(self) -> bool {
        self.words.iter().all(|&word| word == 0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationIdentity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub prefix_width: u32,
    pub left_gap_max: u32,
    pub right_gap_max: u32,
    pub tail_width: u32,
    pub greedy: bool,
    pub non_overlapping: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    pub max_source_ranges: usize,
    pub max_literal_bytes: usize,
    pub max_repeat_bound: u32,
    pub max_gap_bound: u32,
    pub max_build_work: usize,
    pub max_scratch_bytes: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl Default for BuildLimits {
    fn default() -> Self {
        Self {
            max_source_ranges: 256,
            max_literal_bytes: 1 << 20,
            max_repeat_bound: 1_000,
            max_gap_bound: 1_000,
            max_build_work: 16 << 20,
            max_scratch_bytes: 8 << 20,
            max_persistent_bytes: 16 << 20,
            max_peak_bytes: 24 << 20,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    pub prefix_ranges: usize,
    pub separator_ranges: usize,
    pub tail_ranges: usize,
    pub source_ranges: usize,
    pub literal_bytes: usize,
    pub prefix_width: u32,
    pub left_gap_max: u32,
    pub right_gap_max: u32,
    pub tail_width: u32,
    pub work: usize,
    pub temporary_capacity_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceLimits {
    pub max_input_bytes: usize,
    pub max_work: usize,
    pub max_match_events: usize,
    pub max_count: u64,
    pub max_scratch_bytes: usize,
    pub max_peak_bytes: usize,
}

impl Default for ReduceLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 128 << 20,
            max_work: 1 << 29,
            max_match_events: 128 << 20,
            max_count: 128 << 20,
            max_scratch_bytes: 512 << 20,
            max_peak_bytes: 640 << 20,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceUpperBounds {
    pub input_bytes: usize,
    pub literal_bytes: usize,
    pub interval_records: usize,
    pub interval_bytes: usize,
    pub inspections: usize,
    pub branches: usize,
    pub comparisons: usize,
    pub state_writes: usize,
    pub work: usize,
    pub match_events: usize,
    pub count: u64,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceActualCounters {
    pub suffix_intervals: usize,
    pub literal_occurrences: usize,
    pub successful_literals: usize,
    pub prefix_candidates: usize,
    pub match_events: usize,
    pub count: u64,
}

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

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    EmptyClass {
        role: &'static str,
    },
    EmptyLiteral,
    FixedWidthTooSmall {
        role: &'static str,
        needed: u32,
        minimum: u32,
    },
    RepeatLimit {
        needed: u32,
        limit: u32,
    },
    GapLimit {
        needed: u32,
        limit: u32,
    },
    RangeLimit {
        needed: usize,
        limit: usize,
    },
    LiteralLimit {
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
    ReversedRange {
        role: &'static str,
        start: u8,
        end: u8,
    },
    NonCanonicalRanges {
        role: &'static str,
    },
    OverlappingSeparator {
        role: &'static str,
    },
    LiteralStartsInSeparator {
        byte: u8,
    },
    OverlappingLiteral {
        repeated_first: u8,
    },
    AllocationFailed {
        structure: &'static str,
        additional: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "bounded-context construction failed: {self:?}")
    }
}

impl std::error::Error for BuildError {}

struct BuildTraversalBudget {
    source_ranges: usize,
    work: usize,
    max_source_ranges: usize,
    max_work: usize,
}

impl BuildTraversalBudget {
    fn new(literal_bytes: usize, limits: BuildLimits) -> Result<Self, BuildError> {
        let work = literal_bytes
            .checked_mul(8)
            .and_then(|value| value.checked_add(64))
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "build work",
            })?;
        if work > limits.max_build_work {
            return Err(BuildError::WorkLimit {
                needed: work,
                limit: limits.max_build_work,
            });
        }
        Ok(Self {
            source_ranges: 0,
            work,
            max_source_ranges: limits.max_source_ranges,
            max_work: limits.max_build_work,
        })
    }

    fn charge_range(&mut self) -> Result<(), BuildError> {
        let source_ranges =
            self.source_ranges
                .checked_add(1)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "source range count",
                })?;
        if source_ranges > self.max_source_ranges {
            return Err(BuildError::RangeLimit {
                needed: source_ranges,
                limit: self.max_source_ranges,
            });
        }
        let work = self
            .work
            .checked_add(6)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "build work",
            })?;
        if work > self.max_work {
            return Err(BuildError::WorkLimit {
                needed: work,
                limit: self.max_work,
            });
        }
        self.source_ranges = source_ranges;
        self.work = work;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReduceError {
    InputLimit {
        needed: usize,
        limit: usize,
    },
    WorkLimit {
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
    ScratchLimit {
        needed: usize,
        limit: usize,
    },
    PeakLimit {
        needed: usize,
        limit: usize,
    },
    AllocationFailed {
        structure: &'static str,
        additional: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for ReduceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "bounded-context reduction failed: {self:?}")
    }
}

impl std::error::Error for ReduceError {}

#[derive(Debug)]
pub struct BoundedContextPlan {
    prefix: ByteClass,
    separator: ByteClass,
    tail: ByteClass,
    finder: Finder<'static>,
    prefix_width: u32,
    left_gap_max: u32,
    right_gap_max: u32,
    tail_width: u32,
    build: BuildAccounting,
}

impl BoundedContextPlan {
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "construction keeps the complete admitted shape, fail-closed resource preflight, and accounting in one auditable transaction"
    )]
    pub fn build<Prefix, Separator, Tail>(
        prefix: Prefix,
        separator: Separator,
        tail: Tail,
        literal: &[u8],
        prefix_width: u32,
        left_gap_max: u32,
        right_gap_max: u32,
        tail_width: u32,
        limits: BuildLimits,
    ) -> Result<Self, BuildError>
    where
        Prefix: IntoIterator<Item = (u8, u8)>,
        Separator: IntoIterator<Item = (u8, u8)>,
        Tail: IntoIterator<Item = (u8, u8)>,
    {
        if literal.is_empty() {
            return Err(BuildError::EmptyLiteral);
        }
        for (role, width) in [("prefix", prefix_width), ("tail", tail_width)] {
            if width < MIN_FIXED_WIDTH {
                return Err(BuildError::FixedWidthTooSmall {
                    role,
                    needed: width,
                    minimum: MIN_FIXED_WIDTH,
                });
            }
            if width > limits.max_repeat_bound {
                return Err(BuildError::RepeatLimit {
                    needed: width,
                    limit: limits.max_repeat_bound,
                });
            }
        }
        for gap in [left_gap_max, right_gap_max] {
            if gap > limits.max_gap_bound {
                return Err(BuildError::GapLimit {
                    needed: gap,
                    limit: limits.max_gap_bound,
                });
            }
        }
        if literal.len() > limits.max_literal_bytes {
            return Err(BuildError::LiteralLimit {
                needed: literal.len(),
                limit: limits.max_literal_bytes,
            });
        }
        let persistent_bytes =
            size_of::<Self>()
                .checked_add(literal.len())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "persistent bytes",
                })?;
        let peak_bytes =
            persistent_bytes
                .checked_add(literal.len())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "construction peak bytes",
                })?;
        if literal.len() > limits.max_scratch_bytes {
            return Err(BuildError::ScratchLimit {
                needed: literal.len(),
                limit: limits.max_scratch_bytes,
            });
        }
        if persistent_bytes > limits.max_persistent_bytes {
            return Err(BuildError::PersistentLimit {
                needed: persistent_bytes,
                limit: limits.max_persistent_bytes,
            });
        }
        if peak_bytes > limits.max_peak_bytes {
            return Err(BuildError::PeakLimit {
                needed: peak_bytes,
                limit: limits.max_peak_bytes,
            });
        }

        // Each actual yielded range is charged before validation or bitmap
        // mutation. In particular, a caller-provided iterator's `len` or size
        // hint is never trusted for either admission or accounting.
        let mut budget = BuildTraversalBudget::new(literal.len(), limits)?;
        let (prefix_class, prefix_ranges) = ByteClass::from_ranges(prefix, "prefix", &mut budget)?;
        let (separator_class, separator_ranges) =
            ByteClass::from_ranges(separator, "separator", &mut budget)?;
        let (tail_class, tail_ranges) = ByteClass::from_ranges(tail, "tail", &mut budget)?;
        if prefix_class.is_empty() {
            return Err(BuildError::EmptyClass { role: "prefix" });
        }
        if separator_class.is_empty() {
            return Err(BuildError::EmptyClass { role: "separator" });
        }
        if tail_class.is_empty() {
            return Err(BuildError::EmptyClass { role: "tail" });
        }
        let source_ranges = budget.source_ranges;
        let work = budget.work;
        if separator_class.overlaps(prefix_class) {
            return Err(BuildError::OverlappingSeparator { role: "prefix" });
        }
        if separator_class.overlaps(tail_class) {
            return Err(BuildError::OverlappingSeparator { role: "tail" });
        }
        if separator_class.contains(literal[0]) {
            return Err(BuildError::LiteralStartsInSeparator { byte: literal[0] });
        }
        if literal[1..].contains(&literal[0]) {
            return Err(BuildError::OverlappingLiteral {
                repeated_first: literal[0],
            });
        }
        let owned = copy_exact(literal)
            .map_err(|error| allocation_build_error(error, "retained literal", literal.len()))?;
        let finder = FinderBuilder::new().build_forward_owned(owned.into_boxed_slice());
        Ok(Self {
            prefix: prefix_class,
            separator: separator_class,
            tail: tail_class,
            finder,
            prefix_width,
            left_gap_max,
            right_gap_max,
            tail_width,
            build: BuildAccounting {
                prefix_ranges,
                separator_ranges,
                tail_ranges,
                source_ranges,
                literal_bytes: literal.len(),
                prefix_width,
                left_gap_max,
                right_gap_max,
                tail_width,
                work,
                temporary_capacity_bytes: literal.len(),
                persistent_bytes,
                peak_bytes,
            },
        })
    }

    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.build
    }

    #[must_use]
    pub const fn count_identity(&self) -> OperationIdentity {
        OperationIdentity {
            plan_id: PLAN_ID,
            operation_id: COUNT_OPERATION_ID,
            prefix_width: self.prefix_width,
            left_gap_max: self.left_gap_max,
            right_gap_max: self.right_gap_max,
            tail_width: self.tail_width,
            greedy: true,
            non_overlapping: true,
        }
    }

    pub fn count(&self, haystack: &[u8], limits: ReduceLimits) -> Result<CountResult, ReduceError> {
        let upper_bounds = self.preflight(haystack.len(), limits)?;
        let scratch = zeroed_exact(upper_bounds.scratch_bytes).map_err(|error| {
            allocation_reduce_error(error, "suffix interval table", upper_bounds.scratch_bytes)
        })?;
        let actual = self.execute_with(haystack, scratch, |_start, _end| {})?;
        Ok(CountResult {
            count: actual.count,
            accounting: ReduceAccounting {
                identity: self.count_identity(),
                upper_bounds,
                actual,
            },
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the upper-bound certificate computes and validates every named resource dimension together"
    )]
    fn preflight(
        &self,
        input_bytes: usize,
        limits: ReduceLimits,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        let u32_max = usize::try_from(u32::MAX).unwrap_or(usize::MAX);
        if input_bytes > limits.max_input_bytes || input_bytes > u32_max {
            return Err(ReduceError::InputLimit {
                needed: input_bytes,
                limit: limits.max_input_bytes.min(u32_max),
            });
        }
        let literal_bytes = self.finder.needle().len();
        let tail_width =
            usize::try_from(self.tail_width).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "tail width as usize",
            })?;
        let interval_records = input_bytes
            .checked_div(
                tail_width
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "interval denominator",
                    })?,
            )
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "interval record bound",
            })?;
        let interval_bytes = interval_records.checked_mul(INTERVAL_BYTES).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "interval bytes",
            },
        )?;
        let inspections = input_bytes
            .checked_mul(3)
            .and_then(|value| value.checked_add(literal_bytes))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "inspection bound",
            })?;
        let branches = input_bytes
            .checked_mul(8)
            .and_then(|value| {
                literal_bytes
                    .checked_mul(4)
                    .and_then(|term| value.checked_add(term))
            })
            .and_then(|value| value.checked_add(16))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "branch bound",
            })?;
        let comparisons = input_bytes
            .checked_mul(6)
            .and_then(|value| {
                literal_bytes
                    .checked_mul(4)
                    .and_then(|term| value.checked_add(term))
            })
            .and_then(|value| value.checked_add(8))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "comparison bound",
            })?;
        let state_writes = input_bytes
            .checked_mul(4)
            .and_then(|value| {
                literal_bytes
                    .checked_mul(2)
                    .and_then(|term| value.checked_add(term))
            })
            .and_then(|value| value.checked_add(16))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "state-write bound",
            })?;
        let work = input_bytes
            .checked_mul(21)
            .and_then(|value| {
                literal_bytes
                    .checked_mul(11)
                    .and_then(|term| value.checked_add(term))
            })
            .and_then(|value| {
                interval_bytes
                    .checked_mul(3)
                    .and_then(|term| value.checked_add(term))
            })
            .and_then(|value| value.checked_add(40))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "execution work",
            })?;
        let minimum_match_bytes = usize::try_from(self.prefix_width)
            .ok()
            .and_then(|prefix| prefix.checked_add(1))
            .and_then(|value| value.checked_add(literal_bytes))
            .and_then(|value| value.checked_add(1))
            .and_then(|value| {
                usize::try_from(self.tail_width)
                    .ok()
                    .and_then(|tail| value.checked_add(tail))
            })
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "minimum match bytes",
            })?;
        let match_events = input_bytes.checked_div(minimum_match_bytes).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "match event bound",
            },
        )?;
        let count = u64::try_from(match_events).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "count bound",
        })?;
        let peak_bytes = self
            .build
            .persistent_bytes
            .checked_add(interval_bytes)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "execution peak bytes",
            })?;
        enforce_reduce(work, limits.max_work, ReduceResource::Work)?;
        enforce_reduce(
            match_events,
            limits.max_match_events,
            ReduceResource::MatchEvents,
        )?;
        if count > limits.max_count {
            return Err(ReduceError::CountLimit {
                needed: count,
                limit: limits.max_count,
            });
        }
        enforce_reduce(
            interval_bytes,
            limits.max_scratch_bytes,
            ReduceResource::Scratch,
        )?;
        enforce_reduce(peak_bytes, limits.max_peak_bytes, ReduceResource::Peak)?;
        Ok(ReduceUpperBounds {
            input_bytes,
            literal_bytes,
            interval_records,
            interval_bytes,
            inspections,
            branches,
            comparisons,
            state_writes,
            work,
            match_events,
            count,
            scratch_bytes: interval_bytes,
            persistent_bytes: self.build.persistent_bytes,
            peak_bytes,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the three monotone streams share state whose ordering establishes the linear-time and non-overlap proof"
    )]
    fn execute_with(
        &self,
        haystack: &[u8],
        mut intervals: Vec<u8>,
        mut observe: impl FnMut(usize, usize),
    ) -> Result<ReduceActualCounters, ReduceError> {
        let interval_count = self.write_suffix_intervals(haystack, &mut intervals)?;
        let mut interval_cursor = 0_usize;
        let mut latest_interval = None;
        let mut prefix_scanner = PrefixScanner::default();
        let mut pending_prefix = self.next_prefix(haystack, &mut prefix_scanner)?;
        let mut latest_good: Option<GoodLiteral> = None;
        let mut literal_occurrences = 0_usize;
        let mut successful_literals = 0_usize;
        let mut prefix_candidates = usize::from(pending_prefix.is_some());
        let mut match_events = 0_usize;

        for literal_start in self.finder.find_iter(haystack) {
            literal_occurrences =
                literal_occurrences
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "literal occurrence count",
                    })?;
            let literal_end = literal_start
                .checked_add(self.finder.needle().len())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "literal end",
                })?;
            let right_gap = usize::try_from(self.right_gap_max).map_err(|_| {
                ReduceError::ArithmeticOverflow {
                    computation: "right gap as usize",
                }
            })?;
            let suffix_upper = literal_end.saturating_add(right_gap).min(haystack.len());
            while interval_cursor < interval_count {
                let interval = read_interval(&intervals, interval_cursor)?;
                if interval.start > suffix_upper {
                    break;
                }
                latest_interval = Some(interval);
                interval_cursor =
                    interval_cursor
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "interval cursor",
                        })?;
            }
            let Some(interval) = latest_interval else {
                continue;
            };
            let suffix_start = suffix_upper.min(interval.end.saturating_sub(1));
            if suffix_start < literal_end || suffix_start < interval.start {
                continue;
            }
            let good = GoodLiteral {
                start: literal_start,
                match_end: interval.match_end,
            };
            successful_literals =
                successful_literals
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "successful literal count",
                    })?;

            while pending_prefix.is_some_and(|candidate| candidate.upper < good.start) {
                let Some(candidate) = pending_prefix.take() else {
                    break;
                };
                if let Some(selected) = latest_good.filter(|selected| {
                    selected.start >= candidate.lower && selected.start <= candidate.upper
                }) {
                    match_events =
                        match_events
                            .checked_add(1)
                            .ok_or(ReduceError::ArithmeticOverflow {
                                computation: "match event count",
                            })?;
                    observe(candidate.start, selected.match_end);
                    prefix_scanner.skip_to(selected.match_end);
                    latest_good = None;
                }
                pending_prefix = self.next_prefix(haystack, &mut prefix_scanner)?;
                prefix_candidates = prefix_candidates
                    .checked_add(usize::from(pending_prefix.is_some()))
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "prefix candidate count",
                    })?;
            }
            latest_good = Some(good);
        }

        while let Some(candidate) = pending_prefix.take() {
            if let Some(selected) = latest_good.filter(|selected| {
                selected.start >= candidate.lower && selected.start <= candidate.upper
            }) {
                match_events =
                    match_events
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "final match event count",
                        })?;
                observe(candidate.start, selected.match_end);
                prefix_scanner.skip_to(selected.match_end);
                latest_good = None;
            }
            pending_prefix = self.next_prefix(haystack, &mut prefix_scanner)?;
            prefix_candidates = prefix_candidates
                .checked_add(usize::from(pending_prefix.is_some()))
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "final prefix candidate count",
                })?;
        }
        let count = u64::try_from(match_events).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "actual count",
        })?;
        Ok(ReduceActualCounters {
            suffix_intervals: interval_count,
            literal_occurrences,
            successful_literals,
            prefix_candidates,
            match_events,
            count,
        })
    }

    fn write_suffix_intervals(
        &self,
        haystack: &[u8],
        storage: &mut [u8],
    ) -> Result<usize, ReduceError> {
        let tail_width =
            usize::try_from(self.tail_width).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "tail width as usize",
            })?;
        let mut cursor = 0_usize;
        let mut records = 0_usize;
        while cursor < haystack.len() {
            if !self.separator.contains(haystack[cursor]) {
                cursor = cursor
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "suffix scan cursor",
                    })?;
                continue;
            }
            let start = cursor;
            while cursor < haystack.len() && self.separator.contains(haystack[cursor]) {
                cursor = cursor
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "separator run cursor",
                    })?;
            }
            let end = cursor;
            while cursor < haystack.len() && self.tail.contains(haystack[cursor]) {
                cursor = cursor
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "tail run cursor",
                    })?;
            }
            if cursor.saturating_sub(end) >= tail_width {
                let match_end =
                    end.checked_add(tail_width)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "suffix match end",
                        })?;
                write_interval(
                    storage,
                    records,
                    Interval {
                        start,
                        end,
                        match_end,
                    },
                )?;
                records = records
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "suffix interval count",
                    })?;
            }
        }
        Ok(records)
    }

    fn next_prefix(
        &self,
        haystack: &[u8],
        scanner: &mut PrefixScanner,
    ) -> Result<Option<PrefixCandidate>, ReduceError> {
        let width =
            usize::try_from(self.prefix_width).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "prefix width as usize",
            })?;
        while scanner.cursor < haystack.len() {
            let byte = haystack[scanner.cursor];
            if self.prefix.contains(byte) {
                scanner.prefix_run =
                    scanner
                        .prefix_run
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "prefix run length",
                        })?;
                scanner.cursor =
                    scanner
                        .cursor
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "prefix scan cursor",
                        })?;
                continue;
            }
            if self.separator.contains(byte) {
                let separator_start = scanner.cursor;
                while scanner.cursor < haystack.len()
                    && self.separator.contains(haystack[scanner.cursor])
                {
                    scanner.cursor =
                        scanner
                            .cursor
                            .checked_add(1)
                            .ok_or(ReduceError::ArithmeticOverflow {
                                computation: "prefix separator cursor",
                            })?;
                }
                let separator_end = scanner.cursor;
                let prefix_run = core::mem::take(&mut scanner.prefix_run);
                if prefix_run >= width {
                    let start = separator_start.checked_sub(width).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "prefix candidate start",
                        },
                    )?;
                    let left_gap = usize::try_from(self.left_gap_max).map_err(|_| {
                        ReduceError::ArithmeticOverflow {
                            computation: "left gap as usize",
                        }
                    })?;
                    let upper = separator_end.saturating_add(left_gap).min(haystack.len());
                    return Ok(Some(PrefixCandidate {
                        start,
                        lower: separator_end,
                        upper,
                    }));
                }
                continue;
            }
            scanner.prefix_run = 0;
            scanner.cursor =
                scanner
                    .cursor
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "prefix nonclass cursor",
                    })?;
        }
        Ok(None)
    }

    #[cfg(test)]
    fn spans_for_test(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<Vec<(usize, usize)>, ReduceError> {
        let upper = self.preflight(haystack.len(), limits)?;
        let scratch = zeroed_exact(upper.scratch_bytes).map_err(|error| {
            allocation_reduce_error(error, "test suffix interval table", upper.scratch_bytes)
        })?;
        let mut spans = Vec::new();
        self.execute_with(haystack, scratch, |start, end| spans.push((start, end)))?;
        Ok(spans)
    }
}

#[derive(Clone, Copy)]
struct Interval {
    start: usize,
    end: usize,
    match_end: usize,
}

#[derive(Clone, Copy)]
struct GoodLiteral {
    start: usize,
    match_end: usize,
}

#[derive(Clone, Copy)]
struct PrefixCandidate {
    start: usize,
    lower: usize,
    upper: usize,
}

#[derive(Default)]
struct PrefixScanner {
    cursor: usize,
    prefix_run: usize,
}

impl PrefixScanner {
    fn skip_to(&mut self, position: usize) {
        self.cursor = self.cursor.max(position);
        self.prefix_run = 0;
    }
}

fn write_interval(storage: &mut [u8], index: usize, interval: Interval) -> Result<(), ReduceError> {
    let offset = index
        .checked_mul(INTERVAL_BYTES)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "interval write offset",
        })?;
    let end = offset
        .checked_add(INTERVAL_BYTES)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "interval write end",
        })?;
    let record = storage
        .get_mut(offset..end)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "interval capacity proof",
        })?;
    write_interval_field(record, 0, interval.start)?;
    write_interval_field(record, 4, interval.end)?;
    write_interval_field(record, 8, interval.match_end)?;
    Ok(())
}

fn write_interval_field(record: &mut [u8], offset: usize, field: usize) -> Result<(), ReduceError> {
    let value = u32::try_from(field).map_err(|_| ReduceError::ArithmeticOverflow {
        computation: "interval field as u32",
    })?;
    let end = offset
        .checked_add(size_of::<u32>())
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "interval field write end",
        })?;
    let destination = record
        .get_mut(offset..end)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "interval field write capacity",
        })?;
    destination.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn read_interval(storage: &[u8], index: usize) -> Result<Interval, ReduceError> {
    let offset = index
        .checked_mul(INTERVAL_BYTES)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "interval read offset",
        })?;
    let end = offset
        .checked_add(INTERVAL_BYTES)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "interval read end",
        })?;
    let record = storage
        .get(offset..end)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "interval read capacity",
        })?;
    Ok(Interval {
        start: read_interval_field(record, 0)?,
        end: read_interval_field(record, 4)?,
        match_end: read_interval_field(record, 8)?,
    })
}

fn read_interval_field(record: &[u8], start: usize) -> Result<usize, ReduceError> {
    let end = start
        .checked_add(size_of::<u32>())
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "interval field read end",
        })?;
    let source = record
        .get(start..end)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "interval field read capacity",
        })?;
    let bytes: [u8; 4] = source
        .try_into()
        .map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "interval field width",
        })?;
    usize::try_from(u32::from_le_bytes(bytes)).map_err(|_| ReduceError::ArithmeticOverflow {
        computation: "interval field as usize",
    })
}

fn allocation_build_error(
    error: CopyError,
    structure: &'static str,
    additional: usize,
) -> BuildError {
    match error {
        CopyError::LayoutOverflow => BuildError::ArithmeticOverflow {
            computation: "exact literal allocation layout",
        },
        CopyError::AllocationFailed => BuildError::AllocationFailed {
            structure,
            additional,
        },
    }
}

fn allocation_reduce_error(
    error: CopyError,
    structure: &'static str,
    additional: usize,
) -> ReduceError {
    match error {
        CopyError::LayoutOverflow => ReduceError::ArithmeticOverflow {
            computation: "exact suffix allocation layout",
        },
        CopyError::AllocationFailed => ReduceError::AllocationFailed {
            structure,
            additional,
        },
    }
}

#[derive(Clone, Copy)]
enum ReduceResource {
    Work,
    MatchEvents,
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
        ReduceResource::Work => ReduceError::WorkLimit { needed, limit },
        ReduceResource::MatchEvents => ReduceError::MatchEventsLimit { needed, limit },
        ReduceResource::Scratch => ReduceError::ScratchLimit { needed, limit },
        ReduceResource::Peak => ReduceError::PeakLimit { needed, limit },
    })
}

#[cfg(test)]
mod tests {
    use regex::bytes::RegexBuilder;

    use super::{BoundedContextPlan, BuildError, BuildLimits, ReduceError, ReduceLimits};

    #[derive(Clone)]
    struct DeceptiveRanges<'a> {
        ranges: &'a [(u8, u8)],
        cursor: usize,
        reported_len: usize,
    }

    impl<'a> DeceptiveRanges<'a> {
        const fn new(ranges: &'a [(u8, u8)], reported_len: usize) -> Self {
            Self {
                ranges,
                cursor: 0,
                reported_len,
            }
        }
    }

    impl Iterator for DeceptiveRanges<'_> {
        type Item = (u8, u8);

        fn next(&mut self) -> Option<Self::Item> {
            let next = self.ranges.get(self.cursor).copied();
            self.cursor = self.cursor.saturating_add(usize::from(next.is_some()));
            next
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            let claimed = self.reported_len.saturating_sub(self.cursor);
            (claimed, Some(claimed))
        }
    }

    impl ExactSizeIterator for DeceptiveRanges<'_> {}

    fn plan() -> BoundedContextPlan {
        BoundedContextPlan::build(
            [(b'a', b'z')],
            [(b' ', b' ')],
            [(b'a', b'z')],
            b"R",
            4,
            2,
            2,
            4,
            BuildLimits::default(),
        )
        .unwrap()
    }

    fn oracle(pattern: &str, haystack: &[u8]) -> Vec<(usize, usize)> {
        RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap()
            .find_iter(haystack)
            .map(|matched| (matched.start(), matched.end()))
            .collect()
    }

    #[test]
    fn deceptive_exact_size_iterator_is_charged_by_actual_yields() {
        // The prefix advertises one range but yields two. Along with the one
        // separator and one tail range, exact construction therefore needs
        // four ranges and 8*1 + 6*4 + 64 = 96 work units.
        let prefix = [(b'a', b'a'), (b'c', b'c')];
        let build = |limits| {
            BoundedContextPlan::build(
                DeceptiveRanges::new(&prefix, 1),
                [(b' ', b' ')],
                [(b'x', b'z')],
                b"R",
                2,
                2,
                2,
                2,
                limits,
            )
        };
        let exact_limits = BuildLimits {
            max_source_ranges: 4,
            max_build_work: 96,
            ..BuildLimits::default()
        };
        let exact = build(exact_limits).unwrap();
        assert_eq!(exact.build_accounting().prefix_ranges, 2);
        assert_eq!(exact.build_accounting().source_ranges, 4);
        assert_eq!(exact.build_accounting().work, 96);

        assert!(matches!(
            build(BuildLimits {
                max_source_ranges: 3,
                ..exact_limits
            }),
            Err(BuildError::RangeLimit {
                needed: 4,
                limit: 3
            })
        ));
        assert!(matches!(
            build(BuildLimits {
                max_build_work: 95,
                ..exact_limits
            }),
            Err(BuildError::WorkLimit {
                needed: 96,
                limit: 95
            })
        ));
    }

    #[test]
    fn rebar_row_curated_10_bounded_repeat_context_exact_limit_and_one_below() {
        // rebar-row:curated/10-bounded-repeat/context@rust/regex
        // Hand witness (not SUT-derived): for `[a-z]{2} +.{0,2}R.{0,2} +[a-z]{2}`
        // on `aa R bb`, N=7, L=1, T=2, S=12*floor(7/3)=24, hence
        // W=21*7+11*1+3*24+40=270. Limit 270 admits span 0..7/count 1;
        // limit 269 refuses before allocation or input inspection.
        let witness = BoundedContextPlan::build(
            [(b'a', b'z')],
            [(b' ', b' ')],
            [(b'a', b'z')],
            b"R",
            2,
            2,
            2,
            2,
            BuildLimits::default(),
        )
        .unwrap();
        let haystack = b"aa R bb";
        let exact = witness
            .count(
                haystack,
                ReduceLimits {
                    max_work: 270,
                    ..ReduceLimits::default()
                },
            )
            .unwrap();
        assert_eq!(exact.count, 1);
        assert_eq!(
            witness
                .spans_for_test(haystack, ReduceLimits::default())
                .unwrap(),
            vec![(0, 7)]
        );
        let needed = exact.accounting.upper_bounds.work;
        let refused = witness.count(
            haystack,
            ReduceLimits {
                max_work: needed - 1,
                ..ReduceLimits::default()
            },
        );
        assert!(matches!(refused, Err(ReduceError::WorkLimit { .. })));
    }

    #[test]
    fn rebar_row_curated_10_bounded_repeat_context_complete_spans_cover_bytes() {
        // rebar-row:curated/10-bounded-repeat/context@rust/regex
        let plan = plan();
        let pattern = r"[a-z]{4} +.{0,2}R.{0,2} +[a-z]{4}";
        for haystack in [
            b"aaaa R bbbb".as_slice(),
            b"xx aaaa 12R34 bbbb yy cccc R dddd".as_slice(),
            b"aaaa \xFFR\xFE bbbb".as_slice(),
            b"aaaa 12R345 bbbb".as_slice(),
            b"aaaa 12R34 bbb".as_slice(),
        ] {
            assert_eq!(
                plan.spans_for_test(haystack, ReduceLimits::default())
                    .unwrap(),
                oracle(pattern, haystack)
            );
        }
    }

    #[test]
    fn rebar_row_curated_10_bounded_repeat_context_linear_scaling_bounds() {
        // rebar-row:curated/10-bounded-repeat/context@rust/regex
        // For the ledger adversary L=1,T=2:
        // W(32)=1083, W(64)=2151, W(128)=4251. Compiler/build traversal is
        // C<=9Q+64, so Q/2Q/4Q at 64/128/256 are <=640/1216/2368.
        for (n, expected) in [(32, 1083), (64, 2151), (128, 4251)] {
            let interval_bytes = 12 * (n / 3);
            assert_eq!(21 * n + 11 + 3 * interval_bytes + 40, expected);
        }
    }
}
