//! Direct whole-operation reduction for one fixed-width three-class sequence.
//!
//! The admitted shape is `PREFIX MIDDLE{N} SUFFIX` for `N > 0`. Unicode-off
//! plans consume one byte per unit. Unicode-on plans decode each valid UTF-8
//! scalar once; invalid bytes break the pending window and advance one byte.
//! Plans of at most 64 units compile the three classes into a 256-entry
//! scalar-category table and eight position masks. Byte operations and Unicode
//! count operations then use one Shift-And recurrence without operation-time
//! allocation; Unicode scalars above U+00FF retain bounded binary search over
//! scalar ranges. Longer byte plans whose retained middle and suffix masks are
//! disjoint scan suffix candidates and amortize backward middle probes over
//! the source with no operation allocation. Other longer plans, and Unicode
//! operations that emit spans, retain a circular `N + 2` unit window. Every
//! reducer emits the same leftmost non-overlapping sequence and never
//! constructs a boundary-indexed continuation log.

use core::{fmt, mem::size_of};

use crate::{DirectBuildAttempt, DirectBuildAttemptActual, DirectBuildAttemptError, Window};

pub const PLAN_ID: &str =
    "fixed-class-sandwich.scalar-shift-and-disjoint-suffix-or-circular-window.v5";
pub const COUNT_OPERATION_ID: &str = "fixed-class-sandwich.count.v5";
pub const SPAN_SUM_OPERATION_ID: &str = "fixed-class-sandwich.span-sum.v5";
/// Stable identity of allocation-free complete-span visitation.
pub const SPAN_VISIT_OPERATION_ID: &str = "fixed-class-sandwich.span-visit.v3";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Semantics {
    RustBytesUnicodeOff,
    RustBytesUnicodeUtf8False,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Count,
    SpanSum,
    SpanVisit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationIdentity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub operation: Operation,
    pub semantics: Semantics,
    pub middle_repetitions: u32,
    pub non_overlapping: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    pub max_source_ranges: usize,
    pub max_middle_repetitions: u32,
    pub max_build_work: usize,
    pub max_scratch_bytes: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl Default for BuildLimits {
    fn default() -> Self {
        Self {
            max_source_ranges: 1 << 16,
            max_middle_repetitions: 1 << 16,
            max_build_work: 1 << 20,
            max_scratch_bytes: 1 << 20,
            max_persistent_bytes: 1 << 20,
            max_peak_bytes: 2 << 20,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    pub semantics: Semantics,
    pub prefix_ranges: usize,
    pub middle_ranges: usize,
    pub suffix_ranges: usize,
    pub source_ranges: usize,
    pub middle_repetitions: u32,
    pub window_units: usize,
    pub range_payload_bytes: usize,
    pub work: usize,
    pub temporary_capacity_bytes: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

struct DirectBuildTracker {
    actual: DirectBuildAttemptActual,
    live_unpublished_bytes: usize,
}

impl DirectBuildTracker {
    const fn new() -> Self {
        Self {
            actual: DirectBuildAttemptActual {
                work: 0,
                allocations: 0,
                allocated_bytes: 0,
                copied_bytes: 0,
                initialized_bytes: 0,
                live_persistent_bytes: 0,
                peak_bytes: 0,
            },
            live_unpublished_bytes: 0,
        }
    }

    fn record_work(&mut self, work: usize) -> Result<(), BuildError> {
        self.actual.work = u64::try_from(work).map_err(|_| BuildError::ArithmeticOverflow {
            computation: "actual fixed-class work as u64",
        })?;
        Ok(())
    }

    fn observe_reserve(
        &mut self,
        before_capacity: usize,
        after_capacity: usize,
    ) -> Result<(), BuildError> {
        if after_capacity <= before_capacity {
            return Ok(());
        }
        let before = before_capacity
            .checked_mul(size_of::<ScalarRange>())
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "previous fixed-class capacity bytes",
            })?;
        let after = after_capacity.checked_mul(size_of::<ScalarRange>()).ok_or(
            BuildError::ArithmeticOverflow {
                computation: "observed fixed-class capacity bytes",
            },
        )?;
        self.actual.allocations =
            self.actual
                .allocations
                .checked_add(1)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "actual fixed-class allocation count",
                })?;
        self.actual.allocated_bytes = self.actual.allocated_bytes.checked_add(after).ok_or(
            BuildError::ArithmeticOverflow {
                computation: "cumulative fixed-class allocated bytes",
            },
        )?;
        self.live_unpublished_bytes = self
            .live_unpublished_bytes
            .checked_sub(before)
            .and_then(|bytes| bytes.checked_add(after))
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "live fixed-class capacity bytes",
            })?;
        self.actual.peak_bytes = self.actual.peak_bytes.max(self.live_unpublished_bytes);
        Ok(())
    }

    fn observe_range_copy(&mut self) -> Result<(), BuildError> {
        self.actual.copied_bytes = self
            .actual
            .copied_bytes
            .checked_add(size_of::<ScalarRange>())
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "actual fixed-class copied bytes",
            })?;
        self.actual.initialized_bytes = self
            .actual
            .initialized_bytes
            .checked_add(size_of::<ScalarRange>())
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "actual fixed-class initialized bytes",
            })?;
        Ok(())
    }

    fn publish(&mut self, persistent_bytes: usize) -> Result<(), BuildError> {
        self.actual.initialized_bytes = self
            .actual
            .initialized_bytes
            .checked_add(size_of::<FixedClassSandwichPlan>())
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "published fixed-class inline initialized bytes",
            })?;
        self.actual.live_persistent_bytes = persistent_bytes;
        self.actual.peak_bytes = self.actual.peak_bytes.max(persistent_bytes);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceLimits {
    pub max_input_bytes: usize,
    pub max_decode_byte_checks: usize,
    pub max_membership_tests: usize,
    pub max_range_comparisons: usize,
    pub max_reducer_steps: usize,
    pub max_match_events: usize,
    pub max_count: u64,
    pub max_span_sum: u64,
    pub max_work: usize,
    pub max_scratch_bytes: usize,
    pub max_peak_bytes: usize,
}

impl Default for ReduceLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 128 << 20,
            max_decode_byte_checks: 512 << 20,
            max_membership_tests: 384 << 20,
            max_range_comparisons: 2 << 30,
            max_reducer_steps: (128 << 20) + 1,
            max_match_events: 128 << 20,
            max_count: 128 << 20,
            max_span_sum: 128 << 20,
            max_work: usize::MAX,
            max_scratch_bytes: 1 << 20,
            max_peak_bytes: 3 << 20,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceUpperBounds {
    pub input_bytes: usize,
    pub decode_byte_checks: usize,
    pub membership_tests: usize,
    pub range_comparisons: usize,
    pub reducer_steps: usize,
    pub match_events: usize,
    pub count: u64,
    pub span_sum: u64,
    pub work: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceActualCounters {
    pub input_bytes_advanced: usize,
    pub decode_byte_checks: usize,
    pub valid_units: usize,
    pub invalid_bytes: usize,
    pub membership_tests: usize,
    pub range_comparisons: usize,
    pub reducer_steps: usize,
    pub window_resets: usize,
    pub match_events: usize,
    pub count: u64,
    pub matched_bytes: u64,
    pub work: usize,
    pub scratch_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceAccounting {
    pub identity: OperationIdentity,
    pub window: Window,
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

/// One complete non-overlapping match emitted by the reducer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompleteSpan {
    pub start: usize,
    pub end: usize,
}

/// Summary of one allocation-free complete-span traversal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanVisitResult {
    pub matches: usize,
    pub span_sum: u64,
    pub accounting: ReduceAccounting,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    EmptyClass {
        role: &'static str,
    },
    ZeroMiddleRepetitions,
    MiddleRepetitionLimit {
        needed: u32,
        limit: u32,
    },
    ReversedRange {
        role: &'static str,
        start: u32,
        end: u32,
    },
    RangeOutsideSemantics {
        role: &'static str,
        start: u32,
        end: u32,
    },
    NonCanonicalRanges {
        role: &'static str,
    },
    RangeLimit {
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
        role: &'static str,
        additional: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyClass { role } => write!(formatter, "fixed class {role} is empty"),
            Self::ZeroMiddleRepetitions => {
                formatter.write_str("fixed class middle repetition must be nonzero")
            }
            Self::MiddleRepetitionLimit { needed, limit } => write!(
                formatter,
                "fixed class middle repetition needs {needed}, limit is {limit}"
            ),
            Self::ReversedRange { role, start, end } => {
                write!(
                    formatter,
                    "fixed class {role} range {start:#X}..={end:#X} is reversed"
                )
            }
            Self::RangeOutsideSemantics { role, start, end } => write!(
                formatter,
                "fixed class {role} range {start:#X}..={end:#X} is outside its semantic domain"
            ),
            Self::NonCanonicalRanges { role } => {
                write!(formatter, "fixed class {role} ranges are not canonical")
            }
            Self::RangeLimit { needed, limit } => {
                write!(
                    formatter,
                    "fixed classes need {needed} ranges, limit is {limit}"
                )
            }
            Self::WorkLimit { needed, limit } => {
                write!(
                    formatter,
                    "fixed class build needs {needed} work, limit is {limit}"
                )
            }
            Self::ScratchLimit { needed, limit } => write!(
                formatter,
                "fixed class build needs {needed} scratch bytes, limit is {limit}"
            ),
            Self::PersistentLimit { needed, limit } => write!(
                formatter,
                "fixed class plan needs {needed} persistent bytes, limit is {limit}"
            ),
            Self::PeakLimit { needed, limit } => {
                write!(
                    formatter,
                    "fixed class build peaks at {needed} bytes, limit is {limit}"
                )
            }
            Self::AllocationFailed { role, additional } => write!(
                formatter,
                "failed to reserve {additional} ranges for fixed class {role}"
            ),
            Self::ArithmeticOverflow { computation } => {
                write!(
                    formatter,
                    "fixed class arithmetic overflow in {computation}"
                )
            }
        }
    }
}

impl std::error::Error for BuildError {}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReduceError {
    InvalidWindow {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
    InputBytesLimit {
        needed: usize,
        limit: usize,
    },
    DecodeByteChecksLimit {
        needed: usize,
        limit: usize,
    },
    MembershipTestsLimit {
        needed: usize,
        limit: usize,
    },
    RangeComparisonsLimit {
        needed: usize,
        limit: usize,
    },
    ReducerStepsLimit {
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
    WorkLimit {
        needed: usize,
        limit: usize,
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
        additional: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for ReduceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidWindow {
                start,
                end,
                haystack_len,
            } => write!(
                formatter,
                "invalid fixed class window {start}..{end} for {haystack_len} bytes"
            ),
            Self::InputBytesLimit { needed, limit } => {
                limit_message(formatter, "input bytes", *needed, *limit)
            }
            Self::DecodeByteChecksLimit { needed, limit } => {
                limit_message(formatter, "decode byte checks", *needed, *limit)
            }
            Self::MembershipTestsLimit { needed, limit } => {
                limit_message(formatter, "membership tests", *needed, *limit)
            }
            Self::RangeComparisonsLimit { needed, limit } => {
                limit_message(formatter, "range comparisons", *needed, *limit)
            }
            Self::ReducerStepsLimit { needed, limit } => {
                limit_message(formatter, "reducer steps", *needed, *limit)
            }
            Self::MatchEventsLimit { needed, limit } => {
                limit_message(formatter, "match events", *needed, *limit)
            }
            Self::CountLimit { needed, limit } => {
                limit_message(formatter, "count", *needed, *limit)
            }
            Self::SpanSumLimit { needed, limit } => {
                limit_message(formatter, "span sum", *needed, *limit)
            }
            Self::WorkLimit { needed, limit } => limit_message(formatter, "work", *needed, *limit),
            Self::ScratchLimit { needed, limit } => {
                limit_message(formatter, "scratch bytes", *needed, *limit)
            }
            Self::PeakLimit { needed, limit } => {
                limit_message(formatter, "peak bytes", *needed, *limit)
            }
            Self::AllocationFailed { additional } => write!(
                formatter,
                "failed to reserve {additional} fixed class window entries"
            ),
            Self::ArithmeticOverflow { computation } => {
                write!(
                    formatter,
                    "fixed class arithmetic overflow in {computation}"
                )
            }
        }
    }
}

impl std::error::Error for ReduceError {}

fn limit_message<T: fmt::Display>(
    formatter: &mut fmt::Formatter<'_>,
    resource: &str,
    needed: T,
    limit: T,
) -> fmt::Result {
    write!(
        formatter,
        "fixed class {resource} needs {needed}, limit is {limit}"
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ScalarRange {
    start: u32,
    end: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ByteClass {
    words: [u64; 4],
}

impl ByteClass {
    /// Project scalar ranges onto U+0000..=U+00FF. Byte-semantics ranges
    /// already lie wholly inside this domain; Unicode ranges are clipped so
    /// their common low scalars can share the same category table.
    fn from_ranges(
        ranges: &[ScalarRange],
        limits: BuildLimits,
        work: &mut usize,
        tracker: &mut DirectBuildTracker,
    ) -> Result<Self, BuildError> {
        let mut class = Self::default();
        for range in ranges {
            if range.start > u32::from(u8::MAX) {
                break;
            }
            let range_end = range.end.min(u32::from(u8::MAX));
            let first_word =
                usize::try_from(range.start >> 6).map_err(|_| BuildError::ArithmeticOverflow {
                    computation: "fixed class first byte-mask word",
                })?;
            let last_word =
                usize::try_from(range_end >> 6).map_err(|_| BuildError::ArithmeticOverflow {
                    computation: "fixed class last byte-mask word",
                })?;
            for word_index in first_word..=last_word {
                let first_bit = if word_index == first_word {
                    range.start & 63
                } else {
                    0
                };
                let last_bit = if word_index == last_word {
                    range_end & 63
                } else {
                    63
                };
                let last_shift =
                    63_u32
                        .checked_sub(last_bit)
                        .ok_or(BuildError::ArithmeticOverflow {
                            computation: "fixed class byte-mask last shift",
                        })?;
                let first_mask =
                    u64::MAX
                        .checked_shl(first_bit)
                        .ok_or(BuildError::ArithmeticOverflow {
                            computation: "fixed class byte-mask first shift",
                        })?;
                let last_mask =
                    u64::MAX
                        .checked_shr(last_shift)
                        .ok_or(BuildError::ArithmeticOverflow {
                            computation: "fixed class byte-mask last shift",
                        })?;
                let mask = first_mask & last_mask;
                let mask_word =
                    class
                        .words
                        .get_mut(word_index)
                        .ok_or(BuildError::ArithmeticOverflow {
                            computation: "fixed class byte-mask word access",
                        })?;
                *mask_word |= mask;
                *work = work.checked_add(1).ok_or(BuildError::ArithmeticOverflow {
                    computation: "fixed class byte-mask work",
                })?;
                enforce_build(*work, limits.max_build_work, BuildResource::Work)?;
                tracker.record_work(*work)?;
            }
        }
        Ok(class)
    }

    fn contains(&self, byte: u8) -> bool {
        let word = usize::from(byte) >> 6;
        let bit = u32::from(byte) & 63;
        self.words[word] & (1_u64 << bit) != 0
    }

    fn is_disjoint(self, other: Self) -> bool {
        self.words
            .into_iter()
            .zip(other.words)
            .all(|(left, right)| left & right == 0)
    }
}

const BYTE_VALUES: usize = 256;
const BYTE_CATEGORY_COUNT: usize = 8;
const SHIFT_AND_MAX_UNITS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ByteShiftAnd {
    categories: [u8; BYTE_VALUES],
    position_masks: [u64; BYTE_CATEGORY_COUNT],
    accept_mask: u64,
}

impl ByteShiftAnd {
    fn build(
        classes: &[ByteClass; 3],
        window_units: usize,
        limits: BuildLimits,
        work: &mut usize,
        tracker: &mut DirectBuildTracker,
    ) -> Result<Option<Self>, BuildError> {
        if window_units > SHIFT_AND_MAX_UNITS {
            return Ok(None);
        }
        let suffix_position =
            window_units
                .checked_sub(1)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "fixed class Shift-And suffix position",
                })?;
        let accept_mask = 1_u64
            .checked_shl(u32::try_from(suffix_position).map_err(|_| {
                BuildError::ArithmeticOverflow {
                    computation: "fixed class Shift-And suffix shift",
                }
            })?)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "fixed class Shift-And accept mask",
            })?;
        let middle_units = window_units
            .checked_sub(2)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "fixed class Shift-And middle width",
            })?;
        let middle_mask = if middle_units == 0 {
            0
        } else {
            let low = 1_u64
                .checked_shl(u32::try_from(middle_units).map_err(|_| {
                    BuildError::ArithmeticOverflow {
                        computation: "fixed class Shift-And middle shift",
                    }
                })?)
                .and_then(|value| value.checked_sub(1))
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "fixed class Shift-And middle mask",
                })?;
            low.checked_shl(1).ok_or(BuildError::ArithmeticOverflow {
                computation: "fixed class Shift-And middle placement",
            })?
        };
        let mut position_masks = [0_u64; BYTE_CATEGORY_COUNT];
        for (category, mask) in position_masks.iter_mut().enumerate() {
            if category & 1 != 0 {
                *mask |= 1;
            }
            if category & 2 != 0 {
                *mask |= middle_mask;
            }
            if category & 4 != 0 {
                *mask |= accept_mask;
            }
        }
        let mut categories = [0_u8; BYTE_VALUES];
        for byte in u8::MIN..=u8::MAX {
            let mut category = 0_u8;
            for (index, class) in classes.iter().enumerate() {
                if class.contains(byte) {
                    category |= 1_u8
                        .checked_shl(u32::try_from(index).map_err(|_| {
                            BuildError::ArithmeticOverflow {
                                computation: "fixed class Shift-And category shift",
                            }
                        })?)
                        .ok_or(BuildError::ArithmeticOverflow {
                            computation: "fixed class Shift-And category bit",
                        })?;
                }
                *work = work.checked_add(1).ok_or(BuildError::ArithmeticOverflow {
                    computation: "fixed class Shift-And classification work",
                })?;
                enforce_build(*work, limits.max_build_work, BuildResource::Work)?;
                tracker.record_work(*work)?;
            }
            categories[usize::from(byte)] = category;
        }
        Ok(Some(Self {
            categories,
            position_masks,
            accept_mask,
        }))
    }

    #[inline]
    fn position_mask(&self, byte: u8) -> u64 {
        self.position_masks[usize::from(self.categories[usize::from(byte)])]
    }

    #[inline]
    fn position_mask_from_membership(&self, prefix: bool, middle: bool, suffix: bool) -> u64 {
        let category =
            u8::from(prefix) | u8::from(middle).wrapping_shl(1) | u8::from(suffix).wrapping_shl(2);
        self.position_masks[usize::from(category)]
    }
}

#[derive(Debug)]
pub struct FixedClassSandwichPlan {
    prefix: Box<[ScalarRange]>,
    middle: Box<[ScalarRange]>,
    suffix: Box<[ScalarRange]>,
    byte_classes: Option<[ByteClass; 3]>,
    byte_shift_and: Option<ByteShiftAnd>,
    semantics: Semantics,
    middle_repetitions: u32,
    window_units: usize,
    build: BuildAccounting,
}

fn checked_window_units(middle_repetitions: u32, limits: BuildLimits) -> Result<usize, BuildError> {
    if middle_repetitions == 0 {
        return Err(BuildError::ZeroMiddleRepetitions);
    }
    if middle_repetitions > limits.max_middle_repetitions {
        return Err(BuildError::MiddleRepetitionLimit {
            needed: middle_repetitions,
            limit: limits.max_middle_repetitions,
        });
    }
    usize::try_from(middle_repetitions)
        .map_err(|_| BuildError::ArithmeticOverflow {
            computation: "middle repetitions as usize",
        })?
        .checked_add(2)
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "fixed class window units",
        })
}

impl FixedClassSandwichPlan {
    pub fn build_bytes(
        prefix: impl IntoIterator<Item = (u8, u8)>,
        middle: impl IntoIterator<Item = (u8, u8)>,
        suffix: impl IntoIterator<Item = (u8, u8)>,
        middle_repetitions: u32,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        Self::build_bytes_attempt(prefix, middle, suffix, middle_repetitions, limits)
            .map(DirectBuildAttempt::into_plan)
            .map_err(DirectBuildAttemptError::into_source)
    }

    /// Build a byte-semantics plan with exact observed construction effects.
    pub fn build_bytes_attempt(
        prefix: impl IntoIterator<Item = (u8, u8)>,
        middle: impl IntoIterator<Item = (u8, u8)>,
        suffix: impl IntoIterator<Item = (u8, u8)>,
        middle_repetitions: u32,
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>> {
        Self::build_ranges_attempt(
            prefix
                .into_iter()
                .map(|(start, end)| (u32::from(start), u32::from(end))),
            middle
                .into_iter()
                .map(|(start, end)| (u32::from(start), u32::from(end))),
            suffix
                .into_iter()
                .map(|(start, end)| (u32::from(start), u32::from(end))),
            Semantics::RustBytesUnicodeOff,
            middle_repetitions,
            limits,
        )
    }

    pub fn build_unicode(
        prefix: impl IntoIterator<Item = (char, char)>,
        middle: impl IntoIterator<Item = (char, char)>,
        suffix: impl IntoIterator<Item = (char, char)>,
        middle_repetitions: u32,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        Self::build_unicode_attempt(prefix, middle, suffix, middle_repetitions, limits)
            .map(DirectBuildAttempt::into_plan)
            .map_err(DirectBuildAttemptError::into_source)
    }

    /// Build a Unicode-semantics plan with exact observed construction effects.
    pub fn build_unicode_attempt(
        prefix: impl IntoIterator<Item = (char, char)>,
        middle: impl IntoIterator<Item = (char, char)>,
        suffix: impl IntoIterator<Item = (char, char)>,
        middle_repetitions: u32,
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>> {
        Self::build_ranges_attempt(
            prefix
                .into_iter()
                .map(|(start, end)| (u32::from(start), u32::from(end))),
            middle
                .into_iter()
                .map(|(start, end)| (u32::from(start), u32::from(end))),
            suffix
                .into_iter()
                .map(|(start, end)| (u32::from(start), u32::from(end))),
            Semantics::RustBytesUnicodeUtf8False,
            middle_repetitions,
            limits,
        )
    }

    /// Build from canonical inclusive scalar-value ranges. Byte semantics
    /// require every endpoint to fit `u8`; Unicode semantics admit every
    /// scalar value through `char::MAX` (surrogates can appear only inside a
    /// spanning range and are never observed as decoded input units).
    pub fn build_ranges(
        prefix: impl IntoIterator<Item = (u32, u32)>,
        middle: impl IntoIterator<Item = (u32, u32)>,
        suffix: impl IntoIterator<Item = (u32, u32)>,
        semantics: Semantics,
        middle_repetitions: u32,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        Self::build_ranges_attempt(
            prefix,
            middle,
            suffix,
            semantics,
            middle_repetitions,
            limits,
        )
        .map(DirectBuildAttempt::into_plan)
        .map_err(DirectBuildAttemptError::into_source)
    }

    /// Build canonical scalar ranges with exact observed construction effects.
    #[allow(
        clippy::too_many_lines,
        reason = "the three range owners share one exact accounting transaction and publication boundary"
    )]
    pub fn build_ranges_attempt(
        prefix: impl IntoIterator<Item = (u32, u32)>,
        middle: impl IntoIterator<Item = (u32, u32)>,
        suffix: impl IntoIterator<Item = (u32, u32)>,
        semantics: Semantics,
        middle_repetitions: u32,
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>> {
        let mut tracker = DirectBuildTracker::new();
        let result = (|| {
            let window_units = checked_window_units(middle_repetitions, limits)?;
            let mut work = 0_usize;
            let (prefix, prefix_capacity) =
                collect_ranges(prefix, "prefix", semantics, limits, &mut work, &mut tracker)?;
            let (middle, middle_capacity) =
                collect_ranges(middle, "middle", semantics, limits, &mut work, &mut tracker)?;
            let (suffix, suffix_capacity) =
                collect_ranges(suffix, "suffix", semantics, limits, &mut work, &mut tracker)?;
            let source_ranges = prefix
                .len()
                .checked_add(middle.len())
                .and_then(|count| count.checked_add(suffix.len()))
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "fixed class source ranges",
                })?;
            enforce_build(
                source_ranges,
                limits.max_source_ranges,
                BuildResource::Ranges,
            )?;
            let byte_classes = if semantics == Semantics::RustBytesUnicodeOff {
                Some([
                    ByteClass::from_ranges(&prefix, limits, &mut work, &mut tracker)?,
                    ByteClass::from_ranges(&middle, limits, &mut work, &mut tracker)?,
                    ByteClass::from_ranges(&suffix, limits, &mut work, &mut tracker)?,
                ])
            } else {
                None
            };
            let byte_shift_and = if window_units <= SHIFT_AND_MAX_UNITS {
                let shift_and_classes = match &byte_classes {
                    Some(classes) => *classes,
                    None => [
                        ByteClass::from_ranges(&prefix, limits, &mut work, &mut tracker)?,
                        ByteClass::from_ranges(&middle, limits, &mut work, &mut tracker)?,
                        ByteClass::from_ranges(&suffix, limits, &mut work, &mut tracker)?,
                    ],
                };
                ByteShiftAnd::build(
                    &shift_and_classes,
                    window_units,
                    limits,
                    &mut work,
                    &mut tracker,
                )?
            } else {
                None
            };
            work = work.checked_add(1).ok_or(BuildError::ArithmeticOverflow {
                computation: "fixed class repetition work",
            })?;
            enforce_build(work, limits.max_build_work, BuildResource::Work)?;
            tracker.record_work(work)?;
            let range_payload_bytes = source_ranges.checked_mul(size_of::<ScalarRange>()).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "fixed class range payload bytes",
                },
            )?;
            let temporary_capacity_bytes = prefix_capacity
                .checked_add(middle_capacity)
                .and_then(|bytes| bytes.checked_add(suffix_capacity))
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "fixed class temporary capacity bytes",
                })?;
            let persistent_bytes = size_of::<Self>().checked_add(range_payload_bytes).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "fixed class persistent bytes",
                },
            )?;
            let peak_bytes = persistent_bytes
                .checked_add(temporary_capacity_bytes)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "fixed class construction peak bytes",
                })?;
            enforce_build(
                temporary_capacity_bytes,
                limits.max_scratch_bytes,
                BuildResource::Scratch,
            )?;
            enforce_build(
                persistent_bytes,
                limits.max_persistent_bytes,
                BuildResource::Persistent,
            )?;
            enforce_build(peak_bytes, limits.max_peak_bytes, BuildResource::Peak)?;
            let build = BuildAccounting {
                semantics,
                prefix_ranges: prefix.len(),
                middle_ranges: middle.len(),
                suffix_ranges: suffix.len(),
                source_ranges,
                middle_repetitions,
                window_units,
                range_payload_bytes,
                work,
                temporary_capacity_bytes,
                scratch_bytes: temporary_capacity_bytes,
                persistent_bytes,
                peak_bytes,
            };
            let plan = Self {
                prefix: prefix.into_boxed_slice(),
                middle: middle.into_boxed_slice(),
                suffix: suffix.into_boxed_slice(),
                byte_classes,
                byte_shift_and,
                semantics,
                middle_repetitions,
                window_units,
                build,
            };
            tracker.publish(persistent_bytes)?;
            Ok(plan)
        })();
        match result {
            Ok(plan) => Ok(DirectBuildAttempt::new(plan, tracker.actual)),
            Err(source) => {
                tracker.actual.live_persistent_bytes = 0;
                Err(DirectBuildAttemptError::new(source, tracker.actual))
            }
        }
    }

    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.build
    }

    #[must_use]
    pub const fn count_identity(&self) -> OperationIdentity {
        self.identity(Operation::Count)
    }

    #[must_use]
    pub const fn span_sum_identity(&self) -> OperationIdentity {
        self.identity(Operation::SpanSum)
    }

    #[must_use]
    pub const fn span_visit_identity(&self) -> OperationIdentity {
        self.identity(Operation::SpanVisit)
    }

    const fn identity(&self, operation: Operation) -> OperationIdentity {
        OperationIdentity {
            plan_id: PLAN_ID,
            operation_id: match operation {
                Operation::Count => COUNT_OPERATION_ID,
                Operation::SpanSum => SPAN_SUM_OPERATION_ID,
                Operation::SpanVisit => SPAN_VISIT_OPERATION_ID,
            },
            operation,
            semantics: self.semantics,
            middle_repetitions: self.middle_repetitions,
            non_overlapping: true,
        }
    }

    pub fn count(&self, haystack: &[u8], limits: ReduceLimits) -> Result<CountResult, ReduceError> {
        let (upper_bounds, ring) =
            self.preflight(haystack, Window::full(haystack), Operation::Count, limits)?;
        let actual = if self.semantics == Semantics::RustBytesUnicodeUtf8False {
            if let Some(shift_and) = &self.byte_shift_and {
                self.execute_unicode_shift_and_count(haystack, upper_bounds, shift_and)?
            } else {
                self.execute(haystack, Window::full(haystack), upper_bounds, ring)?
            }
        } else {
            self.execute(haystack, Window::full(haystack), upper_bounds, ring)?
        };
        Ok(CountResult {
            count: actual.count,
            accounting: ReduceAccounting {
                identity: self.count_identity(),
                window: Window::full(haystack),
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
        let (upper_bounds, ring) =
            self.preflight(haystack, Window::full(haystack), Operation::SpanSum, limits)?;
        let actual = self.execute(haystack, Window::full(haystack), upper_bounds, ring)?;
        Ok(SpanSumResult {
            span_sum: actual.matched_bytes,
            accounting: ReduceAccounting {
                identity: self.span_sum_identity(),
                window: Window::full(haystack),
                upper_bounds,
                actual,
            },
        })
    }

    /// Visit every complete non-overlapping match in one traversal. All
    /// prospective limits are checked before source access or the first
    /// callback.
    pub fn visit_spans<F>(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
        mut visitor: F,
    ) -> Result<SpanVisitResult, ReduceError>
    where
        F: FnMut(CompleteSpan),
    {
        let (upper_bounds, ring) = self.preflight(
            haystack,
            Window::full(haystack),
            Operation::SpanVisit,
            limits,
        )?;
        let actual = self.execute_with_visitor(
            haystack,
            Window::full(haystack),
            upper_bounds,
            ring,
            &mut visitor,
        )?;
        Ok(SpanVisitResult {
            matches: actual.match_events,
            span_sum: actual.matched_bytes,
            accounting: ReduceAccounting {
                identity: self.span_visit_identity(),
                window: Window::full(haystack),
                upper_bounds,
                actual,
            },
        })
    }

    fn byte_disjoint_suffix_classes(&self) -> Option<&[ByteClass; 3]> {
        if self.semantics != Semantics::RustBytesUnicodeOff || self.byte_shift_and.is_some() {
            return None;
        }
        let classes = self.byte_classes.as_ref()?;
        classes[1].is_disjoint(classes[2]).then_some(classes)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "preflight derives and enforces every resource bound before allocating or traversing input"
    )]
    fn preflight(
        &self,
        haystack: &[u8],
        window: Window,
        operation: Operation,
        limits: ReduceLimits,
    ) -> Result<(ReduceUpperBounds, Vec<Unit>), ReduceError> {
        if window.start() > window.end() || window.end() > haystack.len() {
            return Err(ReduceError::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len: haystack.len(),
            });
        }
        let input_bytes =
            window
                .end()
                .checked_sub(window.start())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "fixed class input bytes",
                })?;
        let decode_factor = if self.semantics == Semantics::RustBytesUnicodeOff {
            1
        } else {
            4
        };
        let decode_byte_checks =
            input_bytes
                .checked_mul(decode_factor)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "fixed class decode byte checks",
                })?;
        let membership_factor =
            if self.semantics == Semantics::RustBytesUnicodeOff && self.byte_shift_and.is_some() {
                1
            } else {
                3
            };
        let membership_tests =
            input_bytes
                .checked_mul(membership_factor)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "fixed class membership tests",
                })?;
        let comparison_factor = if self.byte_classes.is_some() {
            0
        } else {
            binary_search_comparison_bound(self.prefix.len())
                .checked_add(binary_search_comparison_bound(self.middle.len()))
                .and_then(|count| {
                    count.checked_add(binary_search_comparison_bound(self.suffix.len()))
                })
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "fixed class comparison factor",
                })?
        };
        let range_comparisons =
            input_bytes
                .checked_mul(comparison_factor)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "fixed class range comparisons",
                })?;
        let reducer_steps = input_bytes
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "fixed class reducer steps",
            })?;
        let match_events =
            input_bytes
                .checked_div(self.window_units)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "fixed class match event bound",
                })?;
        let count = u64::try_from(match_events).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "fixed class count bound",
        })?;
        let span_sum = u64::try_from(input_bytes).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "fixed class span sum bound",
        })?;
        let work = decode_byte_checks
            .checked_add(membership_tests)
            .and_then(|value| value.checked_add(range_comparisons))
            .and_then(|value| value.checked_add(reducer_steps))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "fixed class work bound",
            })?;
        enforce_reduce(
            input_bytes,
            limits.max_input_bytes,
            ReduceResource::InputBytes,
        )?;
        enforce_reduce(
            decode_byte_checks,
            limits.max_decode_byte_checks,
            ReduceResource::DecodeByteChecks,
        )?;
        enforce_reduce(
            membership_tests,
            limits.max_membership_tests,
            ReduceResource::MembershipTests,
        )?;
        enforce_reduce(
            range_comparisons,
            limits.max_range_comparisons,
            ReduceResource::RangeComparisons,
        )?;
        enforce_reduce(
            reducer_steps,
            limits.max_reducer_steps,
            ReduceResource::ReducerSteps,
        )?;
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
        if matches!(operation, Operation::SpanSum | Operation::SpanVisit)
            && span_sum > limits.max_span_sum
        {
            return Err(ReduceError::SpanSumLimit {
                needed: span_sum,
                limit: limits.max_span_sum,
            });
        }
        enforce_reduce(work, limits.max_work, ReduceResource::Work)?;

        let mut ring = Vec::new();
        let shift_and_operation = self.byte_shift_and.is_some()
            && (self.semantics == Semantics::RustBytesUnicodeOff || operation == Operation::Count);
        let disjoint_suffix_operation = self.byte_disjoint_suffix_classes().is_some();
        let ring_units = if shift_and_operation || disjoint_suffix_operation {
            0
        } else {
            self.window_units
        };
        ring.try_reserve_exact(ring_units)
            .map_err(|_| ReduceError::AllocationFailed {
                additional: ring_units,
            })?;
        let scratch_bytes = ring.capacity().checked_mul(size_of::<Unit>()).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "fixed class ring capacity bytes",
            },
        )?;
        enforce_reduce(
            scratch_bytes,
            limits.max_scratch_bytes,
            ReduceResource::Scratch,
        )?;
        ring.resize(ring_units, Unit::default());
        let persistent_bytes = self.build.persistent_bytes;
        let peak_bytes =
            persistent_bytes
                .checked_add(scratch_bytes)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "fixed class operation peak bytes",
                })?;
        enforce_reduce(peak_bytes, limits.max_peak_bytes, ReduceResource::Peak)?;
        Ok((
            ReduceUpperBounds {
                input_bytes,
                decode_byte_checks,
                membership_tests,
                range_comparisons,
                reducer_steps,
                match_events,
                count,
                span_sum,
                work,
                scratch_bytes,
                persistent_bytes,
                peak_bytes,
            },
            ring,
        ))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the streaming loop keeps decoding, the circular-window invariant and exact counters together"
    )]
    fn execute(
        &self,
        haystack: &[u8],
        window: Window,
        upper: ReduceUpperBounds,
        ring: Vec<Unit>,
    ) -> Result<ReduceActualCounters, ReduceError> {
        self.execute_with_visitor(haystack, window, upper, ring, &mut |_| {})
    }

    fn execute_with_visitor<F>(
        &self,
        haystack: &[u8],
        window: Window,
        upper: ReduceUpperBounds,
        mut ring: Vec<Unit>,
        visitor: &mut F,
    ) -> Result<ReduceActualCounters, ReduceError>
    where
        F: FnMut(CompleteSpan),
    {
        let local = &haystack[window.start()..window.end()];
        if self.semantics == Semantics::RustBytesUnicodeOff
            && let Some(shift_and) = &self.byte_shift_and
        {
            return self.execute_byte_shift_and(local, window.start(), upper, shift_and, visitor);
        }
        if let Some(classes) = self.byte_disjoint_suffix_classes() {
            return self.execute_byte_disjoint_suffix(
                local,
                window.start(),
                upper,
                classes,
                visitor,
            );
        }
        let mut position = 0_usize;
        let mut head = 0_usize;
        let mut length = 0_usize;
        let mut middle_matches = 0_usize;
        let byte_classes = self.byte_classes.as_ref();
        let mut actual = ReduceActualCounters {
            input_bytes_advanced: 0,
            decode_byte_checks: 0,
            valid_units: 0,
            invalid_bytes: 0,
            membership_tests: 0,
            range_comparisons: 0,
            reducer_steps: 0,
            window_resets: 0,
            match_events: 0,
            count: 0,
            matched_bytes: 0,
            work: 0,
            scratch_bytes: upper.scratch_bytes,
        };
        while position < local.len() {
            let decoded = match self.semantics {
                Semantics::RustBytesUnicodeOff => DecodedUnit {
                    scalar: Some(u32::from(local[position])),
                    width: 1,
                    byte_checks: 1,
                },
                Semantics::RustBytesUnicodeUtf8False => decode_scalar(&local[position..]),
            };
            actual.decode_byte_checks = checked_actual_add(
                actual.decode_byte_checks,
                decoded.byte_checks,
                "decode byte checks",
            )?;
            actual.reducer_steps = checked_actual_add(actual.reducer_steps, 1, "reducer steps")?;
            if let Some(scalar) = decoded.scalar {
                actual.valid_units = checked_actual_add(actual.valid_units, 1, "valid units")?;
                let (prefix, middle, suffix, comparisons) = if let Some(classes) = byte_classes {
                    let byte =
                        u8::try_from(scalar).map_err(|_| ReduceError::ArithmeticOverflow {
                            computation: "fixed class byte-mask input",
                        })?;
                    (
                        classes[0].contains(byte),
                        classes[1].contains(byte),
                        classes[2].contains(byte),
                        0,
                    )
                } else {
                    let (prefix, prefix_comparisons) = contains(&self.prefix, scalar)?;
                    let (middle, middle_comparisons) = contains(&self.middle, scalar)?;
                    let (suffix, suffix_comparisons) = contains(&self.suffix, scalar)?;
                    let comparisons = prefix_comparisons
                        .checked_add(middle_comparisons)
                        .and_then(|value| value.checked_add(suffix_comparisons))
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "actual fixed class range comparisons",
                        })?;
                    (prefix, middle, suffix, comparisons)
                };
                actual.membership_tests =
                    checked_actual_add(actual.membership_tests, 3, "membership tests")?;
                actual.range_comparisons =
                    checked_actual_add(actual.range_comparisons, comparisons, "range comparisons")?;
                let unit = Unit {
                    start: position,
                    end: position.checked_add(decoded.width).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "fixed class unit end",
                        },
                    )?,
                    prefix,
                    middle,
                    suffix,
                };
                if length == self.window_units {
                    middle_matches = middle_matches
                        .checked_sub(usize::from(ring[head].middle))
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "fixed class middle count eviction",
                        })?;
                    ring[head] = unit;
                    head = head
                        .checked_add(1)
                        .and_then(|value| value.checked_rem(self.window_units))
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "fixed class circular head",
                        })?;
                } else {
                    let index = head
                        .checked_add(length)
                        .and_then(|value| value.checked_rem(self.window_units))
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "fixed class circular insertion index",
                        })?;
                    ring[index] = unit;
                    length = checked_actual_add(length, 1, "window length")?;
                }
                middle_matches = checked_actual_add(
                    middle_matches,
                    usize::from(middle),
                    "middle membership count",
                )?;
                if length == self.window_units {
                    let last_offset = self.window_units.checked_sub(1).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "fixed class last window offset",
                        },
                    )?;
                    let last = head
                        .checked_add(last_offset)
                        .and_then(|value| value.checked_rem(self.window_units))
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "fixed class circular last index",
                        })?;
                    let interior = middle_matches
                        .checked_sub(usize::from(ring[head].middle))
                        .and_then(|value| value.checked_sub(usize::from(ring[last].middle)))
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "fixed class interior membership count",
                        })?;
                    let required = usize::try_from(self.middle_repetitions).map_err(|_| {
                        ReduceError::ArithmeticOverflow {
                            computation: "fixed class middle repetitions as usize",
                        }
                    })?;
                    if ring[head].prefix && interior == required && ring[last].suffix {
                        let matched = ring[last].end.checked_sub(ring[head].start).ok_or(
                            ReduceError::ArithmeticOverflow {
                                computation: "fixed class matched bytes",
                            },
                        )?;
                        let matched = u64::try_from(matched).map_err(|_| {
                            ReduceError::ArithmeticOverflow {
                                computation: "fixed class matched bytes as u64",
                            }
                        })?;
                        actual.match_events =
                            checked_actual_add(actual.match_events, 1, "match events")?;
                        actual.count =
                            actual
                                .count
                                .checked_add(1)
                                .ok_or(ReduceError::ArithmeticOverflow {
                                    computation: "fixed class count",
                                })?;
                        actual.matched_bytes = actual.matched_bytes.checked_add(matched).ok_or(
                            ReduceError::ArithmeticOverflow {
                                computation: "fixed class matched-byte sum",
                            },
                        )?;
                        visitor(CompleteSpan {
                            start: window.start().checked_add(ring[head].start).ok_or(
                                ReduceError::ArithmeticOverflow {
                                    computation: "fixed class absolute match start",
                                },
                            )?,
                            end: window.start().checked_add(ring[last].end).ok_or(
                                ReduceError::ArithmeticOverflow {
                                    computation: "fixed class absolute match end",
                                },
                            )?,
                        });
                        length = 0;
                        head = 0;
                        middle_matches = 0;
                        actual.window_resets =
                            checked_actual_add(actual.window_resets, 1, "matched window resets")?;
                    }
                }
            } else {
                actual.invalid_bytes =
                    checked_actual_add(actual.invalid_bytes, 1, "invalid bytes")?;
                if length != 0 {
                    actual.window_resets =
                        checked_actual_add(actual.window_resets, 1, "invalid window resets")?;
                }
                length = 0;
                head = 0;
                middle_matches = 0;
            }
            position =
                position
                    .checked_add(decoded.width)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "fixed class input position",
                    })?;
        }
        actual.reducer_steps = checked_actual_add(actual.reducer_steps, 1, "final reducer step")?;
        actual.input_bytes_advanced = position;
        actual.work = actual
            .decode_byte_checks
            .checked_add(actual.membership_tests)
            .and_then(|value| value.checked_add(actual.range_comparisons))
            .and_then(|value| value.checked_add(actual.reducer_steps))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual fixed class work",
            })?;
        debug_assert!(actual.input_bytes_advanced <= upper.input_bytes);
        debug_assert!(actual.decode_byte_checks <= upper.decode_byte_checks);
        debug_assert!(actual.membership_tests <= upper.membership_tests);
        debug_assert!(actual.range_comparisons <= upper.range_comparisons);
        debug_assert!(actual.reducer_steps <= upper.reducer_steps);
        debug_assert!(actual.match_events <= upper.match_events);
        debug_assert!(actual.count <= upper.count);
        debug_assert!(actual.matched_bytes <= upper.span_sum);
        debug_assert!(actual.work <= upper.work);
        Ok(actual)
    }

    /// Execute a byte-only fixed sandwich whose suffix cannot be a middle
    /// byte. Suffix positions are ordered exactly like the corresponding
    /// fixed-width starts. For consecutive inspected suffix positions `p < q`,
    /// validation at `q` either reaches `p` after `q - p <= N` probes and
    /// stops (because every suffix byte is outside the middle class), or uses
    /// at most `N < q - p` probes. Thus every validation is charged to the
    /// disjoint forward interval since the previous suffix, and all backward
    /// probes together are bounded by the input length. An accepted match
    /// advances the minimum suffix by the full width, partitioning the same
    /// argument into non-overlapping post-match domains.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "candidate and probe counters are each injectively bounded by the supplied slice length before their checked publication"
    )]
    fn execute_byte_disjoint_suffix<F>(
        &self,
        local: &[u8],
        absolute_start: usize,
        upper: ReduceUpperBounds,
        classes: &[ByteClass; 3],
        visitor: &mut F,
    ) -> Result<ReduceActualCounters, ReduceError>
    where
        F: FnMut(CompleteSpan),
    {
        debug_assert_eq!(self.semantics, Semantics::RustBytesUnicodeOff);
        debug_assert!(self.byte_shift_and.is_none());
        debug_assert!(classes[1].is_disjoint(classes[2]));

        let middle_width = usize::try_from(self.middle_repetitions).map_err(|_| {
            ReduceError::ArithmeticOverflow {
                computation: "fixed class disjoint-suffix middle width",
            }
        })?;
        let first_suffix =
            self.window_units
                .checked_sub(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "fixed class disjoint-suffix first position",
                })?;
        let mut minimum_suffix = first_suffix;
        let mut suffix_membership_tests = 0_usize;
        let mut middle_membership_tests = 0_usize;
        let mut prefix_membership_tests = 0_usize;
        let mut count = 0_u64;

        for (suffix_position, &byte) in local.iter().enumerate() {
            if suffix_position < minimum_suffix {
                continue;
            }
            suffix_membership_tests += 1;
            if !classes[2].contains(byte) {
                continue;
            }

            let middle_start = suffix_position.checked_sub(middle_width).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "fixed class disjoint-suffix middle start",
                },
            )?;
            let mut probe = suffix_position;
            let mut middle_matches = true;
            while probe > middle_start {
                probe -= 1;
                middle_membership_tests += 1;
                if !classes[1].contains(local[probe]) {
                    middle_matches = false;
                    break;
                }
            }
            if !middle_matches {
                continue;
            }

            let match_start =
                middle_start
                    .checked_sub(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "fixed class disjoint-suffix match start",
                    })?;
            prefix_membership_tests += 1;
            if !classes[0].contains(local[match_start]) {
                continue;
            }

            count = count
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "fixed class disjoint-suffix count",
                })?;
            let end = absolute_start
                .checked_add(suffix_position)
                .and_then(|position| position.checked_add(1))
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "fixed class disjoint-suffix absolute match end",
                })?;
            let start =
                absolute_start
                    .checked_add(match_start)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "fixed class disjoint-suffix absolute match start",
                    })?;
            visitor(CompleteSpan { start, end });

            // Every suffix below this position would correspond to a start at
            // or before the accepted end and is therefore an overlapping
            // candidate. Saturating at the local end is exact when the next
            // mathematical suffix position is outside the supplied slice.
            minimum_suffix = suffix_position
                .checked_add(self.window_units)
                .filter(|&position| position < local.len())
                .unwrap_or(local.len());
        }

        debug_assert!(suffix_membership_tests <= local.len());
        debug_assert!(middle_membership_tests <= local.len());
        debug_assert!(prefix_membership_tests <= local.len());
        let membership_tests = suffix_membership_tests
            .checked_add(middle_membership_tests)
            .and_then(|tests| tests.checked_add(prefix_membership_tests))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "fixed class disjoint-suffix membership tests",
            })?;
        let match_events = usize::try_from(count).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "fixed class disjoint-suffix match events",
        })?;
        let width =
            u64::try_from(self.window_units).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "fixed class disjoint-suffix width as u64",
            })?;
        let matched_bytes = count
            .checked_mul(width)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "fixed class disjoint-suffix matched bytes",
            })?;
        let reducer_steps = local
            .len()
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "fixed class disjoint-suffix reducer steps",
            })?;
        let work = local
            .len()
            .checked_add(membership_tests)
            .and_then(|value| value.checked_add(reducer_steps))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "fixed class disjoint-suffix work",
            })?;
        let actual = ReduceActualCounters {
            input_bytes_advanced: local.len(),
            decode_byte_checks: local.len(),
            valid_units: local.len(),
            invalid_bytes: 0,
            membership_tests,
            range_comparisons: 0,
            reducer_steps,
            window_resets: match_events,
            match_events,
            count,
            matched_bytes,
            work,
            scratch_bytes: 0,
        };
        debug_assert!(actual.input_bytes_advanced <= upper.input_bytes);
        debug_assert!(actual.decode_byte_checks <= upper.decode_byte_checks);
        debug_assert!(actual.membership_tests <= upper.membership_tests);
        debug_assert!(actual.range_comparisons <= upper.range_comparisons);
        debug_assert!(actual.reducer_steps <= upper.reducer_steps);
        debug_assert!(actual.match_events <= upper.match_events);
        debug_assert!(actual.count <= upper.count);
        debug_assert!(actual.matched_bytes <= upper.span_sum);
        debug_assert!(actual.work <= upper.work);
        Ok(actual)
    }

    #[allow(
        clippy::arithmetic_side_effects,
        clippy::too_many_lines,
        reason = "the Shift-And state uses an intentional wrapping-width shift while every published counter remains checked"
    )]
    fn execute_unicode_shift_and_count(
        &self,
        local: &[u8],
        upper: ReduceUpperBounds,
        shift_and: &ByteShiftAnd,
    ) -> Result<ReduceActualCounters, ReduceError> {
        debug_assert_eq!(self.semantics, Semantics::RustBytesUnicodeUtf8False);
        let mut position = 0_usize;
        let mut state = 0_u64;
        let mut actual = ReduceActualCounters {
            input_bytes_advanced: 0,
            decode_byte_checks: 0,
            valid_units: 0,
            invalid_bytes: 0,
            membership_tests: 0,
            range_comparisons: 0,
            reducer_steps: 0,
            window_resets: 0,
            match_events: 0,
            count: 0,
            matched_bytes: 0,
            work: 0,
            scratch_bytes: 0,
        };
        while position < local.len() {
            let decoded = decode_scalar(&local[position..]);
            actual.decode_byte_checks = checked_actual_add(
                actual.decode_byte_checks,
                decoded.byte_checks,
                "decode byte checks",
            )?;
            actual.reducer_steps = checked_actual_add(actual.reducer_steps, 1, "reducer steps")?;
            if let Some(scalar) = decoded.scalar {
                actual.valid_units = checked_actual_add(actual.valid_units, 1, "valid units")?;
                let (position_mask, membership_tests, comparisons) =
                    if let Ok(byte) = u8::try_from(scalar) {
                        (shift_and.position_mask(byte), 1, 0)
                    } else {
                        let (prefix, prefix_comparisons) = contains(&self.prefix, scalar)?;
                        let (middle, middle_comparisons) = contains(&self.middle, scalar)?;
                        let (suffix, suffix_comparisons) = contains(&self.suffix, scalar)?;
                        let comparisons = prefix_comparisons
                            .checked_add(middle_comparisons)
                            .and_then(|value| value.checked_add(suffix_comparisons))
                            .ok_or(ReduceError::ArithmeticOverflow {
                                computation: "actual fixed class range comparisons",
                            })?;
                        (
                            shift_and.position_mask_from_membership(prefix, middle, suffix),
                            3,
                            comparisons,
                        )
                    };
                actual.membership_tests = checked_actual_add(
                    actual.membership_tests,
                    membership_tests,
                    "membership tests",
                )?;
                actual.range_comparisons =
                    checked_actual_add(actual.range_comparisons, comparisons, "range comparisons")?;
                state = (state.wrapping_shl(1) | 1) & position_mask;
                if state & shift_and.accept_mask != 0 {
                    let end = position.checked_add(decoded.width).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "fixed class Unicode Shift-And match end",
                        },
                    )?;
                    let (start, backward_checks) =
                        unicode_window_start(local, end, self.window_units)?;
                    actual.decode_byte_checks = checked_actual_add(
                        actual.decode_byte_checks,
                        backward_checks,
                        "decode byte checks",
                    )?;
                    let matched =
                        end.checked_sub(start)
                            .ok_or(ReduceError::ArithmeticOverflow {
                                computation: "fixed class Unicode Shift-And matched bytes",
                            })?;
                    actual.match_events =
                        checked_actual_add(actual.match_events, 1, "match events")?;
                    actual.count =
                        actual
                            .count
                            .checked_add(1)
                            .ok_or(ReduceError::ArithmeticOverflow {
                                computation: "fixed class Unicode Shift-And count",
                            })?;
                    actual.matched_bytes = actual
                        .matched_bytes
                        .checked_add(u64::try_from(matched).map_err(|_| {
                            ReduceError::ArithmeticOverflow {
                                computation: "fixed class Unicode Shift-And matched bytes as u64",
                            }
                        })?)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "fixed class Unicode Shift-And matched-byte sum",
                        })?;
                    actual.window_resets =
                        checked_actual_add(actual.window_resets, 1, "matched window resets")?;
                    // The next scalar injects the first legal post-match start.
                    state = 0;
                }
            } else {
                actual.invalid_bytes =
                    checked_actual_add(actual.invalid_bytes, 1, "invalid bytes")?;
                if state != 0 {
                    actual.window_resets =
                        checked_actual_add(actual.window_resets, 1, "invalid window resets")?;
                }
                state = 0;
            }
            position =
                position
                    .checked_add(decoded.width)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "fixed class input position",
                    })?;
        }
        actual.reducer_steps = checked_actual_add(actual.reducer_steps, 1, "final reducer step")?;
        actual.input_bytes_advanced = position;
        actual.work = actual
            .decode_byte_checks
            .checked_add(actual.membership_tests)
            .and_then(|value| value.checked_add(actual.range_comparisons))
            .and_then(|value| value.checked_add(actual.reducer_steps))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual fixed class work",
            })?;
        debug_assert!(actual.input_bytes_advanced <= upper.input_bytes);
        debug_assert!(actual.decode_byte_checks <= upper.decode_byte_checks);
        debug_assert!(actual.membership_tests <= upper.membership_tests);
        debug_assert!(actual.range_comparisons <= upper.range_comparisons);
        debug_assert!(actual.reducer_steps <= upper.reducer_steps);
        debug_assert!(actual.match_events <= upper.match_events);
        debug_assert!(actual.count <= upper.count);
        debug_assert!(actual.matched_bytes <= upper.span_sum);
        debug_assert!(actual.work <= upper.work);
        Ok(actual)
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the Shift-And state uses intentional wrapping-width bit shifts while every published counter remains checked"
    )]
    fn execute_byte_shift_and<F>(
        &self,
        local: &[u8],
        absolute_start: usize,
        upper: ReduceUpperBounds,
        shift_and: &ByteShiftAnd,
        visitor: &mut F,
    ) -> Result<ReduceActualCounters, ReduceError>
    where
        F: FnMut(CompleteSpan),
    {
        let mut state = 0_u64;
        let mut count = 0_u64;
        for (index, &byte) in local.iter().enumerate() {
            state = (state.wrapping_shl(1) | 1) & shift_and.position_mask(byte);
            if state & shift_and.accept_mask != 0 {
                count = count
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "fixed class Shift-And count",
                    })?;
                let end = absolute_start
                    .checked_add(index)
                    .and_then(|position| position.checked_add(1))
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "fixed class Shift-And absolute match end",
                    })?;
                let start =
                    end.checked_sub(self.window_units)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "fixed class Shift-And absolute match start",
                        })?;
                visitor(CompleteSpan { start, end });
                // A fixed-width match suppresses every overlapping candidate.
                // The next byte injects the first legal post-match start.
                state = 0;
            }
        }
        let match_events = usize::try_from(count).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "fixed class Shift-And match events",
        })?;
        let width =
            u64::try_from(self.window_units).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "fixed class Shift-And width as u64",
            })?;
        let matched_bytes = count
            .checked_mul(width)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "fixed class Shift-And matched bytes",
            })?;
        let reducer_steps = local
            .len()
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "fixed class Shift-And reducer steps",
            })?;
        let work = local
            .len()
            .checked_add(local.len())
            .and_then(|value| value.checked_add(reducer_steps))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "fixed class Shift-And work",
            })?;
        let actual = ReduceActualCounters {
            input_bytes_advanced: local.len(),
            decode_byte_checks: local.len(),
            valid_units: local.len(),
            invalid_bytes: 0,
            membership_tests: local.len(),
            range_comparisons: 0,
            reducer_steps,
            window_resets: match_events,
            match_events,
            count,
            matched_bytes,
            work,
            scratch_bytes: 0,
        };
        debug_assert!(actual.input_bytes_advanced <= upper.input_bytes);
        debug_assert!(actual.decode_byte_checks <= upper.decode_byte_checks);
        debug_assert!(actual.membership_tests <= upper.membership_tests);
        debug_assert!(actual.range_comparisons <= upper.range_comparisons);
        debug_assert!(actual.reducer_steps <= upper.reducer_steps);
        debug_assert!(actual.match_events <= upper.match_events);
        debug_assert!(actual.count <= upper.count);
        debug_assert!(actual.matched_bytes <= upper.span_sum);
        debug_assert!(actual.work <= upper.work);
        Ok(actual)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Unit {
    start: usize,
    end: usize,
    prefix: bool,
    middle: bool,
    suffix: bool,
}

#[derive(Clone, Copy)]
struct DecodedUnit {
    scalar: Option<u32>,
    width: usize,
    byte_checks: usize,
}

fn unicode_window_start(
    bytes: &[u8],
    end: usize,
    units: usize,
) -> Result<(usize, usize), ReduceError> {
    let mut start = end;
    let mut byte_checks = 0_usize;
    for _ in 0..units {
        start = start
            .checked_sub(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "fixed class Unicode Shift-And window start",
            })?;
        byte_checks = checked_actual_add(byte_checks, 1, "decode byte checks")?;
        while bytes
            .get(start)
            .is_some_and(|byte| byte & 0b1100_0000 == 0b1000_0000)
        {
            start = start
                .checked_sub(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "fixed class Unicode Shift-And scalar start",
                })?;
            byte_checks = checked_actual_add(byte_checks, 1, "decode byte checks")?;
        }
    }
    Ok((start, byte_checks))
}

fn decode_scalar(bytes: &[u8]) -> DecodedUnit {
    let first = bytes[0];
    if first.is_ascii() {
        return DecodedUnit {
            scalar: Some(u32::from(first)),
            width: 1,
            byte_checks: 1,
        };
    }
    let expected = match first {
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => {
            return DecodedUnit {
                scalar: None,
                width: 1,
                byte_checks: 1,
            };
        }
    };
    if bytes.len() < expected {
        return DecodedUnit {
            scalar: None,
            width: 1,
            byte_checks: bytes.len(),
        };
    }
    let candidate = &bytes[..expected];
    match core::str::from_utf8(candidate) {
        Ok(text) => DecodedUnit {
            scalar: text.chars().next().map(u32::from),
            width: expected,
            byte_checks: expected,
        },
        Err(_) => DecodedUnit {
            scalar: None,
            width: 1,
            byte_checks: expected,
        },
    }
}

fn collect_ranges(
    ranges: impl IntoIterator<Item = (u32, u32)>,
    role: &'static str,
    semantics: Semantics,
    limits: BuildLimits,
    work: &mut usize,
    tracker: &mut DirectBuildTracker,
) -> Result<(Vec<ScalarRange>, usize), BuildError> {
    let mut output = Vec::new();
    let mut previous_end: Option<u32> = None;
    for (start, end) in ranges {
        if start > end {
            return Err(BuildError::ReversedRange { role, start, end });
        }
        let valid = match semantics {
            Semantics::RustBytesUnicodeOff => u8::try_from(end).is_ok(),
            // Scalar inputs can never be surrogates, so a canonical range may
            // span the surrogate hole without changing membership semantics.
            Semantics::RustBytesUnicodeUtf8False => end <= 0x10_FFFF,
        };
        if !valid {
            return Err(BuildError::RangeOutsideSemantics { role, start, end });
        }
        if previous_end.is_some_and(|previous| start <= previous.saturating_add(1)) {
            return Err(BuildError::NonCanonicalRanges { role });
        }
        previous_end = Some(end);
        let before_capacity = output.capacity();
        output
            .try_reserve(1)
            .map_err(|_| BuildError::AllocationFailed {
                role,
                additional: 1,
            })?;
        tracker.observe_reserve(before_capacity, output.capacity())?;
        output.push(ScalarRange { start, end });
        tracker.observe_range_copy()?;
        *work = work.checked_add(1).ok_or(BuildError::ArithmeticOverflow {
            computation: "fixed class range work",
        })?;
        enforce_build(*work, limits.max_build_work, BuildResource::Work)?;
        tracker.record_work(*work)?;
    }
    if output.is_empty() {
        return Err(BuildError::EmptyClass { role });
    }
    let capacity_bytes = output
        .capacity()
        .checked_mul(size_of::<ScalarRange>())
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "fixed class range capacity bytes",
        })?;
    Ok((output, capacity_bytes))
}

fn contains(ranges: &[ScalarRange], scalar: u32) -> Result<(bool, usize), ReduceError> {
    let mut low = 0_usize;
    let mut high = ranges.len();
    let mut comparisons = 0_usize;
    while low < high {
        comparisons = checked_actual_add(comparisons, 1, "binary search comparisons")?;
        let middle_offset = high
            .checked_sub(low)
            .and_then(|value| value.checked_div(2))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "fixed class binary search midpoint offset",
            })?;
        let middle = low
            .checked_add(middle_offset)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "fixed class binary search midpoint",
            })?;
        let range = ranges.get(middle).ok_or(ReduceError::ArithmeticOverflow {
            computation: "fixed class range access",
        })?;
        if scalar < range.start {
            high = middle;
        } else if scalar > range.end {
            low = middle
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "fixed class binary search lower bound",
                })?;
        } else {
            return Ok((true, comparisons));
        }
    }
    Ok((false, comparisons))
}

fn binary_search_comparison_bound(mut ranges: usize) -> usize {
    let mut comparisons = 0_usize;
    while ranges != 0 {
        comparisons = comparisons.saturating_add(1);
        ranges /= 2;
    }
    comparisons
}

fn checked_actual_add(
    left: usize,
    right: usize,
    computation: &'static str,
) -> Result<usize, ReduceError> {
    left.checked_add(right)
        .ok_or(ReduceError::ArithmeticOverflow { computation })
}

#[derive(Clone, Copy)]
enum BuildResource {
    Ranges,
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
        BuildResource::Work => BuildError::WorkLimit { needed, limit },
        BuildResource::Scratch => BuildError::ScratchLimit { needed, limit },
        BuildResource::Persistent => BuildError::PersistentLimit { needed, limit },
        BuildResource::Peak => BuildError::PeakLimit { needed, limit },
    })
}

#[derive(Clone, Copy)]
enum ReduceResource {
    InputBytes,
    DecodeByteChecks,
    MembershipTests,
    RangeComparisons,
    ReducerSteps,
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
        ReduceResource::DecodeByteChecks => ReduceError::DecodeByteChecksLimit { needed, limit },
        ReduceResource::MembershipTests => ReduceError::MembershipTestsLimit { needed, limit },
        ReduceResource::RangeComparisons => ReduceError::RangeComparisonsLimit { needed, limit },
        ReduceResource::ReducerSteps => ReduceError::ReducerStepsLimit { needed, limit },
        ReduceResource::MatchEvents => ReduceError::MatchEventsLimit { needed, limit },
        ReduceResource::Work => ReduceError::WorkLimit { needed, limit },
        ReduceResource::Scratch => ReduceError::ScratchLimit { needed, limit },
        ReduceResource::Peak => ReduceError::PeakLimit { needed, limit },
    })
}

#[cfg(test)]
mod tests {
    use regex::bytes::RegexBuilder;

    use super::{
        BuildLimits, CompleteSpan, FixedClassSandwichPlan, Operation, ReduceLimits, Semantics,
    };
    use crate::Window;

    #[test]
    fn build_attempt_reports_exact_success_and_partial_range_failure() {
        let attempt = FixedClassSandwichPlan::build_bytes_attempt(
            [(b'a', b'a')],
            [(b'b', b'b')],
            [(b'c', b'c')],
            2,
            BuildLimits::default(),
        )
        .unwrap();
        let actual = attempt.actual();
        let plan = attempt.into_plan();
        let build = plan.build_accounting();
        assert_eq!(actual.work, u64::try_from(build.work).unwrap());
        assert_eq!(actual.allocations, 3);
        assert_eq!(actual.allocated_bytes, build.temporary_capacity_bytes);
        assert_eq!(actual.copied_bytes, build.range_payload_bytes);
        assert_eq!(actual.initialized_bytes, build.persistent_bytes);
        assert_eq!(actual.live_persistent_bytes, build.persistent_bytes);
        assert_eq!(
            actual.peak_bytes,
            build.temporary_capacity_bytes.max(build.persistent_bytes)
        );

        let failure = FixedClassSandwichPlan::build_bytes_attempt(
            [(b'a', b'a')],
            [(b'z', b'a')],
            [(b'c', b'c')],
            2,
            BuildLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(
            failure.source(),
            super::BuildError::ReversedRange {
                role: "middle",
                start,
                end
            } if *start == u32::from(b'z') && *end == u32::from(b'a')
        ));
        let partial = failure.actual();
        assert_eq!(partial.work, 1);
        assert_eq!(partial.allocations, 1);
        assert!(partial.allocated_bytes >= core::mem::size_of::<super::ScalarRange>());
        assert_eq!(
            partial.copied_bytes,
            core::mem::size_of::<super::ScalarRange>()
        );
        assert_eq!(
            partial.initialized_bytes,
            core::mem::size_of::<super::ScalarRange>()
        );
        assert_eq!(partial.live_persistent_bytes, 0);
        assert!(partial.peak_bytes > 0);
    }

    fn oracle(pattern: &str, unicode: bool, haystack: &[u8]) -> (u64, u64) {
        let regex = RegexBuilder::new(pattern).unicode(unicode).build().unwrap();
        regex
            .find_iter(haystack)
            .fold((0, 0), |(count, bytes), matched| {
                (
                    count.checked_add(1).unwrap(),
                    bytes
                        .checked_add(
                            u64::try_from(matched.end().checked_sub(matched.start()).unwrap())
                                .unwrap(),
                        )
                        .unwrap(),
                )
            })
    }

    fn oracle_spans(pattern: &str, unicode: bool, haystack: &[u8]) -> Vec<CompleteSpan> {
        RegexBuilder::new(pattern)
            .unicode(unicode)
            .build()
            .unwrap()
            .find_iter(haystack)
            .map(|matched| CompleteSpan {
                start: matched.start(),
                end: matched.end(),
            })
            .collect()
    }

    fn assert_byte_oracle(
        plan: &FixedClassSandwichPlan,
        regex: &regex::bytes::Regex,
        haystack: &[u8],
    ) {
        let expected = regex
            .find_iter(haystack)
            .map(|matched| CompleteSpan {
                start: matched.start(),
                end: matched.end(),
            })
            .collect::<Vec<_>>();
        let expected_sum = expected.iter().fold(0_u64, |sum, span| {
            sum.checked_add(u64::try_from(span.end.checked_sub(span.start).unwrap()).unwrap())
                .unwrap()
        });
        let counted = plan.count(haystack, ReduceLimits::default()).unwrap();
        let summed = plan.span_sum(haystack, ReduceLimits::default()).unwrap();
        let mut visited = Vec::new();
        let visit = plan
            .visit_spans(haystack, ReduceLimits::default(), |span| {
                visited.push(span);
            })
            .unwrap();
        assert_eq!(counted.count, u64::try_from(expected.len()).unwrap());
        assert_eq!(counted.accounting.actual.matched_bytes, expected_sum);
        assert_eq!(summed.span_sum, expected_sum);
        assert_eq!(visited, expected);
        assert_eq!(visit.matches, expected.len());
        assert_eq!(visit.span_sum, expected_sum);
    }

    #[test]
    fn byte_windows_match_fixed_width_oracle_and_do_not_overlap() {
        let plan = FixedClassSandwichPlan::build_bytes(
            [(b'a', b'q')],
            [(0, b't'), (b'{', u8::MAX)],
            [(b'x', b'x')],
            3,
            BuildLimits::default(),
        )
        .unwrap();
        assert_eq!(
            plan.build_accounting().semantics,
            Semantics::RustBytesUnicodeOff
        );
        for haystack in [
            b"apppxapppx".as_slice(),
            b"a\xFF\xFF\xFFx".as_slice(),
            b"aqqqxaqx".as_slice(),
            b"zaaaax".as_slice(),
        ] {
            let expected = oracle("[a-q][^u-z]{3}x", false, haystack);
            assert_eq!(
                plan.count(haystack, ReduceLimits::default()).unwrap().count,
                expected.0
            );
            assert_eq!(
                plan.span_sum(haystack, ReduceLimits::default())
                    .unwrap()
                    .span_sum,
                expected.1
            );
        }
    }

    #[test]
    fn byte_masks_match_every_canonical_range_value_and_skip_binary_search() {
        let plan = FixedClassSandwichPlan::build_bytes(
            [(0, 0), (62, 65), (127, 129), (u8::MAX, u8::MAX)],
            [(1, 1), (126, 129), (191, 193), (254, 254)],
            [(2, 2), (63, 66), (190, 193), (253, 253)],
            1,
            BuildLimits::default(),
        )
        .unwrap();
        let build = plan.build_accounting();
        assert!(build.work > build.source_ranges.checked_add(1).unwrap());
        let below_work = build.work.checked_sub(1).unwrap();
        let error = FixedClassSandwichPlan::build_bytes(
            [(0, 0), (62, 65), (127, 129), (u8::MAX, u8::MAX)],
            [(1, 1), (126, 129), (191, 193), (254, 254)],
            [(2, 2), (63, 66), (190, 193), (253, 253)],
            1,
            BuildLimits {
                max_build_work: below_work,
                ..BuildLimits::default()
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            super::BuildError::WorkLimit { needed, limit }
                if needed == build.work && limit.checked_add(1) == Some(build.work)
        ));
        let classes = plan.byte_classes.unwrap();
        for byte in u8::MIN..=u8::MAX {
            let scalar = u32::from(byte);
            for (class, ranges) in [
                (classes[0], plan.prefix.as_ref()),
                (classes[1], plan.middle.as_ref()),
                (classes[2], plan.suffix.as_ref()),
            ] {
                assert_eq!(
                    class.contains(byte),
                    super::contains(ranges, scalar).unwrap().0,
                    "byte={byte}"
                );
            }
        }

        let counted = plan
            .count(
                &[62, 126, 190, 65, 129, 193],
                ReduceLimits {
                    max_range_comparisons: 0,
                    ..ReduceLimits::default()
                },
            )
            .unwrap();
        assert_eq!(counted.count, 2);
        assert_eq!(counted.accounting.upper_bounds.range_comparisons, 0);
        assert_eq!(counted.accounting.actual.range_comparisons, 0);
        assert_eq!(counted.accounting.identity.plan_id, super::PLAN_ID);
    }

    #[test]
    fn byte_shift_and_covers_64_units_and_resets_after_each_match() {
        let plan = FixedClassSandwichPlan::build_bytes(
            [(b'a', b'a')],
            [(b'b', b'b')],
            [(b'c', b'c')],
            62,
            BuildLimits::default(),
        )
        .unwrap();
        assert!(plan.byte_shift_and.is_some());
        let one = format!("a{}c", "b".repeat(62));
        let haystack = format!("{one}{one}a{}c", "b".repeat(61));
        let expected = oracle("ab{62}c", false, haystack.as_bytes());
        let counted = plan
            .count(haystack.as_bytes(), ReduceLimits::default())
            .unwrap();
        let summed = plan
            .span_sum(haystack.as_bytes(), ReduceLimits::default())
            .unwrap();
        assert_eq!(counted.count, expected.0);
        assert_eq!(summed.span_sum, expected.1);
        assert_eq!(counted.accounting.upper_bounds.scratch_bytes, 0);
        assert_eq!(counted.accounting.actual.scratch_bytes, 0);
        assert_eq!(counted.accounting.actual.membership_tests, haystack.len());

        let mut visited = Vec::new();
        let result = plan
            .visit_spans(haystack.as_bytes(), ReduceLimits::default(), |span| {
                visited.push(span);
            })
            .unwrap();
        assert_eq!(visited, oracle_spans("ab{62}c", false, haystack.as_bytes()));
        assert_eq!(result.matches, visited.len());
        assert_eq!(result.span_sum, expected.1);
        assert_eq!(result.accounting.identity, plan.span_visit_identity());
    }

    #[test]
    fn disjoint_suffix_starts_above_shift_and_boundary_and_preserves_short_incumbent() {
        for middle_repetitions in [62_u32, 63, 64, 80] {
            let plan = FixedClassSandwichPlan::build_bytes(
                [(b'a', b'a')],
                [(b'b', b'b')],
                [(b'c', b'c')],
                middle_repetitions,
                BuildLimits::default(),
            )
            .unwrap();
            let middle = "b".repeat(usize::try_from(middle_repetitions).unwrap());
            let one = format!("a{middle}c");
            let haystack = format!("x{one}{one}a{}x", "b".repeat(middle.len()));
            let pattern = format!("ab{{{middle_repetitions}}}c");
            let regex = RegexBuilder::new(&pattern).unicode(false).build().unwrap();
            assert_byte_oracle(&plan, &regex, haystack.as_bytes());

            if middle_repetitions == 62 {
                assert!(plan.byte_shift_and.is_some());
                assert!(plan.byte_disjoint_suffix_classes().is_none());
                let counted = plan
                    .count(haystack.as_bytes(), ReduceLimits::default())
                    .unwrap();
                assert_eq!(counted.accounting.actual.membership_tests, haystack.len());
            } else {
                assert!(plan.byte_shift_and.is_none());
                assert!(plan.byte_disjoint_suffix_classes().is_some());
                let counted = plan
                    .count(haystack.as_bytes(), ReduceLimits::default())
                    .unwrap();
                assert_eq!(counted.accounting.upper_bounds.scratch_bytes, 0);
                assert_eq!(counted.accounting.actual.scratch_bytes, 0);
            }
        }
    }

    #[test]
    fn disjoint_suffix_exhaustive_boundary_combinations_match_oracle() {
        const MIDDLE: usize = 63;
        const WIDTH: usize = MIDDLE + 2;
        const RADIX: usize = 4;
        const VARIABLE_POSITIONS: [usize; 7] =
            [0, 1, MIDDLE, WIDTH - 1, WIDTH, WIDTH + 1, 2 * WIDTH];
        const ALPHABET: [u8; RADIX] = [b'a', b'b', b'c', 0xFF];

        let plan = FixedClassSandwichPlan::build_bytes(
            [(b'a', b'a'), (b'c', b'c')],
            [(b'b', b'b'), (0xFF, 0xFF)],
            [(b'a', b'a'), (b'c', b'c')],
            u32::try_from(MIDDLE).unwrap(),
            BuildLimits::default(),
        )
        .unwrap();
        assert!(plan.byte_disjoint_suffix_classes().is_some());
        let regex = RegexBuilder::new(r"[ac][b\xFF]{63}[ac]")
            .unicode(false)
            .build()
            .unwrap();
        let cases = RADIX.pow(u32::try_from(VARIABLE_POSITIONS.len()).unwrap());
        for mut case in 0..cases {
            let mut haystack = vec![b'b'; 2 * WIDTH + 1];
            for &position in &VARIABLE_POSITIONS {
                haystack[position] = ALPHABET[case % RADIX];
                case /= RADIX;
            }
            assert_byte_oracle(&plan, &regex, &haystack);
        }
    }

    #[test]
    fn disjoint_suffix_random_oracle_covers_long_widths_and_invalid_bytes() {
        const ALPHABET: [u8; 10] = [b'a', b'b', b'c', b'd', b'e', b'x', b'y', b'z', 0x80, 0xFF];
        let mut state = 0xD1B5_4A32_D192_ED03_u64;
        for middle_repetitions in [63_u32, 64, 80, 127] {
            let plan = FixedClassSandwichPlan::build_bytes(
                [(b'a', b'c')],
                [(b'd', b'e'), (0x80, 0xFF)],
                [(b'x', b'z')],
                middle_repetitions,
                BuildLimits::default(),
            )
            .unwrap();
            assert!(plan.byte_disjoint_suffix_classes().is_some());
            let pattern = format!(r"[a-c][d-e\x80-\xFF]{{{middle_repetitions}}}[x-z]");
            let regex = RegexBuilder::new(&pattern).unicode(false).build().unwrap();
            let width = usize::try_from(middle_repetitions)
                .unwrap()
                .checked_add(2)
                .unwrap();
            let length_modulus = width
                .checked_mul(3)
                .and_then(|value| value.checked_add(29))
                .unwrap();
            for case in 0..160_usize {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let length = case
                    .checked_mul(37)
                    .and_then(|value| value.checked_add(usize::try_from(state & 63).unwrap()))
                    .unwrap()
                    % length_modulus;
                let mut haystack = Vec::with_capacity(length);
                for _ in 0..length {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    let alphabet_index =
                        usize::try_from(state % u64::try_from(ALPHABET.len()).unwrap()).unwrap();
                    haystack.push(ALPHABET[alphabet_index]);
                }
                if case % 3 == 0 && length >= width {
                    let placements = length.checked_sub(width).unwrap().checked_add(1).unwrap();
                    let start =
                        usize::try_from(state % u64::try_from(placements).unwrap()).unwrap();
                    haystack[start] = b'a';
                    haystack[start + 1..start + width - 1].fill(if case % 2 == 0 {
                        b'd'
                    } else {
                        0xFF
                    });
                    haystack[start + width - 1] = b'x';
                }
                assert_byte_oracle(&plan, &regex, &haystack);
            }
        }
    }

    #[test]
    fn disjoint_suffix_dense_candidates_and_self_overlap_remain_linear_and_exact() {
        const MIDDLE: usize = 63;
        let plan = FixedClassSandwichPlan::build_bytes(
            [(b'a', b'a'), (b'c', b'c')],
            [(b'b', b'b')],
            [(b'a', b'a'), (b'c', b'c')],
            u32::try_from(MIDDLE).unwrap(),
            BuildLimits::default(),
        )
        .unwrap();
        let regex = RegexBuilder::new(r"[ac]b{63}[ac]")
            .unicode(false)
            .build()
            .unwrap();

        let dense = vec![b'c'; 8_192];
        assert_byte_oracle(&plan, &regex, &dense);
        let dense_count = plan.count(&dense, ReduceLimits::default()).unwrap();
        assert!(
            dense_count.accounting.actual.membership_tests <= dense.len().checked_mul(2).unwrap()
        );

        let one = format!("a{}c", "b".repeat(MIDDLE));
        let overlapping_decoy = format!(
            "a{}ca{}c",
            "b".repeat(MIDDLE.checked_sub(1).unwrap()),
            "b".repeat(MIDDLE)
        );
        let haystack = format!("cc{one}{overlapping_decoy}{one}ccc");
        assert_byte_oracle(&plan, &regex, haystack.as_bytes());
    }

    #[test]
    fn disjoint_suffix_invalid_byte_classes_and_nonzero_window_match_oracle() {
        const MIDDLE: usize = 63;
        let plan = FixedClassSandwichPlan::build_bytes(
            [(0xFF, 0xFF)],
            [(0x80, 0xFD)],
            [(0xFE, 0xFE)],
            u32::try_from(MIDDLE).unwrap(),
            BuildLimits::default(),
        )
        .unwrap();
        let regex = RegexBuilder::new(r"\xFF[\x80-\xFD]{63}\xFE")
            .unicode(false)
            .build()
            .unwrap();
        let one = {
            let mut bytes = vec![0xFF];
            bytes.extend(core::iter::repeat_n(0x80, MIDDLE));
            bytes.push(0xFE);
            bytes
        };
        let mut haystack = b"outside".to_vec();
        let window_start = haystack.len();
        haystack.extend_from_slice(&one);
        haystack.extend_from_slice(&[0xFE, 0xFE, 0xFF]);
        haystack.extend_from_slice(&one);
        let window_end = haystack.len();
        haystack.extend_from_slice(b"outside");
        assert_byte_oracle(&plan, &regex, &haystack);

        let window = Window::new(window_start, window_end);
        let (upper, ring) = plan
            .preflight(
                &haystack,
                window,
                Operation::SpanVisit,
                ReduceLimits::default(),
            )
            .unwrap();
        assert!(ring.is_empty());
        let mut visited = Vec::new();
        let actual = plan
            .execute_with_visitor(&haystack, window, upper, ring, &mut |span| {
                visited.push(span);
            })
            .unwrap();
        let expected = regex
            .find_iter(&haystack[window_start..window_end])
            .map(|matched| CompleteSpan {
                start: window_start.checked_add(matched.start()).unwrap(),
                end: window_start.checked_add(matched.end()).unwrap(),
            })
            .collect::<Vec<_>>();
        assert_eq!(visited, expected);
        assert_eq!(actual.match_events, expected.len());
        assert_eq!(
            actual.input_bytes_advanced,
            window_end.checked_sub(window_start).unwrap()
        );
    }

    #[test]
    fn disjoint_suffix_exact_and_one_below_prospective_resources_close() {
        const MIDDLE: usize = 80;
        let plan = FixedClassSandwichPlan::build_bytes(
            [(b'a', b'q')],
            [(0, b't'), (b'{', u8::MAX)],
            [(b'x', b'x')],
            u32::try_from(MIDDLE).unwrap(),
            BuildLimits::default(),
        )
        .unwrap();
        let one = format!("a{}x", "p".repeat(MIDDLE));
        let haystack = format!("{one}---{one}").into_bytes();
        let baseline = plan.count(&haystack, ReduceLimits::default()).unwrap();
        let upper = baseline.accounting.upper_bounds;
        assert_eq!(upper.scratch_bytes, 0);
        assert_eq!(upper.peak_bytes, upper.persistent_bytes);
        assert_eq!(baseline.accounting.actual.scratch_bytes, 0);

        let exact = ReduceLimits {
            max_input_bytes: upper.input_bytes,
            max_decode_byte_checks: upper.decode_byte_checks,
            max_membership_tests: upper.membership_tests,
            max_range_comparisons: upper.range_comparisons,
            max_reducer_steps: upper.reducer_steps,
            max_match_events: upper.match_events,
            max_count: upper.count,
            max_span_sum: upper.span_sum,
            max_work: upper.work,
            max_scratch_bytes: upper.scratch_bytes,
            max_peak_bytes: upper.peak_bytes,
        };
        assert_eq!(plan.count(&haystack, exact).unwrap().count, baseline.count);
        assert_eq!(
            plan.span_sum(&haystack, exact).unwrap().span_sum,
            baseline.accounting.actual.matched_bytes
        );

        macro_rules! one_below {
            ($field:ident, $error:pat) => {{
                let mut limits = exact;
                limits.$field = limits.$field.checked_sub(1).unwrap();
                assert!(matches!(plan.count(&haystack, limits), Err($error)));
            }};
        }
        one_below!(max_input_bytes, super::ReduceError::InputBytesLimit { .. });
        one_below!(
            max_decode_byte_checks,
            super::ReduceError::DecodeByteChecksLimit { .. }
        );
        one_below!(
            max_membership_tests,
            super::ReduceError::MembershipTestsLimit { .. }
        );
        one_below!(
            max_reducer_steps,
            super::ReduceError::ReducerStepsLimit { .. }
        );
        one_below!(
            max_match_events,
            super::ReduceError::MatchEventsLimit { .. }
        );
        one_below!(max_count, super::ReduceError::CountLimit { .. });
        one_below!(max_work, super::ReduceError::WorkLimit { .. });
        one_below!(max_peak_bytes, super::ReduceError::PeakLimit { .. });

        let mut span_sum_below = exact;
        span_sum_below.max_span_sum = upper.span_sum.checked_sub(1).unwrap();
        assert!(matches!(
            plan.span_sum(&haystack, span_sum_below),
            Err(super::ReduceError::SpanSumLimit { .. })
        ));
    }

    #[test]
    fn overlapping_middle_and_suffix_retain_circular_window_control() {
        let plan = FixedClassSandwichPlan::build_bytes(
            [(b'a', b'a')],
            [(b'b', b'c')],
            [(b'c', b'c')],
            80,
            BuildLimits::default(),
        )
        .unwrap();
        assert!(plan.byte_shift_and.is_none());
        assert!(plan.byte_disjoint_suffix_classes().is_none());
        let one = format!("a{}c", "b".repeat(80));
        let regex = RegexBuilder::new(r"a[bc]{80}c")
            .unicode(false)
            .build()
            .unwrap();
        assert_byte_oracle(&plan, &regex, one.as_bytes());
        let counted = plan.count(one.as_bytes(), ReduceLimits::default()).unwrap();
        assert!(counted.accounting.upper_bounds.scratch_bytes > 0);
        assert!(counted.accounting.actual.scratch_bytes > 0);
    }

    #[test]
    fn wide_overlapping_suffix_control_keeps_invalid_byte_semantics() {
        const MIDDLE: usize = 80;
        let plan = FixedClassSandwichPlan::build_bytes(
            [(b'a', b'q')],
            [(0, b't'), (b'{', u8::MAX)],
            [(b'x', b'x'), (0xE0, 0xFF)],
            u32::try_from(MIDDLE).unwrap(),
            BuildLimits::default(),
        )
        .unwrap();
        assert!(plan.byte_shift_and.is_none());
        assert!(plan.byte_disjoint_suffix_classes().is_none());
        let regex = RegexBuilder::new(r"[a-q][^u-z]{80}[x\xE0-\xFF]")
            .unicode(false)
            .build()
            .unwrap();
        let mut haystack =
            format!("a{}x--a{}", "p".repeat(MIDDLE), "p".repeat(MIDDLE)).into_bytes();
        haystack.push(0xE0);
        assert_byte_oracle(&plan, &regex, &haystack);
        let counted = plan.count(&haystack, ReduceLimits::default()).unwrap();
        assert_eq!(counted.count, 2);
        assert!(counted.accounting.actual.scratch_bytes > 0);
    }

    #[test]
    fn unicode_count_uses_scalar_shift_and_and_spans_retain_windows() {
        let plan = FixedClassSandwichPlan::build_unicode(
            [('a', 'q')],
            [('\0', 't'), ('{', char::MAX)],
            [('x', 'x'), ('à', 'ÿ')],
            3,
            BuildLimits::default(),
        )
        .unwrap();
        assert!(plan.byte_shift_and.is_some());
        for (haystack, needs_range_search) in [
            ("a✓∞éx aöööà".as_bytes(), true),
            (b"a\xFFbcx".as_slice(), false),
            ("zaaaax aqööÿ".as_bytes(), false),
        ] {
            let expected = oracle("[a-q][^u-z]{3}[x\\x{E0}-\\x{FF}]", true, haystack);
            let counted = plan.count(haystack, ReduceLimits::default()).unwrap();
            let summed = plan.span_sum(haystack, ReduceLimits::default()).unwrap();
            assert_eq!(counted.count, expected.0);
            assert_eq!(counted.accounting.actual.matched_bytes, expected.1);
            assert_eq!(summed.span_sum, expected.1);
            assert!(counted.accounting.actual.decode_byte_checks <= haystack.len() * 4);
            assert!(counted.accounting.upper_bounds.range_comparisons > 0);
            assert_eq!(
                counted.accounting.actual.range_comparisons > 0,
                needs_range_search
            );
            assert_eq!(counted.accounting.upper_bounds.scratch_bytes, 0);
            assert_eq!(counted.accounting.actual.scratch_bytes, 0);
            assert!(summed.accounting.actual.scratch_bytes > 0);

            let mut visited = Vec::new();
            let result = plan
                .visit_spans(haystack, ReduceLimits::default(), |span| {
                    visited.push(span);
                })
                .unwrap();
            assert_eq!(
                visited,
                oracle_spans("[a-q][^u-z]{3}[x\\x{E0}-\\x{FF}]", true, haystack)
            );
            assert_eq!(result.matches, visited.len());
            assert_eq!(result.span_sum, expected.1);
        }
    }

    #[test]
    fn span_visit_refuses_before_the_first_callback() {
        let plan = FixedClassSandwichPlan::build_bytes(
            [(b'a', b'a')],
            [(b'b', b'b')],
            [(b'c', b'c')],
            2,
            BuildLimits::default(),
        )
        .unwrap();
        let mut callbacks = 0_usize;
        let error = plan
            .visit_spans(
                b"abbcabbc",
                ReduceLimits {
                    max_span_sum: 7,
                    ..ReduceLimits::default()
                },
                |_| callbacks += 1,
            )
            .unwrap_err();
        assert_eq!(callbacks, 0);
        assert!(matches!(
            error,
            super::ReduceError::SpanSumLimit {
                needed: 8,
                limit: 7
            }
        ));
    }

    #[test]
    fn execution_refuses_before_traversal_when_incumbent_window_scratch_is_starved() {
        let plan = FixedClassSandwichPlan::build_bytes(
            [(b'a', b'a')],
            [(b'b', b'c')],
            [(b'c', b'c')],
            80,
            BuildLimits::default(),
        )
        .unwrap();
        let error = plan
            .count(
                b"abbbc",
                ReduceLimits {
                    max_scratch_bytes: 0,
                    ..ReduceLimits::default()
                },
            )
            .unwrap_err();
        assert!(matches!(error, super::ReduceError::ScratchLimit { .. }));
    }
}
