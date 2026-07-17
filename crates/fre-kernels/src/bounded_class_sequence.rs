//! Linear count reduction for a bounded sequence of compound byte-class units.
//!
//! The admitted language is `(?:HEAD BODY+ TRAIL*){min,max}` with greedy,
//! positive finite outer bounds and three pairwise-disjoint byte classes. The
//! disjointness proof makes each unit boundary deterministic. Three inline
//! 256-bit masks are the complete retained representation, and execution uses
//! constant state without a boundary table, queue, stack, or allocation.
//! Construction is O(Q) in canonical source ranges and reduction is O(N),
//! with both resource envelopes admitted before their respective traversals.
//! rebar-row:curated/10-bounded-repeat/capitals@rust/regex

use core::{fmt, mem::size_of};

pub const PLAN_ID: &str = "bounded-class-sequence-count.inline-byte-bitsets.v1";
pub const COUNT_OPERATION_ID: &str = "bounded-class-sequence-count.count.v1";

const BITMAP_WORDS: usize = 12;
const OVERLAP_COMPARISONS: usize = 12;
const BUILD_FIXED_WORK: usize = BITMAP_WORDS + OVERLAP_COMPARISONS + 6;
const WORK_PER_INPUT_BYTE: usize = 28;
const FINALIZATION_WORK: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationIdentity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub minimum: u32,
    pub maximum: u32,
    pub greedy: bool,
    pub non_overlapping: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    pub max_source_ranges: usize,
    pub max_repeat_bound: u32,
    pub max_build_work: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl Default for BuildLimits {
    fn default() -> Self {
        Self {
            max_source_ranges: 256,
            max_repeat_bound: 1_000,
            max_build_work: 1 << 20,
            max_persistent_bytes: 1 << 20,
            max_peak_bytes: 1 << 20,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    pub head_ranges: usize,
    pub body_ranges: usize,
    pub trail_ranges: usize,
    pub source_ranges: usize,
    pub minimum: u32,
    pub maximum: u32,
    pub range_inspections: usize,
    /// Reversed-range and canonical-order comparison upper bound.
    pub validation_comparisons: usize,
    pub bitmap_zero_writes: usize,
    pub bitmap_word_writes: usize,
    /// Pairwise inline-word comparison upper bound.
    pub overlap_comparisons: usize,
    pub work_bound: usize,
    pub allocations: usize,
    pub reserves: usize,
    pub temporary_copies: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceLimits {
    pub max_input_bytes: usize,
    pub max_count: u64,
    pub max_work: usize,
    pub max_peak_bytes: usize,
}

impl Default for ReduceLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 128 << 20,
            max_count: 128 << 20,
            max_work: 1 << 29,
            max_peak_bytes: 1 << 20,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceUpperBounds {
    pub input_bytes: usize,
    pub byte_inspections: usize,
    pub class_comparisons: usize,
    pub branch_charges: usize,
    pub state_writes: usize,
    pub arithmetic_charges: usize,
    pub finalization_charges: usize,
    pub match_events: u64,
    pub span_sum: u64,
    pub work: usize,
    pub allocations: usize,
    pub reserves: usize,
    pub temporary_copies: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceActualCounters {
    pub input_bytes: usize,
    pub class_comparisons: usize,
    pub completed_units: u64,
    pub discarded_units: u64,
    pub match_events: u64,
    pub matched_bytes: u64,
    pub work_charged: usize,
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
    InvalidRepeat {
        minimum: u32,
        maximum: u32,
    },
    RepeatLimit {
        needed: u32,
        limit: u32,
    },
    ReversedRange {
        role: &'static str,
        start: u8,
        end: u8,
    },
    NonCanonicalRanges {
        role: &'static str,
    },
    OverlappingClasses,
    RangeLimit {
        needed: usize,
        limit: usize,
    },
    WorkLimit {
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
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyClass { role } => {
                write!(formatter, "bounded sequence {role} class is empty")
            }
            Self::InvalidRepeat { minimum, maximum } => write!(
                formatter,
                "bounded sequence repeat {minimum}..={maximum} is invalid"
            ),
            Self::RepeatLimit { needed, limit } => write!(
                formatter,
                "bounded sequence repeat needs {needed}, limit is {limit}"
            ),
            Self::ReversedRange { role, start, end } => write!(
                formatter,
                "bounded sequence {role} range {start:#X}..={end:#X} is reversed"
            ),
            Self::NonCanonicalRanges { role } => {
                write!(
                    formatter,
                    "bounded sequence {role} ranges are not canonical"
                )
            }
            Self::OverlappingClasses => formatter.write_str(
                "bounded sequence head, body, and trail classes must be pairwise disjoint",
            ),
            Self::RangeLimit { needed, limit } => {
                limit_message(formatter, "source ranges", *needed, *limit)
            }
            Self::WorkLimit { needed, limit } => {
                limit_message(formatter, "build work", *needed, *limit)
            }
            Self::PersistentLimit { needed, limit } => {
                limit_message(formatter, "persistent bytes", *needed, *limit)
            }
            Self::PeakLimit { needed, limit } => {
                limit_message(formatter, "peak bytes", *needed, *limit)
            }
            Self::ArithmeticOverflow { computation } => {
                write!(
                    formatter,
                    "bounded sequence overflow while computing {computation}"
                )
            }
        }
    }
}

impl std::error::Error for BuildError {}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReduceError {
    InputLimit { needed: usize, limit: usize },
    CountLimit { needed: u64, limit: u64 },
    WorkLimit { needed: usize, limit: usize },
    PeakLimit { needed: usize, limit: usize },
    ArithmeticOverflow { computation: &'static str },
}

impl fmt::Display for ReduceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputLimit { needed, limit } => {
                limit_message(formatter, "input bytes", *needed, *limit)
            }
            Self::CountLimit { needed, limit } => {
                limit_message(formatter, "count", *needed, *limit)
            }
            Self::WorkLimit { needed, limit } => limit_message(formatter, "work", *needed, *limit),
            Self::PeakLimit { needed, limit } => {
                limit_message(formatter, "peak bytes", *needed, *limit)
            }
            Self::ArithmeticOverflow { computation } => {
                write!(
                    formatter,
                    "bounded sequence overflow while computing {computation}"
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
        "bounded sequence {resource} needs {needed}, limit is {limit}"
    )
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ByteClass {
    words: [u64; 4],
}

impl ByteClass {
    fn from_ranges<I>(ranges: I, role: &'static str) -> Result<(Self, usize), BuildError>
    where
        I: IntoIterator<Item = (u8, u8)>,
    {
        let mut class = Self::default();
        let mut previous_end = None;
        let mut writes = 0_usize;
        for (start, end) in ranges {
            if start > end {
                return Err(BuildError::ReversedRange { role, start, end });
            }
            if previous_end.is_some_and(|previous| previous >= start) {
                return Err(BuildError::NonCanonicalRanges { role });
            }
            previous_end = Some(end);
            let first_word = usize::from(start) >> 6;
            let last_word = usize::from(end) >> 6;
            for word_index in first_word..=last_word {
                let first_bit = if word_index == first_word {
                    u32::from(start) & 63
                } else {
                    0
                };
                let last_bit = if word_index == last_word {
                    u32::from(end) & 63
                } else {
                    63
                };
                let first_mask =
                    u64::MAX
                        .checked_shl(first_bit)
                        .ok_or(BuildError::ArithmeticOverflow {
                            computation: "bitmap first shift",
                        })?;
                let last_shift =
                    63_u32
                        .checked_sub(last_bit)
                        .ok_or(BuildError::ArithmeticOverflow {
                            computation: "bitmap last shift",
                        })?;
                let last_mask =
                    u64::MAX
                        .checked_shr(last_shift)
                        .ok_or(BuildError::ArithmeticOverflow {
                            computation: "bitmap last shift",
                        })?;
                class.words[word_index] |= first_mask & last_mask;
                writes = writes
                    .checked_add(1)
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "bitmap word writes",
                    })?;
            }
        }
        Ok((class, writes))
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
}

#[derive(Clone, Debug)]
pub struct BoundedClassSequencePlan {
    head: ByteClass,
    body: ByteClass,
    trail: ByteClass,
    minimum: u32,
    maximum: u32,
    build: BuildAccounting,
}

impl BoundedClassSequencePlan {
    #[allow(
        clippy::too_many_lines,
        reason = "construction keeps pre-admission derivations beside the zero-allocation bitmap writes"
    )]
    pub fn build<Head, Body, Trail>(
        head: Head,
        body: Body,
        trail: Trail,
        minimum: u32,
        maximum: u32,
        limits: BuildLimits,
    ) -> Result<Self, BuildError>
    where
        Head: ExactSizeIterator<Item = (u8, u8)> + Clone,
        Body: ExactSizeIterator<Item = (u8, u8)> + Clone,
        Trail: ExactSizeIterator<Item = (u8, u8)> + Clone,
    {
        enforce_build(BUILD_FIXED_WORK, limits.max_build_work, BuildResource::Work)?;
        if minimum == 0 || maximum < minimum {
            return Err(BuildError::InvalidRepeat { minimum, maximum });
        }
        if maximum > limits.max_repeat_bound {
            return Err(BuildError::RepeatLimit {
                needed: maximum,
                limit: limits.max_repeat_bound,
            });
        }
        let head_ranges = head.len();
        let body_ranges = body.len();
        let trail_ranges = trail.len();
        for (role, count) in [
            ("head", head_ranges),
            ("body", body_ranges),
            ("trail", trail_ranges),
        ] {
            if count == 0 {
                return Err(BuildError::EmptyClass { role });
            }
        }
        let source_ranges = head_ranges
            .checked_add(body_ranges)
            .and_then(|count| count.checked_add(trail_ranges))
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "source range count",
            })?;
        enforce_build(
            source_ranges,
            limits.max_source_ranges,
            BuildResource::Ranges,
        )?;
        let work_bound = source_ranges
            .checked_mul(7)
            .and_then(|work| work.checked_add(BUILD_FIXED_WORK))
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "build work bound",
            })?;
        enforce_build(work_bound, limits.max_build_work, BuildResource::Work)?;
        let validation_comparisons =
            source_ranges
                .checked_mul(2)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "range validation comparison bound",
                })?;
        let persistent_bytes = size_of::<Self>();
        enforce_build(
            persistent_bytes,
            limits.max_persistent_bytes,
            BuildResource::Persistent,
        )?;
        enforce_build(persistent_bytes, limits.max_peak_bytes, BuildResource::Peak)?;

        // All range reads, comparisons, zero initialization, and possible
        // bitmap writes were admitted above from exact iterator lengths.
        let (head, head_writes) = ByteClass::from_ranges(head, "head")?;
        let (body, body_writes) = ByteClass::from_ranges(body, "body")?;
        let (trail, trail_writes) = ByteClass::from_ranges(trail, "trail")?;
        if head.overlaps(body) || head.overlaps(trail) || body.overlaps(trail) {
            return Err(BuildError::OverlappingClasses);
        }
        let bitmap_word_writes = head_writes
            .checked_add(body_writes)
            .and_then(|writes| writes.checked_add(trail_writes))
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "actual bitmap word writes",
            })?;
        let build = BuildAccounting {
            head_ranges,
            body_ranges,
            trail_ranges,
            source_ranges,
            minimum,
            maximum,
            range_inspections: source_ranges,
            validation_comparisons,
            bitmap_zero_writes: BITMAP_WORDS,
            bitmap_word_writes,
            overlap_comparisons: OVERLAP_COMPARISONS,
            work_bound,
            allocations: 0,
            reserves: 0,
            temporary_copies: 0,
            scratch_bytes: 0,
            persistent_bytes,
            peak_bytes: persistent_bytes,
        };
        Ok(Self {
            head,
            body,
            trail,
            minimum,
            maximum,
            build,
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
            minimum: self.minimum,
            maximum: self.maximum,
            greedy: true,
            non_overlapping: true,
        }
    }

    pub fn count(&self, haystack: &[u8], limits: ReduceLimits) -> Result<CountResult, ReduceError> {
        let upper_bounds = self.preflight(haystack.len(), limits)?;
        let actual = self.execute(haystack, upper_bounds)?;
        Ok(CountResult {
            count: actual.match_events,
            accounting: ReduceAccounting {
                identity: self.count_identity(),
                upper_bounds,
                actual,
            },
        })
    }

    fn preflight(
        &self,
        input_bytes: usize,
        limits: ReduceLimits,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        if input_bytes > limits.max_input_bytes {
            return Err(ReduceError::InputLimit {
                needed: input_bytes,
                limit: limits.max_input_bytes,
            });
        }
        let class_comparisons =
            input_bytes
                .checked_mul(3)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "class comparison bound",
                })?;
        let branch_charges = input_bytes
            .checked_mul(8)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "branch charge bound",
            })?;
        // A maximum-one unit can write run_start, units, completed_units,
        // run_end, matches, matched_bytes, reset units, and the outer state.
        let state_writes = input_bytes
            .checked_mul(8)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "state write bound",
            })?;
        let arithmetic_charges =
            input_bytes
                .checked_mul(8)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "arithmetic charge bound",
                })?;
        let work = input_bytes
            .checked_mul(WORK_PER_INPUT_BYTE)
            .and_then(|work| work.checked_add(FINALIZATION_WORK))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "execution work bound",
            })?;
        if work > limits.max_work {
            return Err(ReduceError::WorkLimit {
                needed: work,
                limit: limits.max_work,
            });
        }
        let minimum =
            usize::try_from(self.minimum).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "minimum repeat as usize",
            })?;
        // Every unit contains one HEAD and at least one BODY byte. Using the
        // complete minimum width avoids rejecting a safe count quota against
        // a looser input/min-repeat estimate.
        let minimum_match_bytes =
            minimum
                .checked_mul(2)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "minimum match bytes",
                })?;
        let match_events = u64::try_from(input_bytes.checked_div(minimum_match_bytes).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "match event division",
            },
        )?)
        .map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "match event bound",
        })?;
        if match_events > limits.max_count {
            return Err(ReduceError::CountLimit {
                needed: match_events,
                limit: limits.max_count,
            });
        }
        let persistent_bytes = self.build.persistent_bytes;
        if persistent_bytes > limits.max_peak_bytes {
            return Err(ReduceError::PeakLimit {
                needed: persistent_bytes,
                limit: limits.max_peak_bytes,
            });
        }
        Ok(ReduceUpperBounds {
            input_bytes,
            byte_inspections: input_bytes,
            class_comparisons,
            branch_charges,
            state_writes,
            arithmetic_charges,
            finalization_charges: FINALIZATION_WORK,
            match_events,
            span_sum: u64::try_from(input_bytes).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "span sum bound",
            })?,
            work,
            allocations: 0,
            reserves: 0,
            temporary_copies: 0,
            scratch_bytes: 0,
            persistent_bytes,
            peak_bytes: persistent_bytes,
        })
    }

    fn execute(
        &self,
        haystack: &[u8],
        upper: ReduceUpperBounds,
    ) -> Result<ReduceActualCounters, ReduceError> {
        let mut reducer = Reducer::new(self.minimum, self.maximum);
        let mut state = State::Seeking;
        for (position, &byte) in haystack.iter().enumerate() {
            let head = self.head.contains(byte);
            let body = self.body.contains(byte);
            let trail = self.trail.contains(byte);
            state = match state {
                State::Seeking => {
                    if head {
                        State::NeedBody { start: position }
                    } else {
                        State::Seeking
                    }
                }
                State::NeedBody { start } => {
                    if body {
                        State::Body { start }
                    } else if head {
                        reducer.finish_run()?;
                        State::NeedBody { start: position }
                    } else {
                        reducer.finish_run()?;
                        State::Seeking
                    }
                }
                State::Body { start } => {
                    if body {
                        State::Body { start }
                    } else if trail {
                        State::Trail { start }
                    } else {
                        reducer.complete_unit(start, position)?;
                        if head {
                            State::NeedBody { start: position }
                        } else {
                            reducer.finish_run()?;
                            State::Seeking
                        }
                    }
                }
                State::Trail { start } => {
                    if trail {
                        State::Trail { start }
                    } else {
                        reducer.complete_unit(start, position)?;
                        if head {
                            State::NeedBody { start: position }
                        } else {
                            reducer.finish_run()?;
                            State::Seeking
                        }
                    }
                }
            };
        }
        match state {
            State::Body { start } | State::Trail { start } => {
                reducer.complete_unit(start, haystack.len())?;
            }
            State::NeedBody { .. } | State::Seeking => {}
        }
        reducer.finish_run()?;
        Ok(ReduceActualCounters {
            input_bytes: haystack.len(),
            class_comparisons: upper.class_comparisons,
            completed_units: reducer.completed_units,
            discarded_units: reducer.discarded_units,
            match_events: reducer.matches,
            matched_bytes: reducer.matched_bytes,
            work_charged: upper.work,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Seeking,
    NeedBody { start: usize },
    Body { start: usize },
    Trail { start: usize },
}

struct Reducer {
    minimum: u32,
    maximum: u32,
    run_start: usize,
    units: u32,
    run_end: usize,
    completed_units: u64,
    discarded_units: u64,
    matches: u64,
    matched_bytes: u64,
}

impl Reducer {
    const fn new(minimum: u32, maximum: u32) -> Self {
        Self {
            minimum,
            maximum,
            run_start: 0,
            units: 0,
            run_end: 0,
            completed_units: 0,
            discarded_units: 0,
            matches: 0,
            matched_bytes: 0,
        }
    }

    fn complete_unit(&mut self, start: usize, end: usize) -> Result<(), ReduceError> {
        if self.units == 0 {
            self.run_start = start;
        }
        self.units = self
            .units
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "completed units in run",
            })?;
        self.completed_units =
            self.completed_units
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "total completed units",
                })?;
        self.run_end = end;
        if self.units == self.maximum {
            self.emit_match()?;
        }
        Ok(())
    }

    fn finish_run(&mut self) -> Result<(), ReduceError> {
        if self.units == 0 {
            return Ok(());
        }
        if self.units >= self.minimum {
            self.emit_match()?;
        } else {
            self.discarded_units = self
                .discarded_units
                .checked_add(u64::from(self.units))
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "discarded units",
                })?;
            self.units = 0;
        }
        Ok(())
    }

    fn emit_match(&mut self) -> Result<(), ReduceError> {
        let width =
            self.run_end
                .checked_sub(self.run_start)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "matched byte width",
                })?;
        self.matches = self
            .matches
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "match count",
            })?;
        self.matched_bytes = self
            .matched_bytes
            .checked_add(
                u64::try_from(width).map_err(|_| ReduceError::ArithmeticOverflow {
                    computation: "matched byte width as u64",
                })?,
            )
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "matched byte sum",
            })?;
        self.units = 0;
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum BuildResource {
    Ranges,
    Work,
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
        BuildResource::Persistent => BuildError::PersistentLimit { needed, limit },
        BuildResource::Peak => BuildError::PeakLimit { needed, limit },
    })
}

#[cfg(test)]
mod tests {
    use super::{BoundedClassSequencePlan, BuildError, BuildLimits, ReduceError, ReduceLimits};

    fn plan(head: &[(u8, u8)], body: &[(u8, u8)], trail: &[(u8, u8)]) -> BoundedClassSequencePlan {
        BoundedClassSequencePlan::build(
            head.iter().copied(),
            body.iter().copied(),
            trail.iter().copied(),
            2,
            3,
            BuildLimits::default(),
        )
        .unwrap()
    }

    // rebar-row:curated/10-bounded-repeat/capitals@rust/regex
    #[test]
    fn capitals_sequence_exact_work_boundary_is_hand_derived() {
        let plan = plan(&[(b'A', b'Z')], &[(b'a', b'z')], &[(b' ', b' ')]);
        let haystack = b"Aa Bb!";
        let exact_work = 176;
        let exact = ReduceLimits {
            max_work: exact_work,
            ..ReduceLimits::default()
        };
        let result = plan.count(haystack, exact).unwrap();
        assert_eq!(result.count, 1);
        assert_eq!(result.accounting.actual.matched_bytes, 5);
        assert_eq!(result.accounting.upper_bounds.work, exact_work);

        let one_below = ReduceLimits {
            max_work: 175,
            ..ReduceLimits::default()
        };
        assert!(matches!(
            plan.count(haystack, one_below),
            Err(ReduceError::WorkLimit { needed, limit })
                if needed == exact_work && limit.checked_add(1) == Some(exact_work)
        ));
    }

    // rebar-row:curated/10-bounded-repeat/capitals@rust/regex
    #[test]
    fn execution_scales_with_n_and_not_source_range_count() {
        let compact = plan(&[(b'A', b'Z')], &[(b'a', b'z')], &[(b' ', b' ')]);
        let medium = plan(
            &[(b'A', b'M'), (b'O', b'Z')],
            &[(b'a', b'm'), (b'o', b'z')],
            &[(0x01, 0x01), (b' ', b' ')],
        );
        let split = plan(
            &[(b'A', b'C'), (b'E', b'G'), (b'I', b'K'), (b'M', b'O')],
            &[(b'a', b'c'), (b'e', b'g'), (b'i', b'k'), (b'm', b'o')],
            &[(0x01, 0x01), (0x03, 0x03), (0x05, 0x05), (0x07, 0x07)],
        );
        assert_eq!(compact.build_accounting().source_ranges, 3);
        assert_eq!(medium.build_accounting().source_ranges, 6);
        assert_eq!(split.build_accounting().source_ranges, 12);
        for haystack in [
            b"Aa Bb!".as_slice(),
            b"Aa Bb!Aa Bb!",
            b"Aa Bb!Aa Bb!Aa Bb!Aa Bb!",
        ] {
            let compact_result = compact.count(haystack, ReduceLimits::default()).unwrap();
            let medium_result = medium.count(haystack, ReduceLimits::default()).unwrap();
            let split_result = split.count(haystack, ReduceLimits::default()).unwrap();
            let expected_work = haystack
                .len()
                .checked_mul(28)
                .unwrap()
                .checked_add(8)
                .unwrap();
            assert_eq!(compact_result.accounting.upper_bounds.work, expected_work);
            assert_eq!(medium_result.accounting.upper_bounds.work, expected_work);
            assert_eq!(split_result.accounting.upper_bounds.work, expected_work);
        }
        assert!(medium.build_accounting().work_bound > compact.build_accounting().work_bound);
        assert!(split.build_accounting().work_bound > medium.build_accounting().work_bound);
    }

    #[test]
    fn greedy_maximal_chunks_do_not_rebalance_a_short_remainder() {
        let plan = plan(&[(b'A', b'Z')], &[(b'a', b'z')], &[(b' ', b' ')]);
        let result = plan
            .count(b"Aa Bb Cc Dd!Ee Ff!G", ReduceLimits::default())
            .unwrap();
        // The first maximal run has four units. Greedy {2,3} consumes three
        // and discards the one-unit remainder instead of shortening match one.
        // The next two-unit run contributes the second match; the final head
        // without a body is not a unit.
        assert_eq!(result.count, 2);
        assert_eq!(result.accounting.actual.completed_units, 6);
        assert_eq!(result.accounting.actual.discarded_units, 1);
        assert_eq!(result.accounting.actual.matched_bytes, 14);
    }

    #[test]
    fn every_nonzero_build_limit_has_an_exact_and_one_below_boundary() {
        let baseline = plan(&[(b'A', b'Z')], &[(b'a', b'z')], &[(b' ', b' ')]).build_accounting();
        let exact = BuildLimits {
            max_source_ranges: baseline.source_ranges,
            max_repeat_bound: baseline.maximum,
            max_build_work: baseline.work_bound,
            max_persistent_bytes: baseline.persistent_bytes,
            max_peak_bytes: baseline.peak_bytes,
        };
        assert!(
            BoundedClassSequencePlan::build(
                [(b'A', b'Z')].into_iter(),
                [(b'a', b'z')].into_iter(),
                [(b' ', b' ')].into_iter(),
                2,
                3,
                exact,
            )
            .is_ok()
        );

        let cases = [
            (
                BuildLimits {
                    max_source_ranges: baseline.source_ranges - 1,
                    ..BuildLimits::default()
                },
                "ranges",
            ),
            (
                BuildLimits {
                    max_repeat_bound: baseline.maximum - 1,
                    ..BuildLimits::default()
                },
                "repeat",
            ),
            (
                BuildLimits {
                    max_build_work: baseline.work_bound - 1,
                    ..BuildLimits::default()
                },
                "work",
            ),
            (
                BuildLimits {
                    max_persistent_bytes: baseline.persistent_bytes - 1,
                    ..BuildLimits::default()
                },
                "persistent",
            ),
            (
                BuildLimits {
                    max_peak_bytes: baseline.peak_bytes - 1,
                    ..BuildLimits::default()
                },
                "peak",
            ),
        ];
        for (limits, expected) in cases {
            let error = BoundedClassSequencePlan::build(
                [(b'A', b'Z')].into_iter(),
                [(b'a', b'z')].into_iter(),
                [(b' ', b' ')].into_iter(),
                2,
                3,
                limits,
            )
            .unwrap_err();
            let actual = match error {
                BuildError::RangeLimit { .. } => "ranges",
                BuildError::RepeatLimit { .. } => "repeat",
                BuildError::WorkLimit { .. } => "work",
                BuildError::PersistentLimit { .. } => "persistent",
                BuildError::PeakLimit { .. } => "peak",
                other => panic!("unexpected build error: {other:?}"),
            };
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn every_nonzero_reduce_limit_is_preflighted_at_exact_and_one_below() {
        let plan = plan(&[(b'A', b'Z')], &[(b'a', b'z')], &[(b' ', b' ')]);
        let haystack = b"Aa Bb!";
        let baseline = plan
            .count(haystack, ReduceLimits::default())
            .unwrap()
            .accounting
            .upper_bounds;
        let exact = ReduceLimits {
            max_input_bytes: baseline.input_bytes,
            max_count: baseline.match_events,
            max_work: baseline.work,
            max_peak_bytes: baseline.peak_bytes,
        };
        assert!(plan.count(haystack, exact).is_ok());

        let cases = [
            (
                ReduceLimits {
                    max_input_bytes: baseline.input_bytes - 1,
                    ..ReduceLimits::default()
                },
                "input",
            ),
            (
                ReduceLimits {
                    max_count: baseline.match_events - 1,
                    ..ReduceLimits::default()
                },
                "count",
            ),
            (
                ReduceLimits {
                    max_work: baseline.work - 1,
                    ..ReduceLimits::default()
                },
                "work",
            ),
            (
                ReduceLimits {
                    max_peak_bytes: baseline.peak_bytes - 1,
                    ..ReduceLimits::default()
                },
                "peak",
            ),
        ];
        for (limits, expected) in cases {
            let error = plan.count(haystack, limits).unwrap_err();
            let actual = match error {
                ReduceError::InputLimit { .. } => "input",
                ReduceError::CountLimit { .. } => "count",
                ReduceError::WorkLimit { .. } => "work",
                ReduceError::PeakLimit { .. } => "peak",
                other => panic!("unexpected reduce error: {other:?}"),
            };
            assert_eq!(actual, expected);
        }
    }
}
