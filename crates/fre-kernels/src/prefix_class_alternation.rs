//! Two ordered `LITERAL BYTE_CLASS+` alternatives reduced in one linear stream.
//!
//! Each literal is proved non-self-overlapping by the sufficient condition
//! that its first byte does not occur in its remainder. Consequently one
//! persistent `memmem::Finder::find_iter` per alternative enumerates every
//! literal occurrence without restarting searches. Merging the two monotone
//! occurrence streams, then greedily extending the selected byte class,
//! implements Rust's leftmost-first, non-overlapping whole-match semantics in
//! `O(N + Q)` time and constant operation space. `N` is the haystack length;
//! `Q` is retained literal bytes plus canonical class ranges.
//!
//! Prospective resource ledger: compiler analysis charges each HIR inspection
//! (1), fixed branch comparison (2 total), literal-byte/self-overlap comparison
//! (2 per byte), and canonical range inspection (1 per range) before it occurs,
//! bounded by `H + 2L + R + 2`. Construction never trusts an iterator length:
//! it charges before every `next`, validates each yielded range, and writes its
//! at-most-four bitmap words in that same single traversal. The fixed 64 units
//! and eight units per retained prefix byte are admitted before construction;
//! self-overlap comparisons, iterator traversals, six base units per yielded
//! range, range comparisons/state writes, and four units per touched bitmap
//! word are then charged before they occur. This also covers two exact
//! allocations and copies, both linear Finder
//! preprocessors, eight bitmap zero-writes, branches, and plan publication.
//! Thus construction is `O(L + R)`, never `O(L * R)` or `O(R^2)`. Persistent,
//! retained-capacity, and peak admission is `size_of(plan) + L`; construction
//! scratch, reserve slack, temporary copies, deduplication storage, UTF-8 or
//! boundary preprocessing, and data-dependent stack/queue storage are zero;
//! the fixed local frame is `O(1)` and covered by the 64-unit fixed term.
//! Execution admits `16N + 8Q + 64`, `N` match events, and `N` count before
//! iterator creation or haystack inspection; this covers both monotone
//! searches, every candidate read/branch/start comparison, membership
//! comparison, counter/cursor write, and count conversion. Execution
//! allocation, initialization, reserve, copy, deduplication, UTF-8/boundary
//! preprocessing, and growing stack/queue storage are zero; its two iterators,
//! two next-candidate slots, and scalar counters form an `O(1)` fixed frame.
//! Allocation failure is typed and never changes the selected route.
//!
//! rebar-row:imported/leipzig/huck-saw@rust/regex

#![allow(
    clippy::arithmetic_side_effects,
    reason = "all reducer arithmetic is preflight-bounded or checked; bitmap shifts use proved 0..=63 operands"
)]

use core::{fmt, mem::size_of, ops::Range};

use fre_exact_alloc::CopyError;
use memchr::memmem::{Finder, FinderBuilder};

pub const PLAN_ID: &str = "prefix-class-alternation.two-monotone-literal-streams.v1";
pub const COUNT_OPERATION_ID: &str = "prefix-class-alternation.count.unicode-off.v1";
pub const UNIFORM_PARTICIPATION_PLAN_ID: &str =
    "prefix-class-alternation.uniform-participation.two-finder.v1";
pub const UNIFORM_PARTICIPATION_OPERATION_ID: &str =
    "prefix-class-alternation.capture-participation.unicode-off.v1";
pub const UNIFORM_PARTICIPATION_ALGORITHM_VERSION: u32 = 1;
pub const UNIFORM_PARTICIPATION_ACCOUNTING_VERSION: u32 = 1;

const FIXED_BUILD_WORK: usize = 64;
const PREFIX_BUILD_WORK_PER_BYTE: usize = 8;
const RANGE_ITEM_BASE_WORK: usize = 6;
const BITMAP_WORK_PER_WORD: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationIdentity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub alternatives: usize,
    pub unicode: bool,
    pub non_overlapping: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    pub max_shape_units: usize,
    pub max_build_work: usize,
    pub max_scratch_bytes: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl BuildLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_shape_units: usize::MAX,
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
            max_shape_units: 4 * 1024 * 1024,
            max_build_work: 32 * 1024 * 1024,
            max_scratch_bytes: 0,
            max_persistent_bytes: 32 * 1024 * 1024,
            max_peak_bytes: 32 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    pub prefix_bytes: usize,
    pub class_ranges: usize,
    pub shape_units: usize,
    pub work_upper_bound: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceLimits {
    pub max_work: usize,
    pub max_match_events: usize,
    pub max_count: u64,
    pub max_scratch_bytes: usize,
    pub max_peak_bytes: usize,
}

impl ReduceLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_work: usize::MAX,
            max_match_events: usize::MAX,
            max_count: u64::MAX,
            max_scratch_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for ReduceLimits {
    fn default() -> Self {
        Self {
            max_work: 512 * 1024 * 1024,
            max_match_events: 64 * 1024 * 1024,
            max_count: 64 * 1024 * 1024,
            max_scratch_bytes: 0,
            max_peak_bytes: 32 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceUpperBounds {
    pub haystack_bytes: usize,
    pub shape_units: usize,
    pub work: usize,
    pub match_events: usize,
    pub count: u64,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceActualCounters {
    pub prefix_candidates: usize,
    pub class_bytes: usize,
    pub matches: usize,
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

/// Capture-aware identity for the direct uniform-participation operation.
///
/// This is deliberately distinct from [`OperationIdentity`]: whole-match
/// aggregate Count and capture participation have different outputs, ledgers,
/// and fallback contracts even when they share the immutable prefix/class
/// plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UniformParticipationIdentity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub algorithm_version: u32,
    pub accounting_version: u32,
    pub alternatives: usize,
    pub unicode: bool,
    pub case_insensitive: bool,
    pub ordered_branch_priority: bool,
    pub greedy_class: bool,
    pub non_overlapping: bool,
    pub participating_with_overall: usize,
    pub capture_schema_slots: usize,
}

/// Capture schema proved from the same canonical HIR as the prefix/class plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UniformParticipationSchema {
    /// Group zero plus the fixed number of participating user groups.
    pub participating_with_overall: usize,
    /// Group zero plus every user slot, including unmatched branch siblings.
    pub capture_schema_slots: usize,
}

/// Independent direct-operation limits. Every positive dimension is checked
/// before iterator creation or haystack inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UniformParticipationLimits {
    pub max_work: usize,
    pub max_first_finder_bytes: usize,
    pub max_second_finder_bytes: usize,
    pub max_prefix_candidates: usize,
    pub max_start_arbitrations: usize,
    pub max_first_class_probes: usize,
    pub max_greedy_extension_reads: usize,
    pub max_results: usize,
    pub max_capture_count: usize,
    pub max_capture_events: usize,
    pub max_operation_allocations: usize,
    pub max_operation_bytes: usize,
    pub max_scratch_bytes: usize,
    pub max_peak_bytes: usize,
}

impl UniformParticipationLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_work: usize::MAX,
            max_first_finder_bytes: usize::MAX,
            max_second_finder_bytes: usize::MAX,
            max_prefix_candidates: usize::MAX,
            max_start_arbitrations: usize::MAX,
            max_first_class_probes: usize::MAX,
            max_greedy_extension_reads: usize::MAX,
            max_results: usize::MAX,
            max_capture_count: usize::MAX,
            max_capture_events: usize::MAX,
            max_operation_allocations: usize::MAX,
            max_operation_bytes: usize::MAX,
            max_scratch_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for UniformParticipationLimits {
    fn default() -> Self {
        Self {
            max_work: 512 * 1024 * 1024,
            max_first_finder_bytes: 64 * 1024 * 1024,
            max_second_finder_bytes: 64 * 1024 * 1024,
            max_prefix_candidates: 128 * 1024 * 1024,
            max_start_arbitrations: 256 * 1024 * 1024,
            max_first_class_probes: 128 * 1024 * 1024,
            max_greedy_extension_reads: 128 * 1024 * 1024,
            max_results: 64 * 1024 * 1024,
            max_capture_count: 128 * 1024 * 1024,
            max_capture_events: 192 * 1024 * 1024,
            max_operation_allocations: 0,
            max_operation_bytes: 0,
            max_scratch_bytes: 0,
            max_peak_bytes: 32 * 1024 * 1024,
        }
    }
}

/// Complete prospective ledger published before direct source access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UniformParticipationProspective {
    pub haystack_bytes: usize,
    pub shape_units: usize,
    pub first_finder_bytes: usize,
    pub second_finder_bytes: usize,
    pub prefix_candidates: usize,
    pub start_arbitrations: usize,
    pub first_class_probes: usize,
    pub greedy_extension_reads: usize,
    pub results: usize,
    pub capture_count: usize,
    pub capture_events: usize,
    pub work: usize,
    pub operation_allocations: usize,
    pub operation_bytes: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Complete actual direct-operation ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UniformParticipationActual {
    pub first_finder_bytes: usize,
    pub second_finder_bytes: usize,
    pub first_finder_candidates: usize,
    pub second_finder_candidates: usize,
    pub prefix_candidates: usize,
    pub start_arbitrations: usize,
    pub first_class_probes: usize,
    pub greedy_extension_reads: usize,
    pub results: usize,
    pub capture_count: usize,
    pub capture_events: usize,
    pub work: usize,
    pub operation_allocations: usize,
    pub operation_bytes: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UniformParticipationAccounting {
    pub identity: UniformParticipationIdentity,
    pub prospective: UniformParticipationProspective,
    pub actual: UniformParticipationActual,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UniformParticipationResult {
    pub matches: usize,
    pub capture_count: usize,
    pub accounting: UniformParticipationAccounting,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum UniformParticipationError {
    InvalidSchema,
    WorkLimit {
        needed: usize,
        limit: usize,
    },
    FirstFinderBytesLimit {
        needed: usize,
        limit: usize,
    },
    SecondFinderBytesLimit {
        needed: usize,
        limit: usize,
    },
    PrefixCandidatesLimit {
        needed: usize,
        limit: usize,
    },
    StartArbitrationsLimit {
        needed: usize,
        limit: usize,
    },
    FirstClassProbesLimit {
        needed: usize,
        limit: usize,
    },
    GreedyExtensionReadsLimit {
        needed: usize,
        limit: usize,
    },
    ResultsLimit {
        needed: usize,
        limit: usize,
    },
    CaptureCountLimit {
        needed: usize,
        limit: usize,
    },
    CaptureEventsLimit {
        needed: usize,
        limit: usize,
    },
    OperationAllocationsLimit {
        needed: usize,
        limit: usize,
    },
    OperationBytesLimit {
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
    ActualEscapedProspective {
        dimension: &'static str,
        actual: usize,
        prospective: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for UniformParticipationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "prefix/class uniform participation failed: {self:?}")
    }
}

impl std::error::Error for UniformParticipationError {}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    EmptyPrefix { alternative: usize },
    SelfOverlappingPrefix { alternative: usize },
    EmptyClass { alternative: usize },
    NonCanonicalClass { alternative: usize },
    ShapeLimit { needed: usize, limit: usize },
    WorkLimit { needed: usize, limit: usize },
    ScratchLimit { needed: usize, limit: usize },
    PersistentLimit { needed: usize, limit: usize },
    PeakLimit { needed: usize, limit: usize },
    AllocationFailed { alternative: usize, bytes: usize },
    ArithmeticOverflow { computation: &'static str },
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "prefix/class alternation build failed: {self:?}")
    }
}

impl std::error::Error for BuildError {}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReduceError {
    WorkLimit { needed: usize, limit: usize },
    MatchEventsLimit { needed: usize, limit: usize },
    CountLimit { needed: u64, limit: u64 },
    ScratchLimit { needed: usize, limit: usize },
    PeakLimit { needed: usize, limit: usize },
    ArithmeticOverflow { computation: &'static str },
}

impl fmt::Display for ReduceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "prefix/class alternation reduction failed: {self:?}")
    }
}

impl std::error::Error for ReduceError {}

#[derive(Clone, Copy, Debug)]
struct ByteClass {
    words: [u64; 4],
}

impl ByteClass {
    const fn empty() -> Self {
        Self { words: [0; 4] }
    }

    fn insert_range(&mut self, start: u8, end: u8, work: &mut BuildWork) -> Result<(), BuildError> {
        let first_word = usize::from(start) >> 6;
        let last_word = usize::from(end) >> 6;
        for word in first_word..=last_word {
            // Covers the loop traversal, the two boundary comparisons and the
            // bitmap word write before any of them occurs. A byte range can
            // touch at most four words, so this remains O(1) per yielded range.
            work.charge(BITMAP_WORK_PER_WORD)?;
            let low = if word == first_word {
                u32::from(start) & 63
            } else {
                0
            };
            let high = if word == last_word {
                u32::from(end) & 63
            } else {
                63
            };
            self.words[word] |= u64::MAX << low & u64::MAX >> (63 - high);
        }
        Ok(())
    }

    fn contains(self, byte: u8) -> bool {
        let word = usize::from(byte) >> 6;
        let bit = u32::from(byte) & 63;
        self.words[word] & (1_u64 << bit) != 0
    }
}

#[derive(Debug)]
struct Alternative {
    finder: Finder<'static>,
    class: ByteClass,
}

#[derive(Debug)]
pub struct PrefixClassAlternationPlan {
    alternatives: [Alternative; 2],
    build: BuildAccounting,
}

impl PrefixClassAlternationPlan {
    #[allow(
        clippy::needless_range_loop,
        clippy::too_many_lines,
        reason = "the fixed two-alternative proof keeps admission, validation, exact allocation, and publication adjacent"
    )]
    pub fn build<I>(
        prefixes: [&[u8]; 2],
        ranges: [I; 2],
        limits: BuildLimits,
    ) -> Result<Self, BuildError>
    where
        I: Iterator<Item = (u8, u8)>,
    {
        let prefix_bytes = prefixes[0].len().checked_add(prefixes[1].len()).ok_or(
            BuildError::ArithmeticOverflow {
                computation: "prefix byte total",
            },
        )?;
        let mut shape_units = prefix_bytes;
        let prefix_build_work = prefix_bytes
            .checked_mul(PREFIX_BUILD_WORK_PER_BYTE)
            .and_then(|work| work.checked_add(FIXED_BUILD_WORK))
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "fixed and prefix build work",
            })?;
        let persistent_bytes =
            size_of::<Self>()
                .checked_add(prefix_bytes)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "persistent bytes",
                })?;
        let scratch_bytes = 0;
        let peak_bytes = persistent_bytes;

        enforce_build(shape_units, limits.max_shape_units, BuildResource::Shape)?;
        enforce_build(
            scratch_bytes,
            limits.max_scratch_bytes,
            BuildResource::Scratch,
        )?;
        enforce_build(
            persistent_bytes,
            limits.max_persistent_bytes,
            BuildResource::Persistent,
        )?;
        enforce_build(peak_bytes, limits.max_peak_bytes, BuildResource::Peak)?;

        // This reservation precedes prefix validation, allocation, copying,
        // bitmap initialization and Finder preprocessing. Range-dependent work
        // is deliberately not guessed from `size_hint`/`ExactSizeIterator`.
        let mut work = BuildWork::new(limits.max_build_work);
        work.charge(prefix_build_work)?;

        for alternative in 0..2 {
            let prefix = prefixes[alternative];
            if prefix.is_empty() {
                return Err(BuildError::EmptyPrefix { alternative });
            }
            for &byte in &prefix[1..] {
                work.charge(1)?;
                if byte == prefix[0] {
                    return Err(BuildError::SelfOverlappingPrefix { alternative });
                }
            }
        }

        let mut classes = [ByteClass::empty(); 2];
        let mut class_ranges = 0_usize;
        for (alternative, mut ranges) in ranges.into_iter().enumerate() {
            let mut previous_end = None;
            loop {
                // Charge the traversal before calling user-supplied iterator
                // code. This includes each yielded item and the terminal None.
                work.charge(1)?;
                let Some((start, end)) = ranges.next() else {
                    break;
                };
                // Covers accepting the yielded item, both range/shape counter
                // writes, their checked arithmetic, the shape-limit comparison
                // and the previous-range presence branch before processing it.
                work.charge(RANGE_ITEM_BASE_WORK)?;
                class_ranges =
                    class_ranges
                        .checked_add(1)
                        .ok_or(BuildError::ArithmeticOverflow {
                            computation: "class range total",
                        })?;
                shape_units = prefix_bytes.checked_add(class_ranges).ok_or(
                    BuildError::ArithmeticOverflow {
                        computation: "shape units",
                    },
                )?;
                enforce_build(shape_units, limits.max_shape_units, BuildResource::Shape)?;

                work.charge(1)?;
                if start > end {
                    return Err(BuildError::NonCanonicalClass { alternative });
                }
                if let Some(previous) = previous_end {
                    work.charge(1)?;
                    if previous >= start {
                        return Err(BuildError::NonCanonicalClass { alternative });
                    }
                }
                work.charge(1)?;
                previous_end = Some(end);
                classes[alternative].insert_range(start, end, &mut work)?;
            }
            if previous_end.is_none() {
                return Err(BuildError::EmptyClass { alternative });
            }
        }

        // Admission above covers both exact allocations, every copied byte,
        // both Finder preprocessors, and all eight zero-initialized bitmap
        // words before any of that work occurs.
        let first = copy_prefix(prefixes[0], 0)?;
        let second = copy_prefix(prefixes[1], 1)?;
        let alternatives = [
            Alternative {
                finder: FinderBuilder::new().build_forward_owned(first.into_boxed_slice()),
                class: classes[0],
            },
            Alternative {
                finder: FinderBuilder::new().build_forward_owned(second.into_boxed_slice()),
                class: classes[1],
            },
        ];
        Ok(Self {
            alternatives,
            build: BuildAccounting {
                prefix_bytes,
                class_ranges,
                shape_units,
                work_upper_bound: work.used(),
                scratch_bytes,
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
            alternatives: 2,
            unicode: false,
            non_overlapping: true,
        }
    }

    pub fn count(&self, haystack: &[u8], limits: ReduceLimits) -> Result<CountResult, ReduceError> {
        let upper_bounds = self.preflight(haystack.len(), limits)?;
        let actual = self.scan(haystack, upper_bounds, |_| {})?;
        Ok(CountResult {
            count: actual.count,
            accounting: ReduceAccounting {
                identity: self.count_identity(),
                upper_bounds,
                actual,
            },
        })
    }

    #[must_use]
    pub const fn uniform_participation_identity(
        &self,
        schema: UniformParticipationSchema,
    ) -> UniformParticipationIdentity {
        UniformParticipationIdentity {
            plan_id: UNIFORM_PARTICIPATION_PLAN_ID,
            operation_id: UNIFORM_PARTICIPATION_OPERATION_ID,
            algorithm_version: UNIFORM_PARTICIPATION_ALGORITHM_VERSION,
            accounting_version: UNIFORM_PARTICIPATION_ACCOUNTING_VERSION,
            alternatives: 2,
            unicode: false,
            case_insensitive: false,
            ordered_branch_priority: true,
            greedy_class: true,
            non_overlapping: true,
            participating_with_overall: schema.participating_with_overall,
            capture_schema_slots: schema.capture_schema_slots,
        }
    }

    /// Publish the complete direct capture-operation envelope without source
    /// access. Callers can use this for transactional owner-local admission.
    pub fn uniform_participation_prospective(
        &self,
        haystack_len: usize,
        schema: UniformParticipationSchema,
        limits: UniformParticipationLimits,
    ) -> Result<UniformParticipationProspective, UniformParticipationError> {
        if schema.participating_with_overall == 0
            || schema.capture_schema_slots < schema.participating_with_overall
        {
            return Err(UniformParticipationError::InvalidSchema);
        }
        let first_finder_bytes = haystack_len;
        let second_finder_bytes = haystack_len;
        let prefix_candidates =
            haystack_len
                .checked_mul(2)
                .ok_or(UniformParticipationError::ArithmeticOverflow {
                    computation: "two complete prefix candidate streams",
                })?;
        let start_arbitrations =
            haystack_len
                .checked_mul(4)
                .ok_or(UniformParticipationError::ArithmeticOverflow {
                    computation: "candidate and selected-start arbitration",
                })?;
        let first_class_probes =
            haystack_len
                .checked_mul(2)
                .ok_or(UniformParticipationError::ArithmeticOverflow {
                    computation: "first-class probes",
                })?;
        let greedy_extension_reads =
            haystack_len
                .checked_mul(2)
                .ok_or(UniformParticipationError::ArithmeticOverflow {
                    computation: "greedy extension reads",
                })?;
        let results = haystack_len;
        let capture_count = results
            .checked_mul(schema.participating_with_overall)
            .ok_or(UniformParticipationError::ArithmeticOverflow {
                computation: "prospective participating capture count",
            })?;
        let capture_events = results.checked_mul(schema.capture_schema_slots).ok_or(
            UniformParticipationError::ArithmeticOverflow {
                computation: "prospective capture schema events",
            },
        )?;
        let shape_work = self
            .build
            .shape_units
            .checked_mul(8)
            .and_then(|value| value.checked_add(64))
            .ok_or(UniformParticipationError::ArithmeticOverflow {
                computation: "uniform participation shape work",
            })?;
        let work = [
            first_finder_bytes,
            second_finder_bytes,
            prefix_candidates,
            start_arbitrations,
            first_class_probes,
            greedy_extension_reads,
            results,
            capture_count,
            capture_events,
            shape_work,
        ]
        .into_iter()
        .try_fold(0_usize, |sum, value| {
            sum.checked_add(value)
                .ok_or(UniformParticipationError::ArithmeticOverflow {
                    computation: "uniform participation total work",
                })
        })?;
        let operation_allocations = 0;
        let operation_bytes = 0;
        let scratch_bytes = 0;
        let persistent_bytes = self.build.persistent_bytes;
        let peak_bytes = persistent_bytes;

        // Preserve reducer precedence independently of source-service limits.
        enforce_uniform(
            results,
            limits.max_results,
            UniformParticipationResource::Results,
        )?;
        enforce_uniform(
            capture_count,
            limits.max_capture_count,
            UniformParticipationResource::CaptureCount,
        )?;
        enforce_uniform(
            capture_events,
            limits.max_capture_events,
            UniformParticipationResource::CaptureEvents,
        )?;
        enforce_uniform(
            first_finder_bytes,
            limits.max_first_finder_bytes,
            UniformParticipationResource::FirstFinderBytes,
        )?;
        enforce_uniform(
            second_finder_bytes,
            limits.max_second_finder_bytes,
            UniformParticipationResource::SecondFinderBytes,
        )?;
        enforce_uniform(
            prefix_candidates,
            limits.max_prefix_candidates,
            UniformParticipationResource::PrefixCandidates,
        )?;
        enforce_uniform(
            start_arbitrations,
            limits.max_start_arbitrations,
            UniformParticipationResource::StartArbitrations,
        )?;
        enforce_uniform(
            first_class_probes,
            limits.max_first_class_probes,
            UniformParticipationResource::FirstClassProbes,
        )?;
        enforce_uniform(
            greedy_extension_reads,
            limits.max_greedy_extension_reads,
            UniformParticipationResource::GreedyExtensionReads,
        )?;
        enforce_uniform(work, limits.max_work, UniformParticipationResource::Work)?;
        enforce_uniform(
            operation_allocations,
            limits.max_operation_allocations,
            UniformParticipationResource::OperationAllocations,
        )?;
        enforce_uniform(
            operation_bytes,
            limits.max_operation_bytes,
            UniformParticipationResource::OperationBytes,
        )?;
        enforce_uniform(
            scratch_bytes,
            limits.max_scratch_bytes,
            UniformParticipationResource::Scratch,
        )?;
        enforce_uniform(
            peak_bytes,
            limits.max_peak_bytes,
            UniformParticipationResource::Peak,
        )?;
        Ok(UniformParticipationProspective {
            haystack_bytes: haystack_len,
            shape_units: self.build.shape_units,
            first_finder_bytes,
            second_finder_bytes,
            prefix_candidates,
            start_arbitrations,
            first_class_probes,
            greedy_extension_reads,
            results,
            capture_count,
            capture_events,
            work,
            operation_allocations,
            operation_bytes,
            scratch_bytes,
            persistent_bytes,
            peak_bytes,
        })
    }

    /// Count fixed capture participation using the direct prefix/class route.
    ///
    /// Preflight completes before either Finder iterator is created. Any
    /// failure after that publication is terminal and never invokes another
    /// route.
    pub fn count_uniform_participation(
        &self,
        haystack: &[u8],
        schema: UniformParticipationSchema,
        limits: UniformParticipationLimits,
    ) -> Result<UniformParticipationResult, UniformParticipationError> {
        let prospective = self.uniform_participation_prospective(haystack.len(), schema, limits)?;
        let (matches, actual) = self.scan_uniform_participation(haystack, schema, prospective)?;
        Ok(UniformParticipationResult {
            matches,
            capture_count: actual.capture_count,
            accounting: UniformParticipationAccounting {
                identity: self.uniform_participation_identity(schema),
                prospective,
                actual,
            },
        })
    }

    #[allow(
        clippy::needless_range_loop,
        clippy::too_many_lines,
        reason = "the fixed two-stream scan keeps each source read and its checked direct-operation counter adjacent"
    )]
    fn scan_uniform_participation(
        &self,
        haystack: &[u8],
        schema: UniformParticipationSchema,
        prospective: UniformParticipationProspective,
    ) -> Result<(usize, UniformParticipationActual), UniformParticipationError> {
        let mut streams = [
            self.alternatives[0].finder.find_iter(haystack),
            self.alternatives[1].finder.find_iter(haystack),
        ];
        let mut next = [streams[0].next(), streams[1].next()];
        let mut finder_candidates = [
            usize::from(next[0].is_some()),
            usize::from(next[1].is_some()),
        ];
        let mut selected_candidates = 0_usize;
        let mut first_class_probes = 0_usize;
        let mut greedy_extension_reads = 0_usize;
        let mut matches = 0_usize;
        let mut cursor = 0_usize;
        loop {
            for alternative in 0..2 {
                while next[alternative].is_some_and(|start| start < cursor) {
                    next[alternative] = streams[alternative].next();
                    finder_candidates[alternative] = finder_candidates[alternative]
                        .checked_add(usize::from(next[alternative].is_some()))
                        .ok_or(UniformParticipationError::ArithmeticOverflow {
                            computation: "actual finder candidates",
                        })?;
                }
            }
            let alternative = match (next[0], next[1]) {
                (None, None) => break,
                (Some(_), None) => 0,
                (None, Some(_)) => 1,
                // Alternative zero wins an equal-start tie.
                (Some(left), Some(right)) => usize::from(right < left),
            };
            let start = next[alternative].ok_or(UniformParticipationError::ArithmeticOverflow {
                computation: "selected direct prefix candidate",
            })?;
            selected_candidates = selected_candidates.checked_add(1).ok_or(
                UniformParticipationError::ArithmeticOverflow {
                    computation: "selected direct prefix candidates",
                },
            )?;
            next[alternative] = streams[alternative].next();
            finder_candidates[alternative] = finder_candidates[alternative]
                .checked_add(usize::from(next[alternative].is_some()))
                .ok_or(UniformParticipationError::ArithmeticOverflow {
                    computation: "actual finder candidates",
                })?;
            let prefix_end = start
                .checked_add(self.alternatives[alternative].finder.needle().len())
                .ok_or(UniformParticipationError::ArithmeticOverflow {
                    computation: "direct prefix end",
                })?;
            let Some(&first_class_byte) = haystack.get(prefix_end) else {
                continue;
            };
            first_class_probes = first_class_probes.checked_add(1).ok_or(
                UniformParticipationError::ArithmeticOverflow {
                    computation: "actual first-class probes",
                },
            )?;
            if !self.alternatives[alternative]
                .class
                .contains(first_class_byte)
            {
                continue;
            }
            let mut end =
                prefix_end
                    .checked_add(1)
                    .ok_or(UniformParticipationError::ArithmeticOverflow {
                        computation: "direct first class byte end",
                    })?;
            while let Some(&byte) = haystack.get(end) {
                greedy_extension_reads = greedy_extension_reads.checked_add(1).ok_or(
                    UniformParticipationError::ArithmeticOverflow {
                        computation: "actual greedy extension reads",
                    },
                )?;
                if !self.alternatives[alternative].class.contains(byte) {
                    break;
                }
                end = end
                    .checked_add(1)
                    .ok_or(UniformParticipationError::ArithmeticOverflow {
                        computation: "direct greedy class end",
                    })?;
            }
            matches =
                matches
                    .checked_add(1)
                    .ok_or(UniformParticipationError::ArithmeticOverflow {
                        computation: "direct match count",
                    })?;
            cursor = end;
        }
        let prefix_candidates = finder_candidates[0]
            .checked_add(finder_candidates[1])
            .ok_or(UniformParticipationError::ArithmeticOverflow {
                computation: "actual prefix candidate total",
            })?;
        let start_arbitrations = prefix_candidates.checked_add(selected_candidates).ok_or(
            UniformParticipationError::ArithmeticOverflow {
                computation: "actual start arbitration total",
            },
        )?;
        let capture_count = matches
            .checked_mul(schema.participating_with_overall)
            .ok_or(UniformParticipationError::ArithmeticOverflow {
                computation: "actual participating capture count",
            })?;
        let capture_events = matches.checked_mul(schema.capture_schema_slots).ok_or(
            UniformParticipationError::ArithmeticOverflow {
                computation: "actual capture schema events",
            },
        )?;
        let shape_work = prospective
            .shape_units
            .checked_mul(8)
            .and_then(|value| value.checked_add(64))
            .ok_or(UniformParticipationError::ArithmeticOverflow {
                computation: "actual direct shape work",
            })?;
        let work = [
            haystack.len(),
            haystack.len(),
            prefix_candidates,
            start_arbitrations,
            first_class_probes,
            greedy_extension_reads,
            matches,
            capture_count,
            capture_events,
            shape_work,
        ]
        .into_iter()
        .try_fold(0_usize, |sum, value| {
            sum.checked_add(value)
                .ok_or(UniformParticipationError::ArithmeticOverflow {
                    computation: "actual direct total work",
                })
        })?;
        let actual = UniformParticipationActual {
            first_finder_bytes: haystack.len(),
            second_finder_bytes: haystack.len(),
            first_finder_candidates: finder_candidates[0],
            second_finder_candidates: finder_candidates[1],
            prefix_candidates,
            start_arbitrations,
            first_class_probes,
            greedy_extension_reads,
            results: matches,
            capture_count,
            capture_events,
            work,
            operation_allocations: 0,
            operation_bytes: 0,
            scratch_bytes: 0,
            persistent_bytes: self.build.persistent_bytes,
            peak_bytes: self.build.persistent_bytes,
        };
        ensure_uniform_actual(&actual, &prospective)?;
        Ok((matches, actual))
    }

    fn preflight(
        &self,
        haystack_len: usize,
        limits: ReduceLimits,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        let work = haystack_len
            .checked_mul(16)
            .and_then(|work| {
                self.build
                    .shape_units
                    .checked_mul(8)
                    .and_then(|shape| work.checked_add(shape))
            })
            .and_then(|work| work.checked_add(64))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "16N + 8Q + 64 work bound",
            })?;
        let match_events = haystack_len;
        let count = u64::try_from(match_events).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "match event bound as u64",
        })?;
        let scratch_bytes = 0;
        let peak_bytes = self.build.persistent_bytes;
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
            scratch_bytes,
            limits.max_scratch_bytes,
            ReduceResource::Scratch,
        )?;
        enforce_reduce(peak_bytes, limits.max_peak_bytes, ReduceResource::Peak)?;
        Ok(ReduceUpperBounds {
            haystack_bytes: haystack_len,
            shape_units: self.build.shape_units,
            work,
            match_events,
            count,
            scratch_bytes,
            persistent_bytes: self.build.persistent_bytes,
            peak_bytes,
        })
    }

    #[allow(
        clippy::needless_range_loop,
        reason = "numeric indices preserve stable alternative priority across paired iterator and candidate arrays"
    )]
    fn scan(
        &self,
        haystack: &[u8],
        upper: ReduceUpperBounds,
        mut emit: impl FnMut(Range<usize>),
    ) -> Result<ReduceActualCounters, ReduceError> {
        let mut streams = [
            self.alternatives[0].finder.find_iter(haystack),
            self.alternatives[1].finder.find_iter(haystack),
        ];
        let mut next = [streams[0].next(), streams[1].next()];
        let mut cursor = 0_usize;
        let mut prefix_candidates = 0_usize;
        let mut class_bytes = 0_usize;
        let mut matches = 0_usize;
        loop {
            for alternative in 0..2 {
                while next[alternative].is_some_and(|start| start < cursor) {
                    next[alternative] = streams[alternative].next();
                }
            }
            let alternative = match (next[0], next[1]) {
                (None, None) => break,
                (Some(_), None) => 0,
                (None, Some(_)) => 1,
                (Some(left), Some(right)) => usize::from(right < left),
            };
            let start = next[alternative].ok_or(ReduceError::ArithmeticOverflow {
                computation: "selected prefix candidate",
            })?;
            next[alternative] = streams[alternative].next();
            prefix_candidates =
                prefix_candidates
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "prefix candidate count",
                    })?;
            let prefix_end = start
                .checked_add(self.alternatives[alternative].finder.needle().len())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "prefix end",
                })?;
            let Some(&first_class_byte) = haystack.get(prefix_end) else {
                continue;
            };
            class_bytes = class_bytes
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "class byte count",
                })?;
            if !self.alternatives[alternative]
                .class
                .contains(first_class_byte)
            {
                continue;
            }
            let mut end = prefix_end
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "first class byte end",
                })?;
            while let Some(&byte) = haystack.get(end) {
                class_bytes =
                    class_bytes
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "class byte count",
                        })?;
                if !self.alternatives[alternative].class.contains(byte) {
                    break;
                }
                end = end.checked_add(1).ok_or(ReduceError::ArithmeticOverflow {
                    computation: "greedy class end",
                })?;
            }
            emit(start..end);
            matches = matches
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "match count",
                })?;
            cursor = end;
        }
        let count = u64::try_from(matches).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "actual count as u64",
        })?;
        debug_assert!(matches <= upper.match_events);
        Ok(ReduceActualCounters {
            prefix_candidates,
            class_bytes,
            matches,
            count,
        })
    }
}

fn copy_prefix(prefix: &[u8], alternative: usize) -> Result<Vec<u8>, BuildError> {
    fre_exact_alloc::copy_exact(prefix).map_err(|error| match error {
        CopyError::LayoutOverflow => BuildError::ArithmeticOverflow {
            computation: "exact prefix allocation layout",
        },
        CopyError::AllocationFailed => BuildError::AllocationFailed {
            alternative,
            bytes: prefix.len(),
        },
    })
}

#[derive(Clone, Copy, Debug)]
struct BuildWork {
    used: usize,
    limit: usize,
}

impl BuildWork {
    const fn new(limit: usize) -> Self {
        Self { used: 0, limit }
    }

    fn charge(&mut self, units: usize) -> Result<(), BuildError> {
        let needed = self
            .used
            .checked_add(units)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "charged build work",
            })?;
        if needed > self.limit {
            return Err(BuildError::WorkLimit {
                needed,
                limit: self.limit,
            });
        }
        self.used = needed;
        Ok(())
    }

    const fn used(self) -> usize {
        self.used
    }
}

#[derive(Clone, Copy)]
enum BuildResource {
    Shape,
    Scratch,
    Persistent,
    Peak,
}

fn enforce_build(needed: usize, limit: usize, resource: BuildResource) -> Result<(), BuildError> {
    if needed <= limit {
        return Ok(());
    }
    Err(match resource {
        BuildResource::Shape => BuildError::ShapeLimit { needed, limit },
        BuildResource::Scratch => BuildError::ScratchLimit { needed, limit },
        BuildResource::Persistent => BuildError::PersistentLimit { needed, limit },
        BuildResource::Peak => BuildError::PeakLimit { needed, limit },
    })
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

#[derive(Clone, Copy)]
enum UniformParticipationResource {
    Work,
    FirstFinderBytes,
    SecondFinderBytes,
    PrefixCandidates,
    StartArbitrations,
    FirstClassProbes,
    GreedyExtensionReads,
    Results,
    CaptureCount,
    CaptureEvents,
    OperationAllocations,
    OperationBytes,
    Scratch,
    Peak,
}

fn enforce_uniform(
    needed: usize,
    limit: usize,
    resource: UniformParticipationResource,
) -> Result<(), UniformParticipationError> {
    if needed <= limit {
        return Ok(());
    }
    Err(match resource {
        UniformParticipationResource::Work => {
            UniformParticipationError::WorkLimit { needed, limit }
        }
        UniformParticipationResource::FirstFinderBytes => {
            UniformParticipationError::FirstFinderBytesLimit { needed, limit }
        }
        UniformParticipationResource::SecondFinderBytes => {
            UniformParticipationError::SecondFinderBytesLimit { needed, limit }
        }
        UniformParticipationResource::PrefixCandidates => {
            UniformParticipationError::PrefixCandidatesLimit { needed, limit }
        }
        UniformParticipationResource::StartArbitrations => {
            UniformParticipationError::StartArbitrationsLimit { needed, limit }
        }
        UniformParticipationResource::FirstClassProbes => {
            UniformParticipationError::FirstClassProbesLimit { needed, limit }
        }
        UniformParticipationResource::GreedyExtensionReads => {
            UniformParticipationError::GreedyExtensionReadsLimit { needed, limit }
        }
        UniformParticipationResource::Results => {
            UniformParticipationError::ResultsLimit { needed, limit }
        }
        UniformParticipationResource::CaptureCount => {
            UniformParticipationError::CaptureCountLimit { needed, limit }
        }
        UniformParticipationResource::CaptureEvents => {
            UniformParticipationError::CaptureEventsLimit { needed, limit }
        }
        UniformParticipationResource::OperationAllocations => {
            UniformParticipationError::OperationAllocationsLimit { needed, limit }
        }
        UniformParticipationResource::OperationBytes => {
            UniformParticipationError::OperationBytesLimit { needed, limit }
        }
        UniformParticipationResource::Scratch => {
            UniformParticipationError::ScratchLimit { needed, limit }
        }
        UniformParticipationResource::Peak => {
            UniformParticipationError::PeakLimit { needed, limit }
        }
    })
}

fn ensure_uniform_actual(
    actual: &UniformParticipationActual,
    prospective: &UniformParticipationProspective,
) -> Result<(), UniformParticipationError> {
    for (dimension, actual, prospective) in [
        (
            "first finder bytes",
            actual.first_finder_bytes,
            prospective.first_finder_bytes,
        ),
        (
            "second finder bytes",
            actual.second_finder_bytes,
            prospective.second_finder_bytes,
        ),
        (
            "prefix candidates",
            actual.prefix_candidates,
            prospective.prefix_candidates,
        ),
        (
            "start arbitrations",
            actual.start_arbitrations,
            prospective.start_arbitrations,
        ),
        (
            "first class probes",
            actual.first_class_probes,
            prospective.first_class_probes,
        ),
        (
            "greedy extension reads",
            actual.greedy_extension_reads,
            prospective.greedy_extension_reads,
        ),
        ("results", actual.results, prospective.results),
        (
            "capture count",
            actual.capture_count,
            prospective.capture_count,
        ),
        (
            "capture events",
            actual.capture_events,
            prospective.capture_events,
        ),
        ("work", actual.work, prospective.work),
        (
            "operation allocations",
            actual.operation_allocations,
            prospective.operation_allocations,
        ),
        (
            "operation bytes",
            actual.operation_bytes,
            prospective.operation_bytes,
        ),
        (
            "scratch bytes",
            actual.scratch_bytes,
            prospective.scratch_bytes,
        ),
        (
            "persistent bytes",
            actual.persistent_bytes,
            prospective.persistent_bytes,
        ),
        ("peak bytes", actual.peak_bytes, prospective.peak_bytes),
    ] {
        if actual > prospective {
            return Err(UniformParticipationError::ActualEscapedProspective {
                dimension,
                actual,
                prospective,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, rc::Rc};

    use regex::bytes::RegexBuilder;

    use super::*;

    fn plan() -> PrefixClassAlternationPlan {
        PrefixClassAlternationPlan::build(
            [b"ab", b"xy"],
            [[(b'a', b'z')].into_iter(), [(b'0', b'9')].into_iter()],
            BuildLimits::unlimited(),
        )
        .unwrap()
    }

    fn sut_spans(plan: &PrefixClassAlternationPlan, haystack: &[u8]) -> Vec<Range<usize>> {
        let upper = plan
            .preflight(haystack.len(), ReduceLimits::unlimited())
            .unwrap();
        let mut spans = Vec::new();
        plan.scan(haystack, upper, |span| spans.push(span)).unwrap();
        spans
    }

    fn reference_spans(pattern: &str, haystack: &[u8]) -> Vec<Range<usize>> {
        RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap()
            .find_iter(haystack)
            .map(|matched| matched.start()..matched.end())
            .collect()
    }

    fn rust_functions_plan() -> PrefixClassAlternationPlan {
        let word = [(b'0', b'9'), (b'A', b'Z'), (b'_', b'_'), (b'a', b'z')];
        PrefixClassAlternationPlan::build(
            [b"fn is_", b"fn as_"],
            [word.into_iter(), word.into_iter()],
            BuildLimits::unlimited(),
        )
        .unwrap()
    }

    const fn rust_functions_schema() -> UniformParticipationSchema {
        UniformParticipationSchema {
            participating_with_overall: 2,
            capture_schema_slots: 3,
        }
    }

    fn exact_uniform_limits(
        prospective: UniformParticipationProspective,
    ) -> UniformParticipationLimits {
        UniformParticipationLimits {
            max_work: prospective.work,
            max_first_finder_bytes: prospective.first_finder_bytes,
            max_second_finder_bytes: prospective.second_finder_bytes,
            max_prefix_candidates: prospective.prefix_candidates,
            max_start_arbitrations: prospective.start_arbitrations,
            max_first_class_probes: prospective.first_class_probes,
            max_greedy_extension_reads: prospective.greedy_extension_reads,
            max_results: prospective.results,
            max_capture_count: prospective.capture_count,
            max_capture_events: prospective.capture_events,
            max_operation_allocations: prospective.operation_allocations,
            max_operation_bytes: prospective.operation_bytes,
            max_scratch_bytes: prospective.scratch_bytes,
            max_peak_bytes: prospective.peak_bytes,
        }
    }

    #[test]
    fn rust_functions_uniform_participation_matches_complete_reference_spans() {
        let plan = rust_functions_plan();
        let pattern = r"fn is_(\w+)|fn as_(\w+)";
        for haystack in [
            b"".as_slice(),
            b"fn is_alpha fn as_beta",
            b"fn is_ fn as_",
            b"fn as_9fn is_Z",
            b"fn is_a\x00fn as_b\xfffn is_c",
            b"fn is_azAZ09_fn as_0__ fn is_\x80",
        ] {
            let spans = reference_spans(pattern, haystack);
            let result = plan
                .count_uniform_participation(
                    haystack,
                    rust_functions_schema(),
                    UniformParticipationLimits::unlimited(),
                )
                .unwrap();
            assert_eq!(spans.len(), result.matches, "haystack={haystack:?}");
            assert_eq!(spans.len() * 2, result.capture_count);
            assert_eq!(spans.len() * 3, result.accounting.actual.capture_events);
            assert_eq!(0, result.accounting.actual.operation_allocations);
            assert_eq!(0, result.accounting.actual.operation_bytes);
            assert_eq!(0, result.accounting.actual.scratch_bytes);
            ensure_uniform_actual(&result.accounting.actual, &result.accounting.prospective)
                .unwrap();
        }
    }

    #[test]
    fn rust_functions_uniform_participation_exact_and_every_positive_one_below() {
        let plan = rust_functions_plan();
        let haystack = b"fn is_alpha fn as_beta";
        let schema = rust_functions_schema();
        let prospective = plan
            .uniform_participation_prospective(
                haystack.len(),
                schema,
                UniformParticipationLimits::unlimited(),
            )
            .unwrap();
        let exact = exact_uniform_limits(prospective);
        assert_eq!(
            4,
            plan.count_uniform_participation(haystack, schema, exact)
                .unwrap()
                .capture_count
        );

        macro_rules! one_below {
            ($limit_field:ident, $prospective_field:ident, $pattern:pat) => {{
                assert!(prospective.$prospective_field > 0);
                let mut limits = exact;
                limits.$limit_field = prospective.$prospective_field - 1;
                assert!(matches!(
                    plan.count_uniform_participation(haystack, schema, limits),
                    Err($pattern)
                ));
            }};
        }
        one_below!(
            max_results,
            results,
            UniformParticipationError::ResultsLimit { .. }
        );
        one_below!(
            max_capture_count,
            capture_count,
            UniformParticipationError::CaptureCountLimit { .. }
        );
        one_below!(
            max_capture_events,
            capture_events,
            UniformParticipationError::CaptureEventsLimit { .. }
        );
        one_below!(
            max_first_finder_bytes,
            first_finder_bytes,
            UniformParticipationError::FirstFinderBytesLimit { .. }
        );
        one_below!(
            max_second_finder_bytes,
            second_finder_bytes,
            UniformParticipationError::SecondFinderBytesLimit { .. }
        );
        one_below!(
            max_prefix_candidates,
            prefix_candidates,
            UniformParticipationError::PrefixCandidatesLimit { .. }
        );
        one_below!(
            max_start_arbitrations,
            start_arbitrations,
            UniformParticipationError::StartArbitrationsLimit { .. }
        );
        one_below!(
            max_first_class_probes,
            first_class_probes,
            UniformParticipationError::FirstClassProbesLimit { .. }
        );
        one_below!(
            max_greedy_extension_reads,
            greedy_extension_reads,
            UniformParticipationError::GreedyExtensionReadsLimit { .. }
        );
        one_below!(max_work, work, UniformParticipationError::WorkLimit { .. });
        one_below!(
            max_peak_bytes,
            peak_bytes,
            UniformParticipationError::PeakLimit { .. }
        );
    }

    #[test]
    fn rust_functions_uniform_participation_n_2n_4n_is_deterministic() {
        let plan = rust_functions_plan();
        let schema = rust_functions_schema();
        let mut previous = None;
        for n in [128, 256, 512] {
            let prospective = plan
                .uniform_participation_prospective(
                    n,
                    schema,
                    UniformParticipationLimits::unlimited(),
                )
                .unwrap();
            assert_eq!(n, prospective.first_finder_bytes);
            assert_eq!(n, prospective.second_finder_bytes);
            assert_eq!(2 * n, prospective.prefix_candidates);
            assert_eq!(4 * n, prospective.start_arbitrations);
            assert_eq!(2 * n, prospective.first_class_probes);
            assert_eq!(2 * n, prospective.greedy_extension_reads);
            assert_eq!(n, prospective.results);
            assert_eq!(2 * n, prospective.capture_count);
            assert_eq!(3 * n, prospective.capture_events);
            if let Some((previous_n, previous_work)) = previous {
                let fixed = plan.build_accounting().shape_units * 8 + 64;
                assert_eq!((n - previous_n) * 18, prospective.work - previous_work);
                assert_eq!(fixed + 18 * n, prospective.work);
            }
            previous = Some((n, prospective.work));
        }
    }

    struct DeceptiveExactRanges {
        items: &'static [(u8, u8)],
        position: usize,
        next_calls: Rc<Cell<usize>>,
        len_calls: Rc<Cell<usize>>,
    }

    impl Iterator for DeceptiveExactRanges {
        type Item = (u8, u8);

        fn next(&mut self) -> Option<Self::Item> {
            self.next_calls.set(self.next_calls.get() + 1);
            let item = self.items.get(self.position).copied();
            self.position += usize::from(item.is_some());
            item
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            // Deliberately violates ExactSizeIterator's semantic contract.
            // Resource safety must depend on actual traversal, not this claim.
            (0, Some(0))
        }
    }

    impl ExactSizeIterator for DeceptiveExactRanges {
        fn len(&self) -> usize {
            self.len_calls.set(self.len_calls.get() + 1);
            0
        }
    }

    fn deceptive_ranges(
        items: &'static [(u8, u8)],
    ) -> (DeceptiveExactRanges, Rc<Cell<usize>>, Rc<Cell<usize>>) {
        let next_calls = Rc::new(Cell::new(0));
        let len_calls = Rc::new(Cell::new(0));
        (
            DeceptiveExactRanges {
                items,
                position: 0,
                next_calls: Rc::clone(&next_calls),
                len_calls: Rc::clone(&len_calls),
            },
            next_calls,
            len_calls,
        )
    }

    #[test]
    fn rebar_row_imported_leipzig_huck_saw_exact_256_and_one_below_255() {
        // rebar-row:imported/leipzig/huck-saw@rust/regex
        // Independent witness: N=9, Q=(2+2)+(1+1)=6, hence
        // W=16*9+8*6+64=256. Expected complete spans are 0..4 and 6..9.
        let plan = plan();
        let haystack = b"abcz--xy7";
        let expected = vec![0..4, 6..9];
        assert_eq!(expected, sut_spans(&plan, haystack));
        let exact = ReduceLimits {
            max_work: 256,
            ..ReduceLimits::unlimited()
        };
        assert_eq!(2, plan.count(haystack, exact).unwrap().count);
        let one_below = ReduceLimits {
            max_work: 255,
            ..ReduceLimits::unlimited()
        };
        assert_eq!(
            Err(ReduceError::WorkLimit {
                needed: 256,
                limit: 255,
            }),
            plan.count(haystack, one_below)
        );
    }

    #[test]
    fn rebar_row_imported_leipzig_huck_saw_complete_span_differential_boundaries() {
        // rebar-row:imported/leipzig/huck-saw@rust/regex
        let plan = plan();
        for haystack in [
            b"".as_slice(),
            b"abz",
            b"_abzz_xy7_",
            b"abxy7",
            b"ababzxy77",
            b"\xFFabq\x80xy0",
        ] {
            assert_eq!(
                reference_spans(r"ab[a-z]+|xy[0-9]+", haystack),
                sut_spans(&plan, haystack),
                "haystack={haystack:?}"
            );
        }
    }

    #[test]
    fn rebar_row_imported_leipzig_huck_saw_additive_n_and_q_witnesses() {
        // rebar-row:imported/leipzig/huck-saw@rust/regex
        // With Q=6, N/2N/4N at 32/64/128 bytes gives exactly
        // 16N+8Q+64 = 624/1136/2160 admitted runtime work.
        let plan = plan();
        for (n, expected) in [(32, 624), (64, 1_136), (128, 2_160)] {
            let upper = plan.preflight(n, ReduceLimits::unlimited()).unwrap();
            assert_eq!(expected, upper.work);
        }

        // Independent Q/2Q/4Q build adversaries use two canonical ranges and
        // prefix payloads of Q-2. The single-pass charged ledger gives
        // 9Q+72 = 216/360/648 at Q=16/32/64.
        for (q, expected) in [(16, 216), (32, 360), (64, 648)] {
            let per_prefix = (q - 2) / 2;
            let mut first = vec![b'b'; per_prefix];
            let mut second = vec![b'd'; per_prefix];
            first[0] = b'A';
            second[0] = b'C';
            let scaled = PrefixClassAlternationPlan::build(
                [&first, &second],
                [[(b'a', b'z')].into_iter(), [(b'0', b'9')].into_iter()],
                BuildLimits::unlimited(),
            )
            .unwrap();
            assert_eq!(q, scaled.build_accounting().shape_units);
            assert_eq!(expected, scaled.build_accounting().work_upper_bound);
        }
    }

    #[test]
    fn deceptive_exact_size_ranges_are_single_pass_and_exactly_charged() {
        static FIRST: [(u8, u8); 2] = [(b'a', b'm'), (b'n', b'z')];
        static SECOND: [(u8, u8); 2] = [(b'0', b'4'), (b'5', b'9')];

        let (first, first_next, first_len) = deceptive_ranges(&FIRST);
        let (second, second_next, second_len) = deceptive_ranges(&SECOND);
        let baseline = PrefixClassAlternationPlan::build(
            [b"ab", b"xy"],
            [first, second],
            BuildLimits::unlimited(),
        )
        .unwrap();
        let accounting = baseline.build_accounting();
        assert_eq!(4, accounting.class_ranges);
        assert_eq!(8, accounting.shape_units);
        assert_eq!(0, first_len.get());
        assert_eq!(0, second_len.get());
        assert_eq!(FIRST.len() + 1, first_next.get());
        assert_eq!(SECOND.len() + 1, second_next.get());

        let (first, _, first_len) = deceptive_ranges(&FIRST);
        let (second, _, second_len) = deceptive_ranges(&SECOND);
        let exact = PrefixClassAlternationPlan::build(
            [b"ab", b"xy"],
            [first, second],
            BuildLimits {
                max_shape_units: accounting.shape_units,
                max_build_work: accounting.work_upper_bound,
                ..BuildLimits::unlimited()
            },
        )
        .unwrap();
        assert_eq!(accounting, exact.build_accounting());
        assert_eq!(0, first_len.get());
        assert_eq!(0, second_len.get());

        let (first, _, _) = deceptive_ranges(&FIRST);
        let (second, _, _) = deceptive_ranges(&SECOND);
        assert!(matches!(
            PrefixClassAlternationPlan::build(
                [b"ab", b"xy"],
                [first, second],
                BuildLimits {
                    max_build_work: accounting.work_upper_bound - 1,
                    ..BuildLimits::unlimited()
                },
            ),
            Err(BuildError::WorkLimit { needed, limit })
                if needed == accounting.work_upper_bound
                    && limit == accounting.work_upper_bound - 1
        ));

        let (first, _, _) = deceptive_ranges(&FIRST);
        let (second, _, _) = deceptive_ranges(&SECOND);
        assert!(matches!(
            PrefixClassAlternationPlan::build(
                [b"ab", b"xy"],
                [first, second],
                BuildLimits {
                    max_shape_units: accounting.shape_units - 1,
                    ..BuildLimits::unlimited()
                },
            ),
            Err(BuildError::ShapeLimit {
                needed: 8,
                limit: 7
            })
        ));
    }
}
