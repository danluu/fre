//! Required internal-anchor candidate streaming with bounded continuation.
//!
//! The admitted grammar is `PREFIX+ ANCHOR HEAD+ TAIL+ OPTIONAL*`, where
//! `PREFIX` excludes the first anchor byte, the anchor is unbordered, `HEAD`
//! is a subset of `TAIL`, and each optional phase has a one-byte introducer
//! excluded by every preceding continuation class. These proofs make anchor
//! candidates non-overlapping, failed verification constant-work, and
//! successful greedy continuation scans disjoint after normal regex
//! non-overlap. Execution therefore streams one candidate and one continuation
//! state without a queue, active set, scratch allocation, or input rewind.

use core::{fmt, mem::size_of};

use crate::required_literal::ByteClass;

pub const PLAN_ID: &str = "required-internal-anchor.bounded-continuation.v3";
pub const COUNT_OPERATION_ID: &str = "required-internal-anchor.count.v3";
pub const MAX_OPTIONAL_STAGES: usize = 4;
const MAX_ANCHOR_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OptionalStageSource {
    pub introducer: u8,
    pub class: ByteClass,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContinuationSource {
    pub head: ByteClass,
    pub tail: ByteClass,
    pub optional: [Option<OptionalStageSource>; MAX_OPTIONAL_STAGES],
    pub optional_count: u8,
}

impl ContinuationSource {
    #[must_use]
    pub const fn new(head: ByteClass, tail: ByteClass) -> Self {
        Self {
            head,
            tail,
            optional: [None; MAX_OPTIONAL_STAGES],
            optional_count: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    pub max_anchor_bytes: usize,
    pub max_build_work: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
    pub max_allocations: usize,
    pub max_reserves: usize,
    pub max_source_copies: usize,
    pub max_scratch_bytes: usize,
}

impl Default for BuildLimits {
    fn default() -> Self {
        Self {
            max_anchor_bytes: 1 << 20,
            max_build_work: 1 << 24,
            max_persistent_bytes: 1 << 24,
            max_peak_bytes: 1 << 24,
            max_allocations: 1,
            max_reserves: 1,
            max_source_copies: 1,
            max_scratch_bytes: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    pub anchor_bytes: usize,
    pub class_words: usize,
    pub optional_stages: usize,
    /// Conservative work envelope admitted before any descriptor or source traversal.
    pub work_upper_bound: usize,
    /// Exact logical work observed in the metered Rust structural proof and source copy.
    pub observed_structural_work: usize,
    pub admission_checks: usize,
    pub descriptor_checks: usize,
    pub class_word_checks: usize,
    pub class_membership_checks: usize,
    pub optional_slot_checks: usize,
    pub optional_pair_checks: usize,
    pub border_candidates: usize,
    pub border_byte_comparisons: usize,
    pub anchor_storage_initialization_bytes: usize,
    pub anchor_copy_bytes: usize,
    pub allocations: usize,
    pub reserves: usize,
    pub source_copies: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountLimits {
    pub max_input_bytes: usize,
    pub max_candidate_visits: usize,
    pub max_continuation_steps: usize,
    pub max_source_accesses: usize,
    pub max_random_access_bytes: usize,
    pub max_sequential_bytes: usize,
    pub max_work: usize,
    pub max_count: u64,
    pub max_queue_entries: usize,
    pub max_frontier_entries: usize,
    pub max_allocations: usize,
    pub max_scratch_bytes: usize,
    pub max_peak_bytes: usize,
}

impl Default for CountLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 128 << 20,
            max_candidate_visits: 128 << 20,
            max_continuation_steps: 1 << 29,
            max_source_accesses: 1 << 29,
            max_random_access_bytes: 1 << 29,
            max_sequential_bytes: 1 << 29,
            max_work: 1 << 29,
            max_count: 128 << 20,
            max_queue_entries: 0,
            max_frontier_entries: 0,
            max_allocations: 0,
            max_scratch_bytes: 0,
            max_peak_bytes: 1 << 24,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountUpperBounds {
    pub input_bytes: usize,
    pub candidate_visits: usize,
    pub finder_calls: usize,
    pub anchor_window_attempts: usize,
    pub finder_source_accesses: usize,
    pub prefix_steps: usize,
    pub continuation_steps: usize,
    pub source_accesses: usize,
    pub random_access_bytes: usize,
    pub sequential_bytes: usize,
    pub control_work: usize,
    pub work: usize,
    pub count: u64,
    pub queue_entries: usize,
    pub frontier_entries: usize,
    pub allocations: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CountActual {
    pub candidate_visits: usize,
    pub finder_calls: usize,
    pub anchor_window_attempts: usize,
    pub finder_source_accesses: usize,
    pub prefix_steps: usize,
    pub continuation_steps: usize,
    pub source_accesses: usize,
    pub random_access_bytes: usize,
    pub sequential_bytes: usize,
    /// Exact logical non-source control transitions executed by this operation.
    pub control_work: usize,
    pub work: usize,
    pub queue_entries: usize,
    pub frontier_entries: usize,
    pub allocations: usize,
    pub scratch_bytes: usize,
    pub peak_bytes: usize,
    pub matches: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountAccounting {
    pub build: BuildAccounting,
    pub upper_bounds: CountUpperBounds,
    pub actual: CountActual,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountResult {
    pub count: u64,
    pub accounting: CountAccounting,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    EmptyPrefix,
    EmptyAnchor,
    AnchorLimit { needed: usize, limit: usize },
    AnchorStartsInPrefix { byte: u8 },
    OverlappingAnchor { border: usize },
    EmptyHead,
    EmptyTail,
    HeadNotSubsetOfTail,
    OptionalCount { count: u8 },
    MissingOptional { index: usize },
    UnexpectedOptional { index: usize },
    DuplicateIntroducer { byte: u8 },
    IntroducerInPrecedingClass { byte: u8, stage: usize },
    EmptyOptionalClass { stage: usize },
    WorkLimit { needed: usize, limit: usize },
    PersistentLimit { needed: usize, limit: usize },
    PeakLimit { needed: usize, limit: usize },
    AllocationLimit { needed: usize, limit: usize },
    ReserveLimit { needed: usize, limit: usize },
    SourceCopyLimit { needed: usize, limit: usize },
    ScratchLimit { needed: usize, limit: usize },
    AllocationFailed { additional: usize },
    AccountingInvariant { actual: usize, upper: usize },
    Overflow(&'static str),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "required internal-anchor build refusal: {self:?}")
    }
}

impl std::error::Error for BuildError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CountResource {
    InputBytes,
    CandidateVisits,
    ContinuationSteps,
    SourceAccesses,
    RandomAccessBytes,
    SequentialBytes,
    Work,
    Count,
    QueueEntries,
    FrontierEntries,
    Allocations,
    ScratchBytes,
    PeakBytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CountError {
    Resource {
        resource: CountResource,
        needed: usize,
        limit: usize,
    },
    CountResource {
        needed: u64,
        limit: u64,
    },
    AccountingInvariant {
        counter: &'static str,
        actual: usize,
        upper: usize,
    },
    Overflow(&'static str),
}

impl fmt::Display for CountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "required internal-anchor count refusal: {self:?}")
    }
}

impl std::error::Error for CountError {}

/// Terminal count refusal together with every execution effect committed
/// before that refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CountAttemptError {
    pub source: CountError,
    pub actual: CountActual,
}

impl fmt::Display for CountAttemptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.source, f)
    }
}

impl std::error::Error for CountAttemptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[derive(Debug)]
pub struct RequiredInternalAnchorPlan {
    prefix: ByteClass,
    continuation: ContinuationSource,
    anchor: [u8; MAX_ANCHOR_BYTES],
    anchor_len: u8,
    build: BuildAccounting,
}

impl RequiredInternalAnchorPlan {
    /// Derive the complete build-work envelope from scalar descriptor dimensions only.
    ///
    /// This performs no anchor-byte, byte-class, or optional-stage traversal.
    pub fn build_work_upper_bound(
        anchor_bytes: usize,
        optional_count: u8,
    ) -> Result<usize, BuildError> {
        build_work_upper_bound(anchor_bytes, usize::from(optional_count))
    }

    /// Build a descriptor-driven candidate stream after proving its bounds.
    pub fn build(
        prefix: ByteClass,
        anchor: &[u8],
        continuation: ContinuationSource,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        let anchor_bytes = anchor.len();
        let optional_count = usize::from(continuation.optional_count);
        let work_upper_bound = build_work_upper_bound(anchor_bytes, optional_count)?;
        if work_upper_bound > limits.max_build_work {
            return Err(BuildError::WorkLimit {
                needed: work_upper_bound,
                limit: limits.max_build_work,
            });
        }
        let persistent_bytes = size_of::<Self>();
        let peak_bytes = persistent_bytes;
        let mut meter = BuildMeter::default();
        meter.admission(1)?;
        meter.admission(1)?;
        let anchor_limit = limits.max_anchor_bytes.min(MAX_ANCHOR_BYTES);
        if anchor_bytes > anchor_limit {
            return Err(BuildError::AnchorLimit {
                needed: anchor_bytes,
                limit: anchor_limit,
            });
        }
        preflight_build_resources(persistent_bytes, peak_bytes, limits, &mut meter)?;

        if class_is_empty(prefix, &mut meter)? {
            return Err(BuildError::EmptyPrefix);
        }
        meter.descriptor(1)?;
        let Some(&first_anchor) = anchor.first() else {
            return Err(BuildError::EmptyAnchor);
        };
        meter.class_membership(1)?;
        if prefix.contains(first_anchor) {
            return Err(BuildError::AnchorStartsInPrefix { byte: first_anchor });
        }
        if class_is_empty(continuation.head, &mut meter)? {
            return Err(BuildError::EmptyHead);
        }
        if class_is_empty(continuation.tail, &mut meter)? {
            return Err(BuildError::EmptyTail);
        }
        if !is_subset(continuation.head, continuation.tail, &mut meter)? {
            return Err(BuildError::HeadNotSubsetOfTail);
        }
        meter.descriptor(1)?;
        if optional_count > MAX_OPTIONAL_STAGES {
            return Err(BuildError::OptionalCount {
                count: continuation.optional_count,
            });
        }
        validate_optional(&continuation, optional_count, &mut meter)?;

        if let Some(border) = longest_border(anchor, &mut meter)? {
            return Err(BuildError::OverlappingAnchor { border });
        }

        meter.anchor_storage_initialization(MAX_ANCHOR_BYTES)?;
        let mut owned_anchor = [0_u8; MAX_ANCHOR_BYTES];
        meter.anchor_copy(anchor_bytes)?;
        owned_anchor[..anchor_bytes].copy_from_slice(anchor);
        let class_words = (3_usize.checked_add(optional_count))
            .and_then(|classes| classes.checked_mul(4))
            .ok_or(BuildError::Overflow("class words"))?;
        let observed_structural_work = meter.total()?;
        if observed_structural_work > work_upper_bound {
            return Err(BuildError::AccountingInvariant {
                actual: observed_structural_work,
                upper: work_upper_bound,
            });
        }
        let anchor_len =
            u8::try_from(anchor_bytes).map_err(|_| BuildError::Overflow("fixed anchor length"))?;
        Ok(Self {
            prefix,
            continuation,
            anchor: owned_anchor,
            anchor_len,
            build: BuildAccounting {
                anchor_bytes,
                class_words,
                optional_stages: optional_count,
                work_upper_bound,
                observed_structural_work,
                admission_checks: meter.admission_checks,
                descriptor_checks: meter.descriptor_checks,
                class_word_checks: meter.class_word_checks,
                class_membership_checks: meter.class_membership_checks,
                optional_slot_checks: meter.optional_slot_checks,
                optional_pair_checks: meter.optional_pair_checks,
                border_candidates: meter.border_candidates,
                border_byte_comparisons: meter.border_byte_comparisons,
                anchor_storage_initialization_bytes: meter.anchor_storage_initialization_bytes,
                anchor_copy_bytes: meter.anchor_copy_bytes,
                allocations: 0,
                reserves: 0,
                source_copies: 1,
                scratch_bytes: 0,
                persistent_bytes,
                peak_bytes,
            },
        })
    }

    #[must_use]
    pub const fn plan_id(&self) -> &'static str {
        PLAN_ID
    }

    #[must_use]
    pub const fn operation_id(&self) -> &'static str {
        COUNT_OPERATION_ID
    }

    #[must_use]
    pub fn anchor(&self) -> &[u8] {
        &self.anchor[..usize::from(self.anchor_len)]
    }

    #[must_use]
    pub const fn prefix(&self) -> ByteClass {
        self.prefix
    }

    #[must_use]
    pub const fn continuation(&self) -> ContinuationSource {
        self.continuation
    }

    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.build
    }

    /// Count leftmost-first non-overlapping matches after complete preflight.
    pub fn count(&self, haystack: &[u8], limits: CountLimits) -> Result<CountResult, CountError> {
        self.count_attempt(haystack, limits)
            .map_err(|error| error.source)
    }

    /// Count while retaining exact terminal accounting when an invariant or
    /// arithmetic refusal occurs after source access.
    #[allow(
        clippy::result_large_err,
        reason = "the audited terminal error deliberately retains the complete exact execution ledger"
    )]
    pub fn count_attempt(
        &self,
        haystack: &[u8],
        limits: CountLimits,
    ) -> Result<CountResult, CountAttemptError> {
        let upper =
            self.count_upper_bounds(haystack.len())
                .map_err(|source| CountAttemptError {
                    source,
                    actual: CountActual::default(),
                })?;
        enforce(&upper, limits).map_err(|source| CountAttemptError {
            source,
            actual: CountActual::default(),
        })?;
        let mut actual = CountActual::default();
        let execution = (|| {
            actual.control_work = add(actual.control_work, 1, "operation initialization")?;
            let mut search = 0_usize;
            let mut match_floor = 0_usize;
            while search <= haystack.len() {
                actual.control_work = add(actual.control_work, 1, "finder dispatch")?;
                actual.finder_calls = add(actual.finder_calls, 1, "finder calls")?;
                let Some(candidate) = self.find_anchor(haystack, search, &mut actual)? else {
                    actual.control_work = add(actual.control_work, 1, "terminal finder miss")?;
                    break;
                };
                actual.control_work = add(actual.control_work, 1, "candidate dispatch")?;
                actual.candidate_visits = add(actual.candidate_visits, 1, "candidate visits")?;
                let after_anchor = add(candidate, self.anchor().len(), "after anchor")?;
                let prefix_start =
                    self.prefix_start(haystack, candidate, match_floor, &mut actual)?;
                actual.control_work = add(actual.control_work, 1, "prefix result")?;
                let Some(start) = prefix_start else {
                    search = after_anchor;
                    continue;
                };
                let continuation = self.verify_continuation(haystack, after_anchor, &mut actual)?;
                actual.control_work = add(actual.control_work, 1, "continuation result")?;
                let Some(end) = continuation else {
                    search = after_anchor;
                    continue;
                };
                actual.control_work = add(actual.control_work, 1, "match reduction")?;
                debug_assert!(start < end);
                actual.matches = actual
                    .matches
                    .checked_add(1)
                    .ok_or(CountError::Overflow("matches"))?;
                search = end;
                match_floor = end;
            }
            actual.control_work = add(actual.control_work, 1, "operation finalization")?;
            Ok(())
        })();
        if let Err(source) = execution {
            if let Err(source) = finish_actual(&mut actual, self.build.persistent_bytes) {
                return Err(CountAttemptError { source, actual });
            }
            return Err(CountAttemptError { source, actual });
        }
        finish_actual(&mut actual, self.build.persistent_bytes)
            .map_err(|source| CountAttemptError { source, actual })?;
        check_actual(&actual, &upper).map_err(|source| CountAttemptError { source, actual })?;
        Ok(CountResult {
            count: actual.matches,
            accounting: CountAccounting {
                build: self.build,
                upper_bounds: upper,
                actual,
            },
        })
    }

    /// Derive every execution resource bound without reading the input.
    pub fn count_upper_bounds(&self, input_bytes: usize) -> Result<CountUpperBounds, CountError> {
        let anchor_bytes = self.anchor().len();
        let candidate_visits = input_bytes
            .checked_div(anchor_bytes)
            .ok_or(CountError::Overflow("candidate bound"))?;
        let finder_calls = add(candidate_visits, 1, "finder calls bound")?;
        let anchor_starts = match input_bytes.checked_sub(anchor_bytes) {
            Some(last) => add(last, 1, "anchor scan starts")?,
            None => 0,
        };
        let finder_source_accesses = mul(anchor_starts, anchor_bytes, "anchor scan source bound")?;
        let prefix_steps = input_bytes;
        let per_candidate = add(
            2,
            usize::from(self.continuation.optional_count),
            "per-candidate continuation overhead",
        )?;
        let continuation_steps = add(
            input_bytes,
            mul(candidate_visits, per_candidate, "continuation bound")?,
            "continuation bound",
        )?;
        let source_accesses = add(
            add(finder_source_accesses, prefix_steps, "source bound")?,
            continuation_steps,
            "source bound",
        )?;
        let random_access_bytes = add(
            finder_source_accesses,
            prefix_steps,
            "random-access byte bound",
        )?;
        let sequential_bytes = continuation_steps;
        let control_work = add(
            anchor_starts,
            add(
                mul(candidate_visits, 5, "candidate control work")?,
                4,
                "fixed control work",
            )?,
            "control work bound",
        )?;
        let work = add(source_accesses, control_work, "work bound")?;
        let count =
            u64::try_from(candidate_visits).map_err(|_| CountError::Overflow("count bound"))?;
        Ok(CountUpperBounds {
            input_bytes,
            candidate_visits,
            finder_calls,
            anchor_window_attempts: anchor_starts,
            finder_source_accesses,
            prefix_steps,
            continuation_steps,
            source_accesses,
            random_access_bytes,
            sequential_bytes,
            control_work,
            work,
            count,
            queue_entries: 0,
            frontier_entries: 0,
            allocations: 0,
            scratch_bytes: 0,
            persistent_bytes: self.build.persistent_bytes,
            peak_bytes: self.build.persistent_bytes,
        })
    }

    fn find_anchor(
        &self,
        haystack: &[u8],
        search: usize,
        actual: &mut CountActual,
    ) -> Result<Option<usize>, CountError> {
        let anchor = self.anchor();
        let Some(last_start) = haystack.len().checked_sub(anchor.len()) else {
            return Ok(None);
        };
        let mut candidate = search;
        while candidate <= last_start {
            actual.anchor_window_attempts =
                add(actual.anchor_window_attempts, 1, "anchor window attempts")?;
            actual.control_work = add(actual.control_work, 1, "anchor window dispatch")?;
            let mut matched = true;
            for (offset, &expected) in anchor.iter().enumerate() {
                let position = add(candidate, offset, "anchor scan position")?;
                actual.finder_source_accesses = add(
                    actual.finder_source_accesses,
                    1,
                    "anchor scan source accesses",
                )?;
                if haystack[position] != expected {
                    matched = false;
                    break;
                }
            }
            if matched {
                return Ok(Some(candidate));
            }
            candidate = add(candidate, 1, "anchor scan candidate")?;
        }
        Ok(None)
    }

    fn prefix_start(
        &self,
        haystack: &[u8],
        candidate: usize,
        match_floor: usize,
        actual: &mut CountActual,
    ) -> Result<Option<usize>, CountError> {
        if candidate == match_floor {
            return Ok(None);
        }
        let mut start = candidate;
        while start > match_floor {
            let previous = start
                .checked_sub(1)
                .ok_or(CountError::Overflow("prefix predecessor"))?;
            actual.prefix_steps = add(actual.prefix_steps, 1, "prefix steps")?;
            if !self.prefix.contains(haystack[previous]) {
                break;
            }
            start = previous;
        }
        Ok((start < candidate).then_some(start))
    }

    fn verify_continuation(
        &self,
        haystack: &[u8],
        start: usize,
        actual: &mut CountActual,
    ) -> Result<Option<usize>, CountError> {
        let Some(&first) = haystack.get(start) else {
            return Ok(None);
        };
        actual.continuation_steps = add(actual.continuation_steps, 1, "continuation steps")?;
        if !self.continuation.head.contains(first) {
            return Ok(None);
        }
        let mut cursor = start;
        let mut tail_bytes = 0_usize;
        while let Some(&byte) = haystack.get(cursor) {
            actual.continuation_steps = add(actual.continuation_steps, 1, "continuation steps")?;
            if !self.continuation.tail.contains(byte) {
                break;
            }
            tail_bytes = add(tail_bytes, 1, "tail bytes")?;
            cursor = add(cursor, 1, "tail cursor")?;
        }
        if tail_bytes < 2 {
            return Ok(None);
        }

        for stage_index in 0..usize::from(self.continuation.optional_count) {
            let stage = self.continuation.optional[stage_index]
                .ok_or(CountError::Overflow("sealed optional stage"))?;
            let Some(&byte) = haystack.get(cursor) else {
                break;
            };
            actual.continuation_steps = add(actual.continuation_steps, 1, "continuation steps")?;
            if byte != stage.introducer {
                continue;
            }
            cursor = add(cursor, 1, "optional introducer")?;
            while let Some(&byte) = haystack.get(cursor) {
                actual.continuation_steps =
                    add(actual.continuation_steps, 1, "continuation steps")?;
                if !stage.class.contains(byte) {
                    break;
                }
                cursor = add(cursor, 1, "optional cursor")?;
            }
        }
        Ok(Some(cursor))
    }
}

#[derive(Default)]
struct BuildMeter {
    admission_checks: usize,
    descriptor_checks: usize,
    class_word_checks: usize,
    class_membership_checks: usize,
    optional_slot_checks: usize,
    optional_pair_checks: usize,
    border_candidates: usize,
    border_byte_comparisons: usize,
    anchor_storage_initialization_bytes: usize,
    anchor_copy_bytes: usize,
}

impl BuildMeter {
    fn admission(&mut self, amount: usize) -> Result<(), BuildError> {
        checked_meter_add(&mut self.admission_checks, amount, "admission checks")
    }

    fn descriptor(&mut self, amount: usize) -> Result<(), BuildError> {
        checked_meter_add(&mut self.descriptor_checks, amount, "descriptor checks")
    }

    fn class_words(&mut self, amount: usize) -> Result<(), BuildError> {
        checked_meter_add(&mut self.class_word_checks, amount, "class word checks")
    }

    fn class_membership(&mut self, amount: usize) -> Result<(), BuildError> {
        checked_meter_add(
            &mut self.class_membership_checks,
            amount,
            "class membership checks",
        )
    }

    fn optional_slots(&mut self, amount: usize) -> Result<(), BuildError> {
        checked_meter_add(
            &mut self.optional_slot_checks,
            amount,
            "optional slot checks",
        )
    }

    fn optional_pairs(&mut self, amount: usize) -> Result<(), BuildError> {
        checked_meter_add(
            &mut self.optional_pair_checks,
            amount,
            "optional pair checks",
        )
    }

    fn border_candidate(&mut self) -> Result<(), BuildError> {
        checked_meter_add(&mut self.border_candidates, 1, "border candidates")
    }

    fn border_byte(&mut self) -> Result<(), BuildError> {
        checked_meter_add(
            &mut self.border_byte_comparisons,
            1,
            "border byte comparisons",
        )
    }

    fn anchor_copy(&mut self, amount: usize) -> Result<(), BuildError> {
        checked_meter_add(&mut self.anchor_copy_bytes, amount, "anchor copy bytes")
    }

    fn anchor_storage_initialization(&mut self, amount: usize) -> Result<(), BuildError> {
        checked_meter_add(
            &mut self.anchor_storage_initialization_bytes,
            amount,
            "anchor storage initialization bytes",
        )
    }

    fn total(&self) -> Result<usize, BuildError> {
        [
            self.admission_checks,
            self.descriptor_checks,
            self.class_word_checks,
            self.class_membership_checks,
            self.optional_slot_checks,
            self.optional_pair_checks,
            self.border_candidates,
            self.border_byte_comparisons,
            self.anchor_storage_initialization_bytes,
            self.anchor_copy_bytes,
        ]
        .into_iter()
        .try_fold(0_usize, |total, amount| {
            total
                .checked_add(amount)
                .ok_or(BuildError::Overflow("observed build work"))
        })
    }
}

fn checked_meter_add(
    value: &mut usize,
    amount: usize,
    computation: &'static str,
) -> Result<(), BuildError> {
    *value = value
        .checked_add(amount)
        .ok_or(BuildError::Overflow(computation))?;
    Ok(())
}

fn class_is_empty(class: ByteClass, meter: &mut BuildMeter) -> Result<bool, BuildError> {
    for word in class.words() {
        meter.class_words(1)?;
        if word != 0 {
            return Ok(false);
        }
    }
    Ok(true)
}

fn validate_optional(
    source: &ContinuationSource,
    count: usize,
    meter: &mut BuildMeter,
) -> Result<(), BuildError> {
    let mut preceding = source.tail;
    for index in 0..MAX_OPTIONAL_STAGES {
        meter.optional_slots(1)?;
        let active = index < count;
        meter.optional_slots(1)?;
        let stage = source.optional[index];
        if active {
            let stage = stage.ok_or(BuildError::MissingOptional { index })?;
            if class_is_empty(stage.class, meter)? {
                return Err(BuildError::EmptyOptionalClass { stage: index });
            }
            meter.class_membership(1)?;
            if preceding.contains(stage.introducer) {
                return Err(BuildError::IntroducerInPrecedingClass {
                    byte: stage.introducer,
                    stage: index,
                });
            }
            for earlier_index in 0..index {
                meter.optional_slots(1)?;
                let earlier =
                    source.optional[earlier_index].ok_or(BuildError::MissingOptional {
                        index: earlier_index,
                    })?;
                meter.optional_pairs(1)?;
                if earlier.introducer == stage.introducer {
                    return Err(BuildError::DuplicateIntroducer {
                        byte: stage.introducer,
                    });
                }
                meter.class_membership(1)?;
                if earlier.class.contains(stage.introducer) {
                    return Err(BuildError::IntroducerInPrecedingClass {
                        byte: stage.introducer,
                        stage: index,
                    });
                }
            }
            preceding = stage.class;
        } else if stage.is_some() {
            return Err(BuildError::UnexpectedOptional { index });
        }
    }
    Ok(())
}

fn is_subset(
    left: ByteClass,
    right: ByteClass,
    meter: &mut BuildMeter,
) -> Result<bool, BuildError> {
    for (left, right) in left.words().into_iter().zip(right.words()) {
        meter.class_words(1)?;
        if left & !right != 0 {
            return Ok(false);
        }
    }
    Ok(true)
}

fn build_work_upper_bound(
    anchor_bytes: usize,
    raw_optional_count: usize,
) -> Result<usize, BuildError> {
    let optional_count = raw_optional_count.min(MAX_OPTIONAL_STAGES);
    let admission_checks = 8_usize;
    let descriptor_checks = 2_usize;
    let class_word_checks = optional_count
        .checked_mul(4)
        .and_then(|value| value.checked_add(16))
        .ok_or(BuildError::Overflow("class word upper bound"))?;
    let preceding_optional_count = optional_count.saturating_sub(1);
    let optional_pairs = optional_count
        .checked_mul(preceding_optional_count)
        .and_then(|value| value.checked_div(2))
        .ok_or(BuildError::Overflow("optional pair upper bound"))?;
    let class_membership_checks = 1_usize
        .checked_add(optional_count)
        .and_then(|value| value.checked_add(optional_pairs))
        .ok_or(BuildError::Overflow("class membership upper bound"))?;
    let optional_slot_checks = MAX_OPTIONAL_STAGES
        .checked_mul(2)
        .and_then(|value| value.checked_add(optional_pairs))
        .ok_or(BuildError::Overflow("optional slot upper bound"))?;
    let optional_pair_checks = optional_pairs;
    let border_candidates = anchor_bytes.saturating_sub(1);
    let preceding_anchor_bytes = anchor_bytes.saturating_sub(1);
    let border_byte_comparisons = anchor_bytes
        .checked_mul(preceding_anchor_bytes)
        .and_then(|value| value.checked_div(2))
        .ok_or(BuildError::Overflow("border comparison upper bound"))?;
    [
        admission_checks,
        descriptor_checks,
        class_word_checks,
        class_membership_checks,
        optional_slot_checks,
        optional_pair_checks,
        border_candidates,
        border_byte_comparisons,
        MAX_ANCHOR_BYTES,
        anchor_bytes,
    ]
    .into_iter()
    .try_fold(0_usize, |total, amount| {
        total
            .checked_add(amount)
            .ok_or(BuildError::Overflow("build work upper bound"))
    })
}

fn preflight_build_resources(
    persistent_bytes: usize,
    peak_bytes: usize,
    limits: BuildLimits,
    meter: &mut BuildMeter,
) -> Result<(), BuildError> {
    meter.admission(1)?;
    if persistent_bytes > limits.max_persistent_bytes {
        return Err(BuildError::PersistentLimit {
            needed: persistent_bytes,
            limit: limits.max_persistent_bytes,
        });
    }
    meter.admission(1)?;
    if peak_bytes > limits.max_peak_bytes {
        return Err(BuildError::PeakLimit {
            needed: peak_bytes,
            limit: limits.max_peak_bytes,
        });
    }
    for (needed, limit, error) in [
        (
            0,
            limits.max_allocations,
            BuildError::AllocationLimit {
                needed: 0,
                limit: limits.max_allocations,
            },
        ),
        (
            0,
            limits.max_reserves,
            BuildError::ReserveLimit {
                needed: 0,
                limit: limits.max_reserves,
            },
        ),
        (
            1,
            limits.max_source_copies,
            BuildError::SourceCopyLimit {
                needed: 1,
                limit: limits.max_source_copies,
            },
        ),
        (
            0,
            limits.max_scratch_bytes,
            BuildError::ScratchLimit {
                needed: 0,
                limit: limits.max_scratch_bytes,
            },
        ),
    ] {
        meter.admission(1)?;
        if needed > limit {
            return Err(error);
        }
    }
    Ok(())
}

fn longest_border(anchor: &[u8], meter: &mut BuildMeter) -> Result<Option<usize>, BuildError> {
    for border in (1..anchor.len()).rev() {
        meter.border_candidate()?;
        let suffix_start = anchor
            .len()
            .checked_sub(border)
            .ok_or(BuildError::Overflow("border suffix"))?;
        let mut matches = true;
        for offset in 0..border {
            meter.border_byte()?;
            let suffix_offset = suffix_start
                .checked_add(offset)
                .ok_or(BuildError::Overflow("border suffix offset"))?;
            if anchor[offset] != anchor[suffix_offset] {
                matches = false;
                break;
            }
        }
        if matches {
            return Ok(Some(border));
        }
    }
    Ok(None)
}

fn enforce(upper: &CountUpperBounds, limits: CountLimits) -> Result<(), CountError> {
    for (resource, needed, limit) in [
        (
            CountResource::InputBytes,
            upper.input_bytes,
            limits.max_input_bytes,
        ),
        (
            CountResource::CandidateVisits,
            upper.candidate_visits,
            limits.max_candidate_visits,
        ),
        (
            CountResource::ContinuationSteps,
            upper.continuation_steps,
            limits.max_continuation_steps,
        ),
        (
            CountResource::SourceAccesses,
            upper.source_accesses,
            limits.max_source_accesses,
        ),
        (
            CountResource::RandomAccessBytes,
            upper.random_access_bytes,
            limits.max_random_access_bytes,
        ),
        (
            CountResource::SequentialBytes,
            upper.sequential_bytes,
            limits.max_sequential_bytes,
        ),
        (CountResource::Work, upper.work, limits.max_work),
        (
            CountResource::QueueEntries,
            upper.queue_entries,
            limits.max_queue_entries,
        ),
        (
            CountResource::FrontierEntries,
            upper.frontier_entries,
            limits.max_frontier_entries,
        ),
        (
            CountResource::Allocations,
            upper.allocations,
            limits.max_allocations,
        ),
        (
            CountResource::ScratchBytes,
            upper.scratch_bytes,
            limits.max_scratch_bytes,
        ),
        (
            CountResource::PeakBytes,
            upper.peak_bytes,
            limits.max_peak_bytes,
        ),
    ] {
        if needed > limit {
            return Err(CountError::Resource {
                resource,
                needed,
                limit,
            });
        }
    }
    if upper.count > limits.max_count {
        return Err(CountError::CountResource {
            needed: upper.count,
            limit: limits.max_count,
        });
    }
    Ok(())
}

fn finish_actual(actual: &mut CountActual, persistent_bytes: usize) -> Result<(), CountError> {
    actual.random_access_bytes = add(
        actual.finder_source_accesses,
        actual.prefix_steps,
        "actual random-access bytes",
    )?;
    actual.sequential_bytes = actual.continuation_steps;
    actual.source_accesses = add(
        actual.random_access_bytes,
        actual.sequential_bytes,
        "actual source accesses",
    )?;
    actual.work = add(actual.source_accesses, actual.control_work, "actual work")?;
    actual.queue_entries = 0;
    actual.frontier_entries = 0;
    actual.allocations = 0;
    actual.scratch_bytes = 0;
    actual.peak_bytes = persistent_bytes;
    Ok(())
}

fn check_actual(actual: &CountActual, upper: &CountUpperBounds) -> Result<(), CountError> {
    for (counter, actual, upper) in [
        (
            "candidate visits",
            actual.candidate_visits,
            upper.candidate_visits,
        ),
        (
            "finder source accesses",
            actual.finder_source_accesses,
            upper.finder_source_accesses,
        ),
        ("finder calls", actual.finder_calls, upper.finder_calls),
        (
            "anchor window attempts",
            actual.anchor_window_attempts,
            upper.anchor_window_attempts,
        ),
        ("prefix steps", actual.prefix_steps, upper.prefix_steps),
        (
            "continuation steps",
            actual.continuation_steps,
            upper.continuation_steps,
        ),
        (
            "source accesses",
            actual.source_accesses,
            upper.source_accesses,
        ),
        (
            "random access bytes",
            actual.random_access_bytes,
            upper.random_access_bytes,
        ),
        (
            "sequential bytes",
            actual.sequential_bytes,
            upper.sequential_bytes,
        ),
        ("control work", actual.control_work, upper.control_work),
        ("work", actual.work, upper.work),
        ("queue entries", actual.queue_entries, upper.queue_entries),
        (
            "frontier entries",
            actual.frontier_entries,
            upper.frontier_entries,
        ),
        ("allocations", actual.allocations, upper.allocations),
        ("scratch bytes", actual.scratch_bytes, upper.scratch_bytes),
        ("peak bytes", actual.peak_bytes, upper.peak_bytes),
    ] {
        if actual > upper {
            return Err(CountError::AccountingInvariant {
                counter,
                actual,
                upper,
            });
        }
    }
    Ok(())
}

fn add(left: usize, right: usize, computation: &'static str) -> Result<usize, CountError> {
    left.checked_add(right)
        .ok_or(CountError::Overflow(computation))
}

fn mul(left: usize, right: usize, computation: &'static str) -> Result<usize, CountError> {
    left.checked_mul(right)
        .ok_or(CountError::Overflow(computation))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ascii_word() -> ByteClass {
        let mut class = ByteClass::default();
        class.insert_inclusive(b'0', b'9');
        class.insert_inclusive(b'A', b'Z');
        class.insert_inclusive(b'a', b'z');
        class.insert_inclusive(b'_', b'_');
        class
    }

    fn except(bytes: &[u8]) -> ByteClass {
        let mut retained = Vec::new();
        for byte in 0..=u8::MAX {
            if !bytes.contains(&byte) {
                retained.push(byte);
            }
        }
        ByteClass::from_bytes(&retained)
    }

    fn uri_source() -> ContinuationSource {
        let host = except(b"/\t\n\x0B\x0C\r ?#");
        let path = except(b"\t\n\x0B\x0C\r ?#");
        let query = except(b"\t\n\x0B\x0C\r #");
        let fragment = except(b"\t\n\x0B\x0C\r ");
        let mut continuation = ContinuationSource::new(host, path);
        continuation.optional[0] = Some(OptionalStageSource {
            introducer: b'?',
            class: query,
        });
        continuation.optional[1] = Some(OptionalStageSource {
            introducer: b'#',
            class: fragment,
        });
        continuation.optional_count = 2;
        continuation
    }

    fn uri_plan() -> RequiredInternalAnchorPlan {
        RequiredInternalAnchorPlan::build(
            ascii_word(),
            b"://",
            uri_source(),
            BuildLimits::default(),
        )
        .expect("generic URI-shaped plan")
    }

    #[test]
    fn uri_shape_counts_leftmost_greedy_nonoverlap_and_malformed_bytes() {
        let plan = uri_plan();
        for (haystack, expected) in [
            (b"http://a/b".as_slice(), 1),
            (b"x http://a/b?q=x#f y".as_slice(), 1),
            (b"bad://x good://a/b".as_slice(), 1),
            (b"no:///x yes://a/b".as_slice(), 1),
            (b"x://a/b://c/d".as_slice(), 1),
            (b"x://a/b y://c/d".as_slice(), 2),
            (b"x://a/\xFF?q=\xFE#\xFD".as_slice(), 1),
            (b"x://a/one?two?three#four#five".as_slice(), 1),
            (b"://a/b x://a".as_slice(), 0),
            (b"x://a/ y://b/c".as_slice(), 2),
        ] {
            let result = plan.count(haystack, CountLimits::default()).unwrap();
            assert_eq!(result.count, expected, "haystack={haystack:?}");
            assert!(
                result.accounting.actual.candidate_visits
                    <= result.accounting.upper_bounds.candidate_visits
            );
            assert!(
                result.accounting.actual.continuation_steps
                    <= result.accounting.upper_bounds.continuation_steps
            );
            let actual = result.accounting.actual;
            assert_eq!(
                actual.random_access_bytes,
                actual.finder_source_accesses + actual.prefix_steps
            );
            assert_eq!(actual.sequential_bytes, actual.continuation_steps);
            assert_eq!(
                actual.source_accesses,
                actual.random_access_bytes + actual.sequential_bytes
            );
            assert!(actual.source_accesses <= result.accounting.upper_bounds.source_accesses);
            assert!(actual.work <= result.accounting.upper_bounds.work);
            assert_eq!(actual.queue_entries, 0);
            assert_eq!(actual.frontier_entries, 0);
            assert_eq!(actual.allocations, 0);
            assert_eq!(actual.scratch_bytes, 0);
            assert_eq!(result.accounting.upper_bounds.allocations, 0);
            assert_eq!(result.accounting.upper_bounds.scratch_bytes, 0);
        }
    }

    #[test]
    fn terminal_attempt_retains_source_effects_and_legacy_error() {
        let mut plan = uri_plan();
        // Simulate a post-construction descriptor-integrity failure that is
        // reachable only after the finder, prefix and two valid optional
        // stages have consumed source.
        plan.continuation.optional_count = 3;
        let haystack = b"x://a/b?q=x#f";
        let legacy = plan
            .count(haystack, CountLimits::default())
            .expect_err("missing sealed third stage must refuse");
        let failure = plan
            .count_attempt(haystack, CountLimits::default())
            .expect_err("audited attempt must preserve the same refusal");
        assert_eq!(failure.source, legacy);
        assert!(failure.actual.finder_source_accesses > 0);
        assert!(failure.actual.prefix_steps > 0);
        assert!(failure.actual.continuation_steps > 0);
        assert!(failure.actual.source_accesses > 0);
        assert!(failure.actual.work > 0);
        assert_eq!(failure.actual.allocations, 0);
    }

    fn exact_count_limits(upper: CountUpperBounds) -> CountLimits {
        CountLimits {
            max_input_bytes: upper.input_bytes,
            max_candidate_visits: upper.candidate_visits,
            max_continuation_steps: upper.continuation_steps,
            max_source_accesses: upper.source_accesses,
            max_random_access_bytes: upper.random_access_bytes,
            max_sequential_bytes: upper.sequential_bytes,
            max_work: upper.work,
            max_count: upper.count,
            max_queue_entries: upper.queue_entries,
            max_frontier_entries: upper.frontier_entries,
            max_allocations: upper.allocations,
            max_scratch_bytes: upper.scratch_bytes,
            max_peak_bytes: upper.peak_bytes,
        }
    }

    fn assert_resource_refusal(
        plan: &RequiredInternalAnchorPlan,
        haystack: &[u8],
        limits: CountLimits,
        resource: CountResource,
    ) {
        assert!(matches!(
            plan.count(haystack, limits),
            Err(CountError::Resource { resource: got, .. }) if got == resource
        ));
    }

    #[test]
    fn source_dimensions_refuse_before_search_at_exact_one_below() {
        let plan = uri_plan();
        let haystack = b"x://a/b y://c/d";
        let baseline = plan.count(haystack, CountLimits::default()).unwrap();
        let upper = baseline.accounting.upper_bounds;
        let exact = exact_count_limits(upper);
        assert_eq!(plan.count(haystack, exact).unwrap(), baseline);
        for (resource, limits) in [
            (
                CountResource::InputBytes,
                CountLimits {
                    max_input_bytes: upper.input_bytes - 1,
                    ..exact
                },
            ),
            (
                CountResource::CandidateVisits,
                CountLimits {
                    max_candidate_visits: upper.candidate_visits - 1,
                    ..exact
                },
            ),
            (
                CountResource::ContinuationSteps,
                CountLimits {
                    max_continuation_steps: upper.continuation_steps - 1,
                    ..exact
                },
            ),
            (
                CountResource::SourceAccesses,
                CountLimits {
                    max_source_accesses: upper.source_accesses - 1,
                    ..exact
                },
            ),
            (
                CountResource::RandomAccessBytes,
                CountLimits {
                    max_random_access_bytes: upper.random_access_bytes - 1,
                    ..exact
                },
            ),
        ] {
            assert_resource_refusal(&plan, haystack, limits, resource);
        }
    }

    #[test]
    fn state_dimensions_refuse_before_search_at_exact_one_below() {
        let plan = uri_plan();
        let haystack = b"x://a/b y://c/d";
        let upper = plan.count_upper_bounds(haystack.len()).unwrap();
        let exact = exact_count_limits(upper);
        for (resource, limits) in [
            (
                CountResource::SequentialBytes,
                CountLimits {
                    max_sequential_bytes: upper.sequential_bytes - 1,
                    ..exact
                },
            ),
            (
                CountResource::Work,
                CountLimits {
                    max_work: upper.work - 1,
                    ..exact
                },
            ),
            (
                CountResource::PeakBytes,
                CountLimits {
                    max_peak_bytes: upper.peak_bytes - 1,
                    ..exact
                },
            ),
        ] {
            assert_resource_refusal(&plan, haystack, limits, resource);
        }
        assert!(matches!(
            plan.count(
                haystack,
                CountLimits {
                    max_count: upper.count - 1,
                    ..exact
                }
            ),
            Err(CountError::CountResource { .. })
        ));
        assert_eq!(upper.allocations, 0);
        assert_eq!(upper.scratch_bytes, 0);
        assert_eq!(upper.queue_entries, 0);
        assert_eq!(upper.frontier_entries, 0);
    }

    #[test]
    fn dense_all_candidate_input_refuses_before_verification() {
        let plan = uri_plan();
        let dense = b"://://://";
        let dense_upper = plan.count_upper_bounds(dense.len()).unwrap();
        let dense_result = plan.count(dense, CountLimits::default()).unwrap();
        assert_eq!(dense_upper.candidate_visits, 3);
        assert_eq!(dense_result.accounting.actual.candidate_visits, 3);
        assert_eq!(dense_result.count, 0);
        assert!(matches!(
            plan.count(
                dense,
                CountLimits {
                    max_candidate_visits: 2,
                    ..CountLimits::default()
                }
            ),
            Err(CountError::Resource {
                resource: CountResource::CandidateVisits,
                needed: 3,
                limit: 2,
            })
        ));
    }

    #[test]
    fn candidate_failures_resume_but_successes_raise_the_nonoverlap_floor() {
        let prefix = ByteClass::from_bytes(b"a");
        let head = ByteClass::from_bytes(b"b");
        let tail = ByteClass::from_bytes(b"ab");
        let plan = RequiredInternalAnchorPlan::build(
            prefix,
            b"X",
            ContinuationSource::new(head, tail),
            BuildLimits::default(),
        )
        .unwrap();
        assert_eq!(
            plan.count(b"aXbaaaXba", CountLimits::default())
                .unwrap()
                .count,
            1
        );
        assert_eq!(
            uri_plan()
                .count(b"://://://", CountLimits::default())
                .unwrap()
                .accounting
                .actual
                .candidate_visits,
            3
        );
    }

    #[test]
    fn construction_proves_anchor_and_phase_invariants_before_allocation() {
        let plan = uri_plan();
        let build = plan.build_accounting();
        assert_eq!(plan.anchor(), b"://");
        assert_eq!(build.allocations, 0);
        assert_eq!(build.reserves, 0);
        assert_eq!(build.source_copies, 1);
        assert_eq!(build.scratch_bytes, 0);
        assert!(build.observed_structural_work <= build.work_upper_bound);
        assert!(build.persistent_bytes <= build.peak_bytes);
        let exact = BuildLimits {
            max_anchor_bytes: build.anchor_bytes,
            max_build_work: build.work_upper_bound,
            max_persistent_bytes: build.persistent_bytes,
            max_peak_bytes: build.peak_bytes,
            max_allocations: build.allocations,
            max_reserves: build.reserves,
            max_source_copies: build.source_copies,
            max_scratch_bytes: build.scratch_bytes,
        };
        let source = uri_source();
        assert!(RequiredInternalAnchorPlan::build(ascii_word(), b"://", source, exact).is_ok());
        assert!(matches!(
            RequiredInternalAnchorPlan::build(
                ascii_word(),
                b"://",
                source,
                BuildLimits {
                    max_build_work: build.work_upper_bound - 1,
                    ..exact
                }
            ),
            Err(BuildError::WorkLimit { .. })
        ));
        for (limits, expected) in [
            (
                BuildLimits {
                    max_anchor_bytes: build.anchor_bytes - 1,
                    ..exact
                },
                "anchor",
            ),
            (
                BuildLimits {
                    max_persistent_bytes: build.persistent_bytes - 1,
                    ..exact
                },
                "persistent",
            ),
            (
                BuildLimits {
                    max_peak_bytes: build.peak_bytes - 1,
                    ..exact
                },
                "peak",
            ),
            (
                BuildLimits {
                    max_source_copies: build.source_copies - 1,
                    ..exact
                },
                "source copies",
            ),
        ] {
            let error = RequiredInternalAnchorPlan::build(ascii_word(), b"://", source, limits)
                .expect_err("one-below build resource must refuse");
            assert!(
                matches!(
                    (expected, &error),
                    ("anchor", BuildError::AnchorLimit { .. })
                        | ("persistent", BuildError::PersistentLimit { .. })
                        | ("peak", BuildError::PeakLimit { .. })
                        | ("source copies", BuildError::SourceCopyLimit { .. })
                ),
                "wrong one-below refusal for {expected}: {error:?}"
            );
        }
        assert!(matches!(
            RequiredInternalAnchorPlan::build(
                ByteClass::from_bytes(b":ab"),
                b"://",
                source,
                BuildLimits::default()
            ),
            Err(BuildError::AnchorStartsInPrefix { .. })
        ));
        assert!(matches!(
            RequiredInternalAnchorPlan::build(ascii_word(), b":a:", source, BuildLimits::default()),
            Err(BuildError::OverlappingAnchor { .. })
        ));
    }

    fn assert_semantic_refusal_is_preflighted(
        prefix: ByteClass,
        anchor: &[u8],
        source: &ContinuationSource,
        expected: fn(&BuildError) -> bool,
    ) {
        let upper =
            RequiredInternalAnchorPlan::build_work_upper_bound(anchor.len(), source.optional_count)
                .unwrap();
        let one_below = upper.checked_sub(1).expect("positive build-work bound");
        assert!(upper > 0);
        let exact = BuildLimits {
            max_build_work: upper,
            ..BuildLimits::default()
        };
        let error = RequiredInternalAnchorPlan::build(prefix, anchor, *source, exact)
            .expect_err("invalid descriptor must refuse");
        assert!(expected(&error), "unexpected semantic refusal: {error:?}");
        assert!(matches!(
            RequiredInternalAnchorPlan::build(
                prefix,
                anchor,
                *source,
                BuildLimits {
                    max_build_work: one_below,
                    ..exact
                }
            ),
            Err(BuildError::WorkLimit {
                needed,
                limit
            }) if needed == upper && limit == one_below
        ));
    }

    #[test]
    fn every_semantic_refusal_is_behind_the_build_work_preflight() {
        let valid = uri_source();
        assert_semantic_refusal_is_preflighted(ByteClass::default(), b"://", &valid, |error| {
            matches!(error, BuildError::EmptyPrefix)
        });
        assert_semantic_refusal_is_preflighted(ascii_word(), b"", &valid, |error| {
            matches!(error, BuildError::EmptyAnchor)
        });
        assert_semantic_refusal_is_preflighted(
            ByteClass::from_bytes(b":a"),
            b"://",
            &valid,
            |error| matches!(error, BuildError::AnchorStartsInPrefix { .. }),
        );

        let mut empty_head = valid;
        empty_head.head = ByteClass::default();
        assert_semantic_refusal_is_preflighted(ascii_word(), b"://", &empty_head, |error| {
            matches!(error, BuildError::EmptyHead)
        });
        let mut empty_tail = valid;
        empty_tail.tail = ByteClass::default();
        assert_semantic_refusal_is_preflighted(ascii_word(), b"://", &empty_tail, |error| {
            matches!(error, BuildError::EmptyTail)
        });
        let mut bad_subset = valid;
        bad_subset.head = ByteClass::from_bytes(b"z");
        bad_subset.tail = ByteClass::from_bytes(b"a");
        assert_semantic_refusal_is_preflighted(ascii_word(), b"://", &bad_subset, |error| {
            matches!(error, BuildError::HeadNotSubsetOfTail)
        });

        let mut optional_count = valid;
        optional_count.optional_count = 5;
        assert_semantic_refusal_is_preflighted(ascii_word(), b"://", &optional_count, |error| {
            matches!(error, BuildError::OptionalCount { .. })
        });
        let mut missing =
            ContinuationSource::new(ByteClass::from_bytes(b"a"), ByteClass::from_bytes(b"a"));
        missing.optional_count = 1;
        assert_semantic_refusal_is_preflighted(ascii_word(), b"://", &missing, |error| {
            matches!(error, BuildError::MissingOptional { .. })
        });
        let mut unexpected =
            ContinuationSource::new(ByteClass::from_bytes(b"a"), ByteClass::from_bytes(b"a"));
        unexpected.optional[0] = Some(OptionalStageSource {
            introducer: b'?',
            class: ByteClass::from_bytes(b"b"),
        });
        assert_semantic_refusal_is_preflighted(ascii_word(), b"://", &unexpected, |error| {
            matches!(error, BuildError::UnexpectedOptional { .. })
        });

        let mut duplicate =
            ContinuationSource::new(ByteClass::from_bytes(b"a"), ByteClass::from_bytes(b"a"));
        duplicate.optional[0] = Some(OptionalStageSource {
            introducer: b'?',
            class: ByteClass::from_bytes(b"b"),
        });
        duplicate.optional[1] = Some(OptionalStageSource {
            introducer: b'?',
            class: ByteClass::from_bytes(b"c"),
        });
        duplicate.optional_count = 2;
        assert_semantic_refusal_is_preflighted(ascii_word(), b"://", &duplicate, |error| {
            matches!(error, BuildError::DuplicateIntroducer { .. })
        });
        let mut preceding =
            ContinuationSource::new(ByteClass::from_bytes(b"a"), ByteClass::from_bytes(b"a?"));
        preceding.optional[0] = Some(OptionalStageSource {
            introducer: b'?',
            class: ByteClass::from_bytes(b"b"),
        });
        preceding.optional_count = 1;
        assert_semantic_refusal_is_preflighted(ascii_word(), b"://", &preceding, |error| {
            matches!(error, BuildError::IntroducerInPrecedingClass { .. })
        });
        let mut empty_optional =
            ContinuationSource::new(ByteClass::from_bytes(b"a"), ByteClass::from_bytes(b"a"));
        empty_optional.optional[0] = Some(OptionalStageSource {
            introducer: b'?',
            class: ByteClass::default(),
        });
        empty_optional.optional_count = 1;
        assert_semantic_refusal_is_preflighted(ascii_word(), b"://", &empty_optional, |error| {
            matches!(error, BuildError::EmptyOptionalClass { .. })
        });
        assert_semantic_refusal_is_preflighted(
            ByteClass::from_bytes(b"x"),
            b"aba",
            &valid,
            |error| matches!(error, BuildError::OverlappingAnchor { .. }),
        );
    }

    #[test]
    fn explicit_anchor_scan_is_exact_on_dense_late_mismatches() {
        let source =
            ContinuationSource::new(ByteClass::from_bytes(b"b"), ByteClass::from_bytes(b"b"));
        let plan = RequiredInternalAnchorPlan::build(
            ByteClass::from_bytes(b"z"),
            b"aaaaaaaaaaaaaaab",
            source,
            BuildLimits::default(),
        )
        .unwrap();
        let haystack = [b'a'; 64];
        let upper = plan.count_upper_bounds(haystack.len()).unwrap();
        assert_eq!(upper.anchor_window_attempts, 49);
        assert_eq!(upper.finder_source_accesses, 784);
        assert_eq!(upper.random_access_bytes, 848);
        assert_eq!(upper.sequential_bytes, 72);
        assert_eq!(upper.control_work, 73);
        assert_eq!(upper.work, 993);
        let exact = exact_count_limits(upper);
        let result = plan.count(&haystack, exact).unwrap();
        assert_eq!(result.count, 0);
        assert_eq!(result.accounting.actual.anchor_window_attempts, 49);
        assert_eq!(result.accounting.actual.finder_source_accesses, 784);
        assert_eq!(result.accounting.actual.control_work, 53);
        assert_eq!(result.accounting.actual.work, 837);
        assert!(matches!(
            plan.count(
                &haystack,
                CountLimits {
                    max_random_access_bytes: upper.random_access_bytes - 1,
                    ..exact
                }
            ),
            Err(CountError::Resource {
                resource: CountResource::RandomAccessBytes,
                ..
            })
        ));

        let mut maximum = [b'a'; MAX_ANCHOR_BYTES];
        maximum[MAX_ANCHOR_BYTES - 1] = b'b';
        assert!(
            RequiredInternalAnchorPlan::build(
                ByteClass::from_bytes(b"z"),
                &maximum,
                source,
                BuildLimits::default(),
            )
            .is_ok()
        );
        let mut too_long = [b'a'; MAX_ANCHOR_BYTES + 1];
        too_long[MAX_ANCHOR_BYTES] = b'b';
        assert!(matches!(
            RequiredInternalAnchorPlan::build(
                ByteClass::from_bytes(b"z"),
                &too_long,
                source,
                BuildLimits::default(),
            ),
            Err(BuildError::AnchorLimit { .. })
        ));
    }
}
