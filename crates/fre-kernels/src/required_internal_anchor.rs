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

use memchr::memmem::{Finder, FinderBuilder};

use crate::required_literal::ByteClass;

pub const PLAN_ID: &str = "required-internal-anchor.bounded-continuation.v1";
pub const COUNT_OPERATION_ID: &str = "required-internal-anchor.count.v1";
pub const MAX_OPTIONAL_STAGES: usize = 4;

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
    pub structural_work: usize,
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
            max_queue_entries: 1,
            max_frontier_entries: 1,
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
    pub finder_source_accesses: usize,
    pub prefix_steps: usize,
    pub continuation_steps: usize,
    pub source_accesses: usize,
    pub random_access_bytes: usize,
    pub sequential_bytes: usize,
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
    pub prefix_steps: usize,
    pub continuation_steps: usize,
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

#[derive(Debug)]
pub struct RequiredInternalAnchorPlan {
    prefix: ByteClass,
    continuation: ContinuationSource,
    finder: Finder<'static>,
    build: BuildAccounting,
}

impl RequiredInternalAnchorPlan {
    /// Build a descriptor-driven candidate stream after proving its bounds.
    pub fn build(
        prefix: ByteClass,
        anchor: &[u8],
        continuation: ContinuationSource,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        if prefix.is_empty() {
            return Err(BuildError::EmptyPrefix);
        }
        let Some(&first_anchor) = anchor.first() else {
            return Err(BuildError::EmptyAnchor);
        };
        if anchor.len() > limits.max_anchor_bytes {
            return Err(BuildError::AnchorLimit {
                needed: anchor.len(),
                limit: limits.max_anchor_bytes,
            });
        }
        if prefix.contains(first_anchor) {
            return Err(BuildError::AnchorStartsInPrefix { byte: first_anchor });
        }
        if continuation.head.is_empty() {
            return Err(BuildError::EmptyHead);
        }
        if continuation.tail.is_empty() {
            return Err(BuildError::EmptyTail);
        }
        if !is_subset(continuation.head, continuation.tail) {
            return Err(BuildError::HeadNotSubsetOfTail);
        }
        let optional_count = usize::from(continuation.optional_count);
        if optional_count > MAX_OPTIONAL_STAGES {
            return Err(BuildError::OptionalCount {
                count: continuation.optional_count,
            });
        }
        validate_optional(&continuation, optional_count)?;

        let structural_work = build_work(anchor.len(), optional_count)?;
        preflight_build_resources(structural_work, 0, 0, limits)?;
        if let Some(border) = longest_border(anchor)? {
            return Err(BuildError::OverlappingAnchor { border });
        }
        let persistent_bytes = size_of::<Self>()
            .checked_add(anchor.len())
            .ok_or(BuildError::Overflow("persistent bytes"))?;
        let peak_bytes = persistent_bytes;
        preflight_build_resources(structural_work, persistent_bytes, peak_bytes, limits)?;

        let mut owned_anchor = Vec::new();
        owned_anchor
            .try_reserve_exact(anchor.len())
            .map_err(|_| BuildError::AllocationFailed {
                additional: anchor.len(),
            })?;
        owned_anchor.extend_from_slice(anchor);
        let class_words = (3_usize.checked_add(optional_count))
            .and_then(|classes| classes.checked_mul(4))
            .ok_or(BuildError::Overflow("class words"))?;
        Ok(Self {
            prefix,
            continuation,
            finder: FinderBuilder::new().build_forward_owned(owned_anchor),
            build: BuildAccounting {
                anchor_bytes: anchor.len(),
                class_words,
                optional_stages: optional_count,
                structural_work,
                allocations: 1,
                reserves: 1,
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
        self.finder.needle()
    }

    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.build
    }

    /// Count leftmost-first non-overlapping matches after complete preflight.
    pub fn count(&self, haystack: &[u8], limits: CountLimits) -> Result<CountResult, CountError> {
        let upper = self.count_upper_bounds(haystack.len())?;
        enforce(&upper, limits)?;
        let mut actual = CountActual::default();
        let mut search = 0_usize;
        let mut match_floor = 0_usize;
        while search <= haystack.len() {
            actual.finder_calls = add(actual.finder_calls, 1, "finder calls")?;
            let Some(relative) = self.finder.find(&haystack[search..]) else {
                break;
            };
            actual.candidate_visits = add(actual.candidate_visits, 1, "candidate visits")?;
            let candidate = add(search, relative, "candidate position")?;
            let after_anchor = add(candidate, self.anchor().len(), "after anchor")?;
            let Some(start) = self.prefix_start(haystack, candidate, match_floor, &mut actual)?
            else {
                search = after_anchor;
                continue;
            };
            let Some(end) = self.verify_continuation(haystack, after_anchor, &mut actual)? else {
                search = after_anchor;
                continue;
            };
            debug_assert!(start < end);
            actual.matches = actual
                .matches
                .checked_add(1)
                .ok_or(CountError::Overflow("matches"))?;
            search = end;
            match_floor = end;
        }
        check_actual(&actual, &upper)?;
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
        let finder_source_accesses = add(
            input_bytes,
            mul(finder_calls, anchor_bytes, "finder source bound")?,
            "finder source bound",
        )?;
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
        let random_access_bytes = prefix_steps;
        let sequential_bytes = add(
            finder_source_accesses,
            continuation_steps,
            "sequential byte bound",
        )?;
        let work = add(
            add(
                source_accesses,
                mul(candidate_visits, 8, "candidate control work")?,
                "work bound",
            )?,
            16,
            "work bound",
        )?;
        let count =
            u64::try_from(candidate_visits).map_err(|_| CountError::Overflow("count bound"))?;
        Ok(CountUpperBounds {
            input_bytes,
            candidate_visits,
            finder_calls,
            finder_source_accesses,
            prefix_steps,
            continuation_steps,
            source_accesses,
            random_access_bytes,
            sequential_bytes,
            work,
            count,
            queue_entries: 1,
            frontier_entries: 1,
            allocations: 0,
            scratch_bytes: 0,
            persistent_bytes: self.build.persistent_bytes,
            peak_bytes: self.build.persistent_bytes,
        })
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

fn validate_optional(source: &ContinuationSource, count: usize) -> Result<(), BuildError> {
    let mut preceding = source.tail;
    for index in 0..MAX_OPTIONAL_STAGES {
        let stage = source.optional[index];
        if index < count {
            let stage = stage.ok_or(BuildError::MissingOptional { index })?;
            if stage.class.is_empty() {
                return Err(BuildError::EmptyOptionalClass { stage: index });
            }
            if preceding.contains(stage.introducer) {
                return Err(BuildError::IntroducerInPrecedingClass {
                    byte: stage.introducer,
                    stage: index,
                });
            }
            for earlier in source.optional[..index].iter().flatten() {
                if earlier.introducer == stage.introducer {
                    return Err(BuildError::DuplicateIntroducer {
                        byte: stage.introducer,
                    });
                }
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

fn is_subset(left: ByteClass, right: ByteClass) -> bool {
    left.words()
        .into_iter()
        .zip(right.words())
        .all(|(left, right)| left & !right == 0)
}

fn build_work(anchor_bytes: usize, optional_count: usize) -> Result<usize, BuildError> {
    let border_work = anchor_bytes
        .checked_mul(anchor_bytes)
        .ok_or(BuildError::Overflow("border work"))?;
    let class_words = (3_usize
        .checked_add(optional_count)
        .ok_or(BuildError::Overflow("class count"))?)
    .checked_mul(4)
    .ok_or(BuildError::Overflow("class words"))?;
    border_work
        .checked_add(class_words)
        .and_then(|work| work.checked_add(optional_count.checked_mul(16)?))
        .and_then(|work| work.checked_add(32))
        .ok_or(BuildError::Overflow("build work"))
}

fn preflight_build_resources(
    structural_work: usize,
    persistent_bytes: usize,
    peak_bytes: usize,
    limits: BuildLimits,
) -> Result<(), BuildError> {
    if structural_work > limits.max_build_work {
        return Err(BuildError::WorkLimit {
            needed: structural_work,
            limit: limits.max_build_work,
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
    for (needed, limit, error) in [
        (
            1,
            limits.max_allocations,
            BuildError::AllocationLimit {
                needed: 1,
                limit: limits.max_allocations,
            },
        ),
        (
            1,
            limits.max_reserves,
            BuildError::ReserveLimit {
                needed: 1,
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
        if needed > limit {
            return Err(error);
        }
    }
    Ok(())
}

fn longest_border(anchor: &[u8]) -> Result<Option<usize>, BuildError> {
    for border in (1..anchor.len()).rev() {
        let suffix_start = anchor
            .len()
            .checked_sub(border)
            .ok_or(BuildError::Overflow("border suffix"))?;
        if anchor[..border] == anchor[suffix_start..] {
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

fn check_actual(actual: &CountActual, upper: &CountUpperBounds) -> Result<(), CountError> {
    for (counter, actual, upper) in [
        (
            "candidate visits",
            actual.candidate_visits,
            upper.candidate_visits,
        ),
        ("finder calls", actual.finder_calls, upper.finder_calls),
        ("prefix steps", actual.prefix_steps, upper.prefix_steps),
        (
            "continuation steps",
            actual.continuation_steps,
            upper.continuation_steps,
        ),
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
            assert_eq!(result.accounting.upper_bounds.allocations, 0);
            assert_eq!(result.accounting.upper_bounds.scratch_bytes, 0);
        }
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
                CountResource::QueueEntries,
                CountLimits {
                    max_queue_entries: 0,
                    ..exact
                },
            ),
            (
                CountResource::FrontierEntries,
                CountLimits {
                    max_frontier_entries: 0,
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
        assert_eq!(build.allocations, 1);
        assert_eq!(build.reserves, 1);
        assert_eq!(build.source_copies, 1);
        assert_eq!(build.scratch_bytes, 0);
        assert!(build.persistent_bytes <= build.peak_bytes);
        let exact = BuildLimits {
            max_anchor_bytes: build.anchor_bytes,
            max_build_work: build.structural_work,
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
                    max_build_work: build.structural_work - 1,
                    ..exact
                }
            ),
            Err(BuildError::WorkLimit { .. })
        ));
        for limits in [
            BuildLimits {
                max_anchor_bytes: build.anchor_bytes - 1,
                ..exact
            },
            BuildLimits {
                max_persistent_bytes: build.persistent_bytes - 1,
                ..exact
            },
            BuildLimits {
                max_peak_bytes: build.peak_bytes - 1,
                ..exact
            },
            BuildLimits {
                max_allocations: build.allocations - 1,
                ..exact
            },
            BuildLimits {
                max_reserves: build.reserves - 1,
                ..exact
            },
            BuildLimits {
                max_source_copies: build.source_copies - 1,
                ..exact
            },
        ] {
            assert!(
                RequiredInternalAnchorPlan::build(ascii_word(), b"://", source, limits).is_err()
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
}
