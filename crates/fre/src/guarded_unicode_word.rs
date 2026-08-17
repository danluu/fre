//! Maximal-run reducers for finite ASCII words with Unicode boundaries.
//!
//! The HIR-side finite proof owns syntax expansion, source order, captures and
//! the exact guarded dictionary. This module classifies maximal ASCII-word
//! runs, rejects almost every unrelated word through exact length and
//! two-byte prefix masks, then verifies surviving source IDs in original
//! order. Every body is a nonempty ASCII word, so a full Unicode word boundary
//! is exactly the absence of an adjacent Unicode word scalar.

#![allow(
    clippy::result_large_err,
    reason = "failures retain complete allocation-free prospective/actual evidence"
)]

use core::{fmt, mem::size_of};

use fre_exact_alloc::{CopyError, ExactVec, try_box_preserve};
use fre_kernels::{
    AsciiByteSet, AsciiByteSetClassifier, AsciiSelection, DispatchPolicy, SimdDispatchContext,
};

use crate::guarded_ascii_word::{Dictionary, Guard};

pub const PLAN_ID: &str = "guarded-unicode-word.maximal-ascii-run-prefix2-set128.v2";
pub const ANCHOR_ALGORITHM_ID: &str =
    "ordered-literal-aggregate.maximal-ascii-run-prefix2.set128.v2";
pub const COUNT_OPERATION_ID: &str = "guarded-unicode-word.maximal-run-count.v2";
pub const SPAN_SUM_OPERATION_ID: &str = "guarded-unicode-word.maximal-run-span-sum.v2";
pub const SPAN_VISIT_OPERATION_ID: &str = "guarded-unicode-word.maximal-run-span-visit.v1";

pub const CERTIFIED_MAX_PATTERNS: usize = 128;
pub const CERTIFIED_MAX_TOTAL_PATTERN_BYTES: usize = 512;
const SIMD_BLOCK_BYTES: usize = 32;
const ASCII_MASK_SLOTS: usize = 128;
const FIRST_BYTE_MASK_OFFSET: usize = 0;
const SECOND_BYTE_MASK_OFFSET: usize = ASCII_MASK_SLOTS;
const LENGTH_MASK_OFFSET: usize = ASCII_MASK_SLOTS * 2;
const CLASSIFIER_BUILD_WORK: u64 = 128;
const FIXED_BUILD_WORK: u64 = 1;
const ASCII_WORD_SET: AsciiByteSet =
    AsciiByteSet::from_words([0x03ff_0000_0000_0000, 0x07ff_fffe_87ff_fffe]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    pub max_patterns: usize,
    pub max_pattern_bytes: usize,
    pub max_build_work: u64,
    pub max_allocations: usize,
    pub max_initialized_bytes: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl BuildLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_patterns: usize::MAX,
            max_pattern_bytes: usize::MAX,
            max_build_work: u64::MAX,
            max_allocations: usize::MAX,
            max_initialized_bytes: usize::MAX,
            max_persistent_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for BuildLimits {
    fn default() -> Self {
        Self {
            max_patterns: CERTIFIED_MAX_PATTERNS,
            max_pattern_bytes: CERTIFIED_MAX_TOTAL_PATTERN_BYTES,
            max_build_work: 16 << 20,
            max_allocations: 2,
            max_initialized_bytes: 1 << 20,
            max_persistent_bytes: 1 << 20,
            max_peak_bytes: 1 << 20,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildProspective {
    pub patterns: usize,
    pub pattern_bytes: usize,
    pub min_pattern_bytes: usize,
    pub max_pattern_bytes: usize,
    pub prefix_bytes: usize,
    pub prefix_selection_work: u64,
    pub max_signature_bucket_patterns: usize,
    pub max_signature_bucket_pattern_bytes: usize,
    pub build_work: u64,
    pub allocations: usize,
    pub initialized_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BuildActual {
    pub work: u64,
    pub allocations: usize,
    pub allocated_bytes: usize,
    pub copied_bytes: usize,
    pub initialized_bytes: usize,
    pub live_persistent_bytes: usize,
    pub peak_bytes: usize,
    pub published: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    pub prospective: BuildProspective,
    pub actual: BuildActual,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildResource {
    Patterns,
    PatternBytes,
    Work,
    Allocations,
    InitializedBytes,
    PersistentBytes,
    PeakBytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildErrorKind {
    UnsupportedShape {
        detail: &'static str,
    },
    ResourceLimit {
        resource: BuildResource,
        needed: u64,
        limit: u64,
    },
    AllocationFailed {
        bytes: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    InternalInvariant {
        detail: &'static str,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildError {
    pub kind: BuildErrorKind,
    pub prospective: Option<BuildProspective>,
    pub actual: BuildActual,
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "guarded Unicode-word maximal-run build failed: {:?}",
            self.kind
        )
    }
}

impl std::error::Error for BuildError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationIdentity {
    pub plan_id: &'static str,
    pub anchor_algorithm_id: &'static str,
    pub operation_id: &'static str,
    pub prefix_bytes: usize,
    pub classifier_selection: AsciiSelection,
    pub certified_max_patterns: usize,
    pub certified_max_total_pattern_bytes: usize,
}

#[derive(Debug)]
struct AnchorOwner {
    classifier: AsciiByteSetClassifier,
    signature_masks: ExactVec<u128>,
}

#[derive(Debug)]
struct AnchorPlan {
    owner: Box<AnchorOwner>,
    build: BuildAccounting,
}

impl AnchorOwner {
    #[inline]
    fn first_byte_patterns(&self, byte: u8) -> u128 {
        self.signature_masks[FIRST_BYTE_MASK_OFFSET + usize::from(byte)]
    }

    #[inline]
    fn second_byte_patterns(&self, byte: u8) -> u128 {
        self.signature_masks[SECOND_BYTE_MASK_OFFSET + usize::from(byte)]
    }

    #[inline]
    fn length_patterns(&self, width: usize) -> u128 {
        self.signature_masks[LENGTH_MASK_OFFSET.saturating_add(width)]
    }
}

#[derive(Debug)]
pub struct Plan {
    dictionary: Dictionary,
    anchor: AnchorPlan,
}

impl Plan {
    pub fn build(dictionary: Dictionary, limits: BuildLimits) -> Result<Self, BuildError> {
        Self::build_with_dispatch(SimdDispatchContext::capture(), dictionary, limits)
    }

    pub fn build_with_dispatch(
        dispatch: SimdDispatchContext,
        dictionary: Dictionary,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        let anchor = AnchorPlan::build(dispatch, &dictionary, limits)?;
        Ok(Self { dictionary, anchor })
    }

    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.anchor.build
    }

    #[must_use]
    pub fn count_identity(&self) -> OperationIdentity {
        self.operation_identity(COUNT_OPERATION_ID)
    }

    #[must_use]
    pub fn span_sum_identity(&self) -> OperationIdentity {
        self.operation_identity(SPAN_SUM_OPERATION_ID)
    }

    #[must_use]
    pub fn span_visit_identity(&self) -> OperationIdentity {
        self.operation_identity(SPAN_VISIT_OPERATION_ID)
    }

    fn operation_identity(&self, operation_id: &'static str) -> OperationIdentity {
        OperationIdentity {
            plan_id: PLAN_ID,
            anchor_algorithm_id: ANCHOR_ALGORITHM_ID,
            operation_id,
            prefix_bytes: self.anchor.build.prospective.prefix_bytes,
            classifier_selection: self.anchor.owner.classifier.selection(),
            certified_max_patterns: CERTIFIED_MAX_PATTERNS,
            certified_max_total_pattern_bytes: CERTIFIED_MAX_TOTAL_PATTERN_BYTES,
        }
    }

    pub fn count(&self, haystack: &[u8], limits: ReduceLimits) -> Result<CountResult, ReduceError> {
        let reduction = self.reduce::<false>(haystack, limits)?;
        Ok(CountResult {
            count: reduction.actual.match_events,
            accounting: ReduceAccounting {
                identity: self.count_identity(),
                upper_bounds: reduction.upper,
                actual: reduction.actual,
            },
        })
    }

    pub fn span_sum(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<SpanSumResult, ReduceError> {
        let reduction = self.reduce::<true>(haystack, limits)?;
        Ok(SpanSumResult {
            span_sum: reduction.actual.span_sum,
            accounting: ReduceAccounting {
                identity: self.span_sum_identity(),
                upper_bounds: reduction.upper,
                actual: reduction.actual,
            },
        })
    }

    pub fn visit_spans<F>(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
        mut visitor: F,
    ) -> Result<SpanVisitResult, ReduceError>
    where
        F: FnMut(Span),
    {
        let reduction = self.reduce_with_visitor::<true, true, F>(
            haystack,
            limits,
            &mut visitor,
        )?;
        Ok(SpanVisitResult {
            matches: reduction.actual.match_events,
            span_sum: reduction.actual.span_sum,
            accounting: ReduceAccounting {
                identity: self.span_visit_identity(),
                upper_bounds: reduction.upper,
                actual: reduction.actual,
            },
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the single scan keeps maximal-run state and its exact accounting in one auditable loop"
    )]
    fn reduce<const SPAN_SUM: bool>(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<Reduction, ReduceError> {
        self.reduce_with_visitor::<SPAN_SUM, false, _>(haystack, limits, &mut |_| {})
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the single scan keeps maximal-run state and its exact accounting in one auditable loop"
    )]
    fn reduce_with_visitor<const SPAN_SUM: bool, const VISIT: bool, F>(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
        visitor: &mut F,
    ) -> Result<Reduction, ReduceError>
    where
        F: FnMut(Span),
    {
        let upper = self.preflight_reduce::<SPAN_SUM>(haystack.len(), limits)?;
        let mut actual = ReduceActual {
            classified_positions: haystack.len(),
            ..ReduceActual::default()
        };
        let mut block_start = 0_usize;
        let mut word_start = None;

        while block_start
            .checked_add(SIMD_BLOCK_BYTES)
            .is_some_and(|end| end <= haystack.len())
        {
            let block_end = block_start
                .checked_add(SIMD_BLOCK_BYTES)
                .ok_or_else(|| reduce_overflow(actual, "Unicode guarded SIMD block end"))?;
            let block: &[u8; SIMD_BLOCK_BYTES] =
                haystack[block_start..block_end].try_into().map_err(|_| {
                    reduce_invariant(actual, "complete Unicode guarded block lost its extent")
                })?;
            let members = self
                .anchor
                .owner
                .classifier
                .classify_32(block)
                .member_mask();
            let mut lane = 0_u32;

            if let Some(start) = word_start {
                let nonmembers = !members;
                if nonmembers == 0 {
                    block_start = block_end;
                    continue;
                }
                let end_lane = nonmembers.trailing_zeros();
                let end =
                    block_start
                        .checked_add(usize::try_from(end_lane).map_err(|_| {
                            reduce_overflow(actual, "Unicode guarded word-end lane")
                        })?)
                        .ok_or_else(|| reduce_overflow(actual, "Unicode guarded word end"))?;
                self.consume_word::<SPAN_SUM, VISIT, F>(
                    haystack,
                    start,
                    end,
                    &mut actual,
                    visitor,
                )?;
                word_start = None;
                lane = end_lane
                    .checked_add(1)
                    .ok_or_else(|| reduce_overflow(actual, "Unicode guarded next lane"))?;
            }

            while lane < u32::BITS {
                let remaining = u32::MAX.checked_shl(lane).unwrap_or(0);
                let member_lanes = members & remaining;
                if member_lanes == 0 {
                    break;
                }
                let start_lane = member_lanes.trailing_zeros();
                let start =
                    block_start
                        .checked_add(usize::try_from(start_lane).map_err(|_| {
                            reduce_overflow(actual, "Unicode guarded word-start lane")
                        })?)
                        .ok_or_else(|| reduce_overflow(actual, "Unicode guarded word start"))?;
                let after_start = start_lane.checked_add(1).ok_or_else(|| {
                    reduce_overflow(actual, "Unicode guarded word-start successor")
                })?;
                let following = u32::MAX.checked_shl(after_start).unwrap_or(0);
                let nonmember_lanes = !members & following;
                if nonmember_lanes == 0 {
                    word_start = Some(start);
                    break;
                }
                let end_lane = nonmember_lanes.trailing_zeros();
                let end =
                    block_start
                        .checked_add(usize::try_from(end_lane).map_err(|_| {
                            reduce_overflow(actual, "Unicode guarded word-end lane")
                        })?)
                        .ok_or_else(|| reduce_overflow(actual, "Unicode guarded word end"))?;
                self.consume_word::<SPAN_SUM, VISIT, F>(
                    haystack,
                    start,
                    end,
                    &mut actual,
                    visitor,
                )?;
                lane = end_lane
                    .checked_add(1)
                    .ok_or_else(|| reduce_overflow(actual, "Unicode guarded next lane"))?;
            }
            block_start = block_end;
        }

        while block_start < haystack.len() {
            if is_ascii_word(haystack[block_start]) {
                word_start.get_or_insert(block_start);
            } else if let Some(start) = word_start.take() {
                self.consume_word::<SPAN_SUM, VISIT, F>(
                    haystack,
                    start,
                    block_start,
                    &mut actual,
                    visitor,
                )?;
            }
            block_start = block_start
                .checked_add(1)
                .ok_or_else(|| reduce_overflow(actual, "Unicode guarded scalar word cursor"))?;
        }
        if let Some(start) = word_start {
            self.consume_word::<SPAN_SUM, VISIT, F>(
                haystack,
                start,
                haystack.len(),
                &mut actual,
                visitor,
            )?;
        }
        actual.iterator_next_calls = actual
            .candidate_events
            .checked_add(1)
            .ok_or_else(|| reduce_overflow(actual, "Unicode guarded iterator calls"))?;
        actual.source_byte_reads = actual
            .classified_positions
            .checked_add(actual.verification_source_reads)
            .and_then(|reads| reads.checked_add(actual.boundary_source_reads))
            .ok_or_else(|| reduce_overflow(actual, "Unicode guarded source reads"))?;
        actual.work = actual_work(actual)?;
        if !actual_fits(actual, upper) {
            return Err(reduce_invariant(
                actual,
                "Unicode guarded actual counters escaped their prospective envelope",
            ));
        }
        Ok(Reduction { upper, actual })
    }

    fn consume_word<const SPAN_SUM: bool, const VISIT: bool, F>(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
        actual: &mut ReduceActual,
        visitor: &mut F,
    ) -> Result<(), ReduceError>
    where
        F: FnMut(Span),
    {
        let prior = *actual;
        increment(
            &mut actual.candidate_events,
            prior,
            "Unicode guarded candidate events",
        )?;
        let width = end
            .checked_sub(start)
            .ok_or_else(|| reduce_overflow(*actual, "Unicode guarded word width"))?;
        let build = self.anchor.build.prospective;
        if width < build.min_pattern_bytes || width > build.max_pattern_bytes {
            return Ok(());
        }
        let mut pattern_bits = self.anchor.owner.length_patterns(width)
            & self.anchor.owner.first_byte_patterns(haystack[start]);
        if build.prefix_bytes == 2 {
            let second = start
                .checked_add(1)
                .ok_or_else(|| reduce_overflow(*actual, "Unicode guarded second prefix byte"))?;
            pattern_bits &= self.anchor.owner.second_byte_patterns(haystack[second]);
        }
        while pattern_bits != 0 {
            let source_index = pattern_bits.trailing_zeros();
            pattern_bits &= pattern_bits.wrapping_sub(1);
            let prior = *actual;
            increment(
                &mut actual.pattern_checks,
                prior,
                "Unicode guarded pattern checks",
            )?;
            let source_index = usize::try_from(source_index)
                .map_err(|_| reduce_overflow(*actual, "Unicode guarded source index"))?;
            let word = self.dictionary.source_word(source_index).ok_or_else(|| {
                reduce_invariant(*actual, "Unicode guarded source word disappeared")
            })?;
            let prior = *actual;
            if !equal_counted(
                &haystack[start..end],
                word.bytes,
                &mut actual.verification_source_reads,
                prior,
            )? {
                continue;
            }
            let prior = *actual;
            increment(
                &mut actual.boundary_checks,
                prior,
                "Unicode guarded left boundary checks",
            )?;
            if start > 0
                && !haystack[start.saturating_sub(1)].is_ascii()
                && unicode_word_before(haystack, start, actual)?
            {
                continue;
            }
            let prior = *actual;
            increment(
                &mut actual.boundary_checks,
                prior,
                "Unicode guarded right boundary checks",
            )?;
            if end < haystack.len()
                && !haystack[end].is_ascii()
                && unicode_word_after(haystack, end, actual)?
            {
                continue;
            }
            actual.match_events = actual
                .match_events
                .checked_add(1)
                .ok_or_else(|| reduce_overflow(*actual, "Unicode guarded match events"))?;
            if SPAN_SUM {
                actual.span_sum =
                    actual
                        .span_sum
                        .checked_add(u64::try_from(word.bytes.len()).map_err(|_| {
                            reduce_overflow(*actual, "Unicode guarded matched width")
                        })?)
                        .ok_or_else(|| reduce_overflow(*actual, "Unicode guarded span sum"))?;
            }
            if VISIT {
                visitor(Span { start, end });
            }
            break;
        }
        Ok(())
    }

    fn preflight_reduce<const SPAN_SUM: bool>(
        &self,
        haystack_bytes: usize,
        limits: ReduceLimits,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        let build = self.anchor.build.prospective;
        // There can be at most one maximal ASCII-word run beginning at each
        // source byte. Using the full haystack extent also covers short runs
        // that are rejected before signature lookup.
        let candidate_positions = haystack_bytes;
        let pattern_checks = candidate_positions
            .checked_mul(build.max_signature_bucket_patterns)
            .ok_or_else(|| reduce_preflight_overflow("Unicode guarded pattern checks"))?;
        let verification_source_reads = candidate_positions
            .checked_mul(build.max_signature_bucket_pattern_bytes)
            .ok_or_else(|| {
                reduce_preflight_overflow("Unicode guarded verification source reads")
            })?;
        let boundary_checks = pattern_checks
            .checked_mul(2)
            .ok_or_else(|| reduce_preflight_overflow("Unicode guarded boundary checks"))?;
        let boundary_source_reads = boundary_checks
            .checked_mul(4)
            .ok_or_else(|| reduce_preflight_overflow("Unicode guarded boundary source reads"))?;
        let source_byte_reads = candidate_positions
            .checked_add(verification_source_reads)
            .and_then(|reads| reads.checked_add(boundary_source_reads))
            .ok_or_else(|| reduce_preflight_overflow("Unicode guarded source reads"))?;
        let iterator_next_calls = candidate_positions
            .checked_add(1)
            .ok_or_else(|| reduce_preflight_overflow("Unicode guarded iterator calls"))?;
        let work = candidate_positions
            .checked_add(iterator_next_calls)
            .and_then(|work| work.checked_add(pattern_checks))
            .and_then(|work| work.checked_add(boundary_checks))
            .and_then(|work| work.checked_add(source_byte_reads))
            .ok_or_else(|| reduce_preflight_overflow("Unicode guarded work"))?;
        let match_events = haystack_bytes
            .checked_div(build.min_pattern_bytes)
            .ok_or_else(|| reduce_preflight_overflow("Unicode guarded match-event quotient"))?;
        let count = u64::try_from(match_events)
            .map_err(|_| reduce_preflight_overflow("Unicode guarded count"))?;
        let span_sum = u64::try_from(haystack_bytes)
            .map_err(|_| reduce_preflight_overflow("Unicode guarded span sum"))?;
        let reducer_steps = candidate_positions
            .checked_add(1)
            .ok_or_else(|| reduce_preflight_overflow("Unicode guarded reducer steps"))?;
        let upper = ReduceUpperBounds {
            haystack_bytes,
            candidate_positions,
            source_byte_reads,
            pattern_checks,
            verification_source_reads,
            boundary_checks,
            boundary_source_reads,
            work: u64::try_from(work)
                .map_err(|_| reduce_preflight_overflow("Unicode guarded work as u64"))?,
            match_events,
            count,
            span_sum,
            reducer_steps,
            scratch_bytes: 0,
            persistent_bytes: build.persistent_bytes,
            peak_bytes: build.persistent_bytes,
        };
        enforce_reduce_limits(upper, SPAN_SUM, limits)?;
        Ok(upper)
    }
}

impl AnchorPlan {
    #[allow(
        clippy::too_many_lines,
        reason = "one fail-closed transaction initializes the exact signature masks and publishes their owner"
    )]
    fn build(
        dispatch: SimdDispatchContext,
        dictionary: &Dictionary,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        let (prospective, mut actual) = preflight_build(dictionary, limits)?;
        let mask_slots = signature_mask_slots(prospective.max_pattern_bytes).ok_or_else(|| {
            build_overflow(
                Some(prospective),
                actual,
                "Unicode guarded signature mask slots",
            )
        })?;
        let mask_bytes = mask_slots.checked_mul(size_of::<u128>()).ok_or_else(|| {
            build_overflow(
                Some(prospective),
                actual,
                "Unicode guarded signature mask bytes",
            )
        })?;
        let mut signature_masks =
            ExactVec::try_with_capacity(mask_slots).map_err(|source| BuildError {
                kind: match source {
                    CopyError::LayoutOverflow => BuildErrorKind::ArithmeticOverflow {
                        computation: "Unicode guarded signature-mask layout",
                    },
                    CopyError::AllocationFailed => {
                        BuildErrorKind::AllocationFailed { bytes: mask_bytes }
                    }
                },
                prospective: Some(prospective),
                actual,
            })?;
        for _ in 0..mask_slots {
            signature_masks.try_push(0).map_err(|_| {
                build_invariant(
                    Some(prospective),
                    actual,
                    "exact Unicode guarded signature-mask capacity changed",
                )
            })?;
        }
        actual.allocations = 1;
        actual.allocated_bytes = mask_bytes;
        actual.initialized_bytes = mask_bytes;
        actual.peak_bytes = mask_bytes;
        for source_index in 0..prospective.patterns {
            let word = dictionary.source_word(source_index).ok_or_else(|| {
                build_invariant(
                    Some(prospective),
                    actual,
                    "Unicode guarded source word disappeared after preflight",
                )
            })?;
            let shift = u32::try_from(source_index).map_err(|_| {
                build_overflow(Some(prospective), actual, "Unicode guarded source bit")
            })?;
            let bit = 1_u128.checked_shl(shift).ok_or_else(|| {
                build_overflow(Some(prospective), actual, "Unicode guarded source bit")
            })?;
            signature_masks[FIRST_BYTE_MASK_OFFSET + usize::from(word.bytes[0])] |= bit;
            if prospective.prefix_bytes == 2 {
                signature_masks[SECOND_BYTE_MASK_OFFSET + usize::from(word.bytes[1])] |= bit;
            }
            let length_mask = LENGTH_MASK_OFFSET
                .checked_add(word.bytes.len())
                .ok_or_else(|| {
                    build_overflow(
                        Some(prospective),
                        actual,
                        "Unicode guarded length-mask index",
                    )
                })?;
            signature_masks[length_mask] |= bit;
        }
        let classifier = dispatch
            .ascii_byte_set_classifier(ASCII_WORD_SET, DispatchPolicy::Auto)
            .map_err(|_| BuildError {
                kind: BuildErrorKind::InternalInvariant {
                    detail: "automatic ASCII classifier lost its scalar fallback",
                },
                prospective: Some(prospective),
                actual,
            })?;
        actual.work = prospective.build_work;
        let owner = AnchorOwner {
            classifier,
            signature_masks,
        };
        let owner = try_box_preserve(owner).map_err(|(source, _)| BuildError {
            kind: match source {
                CopyError::LayoutOverflow => BuildErrorKind::ArithmeticOverflow {
                    computation: "Unicode guarded anchor-owner layout",
                },
                CopyError::AllocationFailed => BuildErrorKind::AllocationFailed {
                    bytes: size_of::<AnchorOwner>(),
                },
            },
            prospective: Some(prospective),
            actual,
        })?;
        actual.allocations = 2;
        actual.allocated_bytes = actual
            .allocated_bytes
            .checked_add(size_of::<AnchorOwner>())
            .ok_or_else(|| {
                build_overflow(Some(prospective), actual, "Unicode guarded allocated bytes")
            })?;
        actual.initialized_bytes = prospective.initialized_bytes;
        actual.live_persistent_bytes = prospective.persistent_bytes;
        actual.peak_bytes = prospective.peak_bytes;
        actual.published = true;
        let build = BuildAccounting {
            prospective,
            actual,
        };
        Ok(Self { owner, build })
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one linear fail-closed preflight derives and enforces every construction dimension"
)]
fn preflight_build(
    dictionary: &Dictionary,
    limits: BuildLimits,
) -> Result<(BuildProspective, BuildActual), BuildError> {
    let identity = dictionary.identity();
    let patterns = identity.entries.len();
    let mut actual = BuildActual {
        work: FIXED_BUILD_WORK,
        ..BuildActual::default()
    };
    if patterns == 0 || patterns > CERTIFIED_MAX_PATTERNS {
        return Err(BuildError {
            kind: BuildErrorKind::UnsupportedShape {
                detail: "Unicode guarded maximal runs require 1..=128 source words",
            },
            prospective: None,
            actual,
        });
    }
    if identity.packed_bytes.len() > CERTIFIED_MAX_TOTAL_PATTERN_BYTES {
        return Err(BuildError {
            kind: BuildErrorKind::UnsupportedShape {
                detail: "Unicode guarded maximal runs require at most 512 source bytes",
            },
            prospective: None,
            actual,
        });
    }
    let mut min_pattern_bytes = usize::MAX;
    let mut max_pattern_bytes = 0_usize;
    for source_index in 0..patterns {
        let Some(word) = dictionary.source_word(source_index) else {
            return Err(build_invariant(
                None,
                actual,
                "Unicode guarded dictionary identity lost a source word",
            ));
        };
        actual.work = actual
            .work
            .checked_add(1)
            .and_then(|work| work.checked_add(u64::try_from(word.bytes.len()).ok()?))
            .ok_or_else(|| {
                build_overflow(None, actual, "Unicode guarded source inspection work")
            })?;
        if word.left != Guard::LeftBoundary || word.right != Guard::RightBoundary {
            return Err(BuildError {
                kind: BuildErrorKind::UnsupportedShape {
                    detail: "Unicode guarded maximal runs require two full boundaries",
                },
                prospective: None,
                actual,
            });
        }
        if word.bytes.is_empty()
            || !word
                .bytes
                .iter()
                .copied()
                .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
        {
            return Err(BuildError {
                kind: BuildErrorKind::UnsupportedShape {
                    detail: "Unicode guarded maximal runs require nonempty ASCII words",
                },
                prospective: None,
                actual,
            });
        }
        min_pattern_bytes = min_pattern_bytes.min(word.bytes.len());
        max_pattern_bytes = max_pattern_bytes.max(word.bytes.len());
    }
    let prefix_bytes = min_pattern_bytes.min(2);
    let mut prefix_selection_work = 0_u64;
    let mut max_signature_bucket_patterns = 0_usize;
    let mut max_signature_bucket_pattern_bytes = 0_usize;
    for source_index in 0..patterns {
        let source = dictionary.source_word(source_index).ok_or_else(|| {
            build_invariant(None, actual, "Unicode guarded source word disappeared")
        })?;
        let mut bucket_patterns = 0_usize;
        let mut bucket_pattern_bytes = 0_usize;
        for candidate_index in 0..patterns {
            let candidate = dictionary.source_word(candidate_index).ok_or_else(|| {
                build_invariant(None, actual, "Unicode guarded bucket word disappeared")
            })?;
            prefix_selection_work = prefix_selection_work.checked_add(1).ok_or_else(|| {
                build_overflow(None, actual, "Unicode guarded signature comparisons")
            })?;
            if candidate.bytes.len() == source.bytes.len()
                && candidate.bytes[0] == source.bytes[0]
                && (prefix_bytes == 1 || candidate.bytes[1] == source.bytes[1])
            {
                bucket_patterns = bucket_patterns.checked_add(1).ok_or_else(|| {
                    build_overflow(None, actual, "Unicode guarded signature bucket patterns")
                })?;
                bucket_pattern_bytes = bucket_pattern_bytes
                    .checked_add(candidate.bytes.len())
                    .ok_or_else(|| {
                        build_overflow(None, actual, "Unicode guarded signature bucket bytes")
                    })?;
            }
        }
        max_signature_bucket_patterns = max_signature_bucket_patterns.max(bucket_patterns);
        max_signature_bucket_pattern_bytes =
            max_signature_bucket_pattern_bytes.max(bucket_pattern_bytes);
    }
    actual.work = actual
        .work
        .checked_add(prefix_selection_work)
        .ok_or_else(|| build_overflow(None, actual, "Unicode guarded prefix-selection work"))?;
    let pattern_map_work =
        patterns
            .checked_mul(prefix_bytes.checked_add(1).ok_or_else(|| {
                build_overflow(None, actual, "Unicode guarded pattern-map fields")
            })?)
            .ok_or_else(|| build_overflow(None, actual, "Unicode guarded pattern-map work"))?;
    let mask_slots = signature_mask_slots(max_pattern_bytes)
        .ok_or_else(|| build_overflow(None, actual, "Unicode guarded signature mask slots"))?;
    let build_work = actual
        .work
        .checked_add(
            u64::try_from(pattern_map_work)
                .map_err(|_| build_overflow(None, actual, "Unicode guarded pattern-map work"))?,
        )
        .and_then(|work| work.checked_add(CLASSIFIER_BUILD_WORK))
        .and_then(|work| work.checked_add(u64::try_from(mask_slots).ok()?))
        .ok_or_else(|| build_overflow(None, actual, "Unicode guarded build work"))?;
    let mask_bytes = mask_slots
        .checked_mul(size_of::<u128>())
        .ok_or_else(|| build_overflow(None, actual, "Unicode guarded signature mask bytes"))?;
    let persistent_bytes = size_of::<AnchorOwner>()
        .checked_add(size_of::<AnchorPlan>())
        .and_then(|bytes| bytes.checked_add(mask_bytes))
        .ok_or_else(|| build_overflow(None, actual, "Unicode guarded persistent bytes"))?;
    let initialized_bytes = persistent_bytes;
    let peak_bytes = persistent_bytes;
    let prospective = BuildProspective {
        patterns,
        pattern_bytes: identity.packed_bytes.len(),
        min_pattern_bytes,
        max_pattern_bytes,
        prefix_bytes,
        prefix_selection_work,
        max_signature_bucket_patterns,
        max_signature_bucket_pattern_bytes,
        build_work,
        allocations: 2,
        initialized_bytes,
        persistent_bytes,
        peak_bytes,
    };
    enforce_build_limits(prospective, limits, actual)?;
    Ok((prospective, actual))
}

fn signature_mask_slots(max_pattern_bytes: usize) -> Option<usize> {
    LENGTH_MASK_OFFSET
        .checked_add(max_pattern_bytes)
        .and_then(|slots| slots.checked_add(1))
}

fn enforce_build_limits(
    prospective: BuildProspective,
    limits: BuildLimits,
    actual: BuildActual,
) -> Result<(), BuildError> {
    let resources = [
        (
            BuildResource::Patterns,
            u64_from_usize_build(prospective.patterns, "Unicode guarded patterns")?,
            u64_from_usize_build(limits.max_patterns, "Unicode guarded pattern limit")?,
        ),
        (
            BuildResource::PatternBytes,
            u64_from_usize_build(prospective.pattern_bytes, "Unicode guarded pattern bytes")?,
            u64_from_usize_build(
                limits.max_pattern_bytes,
                "Unicode guarded pattern-byte limit",
            )?,
        ),
        (
            BuildResource::Work,
            prospective.build_work,
            limits.max_build_work,
        ),
        (
            BuildResource::Allocations,
            u64_from_usize_build(prospective.allocations, "Unicode guarded allocations")?,
            u64_from_usize_build(limits.max_allocations, "Unicode guarded allocation limit")?,
        ),
        (
            BuildResource::InitializedBytes,
            u64_from_usize_build(
                prospective.initialized_bytes,
                "Unicode guarded initialized bytes",
            )?,
            u64_from_usize_build(
                limits.max_initialized_bytes,
                "Unicode guarded initialized-byte limit",
            )?,
        ),
        (
            BuildResource::PersistentBytes,
            u64_from_usize_build(
                prospective.persistent_bytes,
                "Unicode guarded persistent bytes",
            )?,
            u64_from_usize_build(
                limits.max_persistent_bytes,
                "Unicode guarded persistent-byte limit",
            )?,
        ),
        (
            BuildResource::PeakBytes,
            u64_from_usize_build(prospective.peak_bytes, "Unicode guarded peak bytes")?,
            u64_from_usize_build(limits.max_peak_bytes, "Unicode guarded peak-byte limit")?,
        ),
    ];
    for (resource, needed, limit) in resources {
        if needed > limit {
            return Err(BuildError {
                kind: BuildErrorKind::ResourceLimit {
                    resource,
                    needed,
                    limit,
                },
                prospective: Some(prospective),
                actual,
            });
        }
    }
    Ok(())
}

fn u64_from_usize_build(value: usize, computation: &'static str) -> Result<u64, BuildError> {
    u64::try_from(value).map_err(|_| build_overflow(None, BuildActual::default(), computation))
}

const fn build_overflow(
    prospective: Option<BuildProspective>,
    actual: BuildActual,
    computation: &'static str,
) -> BuildError {
    BuildError {
        kind: BuildErrorKind::ArithmeticOverflow { computation },
        prospective,
        actual,
    }
}

const fn build_invariant(
    prospective: Option<BuildProspective>,
    actual: BuildActual,
    detail: &'static str,
) -> BuildError {
    BuildError {
        kind: BuildErrorKind::InternalInvariant { detail },
        prospective,
        actual,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceLimits {
    pub max_haystack_bytes: usize,
    pub max_candidate_positions: usize,
    pub max_source_byte_reads: usize,
    pub max_pattern_checks: usize,
    pub max_boundary_checks: usize,
    pub max_work: u64,
    pub max_match_events: usize,
    pub max_count: u64,
    pub max_span_sum: u64,
    pub max_reducer_steps: usize,
    pub max_peak_bytes: usize,
}

impl ReduceLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_haystack_bytes: usize::MAX,
            max_candidate_positions: usize::MAX,
            max_source_byte_reads: usize::MAX,
            max_pattern_checks: usize::MAX,
            max_boundary_checks: usize::MAX,
            max_work: u64::MAX,
            max_match_events: usize::MAX,
            max_count: u64::MAX,
            max_span_sum: u64::MAX,
            max_reducer_steps: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for ReduceLimits {
    fn default() -> Self {
        Self {
            max_haystack_bytes: 128 << 20,
            max_candidate_positions: 128 << 20,
            max_source_byte_reads: 2 << 30,
            max_pattern_checks: 1 << 30,
            max_boundary_checks: 1 << 30,
            max_work: 8 << 30,
            max_match_events: 64 << 20,
            max_count: 64 << 20,
            max_span_sum: 128 << 20,
            max_reducer_steps: (128 << 20) + 1,
            max_peak_bytes: 64 << 20,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReduceResource {
    HaystackBytes,
    CandidatePositions,
    SourceByteReads,
    PatternChecks,
    BoundaryChecks,
    Work,
    MatchEvents,
    Count,
    SpanSum,
    ReducerSteps,
    PeakBytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceUpperBounds {
    pub haystack_bytes: usize,
    pub candidate_positions: usize,
    pub source_byte_reads: usize,
    pub pattern_checks: usize,
    pub verification_source_reads: usize,
    pub boundary_checks: usize,
    pub boundary_source_reads: usize,
    pub work: u64,
    pub match_events: usize,
    pub count: u64,
    pub span_sum: u64,
    pub reducer_steps: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReduceActual {
    pub classified_positions: usize,
    pub candidate_events: usize,
    pub iterator_next_calls: usize,
    pub pattern_checks: usize,
    pub verification_source_reads: usize,
    pub boundary_checks: usize,
    pub boundary_source_reads: usize,
    pub source_byte_reads: usize,
    pub work: u64,
    pub match_events: u64,
    pub span_sum: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceAccounting {
    pub identity: OperationIdentity,
    pub upper_bounds: ReduceUpperBounds,
    pub actual: ReduceActual,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanVisitResult {
    pub matches: u64,
    pub span_sum: u64,
    pub accounting: ReduceAccounting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReduceErrorKind {
    ResourceLimit {
        resource: ReduceResource,
        needed: u64,
        limit: u64,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    InternalInvariant {
        detail: &'static str,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceError {
    pub kind: ReduceErrorKind,
    pub upper_bounds: Option<ReduceUpperBounds>,
    pub actual: ReduceActual,
}

impl fmt::Display for ReduceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "guarded Unicode-word maximal-run reduction failed: {:?}",
            self.kind
        )
    }
}

impl std::error::Error for ReduceError {}

#[derive(Clone, Copy)]
struct Reduction {
    upper: ReduceUpperBounds,
    actual: ReduceActual,
}

fn enforce_reduce_limits(
    upper: ReduceUpperBounds,
    span_sum: bool,
    limits: ReduceLimits,
) -> Result<(), ReduceError> {
    let resources = [
        (
            ReduceResource::HaystackBytes,
            u64_from_usize_reduce(upper.haystack_bytes, "Unicode guarded haystack bytes")?,
            u64_from_usize_reduce(limits.max_haystack_bytes, "Unicode guarded haystack limit")?,
        ),
        (
            ReduceResource::CandidatePositions,
            u64_from_usize_reduce(
                upper.candidate_positions,
                "Unicode guarded candidate positions",
            )?,
            u64_from_usize_reduce(
                limits.max_candidate_positions,
                "Unicode guarded candidate-position limit",
            )?,
        ),
        (
            ReduceResource::SourceByteReads,
            u64_from_usize_reduce(upper.source_byte_reads, "Unicode guarded source reads")?,
            u64_from_usize_reduce(
                limits.max_source_byte_reads,
                "Unicode guarded source-read limit",
            )?,
        ),
        (
            ReduceResource::PatternChecks,
            u64_from_usize_reduce(upper.pattern_checks, "Unicode guarded pattern checks")?,
            u64_from_usize_reduce(
                limits.max_pattern_checks,
                "Unicode guarded pattern-check limit",
            )?,
        ),
        (
            ReduceResource::BoundaryChecks,
            u64_from_usize_reduce(upper.boundary_checks, "Unicode guarded boundary checks")?,
            u64_from_usize_reduce(
                limits.max_boundary_checks,
                "Unicode guarded boundary-check limit",
            )?,
        ),
        (ReduceResource::Work, upper.work, limits.max_work),
        (
            ReduceResource::MatchEvents,
            u64_from_usize_reduce(upper.match_events, "Unicode guarded match events")?,
            u64_from_usize_reduce(limits.max_match_events, "Unicode guarded match-event limit")?,
        ),
        (ReduceResource::Count, upper.count, limits.max_count),
        (
            ReduceResource::SpanSum,
            if span_sum { upper.span_sum } else { 0 },
            limits.max_span_sum,
        ),
        (
            ReduceResource::ReducerSteps,
            u64_from_usize_reduce(upper.reducer_steps, "Unicode guarded reducer steps")?,
            u64_from_usize_reduce(
                limits.max_reducer_steps,
                "Unicode guarded reducer-step limit",
            )?,
        ),
        (
            ReduceResource::PeakBytes,
            u64_from_usize_reduce(upper.peak_bytes, "Unicode guarded peak bytes")?,
            u64_from_usize_reduce(limits.max_peak_bytes, "Unicode guarded peak-byte limit")?,
        ),
    ];
    for (resource, needed, limit) in resources {
        if needed > limit {
            return Err(ReduceError {
                kind: ReduceErrorKind::ResourceLimit {
                    resource,
                    needed,
                    limit,
                },
                upper_bounds: Some(upper),
                actual: ReduceActual::default(),
            });
        }
    }
    Ok(())
}

fn actual_fits(actual: ReduceActual, upper: ReduceUpperBounds) -> bool {
    actual.classified_positions <= upper.candidate_positions
        && actual.candidate_events <= upper.candidate_positions
        && actual.iterator_next_calls <= upper.candidate_positions.saturating_add(1)
        && actual.pattern_checks <= upper.pattern_checks
        && actual.verification_source_reads <= upper.verification_source_reads
        && actual.boundary_checks <= upper.boundary_checks
        && actual.boundary_source_reads <= upper.boundary_source_reads
        && actual.source_byte_reads <= upper.source_byte_reads
        && actual.work <= upper.work
        && actual.match_events <= upper.count
        && actual.span_sum <= upper.span_sum
}

fn actual_work(actual: ReduceActual) -> Result<u64, ReduceError> {
    let work = actual
        .classified_positions
        .checked_add(actual.iterator_next_calls)
        .and_then(|value| value.checked_add(actual.pattern_checks))
        .and_then(|value| value.checked_add(actual.boundary_checks))
        .and_then(|value| value.checked_add(actual.source_byte_reads))
        .ok_or_else(|| reduce_overflow(actual, "Unicode guarded actual work"))?;
    u64::try_from(work).map_err(|_| reduce_overflow(actual, "Unicode guarded actual work as u64"))
}

fn equal_counted(
    left: &[u8],
    right: &[u8],
    reads: &mut usize,
    actual: ReduceActual,
) -> Result<bool, ReduceError> {
    if left.len() != right.len() {
        return Ok(false);
    }
    for (&left, &right) in left.iter().zip(right) {
        increment(reads, actual, "Unicode guarded verification reads")?;
        if left != right {
            return Ok(false);
        }
    }
    Ok(true)
}

fn unicode_word_before(
    haystack: &[u8],
    position: usize,
    actual: &mut ReduceActual,
) -> Result<bool, ReduceError> {
    if position == 0 {
        return Ok(false);
    }
    let mut start = position
        .checked_sub(1)
        .ok_or_else(|| reduce_overflow(*actual, "Unicode guarded preceding-byte position"))?;
    let prior = *actual;
    increment(
        &mut actual.boundary_source_reads,
        prior,
        "Unicode guarded preceding-byte reads",
    )?;
    if haystack[start].is_ascii() {
        return Ok(is_unicode_word(char::from(haystack[start])));
    }
    let lower = position.saturating_sub(4);
    while start > lower && matches!(haystack[start], 0x80..=0xBF) {
        start = start
            .checked_sub(1)
            .ok_or_else(|| reduce_overflow(*actual, "Unicode guarded preceding-scalar start"))?;
        let prior = *actual;
        increment(
            &mut actual.boundary_source_reads,
            prior,
            "Unicode guarded preceding-byte reads",
        )?;
    }
    let bytes = &haystack[start..position];
    let Ok(text) = core::str::from_utf8(bytes) else {
        return Ok(false);
    };
    let mut scalars = text.chars();
    let Some(scalar) = scalars.next() else {
        return Ok(false);
    };
    Ok(scalars.next().is_none() && is_unicode_word(scalar))
}

fn unicode_word_after(
    haystack: &[u8],
    position: usize,
    actual: &mut ReduceActual,
) -> Result<bool, ReduceError> {
    let Some(&first) = haystack.get(position) else {
        return Ok(false);
    };
    let width = if first.is_ascii() {
        1
    } else {
        match first {
            0xC2..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF4 => 4,
            _ => 1,
        }
    };
    let available = haystack.len().saturating_sub(position).min(width);
    actual.boundary_source_reads = actual
        .boundary_source_reads
        .checked_add(available)
        .ok_or_else(|| reduce_overflow(*actual, "Unicode guarded following-byte reads"))?;
    let Some(bytes) = haystack.get(position..position.saturating_add(width)) else {
        return Ok(false);
    };
    let Ok(text) = core::str::from_utf8(bytes) else {
        return Ok(false);
    };
    let mut scalars = text.chars();
    let Some(scalar) = scalars.next() else {
        return Ok(false);
    };
    Ok(scalars.next().is_none() && is_unicode_word(scalar))
}

fn is_unicode_word(scalar: char) -> bool {
    if scalar.is_ascii() {
        return scalar == '_' || scalar.is_ascii_alphanumeric();
    }
    regex_syntax::try_is_word_character(scalar)
        .expect("fre enables regex-syntax's Unicode Perl tables")
}

const fn is_ascii_word(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn increment(
    value: &mut usize,
    actual: ReduceActual,
    computation: &'static str,
) -> Result<(), ReduceError> {
    *value = value
        .checked_add(1)
        .ok_or_else(|| reduce_overflow(actual, computation))?;
    Ok(())
}

fn u64_from_usize_reduce(value: usize, computation: &'static str) -> Result<u64, ReduceError> {
    u64::try_from(value).map_err(|_| reduce_preflight_overflow(computation))
}

const fn reduce_preflight_overflow(computation: &'static str) -> ReduceError {
    ReduceError {
        kind: ReduceErrorKind::ArithmeticOverflow { computation },
        upper_bounds: None,
        actual: ReduceActual {
            classified_positions: 0,
            candidate_events: 0,
            iterator_next_calls: 0,
            pattern_checks: 0,
            verification_source_reads: 0,
            boundary_checks: 0,
            boundary_source_reads: 0,
            source_byte_reads: 0,
            work: 0,
            match_events: 0,
            span_sum: 0,
        },
    }
}

const fn reduce_overflow(actual: ReduceActual, computation: &'static str) -> ReduceError {
    ReduceError {
        kind: ReduceErrorKind::ArithmeticOverflow { computation },
        upper_bounds: None,
        actual,
    }
}

const fn reduce_invariant(actual: ReduceActual, detail: &'static str) -> ReduceError {
    ReduceError {
        kind: ReduceErrorKind::InternalInvariant { detail },
        upper_bounds: None,
        actual,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guarded_ascii_word::{BuildDimensions, BuildLimits as DictionaryLimits, SourceWord};

    fn dictionary(patterns: &[&[u8]]) -> Dictionary {
        Dictionary::build_precounted(
            BuildDimensions {
                words: patterns.len(),
                packed_bytes: patterns.iter().map(|pattern| pattern.len()).sum(),
            },
            patterns.iter().map(|pattern| SourceWord {
                bytes: pattern,
                left: Guard::LeftBoundary,
                right: Guard::RightBoundary,
            }),
            DictionaryLimits::unlimited(),
        )
        .unwrap()
    }

    fn plan(patterns: &[&[u8]]) -> Plan {
        Plan::build(dictionary(patterns), BuildLimits::unlimited()).unwrap()
    }

    #[test]
    fn unicode_boundaries_priority_and_non_overlap_match_rust_bytes() {
        let patterns = [b"a".as_slice(), b"ab".as_slice(), b"Self".as_slice()];
        let plan = plan(&patterns);
        let oracle = regex::bytes::RegexBuilder::new(r"\b(?:a|ab|Self)\b")
            .unicode(true)
            .build()
            .unwrap();
        let cases: &[&[u8]] = &[
            b"",
            b"a",
            b"ab",
            b"a ab Self a",
            "_a a_".as_bytes(),
            "βa aβ βaβ a".as_bytes(),
            &[0xFF, b'a', 0xFF],
            &[0xC3, b'a', 0xA9],
        ];
        for &haystack in cases {
            let expected = oracle.find_iter(haystack).collect::<Vec<_>>();
            let expected_count = u64::try_from(expected.len()).unwrap();
            let expected_span_sum = expected.iter().try_fold(0_u64, |sum, matched| {
                sum.checked_add(u64::try_from(matched.len()).ok()?)
            });
            assert_eq!(
                plan.count(haystack, ReduceLimits::unlimited())
                    .unwrap()
                    .count,
                expected_count,
                "haystack={haystack:?}"
            );
            assert_eq!(
                plan.span_sum(haystack, ReduceLimits::unlimited())
                    .unwrap()
                    .span_sum,
                expected_span_sum.unwrap(),
                "haystack={haystack:?}"
            );
            let expected_spans = expected
                .iter()
                .map(|matched| Span {
                    start: matched.start(),
                    end: matched.end(),
                })
                .collect::<Vec<_>>();
            let mut visited = Vec::new();
            let visit = plan
                .visit_spans(haystack, ReduceLimits::unlimited(), |span| {
                    visited.push(span);
                })
                .unwrap();
            assert_eq!(visited, expected_spans, "haystack={haystack:?}");
            assert_eq!(visit.matches, expected_count);
            assert_eq!(visit.span_sum, expected_span_sum.unwrap());
            assert_eq!(visit.accounting.identity, plan.span_visit_identity());
        }
    }

    #[test]
    fn maximal_runs_cross_simd_blocks_and_match_rust_bytes() {
        let patterns = [b"as".as_slice(), b"break", b"const", b"Self"];
        let plan = plan(&patterns);
        let oracle = regex::bytes::RegexBuilder::new(r"\b(?:as|break|const|Self)\b")
            .unicode(true)
            .build()
            .unwrap();
        let mut cases = Vec::new();
        for padding in [0, 1, 30, 31, 32, 33, 62, 63, 64, 65] {
            let mut haystack = vec![b' '; padding];
            haystack.extend_from_slice(b"break as_const const Self ");
            haystack.extend(core::iter::repeat_n(b'a', 70));
            haystack.extend_from_slice(" βas asβ as ".as_bytes());
            cases.push(haystack);
        }
        let mut one_block_flush = vec![b' '; 30];
        one_block_flush.extend_from_slice(b"as");
        cases.push(one_block_flush);
        let mut two_block_flush = vec![b' '; 62];
        two_block_flush.extend_from_slice(b"as");
        cases.push(two_block_flush);
        let mut split_unicode_scalar = vec![b' '; 31];
        split_unicode_scalar.extend_from_slice("βas as".as_bytes());
        cases.push(split_unicode_scalar);
        for haystack in cases {
            let expected = oracle.find_iter(&haystack).collect::<Vec<_>>();
            let expected_count = u64::try_from(expected.len()).unwrap();
            let expected_span_sum = expected.iter().try_fold(0_u64, |sum, matched| {
                sum.checked_add(u64::try_from(matched.len()).ok()?)
            });
            let count = plan.count(&haystack, ReduceLimits::unlimited()).unwrap();
            let span_sum = plan.span_sum(&haystack, ReduceLimits::unlimited()).unwrap();
            assert_eq!(count.count, expected_count, "haystack={haystack:?}");
            assert_eq!(
                span_sum.span_sum,
                expected_span_sum.unwrap(),
                "haystack={haystack:?}"
            );
            assert_eq!(count.accounting.actual.classified_positions, haystack.len());
        }
    }

    #[test]
    fn source_order_duplicates_and_prefix_identity_are_retained() {
        let plan = plan(&[b"break", b"const", b"break", b"Self"]);
        let build = plan.build_accounting();
        assert_eq!(build.prospective.patterns, 4);
        assert_eq!(build.prospective.prefix_bytes, 2);
        assert_eq!(
            plan.count_identity().prefix_bytes,
            build.prospective.prefix_bytes
        );
        assert_eq!(
            plan.count(b"break const Self", ReduceLimits::unlimited())
                .unwrap()
                .count,
            3
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one table-style test checks every public reduction quota at its exact boundary"
    )]
    fn every_reduce_limit_refuses_before_source_access() {
        let plan = plan(&[b"as", b"break", b"const"]);
        let haystack = b"as break const";
        let baseline = plan.span_sum(haystack, ReduceLimits::unlimited()).unwrap();
        let upper = baseline.accounting.upper_bounds;
        let exact = ReduceLimits {
            max_haystack_bytes: upper.haystack_bytes,
            max_candidate_positions: upper.candidate_positions,
            max_source_byte_reads: upper.source_byte_reads,
            max_pattern_checks: upper.pattern_checks,
            max_boundary_checks: upper.boundary_checks,
            max_work: upper.work,
            max_match_events: upper.match_events,
            max_count: upper.count,
            max_span_sum: upper.span_sum,
            max_reducer_steps: upper.reducer_steps,
            max_peak_bytes: upper.peak_bytes,
        };
        plan.span_sum(haystack, exact).unwrap();
        let cases = [
            (
                ReduceResource::HaystackBytes,
                ReduceLimits {
                    max_haystack_bytes: exact.max_haystack_bytes - 1,
                    ..exact
                },
            ),
            (
                ReduceResource::CandidatePositions,
                ReduceLimits {
                    max_candidate_positions: exact.max_candidate_positions - 1,
                    ..exact
                },
            ),
            (
                ReduceResource::SourceByteReads,
                ReduceLimits {
                    max_source_byte_reads: exact.max_source_byte_reads - 1,
                    ..exact
                },
            ),
            (
                ReduceResource::PatternChecks,
                ReduceLimits {
                    max_pattern_checks: exact.max_pattern_checks - 1,
                    ..exact
                },
            ),
            (
                ReduceResource::BoundaryChecks,
                ReduceLimits {
                    max_boundary_checks: exact.max_boundary_checks - 1,
                    ..exact
                },
            ),
            (
                ReduceResource::Work,
                ReduceLimits {
                    max_work: exact.max_work - 1,
                    ..exact
                },
            ),
            (
                ReduceResource::MatchEvents,
                ReduceLimits {
                    max_match_events: exact.max_match_events - 1,
                    ..exact
                },
            ),
            (
                ReduceResource::Count,
                ReduceLimits {
                    max_count: exact.max_count - 1,
                    ..exact
                },
            ),
            (
                ReduceResource::SpanSum,
                ReduceLimits {
                    max_span_sum: exact.max_span_sum - 1,
                    ..exact
                },
            ),
            (
                ReduceResource::ReducerSteps,
                ReduceLimits {
                    max_reducer_steps: exact.max_reducer_steps - 1,
                    ..exact
                },
            ),
            (
                ReduceResource::PeakBytes,
                ReduceLimits {
                    max_peak_bytes: exact.max_peak_bytes - 1,
                    ..exact
                },
            ),
        ];
        for (resource, limits) in cases {
            let error = plan.span_sum(haystack, limits).unwrap_err();
            assert!(matches!(
                error.kind,
                ReduceErrorKind::ResourceLimit {
                    resource: actual,
                    ..
                } if actual == resource
            ));
            assert_eq!(error.actual, ReduceActual::default());
            let mut callbacks = 0;
            let visit_error = plan
                .visit_spans(haystack, limits, |_| callbacks += 1)
                .unwrap_err();
            assert_eq!(callbacks, 0);
            assert_eq!(visit_error.kind, error.kind);
            assert_eq!(visit_error.actual, ReduceActual::default());
        }
    }

    #[test]
    fn build_caps_close_exactly_and_refuse_one_below() {
        let owned_dictionary = dictionary(&[b"as".as_slice(), b"break", b"const"]);
        let baseline = Plan::build(owned_dictionary, BuildLimits::unlimited()).unwrap();
        let prospective = baseline.build_accounting().prospective;
        let exact = BuildLimits {
            max_patterns: prospective.patterns,
            max_pattern_bytes: prospective.pattern_bytes,
            max_build_work: prospective.build_work,
            max_allocations: prospective.allocations,
            max_initialized_bytes: prospective.initialized_bytes,
            max_persistent_bytes: prospective.persistent_bytes,
            max_peak_bytes: prospective.peak_bytes,
        };
        Plan::build(dictionary(&[b"as".as_slice(), b"break", b"const"]), exact).unwrap();
        let error = Plan::build(
            dictionary(&[b"as".as_slice(), b"break", b"const"]),
            BuildLimits {
                max_build_work: exact.max_build_work - 1,
                ..exact
            },
        )
        .unwrap_err();
        assert!(matches!(
            error.kind,
            BuildErrorKind::ResourceLimit {
                resource: BuildResource::Work,
                ..
            }
        ));
        assert_eq!(error.actual.allocations, 0);
        assert!(!error.actual.published);
    }
}
