//! Direct operation-specialized search for one root byte class repeated one
//! or more times.
//!
//! The admitted HIR is exactly `CLASS+` or `CLASS+?`, modulo transparent
//! captures. A member scanner establishes the leftmost start. Greedy selected
//! operations use a separately compiled complement scanner to establish the
//! maximal run end, while existence and earliest-end projections stop after
//! the first member.

use fre_exact_alloc::{CopyError, ExactBoxOrUsize};
use fre_kernels::{
    BYTE_SET_BLOCK_BYTES, BYTE_SET_CLASSIFIER_BUILD_WORK, ByteSet256, ByteSetClassifier,
    DispatchPolicy, SimdDispatchContext, classify_byte_delta_16,
};
use memchr::{memchr, memchr2, memchr3};
use regex_syntax::hir::{Class, Hir, HirKind};

use crate::{Match, SearchLimits, SearchWindow};

pub const PLAN_ID: &str = "pure-byte-class-repeat-plus-v1";

const NODE_INSPECTION_WORK: u64 = 1;
const RANGE_INSPECTION_WORK: u64 = 1;
const MEMBER_INSERTION_WORK: u64 = 1;
const LEAF_SELECTION_WORK: u64 = 1;

#[cfg(test)]
std::thread_local! {
    static ORDINARY_FULL_CALLS: core::cell::Cell<(usize, usize)> = const {
        core::cell::Cell::new((0, 0))
    };
}

#[cfg(test)]
pub(crate) fn reset_ordinary_full_call_counts() {
    ORDINARY_FULL_CALLS.set((0, 0));
}

#[cfg(test)]
pub(crate) fn ordinary_full_call_counts() -> (usize, usize) {
    ORDINARY_FULL_CALLS.get()
}

#[cfg(test)]
fn record_ordinary_full_exists() {
    let (exists, span) = ORDINARY_FULL_CALLS.get();
    ORDINARY_FULL_CALLS.set((exists.saturating_add(1), span));
}

#[cfg(test)]
fn record_ordinary_full_span() {
    let (exists, span) = ORDINARY_FULL_CALLS.get();
    ORDINARY_FULL_CALLS.set((exists, span.saturating_add(1)));
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Exists,
    EarliestEnd,
    SelectedEnd,
    Span,
}

/// Exact successful-search effects for one operation-specialized invocation.
///
/// `source_reads` and `actual_work` count the same admitted abstract byte
/// classifications. Fixed-width leaves charge a complete block before its
/// first source read. The unbounded owner permits at most one classifier-block
/// overlap between member and run-end seeks. The bounded sibling can restart
/// after multiple short runs, so its separate source-independent envelope
/// permits one complete classifier block per advancing input position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Accounting {
    pub plan_id: &'static str,
    pub operation: Operation,
    pub input_bytes: usize,
    pub source_reads: usize,
    pub work_upper_bound: u64,
    pub actual_work: u64,
    pub candidate_scans: usize,
    pub run_scans: usize,
    pub match_events: usize,
}

#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    InvalidWindow,
    WorkLimit { needed: u64, limit: u64 },
}

impl core::fmt::Debug for Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidWindow => "InvalidWindow",
            Self::WorkLimit { .. } => "WorkLimit",
        })
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidWindow => {
                formatter.write_str("invalid pure byte-class repeat search window")
            }
            Self::WorkLimit { needed, limit } => write!(
                formatter,
                "pure byte-class repeat needs work unit {needed}, exceeding {limit}"
            ),
        }
    }
}

impl std::error::Error for Error {}

type SearchError = Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InspectionError {
    WorkLimit { needed: u64, limit: u64 },
    ArithmeticOverflow,
}

pub(crate) struct Inspection {
    greedy: bool,
    member_seek: SetSeek,
    run_end_seek: SetSeek,
    classifier_words: Option<[u64; 4]>,
    planner_work: u64,
}

pub(crate) enum InspectionOutcome {
    Eligible(Inspection),
    Ineligible { planner_work: u64 },
}

impl InspectionOutcome {
    pub(crate) const fn planner_work(&self) -> u64 {
        match self {
            Self::Eligible(inspection) => inspection.planner_work,
            Self::Ineligible { planner_work } => *planner_work,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SetSeek {
    Constant(bool),
    One(u8),
    Two(u8, u8),
    Three(u8, u8, u8),
    Range {
        origin: u8,
        maximum_delta: u8,
        inverted: bool,
    },
    Classified { inverted: bool },
}

impl SetSeek {
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the one-to-three-member branch bounds the output index"
    )]
    #[cold]
    pub(super) fn build(words: [u64; 4], cardinality: u32, classified_inverted: bool) -> Self {
        match cardinality {
            0 => Self::Constant(false),
            256 => Self::Constant(true),
            1..=3 => {
                let mut members = [0_u8; 3];
                let mut length = 0_usize;
                let set = ByteSet256::from_words(words);
                for byte in u8::MIN..=u8::MAX {
                    if set.contains(byte) {
                        members[length] = byte;
                        length += 1;
                        if length == usize::try_from(cardinality).expect("small cardinality fits") {
                            break;
                        }
                    }
                }
                match cardinality {
                    1 => Self::One(members[0]),
                    2 => Self::Two(members[0], members[1]),
                    3 => Self::Three(members[0], members[1], members[2]),
                    _ => unreachable!("the small-cardinality branch admits one to three members"),
                }
            }
            _ => {
                if let Some((origin, maximum_delta, inverted)) =
                    contiguous_range(words, cardinality)
                {
                    Self::Range {
                        origin,
                        maximum_delta,
                        inverted,
                    }
                } else {
                    Self::Classified {
                        inverted: classified_inverted,
                    }
                }
            }
        }
    }

    pub(super) const fn requires_classifier(self) -> bool {
        matches!(self, Self::Classified { .. })
    }

    pub(super) fn seek(
        self,
        haystack: &[u8],
        position: usize,
        end: usize,
        meter: &mut WorkMeter,
        classifier: Option<&ByteSetClassifier>,
    ) -> Result<Option<usize>, SearchError> {
        match self {
            Self::Constant(matches) => Ok((matches && position < end).then_some(position)),
            Self::One(_) | Self::Two(_, _) | Self::Three(_, _, _) => {
                seek_small(self, haystack, position, end, meter)
            }
            Self::Range {
                origin,
                maximum_delta,
                inverted,
            } => seek_range(
                origin,
                maximum_delta,
                inverted,
                haystack,
                position,
                end,
                meter,
            ),
            Self::Classified { inverted } => seek_classified(
                classifier.expect("a classified leaf retains the shared classifier"),
                inverted,
                haystack,
                position,
                end,
                meter,
            ),
        }
    }

    /// Search one already-validated unlimited value projection without
    /// constructing or updating the finite-work meter.
    #[inline]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "validated slice bounds make the returned relative offset safe to add"
    )]
    pub(super) fn seek_unmetered(
        self,
        haystack: &[u8],
        position: usize,
        end: usize,
        classifier: Option<&ByteSetClassifier>,
    ) -> Option<usize> {
        match self {
            Self::Constant(matches) => (matches && position < end).then_some(position),
            Self::One(byte) => memchr(byte, &haystack[position..end])
                .map(|relative| position + relative),
            Self::Two(first, second) => memchr2(first, second, &haystack[position..end])
                .map(|relative| position + relative),
            Self::Three(first, second, third) => {
                memchr3(first, second, third, &haystack[position..end])
                    .map(|relative| position + relative)
            }
            Self::Range {
                origin,
                maximum_delta,
                inverted,
            } => seek_range_unmetered(
                origin,
                maximum_delta,
                inverted,
                haystack,
                position,
                end,
            ),
            Self::Classified { inverted } => seek_classified_unmetered(
                classifier.expect("a classified leaf retains the shared classifier"),
                inverted,
                haystack,
                position,
                end,
            ),
        }
    }
}

#[cold]
fn contiguous_range(words: [u64; 4], cardinality: u32) -> Option<(u8, u8, bool)> {
    if let Some((origin, maximum_delta)) = contiguous_bounds(words, cardinality) {
        return Some((origin, maximum_delta, false));
    }
    let complement_cardinality = 256_u32.checked_sub(cardinality)?;
    contiguous_bounds(words.map(|word| !word), complement_cardinality)
        .map(|(origin, maximum_delta)| (origin, maximum_delta, true))
}

#[cold]
fn contiguous_bounds(words: [u64; 4], cardinality: u32) -> Option<(u8, u8)> {
    if cardinality == 0 {
        return None;
    }
    let word_bits = usize::try_from(u64::BITS).expect("the u64 bit width fits usize");
    let first_word = words.iter().position(|word| *word != 0)?;
    let last_word = words.iter().rposition(|word| *word != 0)?;
    let first = first_word
        .checked_mul(word_bits)?
        .checked_add(usize::try_from(words[first_word].trailing_zeros()).ok()?)?;
    let last_bit = u64::BITS
        .checked_sub(1)?
        .checked_sub(words[last_word].leading_zeros())?;
    let last = last_word
        .checked_mul(word_bits)?
        .checked_add(usize::try_from(last_bit).ok()?)?;
    let span = last
        .checked_sub(first)?
        .checked_add(1)?;
    if span != usize::try_from(cardinality).ok()? {
        return None;
    }
    Some((
        u8::try_from(first).ok()?,
        u8::try_from(last.checked_sub(first)?).ok()?,
    ))
}

struct Owner {
    greedy: bool,
    member_seek: SetSeek,
    run_end_seek: SetSeek,
    classifier: Option<ByteSetClassifier>,
}

pub(crate) struct Plan {
    owner: ExactBoxOrUsize<Owner>,
}

impl Plan {
    #[cold]
    fn build(
        greedy: bool,
        member_seek: SetSeek,
        run_end_seek: SetSeek,
        classifier_words: Option<[u64; 4]>,
        dispatch: SimdDispatchContext,
    ) -> Result<Self, CopyError> {
        let classifier = classifier_words.map(|classifier_words| {
            dispatch
                .byte_set_classifier(
                    ByteSet256::from_words(classifier_words),
                    DispatchPolicy::Auto,
                )
                .expect("automatic byte-set dispatch retains a scalar fallback")
        });
        let owner = ExactBoxOrUsize::try_from_boxed(Owner {
            greedy,
            member_seek,
            run_end_seek,
            classifier,
        })?;
        Ok(Self { owner })
    }

    fn owner(&self) -> &Owner {
        self.owner
            .boxed()
            .expect("the pure byte-class repeat retains its exact owner")
    }

    pub(crate) const fn storage_bytes() -> usize {
        core::mem::size_of::<Self>()
            .checked_add(core::mem::size_of::<Owner>())
            .expect("the fixed pure byte-class repeat layouts fit usize")
    }

    /// Search the complete haystack for the ordinary existence facade after
    /// that facade has selected unlimited, report-free execution.
    #[must_use]
    #[inline]
    pub(crate) fn ordinary_is_match_full_unmetered(&self, haystack: &[u8]) -> bool {
        #[cfg(test)]
        record_ordinary_full_exists();
        let owner = self.owner();
        owner
            .member_seek
            .seek_unmetered(haystack, 0, haystack.len(), owner.classifier.as_ref())
            .is_some()
    }

    /// Return the selected complete-haystack span for the ordinary facade
    /// without constructing a window, work meter, or accounting projection.
    #[must_use]
    #[inline]
    pub(crate) fn ordinary_find_full_unmetered(&self, haystack: &[u8]) -> Option<Match> {
        #[cfg(test)]
        record_ordinary_full_span();
        let owner = self.owner();
        let start = owner.member_seek.seek_unmetered(
            haystack,
            0,
            haystack.len(),
            owner.classifier.as_ref(),
        )?;
        let minimum_end = start
            .checked_add(1)
            .expect("a full-haystack member before the end can advance once");
        if !owner.greedy {
            return Some(Match {
                start,
                end: minimum_end,
            });
        }
        let end = owner
            .run_end_seek
            .seek_unmetered(
                haystack,
                minimum_end,
                haystack.len(),
                owner.classifier.as_ref(),
            )
            .unwrap_or(haystack.len());
        Some(Match { start, end })
    }

    /// Count non-overlapping selected matches in one ordinary full-tail
    /// projection without constructing spans, windows, or accounting.
    #[must_use]
    #[inline(never)]
    pub(crate) fn ordinary_count_full_unmetered(&self, haystack: &[u8]) -> u64 {
        let owner = self.owner();
        let mut position = 0_usize;
        let mut count = 0_u64;
        while let Some(start) = owner.member_seek.seek_unmetered(
            haystack,
            position,
            haystack.len(),
            owner.classifier.as_ref(),
        ) {
            let minimum_end = start
                .checked_add(1)
                .expect("a selected byte before the slice end can advance once");
            position = if owner.greedy {
                owner
                    .run_end_seek
                    .seek_unmetered(
                        haystack,
                        minimum_end,
                        haystack.len(),
                        owner.classifier.as_ref(),
                    )
                    .unwrap_or(haystack.len())
            } else {
                minimum_end
            };
            count = count
                .checked_add(1)
                .expect("a positive-width slice match count fits u64");
        }
        count
    }

    pub(crate) fn is_match_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(bool, Accounting), SearchError> {
        validate_window(haystack, window)?;
        let mut meter = WorkMeter::new(limits.max_work);
        let matched = self.owner().member_seek.seek(
            haystack,
            window.start(),
            window.end(),
            &mut meter,
            self.owner().classifier.as_ref(),
        )?;
        let matched = matched.is_some();
        let accounting =
            self.finish_accounting(Operation::Exists, window, meter, 1, 0, usize::from(matched));
        Ok((matched, accounting))
    }

    pub(crate) fn is_match_window_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        validate_window(haystack, window)?;
        let window_width = window
            .end()
            .checked_sub(window.start())
            .expect("a validated window has ordered bounds");
        if limits == SearchLimits::unlimited()
            && u64::try_from(window_width).is_ok()
        {
            let owner = self.owner();
            return Ok(owner
                .member_seek
                .seek_unmetered(
                    haystack,
                    window.start(),
                    window.end(),
                    owner.classifier.as_ref(),
                )
                .is_some());
        }
        let mut meter = WorkMeter::new(limits.max_work);
        self.owner()
            .member_seek
            .seek(
                haystack,
                window.start(),
                window.end(),
                &mut meter,
                self.owner().classifier.as_ref(),
            )
            .map(|matched| matched.is_some())
    }

    pub(crate) fn earliest_end_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, Accounting), SearchError> {
        validate_window(haystack, window)?;
        let mut meter = WorkMeter::new(limits.max_work);
        let end = self
            .owner()
            .member_seek
            .seek(
                haystack,
                window.start(),
                window.end(),
                &mut meter,
                self.owner().classifier.as_ref(),
            )?
            .map(|start| {
                start
                    .checked_add(1)
                    .expect("a member position before the window end can advance once")
            });
        let accounting = self.finish_accounting(
            Operation::EarliestEnd,
            window,
            meter,
            1,
            0,
            usize::from(end.is_some()),
        );
        Ok((end, accounting))
    }

    pub(crate) fn earliest_end_window_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<Option<usize>, SearchError> {
        validate_window(haystack, window)?;
        let window_width = window
            .end()
            .checked_sub(window.start())
            .expect("a validated window has ordered bounds");
        let owner = self.owner();
        if limits == SearchLimits::unlimited() && u64::try_from(window_width).is_ok() {
            return Ok(owner
                .member_seek
                .seek_unmetered(
                    haystack,
                    window.start(),
                    window.end(),
                    owner.classifier.as_ref(),
                )
                .map(|start| {
                    start
                        .checked_add(1)
                        .expect("a member position before the window end can advance once")
                }));
        }
        let mut meter = WorkMeter::new(limits.max_work);
        let start = owner.member_seek.seek(
            haystack,
            window.start(),
            window.end(),
            &mut meter,
            owner.classifier.as_ref(),
        )?;
        Ok(start.map(|start| {
            start
                .checked_add(1)
                .expect("a member position before the window end can advance once")
        }))
    }

    pub(crate) fn selected_end_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, Accounting), SearchError> {
        let (span, accounting) =
            self.selected_window(haystack, window, limits, Operation::SelectedEnd)?;
        let end = span.map(|(_, end)| end);
        Ok((end, accounting))
    }

    pub(crate) fn find_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, Accounting), SearchError> {
        let (span, accounting) = self.selected_window(haystack, window, limits, Operation::Span)?;
        let matched = span.map(|(start, end)| Match { start, end });
        Ok((matched, accounting))
    }

    pub(crate) fn find_window_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<Option<Match>, SearchError> {
        if limits == SearchLimits::unlimited() {
            validate_window(haystack, window)?;
            let window_width = window
                .end()
                .checked_sub(window.start())
                .expect("a validated window has ordered bounds");
            if u64::try_from(window_width).is_err() {
                return self
                    .selected_search(haystack, window, limits)
                    .map(|(span, _)| span.map(|(start, end)| Match { start, end }));
            }
            let owner = self.owner();
            let Some(start) = owner.member_seek.seek_unmetered(
                haystack,
                window.start(),
                window.end(),
                owner.classifier.as_ref(),
            ) else {
                return Ok(None);
            };
            let minimum_end = start
                .checked_add(1)
                .expect("a member position before the window end can advance once");
            if !owner.greedy {
                return Ok(Some(Match {
                    start,
                    end: minimum_end,
                }));
            }
            let end = owner
                .run_end_seek
                .seek_unmetered(
                    haystack,
                    minimum_end,
                    window.end(),
                    owner.classifier.as_ref(),
                )
                .unwrap_or(window.end());
            return Ok(Some(Match { start, end }));
        }
        self.selected_search(haystack, window, limits)
            .map(|(span, _)| span.map(|(start, end)| Match { start, end }))
    }

    #[inline(never)]
    fn selected_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
        operation: Operation,
    ) -> Result<(Option<(usize, usize)>, Accounting), SearchError> {
        let (span, meter) = self.selected_search(haystack, window, limits)?;
        let run_scans = usize::from(self.owner().greedy && span.is_some());
        let accounting = self.finish_accounting(
            operation,
            window,
            meter,
            1,
            run_scans,
            usize::from(span.is_some()),
        );
        Ok((span, accounting))
    }

    fn selected_search(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<(usize, usize)>, WorkMeter), SearchError> {
        validate_window(haystack, window)?;
        let owner = self.owner();
        let mut meter = WorkMeter::new(limits.max_work);
        let Some(start) = owner.member_seek.seek(
            haystack,
            window.start(),
            window.end(),
            &mut meter,
            owner.classifier.as_ref(),
        )?
        else {
            return Ok((None, meter));
        };
        let minimum_end = start
            .checked_add(1)
            .expect("a member position before the window end can advance once");
        if !owner.greedy {
            return Ok((Some((start, minimum_end)), meter));
        }
        let end = owner
            .run_end_seek
            .seek(
                haystack,
                minimum_end,
                window.end(),
                &mut meter,
                owner.classifier.as_ref(),
            )?
            .unwrap_or(window.end());
        Ok((Some((start, end)), meter))
    }

    #[inline(never)]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "validated slice lengths are at most isize::MAX and the only overlap is fifteen bytes"
    )]
    fn finish_accounting(
        &self,
        operation: Operation,
        window: SearchWindow,
        meter: WorkMeter,
        candidate_scans: usize,
        run_scans: usize,
        match_events: usize,
    ) -> Accounting {
        let input_bytes = window.end() - window.start();
        let overlap = if self.owner().greedy
            && matches!(operation, Operation::SelectedEnd | Operation::Span)
        {
            BYTE_SET_BLOCK_BYTES - 1
        } else {
            0
        };
        let work_upper_bound = u64::try_from(input_bytes).expect("one slice length fits u64")
            + u64::try_from(overlap).expect("one classifier overlap fits u64");
        debug_assert!(meter.consumed <= work_upper_bound);
        let source_reads =
            usize::try_from(meter.consumed).expect("slice-relative source reads fit usize");
        Accounting {
            plan_id: PLAN_ID,
            operation,
            input_bytes,
            source_reads,
            work_upper_bound,
            actual_work: meter.consumed,
            candidate_scans,
            run_scans,
            match_events,
        }
    }
}

impl Inspection {
    #[cold]
    pub(crate) fn build(self, dispatch: SimdDispatchContext) -> Result<Plan, CopyError> {
        Plan::build(
            self.greedy,
            self.member_seek,
            self.run_end_seek,
            self.classifier_words,
            dispatch,
        )
    }
}

#[derive(Clone, Copy)]
pub(super) struct WorkMeter {
    limit: u64,
    consumed: u64,
}

impl WorkMeter {
    pub(super) const fn new(limit: u64) -> Self {
        Self { limit, consumed: 0 }
    }

    pub(super) const fn consumed(self) -> u64 {
        self.consumed
    }

    fn remaining(self) -> u64 {
        self.limit.saturating_sub(self.consumed)
    }

    pub(super) fn charge(&mut self, requested: usize) -> Result<(), SearchError> {
        let requested_u64 =
            u64::try_from(requested).expect("one slice-relative work charge fits u64");
        let Some(needed) = self.consumed.checked_add(requested_u64) else {
            return Err(SearchError::WorkLimit {
                needed: u64::MAX,
                limit: self.limit,
            });
        };
        if needed > self.limit {
            return Err(SearchError::WorkLimit {
                needed,
                limit: self.limit,
            });
        }
        self.consumed = needed;
        Ok(())
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "admitted work is bounded by the remaining limit and one validated slice"
    )]
    fn charge_admitted(&mut self, admitted: usize) {
        let admitted_u64 =
            u64::try_from(admitted).expect("one admitted slice-relative charge fits u64");
        self.consumed += admitted_u64;
        debug_assert!(self.consumed <= self.limit);
    }
}

fn seek_small(
    leaf: SetSeek,
    haystack: &[u8],
    position: usize,
    end: usize,
    meter: &mut WorkMeter,
) -> Result<Option<usize>, SearchError> {
    let source = &haystack[position..end];
    if source.is_empty() {
        return Ok(None);
    }
    let admitted = source
        .len()
        .min(usize::try_from(meter.remaining()).unwrap_or(usize::MAX));
    let relative = match leaf {
        SetSeek::One(byte) => memchr(byte, &source[..admitted]),
        SetSeek::Two(first, second) => memchr2(first, second, &source[..admitted]),
        SetSeek::Three(first, second, third) => memchr3(first, second, third, &source[..admitted]),
        _ => unreachable!("only a one-to-three-byte leaf reaches the small scanner"),
    };
    let scanned = relative.map_or(admitted, |offset| offset + 1);
    meter.charge_admitted(scanned);
    if let Some(relative) = relative {
        return Ok(Some(position + relative));
    }
    if admitted == source.len() {
        return Ok(None);
    }
    Err(SearchError::WorkLimit {
        needed: meter.consumed.saturating_add(1),
        limit: meter.limit,
    })
}

fn seek_range(
    origin: u8,
    maximum_delta: u8,
    inverted: bool,
    haystack: &[u8],
    mut position: usize,
    end: usize,
    meter: &mut WorkMeter,
) -> Result<Option<usize>, SearchError> {
    if position == end {
        return Ok(None);
    }

    meter.charge(1)?;
    if (haystack[position].wrapping_sub(origin) <= maximum_delta) != inverted {
        return Ok(Some(position));
    }
    position += 1;

    while end.saturating_sub(position) >= BYTE_SET_BLOCK_BYTES {
        meter.charge(BYTE_SET_BLOCK_BYTES)?;
        let block_end = position + BYTE_SET_BLOCK_BYTES;
        let block: &[u8; BYTE_SET_BLOCK_BYTES] = haystack[position..block_end]
            .try_into()
            .expect("the range classifier checked its complete fixed extent");
        let classified = classify_byte_delta_16(origin, maximum_delta, block).member_mask();
        let members = if inverted { !classified } else { classified };
        if members != 0 {
            let offset = usize::try_from(members.trailing_zeros())
                .expect("a fixed-width range-classifier lane fits usize");
            return Ok(Some(position + offset));
        }
        position = block_end;
    }

    let source = &haystack[position..end];
    let admitted = source
        .len()
        .min(usize::try_from(meter.remaining()).unwrap_or(usize::MAX));
    let relative = source[..admitted]
        .iter()
        .position(|&byte| (byte.wrapping_sub(origin) <= maximum_delta) != inverted);
    let scanned = relative.map_or(admitted, |offset| {
        offset
            .checked_add(1)
            .expect("a hit in the admitted range tail advances once")
    });
    meter.charge_admitted(scanned);
    if let Some(relative) = relative {
        return Ok(Some(position + relative));
    }
    if admitted == source.len() {
        return Ok(None);
    }
    Err(SearchError::WorkLimit {
        needed: meter.consumed.saturating_add(1),
        limit: meter.limit,
    })
}

fn seek_classified(
    classifier: &ByteSetClassifier,
    inverted: bool,
    haystack: &[u8],
    mut position: usize,
    end: usize,
    meter: &mut WorkMeter,
) -> Result<Option<usize>, SearchError> {
    if position == end {
        return Ok(None);
    }

    // One pointwise proof keeps an immediate answer out of the fixed-width
    // classifier without introducing a data-derived length threshold.
    meter.charge(1)?;
    if classifier.set().contains(haystack[position]) != inverted {
        return Ok(Some(position));
    }
    position += 1;

    while end.saturating_sub(position) >= BYTE_SET_BLOCK_BYTES {
        meter.charge(BYTE_SET_BLOCK_BYTES)?;
        let block_end = position + BYTE_SET_BLOCK_BYTES;
        let block: &[u8; BYTE_SET_BLOCK_BYTES] = haystack[position..block_end]
            .try_into()
            .expect("the classifier checked its complete fixed extent");
        let classified = classifier.classify_16(block).member_mask();
        let members = if inverted { !classified } else { classified };
        if members != 0 {
            let offset = usize::try_from(members.trailing_zeros())
                .expect("a fixed-width classifier lane fits usize");
            return Ok(Some(position + offset));
        }
        position = block_end;
    }

    let source = &haystack[position..end];
    let admitted = source
        .len()
        .min(usize::try_from(meter.remaining()).unwrap_or(usize::MAX));
    let set = classifier.set();
    let relative = source[..admitted]
        .iter()
        .position(|&byte| set.contains(byte) != inverted);
    let scanned = relative.map_or(admitted, |offset| {
        offset
            .checked_add(1)
            .expect("a hit in the admitted classified tail advances once")
    });
    meter.charge_admitted(scanned);
    if let Some(relative) = relative {
        return Ok(Some(position + relative));
    }
    if admitted == source.len() {
        return Ok(None);
    }
    Err(SearchError::WorkLimit {
        needed: meter.consumed.saturating_add(1),
        limit: meter.limit,
    })
}

#[inline]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "validated slice bounds and the fixed block extent bound every addition"
)]
fn seek_range_unmetered(
    origin: u8,
    maximum_delta: u8,
    inverted: bool,
    haystack: &[u8],
    mut position: usize,
    end: usize,
) -> Option<usize> {
    if position == end {
        return None;
    }
    if (haystack[position].wrapping_sub(origin) <= maximum_delta) != inverted {
        return Some(position);
    }
    position += 1;

    while end.saturating_sub(position) >= BYTE_SET_BLOCK_BYTES {
        let block_end = position + BYTE_SET_BLOCK_BYTES;
        let block: &[u8; BYTE_SET_BLOCK_BYTES] = haystack[position..block_end]
            .try_into()
            .expect("the range classifier checked its complete fixed extent");
        let raw_mask = classify_byte_delta_16(origin, maximum_delta, block).member_mask();
        let matching_mask = if inverted { !raw_mask } else { raw_mask };
        if matching_mask != 0 {
            let offset = usize::try_from(matching_mask.trailing_zeros())
                .expect("a fixed-width range-classifier lane fits usize");
            return Some(position + offset);
        }
        position = block_end;
    }

    haystack[position..end]
        .iter()
        .position(|&byte| (byte.wrapping_sub(origin) <= maximum_delta) != inverted)
        .map(|relative| position + relative)
}

#[inline]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "validated slice bounds and the fixed block extent bound every addition"
)]
fn seek_classified_unmetered(
    classifier: &ByteSetClassifier,
    inverted: bool,
    haystack: &[u8],
    mut position: usize,
    end: usize,
) -> Option<usize> {
    if position == end {
        return None;
    }
    if classifier.set().contains(haystack[position]) != inverted {
        return Some(position);
    }
    position += 1;

    while end.saturating_sub(position) >= BYTE_SET_BLOCK_BYTES {
        let block_end = position + BYTE_SET_BLOCK_BYTES;
        let block: &[u8; BYTE_SET_BLOCK_BYTES] = haystack[position..block_end]
            .try_into()
            .expect("the classifier checked its complete fixed extent");
        let raw_mask = classifier.classify_16(block).member_mask();
        let matching_mask = if inverted { !raw_mask } else { raw_mask };
        if matching_mask != 0 {
            let offset = usize::try_from(matching_mask.trailing_zeros())
                .expect("a fixed-width classifier lane fits usize");
            return Some(position + offset);
        }
        position = block_end;
    }

    let set = classifier.set();
    haystack[position..end]
        .iter()
        .position(|&byte| set.contains(byte) != inverted)
        .map(|relative| position + relative)
}

pub(super) fn validate_window(haystack: &[u8], window: SearchWindow) -> Result<(), SearchError> {
    if window.start() > window.end() || window.end() > haystack.len() {
        return Err(SearchError::InvalidWindow);
    }
    Ok(())
}

#[cold]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "four 64-bit bitmap cardinalities sum to at most the fixed 256-byte domain"
)]
pub(crate) fn inspect(
    hir: &Hir,
    initial_work: u64,
    max_planner_work: u64,
) -> Result<InspectionOutcome, InspectionError> {
    let mut work = initial_work;
    let root = peel_captures(hir, &mut work, max_planner_work)?;
    let HirKind::Repetition(repetition) = root.kind() else {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    };
    if repetition.min != 1 || repetition.max.is_some() {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    }
    let body = peel_captures(&repetition.sub, &mut work, max_planner_work)?;
    let mut words = [0_u64; 4];
    match body.kind() {
        HirKind::Class(Class::Bytes(class)) => {
            for range in class.ranges() {
                charge_planner(&mut work, RANGE_INSPECTION_WORK, max_planner_work)?;
                for byte in range.start()..=range.end() {
                    charge_planner(&mut work, MEMBER_INSERTION_WORK, max_planner_work)?;
                    let bitmap_index = usize::from(byte >> 6);
                    let bit = u32::from(byte & 63);
                    words[bitmap_index] |= 1_u64 << bit;
                }
            }
        }
        HirKind::Literal(literal) if literal.0.len() == 1 => {
            charge_planner(&mut work, MEMBER_INSERTION_WORK, max_planner_work)?;
            let byte = literal.0[0];
            let bitmap_index = usize::from(byte >> 6);
            let bit = u32::from(byte & 63);
            words[bitmap_index] |= 1_u64 << bit;
        }
        _ => {
            return Ok(InspectionOutcome::Ineligible { planner_work: work });
        }
    }

    let complement = words.map(|word| !word);
    let member_cardinality = words.iter().map(|word| word.count_ones()).sum::<u32>();
    let run_end_cardinality = 256_u32 - member_cardinality;
    charge_leaf_selection(&mut work, max_planner_work)?;
    charge_leaf_selection(&mut work, max_planner_work)?;
    let member_seek = SetSeek::build(words, member_cardinality, false);
    let member_classified = member_seek.requires_classifier();
    let run_end_seek = SetSeek::build(complement, run_end_cardinality, member_classified);
    let run_end_classified = run_end_seek.requires_classifier();
    if member_classified || run_end_classified {
        charge_planner(
            &mut work,
            u64::try_from(BYTE_SET_CLASSIFIER_BUILD_WORK)
                .expect("the fixed classifier build charge fits u64"),
            max_planner_work,
        )?;
    }
    let classifier_words = if member_classified {
        Some(words)
    } else if run_end_classified {
        Some(complement)
    } else {
        None
    };
    Ok(InspectionOutcome::Eligible(Inspection {
        greedy: repetition.greedy,
        member_seek,
        run_end_seek,
        classifier_words,
        planner_work: work,
    }))
}

#[inline(never)]
#[cold]
fn peel_captures<'h>(
    mut hir: &'h Hir,
    work: &mut u64,
    max_planner_work: u64,
) -> Result<&'h Hir, InspectionError> {
    loop {
        charge_planner(work, NODE_INSPECTION_WORK, max_planner_work)?;
        let HirKind::Capture(capture) = hir.kind() else {
            return Ok(hir);
        };
        hir = &capture.sub;
    }
}

fn charge_leaf_selection(work: &mut u64, max_planner_work: u64) -> Result<(), InspectionError> {
    charge_planner(work, LEAF_SELECTION_WORK, max_planner_work)?;
    Ok(())
}

#[cold]
fn charge_planner(work: &mut u64, additional: u64, limit: u64) -> Result<(), InspectionError> {
    let needed = work
        .checked_add(additional)
        .ok_or(InspectionError::ArithmeticOverflow)?;
    if needed > limit {
        return Err(InspectionError::WorkLimit { needed, limit });
    }
    *work = needed;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Accounting, Error, InspectionOutcome, Operation, PLAN_ID, SetSeek, WorkMeter};
    use crate::{
        BuildError, BuildLimits, PlanKind, PlanSelection, PortableBuilder, PortableFindIterLimits,
        PortablePlan, PortableTextBuilder, SearchAccounting, SearchError as FacadeSearchError,
        SearchLimits, SearchSessionLimits, SearchWindow,
    };
    #[cfg(not(feature = "static-dispatch"))]
    use fre_kernels::DispatchPolicy;
    use fre_kernels::{ByteSet256, ByteSetClassifier};

    fn build(pattern: &str) -> crate::PortableRegex {
        PortableBuilder::new(pattern)
            .unicode(false)
            .build()
            .expect("the pure byte-class repeat should build")
    }

    fn accounting(accounting: SearchAccounting) -> Accounting {
        match accounting {
            SearchAccounting::PureByteClassRepeat(accounting) => accounting,
            other => panic!("expected pure byte-class accounting, got {other:?}"),
        }
    }

    fn span(matched: Option<crate::Match>) -> Option<(usize, usize)> {
        matched.map(|matched| (matched.start(), matched.end()))
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "test helpers only set bits in the fixed 256-byte domain"
    )]
    fn member_words(members: &[u8]) -> [u64; 4] {
        let mut words = [0_u64; 4];
        for &byte in members {
            let word = usize::from(byte >> 6);
            let bit = u32::from(byte & 63);
            words[word] |= 1_u64 << bit;
        }
        words
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "test helpers only set bits in one validated inclusive byte range"
    )]
    fn inclusive_words(start: u8, end: u8) -> [u64; 4] {
        let mut words = [0_u64; 4];
        for byte in start..=end {
            let word = usize::from(byte >> 6);
            let bit = u32::from(byte & 63);
            words[word] |= 1_u64 << bit;
        }
        words
    }

    #[test]
    fn shared_set_seek_selects_every_contiguous_shape_without_displacing_small_leaves() {
        for start in u16::from(u8::MIN)..=u16::from(u8::MAX) {
            for end in start..=u16::from(u8::MAX) {
                let start = u8::try_from(start).expect("the byte-domain start fits u8");
                let end = u8::try_from(end).expect("the byte-domain end fits u8");
                let cardinality = u32::from(end)
                    .checked_sub(u32::from(start))
                    .and_then(|delta| delta.checked_add(1))
                    .expect("one inclusive byte range has bounded cardinality");
                let words = inclusive_words(start, end);
                let member = SetSeek::build(words, cardinality, false);
                let expected = match cardinality {
                    1 => SetSeek::One(start),
                    2 => SetSeek::Two(start, start.checked_add(1).expect("two-byte range")),
                    3 => SetSeek::Three(
                        start,
                        start.checked_add(1).expect("three-byte range middle"),
                        start.checked_add(2).expect("three-byte range end"),
                    ),
                    256 => SetSeek::Constant(true),
                    _ => SetSeek::Range {
                        origin: start,
                        maximum_delta: end.wrapping_sub(start),
                        inverted: false,
                    },
                };
                assert_eq!(member, expected, "member range {start:#04x}..={end:#04x}");
                assert!(!member.requires_classifier());

                let complement = words.map(|word| !word);
                let complement_cardinality = 256_u32
                    .checked_sub(cardinality)
                    .expect("one byte-set complement has bounded cardinality");
                let run_end = SetSeek::build(
                    complement,
                    complement_cardinality,
                    member.requires_classifier(),
                );
                match complement_cardinality {
                    0 => assert_eq!(run_end, SetSeek::Constant(false)),
                    1 => assert!(matches!(run_end, SetSeek::One(_))),
                    2 => assert!(matches!(run_end, SetSeek::Two(_, _))),
                    3 => assert!(matches!(run_end, SetSeek::Three(_, _, _))),
                    _ => assert!(matches!(run_end, SetSeek::Range { .. })),
                }
                assert!(
                    !run_end.requires_classifier(),
                    "complement of {start:#04x}..={end:#04x}"
                );
            }
        }
    }

    #[test]
    fn shared_set_seek_retains_generic_fallback_for_holey_sets() {
        let pair = member_words(&[1, 3]);
        let member = SetSeek::build(pair, 2, false);
        assert_eq!(member, SetSeek::Two(1, 3));
        let run_end = SetSeek::build(pair.map(|word| !word), 254, false);
        assert_eq!(run_end, SetSeek::Classified { inverted: false });

        let holey = member_words(&[1, 3, 65, 130]);
        let member = SetSeek::build(holey, 4, false);
        assert_eq!(member, SetSeek::Classified { inverted: false });
        let run_end = SetSeek::build(holey.map(|word| !word), 252, true);
        assert_eq!(run_end, SetSeek::Classified { inverted: true });
    }

    #[test]
    fn range_and_complement_seeks_preserve_exact_fixed_block_work() {
        let words = inclusive_words(0x40, 0x7f);
        let member = SetSeek::build(words, 64, false);
        let run_end = SetSeek::build(words.map(|word| !word), 192, false);
        assert!(matches!(member, SetSeek::Range { inverted: false, .. }));
        assert!(matches!(run_end, SetSeek::Range { inverted: true, .. }));

        let mut member_haystack = [0_u8; 40];
        member_haystack[20] = 0x40;
        let mut run_end_haystack = [0x40_u8; 40];
        run_end_haystack[20] = 0;
        for (leaf, haystack) in [
            (member, &member_haystack[..]),
            (run_end, &run_end_haystack[..]),
        ] {
            let mut exact = WorkMeter::new(33);
            assert_eq!(
                leaf.seek(haystack, 0, haystack.len(), &mut exact, None),
                Ok(Some(20))
            );
            assert_eq!(exact.consumed(), 33);

            let mut one_below = WorkMeter::new(32);
            assert_eq!(
                leaf.seek(haystack, 0, haystack.len(), &mut one_below, None),
                Err(Error::WorkLimit {
                    needed: 33,
                    limit: 32,
                })
            );
            assert_eq!(one_below.consumed(), 17);

            let mut empty = WorkMeter::new(0);
            assert_eq!(leaf.seek(haystack, 0, 0, &mut empty, None), Ok(None));
            assert_eq!(empty.consumed(), 0);
        }

        let mut absent = WorkMeter::new(40);
        assert_eq!(
            member.seek(&[0_u8; 40], 0, 40, &mut absent, None),
            Ok(None)
        );
        assert_eq!(absent.consumed(), 40);
    }

    #[test]
    fn scalar_set_seek_tails_batch_accounting_without_changing_limits() {
        fn assert_contract(
            leaf: SetSeek,
            classifier: Option<&ByteSetClassifier>,
            haystack: &[u8],
            absent_byte: u8,
        ) {
            let mut exact = WorkMeter::new(13);
            assert_eq!(
                leaf.seek(haystack, 0, haystack.len(), &mut exact, classifier),
                Ok(Some(12))
            );
            assert_eq!(exact.consumed(), 13);

            let mut one_below = WorkMeter::new(12);
            assert_eq!(
                leaf.seek(haystack, 0, haystack.len(), &mut one_below, classifier),
                Err(Error::WorkLimit {
                    needed: 13,
                    limit: 12,
                })
            );
            assert_eq!(one_below.consumed(), 12);

            let mut absent_haystack = haystack.to_vec();
            absent_haystack[12] = absent_byte;
            let mut absent = WorkMeter::new(15);
            assert_eq!(
                leaf.seek(
                    &absent_haystack,
                    0,
                    absent_haystack.len(),
                    &mut absent,
                    classifier,
                ),
                Ok(None)
            );
            assert_eq!(absent.consumed(), 15);

            let mut absent_one_below = WorkMeter::new(14);
            assert_eq!(
                leaf.seek(
                    &absent_haystack,
                    0,
                    absent_haystack.len(),
                    &mut absent_one_below,
                    classifier,
                ),
                Err(Error::WorkLimit {
                    needed: 15,
                    limit: 14,
                })
            );
            assert_eq!(absent_one_below.consumed(), 14);
        }

        let range = SetSeek::build(inclusive_words(b'A', b'F'), 6, false);
        let mut range_haystack = [b'.'; 15];
        range_haystack[12] = b'C';
        assert_contract(range, None, &range_haystack, b'.');

        let inverted_range = SetSeek::build(
            inclusive_words(b'A', b'F').map(|word| !word),
            250,
            false,
        );
        let mut inverted_range_haystack = [b'A'; 15];
        inverted_range_haystack[12] = b'.';
        assert_contract(inverted_range, None, &inverted_range_haystack, b'A');

        let classified_words = member_words(&[b'A', b'C', b'E', b'G']);
        let classified = ByteSetClassifier::new(ByteSet256::from_words(classified_words));
        let classified_leaf = SetSeek::build(classified_words, 4, false);
        let mut classified_haystack = [b'.'; 15];
        classified_haystack[12] = b'E';
        assert_contract(
            classified_leaf,
            Some(&classified),
            &classified_haystack,
            b'.',
        );

        let inverted_classified_leaf =
            SetSeek::build(classified_words.map(|word| !word), 252, true);
        let mut inverted_classified_haystack = [b'A'; 15];
        inverted_classified_haystack[12] = b'.';
        assert_contract(
            inverted_classified_leaf,
            Some(&classified),
            &inverted_classified_haystack,
            b'A',
        );
    }

    #[test]
    fn range_plan_omits_generic_classifier_and_preserves_identity_receipts() {
        use regex_syntax::ParserBuilder;

        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse("(?-u:[A-Z])+")
            .expect("one byte range should parse");
        let initial_work = 11_u64;
        let outcome = super::inspect(&hir, initial_work, u64::MAX)
            .expect("one byte range should inspect");
        let InspectionOutcome::Eligible(inspection) = outcome else {
            panic!("one byte range should select the pure repeat plan");
        };
        assert_eq!(
            inspection.member_seek,
            SetSeek::Range {
                origin: b'A',
                maximum_delta: b'Z'.wrapping_sub(b'A'),
                inverted: false,
            }
        );
        assert_eq!(
            inspection.run_end_seek,
            SetSeek::Range {
                origin: b'A',
                maximum_delta: b'Z'.wrapping_sub(b'A'),
                inverted: true,
            }
        );
        assert!(inspection.classifier_words.is_none());
        let expected_work = [
            initial_work,
            super::NODE_INSPECTION_WORK,
            super::NODE_INSPECTION_WORK,
            super::RANGE_INSPECTION_WORK,
            26_u64
                .checked_mul(super::MEMBER_INSERTION_WORK)
                .expect("the fixed member work fits u64"),
            super::LEAF_SELECTION_WORK,
            super::LEAF_SELECTION_WORK,
        ]
        .into_iter()
        .try_fold(0_u64, |total, work| total.checked_add(work))
        .expect("the fixed inspection work fits u64");
        assert_eq!(inspection.planner_work, expected_work);

        let regex = build("(?-u:[A-Z])+");
        assert_eq!(regex.runtime_implementation_id(), PLAN_ID);
        let PortablePlan::PureByteClassRepeat(plan) = &regex.plan else {
            panic!("one byte range should retain the pure repeat plan");
        };
        assert!(plan.owner().classifier.is_none());
        let (matched, receipt) = regex
            .find_accounted(b"!!ABCDEFGHIJKLMNOPQRSTUVWXYZ!!", SearchLimits::unlimited())
            .expect("one range search should succeed");
        assert_eq!(span(matched), Some((2, 28)));
        let receipt = accounting(receipt);
        assert_eq!(receipt.plan_id, PLAN_ID);
        assert_eq!(receipt.operation, Operation::Span);
        assert_eq!(
            receipt.actual_work,
            u64::try_from(receipt.source_reads).expect("source reads fit u64")
        );
        assert!(receipt.actual_work <= receipt.work_upper_bound);

        let generic = build("(?-u:[A-Z_a-z])+");
        let PortablePlan::PureByteClassRepeat(plan) = &generic.plan else {
            panic!("one holey byte set should retain the pure repeat plan");
        };
        assert!(matches!(plan.owner().member_seek, SetSeek::Classified { inverted: false }));
        assert!(matches!(plan.owner().run_end_seek, SetSeek::Classified { inverted: true }));
        assert!(plan.owner().classifier.is_some());

        let generic_hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse("(?-u:[A-Z_a-z])+")
            .expect("one holey byte set should parse");
        let outcome = super::inspect(&generic_hir, initial_work, u64::MAX)
            .expect("one holey byte set should inspect");
        let InspectionOutcome::Eligible(inspection) = outcome else {
            panic!("one holey byte set should select the pure repeat plan");
        };
        assert!(inspection.classifier_words.is_some());
        let expected_generic_work = [
            initial_work,
            super::NODE_INSPECTION_WORK,
            super::NODE_INSPECTION_WORK,
            3_u64
                .checked_mul(super::RANGE_INSPECTION_WORK)
                .expect("the fixed range work fits u64"),
            53_u64
                .checked_mul(super::MEMBER_INSERTION_WORK)
                .expect("the fixed member work fits u64"),
            super::LEAF_SELECTION_WORK,
            super::LEAF_SELECTION_WORK,
            u64::try_from(super::BYTE_SET_CLASSIFIER_BUILD_WORK)
                .expect("the classifier build work fits u64"),
        ]
        .into_iter()
        .try_fold(0_u64, |total, work| total.checked_add(work))
        .expect("the fixed generic inspection work fits u64");
        assert_eq!(inspection.planner_work, expected_generic_work);

        let small_holey = build("(?-u:[ac])+");
        let PortablePlan::PureByteClassRepeat(plan) = &small_holey.plan else {
            panic!("one small holey set should retain the pure repeat plan");
        };
        assert_eq!(plan.owner().member_seek, SetSeek::Two(b'a', b'c'));
        assert_eq!(
            plan.owner().run_end_seek,
            SetSeek::Classified { inverted: false }
        );
        let classifier = plan
            .owner()
            .classifier
            .as_ref()
            .expect("a holey small-set complement needs the generic classifier");
        assert!(!classifier.set().contains(b'a'));
        assert!(classifier.set().contains(b'b'));
        assert!(!classifier.set().contains(b'c'));
        assert_eq!(
            span(
                small_holey
                    .find_accounted(b"!!acacacacacacacacacacb", SearchLimits::unlimited())
                    .expect("the complement-backed run-end seek should succeed")
                    .0
            ),
            Some((2, 22))
        );
    }

    #[test]
    fn facade_selects_only_the_bytes_root_plus_slice() {
        for pattern in [
            "a+",
            "a+?",
            "(?-u:[a-d])+",
            "(?-u:[a-d])+?",
            "(?-u:[^x])+",
            "(?-u:[^x])+?",
            "((?-u:[a-d]))+",
        ] {
            let regex = build(pattern);
            assert_eq!(regex.build_report().plan, PlanKind::PureByteClassRepeat);
            assert_eq!(regex.runtime_implementation_id(), PLAN_ID);
            assert!(regex.build_report().lowering.is_none());
            assert_eq!(regex.build_report().states, 0);
            assert_eq!(regex.build_report().edges, 0);
        }

        for pattern in ["(?-u:[a-d])*", "x(?-u:[a-d])+", "(?-u:[a-d])+(?-u:x)"] {
            let regex = build(pattern);
            assert_ne!(regex.build_report().plan, PlanKind::PureByteClassRepeat);
        }

        let bounded = build("(?-u:[a-d]){1,3}");
        assert_eq!(bounded.build_report().plan, PlanKind::PureByteClassRepeat);
        assert_ne!(bounded.runtime_implementation_id(), PLAN_ID);

        let forced = PortableBuilder::new("a+")
            .unicode(false)
            .plan_selection(PlanSelection::ForceK0)
            .build()
            .unwrap();
        assert_eq!(forced.build_report().plan, PlanKind::K0);

        let text = PortableTextBuilder::new("a+").build().unwrap();
        assert_ne!(
            text.build_report().portable.plan,
            PlanKind::PureByteClassRepeat
        );
    }

    #[test]
    fn polarity_greediness_full_set_and_invalid_windows_are_exact() {
        let positive = build("(?-u:[abc])+");
        let (matched, positive_accounting) =
            positive
                .find_accounted(b"zabcc!", SearchLimits::unlimited())
                .unwrap();
        assert_eq!(span(matched), Some((1, 5)));
        assert_eq!(accounting(positive_accounting).operation, Operation::Span);

        let negative = build("(?-u:[^x])+?");
        let (matched, negative_accounting) =
            negative
                .find_accounted(b"xab", SearchLimits::unlimited())
                .unwrap();
        assert_eq!(span(matched), Some((1, 2)));
        assert_eq!(accounting(negative_accounting).operation, Operation::Span);

        let all = build("(?s-u:.)+");
        let (matched, all_accounting) = all
            .find_accounted(b"\0\n\x80\xff", SearchLimits::unlimited())
            .unwrap();
        assert_eq!(span(matched), Some((0, 4)));
        let all_accounting = accounting(all_accounting);
        assert_eq!(all_accounting.actual_work, 0);
        assert_eq!(all_accounting.source_reads, 0);

        assert!(matches!(
            all.find_window(b"abc", SearchWindow::new(2, 1), SearchLimits::unlimited(),),
            Err(FacadeSearchError::PureByteClassRepeat(Error::InvalidWindow))
        ));
    }

    #[test]
    fn exhaustive_small_strings_and_all_windows_match_the_pinned_bytes_oracle() {
        let patterns = [
            "a+",
            "a+?",
            "(?-u:[a-d])+",
            "(?-u:[a-d])+?",
            "(?-u:[^a])+",
            "(?-u:[^a])+?",
            "(?-u:[\\x80-\\xff])+",
            "(?-u:[^\\x80-\\xff])+",
        ];
        let alphabet = [b'a', b'b', b'd', 0x80_u8];
        for pattern in patterns {
            let fre = build(pattern);
            let oracle = regex::bytes::RegexBuilder::new(pattern)
                .unicode(false)
                .build()
                .unwrap();
            for length in 0_u32..=5 {
                let cases = alphabet.len().pow(length);
                for encoded in 0..cases {
                    let mut value = encoded;
                    let mut haystack = vec![0_u8; usize::try_from(length).unwrap()];
                    for byte in &mut haystack {
                        *byte = alphabet[value % alphabet.len()];
                        value /= alphabet.len();
                    }
                    for start in 0..=haystack.len() {
                        for end in start..=haystack.len() {
                            let window = SearchWindow::new(start, end);
                            let source = &haystack[start..end];
                            let expected_find = oracle
                                .find(source)
                                .map(|matched| (start + matched.start(), start + matched.end()));
                            let expected_shortest =
                                oracle.shortest_match(source).map(|finish| start + finish);

                            let (exists, exists_accounting) = fre
                                .is_match_window(&haystack, window, SearchLimits::unlimited())
                                .unwrap();
                            assert_eq!(
                                exists,
                                expected_find.is_some(),
                                "exists: {pattern:?} {haystack:?} {start}..{end}"
                            );
                            let exists_accounting = accounting(exists_accounting);
                            assert_eq!(exists_accounting.operation, Operation::Exists);
                            assert_eq!(exists_accounting.plan_id, PLAN_ID);
                            assert_eq!(
                                exists_accounting.actual_work,
                                u64::try_from(exists_accounting.source_reads).unwrap()
                            );
                            assert!(
                                exists_accounting.actual_work <= exists_accounting.work_upper_bound
                            );

                            let (shortest, shortest_accounting) = fre
                                .shortest_match_window(&haystack, window, SearchLimits::unlimited())
                                .unwrap();
                            assert_eq!(
                                shortest, expected_shortest,
                                "shortest: {pattern:?} {haystack:?} {start}..{end}"
                            );
                            assert_eq!(
                                accounting(shortest_accounting).operation,
                                Operation::EarliestEnd
                            );

                            let (found, found_accounting) = fre
                                .find_window(&haystack, window, SearchLimits::unlimited())
                                .unwrap();
                            assert_eq!(
                                span(found),
                                expected_find,
                                "span: {pattern:?} {haystack:?} {start}..{end}"
                            );
                            let found_accounting = accounting(found_accounting);
                            assert_eq!(found_accounting.operation, Operation::Span);
                            assert_eq!(
                                found_accounting.actual_work,
                                u64::try_from(found_accounting.source_reads).unwrap()
                            );
                            assert!(
                                found_accounting.actual_work <= found_accounting.work_upper_bound
                            );
                        }
                    }

                    let expected_full = oracle
                        .find(&haystack)
                        .map(|matched| (matched.start(), matched.end()));
                    assert_eq!(
                        fre.is_match(&haystack),
                        expected_full.is_some(),
                        "ordinary exists: {pattern:?} {haystack:?}",
                    );
                    assert_eq!(
                        span(fre.find(&haystack)),
                        expected_full,
                        "ordinary span: {pattern:?} {haystack:?}",
                    );

                    let expected_end = expected_full.map(|(_, end)| end);
                    let (selected_end, selected_accounting) = fre
                        .selected_end(&haystack, SearchLimits::unlimited())
                        .unwrap();
                    assert_eq!(selected_end, expected_end);
                    assert_eq!(
                        accounting(selected_accounting).operation,
                        Operation::SelectedEnd
                    );

                    let expected_iter = oracle
                        .find_iter(&haystack)
                        .map(|matched| (matched.start(), matched.end()))
                        .collect::<Vec<_>>();
                    let actual_iter = fre
                        .find_iter(&haystack, PortableFindIterLimits::unlimited())
                        .unwrap()
                        .map(|matched| {
                            let matched = matched.unwrap();
                            (matched.start(), matched.end())
                        })
                        .collect::<Vec<_>>();
                    assert_eq!(
                        actual_iter, expected_iter,
                        "iterator: {pattern:?} {haystack:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn ordinary_full_scans_preserve_malformed_bytes_and_block_edges() {
        let patterns = [
            "(?s-u:.)+",
            "(?s-u:.)+?",
            "a+",
            "a+?",
            "(?-u:[ac])+",
            "(?-u:[ace])+",
            "(?-u:[a-f])+",
            "(?-u:[a-f])+?",
            "(?-u:[^a-f])+",
            "(?-u:[aceg])+",
            "(?-u:[aceg])+?",
            "(?-u:[^aceg])+",
            "(?-u:[\\x80-\\xff])+",
            "(?-u:[^\\x80-\\xff])+",
        ];
        let alphabet = [0xff_u8, b'a', b'a', b'c', b'e', b'g', b'g', 0x80, b'z', 0];
        for pattern in patterns {
            let fre = build(pattern);
            assert!(matches!(&fre.plan, PortablePlan::PureByteClassRepeat(_)));
            let oracle = regex::bytes::RegexBuilder::new(pattern)
                .unicode(false)
                .build()
                .unwrap();
            for length in [0_usize, 1, 15, 16, 17, 31, 32, 33, 47, 48, 49] {
                for phase in 0..alphabet.len() {
                    let haystack = (0..length)
                        .map(|index| alphabet[(index + phase) % alphabet.len()])
                        .collect::<Vec<_>>();
                    let expected = oracle
                        .find(&haystack)
                        .map(|matched| (matched.start(), matched.end()));
                    assert_eq!(
                        fre.is_match(&haystack),
                        expected.is_some(),
                        "exists pattern={pattern:?} length={length} phase={phase}",
                    );
                    assert_eq!(
                        span(fre.find(&haystack)),
                        expected,
                        "span pattern={pattern:?} length={length} phase={phase}",
                    );
                }
            }
        }
    }

    #[test]
    fn ordinary_full_admits_empty_byte_classes_for_both_preferences() {
        let haystacks = [
            &b""[..],
            &b"a"[..],
            &b"\0\x80\xff"[..],
            &b"aaaaaaaaaaaaaaaaa"[..],
            &b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"[..],
        ];
        for pattern in [r"(?-u:[^\x00-\xFF])+", r"(?-u:[^\x00-\xFF])+?"] {
            let fre = build(pattern);
            let PortablePlan::PureByteClassRepeat(plan) = &fre.plan else {
                panic!("the empty byte class should retain the pure repeat plan");
            };
            let owner = plan.owner();
            assert_eq!(owner.member_seek, SetSeek::Constant(false));
            assert_eq!(owner.run_end_seek, SetSeek::Constant(true));
            assert!(owner.classifier.is_none());

            let oracle = regex::bytes::RegexBuilder::new(pattern)
                .unicode(false)
                .build()
                .unwrap();
            super::reset_ordinary_full_call_counts();
            for haystack in haystacks {
                assert_eq!(fre.is_match(haystack), oracle.is_match(haystack));
                assert_eq!(span(fre.find(haystack)), None);
                assert!(oracle.find(haystack).is_none());
            }
            assert_eq!(
                super::ordinary_full_call_counts(),
                (haystacks.len(), haystacks.len()),
            );
        }
    }

    #[test]
    fn ordinary_full_long_runs_and_late_hits_cross_every_block_edge() {
        for pattern in ["(?-u:[aceg])+", "(?-u:[aceg])+?"] {
            let fre = build(pattern);
            assert!(matches!(&fre.plan, PortablePlan::PureByteClassRepeat(_)));
            let oracle = regex::bytes::RegexBuilder::new(pattern)
                .unicode(false)
                .build()
                .unwrap();
            let greedy = !pattern.ends_with('?');

            for boundary in [15_usize, 16, 17, 31, 32, 33] {
                let mut homogeneous = vec![b'a'; boundary];
                homogeneous.push(0xff);
                let expected_homogeneous = Some((0, if greedy { boundary } else { 1 }));
                assert_eq!(
                    oracle
                        .find(&homogeneous)
                        .map(|matched| (matched.start(), matched.end())),
                    expected_homogeneous,
                );
                assert!(fre.is_match(&homogeneous));
                assert_eq!(span(fre.find(&homogeneous)), expected_homogeneous);

                let mut late_hit = vec![0xff; boundary];
                late_hit.extend_from_slice(b"aa\xff");
                let late_end = boundary
                    .checked_add(if greedy { 2 } else { 1 })
                    .expect("the small boundary has room for the admitted run");
                let expected_late = Some((boundary, late_end));
                assert_eq!(
                    oracle
                        .find(&late_hit)
                        .map(|matched| (matched.start(), matched.end())),
                    expected_late,
                );
                assert!(fre.is_match(&late_hit));
                assert_eq!(span(fre.find(&late_hit)), expected_late);

                let full_miss = vec![0xff; boundary];
                assert!(!oracle.is_match(&full_miss));
                assert!(!fre.is_match(&full_miss));
                assert_eq!(fre.find(&full_miss), None);
            }
        }
    }

    #[test]
    #[cfg(not(feature = "static-dispatch"))]
    fn ordinary_full_retained_dispatch_matches_forced_scalar() {
        fn find_with_classifier(
            plan: &super::Plan,
            classifier: &ByteSetClassifier,
            haystack: &[u8],
        ) -> Option<crate::Match> {
            let owner = plan.owner();
            let start =
                owner
                    .member_seek
                    .seek_unmetered(haystack, 0, haystack.len(), Some(classifier))?;
            let minimum_end = start
                .checked_add(1)
                .expect("a selected byte before the slice end can advance once");
            if !owner.greedy {
                return Some(crate::Match {
                    start,
                    end: minimum_end,
                });
            }
            let end = owner
                .run_end_seek
                .seek_unmetered(haystack, minimum_end, haystack.len(), Some(classifier))
                .unwrap_or(haystack.len());
            Some(crate::Match { start, end })
        }

        let haystacks = [
            &b""[..],
            &b"!!!!!!!!acegg!!!!!!!!"[..],
            &b"\xff\x80\0aceg\xff"[..],
            &b"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!aacegg\xff"[..],
            &b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"[..],
        ];
        for pattern in ["(?-u:[aceg])+", "(?-u:[aceg])+?"] {
            let fre = build(pattern);
            let PortablePlan::PureByteClassRepeat(plan) = &fre.plan else {
                panic!("the holey byte class should retain the pure repeat plan");
            };
            let retained = plan
                .owner()
                .classifier
                .as_ref()
                .expect("the holey byte class retains its dispatched classifier");
            assert_eq!(retained.selection().policy, DispatchPolicy::Auto);
            let scalar = ByteSetClassifier::with_policy(retained.set(), DispatchPolicy::Portable)
                .expect("the portable scalar fallback is always available");
            assert_eq!(scalar.selection().policy, DispatchPolicy::Portable);
            assert_eq!(scalar.selection().variant_id, "byte-set.mask16.scalar.v1");

            let oracle = regex::bytes::RegexBuilder::new(pattern)
                .unicode(false)
                .build()
                .unwrap();
            for haystack in haystacks {
                let expected = oracle
                    .find(haystack)
                    .map(|matched| (matched.start(), matched.end()));
                let retained_find = plan.ordinary_find_full_unmetered(haystack);
                let scalar_find = find_with_classifier(plan, &scalar, haystack);
                let scalar_exists = plan
                    .owner()
                    .member_seek
                    .seek_unmetered(haystack, 0, haystack.len(), Some(&scalar))
                    .is_some();
                assert_eq!(span(retained_find), expected);
                assert_eq!(span(scalar_find), expected);
                assert_eq!(
                    plan.ordinary_is_match_full_unmetered(haystack),
                    expected.is_some(),
                );
                assert_eq!(scalar_exists, expected.is_some());
            }
        }
    }

    #[test]
    fn assertion_bearing_repeats_do_not_enter_the_ordinary_pure_route() {
        let cases = [
            (r"\A(?-u:[a-z])+", &b"abc!"[..]),
            (r"(?-u:[a-z])+\z", &b"!abc"[..]),
            (r"(?-u:\b[a-z]+\b)", &b"!abc!"[..]),
        ];
        super::reset_ordinary_full_call_counts();
        for (pattern, haystack) in cases {
            let fre = build(pattern);
            assert!(
                !matches!(&fre.plan, PortablePlan::PureByteClassRepeat(_)),
                "assertions must make the pure repeat inspector ineligible: {pattern:?}",
            );
            let oracle = regex::bytes::RegexBuilder::new(pattern)
                .unicode(false)
                .build()
                .unwrap();
            let expected = oracle
                .find(haystack)
                .map(|matched| (matched.start(), matched.end()));
            assert_eq!(fre.is_match(haystack), expected.is_some());
            assert_eq!(span(fre.find(haystack)), expected);
        }
        assert_eq!(
            super::ordinary_full_call_counts(),
            (0, 0),
            "assertion-bearing plans retain their own ordinary routes",
        );
    }

    #[test]
    fn ordinary_full_route_is_strictly_contained() {
        let regex = build("(?-u:[aceg])+");
        assert!(matches!(&regex.plan, PortablePlan::PureByteClassRepeat(_)));
        let haystack = b"!!acegg!!a!!";
        let full = SearchWindow::full(haystack);
        let unlimited = SearchLimits::unlimited();
        let expected = Some(crate::Match { start: 2, end: 7 });

        super::reset_ordinary_full_call_counts();
        assert!(regex.is_match_value(haystack, unlimited).unwrap());
        assert!(regex.is_match_accounted(haystack, unlimited).unwrap().0);
        assert!(
            regex
                .is_match_window_value(haystack, full, unlimited)
                .unwrap()
        );
        assert_eq!(regex.find_value(haystack, unlimited).unwrap(), expected);
        assert_eq!(
            regex.find_accounted(haystack, unlimited).unwrap().0,
            expected
        );
        assert_eq!(
            regex.find_at_value(haystack, 0, unlimited).unwrap(),
            expected
        );
        assert_eq!(regex.find_at(haystack, 0, unlimited).unwrap().0, expected);
        assert_eq!(
            regex.find_window_value(haystack, full, unlimited).unwrap(),
            expected,
        );
        assert_eq!(
            regex.find_window(haystack, full, unlimited).unwrap().0,
            expected
        );

        let refusing = SearchLimits {
            max_work: 0,
            max_scratch_bytes: 0,
        };
        assert!(regex.is_match_value(haystack, refusing).is_err());
        assert!(regex.find_value(haystack, refusing).is_err());

        let mut session = regex
            .search_session(SearchSessionLimits::unlimited())
            .unwrap();
        assert_eq!(session.find_value(haystack, unlimited).unwrap(), expected);
        assert!(
            session
                .is_match_window_value(haystack, full, unlimited)
                .unwrap()
        );
        let mut ordinary = regex.ordinary_session().unwrap();
        assert_eq!(ordinary.find_at(haystack, 0).unwrap(), expected);

        assert_eq!(
            regex
                .find_iter(haystack, PortableFindIterLimits::unlimited())
                .unwrap()
                .next()
                .transpose()
                .unwrap(),
            expected,
        );
        assert_eq!(
            regex
                .find_iter_value(haystack, PortableFindIterLimits::unlimited())
                .unwrap()
                .next()
                .transpose()
                .unwrap(),
            expected,
        );
        let mut locations = regex.capture_locations();
        assert_eq!(
            regex
                .captures_read_value(&mut locations, haystack, unlimited)
                .unwrap()
                .map(|matched| crate::Match {
                    start: matched.start(),
                    end: matched.end(),
                }),
            expected,
        );
        assert_eq!(
            super::ordinary_full_call_counts(),
            (0, 0),
            "finite, accounted, windowed, session, iterator, and capture APIs stay canonical",
        );

        assert!(regex.is_match(haystack));
        assert_eq!(super::ordinary_full_call_counts(), (1, 0));
        assert_eq!(regex.find(haystack), expected);
        assert_eq!(super::ordinary_full_call_counts(), (1, 1));

        let bounded = build("(?-u:[aceg]){2,5}");
        assert!(matches!(
            &bounded.plan,
            PortablePlan::BoundedByteClassRepeat(_)
        ));
        assert!(bounded.is_match(haystack));
        assert_eq!(bounded.find(haystack), expected);

        let forced = PortableBuilder::new("(?-u:[aceg])+")
            .unicode(false)
            .plan_selection(PlanSelection::ForceK0)
            .build()
            .unwrap();
        assert!(forced.is_match(haystack));
        assert_eq!(forced.find(haystack), expected);
        assert_eq!(
            super::ordinary_full_call_counts(),
            (1, 1),
            "bounded and forced-K0 ordinary calls retain their own routes",
        );
    }

    #[test]
    fn ordinary_full_explicit_capture_refusal_is_contained() {
        let haystack = b"!!acegg!!";
        let expected = Some(crate::Match { start: 2, end: 7 });
        let unlimited = SearchLimits::unlimited();
        let cases = [
            ("((?-u:[aceg])+)", 2_usize),
            ("((?-u:[aceg]))+", 2),
            ("(?P<run>(?P<byte>(?-u:[aceg]))+)", 3),
        ];

        for (pattern, captures_len) in cases {
            let regex = build(pattern);
            assert!(matches!(&regex.plan, PortablePlan::PureByteClassRepeat(_)));
            assert_eq!(regex.captures_len(), captures_len);

            super::reset_ordinary_full_call_counts();
            assert_eq!(regex.find_value(haystack, unlimited).unwrap(), expected);
            let mut locations = regex.capture_locations();
            let explicit_captures = captures_len
                .checked_sub(1)
                .expect("the whole-match capture is always present");
            assert!(matches!(
                regex.captures_read_value(&mut locations, haystack, unlimited),
                Err(crate::PortableCapturesReadError::ExplicitCapturesUnsupported { captures })
                    if captures == explicit_captures,
            ));
            assert!(matches!(
                regex.captures_read(&mut locations, haystack, unlimited),
                Err(crate::PortableCapturesReadError::ExplicitCapturesUnsupported { captures })
                    if captures == explicit_captures,
            ));
            for group in 0..captures_len {
                assert_eq!(locations.get(group), None);
            }
            assert_eq!(
                super::ordinary_full_call_counts(),
                (0, 0),
                "finite values and explicit-capture refusal stay canonical: {pattern:?}",
            );

            assert!(regex.is_match(haystack));
            assert_eq!(regex.find(haystack), expected);
            assert_eq!(super::ordinary_full_call_counts(), (1, 1));
        }
    }

    #[test]
    fn exact_search_and_construction_limits_close_at_the_measured_boundary() {
        let pattern = "(?-u:[a-d])+";
        let haystack = b"zzzzzzzzzzzzzzzzzzzzabcdabcd!";
        let regex = build(pattern);

        let operations = [
            Operation::Exists,
            Operation::EarliestEnd,
            Operation::SelectedEnd,
            Operation::Span,
        ];
        for operation in operations {
            let measured = match operation {
                Operation::Exists => accounting(
                    regex
                        .is_match_accounted(haystack, SearchLimits::unlimited())
                        .unwrap()
                        .1,
                ),
                Operation::EarliestEnd => accounting(
                    regex
                        .shortest_match(haystack, SearchLimits::unlimited())
                        .unwrap()
                        .1,
                ),
                Operation::SelectedEnd => accounting(
                    regex
                        .selected_end(haystack, SearchLimits::unlimited())
                        .unwrap()
                        .1,
                ),
                Operation::Span => {
                    accounting(
                        regex
                            .find_accounted(haystack, SearchLimits::unlimited())
                            .unwrap()
                            .1,
                    )
                }
            };
            assert_eq!(measured.operation, operation);
            assert!(measured.actual_work > 0);
            assert!(measured.actual_work <= measured.work_upper_bound);

            let exact = SearchLimits {
                max_work: measured.actual_work,
                max_scratch_bytes: 0,
            };
            let exact_accounting = match operation {
                Operation::Exists => {
                    accounting(regex.is_match_accounted(haystack, exact).unwrap().1)
                }
                Operation::EarliestEnd => {
                    accounting(regex.shortest_match(haystack, exact).unwrap().1)
                }
                Operation::SelectedEnd => {
                    accounting(regex.selected_end(haystack, exact).unwrap().1)
                }
                Operation::Span => accounting(regex.find_accounted(haystack, exact).unwrap().1),
            };
            assert_eq!(exact_accounting.actual_work, measured.actual_work);

            let one_below = SearchLimits {
                max_work: measured.actual_work - 1,
                max_scratch_bytes: 0,
            };
            let error = match operation {
                Operation::Exists => regex
                    .is_match_accounted(haystack, one_below)
                    .unwrap_err(),
                Operation::EarliestEnd => regex.shortest_match(haystack, one_below).unwrap_err(),
                Operation::SelectedEnd => regex.selected_end(haystack, one_below).unwrap_err(),
                Operation::Span => regex.find_accounted(haystack, one_below).unwrap_err(),
            };
            assert!(matches!(
                error,
                FacadeSearchError::PureByteClassRepeat(Error::WorkLimit {
                    limit,
                    ..
                }) if limit == measured.actual_work - 1
            ));
        }

        let small = build("a+");
        assert!(matches!(
            small.is_match_accounted(
                b"zzza",
                SearchLimits {
                    max_work: 2,
                    max_scratch_bytes: 0,
                },
            ),
            Err(FacadeSearchError::PureByteClassRepeat(Error::WorkLimit {
                needed: 3,
                limit: 2,
            }))
        ));

        let measured_build = regex.build_report().clone();
        let mut exact_limits = BuildLimits::default();
        exact_limits.max_planner_work = measured_build.planner_work;
        exact_limits.max_persistent_bytes = measured_build.charged_persistent_bytes;
        let exact = PortableBuilder::new(pattern)
            .unicode(false)
            .limits(exact_limits)
            .build()
            .unwrap();
        assert_eq!(
            exact.build_report().planner_work,
            measured_build.planner_work
        );
        assert_eq!(
            exact.build_report().charged_persistent_bytes,
            measured_build.charged_persistent_bytes
        );

        let mut planner_refusal = exact_limits;
        planner_refusal.max_planner_work = measured_build.planner_work - 1;
        assert!(matches!(
            PortableBuilder::new(pattern)
                .unicode(false)
                .limits(planner_refusal)
                .build(),
            Err(BuildError::PlannerWorkLimit { limit, .. })
                if limit == measured_build.planner_work - 1
        ));

        let mut persistent_refusal = exact_limits;
        persistent_refusal.max_persistent_bytes = measured_build.charged_persistent_bytes - 1;
        assert!(matches!(
            PortableBuilder::new(pattern)
                .unicode(false)
                .limits(persistent_refusal)
                .build(),
            Err(BuildError::PersistentBytesLimit { limit, .. })
                if limit == measured_build.charged_persistent_bytes - 1
        ));
    }

    #[test]
    fn native_session_and_iterator_retain_operation_specific_work() {
        let regex = build("(?-u:[^x])+");
        let haystack = b"xxabcxxdef";
        let mut session = regex
            .search_session(crate::SearchSessionLimits::unlimited())
            .unwrap();
        assert_eq!(session.runtime_implementation_id(), PLAN_ID);
        assert!(session.workspace_setup_accounting().is_none());

        let direct = regex
            .find_accounted(haystack, SearchLimits::unlimited())
            .unwrap();
        let reused = session.find(haystack, SearchLimits::unlimited()).unwrap();
        assert_eq!(direct.0, reused.0);
        assert_eq!(
            accounting(direct.1).actual_work,
            accounting(reused.1).actual_work
        );

        let matches = regex
            .find_iter(haystack, PortableFindIterLimits::unlimited())
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            matches
                .iter()
                .map(|matched| (matched.start(), matched.end()))
                .collect::<Vec<_>>(),
            vec![(2, 5), (7, 10)]
        );
    }
}
