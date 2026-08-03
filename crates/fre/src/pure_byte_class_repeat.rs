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
    DispatchPolicy, SimdDispatchContext,
};
use memchr::{memchr, memchr2, memchr3};
use regex_syntax::hir::{Class, Hir, HirKind};

use crate::{Match, SearchLimits, SearchWindow};

pub const PLAN_ID: &str = "pure-byte-class-repeat-plus-v1";

const NODE_INSPECTION_WORK: u64 = 1;
const RANGE_INSPECTION_WORK: u64 = 1;
const MEMBER_INSERTION_WORK: u64 = 1;
const LEAF_SELECTION_WORK: u64 = 1;

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

#[derive(Clone, Copy)]
pub(super) enum SetSeek {
    Constant(bool),
    One(u8),
    Two(u8, u8),
    Three(u8, u8, u8),
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
            _ => Self::Classified {
                inverted: classified_inverted,
            },
        }
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

    while position < end {
        meter.charge(1)?;
        if classifier.set().contains(haystack[position]) != inverted {
            return Ok(Some(position));
        }
        position += 1;
    }
    Ok(None)
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
    let member_classified = matches!(member_cardinality, 4..=255);
    let run_end_classified = matches!(run_end_cardinality, 4..=255);
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
        member_seek: SetSeek::build(words, member_cardinality, false),
        run_end_seek: SetSeek::build(complement, run_end_cardinality, member_classified),
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
    use super::{Accounting, Error, Operation, PLAN_ID};
    use crate::{
        BuildError, BuildLimits, PlanKind, PlanSelection, PortableBuilder, PortableFindIterLimits,
        PortableTextBuilder, SearchAccounting, SearchError as FacadeSearchError, SearchLimits,
        SearchWindow,
    };

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
            positive.find(b"zabcc!", SearchLimits::unlimited()).unwrap();
        assert_eq!(span(matched), Some((1, 5)));
        assert_eq!(accounting(positive_accounting).operation, Operation::Span);

        let negative = build("(?-u:[^x])+?");
        let (matched, negative_accounting) =
            negative.find(b"xab", SearchLimits::unlimited()).unwrap();
        assert_eq!(span(matched), Some((1, 2)));
        assert_eq!(accounting(negative_accounting).operation, Operation::Span);

        let all = build("(?s-u:.)+");
        let (matched, all_accounting) = all
            .find(b"\0\n\x80\xff", SearchLimits::unlimited())
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

                    let expected_end = oracle.find(&haystack).map(|matched| matched.end());
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
                        .is_match(haystack, SearchLimits::unlimited())
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
                    accounting(regex.find(haystack, SearchLimits::unlimited()).unwrap().1)
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
                Operation::Exists => accounting(regex.is_match(haystack, exact).unwrap().1),
                Operation::EarliestEnd => {
                    accounting(regex.shortest_match(haystack, exact).unwrap().1)
                }
                Operation::SelectedEnd => {
                    accounting(regex.selected_end(haystack, exact).unwrap().1)
                }
                Operation::Span => accounting(regex.find(haystack, exact).unwrap().1),
            };
            assert_eq!(exact_accounting.actual_work, measured.actual_work);

            let one_below = SearchLimits {
                max_work: measured.actual_work - 1,
                max_scratch_bytes: 0,
            };
            let error = match operation {
                Operation::Exists => regex.is_match(haystack, one_below).unwrap_err(),
                Operation::EarliestEnd => regex.shortest_match(haystack, one_below).unwrap_err(),
                Operation::SelectedEnd => regex.selected_end(haystack, one_below).unwrap_err(),
                Operation::Span => regex.find(haystack, one_below).unwrap_err(),
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
            small.is_match(
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

        let direct = regex.find(haystack, SearchLimits::unlimited()).unwrap();
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
