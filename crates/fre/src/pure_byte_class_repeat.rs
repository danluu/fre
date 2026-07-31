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
    DispatchPolicy, SelectionReceipt, SimdDispatchContext,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SeekLeafIdentity {
    Empty,
    All,
    One,
    Two,
    Three,
    Classified {
        inverted: bool,
        selection: SelectionReceipt,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlanIdentity {
    pub plan_id: &'static str,
    pub class_words: [u64; 4],
    pub greedy: bool,
    pub member_seek: SeekLeafIdentity,
    pub run_end_seek: SeekLeafIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationIdentity {
    pub plan: PlanIdentity,
    pub operation: Operation,
}

/// Exact successful-search effects for one operation-specialized invocation.
///
/// `source_reads` and `actual_work` count the same admitted abstract byte
/// classifications. Fixed-width leaves charge a complete block before its
/// first source read. A greedy selected operation may classify the suffix of
/// the member-seek block again while locating the run end, so its independent
/// upper bound includes at most one less than a classifier block of overlap.
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

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    InvalidWindow {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
    WorkLimitExceeded {
        limit: u64,
        consumed: u64,
        requested: u64,
        position: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    InternalInvariant {
        detail: &'static str,
    },
}

impl core::fmt::Display for Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidWindow {
                start,
                end,
                haystack_len,
            } => write!(
                formatter,
                "pure byte-class repeat window {start}..{end} exceeds haystack length {haystack_len}"
            ),
            Self::WorkLimitExceeded {
                limit,
                consumed,
                requested,
                position,
            } => write!(
                formatter,
                "pure byte-class repeat work limit {limit} refused {requested} units after {consumed} at byte {position}"
            ),
            Self::ArithmeticOverflow { computation } => {
                write!(
                    formatter,
                    "pure byte-class repeat arithmetic overflow: {computation}"
                )
            }
            Self::InternalInvariant { detail } => {
                write!(
                    formatter,
                    "pure byte-class repeat internal invariant: {detail}"
                )
            }
        }
    }
}

impl std::error::Error for Error {}

type SearchError = Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InspectionError {
    WorkLimit { needed: u64, limit: u64 },
    ArithmeticOverflow(&'static str),
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Inspection {
    words: [u64; 4],
    greedy: bool,
    planner_work: u64,
    storage_bytes: usize,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum InspectionOutcome {
    Eligible(Inspection),
    Ineligible { planner_work: u64 },
}

impl InspectionOutcome {
    pub(crate) const fn planner_work(self) -> u64 {
        match self {
            Self::Eligible(inspection) => inspection.planner_work,
            Self::Ineligible { planner_work } => planner_work,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum SetSeek {
    Empty,
    All,
    One(u8),
    Two(u8, u8),
    Three(u8, u8, u8),
    Classified { inverted: bool },
}

impl SetSeek {
    fn build(words: [u64; 4], classifier_words: Option<[u64; 4]>) -> Self {
        let cardinality = words.iter().map(|word| word.count_ones()).sum::<u32>();
        match cardinality {
            0 => Self::Empty,
            256 => Self::All,
            1..=3 => {
                let mut members = [0_u8; 3];
                let mut length = 0_usize;
                for (word_index, mut word) in words.into_iter().enumerate() {
                    while word != 0 {
                        let bit = word.trailing_zeros();
                        let byte = word_index
                            .checked_mul(64)
                            .and_then(|base| base.checked_add(usize::try_from(bit).ok()?))
                            .and_then(|value| u8::try_from(value).ok())
                            .expect("a byte-set member fits u8");
                        members[length] = byte;
                        length = length
                            .checked_add(1)
                            .expect("a small byte-set cardinality fits usize");
                        word &= word
                            .checked_sub(1)
                            .expect("member extraction starts from a nonzero word");
                    }
                }
                match members[..length] {
                    [byte] => Self::One(byte),
                    [first, second] => Self::Two(first, second),
                    [first, second, third] => Self::Three(first, second, third),
                    _ => unreachable!("one-to-three members have a matching small leaf"),
                }
            }
            _ => Self::Classified {
                inverted: classifier_words
                    .map(|classifier_words| classifier_words != words)
                    .expect("a broad leaf retains the shared classifier set"),
            },
        }
    }

    fn identity(self, classifier: Option<&ByteSetClassifier>) -> SeekLeafIdentity {
        match self {
            Self::Empty => SeekLeafIdentity::Empty,
            Self::All => SeekLeafIdentity::All,
            Self::One(_) => SeekLeafIdentity::One,
            Self::Two(_, _) => SeekLeafIdentity::Two,
            Self::Three(_, _, _) => SeekLeafIdentity::Three,
            Self::Classified { inverted } => SeekLeafIdentity::Classified {
                inverted,
                selection: classifier
                    .expect("a classified leaf retains the shared classifier")
                    .selection(),
            },
        }
    }

    fn seek(
        self,
        haystack: &[u8],
        position: usize,
        end: usize,
        meter: &mut WorkMeter,
        classifier: Option<&ByteSetClassifier>,
    ) -> Result<Option<usize>, SearchError> {
        match self {
            Self::Empty => Ok(None),
            Self::All => Ok((position < end).then_some(position)),
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

#[derive(Debug)]
struct Owner {
    words: [u64; 4],
    greedy: bool,
    member_seek: SetSeek,
    run_end_seek: SetSeek,
    classifier: Option<ByteSetClassifier>,
}

#[derive(Debug)]
pub(crate) struct Plan {
    owner: ExactBoxOrUsize<Owner>,
}

impl Plan {
    fn build(
        words: [u64; 4],
        greedy: bool,
        dispatch: SimdDispatchContext,
    ) -> Result<Self, CopyError> {
        let complement = words.map(|word| !word);
        let member_cardinality = words.iter().map(|word| word.count_ones()).sum::<u32>();
        let run_end_cardinality = 256_u32
            .checked_sub(member_cardinality)
            .expect("a byte-set cardinality cannot exceed 256");
        let classifier_words = if matches!(member_cardinality, 4..=255) {
            Some(words)
        } else if matches!(run_end_cardinality, 4..=255) {
            Some(complement)
        } else {
            None
        };
        let classifier = classifier_words.map(|classifier_words| {
            dispatch
                .byte_set_classifier(
                    ByteSet256::from_words(classifier_words),
                    DispatchPolicy::Auto,
                )
                .expect("automatic byte-set dispatch retains a scalar fallback")
        });
        ExactBoxOrUsize::try_from_boxed(Owner {
            words,
            greedy,
            member_seek: SetSeek::build(words, classifier_words),
            run_end_seek: SetSeek::build(complement, classifier_words),
            classifier,
        })
        .map(|owner| Self { owner })
    }

    fn owner(&self) -> &Owner {
        self.owner
            .boxed()
            .expect("the pure byte-class repeat retains its exact owner")
    }

    #[allow(
        clippy::unused_self,
        reason = "the facade obtains runtime identity from the retained plan variant"
    )]
    pub(crate) const fn plan_id(&self) -> &'static str {
        PLAN_ID
    }

    pub(crate) const fn storage_bytes() -> usize {
        core::mem::size_of::<Self>()
            .checked_add(core::mem::size_of::<Owner>())
            .expect("the fixed pure byte-class repeat layouts fit usize")
    }

    pub(crate) fn identity(&self) -> PlanIdentity {
        let owner = self.owner();
        PlanIdentity {
            plan_id: PLAN_ID,
            class_words: owner.words,
            greedy: owner.greedy,
            member_seek: owner.member_seek.identity(owner.classifier.as_ref()),
            run_end_seek: owner.run_end_seek.identity(owner.classifier.as_ref()),
        }
    }

    pub(crate) fn operation_identity(&self, operation: Operation) -> OperationIdentity {
        OperationIdentity {
            plan: self.identity(),
            operation,
        }
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
            self.finish_accounting(Operation::Exists, window, meter, 1, 0, usize::from(matched))?;
        Ok((matched, accounting))
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
        )?;
        Ok((end, accounting))
    }

    pub(crate) fn selected_end_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, Accounting), SearchError> {
        let SelectedSearch {
            span,
            meter,
            candidate_scans,
            run_scans,
        } = self.selected_search(haystack, window, limits)?;
        let end = span.map(|(_, end)| end);
        let accounting = self.finish_accounting(
            Operation::SelectedEnd,
            window,
            meter,
            candidate_scans,
            run_scans,
            usize::from(end.is_some()),
        )?;
        Ok((end, accounting))
    }

    pub(crate) fn find_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, Accounting), SearchError> {
        let SelectedSearch {
            span,
            meter,
            candidate_scans,
            run_scans,
        } = self.selected_search(haystack, window, limits)?;
        let matched = span.map(|(start, end)| Match { start, end });
        let accounting = self.finish_accounting(
            Operation::Span,
            window,
            meter,
            candidate_scans,
            run_scans,
            usize::from(matched.is_some()),
        )?;
        Ok((matched, accounting))
    }

    fn selected_search(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<SelectedSearch, SearchError> {
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
            return Ok(SelectedSearch {
                span: None,
                meter,
                candidate_scans: 1,
                run_scans: 0,
            });
        };
        let minimum_end = start
            .checked_add(1)
            .expect("a member position before the window end can advance once");
        if !owner.greedy {
            return Ok(SelectedSearch {
                span: Some((start, minimum_end)),
                meter,
                candidate_scans: 1,
                run_scans: 0,
            });
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
        Ok(SelectedSearch {
            span: Some((start, end)),
            meter,
            candidate_scans: 1,
            run_scans: 1,
        })
    }

    #[inline(never)]
    fn finish_accounting(
        &self,
        operation: Operation,
        window: SearchWindow,
        meter: WorkMeter,
        candidate_scans: usize,
        run_scans: usize,
        match_events: usize,
    ) -> Result<Accounting, SearchError> {
        let input_bytes =
            window
                .end()
                .checked_sub(window.start())
                .ok_or(SearchError::InternalInvariant {
                    detail: "validated pure byte-class repeat window was reversed",
                })?;
        let overlap = usize::from(
            self.owner().greedy && matches!(operation, Operation::SelectedEnd | Operation::Span),
        )
        .checked_mul(BYTE_SET_BLOCK_BYTES - 1)
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "pure byte-class repeat fixed-width overlap",
        })?;
        let work_upper_bound = input_bytes
            .checked_add(overlap)
            .and_then(|work| u64::try_from(work).ok())
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "pure byte-class repeat work upper bound",
            })?;
        debug_assert!(meter.consumed <= work_upper_bound);
        let source_reads =
            usize::try_from(meter.consumed).map_err(|_| SearchError::ArithmeticOverflow {
                computation: "pure byte-class repeat source reads",
            })?;
        Ok(Accounting {
            plan_id: PLAN_ID,
            operation,
            input_bytes,
            source_reads,
            work_upper_bound,
            actual_work: meter.consumed,
            candidate_scans,
            run_scans,
            match_events,
        })
    }
}

impl Inspection {
    pub(crate) const fn storage_bytes(self) -> usize {
        self.storage_bytes
    }

    pub(crate) fn build(self, dispatch: SimdDispatchContext) -> Result<Plan, CopyError> {
        Plan::build(self.words, self.greedy, dispatch)
    }
}

#[derive(Clone, Copy, Debug)]
struct SelectedSearch {
    span: Option<(usize, usize)>,
    meter: WorkMeter,
    candidate_scans: usize,
    run_scans: usize,
}

#[derive(Clone, Copy, Debug)]
struct WorkMeter {
    limit: u64,
    consumed: u64,
}

impl WorkMeter {
    const fn new(limit: u64) -> Self {
        Self { limit, consumed: 0 }
    }

    fn remaining(self) -> u64 {
        self.limit.saturating_sub(self.consumed)
    }

    fn charge(&mut self, requested: usize, position: usize) -> Result<(), SearchError> {
        let requested_u64 =
            u64::try_from(requested).map_err(|_| SearchError::ArithmeticOverflow {
                computation: "pure byte-class repeat work charge",
            })?;
        let needed =
            self.consumed
                .checked_add(requested_u64)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "pure byte-class repeat accumulated work",
                })?;
        if needed > self.limit {
            return Err(SearchError::WorkLimitExceeded {
                limit: self.limit,
                consumed: self.consumed,
                requested: requested_u64,
                position,
            });
        }
        self.consumed = needed;
        Ok(())
    }

    fn charge_admitted(&mut self, admitted: usize) -> Result<(), SearchError> {
        let admitted_u64 =
            u64::try_from(admitted).map_err(|_| SearchError::ArithmeticOverflow {
                computation: "pure byte-class repeat admitted work",
            })?;
        self.consumed =
            self.consumed
                .checked_add(admitted_u64)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "pure byte-class repeat admitted accumulated work",
                })?;
        debug_assert!(self.consumed <= self.limit);
        Ok(())
    }
}

fn seek_small(
    leaf: SetSeek,
    haystack: &[u8],
    position: usize,
    end: usize,
    meter: &mut WorkMeter,
) -> Result<Option<usize>, SearchError> {
    let source = haystack
        .get(position..end)
        .ok_or(SearchError::InternalInvariant {
            detail: "pure byte-class small scanner exceeded its validated window",
        })?;
    if source.is_empty() {
        return Ok(None);
    }
    let admitted = source
        .len()
        .min(usize::try_from(meter.remaining()).unwrap_or(usize::MAX));
    if admitted == 0 {
        meter.charge(1, position)?;
        unreachable!("a zero-work small scan must be refused");
    }
    let relative = match leaf {
        SetSeek::One(byte) => memchr(byte, &source[..admitted]),
        SetSeek::Two(first, second) => memchr2(first, second, &source[..admitted]),
        SetSeek::Three(first, second, third) => memchr3(first, second, third, &source[..admitted]),
        _ => {
            return Err(SearchError::InternalInvariant {
                detail: "non-small leaf reached the pure byte-class small scanner",
            });
        }
    };
    let scanned = relative.map_or(admitted, |offset| {
        offset
            .checked_add(1)
            .expect("a matched offset inside an admitted slice can advance once")
    });
    meter.charge_admitted(scanned)?;
    if let Some(relative) = relative {
        return position
            .checked_add(relative)
            .map(Some)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "pure byte-class small scanner candidate",
            });
    }
    if admitted == source.len() {
        return Ok(None);
    }
    let refused_position =
        position
            .checked_add(admitted)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "pure byte-class small scanner refusal position",
            })?;
    meter.charge(1, refused_position)?;
    unreachable!("an exhausted admitted small scan must be refused");
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
    meter.charge(1, position)?;
    if classifier.set().contains(haystack[position]) != inverted {
        return Ok(Some(position));
    }
    position = position
        .checked_add(1)
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "pure byte-class scalar proof advance",
        })?;

    while end.saturating_sub(position) >= BYTE_SET_BLOCK_BYTES {
        meter.charge(BYTE_SET_BLOCK_BYTES, position)?;
        let block_end =
            position
                .checked_add(BYTE_SET_BLOCK_BYTES)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "pure byte-class classifier block end",
                })?;
        let block: &[u8; BYTE_SET_BLOCK_BYTES] = haystack
            .get(position..block_end)
            .ok_or(SearchError::InternalInvariant {
                detail: "pure byte-class classifier exceeded its validated window",
            })?
            .try_into()
            .expect("the classifier checked its complete fixed extent");
        let classified = classifier.classify_16(block).member_mask();
        let members = if inverted { !classified } else { classified };
        if members != 0 {
            let offset = usize::try_from(members.trailing_zeros())
                .expect("a fixed-width classifier lane fits usize");
            return position
                .checked_add(offset)
                .map(Some)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "pure byte-class classified candidate",
                });
        }
        position = block_end;
    }

    while position < end {
        meter.charge(1, position)?;
        if classifier.set().contains(haystack[position]) != inverted {
            return Ok(Some(position));
        }
        position = position
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "pure byte-class scalar tail advance",
            })?;
    }
    Ok(None)
}

fn validate_window(haystack: &[u8], window: SearchWindow) -> Result<(), SearchError> {
    if window.start() > window.end() || window.end() > haystack.len() {
        return Err(SearchError::InvalidWindow {
            start: window.start(),
            end: window.end(),
            haystack_len: haystack.len(),
        });
    }
    Ok(())
}

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

    let member_classified = charge_leaf_selection(&mut work, words, max_planner_work)?;
    let run_end_classified =
        charge_leaf_selection(&mut work, words.map(|word| !word), max_planner_work)?;
    if member_classified || run_end_classified {
        charge_planner(
            &mut work,
            u64::try_from(BYTE_SET_CLASSIFIER_BUILD_WORK).map_err(|_| {
                InspectionError::ArithmeticOverflow("byte-set classifier build work")
            })?,
            max_planner_work,
        )?;
    }
    let storage_bytes = Plan::storage_bytes();
    Ok(InspectionOutcome::Eligible(Inspection {
        words,
        greedy: repetition.greedy,
        planner_work: work,
        storage_bytes,
    }))
}

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

fn charge_leaf_selection(
    work: &mut u64,
    words: [u64; 4],
    max_planner_work: u64,
) -> Result<bool, InspectionError> {
    charge_planner(work, LEAF_SELECTION_WORK, max_planner_work)?;
    let cardinality = words.iter().map(|word| word.count_ones()).sum::<u32>();
    Ok(matches!(cardinality, 4..=255))
}

fn charge_planner(work: &mut u64, additional: u64, limit: u64) -> Result<(), InspectionError> {
    let needed = work
        .checked_add(additional)
        .ok_or(InspectionError::ArithmeticOverflow(
            "pure byte-class repeat planner work",
        ))?;
    if needed > limit {
        return Err(InspectionError::WorkLimit { needed, limit });
    }
    *work = needed;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Accounting, Error, Operation, PLAN_ID, SeekLeafIdentity};
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
            assert!(regex.pure_byte_class_repeat_identity().is_some());
        }

        for pattern in [
            "(?-u:[a-d])*",
            "(?-u:[a-d]){1,3}",
            "x(?-u:[a-d])+",
            "(?-u:[a-d])+(?-u:x)",
        ] {
            let regex = build(pattern);
            assert_ne!(regex.build_report().plan, PlanKind::PureByteClassRepeat);
            assert!(regex.pure_byte_class_repeat_identity().is_none());
        }

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
    fn identities_bind_class_polarity_greediness_and_operation() {
        let positive = build("(?-u:[abc])+");
        let positive_identity = positive.pure_byte_class_repeat_identity().unwrap();
        assert_eq!(positive_identity.plan_id, PLAN_ID);
        assert!(positive_identity.greedy);
        assert_eq!(positive_identity.member_seek, SeekLeafIdentity::Three);
        assert!(matches!(
            positive_identity.run_end_seek,
            SeekLeafIdentity::Classified { .. }
        ));

        let negative = build("(?-u:[^x])+?");
        let negative_identity = negative.pure_byte_class_repeat_identity().unwrap();
        assert!(!negative_identity.greedy);
        assert!(matches!(
            negative_identity.member_seek,
            SeekLeafIdentity::Classified { .. }
        ));
        assert_eq!(negative_identity.run_end_seek, SeekLeafIdentity::One);
        assert_ne!(positive_identity.class_words, negative_identity.class_words);

        let operation = negative
            .pure_byte_class_repeat_operation_identity(Operation::EarliestEnd)
            .unwrap();
        assert_eq!(operation.plan, negative_identity);
        assert_eq!(operation.operation, Operation::EarliestEnd);

        let all = build("(?s-u:.)+");
        let all_identity = all.pure_byte_class_repeat_identity().unwrap();
        assert_eq!(all_identity.member_seek, SeekLeafIdentity::All);
        assert_eq!(all_identity.run_end_seek, SeekLeafIdentity::Empty);
        let (matched, all_accounting) = all
            .find(b"\0\n\x80\xff", SearchLimits::unlimited())
            .unwrap();
        assert_eq!(span(matched), Some((0, 4)));
        let all_accounting = accounting(all_accounting);
        assert_eq!(all_accounting.actual_work, 0);
        assert_eq!(all_accounting.source_reads, 0);

        assert!(matches!(
            all.find_window(b"abc", SearchWindow::new(2, 1), SearchLimits::unlimited(),),
            Err(FacadeSearchError::PureByteClassRepeat(
                Error::InvalidWindow {
                    start: 2,
                    end: 1,
                    haystack_len: 3,
                }
            ))
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
                FacadeSearchError::PureByteClassRepeat(Error::WorkLimitExceeded {
                    limit,
                    ..
                }) if limit == measured.actual_work - 1
            ));
        }

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
