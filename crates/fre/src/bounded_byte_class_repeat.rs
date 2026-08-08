//! Direct search for one positive finite bounded root byte-class repetition.
//!
//! This owner is deliberately separate from the established `CLASS+` owner.
//! It finds the first class run whose length reaches `minimum`, and only a
//! greedy selected-span operation scans onward to the finite `maximum`.

use fre_exact_alloc::{CopyError, ExactBoxOrUsize};
use fre_kernels::{
    BYTE_SET_BLOCK_BYTES, BYTE_SET_CLASSIFIER_BUILD_WORK, ByteSet256, ByteSetClassifier,
    DispatchPolicy, SimdDispatchContext,
};
use regex_syntax::hir::{Class, Hir, HirKind};

use crate::pure_byte_class_repeat::{
    Accounting, Error, Operation, SetSeek, WorkMeter, validate_window,
};
use crate::{Match, SearchLimits, SearchWindow};

pub(crate) const PLAN_ID: &str = "pure-byte-class-repeat-bounded-v1";

const NODE_INSPECTION_WORK: u64 = 1;
const RANGE_INSPECTION_WORK: u64 = 1;
const MEMBER_INSERTION_WORK: u64 = 1;
const LEAF_SELECTION_WORK: u64 = 1;

type SearchError = Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InspectionError {
    WorkLimit { needed: u64, limit: u64 },
    ArithmeticOverflow,
}

pub(crate) struct Inspection {
    minimum: u32,
    maximum: u32,
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

struct Owner {
    minimum: u32,
    maximum: u32,
    greedy: bool,
    member_seek: SetSeek,
    run_end_seek: SetSeek,
    classifier: Option<ByteSetClassifier>,
}

pub(crate) struct Plan {
    owner: ExactBoxOrUsize<Owner>,
}

#[derive(Clone, Copy)]
struct Qualified {
    start: usize,
    minimum_end: usize,
}

struct SearchState {
    qualified: Option<Qualified>,
    meter: WorkMeter,
    candidate_scans: usize,
    run_scans: usize,
}

impl Plan {
    #[cold]
    fn build(
        minimum: u32,
        maximum: u32,
        greedy: bool,
        member_seek: SetSeek,
        run_end_seek: SetSeek,
        classifier_words: Option<[u64; 4]>,
        dispatch: SimdDispatchContext,
    ) -> Result<Self, CopyError> {
        let classifier = classifier_words.map(|words| {
            dispatch
                .byte_set_classifier(ByteSet256::from_words(words), DispatchPolicy::Auto)
                .expect("automatic byte-set dispatch retains a scalar fallback")
        });
        let owner = ExactBoxOrUsize::try_from_boxed(Owner {
            minimum,
            maximum,
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
            .expect("the bounded byte-class repeat retains its exact owner")
    }

    pub(crate) const fn storage_bytes() -> usize {
        core::mem::size_of::<Self>()
            .checked_add(core::mem::size_of::<Owner>())
            .expect("the fixed bounded byte-class repeat layouts fit usize")
    }

    pub(crate) fn is_match_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(bool, Accounting), SearchError> {
        let state = self.qualifying_search(haystack, window, limits)?;
        let matched = state.qualified.is_some();
        let accounting = self.finish_accounting(
            Operation::Exists,
            window,
            state.meter,
            state.candidate_scans,
            state.run_scans,
            usize::from(matched),
        );
        Ok((matched, accounting))
    }

    pub(crate) fn is_match_window_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        if limits == SearchLimits::unlimited() {
            validate_window(haystack, window)?;
            if unmetered_work_fits(window) {
                return Ok(self.qualifying_search_value(haystack, window).is_some());
            }
        }
        self.is_match_window(haystack, window, limits)
            .map(|(matched, _)| matched)
    }

    pub(crate) fn earliest_end_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, Accounting), SearchError> {
        let state = self.qualifying_search(haystack, window, limits)?;
        let end = state.qualified.map(|qualified| qualified.minimum_end);
        let accounting = self.finish_accounting(
            Operation::EarliestEnd,
            window,
            state.meter,
            state.candidate_scans,
            state.run_scans,
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
        if limits == SearchLimits::unlimited() {
            validate_window(haystack, window)?;
            if unmetered_work_fits(window) {
                return Ok(self
                    .qualifying_search_value(haystack, window)
                    .map(|qualified| qualified.minimum_end));
            }
        }
        self.earliest_end_window(haystack, window, limits)
            .map(|(end, _)| end)
    }

    pub(crate) fn selected_end_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, Accounting), SearchError> {
        let (span, accounting) =
            self.selected_window(haystack, window, limits, Operation::SelectedEnd)?;
        Ok((span.map(|(_, end)| end), accounting))
    }

    pub(crate) fn find_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, Accounting), SearchError> {
        let (span, accounting) = self.selected_window(haystack, window, limits, Operation::Span)?;
        Ok((span.map(|(start, end)| Match { start, end }), accounting))
    }

    pub(crate) fn find_window_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<Option<Match>, SearchError> {
        if limits == SearchLimits::unlimited() {
            validate_window(haystack, window)?;
            if unmetered_work_fits(window) {
                return Ok(self
                    .selected_search_value(haystack, window)
                    .map(|(start, end)| Match { start, end }));
            }
        }
        self.find_window(haystack, window, limits)
            .map(|(matched, _)| matched)
    }

    fn selected_search_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
    ) -> Option<(usize, usize)> {
        let qualified = self.qualifying_search_value(haystack, window)?;
        let owner = self.owner();
        if !owner.greedy {
            return Some((qualified.start, qualified.minimum_end));
        }
        let maximum = usize::try_from(owner.maximum)
            .expect("one repetition maximum fits the target index width");
        let maximum_end = qualified.start.saturating_add(maximum).min(window.end());
        let end = if qualified.minimum_end < maximum_end {
            owner
                .run_end_seek
                .seek_unmetered(
                    haystack,
                    qualified.minimum_end,
                    maximum_end,
                    owner.classifier.as_ref(),
                )
                .unwrap_or(maximum_end)
        } else {
            maximum_end
        };
        Some((qualified.start, end))
    }

    #[inline(never)]
    fn selected_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
        operation: Operation,
    ) -> Result<(Option<(usize, usize)>, Accounting), SearchError> {
        let mut state = self.qualifying_search(haystack, window, limits)?;
        let Some(qualified) = state.qualified else {
            let accounting = self.finish_accounting(
                operation,
                window,
                state.meter,
                state.candidate_scans,
                state.run_scans,
                0,
            );
            return Ok((None, accounting));
        };
        let owner = self.owner();
        let mut end = qualified.minimum_end;
        if owner.greedy {
            let maximum = usize::try_from(owner.maximum)
                .expect("one repetition maximum fits the target index width");
            let maximum_end = qualified.start.saturating_add(maximum).min(window.end());
            if qualified.minimum_end < maximum_end {
                state.run_scans = state
                    .run_scans
                    .checked_add(1)
                    .expect("run scans cannot exceed the validated slice length");
                end = owner
                    .run_end_seek
                    .seek(
                        haystack,
                        qualified.minimum_end,
                        maximum_end,
                        &mut state.meter,
                        owner.classifier.as_ref(),
                    )?
                    .unwrap_or(maximum_end);
            }
        }
        let accounting = self.finish_accounting(
            operation,
            window,
            state.meter,
            state.candidate_scans,
            state.run_scans,
            1,
        );
        Ok((Some((qualified.start, end)), accounting))
    }

    fn qualifying_search(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<SearchState, SearchError> {
        validate_window(haystack, window)?;
        let owner = self.owner();
        let minimum = usize::try_from(owner.minimum)
            .expect("one repetition minimum fits the target index width");
        let mut meter = WorkMeter::new(limits.max_work);
        let mut position = window.start();
        let mut candidate_scans = 0_usize;
        let mut run_scans = 0_usize;
        loop {
            candidate_scans = candidate_scans
                .checked_add(1)
                .expect("candidate scans cannot exceed the validated slice length plus one");
            let Some(start) = owner.member_seek.seek(
                haystack,
                position,
                window.end(),
                &mut meter,
                owner.classifier.as_ref(),
            )?
            else {
                return Ok(SearchState {
                    qualified: None,
                    meter,
                    candidate_scans,
                    run_scans,
                });
            };
            if window.end().saturating_sub(start) < minimum {
                return Ok(SearchState {
                    qualified: None,
                    meter,
                    candidate_scans,
                    run_scans,
                });
            }
            let minimum_end = start
                .checked_add(minimum)
                .expect("the remaining-window proof bounds the minimum end");
            if minimum > 1 {
                run_scans = run_scans
                    .checked_add(1)
                    .expect("run scans cannot exceed the validated slice length");
                if let Some(run_end) = owner.run_end_seek.seek(
                    haystack,
                    start + 1,
                    minimum_end,
                    &mut meter,
                    owner.classifier.as_ref(),
                )? {
                    position = run_end
                        .checked_add(1)
                        .expect("a nonmember before the window end can advance once");
                    continue;
                }
            }
            return Ok(SearchState {
                qualified: Some(Qualified { start, minimum_end }),
                meter,
                candidate_scans,
                run_scans,
            });
        }
    }

    fn qualifying_search_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
    ) -> Option<Qualified> {
        let owner = self.owner();
        let minimum = usize::try_from(owner.minimum)
            .expect("one repetition minimum fits the target index width");
        let mut position = window.start();
        loop {
            let start = owner.member_seek.seek_unmetered(
                haystack,
                position,
                window.end(),
                owner.classifier.as_ref(),
            )?;
            if window.end().saturating_sub(start) < minimum {
                return None;
            }
            let minimum_end = start
                .checked_add(minimum)
                .expect("the remaining-window proof bounds the minimum end");
            if minimum > 1
                && let Some(run_end) = owner.run_end_seek.seek_unmetered(
                    haystack,
                    start
                        .checked_add(1)
                        .expect("a member before the window end can advance once"),
                    minimum_end,
                    owner.classifier.as_ref(),
                )
            {
                position = run_end
                    .checked_add(1)
                    .expect("a nonmember before the window end can advance once");
                continue;
            }
            return Some(Qualified { start, minimum_end });
        }
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
    ) -> Accounting {
        let input_bytes = window.end() - window.start();
        // Every logical interval advances past a newly established member or
        // nonmember. A fixed-width classified seek can additionally charge at
        // most one complete block for that interval, so 16*N closes every
        // possible alternation without depending on source contents.
        let work_upper_bound = u64::try_from(input_bytes)
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(BYTE_SET_BLOCK_BYTES).expect("block width fits u64"));
        debug_assert!(meter.consumed() <= work_upper_bound);
        let source_reads =
            usize::try_from(meter.consumed()).expect("charged source reads fit usize");
        Accounting {
            plan_id: PLAN_ID,
            operation,
            input_bytes,
            source_reads,
            work_upper_bound,
            actual_work: meter.consumed(),
            candidate_scans,
            run_scans,
            match_events,
        }
    }
}

fn unmetered_work_fits(window: SearchWindow) -> bool {
    let window_width = window
        .end()
        .checked_sub(window.start())
        .expect("a validated window has ordered bounds");
    u64::try_from(window_width).ok().is_some_and(|width| {
        width
            .checked_mul(u64::try_from(BYTE_SET_BLOCK_BYTES).expect("block width fits u64"))
            .is_some()
    })
}

impl Inspection {
    #[cold]
    pub(crate) fn build(self, dispatch: SimdDispatchContext) -> Result<Plan, CopyError> {
        Plan::build(
            self.minimum,
            self.maximum,
            self.greedy,
            self.member_seek,
            self.run_end_seek,
            self.classifier_words,
            dispatch,
        )
    }
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
    let Some(maximum) = repetition.max else {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    };
    if repetition.min == 0 || maximum < repetition.min {
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
        _ => return Ok(InspectionOutcome::Ineligible { planner_work: work }),
    }

    let complement = words.map(|word| !word);
    let member_cardinality = words.iter().map(|word| word.count_ones()).sum::<u32>();
    if member_cardinality == 0 {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    }
    let run_end_cardinality = 256_u32 - member_cardinality;
    charge_planner(&mut work, LEAF_SELECTION_WORK, max_planner_work)?;
    charge_planner(&mut work, LEAF_SELECTION_WORK, max_planner_work)?;
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
        minimum: repetition.min,
        maximum,
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
    use super::{BYTE_SET_BLOCK_BYTES, PLAN_ID};
    use crate::pure_byte_class_repeat::SetSeek;
    use crate::{
        BuildError, BuildLimits, PlanKind, PlanSelection, PortableBuilder, PortableFindIterLimits,
        PortableFindIterRunLimits, PortablePlan, PortableTextBuilder, SearchAccounting,
        SearchError as FacadeSearchError, SearchLimits, SearchSessionLimits, SearchWindow,
    };
    use crate::{
        PureByteClassRepeatAccounting as Accounting, PureByteClassRepeatOperation as Operation,
        PureByteClassRepeatSearchError as Error,
    };

    fn build(pattern: &str) -> crate::PortableRegex {
        PortableBuilder::new(pattern)
            .unicode(false)
            .build()
            .expect("the bounded byte-class repeat should build")
    }

    fn accounting(accounting: SearchAccounting) -> Accounting {
        match accounting {
            SearchAccounting::PureByteClassRepeat(accounting) => accounting,
            other => panic!("expected bounded byte-class accounting, got {other:?}"),
        }
    }

    fn span(matched: Option<crate::Match>) -> Option<(usize, usize)> {
        matched.map(|matched| (matched.start(), matched.end()))
    }

    #[test]
    fn facade_selects_positive_finite_root_repetitions_without_changing_plus() {
        for pattern in [
            "a{2,4}",
            "a{2,4}?",
            "(?-u:[a-d]){1,7}",
            "(?-u:[^x]){3,9}?",
            "(?-u:[\\x80-\\xff]){2,6}",
            "((?-u:[a-d])){2,4}",
        ] {
            let regex = build(pattern);
            assert_eq!(regex.build_report().plan, PlanKind::PureByteClassRepeat);
            assert_eq!(regex.runtime_implementation_id(), PLAN_ID);
            assert!(regex.build_report().lowering.is_none());
            assert_eq!(regex.build_report().states, 0);
            assert_eq!(regex.build_report().edges, 0);
        }

        for pattern in ["(?-u:[a-d]){0,3}", "x(?-u:[a-d]){2,4}"] {
            let regex = build(pattern);
            assert_ne!(regex.runtime_implementation_id(), PLAN_ID);
        }

        let plus = build("(?-u:[a-d])+");
        assert_eq!(
            plus.runtime_implementation_id(),
            crate::PURE_BYTE_CLASS_REPEAT_PLAN_ID
        );

        let forced = PortableBuilder::new("(?-u:[a-d]){2,4}")
            .unicode(false)
            .plan_selection(PlanSelection::ForceK0)
            .build()
            .unwrap();
        assert_eq!(forced.build_report().plan, PlanKind::K0);

        let text = PortableTextBuilder::new("a{2,4}").build().unwrap();
        assert_ne!(
            text.build_report().portable.plan,
            PlanKind::PureByteClassRepeat
        );
    }

    #[test]
    fn contiguous_and_small_owners_share_range_seeks_without_generic_classifier() {
        let range = build(r"(?-u:[\x40-\x7f]){3,7}");
        assert_eq!(range.runtime_implementation_id(), PLAN_ID);
        let PortablePlan::BoundedByteClassRepeat(plan) = &range.plan else {
            panic!("one bounded range should retain the bounded repeat plan");
        };
        assert_eq!(
            plan.owner().member_seek,
            SetSeek::Range {
                origin: 0x40,
                maximum_delta: 0x3f,
                inverted: false,
            }
        );
        assert_eq!(
            plan.owner().run_end_seek,
            SetSeek::Range {
                origin: 0x40,
                maximum_delta: 0x3f,
                inverted: true,
            }
        );
        assert!(plan.owner().classifier.is_none());

        let (matched, receipt) = range
            .find(b"................................@@@@!", SearchLimits::unlimited())
            .expect("one bounded range search should succeed");
        assert_eq!(span(matched), Some((32, 36)));
        let receipt = accounting(receipt);
        assert_eq!(receipt.plan_id, PLAN_ID);
        assert_eq!(receipt.operation, Operation::Span);
        assert_eq!(
            receipt.actual_work,
            u64::try_from(receipt.source_reads).expect("source reads fit u64")
        );
        assert!(receipt.actual_work <= receipt.work_upper_bound);

        let small = build("a{2,5}");
        let PortablePlan::BoundedByteClassRepeat(plan) = &small.plan else {
            panic!("one bounded literal should retain the bounded repeat plan");
        };
        assert_eq!(plan.owner().member_seek, SetSeek::One(b'a'));
        assert_eq!(
            plan.owner().run_end_seek,
            SetSeek::Range {
                origin: b'a',
                maximum_delta: 0,
                inverted: true,
            }
        );
        assert!(plan.owner().classifier.is_none());

        let small_holey = build("(?-u:[ac]){2,5}");
        let PortablePlan::BoundedByteClassRepeat(plan) = &small_holey.plan else {
            panic!("one bounded holey pair should retain the bounded repeat plan");
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
            .expect("a bounded holey-pair complement needs the generic classifier");
        assert!(!classifier.set().contains(b'a'));
        assert!(classifier.set().contains(b'b'));
        assert!(!classifier.set().contains(b'c'));
    }

    #[test]
    fn exhaustive_sets_bounds_greediness_windows_and_operations_match_oracle() {
        let patterns = [
            "a{2,3}",
            "a{2,3}?",
            "(?-u:[a-d]){1,3}",
            "(?-u:[a-d]){1,3}?",
            "(?-u:[^a]){2,4}",
            "(?-u:[^a]){2,4}?",
            "(?-u:[\\x80-\\xff]){2,5}",
            "(?-u:[\\x80-\\xff]){2,5}?",
            "(?-u:[^\\x80-\\xff]){3,5}",
            "(?-u:[ac]){2,4}",
            "(?-u:[ac]){2,4}?",
            "(?-u:[ace]){2,4}",
            "(?-u:[ace]){2,4}?",
            "(?-u:[abdz]){2,4}",
            "(?-u:[abdz]){2,4}?",
            "(?s-u:.){2,4}",
        ];
        let alphabet = [b'a', b'b', b'c', b'd', 0x80_u8];
        for pattern in patterns {
            let fre = build(pattern);
            let oracle = regex::bytes::RegexBuilder::new(pattern)
                .unicode(false)
                .build()
                .unwrap();
            let PortablePlan::BoundedByteClassRepeat(plan) = &fre.plan else {
                panic!("expected bounded plan for {pattern:?}");
            };
            let mut session = fre
                .search_session(SearchSessionLimits::unlimited())
                .expect("the native bounded session should build");
            for length in 0_u32..=4 {
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
                            let expected = oracle
                                .find(source)
                                .map(|matched| (start + matched.start(), start + matched.end()));
                            let expected_earliest =
                                oracle.shortest_match(source).map(|finish| start + finish);

                            let (exists, exists_accounting) = fre
                                .is_match_window(&haystack, window, SearchLimits::unlimited())
                                .unwrap();
                            assert_eq!(
                                exists,
                                expected.is_some(),
                                "exists: {pattern:?} {haystack:?} {start}..{end}"
                            );
                            let exists_accounting = accounting(exists_accounting);
                            assert_eq!(exists_accounting.plan_id, PLAN_ID);
                            assert_eq!(exists_accounting.operation, Operation::Exists);
                            assert_eq!(
                                exists_accounting.actual_work,
                                u64::try_from(exists_accounting.source_reads).unwrap()
                            );
                            assert!(
                                exists_accounting.actual_work <= exists_accounting.work_upper_bound
                            );
                            assert_eq!(
                                fre.is_match_window_value(
                                    &haystack,
                                    window,
                                    SearchLimits::unlimited(),
                                )
                                .unwrap(),
                                expected.is_some(),
                                "value exists: {pattern:?} {haystack:?} {start}..{end}",
                            );

                            let (earliest, earliest_accounting) = fre
                                .shortest_match_window(&haystack, window, SearchLimits::unlimited())
                                .unwrap();
                            assert_eq!(
                                earliest, expected_earliest,
                                "earliest: {pattern:?} {haystack:?} {start}..{end}"
                            );
                            assert_eq!(
                                accounting(earliest_accounting).operation,
                                Operation::EarliestEnd
                            );
                            assert_eq!(
                                plan.earliest_end_window_value(
                                    &haystack,
                                    window,
                                    SearchLimits::unlimited(),
                                )
                                .unwrap(),
                                expected_earliest,
                                "value earliest: {pattern:?} {haystack:?} {start}..{end}",
                            );
                            assert_eq!(
                                fre.shortest_match_window_value(
                                    &haystack,
                                    window,
                                    SearchLimits::unlimited(),
                                )
                                .unwrap(),
                                expected_earliest,
                                "facade value earliest: {pattern:?} {haystack:?} {start}..{end}",
                            );
                            assert_eq!(
                                session
                                    .shortest_match_window_value(
                                        &haystack,
                                        window,
                                        SearchLimits::unlimited(),
                                    )
                                    .unwrap(),
                                expected_earliest,
                                "session value earliest: {pattern:?} {haystack:?} {start}..{end}",
                            );

                            let (selected_end, selected_accounting) = plan
                                .selected_end_window(&haystack, window, SearchLimits::unlimited())
                                .unwrap();
                            assert_eq!(
                                selected_end,
                                expected.map(|(_, finish)| finish),
                                "selected end: {pattern:?} {haystack:?} {start}..{end}"
                            );
                            assert_eq!(selected_accounting.operation, Operation::SelectedEnd);

                            let (found, found_accounting) = fre
                                .find_window(&haystack, window, SearchLimits::unlimited())
                                .unwrap();
                            assert_eq!(
                                span(found),
                                expected,
                                "span: {pattern:?} {haystack:?} {start}..{end}"
                            );
                            assert_eq!(accounting(found_accounting).operation, Operation::Span);
                            assert_eq!(
                                span(
                                    fre.find_window_value(
                                        &haystack,
                                        window,
                                        SearchLimits::unlimited(),
                                    )
                                    .unwrap(),
                                ),
                                expected,
                                "value span: {pattern:?} {haystack:?} {start}..{end}",
                            );
                        }
                    }

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
                    let actual_value_iter = fre
                        .find_iter_value(&haystack, PortableFindIterLimits::unlimited())
                        .unwrap()
                        .map(|matched| {
                            let matched = matched.unwrap();
                            (matched.start(), matched.end())
                        })
                        .collect::<Vec<_>>();
                    assert_eq!(
                        actual_value_iter, expected_iter,
                        "value iterator: {pattern:?} {haystack:?}"
                    );
                    let session_value_iter = session
                        .find_iter_value(&haystack, PortableFindIterRunLimits::unlimited())
                        .map(|matched| {
                            let matched = matched.unwrap();
                            (matched.start(), matched.end())
                        })
                        .collect::<Vec<_>>();
                    assert_eq!(
                        session_value_iter, expected_iter,
                        "session value iterator: {pattern:?} {haystack:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn value_paths_match_accounted_search_across_classifier_blocks() {
        let patterns = [
            "(?-u:[ac]){5,9}",
            "(?-u:[ac]){5,9}?",
            "(?-u:[ace]){5,9}",
            "(?-u:[ace]){5,9}?",
            "(?-u:[aceg]){5,9}",
            "(?-u:[aceg]){5,9}?",
            "(?-u:[a-z]){5,9}",
            "(?-u:[a-z]){5,9}?",
            "(?-u:[^x]){5,9}",
            "(?-u:[^x]){5,9}?",
            "(?-u:[\\x80\\x82\\x84\\x86]){5,9}",
            "(?-u:[\\x80\\x82\\x84\\x86]){5,9}?",
        ];
        let mut ascii_decoys = Vec::new();
        for _ in 0..20 {
            ascii_decoys.extend_from_slice(b"aceg!");
        }
        ascii_decoys.extend_from_slice(b"acegace");

        let mut high_decoys = Vec::new();
        for _ in 0..20 {
            high_decoys.extend_from_slice(&[0x80, 0x82, 0x84, 0x86, b'!']);
        }
        high_decoys.extend_from_slice(&[0x80, 0x82, 0x84, 0x86, 0x80, 0x82]);

        let mut boundary = vec![b'!'; BYTE_SET_BLOCK_BYTES - 2];
        boundary.extend_from_slice(b"acegacegaceg");
        boundary.extend_from_slice(&[b'!'; BYTE_SET_BLOCK_BYTES + 3]);

        for pattern in patterns {
            let regex = build(pattern);
            let PortablePlan::BoundedByteClassRepeat(plan) = &regex.plan else {
                panic!("expected bounded plan for {pattern:?}");
            };
            for haystack in [&ascii_decoys, &high_decoys, &boundary] {
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        let window = SearchWindow::new(start, end);
                        let expected_match = plan
                            .find_window(haystack, window, SearchLimits::unlimited())
                            .unwrap()
                            .0;
                        let expected_exists = plan
                            .is_match_window(haystack, window, SearchLimits::unlimited())
                            .unwrap()
                            .0;
                        assert_eq!(
                            span(
                                plan.find_window_value(
                                    haystack,
                                    window,
                                    SearchLimits::unlimited(),
                                )
                                .unwrap(),
                            ),
                            span(expected_match),
                            "span: {pattern:?} window={start}..{end}",
                        );
                        assert_eq!(
                            plan.is_match_window_value(
                                haystack,
                                window,
                                SearchLimits::unlimited(),
                            )
                            .unwrap(),
                            expected_exists,
                            "exists: {pattern:?} window={start}..{end}",
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn exact_search_and_construction_limits_close_for_every_operation() {
        let pattern = "(?-u:[a-d]){3,7}";
        let haystack = b"zzabzzabczzabcdabc!";
        let regex = build(pattern);
        let PortablePlan::BoundedByteClassRepeat(plan) = &regex.plan else {
            panic!("expected bounded plan");
        };
        let window = SearchWindow::new(1, haystack.len() - 1);

        for operation in [
            Operation::Exists,
            Operation::EarliestEnd,
            Operation::SelectedEnd,
            Operation::Span,
        ] {
            let measured = match operation {
                Operation::Exists => accounting(
                    regex
                        .is_match_window(haystack, window, SearchLimits::unlimited())
                        .unwrap()
                        .1,
                ),
                Operation::EarliestEnd => accounting(
                    regex
                        .shortest_match_window(haystack, window, SearchLimits::unlimited())
                        .unwrap()
                        .1,
                ),
                Operation::SelectedEnd => {
                    plan.selected_end_window(haystack, window, SearchLimits::unlimited())
                        .unwrap()
                        .1
                }
                Operation::Span => accounting(
                    regex
                        .find_window(haystack, window, SearchLimits::unlimited())
                        .unwrap()
                        .1,
                ),
            };
            assert!(measured.actual_work > 0);
            assert!(measured.actual_work <= measured.work_upper_bound);
            let exact = SearchLimits {
                max_work: measured.actual_work,
                max_scratch_bytes: 0,
            };
            let exact_accounting = match operation {
                Operation::Exists => {
                    accounting(regex.is_match_window(haystack, window, exact).unwrap().1)
                }
                Operation::EarliestEnd => accounting(
                    regex
                        .shortest_match_window(haystack, window, exact)
                        .unwrap()
                        .1,
                ),
                Operation::SelectedEnd => {
                    plan.selected_end_window(haystack, window, exact).unwrap().1
                }
                Operation::Span => {
                    accounting(regex.find_window(haystack, window, exact).unwrap().1)
                }
            };
            assert_eq!(exact_accounting.actual_work, measured.actual_work);

            let one_below = SearchLimits {
                max_work: measured.actual_work - 1,
                max_scratch_bytes: 0,
            };
            let error = match operation {
                Operation::Exists => regex
                    .is_match_window(haystack, window, one_below)
                    .unwrap_err(),
                Operation::EarliestEnd => regex
                    .shortest_match_window(haystack, window, one_below)
                    .unwrap_err(),
                Operation::SelectedEnd => plan
                    .selected_end_window(haystack, window, one_below)
                    .unwrap_err()
                    .into(),
                Operation::Span => regex.find_window(haystack, window, one_below).unwrap_err(),
            };
            assert!(matches!(
                error,
                FacadeSearchError::PureByteClassRepeat(Error::WorkLimit { limit, .. })
                    if limit == measured.actual_work - 1
            ));
            match operation {
                Operation::Exists => {
                    assert!(
                        plan.is_match_window_value(haystack, window, exact)
                            .unwrap()
                    );
                    assert!(matches!(
                        plan.is_match_window_value(haystack, window, one_below),
                        Err(Error::WorkLimit { limit, .. })
                            if limit == measured.actual_work - 1
                    ));
                }
                Operation::Span => {
                    let expected = regex
                        .find_window(haystack, window, SearchLimits::unlimited())
                        .unwrap()
                        .0;
                    assert_eq!(
                        span(plan.find_window_value(haystack, window, exact).unwrap()),
                        span(expected),
                    );
                    assert!(matches!(
                        plan.find_window_value(haystack, window, one_below),
                        Err(Error::WorkLimit { limit, .. })
                            if limit == measured.actual_work - 1
                    ));
                }
                Operation::EarliestEnd => {
                    let expected = regex
                        .shortest_match_window(haystack, window, SearchLimits::unlimited())
                        .unwrap()
                        .0;
                    assert_eq!(
                        plan.earliest_end_window_value(haystack, window, exact)
                            .unwrap(),
                        expected,
                    );
                    assert!(matches!(
                        plan.earliest_end_window_value(haystack, window, one_below),
                        Err(Error::WorkLimit { limit, .. })
                            if limit == measured.actual_work - 1
                    ));
                }
                Operation::SelectedEnd => {}
            }
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
    fn operation_prefixes_and_greedy_maximum_are_exactly_half_open() {
        let greedy = build("(?-u:[a-d]){3,7}");
        let haystack = b"aaaaaaaaX";
        let (exists, exists_accounting) = greedy
            .is_match(haystack, SearchLimits::unlimited())
            .unwrap();
        assert!(exists);
        assert_eq!(accounting(exists_accounting).actual_work, 3);

        let (earliest, earliest_accounting) = greedy
            .shortest_match(haystack, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(earliest, Some(3));
        assert_eq!(accounting(earliest_accounting).actual_work, 3);

        let (found, found_accounting) = greedy.find(haystack, SearchLimits::unlimited()).unwrap();
        assert_eq!(span(found), Some((0, 7)));
        let found_accounting = accounting(found_accounting);
        assert_eq!(found_accounting.actual_work, 7);
        assert_eq!(found_accounting.source_reads, 7);

        let lazy = build("(?-u:[a-d]){3,7}?");
        let (found, lazy_accounting) = lazy.find(haystack, SearchLimits::unlimited()).unwrap();
        assert_eq!(span(found), Some((0, 3)));
        assert_eq!(accounting(lazy_accounting).actual_work, 3);
    }

    #[test]
    fn invalid_window_is_rejected_before_source_reads() {
        let regex = build("(?-u:[^x]){2,5}");
        assert!(matches!(
            regex.find_window(b"abc", SearchWindow::new(2, 1), SearchLimits::unlimited(),),
            Err(FacadeSearchError::PureByteClassRepeat(Error::InvalidWindow))
        ));
    }
}
