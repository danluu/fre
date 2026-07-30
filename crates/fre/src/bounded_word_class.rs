//! Direct search for one greedy class repetition between matching word
//! boundaries.
//!
//! The admitted HIR is exactly `\b CLASS{min,max} \b` (modulo transparent
//! captures), with either the ASCII boundary plus a byte class or the Unicode
//! boundary plus a Unicode scalar class. The class need not be the word
//! property: boundaries are evaluated against the complete original
//! haystack, independently of class membership.

use fre_exact_alloc::{CopyError, ExactBoxOrUsize, ExactVec};
use fre_kernels::{
    ASCII_CLASSIFIER_BUILD_WORK, ASCII_NARROW_BYTES, ASCII_RUN_SCANNER_BUILD_WORK,
    ASCII_WIDE_BYTES, AsciiByteSet, AsciiByteSetClassifier, AsciiByteSetRunScanner, DispatchPolicy,
    SimdDispatchContext,
};
use regex_syntax::hir::{Class, Hir, HirKind, Look};

use crate::{
    Match, SearchLimits, SearchWindow,
    unicode_word_run::{Accounting, Error},
};

pub(crate) const PLAN_ID: &str = "bounded-word-class-linear-bulk-skip-v3";

/// Pointwise checks stay cheaper than entering a fixed-width classifier when
/// a candidate is close to the current cursor. This constant is independent
/// of the regex and haystack.
const CANDIDATE_SCALAR_PREFIX_BYTES: usize = 8;

/// A run-scanner call must be able to replace at least two wide classifier
/// iterations. This keeps short and dense searches on their existing path
/// while amortizing one bulk call over genuinely reusable rejection work.
const BULK_SKIP_MIN_BYTES: usize = ASCII_WIDE_BYTES * 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BoundaryMode {
    Ascii,
    Unicode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ScalarRange {
    start: char,
    end: char,
}

#[derive(Debug)]
enum ClassMatcher {
    Bytes([u64; 4]),
    Unicode {
        ascii_words: [u64; 2],
        ranges: ExactVec<ScalarRange>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CandidateMode {
    /// Every class member is ASCII, so the classifier's member mask is exact.
    ExactAsciiMembers,
    /// ASCII members and every high byte require scalar Unicode inspection.
    UnicodeAsciiMemberOrNonAscii,
}

#[derive(Debug)]
struct CandidateScanner {
    classifier: AsciiByteSetClassifier,
    /// Exact ASCII byte classes can scan their ASCII nonmember complement as
    /// one maximal run. Unicode keeps the classifier path because every high
    /// byte is a semantic decode candidate.
    nonmember_scanner: ExactBoxOrUsize<AsciiByteSetRunScanner>,
    mode: CandidateMode,
}

/// Immutable, allocation-free-at-search-time native plan.
#[derive(Debug)]
pub(crate) struct Plan {
    mode: BoundaryMode,
    class: ClassMatcher,
    candidate_scanner: Option<CandidateScanner>,
    minimum_units: usize,
    maximum_units: Option<usize>,
    storage_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InspectionError {
    WorkLimit { needed: u64, limit: u64 },
    ArithmeticOverflow(&'static str),
}

#[derive(Clone, Copy, Debug)]
enum InspectedClass<'a> {
    Bytes(&'a regex_syntax::hir::ClassBytes),
    Unicode(&'a regex_syntax::hir::ClassUnicode),
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Inspection<'a> {
    mode: BoundaryMode,
    class: InspectedClass<'a>,
    candidate_mode: Option<CandidateMode>,
    dispatch: SimdDispatchContext,
    minimum_units: usize,
    maximum_units: Option<usize>,
    planner_work: u64,
    storage_bytes: usize,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum InspectionOutcome<'a> {
    Eligible(Inspection<'a>),
    Ineligible { planner_work: u64 },
}

impl InspectionOutcome<'_> {
    pub(crate) const fn planner_work(self) -> u64 {
        match self {
            Self::Eligible(inspection) => inspection.planner_work(),
            Self::Ineligible { planner_work } => planner_work,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BoundaryPoint {
    byte: usize,
    units: usize,
}

#[derive(Clone, Copy, Debug)]
struct BoundaryCursor {
    position: usize,
    units: usize,
    run_end: usize,
    done: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ScanningBoundaryPoint {
    point: BoundaryPoint,
    has_member_after: bool,
}

#[derive(Clone, Copy, Debug)]
struct ScanningBoundaryCursor {
    position: usize,
    units: usize,
    end: usize,
    done: bool,
}

impl ScanningBoundaryCursor {
    const fn new(run_start: usize, end: usize) -> Self {
        Self {
            position: run_start,
            units: 0,
            end,
            done: false,
        }
    }

    fn next(
        &mut self,
        plan: &Plan,
        haystack: &[u8],
        accounting: &mut Accounting,
        limits: SearchLimits,
    ) -> Result<Option<ScanningBoundaryPoint>, Error> {
        while !self.done {
            let point = BoundaryPoint {
                byte: self.position,
                units: self.units,
            };
            let has_member_after = if self.position == self.end {
                self.done = true;
                false
            } else {
                let (admitted, width, _) =
                    plan.classify_unit(haystack, self.position, self.end, accounting, limits)?;
                if admitted {
                    self.position = self
                        .position
                        .checked_add(width)
                        .ok_or_else(|| accounting_overflow(limits))?;
                    self.units = self
                        .units
                        .checked_add(1)
                        .ok_or_else(|| accounting_overflow(limits))?;
                    true
                } else {
                    self.done = true;
                    false
                }
            };
            charge(accounting, limits)?;
            if plan.is_word_boundary(haystack, point.byte) {
                return Ok(Some(ScanningBoundaryPoint {
                    point,
                    has_member_after,
                }));
            }
        }
        Ok(None)
    }

    const fn run_end(self) -> usize {
        self.position
    }

    fn last_boundary_through(
        &mut self,
        plan: &Plan,
        haystack: &[u8],
        unit_limit: usize,
        mut selected: BoundaryPoint,
        accounting: &mut Accounting,
        limits: SearchLimits,
    ) -> Result<BoundaryPoint, Error> {
        // A valid end for the earliest start already exists. Search only its
        // remaining finite greedy horizon; no later start can supersede it.
        while !self.done && self.units <= unit_limit {
            let point = BoundaryPoint {
                byte: self.position,
                units: self.units,
            };
            if self.units == unit_limit {
                charge(accounting, limits)?;
                if plan.is_word_boundary(haystack, point.byte) {
                    selected = point;
                }
                break;
            }
            if self.position == self.end {
                self.done = true;
            } else {
                let (admitted, width, _) =
                    plan.classify_unit(haystack, self.position, self.end, accounting, limits)?;
                if admitted {
                    self.position = self
                        .position
                        .checked_add(width)
                        .ok_or_else(|| accounting_overflow(limits))?;
                    self.units = self
                        .units
                        .checked_add(1)
                        .ok_or_else(|| accounting_overflow(limits))?;
                } else {
                    self.done = true;
                }
            }
            charge(accounting, limits)?;
            if plan.is_word_boundary(haystack, point.byte) {
                selected = point;
            }
        }
        Ok(selected)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScannedCandidate {
    AsciiMember { position: usize, byte: u8 },
    NonAscii { position: usize },
}

impl CandidateScanner {
    #[allow(
        clippy::too_many_lines,
        reason = "the scalar, bulk-run, fixed-width, and tail paths keep their exact shared ledger adjacent"
    )]
    fn next(
        &self,
        haystack: &[u8],
        mut position: usize,
        end: usize,
        accounting: &mut Accounting,
        limits: SearchLimits,
    ) -> Result<Option<ScannedCandidate>, Error> {
        let prefix_end = position
            .checked_add(
                end.saturating_sub(position)
                    .min(CANDIDATE_SCALAR_PREFIX_BYTES),
            )
            .ok_or_else(|| accounting_overflow(limits))?;
        while position < prefix_end {
            if let Some(candidate) =
                self.scalar_candidate(haystack, position, accounting, limits)?
            {
                return Ok(Some(candidate));
            }
            position = position
                .checked_add(1)
                .ok_or_else(|| accounting_overflow(limits))?;
        }

        // Preserve the established fixed classifier for the first post-prefix
        // block. Nearby sparse candidates and dense iteration therefore keep
        // their old path even when the untouched suffix is large.
        let mut fixed_block_proved = false;
        while end.saturating_sub(position) >= ASCII_WIDE_BYTES {
            if fixed_block_proved
                && let Some(scanner) = self.nonmember_scanner.boxed()
                && end.saturating_sub(position) >= BULK_SKIP_MIN_BYTES
            {
                let available = limits.max_work.saturating_sub(accounting.work);
                let bulk_len = end
                    .saturating_sub(position)
                    .min(usize::try_from(available).unwrap_or(usize::MAX));
                if bulk_len >= BULK_SKIP_MIN_BYTES {
                    let bulk_end = position
                        .checked_add(bulk_len)
                        .ok_or_else(|| accounting_overflow(limits))?;
                    // This ledger is logical, matching the established ASCII
                    // word-run scanner contract: every skipped source byte is
                    // charged once, while failed-block recovery remains a
                    // private implementation detail of the retained scanner.
                    let skipped = scanner
                        .scan_forward(&haystack[position..bulk_end])
                        .member_run_len();
                    charge_many(accounting, skipped, limits)?;
                    record_source(accounting, skipped, skipped, limits)?;
                    position = position
                        .checked_add(skipped)
                        .ok_or_else(|| accounting_overflow(limits))?;
                    if position == bulk_end {
                        if position == end {
                            return Ok(None);
                        }
                        continue;
                    }
                    let byte = haystack[position];
                    if byte.is_ascii() {
                        debug_assert!(self.classifier.set().contains(byte));
                        charge(accounting, limits)?;
                        record_source(accounting, 1, 1, limits)?;
                        return Ok(Some(ScannedCandidate::AsciiMember { position, byte }));
                    }
                    // The ASCII run scanner deliberately stops at a high byte.
                    // Exact byte classes reject it, so retain the fixed
                    // classifier for arbitrary-byte blocks and resume bulk
                    // scanning afterward.
                    if end.saturating_sub(position) < ASCII_WIDE_BYTES {
                        break;
                    }
                }
            }

            charge_many(accounting, ASCII_WIDE_BYTES, limits)?;
            let block_end = position
                .checked_add(ASCII_WIDE_BYTES)
                .ok_or_else(|| accounting_overflow(limits))?;
            let block: &[u8; ASCII_WIDE_BYTES] = haystack[position..block_end]
                .try_into()
                .expect("the candidate scanner checked its wide extent");
            let masks = self.classifier.classify_32(block);
            let decoded = match self.mode {
                CandidateMode::ExactAsciiMembers => ASCII_WIDE_BYTES,
                CandidateMode::UnicodeAsciiMemberOrNonAscii => {
                    usize::try_from(masks.ascii_mask().count_ones())
                        .expect("a 32-bit ASCII lane count fits usize")
                }
            };
            record_source(accounting, ASCII_WIDE_BYTES, decoded, limits)?;
            let candidates = match self.mode {
                CandidateMode::ExactAsciiMembers => masks.member_mask(),
                CandidateMode::UnicodeAsciiMemberOrNonAscii => {
                    masks.member_mask() | !masks.ascii_mask()
                }
            };
            if candidates != 0 {
                let offset = usize::try_from(candidates.trailing_zeros())
                    .expect("a 32-bit candidate lane fits usize");
                let candidate_position = position
                    .checked_add(offset)
                    .ok_or_else(|| accounting_overflow(limits))?;
                let bit = 1_u32
                    .checked_shl(u32::try_from(offset).expect("wide lane fits u32"))
                    .expect("a wide candidate lane is below 32");
                if masks.member_mask() & bit != 0 {
                    charge(accounting, limits)?;
                    record_source(accounting, 1, 0, limits)?;
                    return Ok(Some(ScannedCandidate::AsciiMember {
                        position: candidate_position,
                        byte: block[offset],
                    }));
                }
                return Ok(Some(ScannedCandidate::NonAscii {
                    position: candidate_position,
                }));
            }
            position = block_end;
            fixed_block_proved = true;
        }

        if end.saturating_sub(position) >= ASCII_NARROW_BYTES {
            charge_many(accounting, ASCII_NARROW_BYTES, limits)?;
            let block_end = position
                .checked_add(ASCII_NARROW_BYTES)
                .ok_or_else(|| accounting_overflow(limits))?;
            let block: &[u8; ASCII_NARROW_BYTES] = haystack[position..block_end]
                .try_into()
                .expect("the candidate scanner checked its narrow extent");
            let masks = self.classifier.classify_16(block);
            let decoded = match self.mode {
                CandidateMode::ExactAsciiMembers => ASCII_NARROW_BYTES,
                CandidateMode::UnicodeAsciiMemberOrNonAscii => {
                    usize::try_from(masks.ascii_mask().count_ones())
                        .expect("a 16-bit ASCII lane count fits usize")
                }
            };
            record_source(accounting, ASCII_NARROW_BYTES, decoded, limits)?;
            let candidates = match self.mode {
                CandidateMode::ExactAsciiMembers => masks.member_mask(),
                CandidateMode::UnicodeAsciiMemberOrNonAscii => {
                    masks.member_mask() | !masks.ascii_mask()
                }
            };
            if candidates != 0 {
                let offset = usize::try_from(candidates.trailing_zeros())
                    .expect("a 16-bit candidate lane fits usize");
                let candidate_position = position
                    .checked_add(offset)
                    .ok_or_else(|| accounting_overflow(limits))?;
                let bit = 1_u16
                    .checked_shl(u32::try_from(offset).expect("narrow lane fits u32"))
                    .expect("a narrow candidate lane is below 16");
                if masks.member_mask() & bit != 0 {
                    charge(accounting, limits)?;
                    record_source(accounting, 1, 0, limits)?;
                    return Ok(Some(ScannedCandidate::AsciiMember {
                        position: candidate_position,
                        byte: block[offset],
                    }));
                }
                return Ok(Some(ScannedCandidate::NonAscii {
                    position: candidate_position,
                }));
            }
            position = block_end;
        }

        while position < end {
            if let Some(candidate) =
                self.scalar_candidate(haystack, position, accounting, limits)?
            {
                return Ok(Some(candidate));
            }
            position = position
                .checked_add(1)
                .ok_or_else(|| accounting_overflow(limits))?;
        }
        Ok(None)
    }

    fn scalar_candidate(
        &self,
        haystack: &[u8],
        position: usize,
        accounting: &mut Accounting,
        limits: SearchLimits,
    ) -> Result<Option<ScannedCandidate>, Error> {
        charge(accounting, limits)?;
        let byte = haystack[position];
        let decoded =
            usize::from(matches!(self.mode, CandidateMode::ExactAsciiMembers) || byte.is_ascii());
        record_source(accounting, 1, decoded, limits)?;
        if self.classifier.set().contains(byte) {
            return Ok(Some(ScannedCandidate::AsciiMember { position, byte }));
        }
        if matches!(self.mode, CandidateMode::UnicodeAsciiMemberOrNonAscii) && !byte.is_ascii() {
            return Ok(Some(ScannedCandidate::NonAscii { position }));
        }
        Ok(None)
    }
}

impl BoundaryCursor {
    const fn new(run_start: usize, run_end: usize) -> Self {
        Self {
            position: run_start,
            units: 0,
            run_end,
            done: false,
        }
    }

    fn next(
        &mut self,
        plan: &Plan,
        haystack: &[u8],
        accounting: &mut Accounting,
        limits: SearchLimits,
    ) -> Result<Option<BoundaryPoint>, Error> {
        while !self.done {
            let point = BoundaryPoint {
                byte: self.position,
                units: self.units,
            };
            if self.position == self.run_end {
                self.done = true;
            } else {
                let width = plan.known_member_width(haystack, self.position, self.run_end);
                charge(accounting, limits)?;
                record_source(accounting, width, 1, limits)?;
                self.position = self
                    .position
                    .checked_add(width)
                    .ok_or_else(|| accounting_overflow(limits))?;
                self.units = self
                    .units
                    .checked_add(1)
                    .ok_or_else(|| accounting_overflow(limits))?;
            }
            charge(accounting, limits)?;
            if plan.is_word_boundary(haystack, point.byte) {
                return Ok(Some(point));
            }
        }
        Ok(None)
    }
}

impl Inspection<'_> {
    pub(crate) const fn planner_work(self) -> u64 {
        self.planner_work
    }

    pub(crate) const fn storage_bytes(self) -> usize {
        self.storage_bytes
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one transactional build keeps class ownership, dispatch, and exact optional allocation together"
    )]
    pub(crate) fn build(self) -> Result<Plan, crate::BuildError> {
        let class = match self.class {
            InspectedClass::Bytes(class) => {
                let mut words = [0_u64; 4];
                for range in class.ranges() {
                    set_byte_range(&mut words, range.start(), range.end());
                }
                ClassMatcher::Bytes(words)
            }
            InspectedClass::Unicode(class) => {
                let mut ranges = ExactVec::try_with_capacity(class.ranges().len()).map_err(
                    |error| match error {
                        CopyError::LayoutOverflow => crate::BuildError::InternalInvariant(
                            "bounded word-class Unicode range layout overflowed",
                        ),
                        CopyError::AllocationFailed => crate::BuildError::AllocationFailed {
                            structure: "bounded word-class Unicode ranges",
                            additional: class.ranges().len(),
                        },
                    },
                )?;
                let mut ascii_words = [0_u64; 2];
                for range in class.ranges() {
                    ranges
                        .try_push(ScalarRange {
                            start: range.start(),
                            end: range.end(),
                        })
                        .map_err(|_| {
                            crate::BuildError::InternalInvariant(
                                "exact Unicode range owner exhausted its admitted capacity",
                            )
                        })?;
                    set_unicode_ascii_range(&mut ascii_words, range.start(), range.end());
                }
                ClassMatcher::Unicode {
                    ascii_words,
                    ranges,
                }
            }
        };
        let candidate_scanner = match (self.candidate_mode, &class) {
            (None, _) => None,
            (Some(CandidateMode::ExactAsciiMembers), ClassMatcher::Bytes(words)) => {
                if words[2] != 0 || words[3] != 0 {
                    return Err(crate::BuildError::InternalInvariant(
                        "exact-ASCII candidate scanner retained a high-byte class member",
                    ));
                }
                let members = AsciiByteSet::from_words([words[0], words[1]]);
                let classifier = self
                    .dispatch
                    .ascii_byte_set_classifier(members, DispatchPolicy::Auto)
                    .expect("automatic ASCII classifier dispatch retains a scalar fallback");
                let member_words = members.words();
                let nonmember_scanner = self
                    .dispatch
                    .ascii_byte_set_run_scanner(
                        AsciiByteSet::from_words([!member_words[0], !member_words[1]]),
                        DispatchPolicy::Auto,
                    )
                    .expect("automatic ASCII run dispatch retains a scalar fallback");
                let nonmember_scanner = ExactBoxOrUsize::try_from_boxed(nonmember_scanner)
                    .map_err(|error| match error {
                        CopyError::LayoutOverflow => crate::BuildError::InternalInvariant(
                            "bounded word-class run-scanner owner layout overflowed",
                        ),
                        CopyError::AllocationFailed => crate::BuildError::AllocationFailed {
                            structure: "bounded word-class run-scanner owner",
                            additional: 1,
                        },
                    })?;
                Some(CandidateScanner {
                    classifier,
                    nonmember_scanner,
                    mode: CandidateMode::ExactAsciiMembers,
                })
            }
            (
                Some(CandidateMode::UnicodeAsciiMemberOrNonAscii),
                ClassMatcher::Unicode { ascii_words, .. },
            ) => {
                let classifier = self
                    .dispatch
                    .ascii_byte_set_classifier(
                        AsciiByteSet::from_words(*ascii_words),
                        DispatchPolicy::Auto,
                    )
                    .expect("automatic ASCII classifier dispatch retains a scalar fallback");
                Some(CandidateScanner {
                    classifier,
                    nonmember_scanner: ExactBoxOrUsize::try_from_usize(0)
                        .expect("zero is an exactly representable inline scanner tag"),
                    mode: CandidateMode::UnicodeAsciiMemberOrNonAscii,
                })
            }
            (Some(_), _) => {
                return Err(crate::BuildError::InternalInvariant(
                    "bounded word-class candidate mode differs from its class representation",
                ));
            }
        };
        Ok(Plan {
            mode: self.mode,
            class,
            candidate_scanner,
            minimum_units: self.minimum_units,
            maximum_units: self.maximum_units,
            storage_bytes: self.storage_bytes,
        })
    }
}

impl Plan {
    #[allow(
        clippy::unused_self,
        reason = "the facade obtains the runtime identity from the retained plan variant"
    )]
    pub(crate) const fn plan_id(&self) -> &'static str {
        PLAN_ID
    }

    pub(crate) const fn storage_bytes(&self) -> usize {
        self.storage_bytes
    }

    pub(crate) fn find_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, Accounting), Error> {
        self.search_window(haystack, window, limits, true)
    }

    pub(crate) fn shortest_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, Accounting), Error> {
        self.search_window(haystack, window, limits, false)
            .map(|(matched, accounting)| (matched.map(Match::end), accounting))
    }

    fn search_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
        greedy: bool,
    ) -> Result<(Option<Match>, Accounting), Error> {
        validate_window(haystack, window)?;
        let mut accounting = Accounting {
            work: 0,
            bytes_examined: 0,
            scalars_decoded: 0,
        };
        let mut position = window.start();
        while position < window.end() {
            let Some((run_start, mut width, run_word)) = (if self.candidate_scanner.is_some() {
                self.next_scanned_member(haystack, position, window.end(), &mut accounting, limits)?
            } else {
                let (admitted, width, run_word) =
                    self.classify_unit(haystack, position, window.end(), &mut accounting, limits)?;
                if admitted {
                    Some((position, width, run_word))
                } else {
                    position = position
                        .checked_add(width)
                        .ok_or_else(|| accounting_overflow(limits))?;
                    None
                }
            }) else {
                if self.candidate_scanner.is_some() {
                    break;
                }
                continue;
            };
            position = run_start;
            if let Some(maximum_units) = self.maximum_units {
                let (matched, run_end) = self.search_bounded_class_run(
                    haystack,
                    run_start,
                    window.end(),
                    maximum_units,
                    &mut accounting,
                    limits,
                    greedy,
                )?;
                if let Some(matched) = matched {
                    return Ok((Some(matched), accounting));
                }
                position = run_end;
                continue;
            }

            let mut run_units = 0_usize;
            let mut homogeneous_wordness = true;
            loop {
                run_units = run_units.checked_add(1).ok_or(Error::WorkLimitExceeded {
                    needed: u64::MAX,
                    limit: limits.max_work,
                })?;
                position = position
                    .checked_add(width)
                    .ok_or(Error::WorkLimitExceeded {
                        needed: u64::MAX,
                        limit: limits.max_work,
                    })?;
                if position >= window.end() {
                    break;
                }
                let (next_admitted, next_width, next_word) =
                    self.classify_unit(haystack, position, window.end(), &mut accounting, limits)?;
                if !next_admitted {
                    break;
                }
                homogeneous_wordness &= next_word == run_word;
                width = next_width;
            }

            if run_units >= self.minimum_units
                && let Some(matched) = self.search_class_run(
                    haystack,
                    run_start,
                    position,
                    run_units,
                    homogeneous_wordness,
                    &mut accounting,
                    limits,
                    greedy,
                )?
            {
                return Ok((Some(matched), accounting));
            }
        }
        Ok((None, accounting))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "two monotone bounded cursors share the caller's exact search ledger"
    )]
    fn search_bounded_class_run(
        &self,
        haystack: &[u8],
        run_start: usize,
        window_end: usize,
        maximum_units: usize,
        accounting: &mut Accounting,
        limits: SearchLimits,
        greedy: bool,
    ) -> Result<(Option<Match>, usize), Error> {
        let mut starts = ScanningBoundaryCursor::new(run_start, window_end);
        let mut start = next_member_boundary(&mut starts, self, haystack, accounting, limits)?;
        if start.is_none() {
            return Ok((None, starts.run_end()));
        }
        let mut ends = ScanningBoundaryCursor::new(run_start, window_end);
        let mut end = ends.next(self, haystack, accounting, limits)?;
        if !greedy {
            while let Some(current_end) = end {
                let Some(latest_start) = current_end.point.units.checked_sub(self.minimum_units)
                else {
                    end = ends.next(self, haystack, accounting, limits)?;
                    continue;
                };
                let earliest_start = current_end.point.units.saturating_sub(maximum_units);
                while start.is_some_and(|candidate| candidate.point.units < earliest_start) {
                    start = next_member_boundary(&mut starts, self, haystack, accounting, limits)?;
                }
                let Some(candidate) = start else {
                    return Ok((None, starts.run_end().max(ends.run_end())));
                };
                if candidate.point.units <= latest_start {
                    return Ok((
                        Some(Match {
                            start: candidate.point.byte,
                            end: current_end.point.byte,
                        }),
                        current_end.point.byte,
                    ));
                }
                end = ends.next(self, haystack, accounting, limits)?;
            }
            return Ok((None, starts.run_end().max(ends.run_end())));
        }

        while let Some(current_start) = start {
            let minimum_end = current_start.point.units.saturating_add(self.minimum_units);
            let maximum_end = current_start.point.units.saturating_add(maximum_units);
            while end.is_some_and(|candidate| candidate.point.units < minimum_end) {
                end = ends.next(self, haystack, accounting, limits)?;
            }
            let Some(first_end) = end else {
                return Ok((None, ends.run_end()));
            };
            if first_end.point.units > maximum_end {
                if !first_end.has_member_after {
                    // This is the terminal run boundary and there were no
                    // intervening boundaries, so no later start exists.
                    return Ok((None, ends.run_end()));
                }
                start = next_member_boundary(&mut starts, self, haystack, accounting, limits)?;
                continue;
            }

            let selected = ends.last_boundary_through(
                self,
                haystack,
                maximum_end,
                first_end.point,
                accounting,
                limits,
            )?;
            return Ok((
                Some(Match {
                    start: current_start.point.byte,
                    end: selected.byte,
                }),
                selected.byte,
            ));
        }
        Ok((None, starts.run_end().max(ends.run_end())))
    }

    fn next_scanned_member(
        &self,
        haystack: &[u8],
        mut position: usize,
        end: usize,
        accounting: &mut Accounting,
        limits: SearchLimits,
    ) -> Result<Option<(usize, usize, bool)>, Error> {
        let scanner = self
            .candidate_scanner
            .as_ref()
            .expect("the scanned path retains a candidate classifier");
        loop {
            let Some(candidate) = scanner.next(haystack, position, end, accounting, limits)? else {
                return Ok(None);
            };
            match candidate {
                ScannedCandidate::AsciiMember { position, byte } => {
                    return Ok(Some((position, 1, is_ascii_word(byte))));
                }
                ScannedCandidate::NonAscii {
                    position: candidate,
                } => {
                    let (admitted, width, word) =
                        self.classify_unit(haystack, candidate, end, accounting, limits)?;
                    if admitted {
                        return Ok(Some((candidate, width, word)));
                    }
                    position = candidate
                        .checked_add(width)
                        .ok_or_else(|| accounting_overflow(limits))?;
                }
            }
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the two monotone cursors share the caller's exact search ledger"
    )]
    fn search_class_run(
        &self,
        haystack: &[u8],
        run_start: usize,
        run_end: usize,
        run_units: usize,
        homogeneous_wordness: bool,
        accounting: &mut Accounting,
        limits: SearchLimits,
        greedy: bool,
    ) -> Result<Option<Match>, Error> {
        if homogeneous_wordness {
            if self
                .maximum_units
                .is_some_and(|maximum| run_units > maximum)
            {
                return Ok(None);
            }
            charge(accounting, limits)?;
            if !self.is_word_boundary(haystack, run_start) {
                return Ok(None);
            }
            charge(accounting, limits)?;
            return Ok(self.is_word_boundary(haystack, run_end).then_some(Match {
                start: run_start,
                end: run_end,
            }));
        }

        let mut starts = BoundaryCursor::new(run_start, run_end);
        let mut candidate = starts.next(self, haystack, accounting, limits)?;
        let mut ends = BoundaryCursor::new(run_start, run_end);

        while let Some(end) = ends.next(self, haystack, accounting, limits)? {
            let Some(latest_start) = end.units.checked_sub(self.minimum_units) else {
                continue;
            };
            let earliest_start = self
                .maximum_units
                .map_or(0, |maximum| end.units.saturating_sub(maximum));
            while candidate.is_some_and(|start| start.units < earliest_start) {
                candidate = starts.next(self, haystack, accounting, limits)?;
            }
            let Some(start) = candidate else {
                return Ok(None);
            };
            if start.units >= run_units || start.units > latest_start {
                continue;
            }
            if !greedy {
                return Ok(Some(Match {
                    start: start.byte,
                    end: end.byte,
                }));
            }

            let final_unit = self.maximum_units.map_or(run_units, |maximum| {
                start.units.saturating_add(maximum).min(run_units)
            });
            let mut selected_end = end.byte;
            while let Some(later) = ends.next(self, haystack, accounting, limits)? {
                if later.units > final_unit {
                    break;
                }
                selected_end = later.byte;
            }
            return Ok(Some(Match {
                start: start.byte,
                end: selected_end,
            }));
        }
        Ok(None)
    }

    fn classify_unit(
        &self,
        haystack: &[u8],
        position: usize,
        end: usize,
        accounting: &mut Accounting,
        limits: SearchLimits,
    ) -> Result<(bool, usize, bool), Error> {
        charge(accounting, limits)?;
        match &self.class {
            ClassMatcher::Bytes(words) => {
                record_source(accounting, 1, 1, limits)?;
                let byte = haystack[position];
                Ok((byte_set_contains(*words, byte), 1, is_ascii_word(byte)))
            }
            ClassMatcher::Unicode {
                ascii_words,
                ranges,
            } => {
                let Some((scalar, width)) = decode_first(&haystack[position..end]) else {
                    record_source(accounting, 1, 0, limits)?;
                    return Ok((false, 1, false));
                };
                record_source(accounting, width, 1, limits)?;
                let admitted = if scalar.is_ascii() {
                    let byte = u8::try_from(u32::from(scalar))
                        .expect("an ASCII scalar fits exactly in one byte");
                    ascii_set_contains(*ascii_words, byte)
                } else {
                    unicode_ranges_contain(ranges, scalar)
                };
                Ok((admitted, width, admitted && is_unicode_word(scalar)))
            }
        }
    }

    fn known_member_width(&self, haystack: &[u8], position: usize, end: usize) -> usize {
        match self.mode {
            BoundaryMode::Ascii => 1,
            BoundaryMode::Unicode => decode_first(&haystack[position..end])
                .map(|(_, width)| width)
                .expect("a retained Unicode class run contains only decoded scalars"),
        }
    }

    fn is_word_boundary(&self, haystack: &[u8], position: usize) -> bool {
        match self.mode {
            BoundaryMode::Ascii => {
                let before = position
                    .checked_sub(1)
                    .and_then(|index| haystack.get(index))
                    .is_some_and(|&byte| is_ascii_word(byte));
                let after = haystack
                    .get(position)
                    .is_some_and(|&byte| is_ascii_word(byte));
                before != after
            }
            BoundaryMode::Unicode => {
                let before = decode_last(&haystack[..position])
                    .is_some_and(|(scalar, _)| is_unicode_word(scalar));
                let after = decode_first(&haystack[position..])
                    .is_some_and(|(scalar, _)| is_unicode_word(scalar));
                before != after
            }
        }
    }
}

/// Inspect one exact root without allocating or retaining borrowed HIR data.
///
/// Unsupported shapes return an ineligible receipt with the exact cumulative
/// planner work retained. Crossing the caller's planner bound is a typed
/// refusal even when the eventual shape would have been unsupported, so every
/// visited node/range remains covered by the published construction budget.
#[allow(
    clippy::too_many_lines,
    reason = "one allocation-free structural proof keeps every shape and range charge adjacent"
)]
pub(crate) fn inspect(
    hir: &Hir,
    dispatch: SimdDispatchContext,
    planner_work_already: u64,
    max_planner_work: u64,
) -> Result<InspectionOutcome<'_>, InspectionError> {
    if planner_work_already > max_planner_work {
        return Err(InspectionError::WorkLimit {
            needed: planner_work_already,
            limit: max_planner_work,
        });
    }
    let mut work = planner_work_already;
    let root = peel_captures(hir, &mut work, max_planner_work)?;
    let HirKind::Concat(parts) = root.kind() else {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    };
    charge_build(
        &mut work,
        u64::try_from(parts.len())
            .map_err(|_| InspectionError::ArithmeticOverflow("concat length"))?,
        max_planner_work,
    )?;
    let [start, repeated, end] = parts.as_slice() else {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    };
    let start = peel_captures(start, &mut work, max_planner_work)?;
    let end = peel_captures(end, &mut work, max_planner_work)?;
    let mode = match (start.kind(), end.kind()) {
        (HirKind::Look(Look::WordAscii), HirKind::Look(Look::WordAscii)) => BoundaryMode::Ascii,
        (HirKind::Look(Look::WordUnicode), HirKind::Look(Look::WordUnicode)) => {
            BoundaryMode::Unicode
        }
        _ => {
            return Ok(InspectionOutcome::Ineligible { planner_work: work });
        }
    };
    let repeated = peel_captures(repeated, &mut work, max_planner_work)?;
    let HirKind::Repetition(repetition) = repeated.kind() else {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    };
    charge_build(&mut work, 1, max_planner_work)?;
    if repetition.min == 0 || !repetition.greedy {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    }
    let minimum_units = usize::try_from(repetition.min)
        .map_err(|_| InspectionError::ArithmeticOverflow("minimum repetition"))?;
    let maximum_units = repetition
        .max
        .map(usize::try_from)
        .transpose()
        .map_err(|_| InspectionError::ArithmeticOverflow("maximum repetition"))?;
    let class = peel_captures(&repetition.sub, &mut work, max_planner_work)?;
    let (inspected, candidate_mode) =
        match (mode, class.kind()) {
            (BoundaryMode::Ascii, HirKind::Class(Class::Bytes(class))) => {
                let range_count = u64::try_from(class.ranges().len())
                    .map_err(|_| InspectionError::ArithmeticOverflow("byte class ranges"))?;
                let (members, ascii_only) = class.ranges().iter().try_fold(
                    (0_u64, true),
                    |(total, ascii_only), range| {
                        let width = u64::from(range.end())
                            .checked_sub(u64::from(range.start()))
                            .and_then(|value| value.checked_add(1))
                            .ok_or(InspectionError::ArithmeticOverflow("byte class members"))?;
                        let total = total
                            .checked_add(width)
                            .ok_or(InspectionError::ArithmeticOverflow("byte class members"))?;
                        Ok::<_, InspectionError>((total, ascii_only && range.end().is_ascii()))
                    },
                )?;
                charge_build(&mut work, range_count, max_planner_work)?;
                charge_build(&mut work, members, max_planner_work)?;
                if !ascii_only {
                    return Ok(InspectionOutcome::Ineligible { planner_work: work });
                }
                (
                    InspectedClass::Bytes(class),
                    Some(CandidateMode::ExactAsciiMembers),
                )
            }
            (BoundaryMode::Unicode, HirKind::Class(Class::Unicode(class))) => {
                let range_count = u64::try_from(class.ranges().len())
                    .map_err(|_| InspectionError::ArithmeticOverflow("Unicode class ranges"))?;
                // One range inspection and one exact retained-range copy.
                let range_work =
                    range_count
                        .checked_mul(2)
                        .ok_or(InspectionError::ArithmeticOverflow(
                            "Unicode class range work",
                        ))?;
                charge_build(&mut work, range_work, max_planner_work)?;
                let ascii_members = class.ranges().iter().try_fold(0_u64, |total, range| {
                    let start = u32::from(range.start());
                    let end = u32::from(range.end()).min(0x7F);
                    if start > end {
                        Ok(total)
                    } else {
                        let width = end
                            .checked_sub(start)
                            .and_then(|value| value.checked_add(1))
                            .ok_or(InspectionError::ArithmeticOverflow(
                                "Unicode ASCII-class members",
                            ))?;
                        total.checked_add(u64::from(width)).ok_or(
                            InspectionError::ArithmeticOverflow("Unicode ASCII-class members"),
                        )
                    }
                })?;
                charge_build(&mut work, ascii_members, max_planner_work)?;
                (
                    InspectedClass::Unicode(class),
                    Some(CandidateMode::UnicodeAsciiMemberOrNonAscii),
                )
            }
            _ => {
                return Ok(InspectionOutcome::Ineligible { planner_work: work });
            }
        };
    if candidate_mode.is_some() {
        charge_build(
            &mut work,
            u64::try_from(ASCII_CLASSIFIER_BUILD_WORK)
                .map_err(|_| InspectionError::ArithmeticOverflow("ASCII classifier work"))?,
            max_planner_work,
        )?;
    }
    if candidate_mode == Some(CandidateMode::ExactAsciiMembers) {
        charge_build(
            &mut work,
            u64::try_from(ASCII_RUN_SCANNER_BUILD_WORK)
                .map_err(|_| InspectionError::ArithmeticOverflow("ASCII run-scanner work"))?,
            max_planner_work,
        )?;
    }
    let range_bytes = match inspected {
        InspectedClass::Bytes(_) => 0,
        InspectedClass::Unicode(class) => class
            .ranges()
            .len()
            .checked_mul(core::mem::size_of::<ScalarRange>())
            .ok_or(InspectionError::ArithmeticOverflow(
                "Unicode class retained bytes",
            ))?,
    };
    let run_scanner_bytes = usize::from(candidate_mode == Some(CandidateMode::ExactAsciiMembers))
        .checked_mul(core::mem::size_of::<AsciiByteSetRunScanner>())
        .ok_or(InspectionError::ArithmeticOverflow(
            "bounded word-class run-scanner storage",
        ))?;
    let storage_bytes = core::mem::size_of::<Plan>()
        .checked_add(range_bytes)
        .and_then(|bytes| bytes.checked_add(run_scanner_bytes))
        .ok_or(InspectionError::ArithmeticOverflow(
            "bounded word-class plan storage",
        ))?;
    Ok(InspectionOutcome::Eligible(Inspection {
        mode,
        class: inspected,
        candidate_mode,
        dispatch,
        minimum_units,
        maximum_units,
        planner_work: work,
        storage_bytes,
    }))
}

fn peel_captures<'a>(
    mut hir: &'a Hir,
    work: &mut u64,
    limit: u64,
) -> Result<&'a Hir, InspectionError> {
    loop {
        charge_build(work, 1, limit)?;
        let HirKind::Capture(capture) = hir.kind() else {
            return Ok(hir);
        };
        hir = &capture.sub;
    }
}

fn charge_build(work: &mut u64, amount: u64, limit: u64) -> Result<(), InspectionError> {
    let needed = work
        .checked_add(amount)
        .ok_or(InspectionError::ArithmeticOverflow("planner work"))?;
    if needed > limit {
        return Err(InspectionError::WorkLimit { needed, limit });
    }
    *work = needed;
    Ok(())
}

fn next_member_boundary(
    cursor: &mut ScanningBoundaryCursor,
    plan: &Plan,
    haystack: &[u8],
    accounting: &mut Accounting,
    limits: SearchLimits,
) -> Result<Option<ScanningBoundaryPoint>, Error> {
    loop {
        let Some(point) = cursor.next(plan, haystack, accounting, limits)? else {
            return Ok(None);
        };
        if point.has_member_after {
            return Ok(Some(point));
        }
    }
}

fn validate_window(haystack: &[u8], window: SearchWindow) -> Result<(), Error> {
    if window.start() > window.end() || window.end() > haystack.len() {
        return Err(Error::InvalidWindow {
            start: window.start(),
            end: window.end(),
            haystack_len: haystack.len(),
        });
    }
    Ok(())
}

fn charge(accounting: &mut Accounting, limits: SearchLimits) -> Result<(), Error> {
    charge_many(accounting, 1, limits)
}

fn charge_many(
    accounting: &mut Accounting,
    amount: usize,
    limits: SearchLimits,
) -> Result<(), Error> {
    let amount = u64::try_from(amount).map_err(|_| accounting_overflow(limits))?;
    let needed = accounting
        .work
        .checked_add(amount)
        .ok_or_else(|| accounting_overflow(limits))?;
    if needed > limits.max_work {
        return Err(Error::WorkLimitExceeded {
            needed,
            limit: limits.max_work,
        });
    }
    accounting.work = needed;
    Ok(())
}

fn record_source(
    accounting: &mut Accounting,
    bytes: usize,
    scalars: usize,
    limits: SearchLimits,
) -> Result<(), Error> {
    accounting.bytes_examined = accounting
        .bytes_examined
        .checked_add(bytes)
        .ok_or_else(|| accounting_overflow(limits))?;
    accounting.scalars_decoded = accounting
        .scalars_decoded
        .checked_add(scalars)
        .ok_or_else(|| accounting_overflow(limits))?;
    Ok(())
}

const fn accounting_overflow(limits: SearchLimits) -> Error {
    Error::WorkLimitExceeded {
        needed: u64::MAX,
        limit: limits.max_work,
    }
}

fn set_byte_range(words: &mut [u64; 4], start: u8, end: u8) {
    let mut byte = start;
    loop {
        let word = usize::from(byte) / 64;
        let bit = usize::from(byte) % 64;
        words[word] |= 1_u64 << bit;
        if byte == end {
            break;
        }
        byte = byte
            .checked_add(1)
            .expect("a nonterminal byte-class member is below 255");
    }
}

fn set_unicode_ascii_range(words: &mut [u64; 2], start: char, end: char) {
    let start = u32::from(start);
    let end = u32::from(end).min(0x7F);
    if start > end {
        return;
    }
    for codepoint in start..=end {
        let byte = u8::try_from(codepoint).expect("the range was clipped to ASCII");
        let word = usize::from(byte) / 64;
        let bit = usize::from(byte) % 64;
        words[word] |= 1_u64 << bit;
    }
}

fn byte_set_contains(words: [u64; 4], byte: u8) -> bool {
    let word = usize::from(byte) / 64;
    let bit = usize::from(byte) % 64;
    words[word] & (1_u64 << bit) != 0
}

fn ascii_set_contains(words: [u64; 2], byte: u8) -> bool {
    let word = usize::from(byte) / 64;
    let bit = usize::from(byte) % 64;
    words[word] & (1_u64 << bit) != 0
}

fn unicode_ranges_contain(ranges: &[ScalarRange], scalar: char) -> bool {
    let index = ranges.partition_point(|range| range.end < scalar);
    ranges.get(index).is_some_and(|range| range.start <= scalar)
}

fn is_ascii_word(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn is_unicode_word(scalar: char) -> bool {
    if scalar.is_ascii() {
        return scalar == '_' || scalar.is_ascii_alphanumeric();
    }
    regex_syntax::try_is_word_character(scalar)
        .expect("fre enables regex-syntax's Unicode Perl tables")
}

fn decode_first(bytes: &[u8]) -> Option<(char, usize)> {
    let first = *bytes.first()?;
    if first.is_ascii() {
        return Some((char::from(first), 1));
    }
    let width = match first {
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => return None,
    };
    let scalar = core::str::from_utf8(bytes.get(..width)?)
        .ok()?
        .chars()
        .next()?;
    Some((scalar, width))
}

fn decode_last(bytes: &[u8]) -> Option<(char, usize)> {
    let mut start = bytes.len().checked_sub(1)?;
    let lower = bytes.len().saturating_sub(4);
    while start > lower && matches!(bytes[start], 0x80..=0xBF) {
        start = start.checked_sub(1)?;
    }
    let (scalar, width) = decode_first(&bytes[start..])?;
    (start.checked_add(width) == Some(bytes.len())).then_some((scalar, width))
}

#[cfg(test)]
mod tests {
    use fre_kernels::SimdDispatchContext;
    use regex_syntax::ParserBuilder;

    use super::{
        ASCII_CLASSIFIER_BUILD_WORK, ASCII_RUN_SCANNER_BUILD_WORK, BULK_SKIP_MIN_BYTES,
        CandidateMode, InspectionError, InspectionOutcome, PLAN_ID, inspect,
    };
    use crate::{
        BuildError, BuildLimits, PlanSelection, PortableBuilder, SearchLimits, SearchWindow,
    };

    fn plan(pattern: &str, unicode: bool) -> super::Plan {
        let hir = ParserBuilder::new()
            .unicode(unicode)
            .utf8(false)
            .build()
            .parse(pattern)
            .expect("test pattern");
        let InspectionOutcome::Eligible(inspection) =
            inspect(&hir, SimdDispatchContext::capture(), 0, u64::MAX).expect("inspection")
        else {
            panic!("eligible shape");
        };
        inspection.build().expect("plan build")
    }

    #[test]
    fn exact_shape_and_existing_unbounded_word_shape_are_structurally_visible() {
        let bounded = plan(r"(?-u:\b[A-Za-z]{3,9}\b)", false);
        assert_eq!(bounded.plan_id(), PLAN_ID);
        let unicode = plan(r"\b\p{L}{2,8}\b", true);
        assert_eq!(unicode.plan_id(), PLAN_ID);
        // The facade orders the established exact-word route first, but this
        // inspector remains a complete proof for arbitrary unbounded classes.
        let unbounded = plan(r"\b\p{L}{2,}\b", true);
        assert_eq!(unbounded.plan_id(), PLAN_ID);
    }

    #[test]
    fn mixed_wordness_uses_leftmost_start_and_greedy_boundary_end() {
        let plan = plan(r"(?-u:\b[A/_-]{2,5}\b)", false);
        let haystack = b" A-A/A.";
        let matched = plan
            .find_window(
                haystack,
                SearchWindow::full(haystack),
                SearchLimits::unlimited(),
            )
            .expect("search")
            .0
            .expect("match");
        assert_eq!(matched.range(), 1..6);
    }

    #[test]
    fn malformed_unicode_bytes_are_nonmembers_and_nonword_context() {
        let plan = plan(r"\b\p{L}{2,8}\b", true);
        let haystack = [0xFF, b'a', b'b', 0xCE, 0xFF, b'c', b'd'];
        let first = plan
            .find_window(
                &haystack,
                SearchWindow::full(&haystack),
                SearchLimits::unlimited(),
            )
            .expect("search")
            .0
            .expect("first match");
        assert_eq!(first.range(), 1..3);
    }

    #[test]
    fn classifier_admission_build_work_and_high_byte_refusal_are_exact() {
        let parse = |pattern: &str| {
            ParserBuilder::new()
                .unicode(false)
                .utf8(false)
                .build()
                .parse(pattern)
                .expect("test pattern")
        };
        let ascii_hir = parse(r"(?-u:\b[A-B]{1,3}\b)");
        let high_hir = parse(r"(?-u:\b[\x80-\x81]{1,3}\b)");
        let InspectionOutcome::Eligible(ascii) =
            inspect(&ascii_hir, SimdDispatchContext::capture(), 0, u64::MAX)
                .expect("ASCII inspection")
        else {
            panic!("ASCII class should be eligible");
        };
        let high = inspect(&high_hir, SimdDispatchContext::capture(), 0, u64::MAX)
            .expect("high-byte inspection");
        assert!(matches!(high, InspectionOutcome::Ineligible { .. }));
        assert_eq!(ascii.candidate_mode, Some(CandidateMode::ExactAsciiMembers));
        assert_eq!(
            ascii.planner_work(),
            high.planner_work()
                .checked_add(u64::try_from(ASCII_CLASSIFIER_BUILD_WORK).unwrap())
                .unwrap()
                .checked_add(u64::try_from(ASCII_RUN_SCANNER_BUILD_WORK).unwrap())
                .unwrap()
        );

        let ascii = ascii.build().expect("ASCII plan");
        assert!(
            ascii
                .candidate_scanner
                .as_ref()
                .is_some_and(|scanner| scanner.nonmember_scanner.boxed().is_some())
        );
        let high = PortableBuilder::new(r"(?-u:\b[\x80-\x81]{1,3}\b)")
            .unicode(false)
            .plan_selection(PlanSelection::Auto)
            .build()
            .expect("high-byte fallback plan");
        assert_ne!(high.runtime_implementation_id(), PLAN_ID);
    }

    #[test]
    fn ineligible_inspection_retains_prior_work_and_facade_composes_it() {
        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse("needle")
            .expect("test pattern");
        let local =
            inspect(&hir, SimdDispatchContext::capture(), 0, u64::MAX).expect("local inspection");
        assert!(matches!(local, InspectionOutcome::Ineligible { .. }));
        let local_work = local.planner_work();
        assert!(local_work > 0);

        let prior = 37_u64;
        let cumulative = inspect(&hir, SimdDispatchContext::capture(), prior, u64::MAX)
            .expect("cumulative inspection");
        assert_eq!(
            cumulative.planner_work(),
            prior.checked_add(local_work).unwrap()
        );
        let needed = cumulative.planner_work();
        assert!(matches!(
            inspect(
                &hir,
                SimdDispatchContext::capture(),
                prior,
                needed - 1
            ),
            Err(InspectionError::WorkLimit {
                needed: actual,
                limit,
            }) if actual == needed && limit == needed - 1
        ));

        let regex = PortableBuilder::new("needle")
            .unicode(false)
            .plan_selection(PlanSelection::Auto)
            .build()
            .expect("facade fallback");
        let facade_work = regex.build_report().planner_work;
        assert!(facade_work >= local_work);
        let exact = PortableBuilder::new("needle")
            .unicode(false)
            .plan_selection(PlanSelection::Auto)
            .limits(BuildLimits {
                max_planner_work: facade_work,
                ..BuildLimits::default()
            })
            .build()
            .expect("exact cumulative planner limit");
        assert_eq!(exact.build_report().planner_work, facade_work);
        assert!(matches!(
            PortableBuilder::new("needle")
                .unicode(false)
                .plan_selection(PlanSelection::Auto)
                .limits(BuildLimits {
                    max_planner_work: facade_work - 1,
                    ..BuildLimits::default()
                })
                .build(),
            Err(BuildError::PlannerWorkLimit {
                needed,
                limit,
            }) if needed == facade_work && limit == facade_work - 1
        ));
    }

    #[test]
    fn scalar_crossover_and_wide_absent_scans_have_exact_ledgers() {
        let plan = plan(r"(?-u:\b[A-B]{1,3}\b)", false);

        let absent = vec![b'-'; 64];
        let (matched, accounting) = plan
            .find_window(
                &absent,
                SearchWindow::full(&absent),
                SearchLimits::unlimited(),
            )
            .expect("absent scan");
        assert_eq!(matched, None);
        assert_eq!(accounting.work(), 64);
        assert_eq!(accounting.bytes_examined(), 64);
        assert_eq!(accounting.scalars_decoded(), 64);
        assert!(
            plan.find_window(
                &absent,
                SearchWindow::full(&absent),
                SearchLimits {
                    max_work: accounting.work(),
                    max_scratch_bytes: 0,
                },
            )
            .is_ok()
        );
        assert!(matches!(
            plan.find_window(
                &absent,
                SearchWindow::full(&absent),
                SearchLimits {
                    max_work: accounting.work() - 1,
                    max_scratch_bytes: 0,
                },
            ),
            Err(crate::UnicodeWordRunError::WorkLimitExceeded {
                needed: 64,
                limit: 63,
            })
        ));

        let mut near = vec![b'-'; 64];
        near[3] = b'A';
        let (matched, accounting) = plan
            .find_window(&near, SearchWindow::full(&near), SearchLimits::unlimited())
            .expect("scalar-prefix candidate");
        assert_eq!(matched.expect("near match").range(), 3..4);
        assert_eq!(accounting.work(), 10);
        assert_eq!(accounting.bytes_examined(), 7);
        assert_eq!(accounting.scalars_decoded(), 7);

        let mut wide = vec![b'-'; 64];
        wide[20] = b'A';
        let (matched, accounting) = plan
            .find_window(&wide, SearchWindow::full(&wide), SearchLimits::unlimited())
            .expect("wide candidate");
        assert_eq!(matched.expect("wide match").range(), 20..21);
        assert_eq!(accounting.work(), 47);
        assert_eq!(accounting.bytes_examined(), 44);
        assert_eq!(accounting.scalars_decoded(), 43);
        assert!(matches!(
            plan.find_window(
                &wide,
                SearchWindow::full(&wide),
                SearchLimits {
                    max_work: accounting.work() - 1,
                    max_scratch_bytes: 0,
                },
            ),
            Err(crate::UnicodeWordRunError::WorkLimitExceeded {
                needed: 47,
                limit: 46,
            })
        ));
    }

    #[test]
    fn long_ascii_rejections_use_one_logical_bulk_span_and_resume_after_high_bytes() {
        let plan = plan(r"(?-u:\b[A-B]{1,3}\b)", false);
        let length = BULK_SKIP_MIN_BYTES
            .checked_mul(64)
            .and_then(|length| length.checked_add(3))
            .unwrap();

        let absent = vec![b'-'; length];
        let (matched, accounting) = plan
            .find_window(
                &absent,
                SearchWindow::full(&absent),
                SearchLimits::unlimited(),
            )
            .expect("long absent bulk scan");
        assert_eq!(matched, None);
        assert_eq!(accounting.work(), u64::try_from(length).unwrap());
        assert_eq!(accounting.bytes_examined(), length);
        assert_eq!(accounting.scalars_decoded(), length);
        assert!(matches!(
            plan.find_window(
                &absent,
                SearchWindow::full(&absent),
                SearchLimits {
                    max_work: accounting.work() - 1,
                    max_scratch_bytes: 0,
                },
            ),
            Err(crate::UnicodeWordRunError::WorkLimitExceeded {
                needed,
                limit,
            }) if needed == u64::try_from(length).unwrap()
                && limit == u64::try_from(length - 1).unwrap()
        ));

        let candidate = length - 17;
        let mut sparse = absent;
        sparse[candidate] = b'A';
        let (matched, accounting) = plan
            .find_window(
                &sparse,
                SearchWindow::full(&sparse),
                SearchLimits::unlimited(),
            )
            .expect("long sparse bulk scan");
        assert_eq!(
            matched.expect("long sparse candidate").range(),
            candidate..candidate + 1
        );
        assert_eq!(
            accounting.work(),
            u64::try_from(candidate.checked_add(7).unwrap()).unwrap()
        );
        assert_eq!(
            accounting.bytes_examined(),
            candidate.checked_add(4).unwrap()
        );
        assert_eq!(
            accounting.scalars_decoded(),
            candidate.checked_add(4).unwrap()
        );

        sparse[128..160].fill(0xFF);
        let (matched, high_accounting) = plan
            .find_window(
                &sparse,
                SearchWindow::full(&sparse),
                SearchLimits::unlimited(),
            )
            .expect("bulk scan around arbitrary bytes");
        assert_eq!(
            matched.expect("candidate after arbitrary bytes").range(),
            candidate..candidate + 1
        );
        assert_eq!(high_accounting.work(), accounting.work());
        assert_eq!(
            high_accounting.bytes_examined(),
            accounting.bytes_examined()
        );
        assert_eq!(
            high_accounting.scalars_decoded(),
            accounting.scalars_decoded()
        );
    }

    #[test]
    fn unicode_vector_candidates_include_high_bytes_and_decode_malformed_normally() {
        let plan = plan(r"\b\p{Greek}{2,3}\b", true);
        let mut source = vec![b'-'; 64];
        source[20..24].copy_from_slice("αβ".as_bytes());
        let (matched, accounting) = plan
            .find_window(
                &source,
                SearchWindow::full(&source),
                SearchLimits::unlimited(),
            )
            .expect("Unicode vector candidate");
        assert_eq!(matched.expect("Greek match").range(), 20..24);
        assert_eq!(accounting.work(), 49);
        assert_eq!(accounting.bytes_examined(), 49);
        assert_eq!(accounting.scalars_decoded(), 41);

        source[12] = 0xFF;
        let (matched, malformed_accounting) = plan
            .find_window(
                &source,
                SearchWindow::full(&source),
                SearchLimits::unlimited(),
            )
            .expect("malformed candidate recovery");
        assert_eq!(
            matched.expect("Greek match after malformed byte").range(),
            20..24
        );
        assert!(malformed_accounting.work() > accounting.work());
        assert!(
            plan.find_window(
                &source,
                SearchWindow::full(&source),
                SearchLimits {
                    max_work: malformed_accounting.work(),
                    max_scratch_bytes: 0,
                },
            )
            .is_ok()
        );
        assert!(matches!(
            plan.find_window(
                &source,
                SearchWindow::full(&source),
                SearchLimits {
                    max_work: malformed_accounting.work() - 1,
                    max_scratch_bytes: 0,
                },
            ),
            Err(crate::UnicodeWordRunError::WorkLimitExceeded { .. })
        ));
    }
}
