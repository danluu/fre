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
    ASCII_WIDE_BYTES, AsciiByteSet, AsciiByteSetClassifier, AsciiByteSetRunScanner,
    BYTE_SET_BLOCK_BYTES, BYTE_SET_CLASSIFIER_BUILD_WORK, ByteSet256, ByteSetClassifier,
    DispatchPolicy, SimdDispatchContext,
};
use regex_syntax::hir::{Class, Hir, HirKind, Look};

use crate::{
    Match, SearchLimits, SearchWindow,
    unicode_word_run::{Accounting, Error},
};

pub(crate) const PLAN_ID: &str = "bounded-word-class-linear-full-byte-v4";

/// Pointwise checks stay cheaper than entering a fixed-width classifier when
/// a candidate is close to the current cursor. This constant is independent
/// of the regex and haystack.
const CANDIDATE_SCALAR_PREFIX_BYTES: usize = 8;

/// A run-scanner call must be able to replace at least two wide classifier
/// iterations. This keeps short and dense searches on their existing path
/// while amortizing one bulk call over genuinely reusable rejection work.
const BULK_SKIP_MIN_BYTES: usize = ASCII_WIDE_BYTES * 2;

// The canonical Unicode unbounded search consumes at most six logical work
// units per source byte plus its two endpoint checks. Keeping a slightly wider
// source-independent envelope preserves the incumbent's overflow behavior on
// theoretical slices too large for its receipt counters.
const ORDINARY_UNMETERED_WORK_FACTOR: usize = 8;
const ORDINARY_UNMETERED_FIXED_WORK: usize = 8;

#[cfg(test)]
pub(crate) mod ordinary_is_match_probe {
    use core::cell::Cell;

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub(crate) struct Counts {
        pub(crate) calls: usize,
        pub(crate) candidate_scans: usize,
        pub(crate) unit_classifications: usize,
    }

    std::thread_local! {
        static COUNTS: Cell<Counts> = const { Cell::new(Counts {
            calls: 0,
            candidate_scans: 0,
            unit_classifications: 0,
        }) };
    }

    pub(crate) fn reset() {
        COUNTS.set(Counts::default());
    }

    pub(crate) fn snapshot() -> Counts {
        COUNTS.get()
    }

    pub(super) fn record_call() {
        COUNTS.with(|counts| {
            let mut next = counts.get();
            next.calls = next.calls.checked_add(1).expect("ordinary call probe fits");
            counts.set(next);
        });
    }

    pub(super) fn record_candidate_scan() {
        COUNTS.with(|counts| {
            let mut next = counts.get();
            next.candidate_scans = next
                .candidate_scans
                .checked_add(1)
                .expect("ordinary candidate-scan probe fits");
            counts.set(next);
        });
    }

    pub(super) fn record_unit_classification() {
        COUNTS.with(|counts| {
            let mut next = counts.get();
            next.unit_classifications = next
                .unit_classifications
                .checked_add(1)
                .expect("ordinary unit-classification probe fits");
            counts.set(next);
        });
    }
}

#[cfg(test)]
pub(crate) mod ordinary_find_probe {
    use core::cell::Cell;

    std::thread_local! {
        static CALLS: Cell<usize> = const { Cell::new(0) };
    }

    pub(crate) fn reset() {
        CALLS.set(0);
    }

    pub(crate) fn calls() -> usize {
        CALLS.get()
    }

    pub(super) fn record_call() {
        CALLS.with(|calls| {
            calls.set(
                calls
                    .get()
                    .checked_add(1)
                    .expect("ordinary find probe fits"),
            );
        });
    }
}

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
    /// Every class member is an ASCII word byte. A complete match must
    /// therefore consume one whole ASCII word: neither assertion can hold at
    /// an interior class boundary. This lets the search classify each word at
    /// most once instead of replaying independent start and end cursors.
    AsciiWordSubset,
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

/// Immutable outer owner. Exact full-byte scanning is dispatched once here,
/// leaving the established ASCII/Unicode plan and hot scanner representation
/// unchanged.
#[derive(Debug)]
pub(crate) enum Plan {
    Established(EstablishedPlan),
    ExactBytes(ExactBytePlan),
}

#[derive(Debug)]
pub(crate) struct EstablishedPlan {
    mode: BoundaryMode,
    class: ClassMatcher,
    candidate_scanner: Option<CandidateScanner>,
    minimum_units: usize,
    maximum_units: Option<usize>,
    storage_bytes: usize,
}

#[derive(Debug)]
pub(crate) struct ExactBytePlan {
    established: EstablishedPlan,
    classifier: ExactBoxOrUsize<ByteSetClassifier>,
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
    exact_byte_candidates: bool,
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
        plan: &EstablishedPlan,
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
        plan: &EstablishedPlan,
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
                CandidateMode::AsciiWordSubset | CandidateMode::ExactAsciiMembers => {
                    ASCII_WIDE_BYTES
                }
                CandidateMode::UnicodeAsciiMemberOrNonAscii => {
                    usize::try_from(masks.ascii_mask().count_ones())
                        .expect("a 32-bit ASCII lane count fits usize")
                }
            };
            record_source(accounting, ASCII_WIDE_BYTES, decoded, limits)?;
            let candidates = match self.mode {
                CandidateMode::AsciiWordSubset | CandidateMode::ExactAsciiMembers => {
                    masks.member_mask()
                }
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
                CandidateMode::AsciiWordSubset | CandidateMode::ExactAsciiMembers => {
                    ASCII_NARROW_BYTES
                }
                CandidateMode::UnicodeAsciiMemberOrNonAscii => {
                    usize::try_from(masks.ascii_mask().count_ones())
                        .expect("a 16-bit ASCII lane count fits usize")
                }
            };
            record_source(accounting, ASCII_NARROW_BYTES, decoded, limits)?;
            let candidates = match self.mode {
                CandidateMode::AsciiWordSubset | CandidateMode::ExactAsciiMembers => {
                    masks.member_mask()
                }
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

    /// Mirror the canonical Unicode candidate order after the caller has
    /// admitted the complete ordinary full-window envelope. Unicode plans do
    /// not retain the ASCII nonmember run scanner, so their canonical order is
    /// exactly scalar prefix, wide blocks, narrow block, scalar tail.
    fn next_unicode_unmetered<const RECORD_PROBE: bool>(
        &self,
        haystack: &[u8],
        mut position: usize,
        end: usize,
    ) -> Option<ScannedCandidate> {
        debug_assert_eq!(self.mode, CandidateMode::UnicodeAsciiMemberOrNonAscii);
        #[cfg(test)]
        if RECORD_PROBE {
            ordinary_is_match_probe::record_candidate_scan();
        }
        let prefix_end = position
            .checked_add(
                end.saturating_sub(position)
                    .min(CANDIDATE_SCALAR_PREFIX_BYTES),
            )
            .expect("the scalar prefix remains inside the source");
        while position < prefix_end {
            if let Some(candidate) = self.unicode_scalar_candidate_unmetered(haystack, position) {
                return Some(candidate);
            }
            position = position
                .checked_add(1)
                .expect("a position before the source end can advance");
        }

        while end.saturating_sub(position) >= ASCII_WIDE_BYTES {
            let block_end = position
                .checked_add(ASCII_WIDE_BYTES)
                .expect("a proved wide block remains inside the source");
            let block: &[u8; ASCII_WIDE_BYTES] = haystack[position..block_end]
                .try_into()
                .expect("the candidate scanner checked its wide extent");
            let masks = self.classifier.classify_32(block);
            let candidates = masks.member_mask() | !masks.ascii_mask();
            if candidates != 0 {
                let offset = usize::try_from(candidates.trailing_zeros())
                    .expect("a 32-bit candidate lane fits usize");
                let candidate_position = position
                    .checked_add(offset)
                    .expect("a candidate lane remains inside its block");
                let bit = 1_u32
                    .checked_shl(u32::try_from(offset).expect("wide lane fits u32"))
                    .expect("a wide candidate lane is below 32");
                if masks.member_mask() & bit != 0 {
                    return Some(ScannedCandidate::AsciiMember {
                        position: candidate_position,
                        byte: block[offset],
                    });
                }
                return Some(ScannedCandidate::NonAscii {
                    position: candidate_position,
                });
            }
            position = block_end;
        }

        if end.saturating_sub(position) >= ASCII_NARROW_BYTES {
            let block_end = position
                .checked_add(ASCII_NARROW_BYTES)
                .expect("a proved narrow block remains inside the source");
            let block: &[u8; ASCII_NARROW_BYTES] = haystack[position..block_end]
                .try_into()
                .expect("the candidate scanner checked its narrow extent");
            let masks = self.classifier.classify_16(block);
            let candidates = masks.member_mask() | !masks.ascii_mask();
            if candidates != 0 {
                let offset = usize::try_from(candidates.trailing_zeros())
                    .expect("a 16-bit candidate lane fits usize");
                let candidate_position = position
                    .checked_add(offset)
                    .expect("a candidate lane remains inside its block");
                let bit = 1_u16
                    .checked_shl(u32::try_from(offset).expect("narrow lane fits u32"))
                    .expect("a narrow candidate lane is below 16");
                if masks.member_mask() & bit != 0 {
                    return Some(ScannedCandidate::AsciiMember {
                        position: candidate_position,
                        byte: block[offset],
                    });
                }
                return Some(ScannedCandidate::NonAscii {
                    position: candidate_position,
                });
            }
            position = block_end;
        }

        while position < end {
            if let Some(candidate) = self.unicode_scalar_candidate_unmetered(haystack, position) {
                return Some(candidate);
            }
            position = position
                .checked_add(1)
                .expect("a position before the source end can advance");
        }
        None
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
        let decoded = usize::from(
            matches!(
                self.mode,
                CandidateMode::AsciiWordSubset | CandidateMode::ExactAsciiMembers
            ) || byte.is_ascii(),
        );
        record_source(accounting, 1, decoded, limits)?;
        if self.classifier.set().contains(byte) {
            return Ok(Some(ScannedCandidate::AsciiMember { position, byte }));
        }
        if matches!(self.mode, CandidateMode::UnicodeAsciiMemberOrNonAscii) && !byte.is_ascii() {
            return Ok(Some(ScannedCandidate::NonAscii { position }));
        }
        Ok(None)
    }

    fn unicode_scalar_candidate_unmetered(
        &self,
        haystack: &[u8],
        position: usize,
    ) -> Option<ScannedCandidate> {
        let byte = haystack[position];
        if self.classifier.set().contains(byte) {
            return Some(ScannedCandidate::AsciiMember { position, byte });
        }
        if !byte.is_ascii() {
            return Some(ScannedCandidate::NonAscii { position });
        }
        None
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
        plan: &EstablishedPlan,
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
            (
                Some(mode @ (CandidateMode::AsciiWordSubset | CandidateMode::ExactAsciiMembers)),
                ClassMatcher::Bytes(words),
            ) => {
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
                    mode,
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
        let exact_byte_classifier = match (self.exact_byte_candidates, &class) {
            (false, _) => None,
            (true, ClassMatcher::Bytes(words)) => {
                if words[2] == 0 && words[3] == 0 {
                    return Err(crate::BuildError::InternalInvariant(
                        "full-byte candidate scanner retained an ASCII-only class",
                    ));
                }
                let classifier = self
                    .dispatch
                    .byte_set_classifier(ByteSet256::from_words(*words), DispatchPolicy::Auto)
                    .expect("automatic byte-set dispatch retains a scalar fallback");
                Some(
                    ExactBoxOrUsize::try_from_boxed(classifier).map_err(|error| match error {
                        CopyError::LayoutOverflow => crate::BuildError::InternalInvariant(
                            "bounded word-class byte-set classifier owner layout overflowed",
                        ),
                        CopyError::AllocationFailed => crate::BuildError::AllocationFailed {
                            structure: "bounded word-class byte-set classifier owner",
                            additional: 1,
                        },
                    })?,
                )
            }
            (true, _) => {
                return Err(crate::BuildError::InternalInvariant(
                    "full-byte candidate ownership retained a non-byte class",
                ));
            }
        };
        let established = EstablishedPlan {
            mode: self.mode,
            class,
            candidate_scanner,
            minimum_units: self.minimum_units,
            maximum_units: self.maximum_units,
            storage_bytes: self.storage_bytes,
        };
        Ok(match exact_byte_classifier {
            Some(classifier) => Plan::ExactBytes(ExactBytePlan {
                established,
                classifier,
            }),
            None => Plan::Established(established),
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
        match self {
            Self::Established(plan) => plan.storage_bytes,
            Self::ExactBytes(plan) => plan.established.storage_bytes,
        }
    }

    fn ordinary_unicode_unbounded_full_plan(
        &self,
        haystack_len: usize,
    ) -> Option<&EstablishedPlan> {
        let Self::Established(plan) = self else {
            return None;
        };
        (plan.mode == BoundaryMode::Unicode
            && plan.maximum_units.is_none()
            && matches!(&plan.class, ClassMatcher::Unicode { .. })
            && plan
                .candidate_scanner
                .as_ref()
                .is_some_and(|scanner| scanner.mode == CandidateMode::UnicodeAsciiMemberOrNonAscii)
            && ordinary_unmetered_envelope_fits(haystack_len))
        .then_some(plan)
    }

    /// Complete an ordinary unlimited full-window existence call for the
    /// Unicode unbounded owner, or decline without inspecting source bytes.
    /// Every other owner and operation retains the canonical accounted path.
    #[must_use]
    pub(crate) fn ordinary_is_match_full_unmetered(&self, haystack: &[u8]) -> Option<bool> {
        let plan = self.ordinary_unicode_unbounded_full_plan(haystack.len())?;
        #[cfg(test)]
        ordinary_is_match_probe::record_call();
        Some(plan.is_match_unicode_unbounded_full_unmetered(haystack))
    }

    /// Complete an ordinary unlimited full-window span call for the same
    /// Unicode unbounded owner as the Boolean projection, or decline without
    /// inspecting source bytes. Explicit finite and windowed operations retain
    /// the canonical accounted path.
    #[must_use]
    pub(crate) fn ordinary_find_full_unmetered(&self, haystack: &[u8]) -> Option<Option<Match>> {
        let plan = self.ordinary_unicode_unbounded_full_plan(haystack.len())?;
        #[cfg(test)]
        ordinary_find_probe::record_call();
        Some(plan.find_unicode_unbounded_full_unmetered(haystack))
    }

    pub(crate) fn find_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, Accounting), Error> {
        match self {
            Self::Established(plan) => plan.find_window(haystack, window, limits),
            Self::ExactBytes(plan) => plan.find_window(haystack, window, limits),
        }
    }

    pub(crate) fn shortest_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, Accounting), Error> {
        match self {
            Self::Established(plan) => plan.shortest_window(haystack, window, limits),
            Self::ExactBytes(plan) => plan.shortest_window(haystack, window, limits),
        }
    }
}

impl EstablishedPlan {
    fn find_unicode_unbounded_full_unmetered(&self, haystack: &[u8]) -> Option<Match> {
        debug_assert_eq!(self.mode, BoundaryMode::Unicode);
        debug_assert!(self.maximum_units.is_none());
        let end = haystack.len();
        let mut position = 0_usize;
        while position < end {
            let Some((run_start, mut width, run_word)) =
                self.next_unicode_member_unmetered::<false>(haystack, position, end)
            else {
                break;
            };
            position = run_start;
            let mut run_units = 0_usize;
            let mut homogeneous_wordness = true;
            loop {
                run_units = run_units
                    .checked_add(1)
                    .expect("a source cannot contain more scalars than bytes");
                position = position
                    .checked_add(width)
                    .expect("a decoded scalar within the source can advance");
                if position >= end {
                    break;
                }
                let (next_admitted, next_width, next_word) =
                    self.classify_unicode_unit_unmetered::<false>(haystack, position, end);
                if !next_admitted {
                    break;
                }
                homogeneous_wordness &= next_word == run_word;
                width = next_width;
            }

            if run_units >= self.minimum_units
                && let Some(matched) = self.unbounded_class_run_find_unmetered(
                    haystack,
                    run_start,
                    position,
                    run_units,
                    homogeneous_wordness,
                )
            {
                return Some(matched);
            }
        }
        None
    }

    fn is_match_unicode_unbounded_full_unmetered(&self, haystack: &[u8]) -> bool {
        debug_assert_eq!(self.mode, BoundaryMode::Unicode);
        debug_assert!(self.maximum_units.is_none());
        let end = haystack.len();
        let mut position = 0_usize;
        while position < end {
            let Some((run_start, mut width, run_word)) =
                self.next_unicode_member_unmetered::<true>(haystack, position, end)
            else {
                break;
            };
            position = run_start;
            let mut run_units = 0_usize;
            let mut homogeneous_wordness = true;
            loop {
                run_units = run_units
                    .checked_add(1)
                    .expect("a source cannot contain more scalars than bytes");
                position = position
                    .checked_add(width)
                    .expect("a decoded scalar within the source can advance");
                if position >= end {
                    break;
                }
                let (next_admitted, next_width, next_word) =
                    self.classify_unicode_unit_unmetered::<true>(haystack, position, end);
                if !next_admitted {
                    break;
                }
                homogeneous_wordness &= next_word == run_word;
                width = next_width;
            }

            if run_units >= self.minimum_units
                && self.unbounded_class_run_exists_unmetered(
                    haystack,
                    run_start,
                    position,
                    run_units,
                    homogeneous_wordness,
                )
            {
                return true;
            }
        }
        false
    }

    fn next_unicode_member_unmetered<const RECORD_PROBE: bool>(
        &self,
        haystack: &[u8],
        mut position: usize,
        end: usize,
    ) -> Option<(usize, usize, bool)> {
        let scanner = self
            .candidate_scanner
            .as_ref()
            .expect("the Unicode path retains its candidate classifier");
        loop {
            let candidate =
                scanner.next_unicode_unmetered::<RECORD_PROBE>(haystack, position, end)?;
            match candidate {
                ScannedCandidate::AsciiMember { position, byte } => {
                    return Some((position, 1, is_ascii_word(byte)));
                }
                ScannedCandidate::NonAscii {
                    position: candidate,
                } => {
                    let (admitted, width, word) = self
                        .classify_unicode_unit_unmetered::<RECORD_PROBE>(haystack, candidate, end);
                    if admitted {
                        return Some((candidate, width, word));
                    }
                    position = candidate
                        .checked_add(width)
                        .expect("a classified scalar within the source can advance");
                }
            }
        }
    }

    fn unbounded_class_run_exists_unmetered(
        &self,
        haystack: &[u8],
        run_start: usize,
        run_end: usize,
        run_units: usize,
        homogeneous_wordness: bool,
    ) -> bool {
        if homogeneous_wordness {
            return self.is_word_boundary(haystack, run_start)
                && self.is_word_boundary(haystack, run_end);
        }

        // With no maximum repetition, the earliest word-boundary start is at
        // least as useful as every later start. Visit the same decoded class
        // boundaries as the canonical cursors while retaining only that unit
        // index and the Boolean projection.
        let mut earliest_start = None;
        let mut position = run_start;
        let mut units = 0_usize;
        loop {
            if self.is_word_boundary(haystack, position) {
                if earliest_start
                    .is_some_and(|start| units.saturating_sub(start) >= self.minimum_units)
                {
                    return true;
                }
                if earliest_start.is_none() && units < run_units {
                    earliest_start = Some(units);
                }
            }
            if position == run_end {
                break;
            }
            let width = self.known_member_width(haystack, position, run_end);
            position = position
                .checked_add(width)
                .expect("a retained class scalar remains inside its run");
            units = units
                .checked_add(1)
                .expect("a source cannot contain more scalars than bytes");
        }
        false
    }

    fn unbounded_class_run_find_unmetered(
        &self,
        haystack: &[u8],
        run_start: usize,
        run_end: usize,
        run_units: usize,
        homogeneous_wordness: bool,
    ) -> Option<Match> {
        if homogeneous_wordness {
            return (self.is_word_boundary(haystack, run_start)
                && self.is_word_boundary(haystack, run_end))
            .then_some(Match {
                start: run_start,
                end: run_end,
            });
        }

        // The canonical greedy cursor selects the earliest boundary start
        // that can reach the minimum and then the final reachable boundary.
        // Retain those two byte positions while visiting the same decoded
        // class boundaries once.
        let mut earliest_start = None;
        let mut selected_end = None;
        let mut position = run_start;
        let mut units = 0_usize;
        loop {
            if self.is_word_boundary(haystack, position) {
                if earliest_start.is_none() && units < run_units {
                    earliest_start = Some((position, units));
                }
                if earliest_start.is_some_and(|(_, start_units)| {
                    units.saturating_sub(start_units) >= self.minimum_units
                }) {
                    selected_end = Some(position);
                }
            }
            if position == run_end {
                break;
            }
            let width = self.known_member_width(haystack, position, run_end);
            position = position
                .checked_add(width)
                .expect("a retained class scalar remains inside its run");
            units = units
                .checked_add(1)
                .expect("a source cannot contain more scalars than bytes");
        }
        earliest_start.and_then(|(start, _)| selected_end.map(|end| Match { start, end }))
    }

    fn classify_unicode_unit_unmetered<const RECORD_PROBE: bool>(
        &self,
        haystack: &[u8],
        position: usize,
        end: usize,
    ) -> (bool, usize, bool) {
        #[cfg(test)]
        if RECORD_PROBE {
            ordinary_is_match_probe::record_unit_classification();
        }
        let ClassMatcher::Unicode {
            ascii_words,
            ranges,
        } = &self.class
        else {
            unreachable!("the Unicode ordinary route owns a Unicode class");
        };
        let Some((scalar, width)) = decode_first(&haystack[position..end]) else {
            return (false, 1, false);
        };
        let admitted = if scalar.is_ascii() {
            let byte =
                u8::try_from(u32::from(scalar)).expect("an ASCII scalar fits exactly in one byte");
            ascii_set_contains(*ascii_words, byte)
        } else {
            unicode_ranges_contain(ranges, scalar)
        };
        (admitted, width, admitted && is_unicode_word(scalar))
    }

    fn find_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, Accounting), Error> {
        self.search_window(haystack, window, limits, true)
    }

    fn shortest_window(
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
        if self
            .candidate_scanner
            .as_ref()
            .is_some_and(|scanner| scanner.mode == CandidateMode::AsciiWordSubset)
        {
            return self.search_ascii_word_subset_window(haystack, window, limits);
        }
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

    /// Search a class proved to be a subset of ASCII word bytes.
    ///
    /// Both assertions are ASCII word boundaries. Once a class candidate is
    /// inside an ASCII word, no later class byte in that word can be a valid
    /// start. Likewise, a valid end can only be the end of the same complete
    /// word. The generic bounded search cannot use that fact because it also
    /// owns classes containing non-word members, so it advances independent
    /// start and end boundary cursors and reclassifies their shared prefix.
    /// This proof collapses those cursors into one monotone word traversal.
    fn search_ascii_word_subset_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, Accounting), Error> {
        debug_assert_eq!(self.mode, BoundaryMode::Ascii);
        let ClassMatcher::Bytes(class_words) = &self.class else {
            unreachable!("the ASCII-word-subset proof owns one byte class");
        };
        let scanner = self
            .candidate_scanner
            .as_ref()
            .expect("the ASCII-word-subset path retains its candidate scanner");
        debug_assert_eq!(scanner.mode, CandidateMode::AsciiWordSubset);

        let mut accounting = Accounting {
            work: 0,
            bytes_examined: 0,
            scalars_decoded: 0,
        };
        let mut position = window.start();
        while position < window.end() {
            let Some(candidate) =
                scanner.next(haystack, position, window.end(), &mut accounting, limits)?
            else {
                break;
            };
            let ScannedCandidate::AsciiMember {
                position: word_start,
                ..
            } = candidate
            else {
                unreachable!("an ASCII byte-class scanner cannot emit a non-ASCII candidate");
            };

            // Assertion context is read from the original haystack, including
            // when the search window begins in the middle of an ASCII word.
            charge(&mut accounting, limits)?;
            let has_word_before = word_start
                .checked_sub(1)
                .and_then(|index| haystack.get(index))
                .is_some_and(|&byte| is_ascii_word(byte));
            position = word_start
                .checked_add(1)
                .ok_or_else(|| accounting_overflow(limits))?;
            if has_word_before {
                // No interior position in this word can satisfy the start
                // assertion. Skip it once rather than rediscovering every
                // later class member as another impossible candidate.
                while position < window.end() {
                    charge(&mut accounting, limits)?;
                    let byte = haystack[position];
                    record_source(&mut accounting, 1, 1, limits)?;
                    position = position
                        .checked_add(1)
                        .ok_or_else(|| accounting_overflow(limits))?;
                    if !is_ascii_word(byte) {
                        break;
                    }
                }
                continue;
            }

            // The candidate byte is already proved and charged by the
            // scanner. Traverse the rest of its ASCII word exactly once,
            // retaining whether every byte belongs to the repeated class.
            let mut word_units = 1_usize;
            let mut class_only = true;
            while position < window.end() {
                charge(&mut accounting, limits)?;
                let byte = haystack[position];
                record_source(&mut accounting, 1, 1, limits)?;
                if !is_ascii_word(byte) {
                    break;
                }
                class_only &= byte_set_contains(*class_words, byte);
                word_units = word_units
                    .checked_add(1)
                    .ok_or_else(|| accounting_overflow(limits))?;
                position = position
                    .checked_add(1)
                    .ok_or_else(|| accounting_overflow(limits))?;
            }

            charge(&mut accounting, limits)?;
            let complete_word = !haystack
                .get(position)
                .is_some_and(|&byte| is_ascii_word(byte));
            let within_maximum = self
                .maximum_units
                .is_none_or(|maximum| word_units <= maximum);
            if complete_word
                && class_only
                && word_units >= self.minimum_units
                && within_maximum
            {
                return Ok((
                    Some(Match {
                        start: word_start,
                        end: position,
                    }),
                    accounting,
                ));
            }

            // If the loop observed a non-word byte inside the window, it has
            // already been classified and cannot start a class match.
            if position < window.end() {
                position = position
                    .checked_add(1)
                    .ok_or_else(|| accounting_overflow(limits))?;
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

impl ExactBytePlan {
    fn find_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, Accounting), Error> {
        self.search_window(haystack, window, limits, true)
    }

    fn shortest_window(
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
        let classifier = self
            .classifier
            .boxed()
            .expect("the exact-byte plan owns its compiled classifier");
        let plan = &self.established;
        let mut accounting = Accounting {
            work: 0,
            bytes_examined: 0,
            scalars_decoded: 0,
        };
        let mut position = window.start();
        while position < window.end() {
            let Some((run_start, byte)) = next_exact_byte_candidate(
                classifier,
                haystack,
                position,
                window.end(),
                &mut accounting,
                limits,
            )?
            else {
                break;
            };
            let mut width = 1_usize;
            let run_word = is_ascii_word(byte);
            position = run_start;
            if let Some(maximum_units) = plan.maximum_units {
                let (matched, run_end) = plan.search_bounded_class_run(
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
                    plan.classify_unit(haystack, position, window.end(), &mut accounting, limits)?;
                if !next_admitted {
                    break;
                }
                homogeneous_wordness &= next_word == run_word;
                width = next_width;
            }

            if run_units >= plan.minimum_units
                && let Some(matched) = plan.search_class_run(
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
}

fn next_exact_byte_candidate(
    classifier: &ByteSetClassifier,
    haystack: &[u8],
    mut position: usize,
    end: usize,
    accounting: &mut Accounting,
    limits: SearchLimits,
) -> Result<Option<(usize, u8)>, Error> {
    let prefix_end = position
        .checked_add(
            end.saturating_sub(position)
                .min(CANDIDATE_SCALAR_PREFIX_BYTES),
        )
        .ok_or_else(|| accounting_overflow(limits))?;
    while position < prefix_end {
        charge(accounting, limits)?;
        let byte = haystack[position];
        record_source(accounting, 1, 1, limits)?;
        if classifier.set().contains(byte) {
            return Ok(Some((position, byte)));
        }
        position = position
            .checked_add(1)
            .ok_or_else(|| accounting_overflow(limits))?;
    }

    while end.saturating_sub(position) >= BYTE_SET_BLOCK_BYTES {
        charge_many(accounting, BYTE_SET_BLOCK_BYTES, limits)?;
        let block_end = position
            .checked_add(BYTE_SET_BLOCK_BYTES)
            .ok_or_else(|| accounting_overflow(limits))?;
        let block: &[u8; BYTE_SET_BLOCK_BYTES] = haystack[position..block_end]
            .try_into()
            .expect("the exact-byte scanner checked its fixed extent");
        let candidates = classifier.classify_16(block).member_mask();
        record_source(
            accounting,
            BYTE_SET_BLOCK_BYTES,
            BYTE_SET_BLOCK_BYTES,
            limits,
        )?;
        if candidates != 0 {
            let offset = usize::try_from(candidates.trailing_zeros())
                .expect("a 16-bit candidate lane fits usize");
            let candidate_position = position
                .checked_add(offset)
                .ok_or_else(|| accounting_overflow(limits))?;
            charge(accounting, limits)?;
            record_source(accounting, 1, 0, limits)?;
            return Ok(Some((candidate_position, block[offset])));
        }
        position = block_end;
    }

    while position < end {
        charge(accounting, limits)?;
        let byte = haystack[position];
        record_source(accounting, 1, 1, limits)?;
        if classifier.set().contains(byte) {
            return Ok(Some((position, byte)));
        }
        position = position
            .checked_add(1)
            .ok_or_else(|| accounting_overflow(limits))?;
    }
    Ok(None)
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
    let (inspected, candidate_mode, exact_byte_candidates) =
        match (mode, class.kind()) {
            (BoundaryMode::Ascii, HirKind::Class(Class::Bytes(class))) => {
                let range_count = u64::try_from(class.ranges().len())
                    .map_err(|_| InspectionError::ArithmeticOverflow("byte class ranges"))?;
                let (members, ascii_only, ascii_word_subset) =
                    class.ranges().iter().try_fold(
                    (0_u64, true, true),
                    |(total, ascii_only, ascii_word_subset), range| {
                        let width = u64::from(range.end())
                            .checked_sub(u64::from(range.start()))
                            .and_then(|value| value.checked_add(1))
                            .ok_or(InspectionError::ArithmeticOverflow("byte class members"))?;
                        let total = total
                            .checked_add(width)
                            .ok_or(InspectionError::ArithmeticOverflow("byte class members"))?;
                        Ok::<_, InspectionError>((
                            total,
                            ascii_only && range.end().is_ascii(),
                            ascii_word_subset
                                && range.end().is_ascii()
                                && (range.start()..=range.end()).all(is_ascii_word),
                        ))
                    },
                )?;
                charge_build(&mut work, range_count, max_planner_work)?;
                charge_build(&mut work, members, max_planner_work)?;
                if ascii_only {
                    (
                        InspectedClass::Bytes(class),
                        Some(if ascii_word_subset {
                            CandidateMode::AsciiWordSubset
                        } else {
                            CandidateMode::ExactAsciiMembers
                        }),
                        false,
                    )
                } else {
                    (InspectedClass::Bytes(class), None, true)
                }
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
                    false,
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
    if exact_byte_candidates {
        charge_build(
            &mut work,
            u64::try_from(BYTE_SET_CLASSIFIER_BUILD_WORK)
                .map_err(|_| InspectionError::ArithmeticOverflow("byte-set classifier work"))?,
            max_planner_work,
        )?;
    }
    if matches!(
        candidate_mode,
        Some(CandidateMode::AsciiWordSubset | CandidateMode::ExactAsciiMembers)
    ) {
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
    let run_scanner_bytes = usize::from(matches!(
        candidate_mode,
        Some(CandidateMode::AsciiWordSubset | CandidateMode::ExactAsciiMembers)
    ))
    .checked_mul(core::mem::size_of::<AsciiByteSetRunScanner>())
    .ok_or(InspectionError::ArithmeticOverflow(
        "bounded word-class run-scanner storage",
    ))?;
    let byte_classifier_bytes = usize::from(exact_byte_candidates)
        .checked_mul(core::mem::size_of::<ByteSetClassifier>())
        .ok_or(InspectionError::ArithmeticOverflow(
            "bounded word-class byte-set classifier storage",
        ))?;
    let storage_bytes = core::mem::size_of::<Plan>()
        .checked_add(range_bytes)
        .and_then(|bytes| bytes.checked_add(run_scanner_bytes))
        .and_then(|bytes| bytes.checked_add(byte_classifier_bytes))
        .ok_or(InspectionError::ArithmeticOverflow(
            "bounded word-class plan storage",
        ))?;
    Ok(InspectionOutcome::Eligible(Inspection {
        mode,
        class: inspected,
        candidate_mode,
        exact_byte_candidates,
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
    plan: &EstablishedPlan,
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

fn ordinary_unmetered_envelope_fits(haystack_len: usize) -> bool {
    haystack_len
        .checked_mul(ORDINARY_UNMETERED_WORK_FACTOR)
        .and_then(|work| work.checked_add(ORDINARY_UNMETERED_FIXED_WORK))
        .and_then(|work| u64::try_from(work).ok())
        .is_some()
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
    use regex::bytes::RegexBuilder as BytesRegexBuilder;
    use regex_syntax::ParserBuilder;

    use super::{
        ASCII_CLASSIFIER_BUILD_WORK, ASCII_RUN_SCANNER_BUILD_WORK, BULK_SKIP_MIN_BYTES,
        BYTE_SET_CLASSIFIER_BUILD_WORK, ByteSetClassifier, CandidateMode, CandidateScanner,
        InspectionError, InspectionOutcome, PLAN_ID, inspect, ordinary_find_probe,
        ordinary_is_match_probe,
    };
    use crate::{
        BuildError, BuildLimits, PlanSelection, PortableBuilder, PortableCapturesReadError,
        PortableFindIterLimits, SearchError, SearchLimits, SearchSessionLimits, SearchWindow,
        UnicodeWordRunError,
    };

    fn generated_background(length: usize, seed: u64) -> Vec<u8> {
        const ALPHABET: &[u8] = b"qxvjkm ,.;/\n";
        let mut state = seed;
        (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let modulus = u64::try_from(ALPHABET.len()).expect("alphabet length fits u64");
                let index = usize::try_from(state % modulus).expect("alphabet index fits usize");
                ALPHABET[index]
            })
            .collect()
    }

    fn generated_with_suffix(length: usize, seed: u64, suffix: &[u8]) -> Vec<u8> {
        assert!(suffix.len() <= length);
        let mut bytes = generated_background(length - suffix.len(), seed);
        bytes.extend_from_slice(suffix);
        bytes
    }

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
    fn ordinary_unmetered_envelope_has_an_exact_nonallocating_boundary() {
        let usize_ceiling = (usize::MAX - super::ORDINARY_UNMETERED_FIXED_WORK)
            / super::ORDINARY_UNMETERED_WORK_FACTOR;
        let u64_ceiling = u64::MAX
            .checked_sub(u64::try_from(super::ORDINARY_UNMETERED_FIXED_WORK).unwrap())
            .map(|work| {
                work / u64::try_from(super::ORDINARY_UNMETERED_WORK_FACTOR).unwrap()
            })
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or(usize::MAX);
        let largest_admitted = usize_ceiling.min(u64_ceiling);

        assert!(super::ordinary_unmetered_envelope_fits(0));
        assert!(super::ordinary_unmetered_envelope_fits(largest_admitted));
        if let Some(first_rejected) = largest_admitted.checked_add(1) {
            assert!(!super::ordinary_unmetered_envelope_fits(first_rejected));
        }
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
    fn ascii_word_subset_proof_collapses_cursors_without_changing_windows_or_endpoints() {
        let patterns = [
            r"(?-u:\b[a-z]{2,5}\b)",
            r"(?-u:\b[0-9_]{1,3}\b)",
            r"(?-u:\b[A-Za-z0-9_]{2,}\b)",
        ];
        let alphabet = [b'a', b'z', b'0', b'_', b'!', 0xff];
        for pattern in patterns {
            let specialized = plan(pattern, false);
            let mut generic = plan(pattern, false);
            let super::Plan::Established(generic) = &mut generic else {
                panic!("an ASCII word subset uses the established owner");
            };
            let scanner = generic
                .candidate_scanner
                .as_mut()
                .expect("an ASCII word subset retains a candidate scanner");
            assert_eq!(scanner.mode, CandidateMode::AsciiWordSubset);
            scanner.mode = CandidateMode::ExactAsciiMembers;

            for length in 0_u32..=4 {
                for mut encoded in 0..alphabet.len().pow(length) {
                    let mut haystack = Vec::with_capacity(usize::try_from(length).unwrap());
                    for _ in 0..length {
                        haystack.push(alphabet[encoded % alphabet.len()]);
                        encoded /= alphabet.len();
                    }
                    for start in 0..=haystack.len() {
                        for end in start..=haystack.len() {
                            let window = SearchWindow::new(start, end);
                            let expected = generic
                                .find_window(&haystack, window, SearchLimits::unlimited())
                                .expect("generic bounded search")
                                .0;
                            let actual = specialized
                                .find_window(&haystack, window, SearchLimits::unlimited())
                                .expect("collapsed bounded search")
                                .0;
                            assert_eq!(actual, expected, "{pattern:?}/{haystack:?}/{start}..{end}");
                            let expected_end = generic
                                .shortest_window(&haystack, window, SearchLimits::unlimited())
                                .expect("generic bounded shortest")
                                .0;
                            let actual_end = specialized
                                .shortest_window(&haystack, window, SearchLimits::unlimited())
                                .expect("collapsed bounded shortest")
                                .0;
                            assert_eq!(
                                actual_end, expected_end,
                                "shortest {pattern:?}/{haystack:?}/{start}..{end}"
                            );
                        }
                    }
                }
            }
        }

        let super::Plan::Established(mixed) = plan(r"(?-u:\b[A_-]{1,3}\b)", false)
        else {
            panic!("a mixed ASCII class uses the established owner");
        };
        assert_eq!(
            mixed
                .candidate_scanner
                .expect("a mixed ASCII class retains a candidate scanner")
                .mode,
            CandidateMode::ExactAsciiMembers
        );
    }

    #[test]
    fn ascii_word_subset_route_preserves_original_context_and_exact_work_fence() {
        let plan = plan(r"(?-u:\b[a-z]{2,5}\b)", false);
        let haystack = b"1ab!cde!fghijk!yz";
        for (window, expected) in [
            (SearchWindow::new(0, haystack.len()), Some(4..7)),
            (SearchWindow::new(1, haystack.len()), Some(4..7)),
            (SearchWindow::new(2, haystack.len()), Some(4..7)),
            (SearchWindow::new(4, 7), Some(4..7)),
            (SearchWindow::new(5, 7), None),
            (SearchWindow::new(4, 6), None),
        ] {
            let (matched, accounting) = plan
                .find_window(haystack, window, SearchLimits::unlimited())
                .expect("ASCII word-subset window");
            assert_eq!(matched.map(|matched| matched.range()), expected, "{window:?}");
            assert!(accounting.work() > 0);
            assert!(
                plan.find_window(
                    haystack,
                    window,
                    SearchLimits {
                        max_work: accounting.work(),
                        max_scratch_bytes: 0,
                    },
                )
                .is_ok()
            );
            assert!(matches!(
                plan.find_window(
                    haystack,
                    window,
                    SearchLimits {
                        max_work: accounting.work() - 1,
                        max_scratch_bytes: 0,
                    },
                ),
                Err(crate::UnicodeWordRunError::WorkLimitExceeded { .. })
            ));
        }
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
    fn classifier_admission_build_work_and_full_byte_ownership_are_exact() {
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
        let InspectionOutcome::Eligible(high) =
            inspect(&high_hir, SimdDispatchContext::capture(), 0, u64::MAX)
                .expect("high-byte inspection")
        else {
            panic!("high-byte class should be eligible");
        };
        assert_eq!(ascii.candidate_mode, Some(CandidateMode::AsciiWordSubset));
        assert!(!ascii.exact_byte_candidates);
        assert_eq!(high.candidate_mode, None);
        assert!(high.exact_byte_candidates);
        assert_eq!(
            ascii
                .planner_work()
                .checked_sub(u64::try_from(ASCII_CLASSIFIER_BUILD_WORK).unwrap())
                .unwrap()
                .checked_sub(u64::try_from(ASCII_RUN_SCANNER_BUILD_WORK).unwrap())
                .unwrap(),
            high.planner_work()
                .checked_sub(u64::try_from(BYTE_SET_CLASSIFIER_BUILD_WORK).unwrap())
                .unwrap()
        );
        assert_eq!(
            ascii
                .storage_bytes()
                .checked_sub(core::mem::size_of::<super::AsciiByteSetRunScanner>())
                .unwrap(),
            high.storage_bytes()
                .checked_sub(core::mem::size_of::<ByteSetClassifier>())
                .unwrap()
        );

        let ascii = ascii.build().expect("ASCII plan");
        assert!(matches!(
            &ascii,
            super::Plan::Established(plan)
                if matches!(
                    plan.candidate_scanner.as_ref(),
                    Some(CandidateScanner {
                        nonmember_scanner,
                        mode: CandidateMode::AsciiWordSubset,
                        ..
                    }) if nonmember_scanner.boxed().is_some()
                )
        ));
        let high = high.build().expect("high-byte plan");
        assert!(matches!(
            &high,
            super::Plan::ExactBytes(super::ExactBytePlan { classifier, .. })
                if classifier.boxed().is_some_and(|classifier| {
                    classifier.set().contains(0x80) && classifier.set().contains(0x81)
                })
        ));

        let facade = PortableBuilder::new(r"(?-u:\b[\x80-\x81]{1,3}\b)")
            .unicode(false)
            .plan_selection(PlanSelection::Auto)
            .build()
            .expect("high-byte direct plan");
        assert_eq!(facade.runtime_implementation_id(), PLAN_ID);
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
        assert_eq!(accounting.work(), 7);
        assert_eq!(accounting.bytes_examined(), 5);
        assert_eq!(accounting.scalars_decoded(), 5);

        let mut wide = vec![b'-'; 64];
        wide[20] = b'A';
        let (matched, accounting) = plan
            .find_window(&wide, SearchWindow::full(&wide), SearchLimits::unlimited())
            .expect("wide candidate");
        assert_eq!(matched.expect("wide match").range(), 20..21);
        assert_eq!(accounting.work(), 44);
        assert_eq!(accounting.bytes_examined(), 42);
        assert_eq!(accounting.scalars_decoded(), 41);
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
                needed: 44,
                limit: 43,
            })
        ));
    }

    #[test]
    fn full_byte_crossover_and_absent_scan_have_exact_ledgers() {
        let plan = plan(r"(?-u:\b[\x80-\x81]{1,3}\b)", false);
        let absent = vec![0x90; 56];
        let (matched, accounting) = plan
            .find_window(
                &absent,
                SearchWindow::full(&absent),
                SearchLimits::unlimited(),
            )
            .expect("full-byte absent scan");
        assert_eq!(matched, None);
        assert_eq!(accounting.work(), 56);
        assert_eq!(accounting.bytes_examined(), 56);
        assert_eq!(accounting.scalars_decoded(), 56);
        assert!(matches!(
            plan.find_window(
                &absent,
                SearchWindow::full(&absent),
                SearchLimits {
                    max_work: 55,
                    max_scratch_bytes: 0,
                },
            ),
            Err(crate::UnicodeWordRunError::WorkLimitExceeded {
                needed: 56,
                limit: 55,
            })
        ));

        let mut dense = absent;
        dense[3] = 0x80;
        dense[20] = 0x81;
        dense[39] = 0x80;
        assert_eq!(
            plan.find_window(
                &dense,
                SearchWindow::full(&dense),
                SearchLimits::unlimited(),
            )
            .expect("full-byte dense scan")
            .0,
            None
        );
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
            u64::try_from(candidate.checked_add(4).unwrap()).unwrap()
        );
        assert_eq!(
            accounting.bytes_examined(),
            candidate.checked_add(2).unwrap()
        );
        assert_eq!(
            accounting.scalars_decoded(),
            candidate.checked_add(2).unwrap()
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

    #[test]
    fn ordinary_unmetered_boolean_matches_exact_unicode_greek_late_case() {
        const PATTERN: &str = r"\b\p{Greek}+\b";
        let suffix = " Ωμέγα ".as_bytes();
        let haystack = generated_with_suffix(4_093, 0x1111_2222_3333_4444, suffix);
        let run_start = haystack.len() - suffix.len() + 1;
        let run_end = haystack.len() - 1;
        let plan = plan(PATTERN, true);
        let canonical = plan
            .find_window(
                &haystack,
                SearchWindow::full(&haystack),
                SearchLimits::unlimited(),
            )
            .expect("canonical Greek benchmark search")
            .0
            .expect("the benchmark suffix contains one Greek word");
        assert_eq!(canonical.range(), run_start..run_end);
        assert_eq!(
            plan.ordinary_is_match_full_unmetered(&haystack),
            Some(true)
        );

        let regex = PortableBuilder::new(PATTERN)
            .unicode(true)
            .build()
            .expect("the public benchmark regex builds");
        assert_eq!(regex.runtime_implementation_id(), PLAN_ID);
        ordinary_is_match_probe::reset();
        assert!(regex.is_match(&haystack));
        let counts = ordinary_is_match_probe::snapshot();
        assert_eq!(counts.calls, 1);
        assert!(counts.candidate_scans > 0);
        assert!(counts.unit_classifications > 0);
    }

    #[test]
    fn ordinary_unmetered_find_matches_exact_unicode_greek_late_case() {
        const PATTERN: &str = r"\b\p{Greek}+\b";
        let suffix = " Ωμέγα ".as_bytes();
        let haystack = generated_with_suffix(4_093, 0x9999_aaaa_bbbb_cccc, suffix);
        let expected = Some((haystack.len() - suffix.len() + 1, haystack.len() - 1));
        let plan = plan(PATTERN, true);
        assert_eq!(
            plan.find_window(
                &haystack,
                SearchWindow::full(&haystack),
                SearchLimits::unlimited(),
            )
            .expect("canonical Greek benchmark search")
            .0
            .map(|matched| (matched.start(), matched.end())),
            expected,
        );
        assert_eq!(
            plan.ordinary_find_full_unmetered(&haystack)
                .expect("the Unicode unbounded owner is eligible")
                .map(|matched| (matched.start(), matched.end())),
            expected,
        );

        let regex = PortableBuilder::new(PATTERN)
            .unicode(true)
            .build()
            .expect("the public benchmark regex builds");
        assert_eq!(regex.runtime_implementation_id(), PLAN_ID);
        ordinary_find_probe::reset();
        assert_eq!(
            regex
                .find(&haystack)
                .map(|matched| (matched.start(), matched.end())),
            expected,
        );
        assert_eq!(ordinary_find_probe::calls(), 1);
    }

    #[test]
    fn ordinary_unmetered_find_handles_homogeneous_unicode_nonword_runs() {
        const PATTERN: &str = r"\b[♥☀]{2,}\b";
        assert!(!super::is_unicode_word('♥'));
        assert!(!super::is_unicode_word('☀'));
        let plan = plan(PATTERN, true);
        let oracle = BytesRegexBuilder::new(PATTERN)
            .unicode(true)
            .build()
            .expect("Unicode bytes-regex oracle");
        for haystack in ["a♥☀♥b".as_bytes(), "!♥☀♥!".as_bytes()] {
            let expected = oracle
                .find(haystack)
                .map(|matched| (matched.start(), matched.end()));
            let canonical = plan
                .find_window(
                    haystack,
                    SearchWindow::full(haystack),
                    SearchLimits::unlimited(),
                )
                .expect("canonical homogeneous-nonword search")
                .0
                .map(|matched| (matched.start(), matched.end()));
            let ordinary = plan
                .ordinary_find_full_unmetered(haystack)
                .expect("the Unicode unbounded owner is eligible")
                .map(|matched| (matched.start(), matched.end()));
            assert_eq!(canonical, expected, "canonical haystack={haystack:?}");
            assert_eq!(ordinary, expected, "ordinary haystack={haystack:?}");
        }
    }

    #[test]
    fn ordinary_unmetered_find_decodes_wide_and_mixed_unicode_word_members() {
        const PATTERN: &str =
            r"\b[\x{4E2D}\x{10400}\x{0301}\x{203F}\x{2665}]{2,}\b";
        let combining = '\u{0301}';
        let connector = '\u{203F}';
        let nonword = '\u{2665}';
        assert_eq!('中'.len_utf8(), 3);
        assert_eq!('𐐀'.len_utf8(), 4);
        assert!(super::is_unicode_word('中'));
        assert!(super::is_unicode_word('𐐀'));
        assert!(super::is_unicode_word(combining));
        assert!(super::is_unicode_word(connector));
        assert!(!super::is_unicode_word(nonword));

        let haystack = format!("!中{combining}{connector}{nonword}𐐀!").into_bytes();
        let expected = Some((1, haystack.len() - 1));
        let plan = plan(PATTERN, true);
        let oracle = BytesRegexBuilder::new(PATTERN)
            .unicode(true)
            .build()
            .expect("Unicode bytes-regex oracle");
        assert_eq!(
            oracle
                .find(&haystack)
                .map(|matched| (matched.start(), matched.end())),
            expected,
        );
        assert_eq!(
            plan.find_window(
                &haystack,
                SearchWindow::full(&haystack),
                SearchLimits::unlimited(),
            )
            .expect("canonical wide-scalar search")
            .0
            .map(|matched| (matched.start(), matched.end())),
            expected,
        );
        assert_eq!(
            plan.ordinary_find_full_unmetered(&haystack)
                .expect("the Unicode unbounded owner is eligible")
                .map(|matched| (matched.start(), matched.end())),
            expected,
        );
    }

    #[test]
    fn ordinary_unmetered_find_handles_alternating_wordness_for_multiple_minimums() {
        let left_clipped = "aα♥β♥γ!";
        let right_clipped = "!α♥β♥γz";
        let cases = [
            (r"\b[\p{Greek}\x{2665}]+\b", true),
            (r"\b[\p{Greek}\x{2665}]{2,}\b", true),
            (r"\b[\p{Greek}\x{2665}]{4,}\b", true),
            (r"\b[\p{Greek}\x{2665}]{5,}\b", false),
        ];
        for (pattern, present) in cases {
            let plan = plan(pattern, true);
            let oracle = BytesRegexBuilder::new(pattern)
                .unicode(true)
                .build()
                .expect("Unicode bytes-regex oracle");
            let expected = [
                present.then_some((
                    left_clipped.find('♥').expect("left internal boundary"),
                    left_clipped.len() - 1,
                )),
                present.then_some((
                    1,
                    right_clipped.rfind('γ').expect("right internal boundary"),
                )),
            ];
            for (haystack, expected) in [left_clipped, right_clipped].into_iter().zip(expected) {
                let haystack = haystack.as_bytes();
                assert_eq!(
                    oracle
                        .find(haystack)
                        .map(|matched| (matched.start(), matched.end())),
                    expected,
                    "upstream pattern={pattern:?} haystack={haystack:?}",
                );
                assert_eq!(
                    plan.find_window(
                        haystack,
                        SearchWindow::full(haystack),
                        SearchLimits::unlimited(),
                    )
                    .expect("canonical alternating-wordness search")
                    .0
                    .map(|matched| (matched.start(), matched.end())),
                    expected,
                    "canonical pattern={pattern:?} haystack={haystack:?}",
                );
                assert_eq!(
                    plan.ordinary_find_full_unmetered(haystack)
                        .expect("the Unicode unbounded owner is eligible")
                        .map(|matched| (matched.start(), matched.end())),
                    expected,
                    "ordinary pattern={pattern:?} haystack={haystack:?}",
                );
            }
        }
    }

    #[test]
    fn ordinary_unmetered_find_preserves_malformed_context_and_greedy_boundaries() {
        const PATTERN: &str = r"\b[\p{Greek}_/]{2,}\b";
        let plan = plan(PATTERN, true);
        let cases = [
            "!α/β_γ!".as_bytes().to_vec(),
            [vec![0xff], "α/β".as_bytes().to_vec(), vec![0xff]].concat(),
            [vec![0xce, b'!'], "α/β".as_bytes().to_vec(), vec![0xb1]].concat(),
            [
                "a".as_bytes().to_vec(),
                "α/β".as_bytes().to_vec(),
                vec![b'!'],
            ]
            .concat(),
            b"plain ASCII only".to_vec(),
        ];
        for haystack in cases {
            let expected = plan
                .find_window(
                    &haystack,
                    SearchWindow::full(&haystack),
                    SearchLimits::unlimited(),
                )
                .expect("canonical malformed-context search")
                .0
                .map(|matched| (matched.start(), matched.end()));
            let actual = plan
                .ordinary_find_full_unmetered(&haystack)
                .expect("the Unicode unbounded owner is eligible")
                .map(|matched| (matched.start(), matched.end()));
            assert_eq!(actual, expected, "haystack={haystack:?}");
        }
    }

    #[test]
    fn ordinary_unmetered_boolean_preserves_boundaries_and_malformed_bytes() {
        const PATTERN: &str = r"\b\p{Greek}{2,}\b";
        let plan = plan(PATTERN, true);
        let oracle = BytesRegexBuilder::new(PATTERN)
            .unicode(true)
            .build()
            .expect("Unicode bytes-regex oracle");
        let cases = [
            "!αβ!".as_bytes().to_vec(),
            "aαβ!".as_bytes().to_vec(),
            "!αβa".as_bytes().to_vec(),
            "!α!".as_bytes().to_vec(),
            b"plain ASCII only".to_vec(),
            [vec![0xff], "αβ".as_bytes().to_vec(), vec![0xff]].concat(),
            [vec![0xce, b'!'], "αβ".as_bytes().to_vec(), vec![0xb1]].concat(),
        ];
        for haystack in cases {
            let canonical = plan
                .find_window(
                    &haystack,
                    SearchWindow::full(&haystack),
                    SearchLimits::unlimited(),
                )
                .expect("canonical boundary-context search")
                .0
                .is_some();
            let expected = oracle.is_match(&haystack);
            assert_eq!(canonical, expected, "canonical parity for {haystack:?}");
            assert_eq!(
                plan.ordinary_is_match_full_unmetered(&haystack),
                Some(expected),
                "ordinary parity for {haystack:?}",
            );
        }
    }

    #[test]
    fn ordinary_unmetered_values_differentially_exhaust_short_byte_sources() {
        let patterns = [
            r"\b\p{Greek}+\b",
            r"\b\p{L}{2,}\b",
            r"\b[\p{Greek}_/]+\b",
        ];
        let alphabet = [b'A', b'_', b'/', b'!', 0xff, 0xce, 0xb1, 0xb2];
        for pattern in patterns {
            let plan = plan(pattern, true);
            let oracle = BytesRegexBuilder::new(pattern)
                .unicode(true)
                .build()
                .expect("bytes-regex oracle");
            for length in 0_u32..=5 {
                for mut encoded in 0..alphabet.len().pow(length) {
                    let mut haystack = Vec::with_capacity(
                        usize::try_from(length).expect("small exhaustive source length"),
                    );
                    for _ in 0..length {
                        haystack.push(alphabet[encoded % alphabet.len()]);
                        encoded /= alphabet.len();
                    }
                    let canonical = plan
                        .find_window(
                            &haystack,
                            SearchWindow::full(&haystack),
                            SearchLimits::unlimited(),
                        )
                        .expect("canonical exhaustive search")
                        .0
                        .map(|matched| (matched.start(), matched.end()));
                    let ordinary = plan
                        .ordinary_find_full_unmetered(&haystack)
                        .expect("the Unicode unbounded owner is eligible")
                        .map(|matched| (matched.start(), matched.end()));
                    assert_eq!(
                        ordinary, canonical,
                        "ordinary span pattern={pattern:?} haystack={haystack:?}",
                    );
                    assert_eq!(
                        plan.ordinary_is_match_full_unmetered(&haystack),
                        Some(canonical.is_some()),
                        "ordinary existence pattern={pattern:?} haystack={haystack:?}",
                    );
                    // The incumbent and regex::bytes intentionally diverge on
                    // some malformed Unicode-boundary contexts. That inherited
                    // behavior is outside this ordinary value-path lane; valid
                    // UTF-8 retains complete upstream differential coverage.
                    if core::str::from_utf8(&haystack).is_ok() {
                        assert_eq!(
                            canonical,
                            oracle
                                .find(&haystack)
                                .map(|matched| (matched.start(), matched.end())),
                            "canonical pattern={pattern:?} haystack={haystack:?}",
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn only_public_ordinary_is_match_enters_the_unmetered_boolean_route() {
        const PATTERN: &str = r"\b\p{Greek}+\b";
        let hit = "!Ωμέγα!".as_bytes();
        let miss = b"plain ASCII";
        let regex = PortableBuilder::new(PATTERN)
            .unicode(true)
            .build()
            .expect("bounded Unicode word-class facade");
        assert_eq!(regex.runtime_implementation_id(), PLAN_ID);

        ordinary_is_match_probe::reset();
        assert!(regex.is_match(hit));
        assert!(!regex.is_match(miss));
        let ordinary = ordinary_is_match_probe::snapshot();
        assert_eq!(ordinary.calls, 2);
        assert!(ordinary.candidate_scans >= 2);

        assert!(regex
            .is_match_accounted(hit, SearchLimits::unlimited())
            .expect("accounted existence")
            .0);
        assert!(regex
            .is_match_value(hit, SearchLimits::unlimited())
            .expect("explicit value existence"));
        assert!(regex
            .is_match_at(hit, 0, SearchLimits::unlimited())
            .expect("accounted ranged existence")
            .0);
        assert!(regex
            .is_match_window_value(
                hit,
                SearchWindow::full(hit),
                SearchLimits::unlimited(),
            )
            .expect("value window existence"));
        assert!(regex.find(hit).is_some());
        assert!(regex
            .find_value(hit, SearchLimits::unlimited())
            .expect("value span")
            .is_some());

        let mut locations = regex.capture_locations();
        assert!(regex
            .captures_read_value(&mut locations, hit, SearchLimits::unlimited())
            .expect("capture-free locations")
            .is_some());
        let mut session = regex
            .search_session(SearchSessionLimits::unlimited())
            .expect("native session");
        assert!(session
            .is_match_value(hit, SearchLimits::unlimited())
            .expect("session value existence"));

        let invalid = SearchWindow::new(2, 1);
        assert!(matches!(
            regex.is_match_window_value(
                hit,
                invalid,
                SearchLimits {
                    max_work: 0,
                    max_scratch_bytes: 0,
                },
            ),
            Err(SearchError::UnicodeWordRun(
                UnicodeWordRunError::InvalidWindow {
                    start: 2,
                    end: 1,
                    haystack_len,
                }
            )) if haystack_len == hit.len()
        ));
        assert!(matches!(
            regex.is_match_value(
                hit,
                SearchLimits {
                    max_work: 0,
                    max_scratch_bytes: 0,
                },
            ),
            Err(SearchError::UnicodeWordRun(
                UnicodeWordRunError::WorkLimitExceeded { .. }
            ))
        ));

        let bounded = PortableBuilder::new(r"\b\p{Greek}{2,8}\b")
            .unicode(true)
            .build()
            .expect("bounded maximum fallback fixture");
        assert_eq!(bounded.runtime_implementation_id(), PLAN_ID);
        assert!(bounded.is_match(hit));
        assert_eq!(ordinary_is_match_probe::snapshot(), ordinary);
    }

    #[test]
    fn public_and_zero_origin_ordinary_session_find_enter_the_unmetered_span_route() {
        const PATTERN: &str = r"\b\p{Greek}+\b";
        let hit = "!Ωμέγα!".as_bytes();
        let miss = b"plain ASCII";
        let expected = Some((1, hit.len() - 1));
        let regex = PortableBuilder::new(PATTERN)
            .unicode(true)
            .build()
            .expect("bounded Unicode word-class facade");
        assert_eq!(regex.runtime_implementation_id(), PLAN_ID);

        ordinary_find_probe::reset();
        assert_eq!(
            regex
                .find(hit)
                .map(|matched| (matched.start(), matched.end())),
            expected,
        );
        assert_eq!(regex.find(miss), None);
        let ordinary_calls = ordinary_find_probe::calls();
        assert_eq!(ordinary_calls, 2);

        assert!(regex.is_match(hit));
        assert_eq!(
            regex
                .find_value(hit, SearchLimits::unlimited())
                .expect("finite value span")
                .map(|matched| (matched.start(), matched.end())),
            expected,
        );
        assert_eq!(
            regex
                .find_accounted(hit, SearchLimits::unlimited())
                .expect("accounted span")
                .0
                .map(|matched| (matched.start(), matched.end())),
            expected,
        );
        assert_eq!(
            regex
                .find_at_value(hit, 0, SearchLimits::unlimited())
                .expect("ranged value span")
                .map(|matched| (matched.start(), matched.end())),
            expected,
        );
        assert_eq!(
            regex
                .find_window_value(hit, SearchWindow::full(hit), SearchLimits::unlimited(),)
                .expect("windowed value span")
                .map(|matched| (matched.start(), matched.end())),
            expected,
        );
        assert_eq!(
            regex
                .find_window(hit, SearchWindow::full(hit), SearchLimits::unlimited(),)
                .expect("windowed accounted span")
                .0
                .map(|matched| (matched.start(), matched.end())),
            expected,
        );

        let mut session = regex
            .search_session(SearchSessionLimits::unlimited())
            .expect("native session");
        assert_eq!(
            session
                .find_value(hit, SearchLimits::unlimited())
                .expect("session value span")
                .map(|matched| (matched.start(), matched.end())),
            expected,
        );
        assert_eq!(
            ordinary_find_probe::calls(),
            ordinary_calls,
            "finite, windowed, and explicit-session APIs stay canonical",
        );
        let mut ordinary = regex.ordinary_session().expect("ordinary session");
        assert_eq!(
            ordinary
                .find_at(hit, 0)
                .expect("ordinary-session span")
                .map(|matched| (matched.start(), matched.end())),
            expected,
        );
        assert_eq!(
            ordinary_find_probe::calls(),
            ordinary_calls + 1,
            "a zero-origin ordinary-session span enters the ordinary full route",
        );

        let expected_iter = vec![expected.expect("hit span")];
        let accounted_iter = regex
            .find_iter(hit, PortableFindIterLimits::unlimited())
            .expect("accounted iterator")
            .map(|matched| {
                let matched = matched.expect("accounted iterator item");
                (matched.start(), matched.end())
            })
            .collect::<Vec<_>>();
        assert_eq!(accounted_iter, expected_iter);
        let value_iter = regex
            .find_iter_value(hit, PortableFindIterLimits::unlimited())
            .expect("value iterator")
            .map(|matched| {
                let matched = matched.expect("value iterator item");
                (matched.start(), matched.end())
            })
            .collect::<Vec<_>>();
        assert_eq!(value_iter, expected_iter);

        let mut locations = regex.capture_locations();
        assert_eq!(
            regex
                .captures_read_value(&mut locations, hit, SearchLimits::unlimited())
                .expect("capture-free locations")
                .map(|matched| (matched.start(), matched.end())),
            expected,
        );
        assert!(matches!(
            regex.find_value(
                hit,
                SearchLimits {
                    max_work: 0,
                    max_scratch_bytes: 0,
                },
            ),
            Err(SearchError::UnicodeWordRun(
                UnicodeWordRunError::WorkLimitExceeded { .. }
            ))
        ));
        assert_eq!(
            ordinary_find_probe::calls(),
            ordinary_calls + 1,
            "iterator, capture, boolean, and finite refusal APIs stay canonical",
        );

        let bounded_plan = plan(r"\b\p{Greek}{2,8}\b", true);
        assert_eq!(bounded_plan.ordinary_find_full_unmetered(hit), None);
        let ascii_plan = plan(r"(?-u:\b[A-Z]+\b)", false);
        assert_eq!(ascii_plan.ordinary_find_full_unmetered(b"ABC"), None);
        let exact_bytes = plan(r"(?-u:\b[\x80-\x81]+\b)", false);
        assert_eq!(exact_bytes.ordinary_find_full_unmetered(&[0x80]), None);

        let bounded = PortableBuilder::new(r"\b\p{Greek}{2,8}\b")
            .unicode(true)
            .build()
            .expect("bounded maximum fallback fixture");
        assert_eq!(bounded.runtime_implementation_id(), PLAN_ID);
        assert_eq!(
            bounded
                .find(hit)
                .map(|matched| (matched.start(), matched.end())),
            expected,
        );
        assert_eq!(ordinary_find_probe::calls(), ordinary_calls + 1);
    }

    #[test]
    fn explicit_capture_apis_do_not_enter_the_ordinary_find_route() {
        let regex = PortableBuilder::new(r"(\b\p{Greek}+\b)")
            .unicode(true)
            .build()
            .expect("captured bounded Unicode word-class facade");
        assert_eq!(regex.runtime_implementation_id(), PLAN_ID);
        assert_eq!(regex.captures_len(), 2);
        let haystack = "!Ωμέγα!".as_bytes();
        let mut locations = regex.capture_locations();

        ordinary_find_probe::reset();
        assert!(matches!(
            regex.captures_read(
                &mut locations,
                haystack,
                SearchLimits::unlimited(),
            ),
            Err(PortableCapturesReadError::ExplicitCapturesUnsupported { captures: 1 })
        ));
        assert!(matches!(
            regex.captures_read_value(
                &mut locations,
                haystack,
                SearchLimits::unlimited(),
            ),
            Err(PortableCapturesReadError::ExplicitCapturesUnsupported { captures: 1 })
        ));
        assert_eq!(locations.get(0), None);
        assert_eq!(locations.get(1), None);
        assert_eq!(ordinary_find_probe::calls(), 0);

        assert_eq!(
            regex
                .find(haystack)
                .map(|matched| (matched.start(), matched.end())),
            Some((1, haystack.len() - 1)),
        );
        assert_eq!(ordinary_find_probe::calls(), 1);
    }
}
