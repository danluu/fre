//! Source proofs and native owners for finite deterministic prefixes and tails.
//!
//! The admitted HIR language is exactly `bytes{pmin,pmax} SUFFIX`: one or more
//! finite greedy repetitions (or fixed one-byte terms) whose body accepts every
//! byte independently, followed by one nonempty exact literal. Multiple prefix
//! terms remain safe even though their byte languages overlap completely. For
//! any fixed match start, each attainable total prefix width has one
//! lexicographically greatest feasible length vector. Those representatives
//! are monotone in total width because every remaining sum of finite integer
//! intervals is itself an interval. Greedy backtracking therefore reaches the
//! latest suffix position that can match before any earlier one. (The raw
//! lexicographic order of every feasible vector is not, by itself, total-width
//! order.)
//!
//! This proof deliberately does not infer universality from a whole-graph union
//! of consuming edges. Each repeated position must independently accept all 256
//! bytes. Variable-width alternation, correlated multi-byte branches, looks,
//! Unicode scalar classes, lazy repetition and a merely partial literal tail
//! all fail closed. The late K0 caller supplies the exact graph-proved suffix
//! and admission binds it to the entire HIR tail. The stricter early native
//! route retains a one-byte exact tail directly from the same metered walk.
//! A multi-byte tail is retained only by the independently proved delimited
//! shape below; other multi-byte tails remain eligible for K0's existing
//! mandatory-cut and suffix machinery.
//!
//! The early native route also admits the disjoint delimited language
//! `(C{m,n}D){p,q}S`, where both repetitions are finite, positive, and greedy,
//! `D` is one byte outside `C`, and the first byte of nonempty exact `S`
//! belongs to neither `C` nor `D`. Every `S` occurrence is consequently a
//! barrier that no repeated token can cross. Visiting `S` occurrences in
//! source order and recovering at most `q` bounded class runs backwards makes
//! the first successful occurrence both the earliest accepting end and the
//! selected leftmost-first match. At a fixed recovered start, the next byte
//! after each delimiter selects either another token (`C`) or the tail (`S`),
//! never both, so the selected greedy endpoint is unique.

use core::mem::size_of;

use fre_automata::SearchWindow;
use fre_kernels::{
    BYTE_SET_BLOCK_BYTES, BYTE_SET_CLASSIFIER_BUILD_WORK, ByteSet256, ByteSetClassifier,
    DispatchPolicy,
    LiteralBuildLimits, LiteralError, LiteralPlan, LiteralSearchLimits,
    RequiredLiteralSearchAccounting as SearchAccounting,
    RequiredLiteralSearchError as SearchError, RequiredLiteralSearchLimits as SearchLimits,
    SimdDispatchContext, Window as LiteralWindow,
};
use regex_syntax::hir::{Class, Hir, HirKind};

use crate::pure_byte_class_repeat::SetSeek;

const NODE_INSPECTION_WORK: u64 = 1;
const RANGE_INSPECTION_WORK: u64 = 1;
const MEMBER_INSERTION_WORK: u64 = 1;
const BITMAP_WORD_WORK: u64 = 1;
const WIDTH_ARITHMETIC_WORK: u64 = 1;
const SUFFIX_LENGTH_WORK: u64 = 1;
const SUFFIX_BYTE_WORK: u64 = 1;
const SEEK_SELECTION_WORK: u64 = 1;
const UNIVERSAL_WORDS: [u64; 4] = [u64::MAX; 4];
const SEARCH_BASE_WORK: u64 = 8;
const SEARCH_CALL_WORK: u64 = 8;
const NATIVE_SUFFIX_BYTES: usize = 1;

#[cfg(test)]
pub(crate) mod value_path_probe {
    use core::cell::Cell;

    std::thread_local! {
        static COUNTS: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
    }

    pub(crate) fn reset() {
        COUNTS.set((0, 0));
    }

    pub(crate) fn snapshot() -> (usize, usize) {
        COUNTS.get()
    }

    pub(super) fn record_exists() {
        let (exists, span) = COUNTS.get();
        COUNTS.set((exists.saturating_add(1), span));
    }

    pub(super) fn record_span() {
        let (exists, span) = COUNTS.get();
        COUNTS.set((exists, span.saturating_add(1)));
    }
}

/// Stable identity for the early source-proved native owner.
pub(crate) const PLAN_ID: &str = "required-literal.universal-finite-greedy-corridor.v1";
pub(crate) const DELIMITED_SEGMENT_PLAN_ID: &str =
    "required-literal.bounded-delimited-segment-repeat.v1";

/// Exact source-independent language geometry proved by one inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Descriptor {
    minimum_prefix_bytes: usize,
    maximum_prefix_bytes: usize,
    minimum_match_bytes: usize,
    maximum_match_bytes: usize,
    suffix_bytes: usize,
}

impl Descriptor {
    pub(crate) const fn minimum_prefix_bytes(self) -> usize {
        self.minimum_prefix_bytes
    }

    pub(crate) const fn maximum_prefix_bytes(self) -> usize {
        self.maximum_prefix_bytes
    }

    pub(crate) const fn minimum_match_bytes(self) -> usize {
        self.minimum_match_bytes
    }

    pub(crate) const fn maximum_match_bytes(self) -> usize {
        self.maximum_match_bytes
    }

    pub(crate) const fn suffix_bytes(self) -> usize {
        self.suffix_bytes
    }
}

/// Completed optional proof and its exact cumulative planner work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Inspection {
    descriptor: Descriptor,
    planner_work: u64,
}

impl Inspection {
    pub(crate) const fn descriptor(self) -> Descriptor {
        self.descriptor
    }

    pub(crate) const fn planner_work(self) -> u64 {
        self.planner_work
    }
}

/// Transactional result of one optional structural proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

/// Hard planner refusal. Semantic shape mismatches are ordinary ineligibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InspectionError {
    WorkLimit {
        actual: u64,
        needed: u64,
        limit: u64,
    },
    ArithmeticOverflow,
}

/// Borrowed source authority for construction before generic K0 lowering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeInspection<'hir> {
    descriptor: Descriptor,
    suffix: &'hir [u8],
    planner_work: u64,
}

impl<'hir> NativeInspection<'hir> {
    pub(crate) const fn descriptor(self) -> Descriptor {
        self.descriptor
    }

    pub(crate) const fn suffix(self) -> &'hir [u8] {
        self.suffix
    }

    #[cfg(test)]
    pub(crate) const fn planner_work(self) -> u64 {
        self.planner_work
    }
}

/// Borrowed source authority for the disjoint bounded-delimited owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DelimitedSegmentInspection<'hir> {
    descriptor: Descriptor,
    suffix: &'hir [u8],
    segment: DelimitedSegment,
    classifier_words: Option<[u64; 4]>,
    planner_work: u64,
}

impl<'hir> DelimitedSegmentInspection<'hir> {
    pub(crate) const fn descriptor(self) -> Descriptor {
        self.descriptor
    }

    pub(crate) const fn suffix(self) -> &'hir [u8] {
        self.suffix
    }

    #[cfg(test)]
    pub(crate) const fn planner_work(self) -> u64 {
        self.planner_work
    }
}

/// Transactional source-only result for the early native route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeInspectionOutcome<'hir> {
    Eligible(NativeInspection<'hir>),
    Delimited(DelimitedSegmentInspection<'hir>),
    Ineligible { planner_work: u64 },
}

impl NativeInspectionOutcome<'_> {
    pub(crate) const fn planner_work(self) -> u64 {
        match self {
            Self::Eligible(inspection) => inspection.planner_work,
            Self::Delimited(inspection) => inspection.planner_work,
            Self::Ineligible { planner_work } => planner_work,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Run {
    minimum: usize,
    maximum: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DelimitedSegment {
    class_words: [u64; 4],
    class_minimum: usize,
    class_maximum: usize,
    segment_minimum: usize,
    segment_maximum: usize,
    delimiter: u8,
    member_seek: SetSeek,
    run_end_seek: SetSeek,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Meter {
    work: u64,
    limit: u64,
}

impl Meter {
    fn new(initial_work: u64, limit: u64) -> Result<Self, InspectionError> {
        if initial_work > limit {
            return Err(InspectionError::WorkLimit {
                actual: limit,
                needed: initial_work,
                limit,
            });
        }
        Ok(Self {
            work: initial_work,
            limit,
        })
    }

    fn charge(&mut self, additional: u64) -> Result<(), InspectionError> {
        let needed = self
            .work
            .checked_add(additional)
            .ok_or(InspectionError::ArithmeticOverflow)?;
        if needed > self.limit {
            return Err(InspectionError::WorkLimit {
                actual: self.work,
                needed,
                limit: self.limit,
            });
        }
        self.work = needed;
        Ok(())
    }
}

/// Prove one exact all-greedy `bytes{pmin,pmax} SUFFIX` HIR language.
///
/// `mandatory_suffix` must be the exact nonempty suffix independently bound to
/// the lower plan that will consume this descriptor. This analyzer allocates
/// nothing and returns the exact cumulative work completed on both admission
/// and semantic decline.
pub(crate) fn inspect(
    hir: &Hir,
    mandatory_suffix: &[u8],
    initial_work: u64,
    max_planner_work: u64,
) -> Result<InspectionOutcome, InspectionError> {
    let mut meter = Meter::new(initial_work, max_planner_work)?;
    let inspected = inspect_inner(hir, Some(mandatory_suffix), true, &mut meter)?;
    Ok(match inspected {
        Some((descriptor, _)) => InspectionOutcome::Eligible(Inspection {
            descriptor,
            planner_work: meter.work,
        }),
        None => InspectionOutcome::Ineligible {
            planner_work: meter.work,
        },
    })
}

/// Prove and retain one source literal without first constructing a K0 graph.
///
/// The caller separately authenticates that the parsed source has no explicit
/// captures before publishing this capture-erasing owner. This stricter route
/// also declines every retained HIR alternation, even a byte-universal union.
/// Universal corridors require a single-byte suffix. Multi-byte suffixes are
/// retained only by the disjoint bounded-delimited shape; all others retain
/// the existing K0 mandatory-cut and adaptive negative-proof routes. The late
/// K0 theorem remains available for every source shape declined here.
pub(crate) fn inspect_native(
    hir: &Hir,
    initial_work: u64,
    max_planner_work: u64,
) -> Result<NativeInspectionOutcome<'_>, InspectionError> {
    let mut meter = Meter::new(initial_work, max_planner_work)?;
    let inspected = inspect_inner(hir, None, false, &mut meter)?;
    if let Some((descriptor, suffix)) = inspected {
        return Ok(if suffix.len() == NATIVE_SUFFIX_BYTES {
            NativeInspectionOutcome::Eligible(NativeInspection {
                descriptor,
                suffix,
                planner_work: meter.work,
            })
        } else {
            NativeInspectionOutcome::Ineligible {
                planner_work: meter.work,
            }
        });
    }
    Ok(match inspect_delimited_segment_inner(hir, &mut meter)? {
        Some((descriptor, suffix, segment, classifier_words)) => {
            NativeInspectionOutcome::Delimited(DelimitedSegmentInspection {
                descriptor,
                suffix,
                segment,
                classifier_words,
                planner_work: meter.work,
            })
        }
        None => NativeInspectionOutcome::Ineligible {
            planner_work: meter.work,
        },
    })
}

#[cold]
#[inline(never)]
fn inspect_delimited_segment_inner<'hir>(
    hir: &'hir Hir,
    meter: &mut Meter,
) -> Result<
    Option<(
        Descriptor,
        &'hir [u8],
        DelimitedSegment,
        Option<[u64; 4]>,
    )>,
    InspectionError,
> {
    let root = peel_captures(hir, meter)?;
    let HirKind::Concat(parts) = root.kind() else {
        return Ok(None);
    };
    let [repeated, tail] = parts.as_slice() else {
        return Ok(None);
    };
    let Some(suffix) = exact_suffix(tail, None, meter)? else {
        return Ok(None);
    };

    let repeated = peel_captures(repeated, meter)?;
    let HirKind::Repetition(segment_repeat) = repeated.kind() else {
        return Ok(None);
    };
    let Some(segment_maximum) = segment_repeat.max else {
        return Ok(None);
    };
    if !segment_repeat.greedy
        || segment_repeat.min == 0
        || segment_maximum < segment_repeat.min
    {
        return Ok(None);
    }
    let Ok(segment_minimum) = usize::try_from(segment_repeat.min) else {
        return Ok(None);
    };
    let Ok(segment_maximum) = usize::try_from(segment_maximum) else {
        return Ok(None);
    };

    let segment = peel_captures(&segment_repeat.sub, meter)?;
    let HirKind::Concat(segment_parts) = segment.kind() else {
        return Ok(None);
    };
    let [class_run, delimiter_hir] = segment_parts.as_slice() else {
        return Ok(None);
    };
    let class_run = peel_captures(class_run, meter)?;
    let HirKind::Repetition(class_repeat) = class_run.kind() else {
        return Ok(None);
    };
    let Some(class_maximum) = class_repeat.max else {
        return Ok(None);
    };
    if !class_repeat.greedy || class_repeat.min == 0 || class_maximum < class_repeat.min {
        return Ok(None);
    }
    let Ok(class_minimum) = usize::try_from(class_repeat.min) else {
        return Ok(None);
    };
    let Ok(class_maximum) = usize::try_from(class_maximum) else {
        return Ok(None);
    };
    let Some(class_words) =
        inspect_one_byte_language(&class_repeat.sub, false, meter)?
    else {
        return Ok(None);
    };
    if class_words.iter().all(|word| *word == 0) {
        return Ok(None);
    }
    let Some(delimiter) = exact_suffix(delimiter_hir, None, meter)? else {
        return Ok(None);
    };
    let [delimiter] = delimiter else {
        return Ok(None);
    };
    meter.charge(BITMAP_WORD_WORK)?;
    if byte_is_member(class_words, *delimiter) {
        return Ok(None);
    }
    meter.charge(BITMAP_WORD_WORK)?;
    if suffix[0] == *delimiter || byte_is_member(class_words, suffix[0]) {
        return Ok(None);
    }

    let Some(class_minimum_with_delimiter) =
        checked_add_width(class_minimum, 1, meter)?
    else {
        return Ok(None);
    };
    let Some(class_maximum_with_delimiter) =
        checked_add_width(class_maximum, 1, meter)?
    else {
        return Ok(None);
    };
    let Some(minimum_prefix_bytes) = checked_mul_width(
        class_minimum_with_delimiter,
        segment_minimum,
        meter,
    )? else {
        return Ok(None);
    };
    let Some(maximum_prefix_bytes) = checked_mul_width(
        class_maximum_with_delimiter,
        segment_maximum,
        meter,
    )? else {
        return Ok(None);
    };
    let Some(minimum_match_bytes) =
        checked_add_width(minimum_prefix_bytes, suffix.len(), meter)?
    else {
        return Ok(None);
    };
    let Some(maximum_match_bytes) =
        checked_add_width(maximum_prefix_bytes, suffix.len(), meter)?
    else {
        return Ok(None);
    };
    let class_cardinality = class_words
        .iter()
        .map(|word| word.count_ones())
        .sum::<u32>();
    meter.charge(SEEK_SELECTION_WORK)?;
    let member_seek = SetSeek::build(class_words, class_cardinality, false);
    meter.charge(SEEK_SELECTION_WORK)?;
    let run_end_seek = SetSeek::build(
        class_words.map(|word| !word),
        256_u32 - class_cardinality,
        member_seek.requires_classifier(),
    );
    if member_seek.requires_classifier() || run_end_seek.requires_classifier() {
        meter.charge(
            u64::try_from(BYTE_SET_CLASSIFIER_BUILD_WORK)
                .map_err(|_| InspectionError::ArithmeticOverflow)?,
        )?;
    }
    let classifier_words = if member_seek.requires_classifier() {
        Some(class_words)
    } else if run_end_seek.requires_classifier() {
        Some(class_words.map(|word| !word))
    } else {
        None
    };
    Ok(Some((
        Descriptor {
            minimum_prefix_bytes,
            maximum_prefix_bytes,
            minimum_match_bytes,
            maximum_match_bytes,
            suffix_bytes: suffix.len(),
        },
        suffix,
        DelimitedSegment {
            class_words,
            class_minimum,
            class_maximum,
            segment_minimum,
            segment_maximum,
            delimiter: *delimiter,
            member_seek,
            run_end_seek,
        },
        classifier_words,
    )))
}

fn inspect_inner<'hir>(
    hir: &'hir Hir,
    mandatory_suffix: Option<&[u8]>,
    allow_alternation: bool,
    meter: &mut Meter,
) -> Result<Option<(Descriptor, &'hir [u8])>, InspectionError> {
    let root = peel_captures(hir, meter)?;
    let HirKind::Concat(parts) = root.kind() else {
        return Ok(None);
    };
    let Some((tail, prefix)) = parts.split_last() else {
        return Ok(None);
    };
    let Some(suffix) = exact_suffix(tail, mandatory_suffix, meter)? else {
        return Ok(None);
    };
    if prefix.is_empty() {
        return Ok(None);
    }

    let mut minimum_prefix_bytes = 0_usize;
    let mut maximum_prefix_bytes = 0_usize;
    for part in prefix {
        let Some(run) = inspect_run(part, allow_alternation, meter)? else {
            return Ok(None);
        };
        let Some(next_minimum) =
            checked_add_width(minimum_prefix_bytes, run.minimum, meter)?
        else {
            return Ok(None);
        };
        let Some(next_maximum) =
            checked_add_width(maximum_prefix_bytes, run.maximum, meter)?
        else {
            return Ok(None);
        };
        minimum_prefix_bytes = next_minimum;
        maximum_prefix_bytes = next_maximum;
    }

    let Some(minimum_match_bytes) =
        checked_add_width(minimum_prefix_bytes, suffix.len(), meter)?
    else {
        return Ok(None);
    };
    let Some(maximum_match_bytes) =
        checked_add_width(maximum_prefix_bytes, suffix.len(), meter)?
    else {
        return Ok(None);
    };
    Ok(Some((
        Descriptor {
            minimum_prefix_bytes,
            maximum_prefix_bytes,
            minimum_match_bytes,
            maximum_match_bytes,
            suffix_bytes: suffix.len(),
        },
        suffix,
    )))
}

fn exact_suffix<'hir>(
    hir: &'hir Hir,
    mandatory_suffix: Option<&[u8]>,
    meter: &mut Meter,
) -> Result<Option<&'hir [u8]>, InspectionError> {
    let tail = peel_captures(hir, meter)?;
    let HirKind::Literal(literal) = tail.kind() else {
        return Ok(None);
    };
    meter.charge(SUFFIX_LENGTH_WORK)?;
    if literal.0.is_empty()
        || mandatory_suffix.is_some_and(|expected| literal.0.len() != expected.len())
    {
        return Ok(None);
    }
    for (index, &actual) in literal.0.iter().enumerate() {
        meter.charge(SUFFIX_BYTE_WORK)?;
        if mandatory_suffix.is_some_and(|expected| actual != expected[index]) {
            return Ok(None);
        }
    }
    Ok(Some(&literal.0))
}

fn inspect_run(
    hir: &Hir,
    allow_alternation: bool,
    meter: &mut Meter,
) -> Result<Option<Run>, InspectionError> {
    let hir = peel_captures(hir, meter)?;
    let (words, minimum, maximum) = match hir.kind() {
        HirKind::Repetition(repetition) => {
            let Some(maximum) = repetition.max else {
                return Ok(None);
            };
            if !repetition.greedy || maximum == 0 || maximum < repetition.min {
                return Ok(None);
            }
            let Ok(minimum) = usize::try_from(repetition.min) else {
                return Ok(None);
            };
            let Ok(maximum) = usize::try_from(maximum) else {
                return Ok(None);
            };
            let Some(words) =
                inspect_one_byte_language(&repetition.sub, allow_alternation, meter)?
            else {
                return Ok(None);
            };
            (words, minimum, maximum)
        }
        _ => {
            let Some(words) =
                inspect_one_byte_language_peeled(hir, allow_alternation, meter)?
            else {
                return Ok(None);
            };
            (words, 1, 1)
        }
    };
    if !is_universal(words, meter)? {
        return Ok(None);
    }
    Ok(Some(Run { minimum, maximum }))
}

fn inspect_one_byte_language(
    hir: &Hir,
    allow_alternation: bool,
    meter: &mut Meter,
) -> Result<Option<[u64; 4]>, InspectionError> {
    let hir = peel_captures(hir, meter)?;
    inspect_one_byte_language_peeled(hir, allow_alternation, meter)
}

fn inspect_one_byte_language_peeled(
    hir: &Hir,
    allow_alternation: bool,
    meter: &mut Meter,
) -> Result<Option<[u64; 4]>, InspectionError> {
    match hir.kind() {
        HirKind::Class(Class::Bytes(class)) => {
            let mut words = [0_u64; 4];
            for range in class.ranges() {
                meter.charge(RANGE_INSPECTION_WORK)?;
                if range.start() > range.end() {
                    return Ok(None);
                }
                for byte in range.start()..=range.end() {
                    meter.charge(MEMBER_INSERTION_WORK)?;
                    let word = usize::from(byte >> 6);
                    let bit = u32::from(byte & 63);
                    words[word] |= 1_u64 << bit;
                }
            }
            Ok(Some(words))
        }
        HirKind::Literal(literal) if literal.0.len() == 1 => {
            meter.charge(MEMBER_INSERTION_WORK)?;
            let byte = literal.0[0];
            let word = usize::from(byte >> 6);
            let bit = u32::from(byte & 63);
            let mut words = [0_u64; 4];
            words[word] |= 1_u64 << bit;
            Ok(Some(words))
        }
        HirKind::Alternation(alternatives)
            if allow_alternation && !alternatives.is_empty() =>
        {
            let mut words = [0_u64; 4];
            for alternative in alternatives {
                let Some(branch) =
                    inspect_one_byte_language(alternative, allow_alternation, meter)?
                else {
                    return Ok(None);
                };
                for (word, branch_word) in words.iter_mut().zip(branch) {
                    meter.charge(BITMAP_WORD_WORK)?;
                    *word |= branch_word;
                }
            }
            Ok(Some(words))
        }
        HirKind::Class(Class::Unicode(_))
        | HirKind::Empty
        | HirKind::Literal(_)
        | HirKind::Look(_)
        | HirKind::Repetition(_)
        | HirKind::Capture(_)
        | HirKind::Concat(_)
        | HirKind::Alternation(_) => Ok(None),
    }
}

fn is_universal(words: [u64; 4], meter: &mut Meter) -> Result<bool, InspectionError> {
    let mut universal = true;
    for (word, expected) in words.into_iter().zip(UNIVERSAL_WORDS) {
        meter.charge(BITMAP_WORD_WORK)?;
        universal &= word == expected;
    }
    Ok(universal)
}

fn byte_is_member(words: [u64; 4], byte: u8) -> bool {
    let word = usize::from(byte >> 6);
    let bit = u32::from(byte & 63);
    words[word] & (1_u64 << bit) != 0
}

fn checked_add_width(
    left: usize,
    right: usize,
    meter: &mut Meter,
) -> Result<Option<usize>, InspectionError> {
    meter.charge(WIDTH_ARITHMETIC_WORK)?;
    Ok(left.checked_add(right))
}

fn checked_mul_width(
    left: usize,
    right: usize,
    meter: &mut Meter,
) -> Result<Option<usize>, InspectionError> {
    meter.charge(WIDTH_ARITHMETIC_WORK)?;
    Ok(left.checked_mul(right))
}

fn peel_captures<'h>(
    mut hir: &'h Hir,
    meter: &mut Meter,
) -> Result<&'h Hir, InspectionError> {
    loop {
        meter.charge(NODE_INSPECTION_WORK)?;
        let HirKind::Capture(capture) = hir.kind() else {
            return Ok(hir);
        };
        hir = &capture.sub;
    }
}

/// Boxed native owner for one source-proved universal finite corridor.
///
/// For each suffix occurrence at `q`, valid starts form the interval
/// `[q - pmax, q - pmin]`. These intervals move monotonically right as `q`
/// increases, so the first suffix at or after `window.start + pmin` proves the
/// globally earliest match start. Once that start is fixed, greedy priority is
/// exactly the last overlapping suffix occurrence in its finite corridor.
#[derive(Debug)]
pub(crate) struct Plan {
    suffix: LiteralPlan,
    descriptor: Descriptor,
}

impl Plan {
    pub(crate) fn projected_storage_bytes(suffix_bytes: usize) -> Option<usize> {
        size_of::<Self>().checked_add(suffix_bytes)
    }

    pub(crate) fn build(
        inspection: NativeInspection<'_>,
        limits: LiteralBuildLimits,
    ) -> Result<Self, LiteralError> {
        debug_assert_eq!(inspection.descriptor.suffix_bytes, inspection.suffix.len());
        let suffix = LiteralPlan::new(inspection.suffix, limits)?;
        Ok(Self {
            suffix,
            descriptor: inspection.descriptor,
        })
    }

    pub(crate) const fn plan_id(&self) -> &'static str {
        PLAN_ID
    }

    pub(crate) fn storage_bytes(&self) -> Option<usize> {
        Self::projected_storage_bytes(self.suffix.storage_bytes())
    }

    pub(crate) fn is_match_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(bool, SearchAccounting), SearchError> {
        let (end, accounting) = self.shortest_window(haystack, window, limits)?;
        Ok((end.is_some(), accounting))
    }

    pub(crate) fn is_match_window_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        #[cfg(test)]
        value_path_probe::record_exists();
        self.preflight(haystack.len(), window, 1, limits)?;
        self.first_suffix_value(haystack, window)
            .map(|matched| matched.is_some())
    }

    pub(crate) fn shortest_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        let mut accounting = self.preflight(haystack.len(), window, 1, limits)?;
        let matched = self.first_suffix(haystack, window, &mut accounting)?;
        Ok((matched.map(|(_, end)| end), accounting))
    }

    pub(crate) fn find_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        let mut accounting = self.preflight(haystack.len(), window, 2, limits)?;
        let Some((first_suffix_start, first_suffix_end)) =
            self.first_suffix(haystack, window, &mut accounting)?
        else {
            return Ok((None, accounting));
        };

        let selected_start = first_suffix_start
            .saturating_sub(self.descriptor.maximum_prefix_bytes)
            .max(window.start());
        let corridor_end = selected_start
            .saturating_add(self.descriptor.maximum_match_bytes)
            .min(window.end());
        accounting.finder_calls = 2;
        let (last_suffix, _) = self
            .suffix
            .rfind_window(
                haystack,
                LiteralWindow::new(first_suffix_start, corridor_end),
                LiteralSearchLimits::unlimited(),
            )
            .map_err(map_literal_search_error)?;
        if last_suffix.is_some() {
            accounting.candidate_visits = 2;
        }
        // The reverse window contains the already authenticated first suffix,
        // so a miss is unreachable. Refuse instead of returning a valid but
        // potentially nongreedy span if a native finder violates that contract.
        let Some((_, selected_end)) = last_suffix else {
            return Err(SearchError::ArithmeticOverflow {
                computation: "universal corridor reverse finder lost its authenticated suffix",
            });
        };
        if selected_end < first_suffix_end {
            return Err(SearchError::ArithmeticOverflow {
                computation: "universal corridor reverse finder moved before its first suffix",
            });
        }
        Ok((Some((selected_start, selected_end)), accounting))
    }

    pub(crate) fn find_window_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<Option<(usize, usize)>, SearchError> {
        #[cfg(test)]
        value_path_probe::record_span();
        self.preflight(haystack.len(), window, 2, limits)?;
        let Some((first_suffix_start, first_suffix_end)) =
            self.first_suffix_value(haystack, window)?
        else {
            return Ok(None);
        };

        let selected_start = first_suffix_start
            .saturating_sub(self.descriptor.maximum_prefix_bytes)
            .max(window.start());
        let corridor_end = selected_start
            .saturating_add(self.descriptor.maximum_match_bytes)
            .min(window.end());
        let last_suffix = self
            .suffix
            .rfind_window_value(
                haystack,
                LiteralWindow::new(first_suffix_start, corridor_end),
                LiteralSearchLimits::unlimited(),
            )
            .map_err(map_literal_search_error)?;
        let Some((_, selected_end)) = last_suffix else {
            return Err(SearchError::ArithmeticOverflow {
                computation: "universal corridor reverse finder lost its authenticated suffix",
            });
        };
        if selected_end < first_suffix_end {
            return Err(SearchError::ArithmeticOverflow {
                computation: "universal corridor reverse finder moved before its first suffix",
            });
        }
        Ok(Some((selected_start, selected_end)))
    }

    fn first_suffix_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
    ) -> Result<Option<(usize, usize)>, SearchError> {
        let Some(suffix_window_start) = window
            .start()
            .checked_add(self.descriptor.minimum_prefix_bytes)
        else {
            return Ok(None);
        };
        if suffix_window_start > window.end() {
            return Ok(None);
        }
        self.suffix
            .find_window_value(
                haystack,
                LiteralWindow::new(suffix_window_start, window.end()),
                LiteralSearchLimits::unlimited(),
            )
            .map_err(map_literal_search_error)
    }

    fn first_suffix(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        accounting: &mut SearchAccounting,
    ) -> Result<Option<(usize, usize)>, SearchError> {
        let Some(suffix_window_start) = window
            .start()
            .checked_add(self.descriptor.minimum_prefix_bytes)
        else {
            return Ok(None);
        };
        if suffix_window_start > window.end() {
            return Ok(None);
        }
        accounting.finder_calls = 1;
        let (matched, _) = self
            .suffix
            .find_window(
                haystack,
                LiteralWindow::new(suffix_window_start, window.end()),
                LiteralSearchLimits::unlimited(),
            )
            .map_err(map_literal_search_error)?;
        if matched.is_some() {
            accounting.candidate_visits = 1;
        }
        Ok(matched)
    }

    fn preflight(
        &self,
        haystack_len: usize,
        window: SearchWindow,
        finder_calls_upper_bound: usize,
        limits: SearchLimits,
    ) -> Result<SearchAccounting, SearchError> {
        if window.start() > window.end() || window.end() > haystack_len {
            return Err(SearchError::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len,
            });
        }
        if finder_calls_upper_bound > limits.max_candidate_visits {
            return Err(SearchError::CandidateLimit {
                needed: finder_calls_upper_bound,
                limit: limits.max_candidate_visits,
            });
        }
        let window_bytes = window.end().checked_sub(window.start()).ok_or(
            SearchError::ArithmeticOverflow {
                computation: "universal corridor window bytes",
            },
        )?;
        let one_finder_work = window_bytes.checked_add(self.suffix.needle().len()).ok_or(
            SearchError::ArithmeticOverflow {
                computation: "universal corridor finder terms",
            },
        )?;
        let finder_work = one_finder_work
            .checked_mul(finder_calls_upper_bound)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "universal corridor finder work",
            })?;
        let finder_work_upper_bound = u64::try_from(finder_work).map_err(|_| {
            SearchError::ArithmeticOverflow {
                computation: "universal corridor finder work as u64",
            }
        })?;
        let call_work = u64::try_from(finder_calls_upper_bound)
            .ok()
            .and_then(|calls| calls.checked_mul(SEARCH_CALL_WORK))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "universal corridor structural work",
            })?;
        let work_upper_bound = finder_work_upper_bound
            .checked_add(SEARCH_BASE_WORK)
            .and_then(|work| work.checked_add(call_work))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "universal corridor total work",
            })?;
        if work_upper_bound > limits.max_work_upper_bound {
            return Err(SearchError::WorkLimit {
                needed: work_upper_bound,
                limit: limits.max_work_upper_bound,
            });
        }
        Ok(SearchAccounting {
            window_bytes,
            candidate_visits_upper_bound: finder_calls_upper_bound,
            finder_calls_upper_bound,
            finder_work_upper_bound,
            backward_work_upper_bound: 0,
            work_upper_bound,
            scratch_bytes: 0,
            candidate_visits: 0,
            finder_calls: 0,
            backward_bytes_examined: 0,
        })
    }
}

/// Boxed native owner for one source-proved bounded-delimited segment repeat.
#[derive(Debug)]
pub(crate) struct BoundedDelimitedSegmentPlan {
    suffix: LiteralPlan,
    descriptor: Descriptor,
    segment: DelimitedSegment,
    class_classifier: Option<ByteSetClassifier>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DelimitedSearchUpperBounds {
    window_bytes: usize,
    candidate_visits_upper_bound: usize,
    finder_calls_upper_bound: usize,
    finder_work_upper_bound: u64,
    backward_work_upper_bound: usize,
    work_upper_bound: u64,
}

impl DelimitedSearchUpperBounds {
    fn into_accounting(self) -> SearchAccounting {
        SearchAccounting {
            window_bytes: self.window_bytes,
            candidate_visits_upper_bound: self.candidate_visits_upper_bound,
            finder_calls_upper_bound: self.finder_calls_upper_bound,
            finder_work_upper_bound: self.finder_work_upper_bound,
            backward_work_upper_bound: self.backward_work_upper_bound,
            work_upper_bound: self.work_upper_bound,
            scratch_bytes: 0,
            candidate_visits: 0,
            finder_calls: 0,
            backward_bytes_examined: 0,
        }
    }
}

trait DelimitedSearchRecorder {
    type Output;

    fn finish(self, matched: Option<(usize, usize)>) -> Self::Output;

    #[inline(always)]
    fn record_forward_candidate(&mut self) -> Result<(), SearchError> {
        Ok(())
    }

    #[inline(always)]
    fn record_backward_byte(&mut self) -> Result<(), SearchError> {
        Ok(())
    }
}

impl DelimitedSearchRecorder for () {
    // Successful preflight computes finite `usize` bounds that dominate every
    // candidate and byte-probe counter below. The reported checked additions
    // therefore cannot overflow, so erasing them here removes only receipt
    // projection and cannot erase a reachable semantic failure.
    type Output = Option<(usize, usize)>;

    #[inline(always)]
    fn finish(self, matched: Option<(usize, usize)>) -> Self::Output {
        matched
    }
}

impl DelimitedSearchRecorder for SearchAccounting {
    type Output = (Option<(usize, usize)>, SearchAccounting);

    #[inline(always)]
    fn finish(self, matched: Option<(usize, usize)>) -> Self::Output {
        (matched, self)
    }

    #[inline(always)]
    fn record_forward_candidate(&mut self) -> Result<(), SearchError> {
        self.candidate_visits =
            self.candidate_visits
                .checked_add(1)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "delimited segment forward candidates",
                })?;
        Ok(())
    }

    #[inline(always)]
    fn record_backward_byte(&mut self) -> Result<(), SearchError> {
        self.backward_bytes_examined =
            self.backward_bytes_examined
                .checked_add(1)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "delimited segment backward-byte accounting",
                })?;
        Ok(())
    }
}

impl BoundedDelimitedSegmentPlan {
    pub(crate) fn projected_storage_bytes(suffix_bytes: usize) -> Option<usize> {
        size_of::<Self>().checked_add(suffix_bytes)
    }

    #[cold]
    #[inline(never)]
    pub(crate) fn build(
        inspection: DelimitedSegmentInspection<'_>,
        limits: LiteralBuildLimits,
    ) -> Result<Self, LiteralError> {
        debug_assert_eq!(inspection.descriptor.suffix_bytes, inspection.suffix.len());
        let suffix = LiteralPlan::new(inspection.suffix, limits)?;
        let class_classifier = inspection.classifier_words.map(|words| {
            SimdDispatchContext::capture()
                .byte_set_classifier(ByteSet256::from_words(words), DispatchPolicy::Auto)
                .expect("automatic byte-set dispatch retains a scalar fallback")
        });
        Ok(Self {
            suffix,
            descriptor: inspection.descriptor,
            segment: inspection.segment,
            class_classifier,
        })
    }

    pub(crate) const fn plan_id(&self) -> &'static str {
        DELIMITED_SEGMENT_PLAN_ID
    }

    pub(crate) fn storage_bytes(&self) -> Option<usize> {
        Self::projected_storage_bytes(self.suffix.storage_bytes())
    }

    pub(crate) fn is_match_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(bool, SearchAccounting), SearchError> {
        let (end, accounting) = self.shortest_window(haystack, window, limits)?;
        Ok((end.is_some(), accounting))
    }

    pub(crate) fn is_match_window_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        #[cfg(test)]
        value_path_probe::record_exists();
        self.find_delimited_segment_window_value(haystack, window, limits)
            .map(|matched| matched.is_some())
    }

    pub(crate) fn shortest_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        self.find_delimited_segment_window(haystack, window, limits)
            .map(|(matched, accounting)| (matched.map(|(_, end)| end), accounting))
    }

    pub(crate) fn find_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        self.find_delimited_segment_window(haystack, window, limits)
    }

    pub(crate) fn find_window_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<Option<(usize, usize)>, SearchError> {
        #[cfg(test)]
        value_path_probe::record_span();
        self.find_delimited_segment_window_value(haystack, window, limits)
    }

    fn find_delimited_segment_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        let segment = &self.segment;
        let upper_bounds = self.preflight_delimited_segment(haystack.len(), window, limits)?;
        let mut accounting = upper_bounds.into_accounting();
        let Some(mut search_start) = window
            .start()
            .checked_add(self.descriptor.minimum_prefix_bytes)
        else {
            return Ok((None, accounting));
        };
        if search_start > window.end() {
            return Ok((None, accounting));
        }
        accounting.finder_calls = 1;
        let (found, _) = self
            .suffix
            .find_window(
                haystack,
                LiteralWindow::new(search_start, window.end()),
                LiteralSearchLimits::unlimited(),
            )
            .map_err(map_literal_search_error)?;
        let Some((suffix_start, suffix_end)) = found else {
            return Ok((None, accounting));
        };
        accounting.candidate_visits = 1;
        if let Some(start) = recover_delimited_segment_start(
            haystack,
            window.start(),
            suffix_start,
            segment,
            &mut accounting,
        )? {
            return Ok((Some((start, suffix_end)), accounting));
        }
        search_start = suffix_start
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "delimited segment barrier handoff",
            })?;
        self.find_delimited_segment_forward(haystack, window, search_start, accounting)
    }

    fn find_delimited_segment_window_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<Option<(usize, usize)>, SearchError> {
        self.preflight_delimited_segment(haystack.len(), window, limits)?;
        let segment = &self.segment;
        let Some(mut search_start) = window
            .start()
            .checked_add(self.descriptor.minimum_prefix_bytes)
        else {
            return Ok(None);
        };
        if search_start > window.end() {
            return Ok(None);
        }
        let found = self
            .suffix
            .find_window_value(
                haystack,
                LiteralWindow::new(search_start, window.end()),
                LiteralSearchLimits::unlimited(),
            )
            .map_err(map_literal_search_error)?;
        let Some((suffix_start, suffix_end)) = found else {
            return Ok(None);
        };
        if let Some(start) = recover_delimited_segment_start(
            haystack,
            window.start(),
            suffix_start,
            segment,
            &mut (),
        )? {
            return Ok(Some((start, suffix_end)));
        }
        search_start = suffix_start
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "delimited segment barrier handoff",
            })?;
        self.find_delimited_segment_forward(haystack, window, search_start, ())
    }

    #[inline(never)]
    fn find_delimited_segment_forward<R: DelimitedSearchRecorder>(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        mut position: usize,
        mut recorder: R,
    ) -> Result<R::Output, SearchError> {
        let segment = &self.segment;
        while let Some(run_start) = segment.member_seek.seek_unmetered(
            haystack,
            position,
            window.end(),
            self.class_classifier.as_ref(),
        ) {
            let run_end = segment
                .run_end_seek
                .seek_unmetered(
                    haystack,
                    run_start,
                    window.end(),
                    self.class_classifier.as_ref(),
                )
                .unwrap_or(window.end());
            let run_bytes =
                run_end
                    .checked_sub(run_start)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "delimited segment physical run",
                    })?;
            if run_bytes >= segment.class_minimum {
                recorder.record_forward_candidate()?;
                let candidate = run_end.saturating_sub(segment.class_maximum).max(run_start);
                if let Some(end) = verify_delimited_segment_forward(
                    haystack,
                    candidate,
                    window.end(),
                    self.suffix.needle(),
                    segment,
                    &mut recorder,
                )? {
                    return Ok(recorder.finish(Some((candidate, end))));
                }
            }
            if run_end >= window.end() {
                break;
            }
            position = run_end
                .checked_add(1)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "delimited segment forward resume",
                })?;
        }
        Ok(recorder.finish(None))
    }

    fn preflight_delimited_segment(
        &self,
        haystack_len: usize,
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<DelimitedSearchUpperBounds, SearchError> {
        let segment = &self.segment;
        if window.start() > window.end() || window.end() > haystack_len {
            return Err(SearchError::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len,
            });
        }
        let window_bytes = window.end().checked_sub(window.start()).ok_or(
            SearchError::ArithmeticOverflow {
                computation: "delimited segment window bytes",
            },
        )?;
        let candidate_visits_upper_bound = window_bytes;
        let finder_calls_upper_bound = 1;
        if candidate_visits_upper_bound > limits.max_candidate_visits {
            return Err(SearchError::CandidateLimit {
                needed: candidate_visits_upper_bound,
                limit: limits.max_candidate_visits,
            });
        }
        let finder_work = window_bytes
            .checked_add(self.suffix.needle().len())
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "delimited segment finder work",
            })?;
        let finder_work_upper_bound = u64::try_from(finder_work).map_err(|_| {
            SearchError::ArithmeticOverflow {
                computation: "delimited segment finder work as u64",
            }
        })?;
        let reverse_probe_work = segment
            .class_maximum
            .checked_add(2)
            .and_then(|work| work.checked_mul(segment.segment_maximum))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "delimited segment reverse work per candidate",
            })?;
        let forward_work_per_byte = self
            .descriptor
            .maximum_match_bytes
            .checked_add(2)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "delimited segment forward work per byte",
            })?;
        let root_scan_work = window_bytes
            .checked_mul(BYTE_SET_BLOCK_BYTES)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "delimited segment root scan work",
            })?;
        // Reuse the RequiredLiteral certificate's backward-work bucket for
        // every structural source probe: reverse recovery, forward token
        // verification, and the restarted fixed-block root scanner.
        let backward_work_upper_bound = window_bytes
            .checked_mul(forward_work_per_byte)
            .and_then(|work| work.checked_add(root_scan_work))
            .and_then(|work| work.checked_add(reverse_probe_work))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "delimited segment backward work",
            })?;
        let backward_work = u64::try_from(backward_work_upper_bound).map_err(|_| {
            SearchError::ArithmeticOverflow {
                computation: "delimited segment backward work as u64",
            }
        })?;
        let call_work = u64::try_from(finder_calls_upper_bound)
            .ok()
            .and_then(|calls| calls.checked_mul(SEARCH_CALL_WORK))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "delimited segment structural work",
            })?;
        let work_upper_bound = SEARCH_BASE_WORK
            .checked_add(finder_work_upper_bound)
            .and_then(|work| work.checked_add(backward_work))
            .and_then(|work| work.checked_add(call_work))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "delimited segment total work",
            })?;
        if work_upper_bound > limits.max_work_upper_bound {
            return Err(SearchError::WorkLimit {
                needed: work_upper_bound,
                limit: limits.max_work_upper_bound,
            });
        }
        Ok(DelimitedSearchUpperBounds {
            window_bytes,
            candidate_visits_upper_bound,
            finder_calls_upper_bound,
            finder_work_upper_bound,
            backward_work_upper_bound,
            work_upper_bound,
        })
    }

}

fn recover_delimited_segment_start<R: DelimitedSearchRecorder>(
    haystack: &[u8],
    window_start: usize,
    suffix_start: usize,
    segment: &DelimitedSegment,
    recorder: &mut R,
) -> Result<Option<usize>, SearchError> {
    let mut cursor = suffix_start;
    let mut recovered = None;
    for segment_count in 1..=segment.segment_maximum {
        if cursor <= window_start {
            break;
        }
        charge_delimited_backward(recorder)?;
        if haystack[cursor - 1] != segment.delimiter {
            break;
        }
        let run_end = cursor - 1;
        let mut run_start = run_end;
        let mut class_bytes = 0_usize;
        while run_start > window_start && class_bytes <= segment.class_maximum {
            charge_delimited_backward(recorder)?;
            let byte = haystack[run_start - 1];
            if !byte_is_member(segment.class_words, byte) {
                break;
            }
            run_start -= 1;
            class_bytes += 1;
        }
        if class_bytes < segment.class_minimum {
            break;
        }
        if class_bytes > segment.class_maximum {
            if segment_count >= segment.segment_minimum {
                recovered = Some(run_end - segment.class_maximum);
            }
            break;
        }
        if segment_count >= segment.segment_minimum {
            recovered = Some(run_start);
        }
        cursor = run_start;
    }
    Ok(recovered)
}

fn verify_delimited_segment_forward<R: DelimitedSearchRecorder>(
    haystack: &[u8],
    start: usize,
    window_end: usize,
    suffix: &[u8],
    segment: &DelimitedSegment,
    recorder: &mut R,
) -> Result<Option<usize>, SearchError> {
    let mut position = start;
    for segment_count in 1..=segment.segment_maximum {
        let mut class_bytes = 0_usize;
        while position < window_end && class_bytes <= segment.class_maximum {
            charge_delimited_backward(recorder)?;
            if !byte_is_member(segment.class_words, haystack[position]) {
                break;
            }
            position += 1;
            class_bytes += 1;
        }
        if class_bytes < segment.class_minimum || class_bytes > segment.class_maximum {
            return Ok(None);
        }
        if position >= window_end {
            return Ok(None);
        }
        charge_delimited_backward(recorder)?;
        if haystack[position] != segment.delimiter {
            return Ok(None);
        }
        position += 1;

        if segment_count >= segment.segment_minimum {
            let Some(suffix_end) = position.checked_add(suffix.len()) else {
                return Err(SearchError::ArithmeticOverflow {
                    computation: "delimited segment selected suffix end",
                });
            };
            if suffix_end <= window_end {
                let mut matched = true;
                for (&actual, &expected) in haystack[position..suffix_end].iter().zip(suffix) {
                    charge_delimited_backward(recorder)?;
                    if actual != expected {
                        matched = false;
                        break;
                    }
                }
                if matched {
                    return Ok(Some(suffix_end));
                }
            }
        }
        if segment_count == segment.segment_maximum
            || position >= window_end
            || !byte_is_member(segment.class_words, haystack[position])
        {
            return Ok(None);
        }
    }
    Ok(None)
}

#[inline(always)]
fn charge_delimited_backward<R: DelimitedSearchRecorder>(
    recorder: &mut R,
) -> Result<(), SearchError> {
    recorder.record_backward_byte()
}

fn map_literal_search_error(error: LiteralError) -> SearchError {
    match error {
        LiteralError::InvalidWindow {
            start,
            end,
            haystack_len,
        } => SearchError::InvalidWindow {
            start,
            end,
            haystack_len,
        },
        LiteralError::LinearTermLimit { needed, limit } => SearchError::WorkLimit {
            needed: u64::try_from(needed).unwrap_or(u64::MAX),
            limit: u64::try_from(limit).unwrap_or(u64::MAX),
        },
        LiteralError::ArithmeticOverflow { .. }
        | LiteralError::NeedleLimit { .. }
        | LiteralError::AllocationFailed { .. } => SearchError::ArithmeticOverflow {
            computation: "authenticated universal corridor literal search",
        },
        _ => SearchError::ArithmeticOverflow {
            computation: "unknown universal corridor literal search failure",
        },
    }
}

#[cfg(test)]
mod tests {
    use regex_syntax::ParserBuilder;

    use super::{
        BYTE_SET_BLOCK_BYTES, BoundedDelimitedSegmentPlan, DELIMITED_SEGMENT_PLAN_ID,
        Descriptor, InspectionError, InspectionOutcome, LiteralBuildLimits,
        NativeInspectionOutcome, Plan, SearchAccounting, SearchError, SearchLimits,
        SearchWindow, inspect, inspect_native,
    };

    fn parse_bytes(pattern: &str) -> regex_syntax::hir::Hir {
        ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(pattern)
            .unwrap()
    }

    fn parse_unicode(pattern: &str) -> regex_syntax::hir::Hir {
        ParserBuilder::new().build().parse(pattern).unwrap()
    }

    fn eligible(pattern: &str, suffix: &[u8]) -> (Descriptor, u64) {
        let outcome = inspect(&parse_bytes(pattern), suffix, 0, u64::MAX).unwrap();
        let InspectionOutcome::Eligible(inspection) = outcome else {
            panic!("universal finite greedy corridor was refused: {pattern:?}");
        };
        (inspection.descriptor(), inspection.planner_work())
    }

    #[test]
    fn admitted_spellings_publish_exact_language_geometry() {
        for (pattern, suffix, expected) in [
            (
                r"(?s-u:.{2,16}.{2,48}XYZ)",
                b"XYZ".as_slice(),
                (4, 64, 7, 67, 3),
            ),
            (
                r"(?s-u:(?:[\x00-\x7F]|[\x80-\xFF]){2,32}.{6,96}WXYZ)",
                b"WXYZ".as_slice(),
                (8, 128, 12, 132, 4),
            ),
            (
                r"(?s-u:(?:\w|\W){0,4}Q)",
                b"Q".as_slice(),
                (0, 4, 1, 5, 1),
            ),
            (
                r"(?s-u:(.{2,3})((?:XYZ)))",
                b"XYZ".as_slice(),
                (2, 3, 5, 6, 3),
            ),
            (
                r"(?s-u:[\x00-\xFF]{2}Z)",
                b"Z".as_slice(),
                (2, 2, 3, 3, 1),
            ),
        ] {
            let (descriptor, _) = eligible(pattern, suffix);
            assert_eq!(
                (
                    descriptor.minimum_prefix_bytes(),
                    descriptor.maximum_prefix_bytes(),
                    descriptor.minimum_match_bytes(),
                    descriptor.maximum_match_bytes(),
                    descriptor.suffix_bytes(),
                ),
                expected,
                "pattern={pattern:?}",
            );
        }
    }

    #[test]
    fn every_two_range_partition_of_the_byte_universe_is_admitted() {
        for left_end in 0_u8..u8::MAX {
            let right_start = left_end.checked_add(1).expect("partition has a right half");
            let pattern = format!(
                r"(?s-u:(?:[\x00-\x{left_end:02X}]|[\x{right_start:02X}-\xFF]){{1,2}}X)",
            );
            let (descriptor, _) = eligible(&pattern, b"X");
            assert_eq!(descriptor.minimum_prefix_bytes(), 1);
            assert_eq!(descriptor.maximum_prefix_bytes(), 2);
        }
    }

    #[test]
    fn every_single_byte_hole_is_rejected() {
        for hole in 0_u8..=u8::MAX {
            let atom = match hole {
                0 => r"[\x01-\xFF]".to_owned(),
                u8::MAX => r"[\x00-\xFE]".to_owned(),
                _ => {
                    let left_end = hole.checked_sub(1).expect("nonzero hole");
                    let right_start = hole.checked_add(1).expect("nonterminal hole");
                    format!(
                        r"(?:[\x00-\x{left_end:02X}]|[\x{right_start:02X}-\xFF])",
                    )
                }
            };
            let pattern = format!(r"(?s-u:{atom}{{1,2}}X)");
            assert!(
                matches!(
                    inspect(&parse_bytes(&pattern), b"X", 0, u64::MAX).unwrap(),
                    InspectionOutcome::Ineligible { .. },
                ),
                "single-byte hole was admitted: hole={hole} pattern={pattern:?}",
            );
        }
    }

    #[test]
    fn the_entire_nonempty_literal_tail_is_bound() {
        let hir = parse_bytes(r"(?s-u:.{1,4}(XYZ))");
        assert!(matches!(
            inspect(&hir, b"XYZ", 0, u64::MAX).unwrap(),
            InspectionOutcome::Eligible(_),
        ));
        for suffix in [
            b"".as_slice(),
            b"YZ".as_slice(),
            b"WXYZ".as_slice(),
            b"XYQ".as_slice(),
        ] {
            assert!(matches!(
                inspect(&hir, suffix, 0, u64::MAX).unwrap(),
                InspectionOutcome::Ineligible { .. },
            ));
        }
    }

    #[test]
    fn priority_assertion_and_correlation_violations_fail_closed() {
        for pattern in [
            r"(?s-u:.{1,2}?X)",
            r"(?s-u:.{1,2}.{1,2}?X)",
            r"(?s-u:.{2}?X)",
            r"(?s-u:^.{1,2}X)",
            r"(?s-u:.{1,2}X$)",
            r"(?s-u:.{1,2}\bX)",
            r"(?-u:.{1,2}X)",
            r"(?s-u:[\x00-\xFE]{1,2}X)",
            r"(?s-u:a.{1,2}X)",
            r"(?s-u:.*X)",
            r"(?s-u:(?:.{1}|.{2})X)",
            r"(?s-u:(?:[\x00-\x7F]{2}|[\x80-\xFF]{2})X)",
            r"(?s-u:(?:[\x00-\x7F][\x80-\xFF]|[\x80-\xFF][\x00-\x7F])X)",
            r"(?s-u:(.{1,2}.{1,2})X)",
            r"(?s-u:.{1,2}[XY])",
            r"(?s-u:X)",
        ] {
            assert!(
                matches!(
                    inspect(&parse_bytes(pattern), b"X", 0, u64::MAX).unwrap(),
                    InspectionOutcome::Ineligible { .. },
                ),
                "invalid corridor was admitted: {pattern:?}",
            );
        }

        for pattern in [r"(?s:.{1,2}X)", r"(?s:\p{Greek}{1,2}X)"] {
            assert!(
                matches!(
                    inspect(&parse_unicode(pattern), b"X", 0, u64::MAX).unwrap(),
                    InspectionOutcome::Ineligible { .. },
                ),
                "Unicode scalar corridor was admitted: {pattern:?}",
            );
        }
    }

    #[test]
    fn planner_work_closes_at_exact_and_one_below_limits() {
        let hir = parse_bytes(
            r"(?s-u:(?:[\x00-\x7F]|[\x80-\xFF]){2,32}.{6,96}WXYZ)",
        );
        let initial_work = 19;
        let InspectionOutcome::Eligible(unlimited) =
            inspect(&hir, b"WXYZ", initial_work, u64::MAX).unwrap()
        else {
            panic!("resource fixture was refused");
        };
        let exact_work = unlimited.planner_work();
        assert!(exact_work > initial_work);
        let exact = inspect(&hir, b"WXYZ", initial_work, exact_work).unwrap();
        assert_eq!(exact.planner_work(), exact_work);
        assert_eq!(
            match exact {
                InspectionOutcome::Eligible(inspection) => inspection.descriptor(),
                InspectionOutcome::Ineligible { .. } => panic!("exact limit declined"),
            },
            unlimited.descriptor(),
        );

        let one_below = exact_work.checked_sub(1).expect("positive planner work");
        assert_eq!(
            inspect(&hir, b"WXYZ", initial_work, one_below),
            Err(InspectionError::WorkLimit {
                actual: one_below,
                needed: exact_work,
                limit: one_below,
            }),
        );
        assert_eq!(
            inspect(&hir, b"WXYZ", 2, 1),
            Err(InspectionError::WorkLimit {
                actual: 1,
                needed: 2,
                limit: 1,
            }),
        );
        assert_eq!(
            inspect(&hir, b"WXYZ", 0, 0),
            Err(InspectionError::WorkLimit {
                actual: 0,
                needed: 1,
                limit: 0,
            }),
        );
    }

    fn native_plan(pattern: &str) -> Plan {
        let hir = parse_bytes(pattern);
        let NativeInspectionOutcome::Eligible(inspection) =
            inspect_native(&hir, 0, u64::MAX).unwrap()
        else {
            panic!("native source inspection refused {pattern:?}");
        };
        Plan::build(inspection, LiteralBuildLimits::default()).unwrap()
    }

    fn delimited_plan(pattern: &str) -> BoundedDelimitedSegmentPlan {
        let hir = parse_bytes(pattern);
        let NativeInspectionOutcome::Delimited(inspection) =
            inspect_native(&hir, 0, u64::MAX).unwrap()
        else {
            panic!("bounded-delimited source inspection refused {pattern:?}");
        };
        BoundedDelimitedSegmentPlan::build(inspection, LiteralBuildLimits::default()).unwrap()
    }

    #[test]
    fn native_source_route_is_stricter_and_closes_its_work_receipt() {
        let hir = parse_bytes(r"(?s-u:.{2,16}.{2,48}X)");
        let NativeInspectionOutcome::Eligible(unlimited) =
            inspect_native(&hir, 7, u64::MAX).unwrap()
        else {
            panic!("direct universal corridor was refused");
        };
        assert_eq!(unlimited.suffix(), b"X");
        assert_eq!(unlimited.descriptor().minimum_prefix_bytes(), 4);
        assert_eq!(unlimited.descriptor().maximum_prefix_bytes(), 64);
        let exact_work = unlimited.planner_work();
        assert_eq!(
            inspect_native(&hir, 7, exact_work).unwrap().planner_work(),
            exact_work,
        );
        assert_eq!(
            inspect_native(&hir, 7, exact_work - 1),
            Err(InspectionError::WorkLimit {
                actual: exact_work - 1,
                needed: exact_work,
                limit: exact_work - 1,
            }),
        );

        let multi_byte = parse_bytes(r"(?s-u:.{2,16}.{2,48}XYZ)");
        let declined = inspect_native(&multi_byte, 7, u64::MAX).unwrap();
        assert!(matches!(
            declined,
            NativeInspectionOutcome::Ineligible { .. },
        ));
        let declined_work = declined.planner_work();
        assert_eq!(
            inspect_native(&multi_byte, 7, declined_work)
                .unwrap()
                .planner_work(),
            declined_work,
        );
        assert!(matches!(
            inspect(&multi_byte, b"XYZ", 7, u64::MAX).unwrap(),
            InspectionOutcome::Eligible(_),
        ));

        for pattern in [
            r"(?s-u:(?:.{1}|.{2})X)",
            r"(?s-u:.{1,4}?X)",
            r"(?s-u:.*X)",
            r"(?s-u:.{1,4}\bX)",
            r"(?s-u:.{1,4})",
        ] {
            let hir = parse_bytes(pattern);
            let declined = inspect_native(&hir, 0, u64::MAX).unwrap();
            assert!(
                matches!(declined, NativeInspectionOutcome::Ineligible { .. }),
                "strict native inspection admitted {pattern:?}",
            );
            let exact_work = declined.planner_work();
            assert_eq!(
                inspect_native(&hir, 0, exact_work).unwrap().planner_work(),
                exact_work,
                "semantic decline work did not replay: {pattern:?}",
            );
        }
        assert!(matches!(
            inspect_native(&parse_unicode(r"(?s:.{1,4}X)"), 0, u64::MAX).unwrap(),
            NativeInspectionOutcome::Ineligible { .. },
        ));
    }

    #[test]
    fn bounded_delimited_segment_inspection_is_structural_and_exactly_metered() {
        let pattern = r"(?-u:(?:[a-z]{1,16}/){1,4}DONE)";
        let hir = parse_bytes(pattern);
        let NativeInspectionOutcome::Delimited(unlimited) =
            inspect_native(&hir, 11, u64::MAX).unwrap()
        else {
            panic!("bounded delimited segment was refused");
        };
        assert_eq!(unlimited.suffix(), b"DONE");
        assert_eq!(unlimited.descriptor().minimum_prefix_bytes(), 2);
        assert_eq!(unlimited.descriptor().maximum_prefix_bytes(), 68);
        assert_eq!(unlimited.descriptor().minimum_match_bytes(), 6);
        assert_eq!(unlimited.descriptor().maximum_match_bytes(), 72);
        let exact_work = unlimited.planner_work();
        assert_eq!(
            inspect_native(&hir, 11, exact_work)
                .unwrap()
                .planner_work(),
            exact_work,
        );
        assert_eq!(
            inspect_native(&hir, 11, exact_work - 1),
            Err(InspectionError::WorkLimit {
                actual: exact_work - 1,
                needed: exact_work,
                limit: exact_work - 1,
            }),
        );
        let plan = delimited_plan(pattern);
        assert_eq!(plan.plan_id(), DELIMITED_SEGMENT_PLAN_ID);

        for declined in [
            r"(?-u:(?:[a/]{1,2}/){1,2}X)",
            r"(?-u:(?:[ab]{1,2}/){1,2}a)",
            r"(?-u:(?:[ab]{1,2}/){1,2}/X)",
            r"(?-u:(?:[ab]{1,2}/){0,2}X)",
            r"(?-u:(?:[ab]{1,2}/){1,}X)",
            r"(?-u:(?:[ab]{1,2}?/){1,2}X)",
            r"(?-u:(?:[ab]{1,2}/){1,2}?X)",
        ] {
            assert!(
                matches!(
                    inspect_native(&parse_bytes(declined), 0, u64::MAX).unwrap(),
                    NativeInspectionOutcome::Ineligible { .. },
                ),
                "invalid bounded segment was admitted: {declined:?}",
            );
        }
    }

    #[test]
    fn bounded_delimited_segment_handles_overlong_runs_and_tail_barriers() {
        let plan = delimited_plan(r"(?-u:(?:a{1,2}/){1,2}X)");
        for (haystack, expected) in [
            (b"aaa/X".as_slice(), Some((1, 5))),
            (b"a/aaa/X".as_slice(), Some((3, 7))),
            (b"X!aa/X".as_slice(), Some((2, 6))),
            (b"a/a/X".as_slice(), Some((0, 5))),
            (b"a/aaa/a/X".as_slice(), Some((3, 9))),
        ] {
            assert_eq!(
                plan.find_window(
                    haystack,
                    SearchWindow::full(haystack),
                    SearchLimits::unlimited(),
                )
                .unwrap()
                .0,
                expected,
                "haystack={haystack:?}",
            );
        }

        let overlapping = delimited_plan(r"(?-u:(?:a{1,2}/){1,2}xa/xa)");
        assert_eq!(
            overlapping
                .find_window(
                    b"!!xa/xa/xa",
                    SearchWindow::full(b"!!xa/xa/xa"),
                    SearchLimits::unlimited(),
                )
                .unwrap()
                .0,
            Some((3, 10)),
        );

        let deep = delimited_plan(r"(?-u:(?:a{1,2}/){2,3}X)");
        for (haystack, expected) in [
            (b"aaa/a/X".as_slice(), Some((1, 7))),
            (b"a/aaa/X".as_slice(), None),
            (b"aa/aa/aa/X".as_slice(), Some((0, 10))),
        ] {
            assert_eq!(
                deep.find_window(
                    haystack,
                    SearchWindow::full(haystack),
                    SearchLimits::unlimited(),
                )
                .unwrap()
                .0,
                expected,
                "deep haystack={haystack:?}",
            );
        }
    }

    #[test]
    fn bounded_delimited_segment_matches_upstream_for_every_small_window() {
        let pattern = r"(?-u:(?:[ab]{1,2}/){1,2}X)";
        let plan = delimited_plan(pattern);
        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        let alphabet = [b'a', b'b', b'/', b'X', b'!'];
        for length in 0_u32..=6 {
            let haystack_count = alphabet.len().pow(length);
            for mut code in 0..haystack_count {
                let mut haystack = vec![0_u8; length as usize];
                for byte in &mut haystack {
                    *byte = alphabet[code % alphabet.len()];
                    code /= alphabet.len();
                }
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        let window = SearchWindow::new(start, end);
                        let slice = &haystack[start..end];
                        let expected = upstream.find(slice).map(|matched| {
                            (start + matched.start(), start + matched.end())
                        });
                        let expected_shortest =
                            upstream.shortest_match(slice).map(|offset| start + offset);
                        let (actual, accounting) = plan
                            .find_window(&haystack, window, SearchLimits::unlimited())
                            .unwrap();
                        assert_eq!(
                            actual,
                            expected,
                            "span haystack={haystack:?} window={start}..{end}",
                        );
                        assert_eq!(
                            plan.find_window_value(
                                &haystack,
                                window,
                                SearchLimits::unlimited(),
                            )
                            .unwrap(),
                            expected,
                            "value span haystack={haystack:?} window={start}..{end}",
                        );
                        assert_eq!(
                            plan.is_match_window_value(
                                &haystack,
                                window,
                                SearchLimits::unlimited(),
                            )
                            .unwrap(),
                            expected.is_some(),
                            "value exists haystack={haystack:?} window={start}..{end}",
                        );
                        assert!(
                            accounting.candidate_visits
                                <= accounting.candidate_visits_upper_bound,
                        );
                        assert!(accounting.finder_calls <= accounting.finder_calls_upper_bound);
                        assert!(
                            accounting.backward_bytes_examined
                                <= accounting.backward_work_upper_bound,
                        );
                        let (actual_shortest, shortest_accounting) = plan
                            .shortest_window(&haystack, window, SearchLimits::unlimited())
                            .unwrap();
                        assert_eq!(
                            actual_shortest,
                            expected_shortest,
                            "shortest haystack={haystack:?} window={start}..{end}",
                        );
                        assert!(
                            shortest_accounting.candidate_visits
                                <= shortest_accounting.candidate_visits_upper_bound,
                        );
                        assert!(
                            shortest_accounting.finder_calls
                                <= shortest_accounting.finder_calls_upper_bound,
                        );
                        assert!(
                            shortest_accounting.backward_bytes_examined
                                <= shortest_accounting.backward_work_upper_bound,
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn bounded_delimited_segment_reported_receipts_remain_exact() {
        let plan = delimited_plan(r"(?-u:(?:[ab]{1,2}/){1,2}X)");
        for (haystack, matched, expected) in [
            (
                b"X".as_slice(),
                None,
                SearchAccounting {
                    window_bytes: 1,
                    candidate_visits_upper_bound: 1,
                    finder_calls_upper_bound: 1,
                    finder_work_upper_bound: 2,
                    backward_work_upper_bound: 33,
                    work_upper_bound: 51,
                    scratch_bytes: 0,
                    candidate_visits: 0,
                    finder_calls: 0,
                    backward_bytes_examined: 0,
                },
            ),
            (
                b"!!!!".as_slice(),
                None,
                SearchAccounting {
                    window_bytes: 4,
                    candidate_visits_upper_bound: 4,
                    finder_calls_upper_bound: 1,
                    finder_work_upper_bound: 5,
                    backward_work_upper_bound: 108,
                    work_upper_bound: 129,
                    scratch_bytes: 0,
                    candidate_visits: 0,
                    finder_calls: 1,
                    backward_bytes_examined: 0,
                },
            ),
            (
                b"aa/X".as_slice(),
                Some((0, 4)),
                SearchAccounting {
                    window_bytes: 4,
                    candidate_visits_upper_bound: 4,
                    finder_calls_upper_bound: 1,
                    finder_work_upper_bound: 5,
                    backward_work_upper_bound: 108,
                    work_upper_bound: 129,
                    scratch_bytes: 0,
                    candidate_visits: 1,
                    finder_calls: 1,
                    backward_bytes_examined: 3,
                },
            ),
            (
                b"!!X!aa/X".as_slice(),
                Some((4, 8)),
                SearchAccounting {
                    window_bytes: 8,
                    candidate_visits_upper_bound: 8,
                    finder_calls_upper_bound: 1,
                    finder_work_upper_bound: 9,
                    backward_work_upper_bound: 208,
                    work_upper_bound: 233,
                    scratch_bytes: 0,
                    candidate_visits: 2,
                    finder_calls: 1,
                    backward_bytes_examined: 6,
                },
            ),
            (
                b"aaa/X".as_slice(),
                Some((1, 5)),
                SearchAccounting {
                    window_bytes: 5,
                    candidate_visits_upper_bound: 5,
                    finder_calls_upper_bound: 1,
                    finder_work_upper_bound: 6,
                    backward_work_upper_bound: 133,
                    work_upper_bound: 155,
                    scratch_bytes: 0,
                    candidate_visits: 1,
                    finder_calls: 1,
                    backward_bytes_examined: 4,
                },
            ),
            (
                b"!!X!aaa/!".as_slice(),
                None,
                SearchAccounting {
                    window_bytes: 9,
                    candidate_visits_upper_bound: 9,
                    finder_calls_upper_bound: 1,
                    finder_work_upper_bound: 10,
                    backward_work_upper_bound: 233,
                    work_upper_bound: 259,
                    scratch_bytes: 0,
                    candidate_visits: 2,
                    finder_calls: 1,
                    backward_bytes_examined: 6,
                },
            ),
        ] {
            let (actual, accounting) = plan
                .find_window(
                    haystack,
                    SearchWindow::full(haystack),
                    SearchLimits::unlimited(),
                )
                .unwrap();
            assert_eq!(actual, matched, "haystack={haystack:?}");
            assert_eq!(accounting, expected, "haystack={haystack:?}");
        }

        let classified = delimited_plan(r"(?-u:(?:[aceg]{1,2}/){1,2}X)");
        let classified_haystack = b"!!X!a!c!e!g!a!c!e!g!";
        assert_eq!(
            classified
                .find_window(
                    classified_haystack,
                    SearchWindow::full(classified_haystack),
                    SearchLimits::unlimited(),
                )
                .unwrap(),
            (
                None,
                SearchAccounting {
                    window_bytes: 20,
                    candidate_visits_upper_bound: 20,
                    finder_calls_upper_bound: 1,
                    finder_work_upper_bound: 21,
                    backward_work_upper_bound: 508,
                    work_upper_bound: 545,
                    scratch_bytes: 0,
                    candidate_visits: 9,
                    finder_calls: 1,
                    backward_bytes_examined: 25,
                },
            ),
        );
    }

    #[test]
    fn bounded_delimited_segment_search_limits_close_before_source_reads() {
        let plan = delimited_plan(r"(?-u:(?:[ab]{1,2}/){1,2}X)");
        let haystack = b"!!X!aa/X";
        let window = SearchWindow::full(haystack);
        let (matched, accounting) = plan
            .find_window(haystack, window, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(matched, Some((4, 8)));
        assert_eq!(accounting.finder_calls, 1);
        assert!(accounting.candidate_visits >= 2);
        assert!(accounting.candidate_visits <= accounting.candidate_visits_upper_bound);
        assert!(accounting.finder_calls <= accounting.finder_calls_upper_bound);
        assert!(accounting.backward_bytes_examined <= accounting.backward_work_upper_bound);
        let exact = SearchLimits {
            max_work_upper_bound: accounting.work_upper_bound,
            max_candidate_visits: accounting.candidate_visits_upper_bound,
            max_scratch_bytes: 0,
        };
        assert_eq!(plan.find_window(haystack, window, exact).unwrap().0, matched);
        assert_eq!(
            plan.find_window_value(haystack, window, exact).unwrap(),
            matched,
        );
        assert_eq!(
            plan.is_match_window_value(haystack, window, exact).unwrap(),
            matched.is_some(),
        );
        assert_eq!(
            plan.find_window(
                haystack,
                window,
                SearchLimits {
                    max_work_upper_bound: accounting.work_upper_bound - 1,
                    ..exact
                },
            ),
            Err(SearchError::WorkLimit {
                needed: accounting.work_upper_bound,
                limit: accounting.work_upper_bound - 1,
            }),
        );
        assert_eq!(
            plan.find_window_value(
                haystack,
                window,
                SearchLimits {
                    max_work_upper_bound: accounting.work_upper_bound - 1,
                    ..exact
                },
            ),
            Err(SearchError::WorkLimit {
                needed: accounting.work_upper_bound,
                limit: accounting.work_upper_bound - 1,
            }),
        );
        assert_eq!(
            plan.is_match_window_value(
                haystack,
                window,
                SearchLimits {
                    max_work_upper_bound: accounting.work_upper_bound - 1,
                    ..exact
                },
            ),
            Err(SearchError::WorkLimit {
                needed: accounting.work_upper_bound,
                limit: accounting.work_upper_bound - 1,
            }),
        );
        assert_eq!(
            plan.find_window(
                haystack,
                window,
                SearchLimits {
                    max_candidate_visits: accounting.candidate_visits_upper_bound - 1,
                    ..exact
                },
            ),
            Err(SearchError::CandidateLimit {
                needed: accounting.candidate_visits_upper_bound,
                limit: accounting.candidate_visits_upper_bound - 1,
            }),
        );
        assert_eq!(
            plan.find_window_value(
                haystack,
                window,
                SearchLimits {
                    max_candidate_visits: accounting.candidate_visits_upper_bound - 1,
                    ..exact
                },
            ),
            Err(SearchError::CandidateLimit {
                needed: accounting.candidate_visits_upper_bound,
                limit: accounting.candidate_visits_upper_bound - 1,
            }),
        );
        assert_eq!(
            plan.is_match_window_value(
                haystack,
                window,
                SearchLimits {
                    max_candidate_visits: accounting.candidate_visits_upper_bound - 1,
                    ..exact
                },
            ),
            Err(SearchError::CandidateLimit {
                needed: accounting.candidate_visits_upper_bound,
                limit: accounting.candidate_visits_upper_bound - 1,
            }),
        );

        let invalid = SearchWindow::new(window.end(), window.start());
        let refusing = SearchLimits {
            max_work_upper_bound: 0,
            max_candidate_visits: 0,
            max_scratch_bytes: 0,
        };
        assert!(matches!(
            plan.find_window(haystack, invalid, refusing),
            Err(SearchError::InvalidWindow { .. }),
        ));
        assert!(matches!(
            plan.is_match_window(haystack, invalid, refusing),
            Err(SearchError::InvalidWindow { .. }),
        ));
        assert!(matches!(
            plan.find_window_value(haystack, invalid, refusing),
            Err(SearchError::InvalidWindow { .. }),
        ));
        assert!(matches!(
            plan.is_match_window_value(haystack, invalid, refusing),
            Err(SearchError::InvalidWindow { .. }),
        ));

        let classified = delimited_plan(r"(?-u:(?:[aceg]{1,2}/){1,2}X)");
        let classified_haystack = b"!!X!a!c!e!g!a!c!e!g!";
        let (_, classified_accounting) = classified
            .find_window(
                classified_haystack,
                SearchWindow::full(classified_haystack),
                SearchLimits::unlimited(),
            )
            .unwrap();
        assert!(
            classified_accounting.backward_work_upper_bound
                >= classified_haystack.len() * BYTE_SET_BLOCK_BYTES,
        );
    }

    #[test]
    fn native_span_exists_and_earliest_end_match_upstream_for_every_small_window() {
        let alphabet = [b'a', b'b', b'X'];
        for pattern in [
            r"(?s-u:.{0,3}X)",
            r"(?s-u:.{1,2}.{0,2}X)",
            r"(?s-u:[\x00-\xFF]{2,4}X)",
        ] {
            let plan = native_plan(pattern);
            let upstream = regex::bytes::RegexBuilder::new(pattern)
                .unicode(false)
                .build()
                .unwrap();
            for length in 0_u32..=6 {
                let haystack_count = alphabet.len().pow(length);
                for mut code in 0..haystack_count {
                    let mut haystack = vec![0_u8; length as usize];
                    for byte in &mut haystack {
                        *byte = alphabet[code % alphabet.len()];
                        code /= alphabet.len();
                    }
                    for start in 0..=haystack.len() {
                        for end in start..=haystack.len() {
                            let window = SearchWindow::new(start, end);
                            let slice = &haystack[start..end];
                            let expected = upstream.find(slice).map(|matched| {
                                (start + matched.start(), start + matched.end())
                            });
                            let expected_shortest =
                                upstream.shortest_match(slice).map(|offset| start + offset);
                            assert_eq!(
                                plan.find_window(
                                    &haystack,
                                    window,
                                    SearchLimits::unlimited(),
                                )
                                .unwrap()
                                .0,
                                expected,
                                "span pattern={pattern:?} haystack={haystack:?} window={start}..{end}",
                            );
                            assert_eq!(
                                plan.find_window_value(
                                    &haystack,
                                    window,
                                    SearchLimits::unlimited(),
                                )
                                .unwrap(),
                                expected,
                                "value span pattern={pattern:?} haystack={haystack:?} window={start}..{end}",
                            );
                            assert_eq!(
                                plan.shortest_window(
                                    &haystack,
                                    window,
                                    SearchLimits::unlimited(),
                                )
                                .unwrap()
                                .0,
                                expected_shortest,
                                "earliest-end pattern={pattern:?} haystack={haystack:?} window={start}..{end}",
                            );
                            assert_eq!(
                                plan.is_match_window(
                                    &haystack,
                                    window,
                                    SearchLimits::unlimited(),
                                )
                                .unwrap()
                                .0,
                                expected.is_some(),
                                "exists pattern={pattern:?} haystack={haystack:?} window={start}..{end}",
                            );
                            assert_eq!(
                                plan.is_match_window_value(
                                    &haystack,
                                    window,
                                    SearchLimits::unlimited(),
                                )
                                .unwrap(),
                                expected.is_some(),
                                "value exists pattern={pattern:?} haystack={haystack:?} window={start}..{end}",
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn native_search_limits_close_before_source_reads() {
        let plan = native_plan(r"(?s-u:.{0,3}X)");
        let haystack = b"aaaaX";
        let window = SearchWindow::full(haystack);
        let (matched, accounting) = plan
            .find_window(haystack, window, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(matched, Some((1, 5)));
        assert_eq!(accounting.finder_calls, 2);
        assert_eq!(accounting.candidate_visits, 2);

        let (exists, exists_accounting) = plan
            .is_match_window(haystack, window, SearchLimits::unlimited())
            .unwrap();
        assert!(exists);
        assert_eq!(exists_accounting.finder_calls_upper_bound, 1);
        let exact_exists = SearchLimits {
            max_work_upper_bound: exists_accounting.work_upper_bound,
            max_candidate_visits: exists_accounting.candidate_visits_upper_bound,
            max_scratch_bytes: 0,
        };
        assert!(
            plan.is_match_window_value(haystack, window, exact_exists)
                .unwrap(),
        );
        assert_eq!(
            plan.is_match_window_value(
                haystack,
                window,
                SearchLimits {
                    max_work_upper_bound: exists_accounting.work_upper_bound - 1,
                    ..exact_exists
                },
            ),
            Err(SearchError::WorkLimit {
                needed: exists_accounting.work_upper_bound,
                limit: exists_accounting.work_upper_bound - 1,
            }),
        );
        assert_eq!(
            plan.is_match_window_value(
                haystack,
                window,
                SearchLimits {
                    max_candidate_visits: 0,
                    ..SearchLimits::unlimited()
                },
            ),
            Err(SearchError::CandidateLimit {
                needed: 1,
                limit: 0,
            }),
        );

        let exact = SearchLimits {
            max_work_upper_bound: accounting.work_upper_bound,
            max_candidate_visits: accounting.candidate_visits_upper_bound,
            max_scratch_bytes: 0,
        };
        assert_eq!(plan.find_window(haystack, window, exact).unwrap().0, matched);
        assert_eq!(
            plan.find_window_value(haystack, window, exact).unwrap(),
            matched,
        );
        assert_eq!(
            plan.is_match_window_value(haystack, window, SearchLimits::unlimited())
                .unwrap(),
            matched.is_some(),
        );
        let one_below = SearchLimits {
            max_work_upper_bound: accounting.work_upper_bound - 1,
            ..exact
        };
        assert_eq!(
            plan.find_window(haystack, window, one_below),
            Err(SearchError::WorkLimit {
                needed: accounting.work_upper_bound,
                limit: accounting.work_upper_bound - 1,
            }),
        );
        assert_eq!(
            plan.find_window_value(haystack, window, one_below),
            Err(SearchError::WorkLimit {
                needed: accounting.work_upper_bound,
                limit: accounting.work_upper_bound - 1,
            }),
        );
        assert_eq!(
            plan.find_window(
                haystack,
                window,
                SearchLimits {
                    max_candidate_visits: 1,
                    ..SearchLimits::unlimited()
                },
            ),
            Err(SearchError::CandidateLimit {
                needed: 2,
                limit: 1,
            }),
        );
        assert_eq!(
            plan.find_window_value(
                haystack,
                window,
                SearchLimits {
                    max_candidate_visits: 1,
                    ..SearchLimits::unlimited()
                },
            ),
            Err(SearchError::CandidateLimit {
                needed: 2,
                limit: 1,
            }),
        );
        assert!(matches!(
            plan.find_window(
                haystack,
                SearchWindow::new(0, haystack.len() + 1),
                SearchLimits::unlimited(),
            ),
            Err(SearchError::InvalidWindow { .. }),
        ));
        assert!(matches!(
            plan.find_window_value(
                haystack,
                SearchWindow::new(0, haystack.len() + 1),
                SearchLimits::unlimited(),
            ),
            Err(SearchError::InvalidWindow { .. }),
        ));
        assert!(matches!(
            plan.is_match_window_value(
                haystack,
                SearchWindow::new(0, haystack.len() + 1),
                SearchLimits::unlimited(),
            ),
            Err(SearchError::InvalidWindow { .. }),
        ));
    }
}
