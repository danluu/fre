//! Source proof and native owner for a finite universal-byte corridor and tail.
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
//! route retains a one-byte exact tail directly from the same metered walk;
//! multi-byte tails remain eligible for K0's existing mandatory-cut and
//! suffix machinery.

use core::mem::size_of;

use fre_automata::SearchWindow;
use fre_kernels::{
    LiteralBuildLimits, LiteralError, LiteralPlan, LiteralSearchLimits,
    RequiredLiteralSearchAccounting as SearchAccounting,
    RequiredLiteralSearchError as SearchError, RequiredLiteralSearchLimits as SearchLimits,
    Window as LiteralWindow,
};
use regex_syntax::hir::{Class, Hir, HirKind};

const NODE_INSPECTION_WORK: u64 = 1;
const RANGE_INSPECTION_WORK: u64 = 1;
const MEMBER_INSERTION_WORK: u64 = 1;
const BITMAP_WORD_WORK: u64 = 1;
const WIDTH_ARITHMETIC_WORK: u64 = 1;
const SUFFIX_LENGTH_WORK: u64 = 1;
const SUFFIX_BYTE_WORK: u64 = 1;
const UNIVERSAL_WORDS: [u64; 4] = [u64::MAX; 4];
const SEARCH_BASE_WORK: u64 = 8;
const SEARCH_CALL_WORK: u64 = 8;
const NATIVE_SUFFIX_BYTES: usize = 1;

/// Stable identity for the early source-proved native owner.
pub(crate) const PLAN_ID: &str = "required-literal.universal-finite-greedy-corridor.v1";

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

/// Transactional source-only result for the early native route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeInspectionOutcome<'hir> {
    Eligible(NativeInspection<'hir>),
    Ineligible { planner_work: u64 },
}

impl NativeInspectionOutcome<'_> {
    pub(crate) const fn planner_work(self) -> u64 {
        match self {
            Self::Eligible(inspection) => inspection.planner_work,
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
/// also declines every retained HIR alternation, even a byte-universal union,
/// and every multi-byte suffix. Single-byte suffixes use `LiteralPlan`'s direct
/// byte finder; multi-byte suffixes retain the existing K0 mandatory-cut and
/// adaptive negative-proof routes. The late K0 theorem remains available for
/// every source shape declined here.
pub(crate) fn inspect_native(
    hir: &Hir,
    initial_work: u64,
    max_planner_work: u64,
) -> Result<NativeInspectionOutcome<'_>, InspectionError> {
    let mut meter = Meter::new(initial_work, max_planner_work)?;
    let inspected = inspect_inner(hir, None, false, &mut meter)?;
    Ok(match inspected {
        Some((descriptor, suffix)) if suffix.len() == NATIVE_SUFFIX_BYTES => {
            NativeInspectionOutcome::Eligible(NativeInspection {
                descriptor,
                suffix,
                planner_work: meter.work,
            })
        }
        Some(_) | None => NativeInspectionOutcome::Ineligible {
            planner_work: meter.work,
        },
    })
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

fn checked_add_width(
    left: usize,
    right: usize,
    meter: &mut Meter,
) -> Result<Option<usize>, InspectionError> {
    meter.charge(WIDTH_ARITHMETIC_WORK)?;
    Ok(left.checked_add(right))
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
        self.is_match_window(haystack, window, limits)
            .map(|(matched, _)| matched)
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
        self.find_window(haystack, window, limits)
            .map(|(matched, _)| matched)
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
        Descriptor, InspectionError, InspectionOutcome, LiteralBuildLimits,
        NativeInspectionOutcome, Plan, SearchError, SearchLimits, SearchWindow, inspect,
        inspect_native,
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

        let exact = SearchLimits {
            max_work_upper_bound: accounting.work_upper_bound,
            max_candidate_visits: accounting.candidate_visits_upper_bound,
            max_scratch_bytes: 0,
        };
        assert_eq!(plan.find_window(haystack, window, exact).unwrap().0, matched);
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
        assert!(matches!(
            plan.find_window(
                haystack,
                SearchWindow::new(0, haystack.len() + 1),
                SearchLimits::unlimited(),
            ),
            Err(SearchError::InvalidWindow { .. }),
        ));
    }
}
