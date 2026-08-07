//! Architecture-neutral proof and oracle for bounded mandatory-candidate retry.
//!
//! A graph-required suffix of width `m` aligns every complete match with a
//! suffix base `b`. If the complete language has maximum width `M`, that match
//! starts no earlier than `b - (M - m)` and ends at `b + m`. A failed DFA
//! search over precisely that interval therefore rejects only this candidate;
//! scanning can continue at `b + 1` without replaying the remainder of the
//! semantic window. Candidate absence proves global absence because the suffix
//! facts are derived from every accepting graph path.
//!
//! The same proof applies to a mandatory interior root. If every accepting
//! path reaches that root after at most `P` consumed bytes and reaches an
//! accept within at most `T` more bytes, a candidate at `b` needs only
//! `[max(start, b-P), min(end, b+T)]`. Unlike a terminal suffix, `b+T` is an
//! upper bound rather than an exact acceptance boundary and must be clamped to
//! the semantic window end.

use crate::program::OutputContract;
#[cfg(test)]
use crate::{
    dfa::NativeDfaView,
    program::{AnchoredByteSet, NativeProgramView},
};

/// Maximum estimated transition work per 256 scanned bytes admitted by the
/// retry lowering. This is a source- and input-independent overlap model:
/// dense candidates or wide verifier windows retain the ordinary DFA path.
const MAX_RETRY_TRANSITIONS_PER_256_BYTES: u64 = 128;

/// Expected aligned candidate bases per 256 scanned bytes.
///
/// A single filter column uses the native byte-frequency scale directly. If
/// every candidate is refined by more aligned columns before entering the
/// verifier, their stable frequency units are multiplied and each additional
/// column contributes another factor of 256 to the denominator. Keeping that
/// value rational is important: a selective pair can have fewer than one
/// expected candidate per 256 bytes, which an integer frequency cannot
/// represent without a large conservative rounding error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "retained for a future cost model with a conservative primary-frequency guard"
)]
pub(crate) struct EffectiveCandidateFrequency {
    units_numerator: u64,
    units_denominator: u64,
}

#[allow(
    dead_code,
    reason = "retained for a future cost model with a conservative primary-frequency guard"
)]
impl EffectiveCandidateFrequency {
    /// Construct the historical one-column estimate.
    #[must_use]
    pub(crate) fn from_primary_units(units: u16) -> Option<Self> {
        if !(1..=256).contains(&units) {
            return None;
        }
        Some(Self {
            units_numerator: u64::from(units),
            units_denominator: 1,
        })
    }

    /// Combine every aligned column that is checked before DFA verification.
    ///
    /// The current native refinement retains at most three columns, but this
    /// constructor is checked and simply declines if a future wider product
    /// cannot be represented exactly.
    #[must_use]
    pub(crate) fn from_aligned_column_units(units: &[u16]) -> Option<Self> {
        let (&first, rest) = units.split_first()?;
        let mut frequency = Self::from_primary_units(first)?;
        for &column_units in rest {
            if !(1..=256).contains(&column_units) {
                return None;
            }
            frequency.units_numerator = frequency
                .units_numerator
                .checked_mul(u64::from(column_units))?;
            frequency.units_denominator = frequency.units_denominator.checked_mul(256)?;
        }
        Some(frequency)
    }
}

/// Structural plan shared by the native emitters and this executable oracle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BoundedSuffixRetryPlan {
    /// Concrete graph-required bytes available to the candidate scanner.
    candidate_width: u8,
    /// Maximum consumed bytes from the candidate root through an accept.
    forward_width: u64,
    /// Maximum complete verifier width (`backtrack + forward_width`).
    total_width: u64,
    backtrack: u64,
    /// Interior bounds clamp `b + T`; terminal suffixes require it to fit.
    clamp_forward_end: bool,
    /// Ceiling of the rational expected transition work per 256 scanned
    /// bytes. Selection compares the unrounded rational value.
    estimated_transition_units: u64,
}

impl BoundedSuffixRetryPlan {
    #[must_use]
    pub(crate) const fn minimum_width(self) -> u8 {
        self.candidate_width
    }

    #[must_use]
    pub(crate) const fn forward_width(self) -> u64 {
        self.forward_width
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) const fn maximum_width(self) -> u64 {
        self.total_width
    }

    #[must_use]
    pub(crate) const fn backtrack(self) -> u64 {
        self.backtrack
    }

    #[must_use]
    pub(crate) const fn clamps_forward_end(self) -> bool {
        self.clamp_forward_end
    }

    #[must_use]
    pub(crate) const fn estimated_transition_units(self) -> u64 {
        self.estimated_transition_units
    }
}

/// Select retry only when the bounded verifier is structurally cheaper than
/// replaying a likely-overlapping candidate stream.
///
/// `candidate_frequency_units` uses the native filter's stable 0..=256 byte
/// frequency scale. The multiplication is the expected verifier transitions
/// per 256 scanned bytes. Overflow and every unsupported semantic shape
/// conservatively decline.
#[must_use]
pub(crate) fn select_bounded_suffix_retry(
    output: OutputContract,
    initial_pending: bool,
    minimum_width: u8,
    maximum_width: Option<usize>,
    candidate_frequency_units: u16,
) -> Option<BoundedSuffixRetryPlan> {
    select_bounded_suffix_retry_with_effective_frequency(
        output,
        initial_pending,
        minimum_width,
        maximum_width,
        EffectiveCandidateFrequency::from_primary_units(candidate_frequency_units)?,
    )
}

/// Select terminal-suffix retry using the effective frequency of every
/// aligned column checked before verification.
#[must_use]
#[allow(
    dead_code,
    reason = "joint-selectivity-only admission is too optimistic for production"
)]
pub(crate) fn select_bounded_suffix_retry_with_effective_frequency(
    output: OutputContract,
    initial_pending: bool,
    minimum_width: u8,
    maximum_width: Option<usize>,
    candidate_frequency: EffectiveCandidateFrequency,
) -> Option<BoundedSuffixRetryPlan> {
    let maximum_width = u64::try_from(maximum_width?).ok()?;
    let forward_width = u64::from(minimum_width);
    let backtrack = maximum_width.checked_sub(forward_width)?;
    select_bounded_retry(
        output,
        initial_pending,
        minimum_width,
        backtrack,
        forward_width,
        false,
        candidate_frequency,
    )
}

/// Select bounded retry for a graph-mandatory interior root with finite
/// consumed-distance proofs.
///
/// `candidate_width` is the concrete literal depth checked by the candidate
/// scanner. `max_before_root` and `max_through_accept` are independent graph
/// bounds; the latter includes the root's consumed byte(s), so it must cover
/// the complete candidate literal.
#[must_use]
pub(crate) fn select_bounded_interior_retry(
    output: OutputContract,
    initial_pending: bool,
    candidate_width: u8,
    max_before_root: u32,
    max_through_accept: u32,
    candidate_frequency_units: u16,
) -> Option<BoundedSuffixRetryPlan> {
    select_bounded_interior_retry_with_effective_frequency(
        output,
        initial_pending,
        candidate_width,
        max_before_root,
        max_through_accept,
        EffectiveCandidateFrequency::from_primary_units(candidate_frequency_units)?,
    )
}

/// Select interior retry using the effective frequency of every aligned
/// column checked before verification.
#[must_use]
#[allow(
    dead_code,
    reason = "joint-selectivity-only admission is too optimistic for production"
)]
pub(crate) fn select_bounded_interior_retry_with_effective_frequency(
    output: OutputContract,
    initial_pending: bool,
    candidate_width: u8,
    max_before_root: u32,
    max_through_accept: u32,
    candidate_frequency: EffectiveCandidateFrequency,
) -> Option<BoundedSuffixRetryPlan> {
    select_bounded_retry(
        output,
        initial_pending,
        candidate_width,
        u64::from(max_before_root),
        u64::from(max_through_accept),
        true,
        candidate_frequency,
    )
}

fn select_bounded_retry(
    output: OutputContract,
    initial_pending: bool,
    candidate_width: u8,
    backtrack: u64,
    forward_width: u64,
    clamp_forward_end: bool,
    candidate_frequency: EffectiveCandidateFrequency,
) -> Option<BoundedSuffixRetryPlan> {
    if output != OutputContract::Exists
        || initial_pending
        || candidate_width == 0
        || forward_width < u64::from(candidate_width)
    {
        return None;
    }
    let total_width = backtrack.checked_add(forward_width)?;
    let estimated_transition_numerator =
        u128::from(total_width).checked_mul(u128::from(candidate_frequency.units_numerator))?;
    let retry_budget_numerator = u128::from(MAX_RETRY_TRANSITIONS_PER_256_BYTES)
        .checked_mul(u128::from(candidate_frequency.units_denominator))?;
    if estimated_transition_numerator > retry_budget_numerator {
        return None;
    }
    let estimated_transition_units = u64::try_from(
        estimated_transition_numerator.div_ceil(u128::from(candidate_frequency.units_denominator)),
    )
    .ok()?;
    Some(BoundedSuffixRetryPlan {
        candidate_width,
        forward_width,
        total_width,
        backtrack,
        clamp_forward_end,
        estimated_transition_units,
    })
}

/// One aligned necessary suffix column used by the executable model.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ModelColumn {
    offset: u8,
    membership: AnchoredByteSet,
}

/// Observable execution facts retained by exhaustive tests.
#[cfg(test)]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct BoundedSuffixRetryTrace {
    pub(crate) matched: bool,
    pub(crate) candidate_bases: Vec<usize>,
    pub(crate) verifier_windows: Vec<(usize, usize)>,
    pub(crate) verifier_transitions: usize,
}

#[cfg(test)]
fn contains(set: AnchoredByteSet, byte: u8) -> bool {
    let index = usize::from(byte);
    set.words()[index / 64] & (1_u64 << (index % 64)) != 0
}

#[cfg(test)]
fn suffix_model_columns(view: NativeProgramView<'_>) -> Option<Vec<ModelColumn>> {
    let suffix = view.anchored_suffix.sets();
    let width = u8::try_from(suffix.len()).ok()?;
    let mut columns = Vec::new();
    columns.try_reserve_exact(suffix.len()).ok()?;
    // Suffix facts are stored final-byte first. Native scanners use offsets
    // from the beginning of the required suffix.
    for (reverse_offset, &membership) in suffix.iter().enumerate() {
        let reverse_offset = u8::try_from(reverse_offset).ok()?;
        let offset = width.checked_sub(reverse_offset)?.checked_sub(1)?;
        columns.push(ModelColumn { offset, membership });
    }
    (!columns.is_empty()).then_some(columns)
}

#[cfg(test)]
fn forward_model_columns(sets: &[AnchoredByteSet]) -> Option<Vec<ModelColumn>> {
    let mut columns = Vec::new();
    columns.try_reserve_exact(sets.len()).ok()?;
    for (offset, &membership) in sets.iter().enumerate() {
        columns.push(ModelColumn {
            offset: u8::try_from(offset).ok()?,
            membership,
        });
    }
    (!columns.is_empty()).then_some(columns)
}

#[cfg(test)]
fn valid_native_view(dfa: NativeDfaView<'_>) -> Option<usize> {
    if dfa.class_count == 0
        || dfa.class_count > 256
        || dfa.class_representatives.len() != dfa.class_count
        || dfa.forward_cells.is_empty()
        || !dfa.forward_cells.len().is_multiple_of(dfa.class_count)
    {
        return None;
    }
    let states = dfa.forward_cells.len().checked_div(dfa.class_count)?;
    let initial = usize::try_from(dfa.initial_state).ok()?;
    (initial < states).then_some(states)
}

#[cfg(test)]
fn verify_exists(
    dfa: NativeDfaView<'_>,
    haystack: &[u8],
    start: usize,
    end: usize,
    trace: &mut BoundedSuffixRetryTrace,
) -> Option<bool> {
    let states = valid_native_view(dfa)?;
    if dfa.initial_pending {
        return Some(true);
    }
    let mut state = dfa.initial_state;
    for &byte in haystack.get(start..end)? {
        let class = usize::from(*dfa.byte_classes.get(usize::from(byte))?);
        if class >= dfa.class_count {
            return None;
        }
        let state_index = usize::try_from(state).ok()?;
        if state_index >= states {
            return None;
        }
        let cell = *dfa.forward_cells.get(
            state_index
                .checked_mul(dfa.class_count)?
                .checked_add(class)?,
        )?;
        trace.verifier_transitions = trace.verifier_transitions.checked_add(1)?;
        if cell.accepted() {
            return Some(true);
        }
        if cell.next() == u32::MAX {
            return Some(false);
        }
        state = cell.next();
    }
    Some(false)
}

#[cfg(test)]
fn execute_bounded_retry_model(
    view: NativeProgramView<'_>,
    plan: BoundedSuffixRetryPlan,
    columns: &[ModelColumn],
    haystack: &[u8],
    original_start: usize,
    original_end: usize,
) -> Option<BoundedSuffixRetryTrace> {
    if view.output != OutputContract::Exists
        || view.dfa.initial_pending
        || original_start > original_end
        || original_end > haystack.len()
        || columns.is_empty()
        || columns
            .iter()
            .any(|column| column.offset >= plan.candidate_width)
    {
        return None;
    }
    let maximum_offset = columns
        .iter()
        .map(|column| usize::from(column.offset))
        .max()?;
    let backtrack = usize::try_from(plan.backtrack).ok()?;
    let forward_width = usize::try_from(plan.forward_width).ok()?;
    let mut base = original_start;
    let mut trace = BoundedSuffixRetryTrace::default();
    while base
        .checked_add(maximum_offset)
        .is_some_and(|last_column| last_column < original_end)
    {
        let candidate = columns.iter().all(|column| {
            base.checked_add(usize::from(column.offset))
                .and_then(|position| haystack.get(position))
                .is_some_and(|&byte| contains(column.membership, byte))
        });
        if !candidate {
            base = base.checked_add(1)?;
            continue;
        }
        trace.candidate_bases.push(base);
        let verifier_start = base.saturating_sub(backtrack).max(original_start);
        let forward_end = base.checked_add(forward_width)?;
        let verifier_end = if plan.clamp_forward_end {
            forward_end.min(original_end)
        } else {
            if forward_end > original_end {
                break;
            }
            forward_end
        };
        trace.verifier_windows.push((verifier_start, verifier_end));
        if verify_exists(view.dfa, haystack, verifier_start, verifier_end, &mut trace)? {
            trace.matched = true;
            return Some(trace);
        }
        base = base.checked_add(1)?;
    }
    Some(trace)
}

/// Execute the candidate/retry control flow independently of either machine
/// encoder. `None` means the structural inputs are malformed or unsupported.
#[must_use]
#[cfg(test)]
pub(crate) fn execute_bounded_suffix_retry_model(
    view: NativeProgramView<'_>,
    plan: BoundedSuffixRetryPlan,
    haystack: &[u8],
    original_start: usize,
    original_end: usize,
) -> Option<BoundedSuffixRetryTrace> {
    if view.output != OutputContract::Exists
        || view.dfa.initial_pending
        || original_start > original_end
        || original_end > haystack.len()
        || plan.clamp_forward_end
        || usize::from(plan.candidate_width) != view.anchored_suffix.sets().len()
        || plan.forward_width != u64::from(plan.candidate_width)
        || Some(usize::try_from(plan.total_width).ok()?) != view.max_match_width
    {
        return None;
    }
    let columns = suffix_model_columns(view)?;
    execute_bounded_retry_model(view, plan, &columns, haystack, original_start, original_end)
}

/// Execute a mandatory-interior candidate model with forward-order literal
/// columns. This is the architecture-neutral oracle for native integration.
#[must_use]
#[cfg(test)]
pub(crate) fn execute_bounded_interior_retry_model(
    view: NativeProgramView<'_>,
    plan: BoundedSuffixRetryPlan,
    candidate_sets: &[AnchoredByteSet],
    haystack: &[u8],
    original_start: usize,
    original_end: usize,
) -> Option<BoundedSuffixRetryTrace> {
    if !plan.clamp_forward_end || usize::from(plan.candidate_width) != candidate_sets.len() {
        return None;
    }
    let columns = forward_model_columns(candidate_sets)?;
    execute_bounded_retry_model(view, plan, &columns, haystack, original_start, original_end)
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "bounded exhaustive enumeration and checked test windows"
)]
mod tests {
    use super::*;
    use crate::{CompileMode, CompileRequest, MatchResult, SearchWindow, Target, compile};

    fn plan_for(view: NativeProgramView<'_>, frequency: u16) -> BoundedSuffixRetryPlan {
        select_bounded_suffix_retry(
            view.output,
            view.dfa.initial_pending,
            u8::try_from(view.anchored_suffix.sets().len()).unwrap(),
            view.max_match_width,
            frequency,
        )
        .unwrap()
    }

    fn assert_exhaustive(pattern: &str, alphabet: &[u8], maximum_len: usize) {
        let compiled = compile(
            CompileRequest::new(pattern, Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        )
        .unwrap();
        let view = compiled.program().native_dfa_view().unwrap();
        let plan = plan_for(view, 1);
        let mut haystack = Vec::new();
        for len in 0..=maximum_len {
            let cases = alphabet.len().pow(u32::try_from(len).unwrap());
            for mut ordinal in 0..cases {
                haystack.clear();
                haystack.resize(len, 0);
                for byte in &mut haystack {
                    *byte = alphabet[ordinal % alphabet.len()];
                    ordinal /= alphabet.len();
                }
                for start in 0..=len {
                    for end in start..=len {
                        let expected = compiled
                            .search(&haystack, SearchWindow::new(start, end))
                            .unwrap();
                        let actual =
                            execute_bounded_suffix_retry_model(view, plan, &haystack, start, end)
                                .unwrap();
                        assert_eq!(
                            actual.matched,
                            matches!(expected, MatchResult::Exists(true)),
                            "pattern={pattern:?} haystack={haystack:?} window={start}..{end} trace={actual:?}"
                        );
                        for &(verify_start, verify_end) in &actual.verifier_windows {
                            assert!(start <= verify_start);
                            assert!(verify_start <= verify_end);
                            assert!(verify_end <= end);
                            assert!(
                                verify_end - verify_start
                                    <= usize::try_from(plan.maximum_width()).unwrap()
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn selection_declines_unsupported_outputs_and_dense_overlap() {
        for output in [OutputContract::SelectedEnd, OutputContract::Span] {
            assert!(select_bounded_suffix_retry(output, false, 2, Some(8), 1).is_none());
        }
        assert!(select_bounded_suffix_retry(OutputContract::Exists, true, 2, Some(8), 1).is_none());
        assert!(select_bounded_suffix_retry(OutputContract::Exists, false, 2, None, 1).is_none());
        assert!(
            select_bounded_suffix_retry(OutputContract::Exists, false, 2, Some(1), 1).is_none()
        );
        assert!(
            select_bounded_suffix_retry(OutputContract::Exists, false, 2, Some(9), 15).is_none(),
            "nine verifier transitions at 15/256 candidate density exceed the overlap budget"
        );
        let plan =
            select_bounded_suffix_retry(OutputContract::Exists, false, 2, Some(9), 14).unwrap();
        assert_eq!(plan.backtrack(), 7);
        assert_eq!(plan.forward_width(), 2);
        assert!(!plan.clamps_forward_end());
        assert_eq!(plan.estimated_transition_units(), 126);

        for output in [OutputContract::SelectedEnd, OutputContract::Span] {
            assert!(select_bounded_interior_retry(output, false, 1, 2, 3, 1).is_none());
        }
        assert!(select_bounded_interior_retry(OutputContract::Exists, true, 1, 2, 3, 1).is_none());
        assert!(
            select_bounded_interior_retry(OutputContract::Exists, false, 4, 2, 3, 1).is_none(),
            "the through-accept bound must cover the candidate literal"
        );
        let interior =
            select_bounded_interior_retry(OutputContract::Exists, false, 1, 2, 3, 1).unwrap();
        assert_eq!(interior.minimum_width(), 1);
        assert_eq!(interior.backtrack(), 2);
        assert_eq!(interior.forward_width(), 3);
        assert_eq!(interior.maximum_width(), 5);
        assert!(interior.clamps_forward_end());
    }

    #[test]
    fn effective_aligned_frequency_preserves_fractional_selectivity_exactly() {
        assert!(EffectiveCandidateFrequency::from_aligned_column_units(&[]).is_none());
        assert!(EffectiveCandidateFrequency::from_aligned_column_units(&[0]).is_none());
        assert!(EffectiveCandidateFrequency::from_aligned_column_units(&[257]).is_none());

        // A primary with 32 frequency units makes a 1,024-transition retry
        // prohibitively dense on its own. An aligned one-unit secondary is
        // checked before the verifier, reducing the model to 32/256 expected
        // candidates per 256 bytes and exactly 128 verifier transitions.
        assert!(
            select_bounded_interior_retry(OutputContract::Exists, false, 1, 1_023, 1, 32).is_none()
        );
        let two_columns = EffectiveCandidateFrequency::from_aligned_column_units(&[32, 1]).unwrap();
        assert_eq!(two_columns.units_numerator, 32);
        assert_eq!(two_columns.units_denominator, 256);
        let selected = select_bounded_interior_retry_with_effective_frequency(
            OutputContract::Exists,
            false,
            1,
            1_023,
            1,
            two_columns,
        )
        .unwrap();
        assert_eq!(selected.estimated_transition_units(), 128);
        assert!(
            select_bounded_interior_retry_with_effective_frequency(
                OutputContract::Exists,
                false,
                1,
                1_024,
                1,
                two_columns,
            )
            .is_none(),
            "the selector must compare the unrounded rational work at the boundary"
        );

        // A third checked column remains fractional rather than rounding up
        // after either multiplication: 262,144 * 32 / 65,536 = 128.
        let three_columns =
            EffectiveCandidateFrequency::from_aligned_column_units(&[32, 1, 1]).unwrap();
        let selected = select_bounded_interior_retry_with_effective_frequency(
            OutputContract::Exists,
            false,
            1,
            262_143,
            1,
            three_columns,
        )
        .unwrap();
        assert_eq!(selected.estimated_transition_units(), 128);
        assert!(
            select_bounded_interior_retry_with_effective_frequency(
                OutputContract::Exists,
                false,
                1,
                262_144,
                1,
                three_columns,
            )
            .is_none()
        );

        let fractional = EffectiveCandidateFrequency::from_aligned_column_units(&[1, 1]).unwrap();
        let selected = select_bounded_interior_retry_with_effective_frequency(
            OutputContract::Exists,
            false,
            1,
            0,
            1,
            fractional,
        )
        .unwrap();
        assert_eq!(
            selected.estimated_transition_units(),
            1,
            "the stored ranking key rounds up, but selection uses the exact fraction"
        );
    }

    #[test]
    fn model_retries_false_suffix_candidates_in_bounded_windows() {
        let pattern = r"(?:MQw|[d-e]|r74){2,3}[j-k]Q";
        let compiled = compile(
            CompileRequest::new(pattern, Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        )
        .unwrap();
        let view = compiled.program().native_dfa_view().unwrap();
        let plan = plan_for(view, 1);
        let suffix_sets = view.anchored_suffix.sets();
        let candidate_width = suffix_sets.len();
        let alternatives = suffix_sets
            .iter()
            .rev()
            .map(|set| {
                (u8::MIN..=u8::MAX)
                    .filter(|&byte| contains(*set, byte))
                    .take(16)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        assert!(alternatives.iter().all(|bytes| !bytes.is_empty()));
        let mut false_suffix = vec![0_u8; candidate_width];
        let cases = alternatives
            .iter()
            .map(Vec::len)
            .try_fold(1_usize, usize::checked_mul)
            .unwrap();
        let mut found = false;
        for mut ordinal in 0..cases {
            for (byte, choices) in false_suffix.iter_mut().zip(&alternatives) {
                *byte = choices[ordinal % choices.len()];
                ordinal /= choices.len();
            }
            let expected = compiled
                .search(&false_suffix, SearchWindow::new(0, false_suffix.len()))
                .unwrap();
            if expected == MatchResult::Exists(false) {
                found = true;
                break;
            }
        }
        assert!(found, "the independent suffix columns need a false product");
        let maximum_width = usize::try_from(plan.maximum_width()).unwrap();
        let mut haystack = Vec::new();
        for _ in 0..4 {
            haystack.extend(std::iter::repeat_n(0, maximum_width));
            haystack.extend_from_slice(&false_suffix);
        }
        haystack.extend(std::iter::repeat_n(0, maximum_width));
        haystack.extend_from_slice(b"MQwMQwjQ");
        let trace =
            execute_bounded_suffix_retry_model(view, plan, &haystack, 0, haystack.len()).unwrap();
        assert!(trace.matched);
        assert!(trace.candidate_bases.len() >= 5, "{trace:?}");
        assert_eq!(trace.candidate_bases.len(), trace.verifier_windows.len());
        assert!(
            trace
                .verifier_windows
                .iter()
                .all(|&(start, end)| end - start <= 11)
        );
    }

    #[test]
    fn model_matches_dfa_for_all_small_windows_and_bounded_shapes() {
        // Literal, variable alternation, optional, bounded repetition, and
        // nullable subexpressions exercise different `M - m` lower bounds.
        for pattern in [
            "ab",
            "(?:ab|c)d",
            "a(?:b)?c",
            "(?:a|bb){1,2}c",
            "(?:a?b){1,2}c",
        ] {
            assert_exhaustive(pattern, b"abcdx", 6);
        }
    }

    #[test]
    fn interior_model_clamps_a_longer_forward_bound_and_matches_every_small_window() {
        let pattern = "(?:ab|c)X(?:de|f)";
        let compiled = compile(
            CompileRequest::new(pattern, Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        )
        .unwrap();
        let view = compiled.program().native_dfa_view().unwrap();
        let plan = select_bounded_interior_retry(view.output, view.dfa.initial_pending, 1, 2, 3, 1)
            .unwrap();
        assert!(plan.forward_width() > u64::from(plan.minimum_width()));
        let byte = usize::from(b'X');
        let mut words = [0_u64; 4];
        words[byte / 64] |= 1_u64 << (byte % 64);
        let candidate_sets = [AnchoredByteSet::from_words(words)];

        let clamped =
            execute_bounded_interior_retry_model(view, plan, &candidate_sets, b"cXf", 0, 3)
                .unwrap();
        assert!(clamped.matched);
        assert_eq!(clamped.candidate_bases, [1]);
        assert_eq!(clamped.verifier_windows, [(0, 3)]);

        let alphabet = b"abcdefXz";
        let mut haystack = Vec::new();
        for len in 0_usize..=5 {
            let cases = alphabet.len().pow(u32::try_from(len).unwrap());
            for mut ordinal in 0..cases {
                haystack.clear();
                haystack.resize(len, 0);
                for byte in &mut haystack {
                    *byte = alphabet[ordinal % alphabet.len()];
                    ordinal /= alphabet.len();
                }
                for start in 0..=len {
                    for end in start..=len {
                        let expected = compiled
                            .search(&haystack, SearchWindow::new(start, end))
                            .unwrap();
                        let actual = execute_bounded_interior_retry_model(
                            view,
                            plan,
                            &candidate_sets,
                            &haystack,
                            start,
                            end,
                        )
                        .unwrap();
                        assert_eq!(
                            actual.matched,
                            matches!(expected, MatchResult::Exists(true)),
                            "haystack={haystack:?} window={start}..{end} trace={actual:?}"
                        );
                        for &(verify_start, verify_end) in &actual.verifier_windows {
                            assert!(start <= verify_start);
                            assert!(verify_start <= verify_end);
                            assert!(verify_end <= end);
                            assert!(
                                verify_end - verify_start
                                    <= usize::try_from(plan.maximum_width()).unwrap()
                            );
                        }
                    }
                }
            }
        }
    }
}
