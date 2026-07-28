//! Bounded required-literal prefilter for capture-preserving operations.

use core::{fmt, mem::size_of};
use std::{alloc::Layout, sync::Arc};

use fre_exact_alloc::{CopyError, ExactVec};
use fre_kernels::{
    LiteralSetAccounting, LiteralSetBuildAccounting, LiteralSetBuildLimits, LiteralSetError,
    LiteralSetIterationAccounting, LiteralSetMatchSemantics, LiteralSetMatches, LiteralSetPlan,
    LiteralSetSearchLimits,
};
use fre_syntax::CacheKey;
use regex_syntax::hir::{Class, Hir, HirKind};

/// Versioned algorithm identity for the required-any-literal proof.
pub const CAPTURE_REQUIRED_LITERAL_PLAN_ID: &str = "fre.capture.required-any-literal-dfa.v5";

const MAX_INLINE_NEEDLES: usize = 64;
const NEEDLE_OFFSET_SLOTS: usize = MAX_INLINE_NEEDLES + 1;

#[derive(Clone, Copy)]
enum RawNeedle<'hir> {
    Literal(&'hir [u8]),
    Byte([u8; 1]),
}

impl RawNeedle<'_> {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Literal(bytes) => bytes,
            Self::Byte(byte) => byte,
        }
    }
}

#[cfg(test)]
mod exact_allocation_probe {
    use std::cell::Cell;

    std::thread_local! {
        static CALLS: Cell<usize> = const { Cell::new(0) };
    }

    pub(super) fn record() {
        CALLS.set(CALLS.get().checked_add(1).expect("test probe overflow"));
    }

    pub(super) fn reset() {
        CALLS.set(0);
    }

    pub(super) fn calls() -> usize {
        CALLS.get()
    }
}

/// Fixed construction limits included in plan identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureRequiredLiteralBuildLimits {
    pub max_planner_work: usize,
    pub max_hir_depth: usize,
    pub max_needles: usize,
    pub max_needle_bytes: usize,
    pub max_source_bytes: usize,
    pub max_scratch_bytes: usize,
    pub max_peak_bytes: usize,
    pub literal_set: LiteralSetBuildLimits,
}

impl Default for CaptureRequiredLiteralBuildLimits {
    fn default() -> Self {
        Self {
            max_planner_work: 1_000_000,
            max_hir_depth: 250,
            max_needles: 64,
            max_needle_bytes: 4 * 1_024,
            max_source_bytes: 16 * 1_048_576,
            max_scratch_bytes: 4 * 1_024,
            max_peak_bytes: 64 * 1_048_576,
            literal_set: LiteralSetBuildLimits {
                max_patterns: 64,
                max_pattern_bytes: 4 * 1_024,
                max_build_work: 4 * 1_048_576,
                max_build_bytes: 32 * 1_048_576,
                max_persistent_bytes: 8 * 1_048_576,
            },
        }
    }
}

/// Exact planner and bounded DFA construction receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureRequiredLiteralBuildAccounting {
    pub planner_work: usize,
    pub hir_nodes: usize,
    pub hir_depth: usize,
    pub raw_needles: usize,
    pub raw_needle_bytes: usize,
    pub needles: usize,
    pub needle_bytes: usize,
    pub minimum_needle_bytes: usize,
    /// Whether no effective literal contains CR or LF, permitting a
    /// construction-proved whole-input scan aligned with stripped lines.
    pub line_partition_safe: bool,
    pub source_bytes: usize,
    pub scratch_bytes: usize,
    pub peak_bytes_upper_bound: usize,
    pub literal_set: LiteralSetBuildAccounting,
}

/// Flat, exact-capacity effective needle storage retained in plan identity.
pub struct CaptureRequiredLiteralNeedles {
    arena: ExactVec<u8>,
    offsets: [usize; NEEDLE_OFFSET_SLOTS],
    count: usize,
}

impl CaptureRequiredLiteralNeedles {
    /// Number of effective needles.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether the effective set is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Total bytes in the exact flat arena.
    #[must_use]
    pub const fn byte_len(&self) -> usize {
        self.arena.len()
    }

    /// Borrow one effective needle in deterministic first-occurrence order.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&[u8]> {
        if index >= self.count {
            return None;
        }
        let end_index = index.checked_add(1)?;
        Some(&self.arena[self.offsets[index]..self.offsets[end_index]])
    }

    /// Iterate over effective needles in deterministic first-occurrence order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &[u8]> + '_ {
        (0..self.count).map(|index| {
            self.get(index)
                .expect("bounded needle iterator index remains in range")
        })
    }
}

impl fmt::Debug for CaptureRequiredLiteralNeedles {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_list().entries(self.iter()).finish()
    }
}

impl PartialEq for CaptureRequiredLiteralNeedles {
    fn eq(&self, other: &Self) -> bool {
        self.count == other.count
            && self.arena.as_slice() == other.arena.as_slice()
            && self.offsets[..=self.count] == other.offsets[..=other.count]
    }
}

impl Eq for CaptureRequiredLiteralNeedles {}

/// Immutable proof identity. Source syntax remains distinct even when HIRs agree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureRequiredLiteralIdentity {
    pub syntax: Arc<CacheKey>,
    pub plan_id: &'static str,
    pub needles: Arc<CaptureRequiredLiteralNeedles>,
}

/// Published construction report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureRequiredLiteralBuildReport {
    pub identity: CaptureRequiredLiteralIdentity,
    pub accounting: CaptureRequiredLiteralBuildAccounting,
}

/// Typed construction refusal.
#[derive(Debug)]
#[non_exhaustive]
pub enum CaptureRequiredLiteralBuildError {
    Resource {
        resource: &'static str,
        required: usize,
        limit: usize,
    },
    Allocation {
        structure: &'static str,
        items: usize,
    },
    LiteralSet(LiteralSetError),
    Overflow(&'static str),
    InternalInvariant(&'static str),
}

impl fmt::Display for CaptureRequiredLiteralBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resource {
                resource,
                required,
                limit,
            } => write!(
                f,
                "required-literal {resource} needs {required}, exceeding {limit}"
            ),
            Self::Allocation { structure, items } => write!(
                f,
                "required-literal failed to reserve {items} {structure} items"
            ),
            Self::LiteralSet(error) => write!(f, "required-literal DFA failed: {error}"),
            Self::Overflow(computation) => write!(
                f,
                "required-literal arithmetic overflow while computing {computation}"
            ),
            Self::InternalInvariant(detail) => {
                write!(f, "required-literal invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for CaptureRequiredLiteralBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::LiteralSet(error) => Some(error),
            _ => None,
        }
    }
}

/// Per-window transition limit, retained in cache identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureRequiredLiteralRunLimits {
    pub max_transitions: usize,
}

impl Default for CaptureRequiredLiteralRunLimits {
    fn default() -> Self {
        Self {
            max_transitions: 128 * 1_048_576,
        }
    }
}

/// Complete identity for one prefilter search.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureRequiredLiteralSearchOperation {
    /// One first-match candidate decision over an independent byte slice.
    CandidateV1,
    /// One non-overlapping literal stream aligned by the caller with lines.
    LinePartitionMatchesV1,
}

/// Complete identity for one prefilter search.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureRequiredLiteralCacheIdentity {
    pub plan: CaptureRequiredLiteralIdentity,
    pub build_limits: CaptureRequiredLiteralBuildLimits,
    pub operation: CaptureRequiredLiteralSearchOperation,
    pub run_limits: CaptureRequiredLiteralRunLimits,
}

/// Successful candidate decision and exact DFA accounting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureRequiredLiteralSearchReport {
    pub identity: CaptureRequiredLiteralCacheIdentity,
    pub candidate: bool,
    pub accounting: LiteralSetAccounting,
}

/// One checked whole-input literal stream that is safe to align with
/// LF/CRLF-stripped line partitions.
///
/// Construction is refused with `Ok(None)` when an effective literal contains
/// either line-terminator byte. In that case a caller must retain independent
/// per-line searches, since a whole-input match could otherwise cross or
/// consume a semantic delimiter and shadow an in-line candidate.
#[derive(Debug)]
pub struct CaptureRequiredLiteralLinePartitionMatches<'plan, 'haystack> {
    identity: CaptureRequiredLiteralCacheIdentity,
    accounting: LiteralSetIterationAccounting,
    matches: LiteralSetMatches<'plan, 'haystack>,
}

impl CaptureRequiredLiteralLinePartitionMatches<'_, '_> {
    /// Complete plan/build/run identity for this scan.
    #[must_use]
    pub const fn identity(&self) -> &CaptureRequiredLiteralCacheIdentity {
        &self.identity
    }

    /// Complete-haystack DFA prospective charged before iteration.
    #[must_use]
    pub const fn accounting(&self) -> LiteralSetIterationAccounting {
        self.accounting
    }
}

impl Iterator for CaptureRequiredLiteralLinePartitionMatches<'_, '_> {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<Self::Item> {
        self.matches.next()
    }
}

impl core::iter::FusedIterator for CaptureRequiredLiteralLinePartitionMatches<'_, '_> {}

/// Failed candidate decision retaining complete identity.
#[derive(Debug)]
pub struct CaptureRequiredLiteralSearchError {
    pub identity: CaptureRequiredLiteralCacheIdentity,
    pub source: LiteralSetError,
}

impl fmt::Display for CaptureRequiredLiteralSearchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "required-literal search failed: {}", self.source)
    }
}

impl std::error::Error for CaptureRequiredLiteralSearchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

pub(crate) struct CaptureRequiredLiteralBuildOutcome {
    pub(crate) plan: Option<CaptureRequiredLiteralPlan>,
    pub(crate) planner_work: usize,
}

pub(crate) struct CaptureRequiredLiteralBuildFailure {
    pub(crate) source: CaptureRequiredLiteralBuildError,
    pub(crate) planner_work: usize,
}

#[allow(
    clippy::too_many_lines,
    reason = "the bounded proof, allocation, publication, and DFA receipts remain one auditable transaction"
)]
pub(crate) fn build_from_hir(
    hir: &Hir,
    syntax: Arc<CacheKey>,
    limits: CaptureRequiredLiteralBuildLimits,
) -> Result<CaptureRequiredLiteralBuildOutcome, CaptureRequiredLiteralBuildFailure> {
    build_from_hirs(core::slice::from_ref(hir), syntax, limits)
}

/// Build one conservative any-literal plan for the logical ordered
/// alternation of independently owned HIR roots.
///
/// This deliberately traverses the roots as an alternation instead of
/// materializing [`Hir::alternation`]. The latter performs upstream HIR
/// normalization with variable internal allocations that are neither needed
/// for this conservative proof nor owned by the plan. Each root remains live
/// only for the bounded proof construction; publication still copies every
/// selected literal into the plan's exact-capacity arena.
pub(crate) fn build_from_hirs(
    hirs: &[Hir],
    syntax: Arc<CacheKey>,
    limits: CaptureRequiredLiteralBuildLimits,
) -> Result<CaptureRequiredLiteralBuildOutcome, CaptureRequiredLiteralBuildFailure> {
    let mut meter = Meter::new(limits);
    match build_from_hirs_metered(hirs, syntax, limits, &mut meter) {
        Ok(plan) => Ok(CaptureRequiredLiteralBuildOutcome {
            plan,
            planner_work: meter.work,
        }),
        Err(source) => Err(CaptureRequiredLiteralBuildFailure {
            source,
            planner_work: meter.work,
        }),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the exact antichain, resource preflight, allocation, DFA construction, and publication form one auditable transaction"
)]
fn build_from_hirs_metered(
    hirs: &[Hir],
    syntax: Arc<CacheKey>,
    limits: CaptureRequiredLiteralBuildLimits,
    meter: &mut Meter,
) -> Result<Option<CaptureRequiredLiteralPlan>, CaptureRequiredLiteralBuildError> {
    let Some(raw_metrics) = measure_hir_alternation(hirs, meter)? else {
        return Ok(None);
    };
    if raw_metrics.needles > MAX_INLINE_NEEDLES {
        return Err(CaptureRequiredLiteralBuildError::Resource {
            resource: "raw needle references",
            required: raw_metrics.needles,
            limit: MAX_INLINE_NEEDLES,
        });
    }

    let canonical_scratch = size_of::<[RawNeedle<'static>; MAX_INLINE_NEEDLES]>()
        .checked_add(size_of::<[bool; MAX_INLINE_NEEDLES]>())
        .ok_or(CaptureRequiredLiteralBuildError::Overflow(
            "canonical antichain scratch",
        ))?;
    check_limit("scratch bytes", canonical_scratch, limits.max_scratch_bytes)?;

    let mut raw_needles = [RawNeedle::Literal(&[]); MAX_INLINE_NEEDLES];
    let mut raw_count = 0_usize;
    collect_hir_alternation(hirs, meter, &mut raw_needles, &mut raw_count)?;
    if raw_count != raw_metrics.needles {
        return Err(CaptureRequiredLiteralBuildError::InternalInvariant(
            "collected raw needle count differs from proof",
        ));
    }
    let (retained, effective) = effective_antichain(&raw_needles[..raw_count], meter)?;
    check_metric_limits(effective, limits)?;
    if effective.needles == 0 {
        return Ok(None);
    }

    let reference_scratch = effective.needles.checked_mul(size_of::<&[u8]>()).ok_or(
        CaptureRequiredLiteralBuildError::Overflow("exact reference scratch"),
    )?;
    let scratch_bytes = canonical_scratch.checked_add(reference_scratch).ok_or(
        CaptureRequiredLiteralBuildError::Overflow("combined canonical and reference scratch"),
    )?;
    check_limit("scratch bytes", scratch_bytes, limits.max_scratch_bytes)?;

    let needle_arc_block = arc_block_bytes::<CaptureRequiredLiteralNeedles>()?;
    let source_before_matcher = effective.bytes.checked_add(needle_arc_block).ok_or(
        CaptureRequiredLiteralBuildError::Overflow("effective needle source bytes"),
    )?;
    check_limit(
        "source bytes",
        source_before_matcher,
        limits.max_source_bytes,
    )?;

    let dfa_limits = limits.literal_set;
    let matcher_arc_block = arc_block_bytes::<LiteralSetPlan>()?;
    let plan_value_bytes = size_of::<CaptureRequiredLiteralPlan>();
    let fixed_persistent = source_before_matcher
        .checked_add(matcher_arc_block)
        .and_then(|bytes| bytes.checked_add(plan_value_bytes))
        .ok_or(CaptureRequiredLiteralBuildError::Overflow(
            "fixed persistent bytes",
        ))?;
    let source_bytes = fixed_persistent
        .checked_add(dfa_limits.max_persistent_bytes)
        .ok_or(CaptureRequiredLiteralBuildError::Overflow(
            "reserved published source bytes",
        ))?;
    check_limit("source bytes", source_bytes, limits.max_source_bytes)?;

    let live_before_dfa = fixed_persistent.checked_add(scratch_bytes).ok_or(
        CaptureRequiredLiteralBuildError::Overflow("live bytes before DFA"),
    )?;
    let peak_bytes_upper_bound = live_before_dfa
        .checked_add(dfa_limits.max_build_bytes)
        .ok_or(CaptureRequiredLiteralBuildError::Overflow(
            "reserved peak build bytes",
        ))?;
    check_limit("peak bytes", peak_bytes_upper_bound, limits.max_peak_bytes)?;
    // Admit every raw publication-loop visit, retained offset, effective-byte
    // visit (copy plus CR/LF classification), reference publication, and final
    // publication before either exact allocation or copy work begins.
    let publication_work = effective
        .needles
        .checked_mul(2)
        .and_then(|work| work.checked_add(raw_count))
        .and_then(|work| work.checked_add(effective.bytes))
        .and_then(|work| work.checked_add(3))
        .ok_or(CaptureRequiredLiteralBuildError::Overflow(
            "needle publication work",
        ))?;
    meter.charge(publication_work)?;

    #[cfg(test)]
    exact_allocation_probe::record();
    let mut arena = ExactVec::try_with_capacity(effective.bytes)
        .map_err(|error| map_exact_allocation(error, "effective needle byte", effective.bytes))?;
    let mut offsets = [0_usize; NEEDLE_OFFSET_SLOTS];
    let mut effective_index = 0_usize;
    let mut line_partition_safe = true;
    for (raw_index, needle) in raw_needles[..raw_count].iter().enumerate() {
        if !retained[raw_index] {
            continue;
        }
        offsets[effective_index] = arena.len();
        for &byte in needle.bytes() {
            line_partition_safe &= byte != b'\r' && byte != b'\n';
            arena.try_push(byte).map_err(|_| {
                CaptureRequiredLiteralBuildError::InternalInvariant(
                    "admitted exact needle arena rejected a byte",
                )
            })?;
        }
        effective_index =
            effective_index
                .checked_add(1)
                .ok_or(CaptureRequiredLiteralBuildError::Overflow(
                    "effective needle index",
                ))?;
        offsets[effective_index] = arena.len();
    }
    if effective_index != effective.needles || arena.len() != effective.bytes {
        return Err(CaptureRequiredLiteralBuildError::InternalInvariant(
            "effective needle publication differs from antichain proof",
        ));
    }
    let needles = CaptureRequiredLiteralNeedles {
        arena,
        offsets,
        count: effective.needles,
    };
    #[cfg(test)]
    exact_allocation_probe::record();
    let mut refs = ExactVec::try_with_capacity(effective.needles).map_err(|error| {
        map_exact_allocation(error, "effective needle reference", effective.needles)
    })?;
    for index in 0..effective.needles {
        refs.try_push(needles.get(index).ok_or(
            CaptureRequiredLiteralBuildError::InternalInvariant(
                "effective needle offset is missing",
            ),
        )?)
        .map_err(|_| {
            CaptureRequiredLiteralBuildError::InternalInvariant(
                "admitted exact reference storage rejected a needle",
            )
        })?;
    }
    let matcher = LiteralSetPlan::new_streaming_any(refs.as_slice(), dfa_limits)
        .map_err(CaptureRequiredLiteralBuildError::LiteralSet)?;
    let literal_set = matcher.build_accounting();
    if literal_set.match_semantics != LiteralSetMatchSemantics::StreamingAny
        || literal_set.minimum_pattern_bytes != effective.minimum_bytes
    {
        return Err(CaptureRequiredLiteralBuildError::InternalInvariant(
            "literal-set semantics or minimum differs from effective needle proof",
        ));
    }

    let actual_source_bytes = fixed_persistent
        .checked_add(literal_set.persistent_bytes)
        .ok_or(CaptureRequiredLiteralBuildError::Overflow(
            "published source bytes",
        ))?;
    if actual_source_bytes > source_bytes {
        return Err(CaptureRequiredLiteralBuildError::InternalInvariant(
            "literal-set source exceeded its admitted reservation",
        ));
    }
    let actual_peak_bytes_upper_bound = live_before_dfa
        .checked_add(literal_set.build_bytes_upper_bound)
        .ok_or(CaptureRequiredLiteralBuildError::Overflow(
            "peak build bytes",
        ))?;
    if actual_peak_bytes_upper_bound > peak_bytes_upper_bound {
        return Err(CaptureRequiredLiteralBuildError::InternalInvariant(
            "literal-set peak exceeded its admitted reservation",
        ));
    }

    let identity = CaptureRequiredLiteralIdentity {
        syntax,
        plan_id: CAPTURE_REQUIRED_LITERAL_PLAN_ID,
        needles: Arc::new(needles),
    };
    let report = CaptureRequiredLiteralBuildReport {
        identity,
        accounting: CaptureRequiredLiteralBuildAccounting {
            planner_work: meter.work,
            hir_nodes: meter.nodes,
            hir_depth: meter.depth,
            raw_needles: raw_metrics.needles,
            raw_needle_bytes: raw_metrics.bytes,
            needles: effective.needles,
            needle_bytes: effective.bytes,
            minimum_needle_bytes: effective.minimum_bytes,
            line_partition_safe,
            source_bytes,
            scratch_bytes,
            peak_bytes_upper_bound,
            literal_set,
        },
    };
    Ok(Some(CaptureRequiredLiteralPlan {
        matcher: Arc::new(matcher),
        build_limits: limits,
        report,
    }))
}

/// Immutable, cheaply cloneable candidate prefilter.
#[derive(Clone, Debug)]
pub struct CaptureRequiredLiteralPlan {
    matcher: Arc<LiteralSetPlan>,
    build_limits: CaptureRequiredLiteralBuildLimits,
    report: CaptureRequiredLiteralBuildReport,
}

impl CaptureRequiredLiteralPlan {
    #[must_use]
    pub const fn build_report(&self) -> &CaptureRequiredLiteralBuildReport {
        &self.report
    }

    /// Derive the complete cache identity used by [`Self::is_candidate`] for
    /// the supplied execution limits.
    ///
    /// This lets a composite caller authenticate a returned
    /// [`CaptureRequiredLiteralSearchReport`] to this exact immutable plan,
    /// its construction limits, the [`CaptureRequiredLiteralSearchOperation::CandidateV1`]
    /// operation, and its own run limits without performing a search.
    #[must_use]
    pub fn candidate_cache_identity(
        &self,
        run_limits: CaptureRequiredLiteralRunLimits,
    ) -> CaptureRequiredLiteralCacheIdentity {
        self.cache_identity(
            run_limits,
            CaptureRequiredLiteralSearchOperation::CandidateV1,
        )
    }

    #[allow(
        clippy::result_large_err,
        reason = "typed refusal retains complete cache identity without an unmetered error-path allocation"
    )]
    pub fn is_candidate(
        &self,
        haystack: &[u8],
        run_limits: CaptureRequiredLiteralRunLimits,
    ) -> Result<CaptureRequiredLiteralSearchReport, CaptureRequiredLiteralSearchError> {
        let identity = self.candidate_cache_identity(run_limits);
        let (matched, accounting) = self
            .matcher
            .find(
                haystack,
                LiteralSetSearchLimits {
                    max_transitions: run_limits.max_transitions,
                },
            )
            .map_err(|source| CaptureRequiredLiteralSearchError {
                identity: identity.clone(),
                source,
            })?;
        Ok(CaptureRequiredLiteralSearchReport {
            identity,
            candidate: matched.is_some(),
            accounting,
        })
    }

    /// Start one DFA traversal whose matches can be merged with a caller's
    /// exact LF/CRLF line scan.
    ///
    /// `Ok(None)` is a semantic fallback signal, not a resource failure. It is
    /// returned when any effective required literal contains CR or LF, because
    /// a whole-haystack match could then consume a stripped delimiter. `Some`
    /// retains a complete operation-specific cache identity and whole-input
    /// iterator transition envelope.
    #[allow(
        clippy::result_large_err,
        reason = "typed refusal retains complete cache identity without an unmetered error-path allocation"
    )]
    pub fn line_partition_matches<'plan, 'haystack>(
        &'plan self,
        haystack: &'haystack [u8],
        run_limits: CaptureRequiredLiteralRunLimits,
    ) -> Result<
        Option<CaptureRequiredLiteralLinePartitionMatches<'plan, 'haystack>>,
        CaptureRequiredLiteralSearchError,
    > {
        let Some(prospective) =
            self.line_partition_prospective(haystack.len())
                .map_err(|source| CaptureRequiredLiteralSearchError {
                    identity: self.cache_identity(
                        run_limits,
                        CaptureRequiredLiteralSearchOperation::LinePartitionMatchesV1,
                    ),
                    source,
                })?
        else {
            return Ok(None);
        };
        let identity = self.cache_identity(
            run_limits,
            CaptureRequiredLiteralSearchOperation::LinePartitionMatchesV1,
        );
        if prospective.transitions_upper_bound > run_limits.max_transitions {
            return Err(CaptureRequiredLiteralSearchError {
                identity,
                source: LiteralSetError::TransitionLimit {
                    needed: prospective.transitions_upper_bound,
                    limit: run_limits.max_transitions,
                },
            });
        }
        let (matches, accounting) = self
            .matcher
            .find_iter(
                haystack,
                LiteralSetSearchLimits {
                    max_transitions: run_limits.max_transitions,
                },
            )
            .map_err(|source| CaptureRequiredLiteralSearchError {
                identity: identity.clone(),
                source,
            })?;
        Ok(Some(CaptureRequiredLiteralLinePartitionMatches {
            identity,
            accounting,
            matches,
        }))
    }

    /// Derive the complete line-partition iterator envelope without reading
    /// input bytes. `None` is the construction-owned delimiter fallback.
    pub fn line_partition_prospective(
        &self,
        haystack_len: usize,
    ) -> Result<Option<LiteralSetIterationAccounting>, LiteralSetError> {
        if !self.report.accounting.line_partition_safe {
            return Ok(None);
        }
        self.matcher.find_iter_accounting(haystack_len).map(Some)
    }

    fn cache_identity(
        &self,
        run_limits: CaptureRequiredLiteralRunLimits,
        operation: CaptureRequiredLiteralSearchOperation,
    ) -> CaptureRequiredLiteralCacheIdentity {
        CaptureRequiredLiteralCacheIdentity {
            plan: self.report.identity.clone(),
            build_limits: self.build_limits,
            operation,
            run_limits,
        }
    }
}

#[derive(Clone, Copy)]
struct Metrics {
    needles: usize,
    bytes: usize,
    minimum_bytes: usize,
}

fn prefer_required_literal(candidate: Metrics, current: Metrics) -> bool {
    candidate.minimum_bytes > current.minimum_bytes
        || (candidate.minimum_bytes == current.minimum_bytes
            && (candidate.needles < current.needles
                || (candidate.needles == current.needles && candidate.bytes > current.bytes)))
}

struct Meter {
    limits: CaptureRequiredLiteralBuildLimits,
    work: usize,
    nodes: usize,
    depth: usize,
}

impl Meter {
    const fn new(limits: CaptureRequiredLiteralBuildLimits) -> Self {
        Self {
            limits,
            work: 0,
            nodes: 0,
            depth: 0,
        }
    }

    fn enter(&mut self, depth: usize) -> Result<(), CaptureRequiredLiteralBuildError> {
        check_limit("HIR depth", depth, self.limits.max_hir_depth)?;
        self.depth = self.depth.max(depth);
        self.nodes = self
            .nodes
            .checked_add(1)
            .ok_or(CaptureRequiredLiteralBuildError::Overflow("HIR nodes"))?;
        self.charge(1)
    }

    fn charge(&mut self, amount: usize) -> Result<(), CaptureRequiredLiteralBuildError> {
        let required = self
            .work
            .checked_add(amount)
            .ok_or(CaptureRequiredLiteralBuildError::Overflow("planner work"))?;
        check_limit("planner work", required, self.limits.max_planner_work)?;
        self.work = required;
        Ok(())
    }
}

fn measure(
    hir: &Hir,
    depth: usize,
    meter: &mut Meter,
) -> Result<Option<Metrics>, CaptureRequiredLiteralBuildError> {
    meter.enter(depth)?;
    match hir.kind() {
        HirKind::Literal(literal) if !literal.0.is_empty() => {
            meter.charge(literal.0.len())?;
            Ok(Some(Metrics {
                needles: 1,
                bytes: literal.0.len(),
                minimum_bytes: literal.0.len(),
            }))
        }
        HirKind::Class(class) => measure_ascii_class(class, meter),
        HirKind::Capture(capture) => measure(&capture.sub, next_depth(depth)?, meter),
        HirKind::Repetition(repetition) if repetition.min > 0 => {
            measure(&repetition.sub, next_depth(depth)?, meter)
        }
        HirKind::Concat(children) => {
            let mut best = None;
            for child in children {
                if let Some(metrics) = measure(child, next_depth(depth)?, meter)?
                    && best.is_none_or(|current| prefer_required_literal(metrics, current))
                {
                    best = Some(metrics);
                }
            }
            Ok(best)
        }
        HirKind::Alternation(children) if !children.is_empty() => {
            let mut needles = 0_usize;
            let mut bytes = 0_usize;
            let mut minimum_bytes = usize::MAX;
            for child in children {
                let Some(metrics) = measure(child, next_depth(depth)?, meter)? else {
                    return Ok(None);
                };
                needles = needles
                    .checked_add(metrics.needles)
                    .ok_or(CaptureRequiredLiteralBuildError::Overflow("needle count"))?;
                bytes = bytes
                    .checked_add(metrics.bytes)
                    .ok_or(CaptureRequiredLiteralBuildError::Overflow("needle bytes"))?;
                minimum_bytes = minimum_bytes.min(metrics.minimum_bytes);
            }
            Ok(Some(Metrics {
                needles,
                bytes,
                minimum_bytes,
            }))
        }
        _ => Ok(None),
    }
}

/// Measure independently parsed roots as one logical alternation without
/// constructing an upstream normalized HIR node. No synthetic root is
/// charged: this helper owns no additional HIR and the individual parser
/// receipts already account for every supplied root.
fn measure_hir_alternation(
    hirs: &[Hir],
    meter: &mut Meter,
) -> Result<Option<Metrics>, CaptureRequiredLiteralBuildError> {
    if hirs.is_empty() {
        return Ok(None);
    }
    let mut needles = 0_usize;
    let mut bytes = 0_usize;
    let mut minimum_bytes = usize::MAX;
    for hir in hirs {
        let Some(metrics) = measure(hir, 1, meter)? else {
            return Ok(None);
        };
        needles = needles
            .checked_add(metrics.needles)
            .ok_or(CaptureRequiredLiteralBuildError::Overflow("needle count"))?;
        bytes = bytes
            .checked_add(metrics.bytes)
            .ok_or(CaptureRequiredLiteralBuildError::Overflow("needle bytes"))?;
        minimum_bytes = minimum_bytes.min(metrics.minimum_bytes);
    }
    Ok(Some(Metrics {
        needles,
        bytes,
        minimum_bytes,
    }))
}

fn measure_ascii_class(
    class: &Class,
    meter: &mut Meter,
) -> Result<Option<Metrics>, CaptureRequiredLiteralBuildError> {
    let mut bytes = 0_usize;
    match class {
        Class::Unicode(class) => {
            for range in class.ranges() {
                meter.charge(1)?;
                let start = u32::from(range.start());
                let end = u32::from(range.end());
                if end > 0x7F {
                    return Ok(None);
                }
                let width = inclusive_class_width(u64::from(start), u64::from(end))?;
                meter.charge(width)?;
                bytes =
                    bytes
                        .checked_add(width)
                        .ok_or(CaptureRequiredLiteralBuildError::Overflow(
                            "ASCII class bytes",
                        ))?;
            }
        }
        Class::Bytes(class) => {
            for range in class.ranges() {
                meter.charge(1)?;
                let width =
                    inclusive_class_width(u64::from(range.start()), u64::from(range.end()))?;
                meter.charge(width)?;
                bytes =
                    bytes
                        .checked_add(width)
                        .ok_or(CaptureRequiredLiteralBuildError::Overflow(
                            "byte class bytes",
                        ))?;
            }
        }
    }
    if bytes > MAX_INLINE_NEEDLES {
        return Ok(None);
    }
    Ok((bytes != 0).then_some(Metrics {
        needles: bytes,
        bytes,
        minimum_bytes: 1,
    }))
}

fn collect_ascii_class(
    class: &Class,
    meter: &mut Meter,
    output: &mut [RawNeedle<'_>; MAX_INLINE_NEEDLES],
    count: &mut usize,
) -> Result<(), CaptureRequiredLiteralBuildError> {
    match class {
        Class::Unicode(class) => {
            for range in class.ranges() {
                meter.charge(1)?;
                let start = u32::from(range.start());
                let end = u32::from(range.end());
                if end > 0x7F {
                    return Err(CaptureRequiredLiteralBuildError::InternalInvariant(
                        "proved ASCII class contains a non-ASCII scalar",
                    ));
                }
                let width = inclusive_class_width(u64::from(start), u64::from(end))?;
                meter.charge(width)?;
                for value in start..=end {
                    push_raw_byte(
                        output,
                        count,
                        u8::try_from(value).map_err(|_| {
                            CaptureRequiredLiteralBuildError::InternalInvariant(
                                "proved ASCII scalar does not fit one byte",
                            )
                        })?,
                    )?;
                }
            }
        }
        Class::Bytes(class) => {
            for range in class.ranges() {
                meter.charge(1)?;
                let width =
                    inclusive_class_width(u64::from(range.start()), u64::from(range.end()))?;
                meter.charge(width)?;
                for byte in range.start()..=range.end() {
                    push_raw_byte(output, count, byte)?;
                }
            }
        }
    }
    Ok(())
}

fn inclusive_class_width(start: u64, end: u64) -> Result<usize, CaptureRequiredLiteralBuildError> {
    let width = end
        .checked_sub(start)
        .and_then(|width| width.checked_add(1))
        .ok_or(CaptureRequiredLiteralBuildError::Overflow(
            "inclusive class width",
        ))?;
    usize::try_from(width)
        .map_err(|_| CaptureRequiredLiteralBuildError::Overflow("inclusive class width"))
}

fn push_raw_byte(
    output: &mut [RawNeedle<'_>; MAX_INLINE_NEEDLES],
    count: &mut usize,
    byte: u8,
) -> Result<(), CaptureRequiredLiteralBuildError> {
    if *count >= MAX_INLINE_NEEDLES {
        return Err(CaptureRequiredLiteralBuildError::InternalInvariant(
            "measured raw needles exceed inline storage",
        ));
    }
    output[*count] = RawNeedle::Byte([byte]);
    *count = count
        .checked_add(1)
        .ok_or(CaptureRequiredLiteralBuildError::Overflow(
            "raw needle reference count",
        ))?;
    Ok(())
}

fn collect_refs<'hir>(
    hir: &'hir Hir,
    depth: usize,
    meter: &mut Meter,
    output: &mut [RawNeedle<'hir>; MAX_INLINE_NEEDLES],
    count: &mut usize,
) -> Result<(), CaptureRequiredLiteralBuildError> {
    meter.enter(depth)?;
    match hir.kind() {
        HirKind::Literal(literal) if !literal.0.is_empty() => {
            meter.charge(literal.0.len().checked_add(1).ok_or(
                CaptureRequiredLiteralBuildError::Overflow("needle publication work"),
            )?)?;
            if *count >= MAX_INLINE_NEEDLES {
                return Err(CaptureRequiredLiteralBuildError::InternalInvariant(
                    "measured raw needles exceed inline reference storage",
                ));
            }
            output[*count] = RawNeedle::Literal(literal.0.as_ref());
            *count = count
                .checked_add(1)
                .ok_or(CaptureRequiredLiteralBuildError::Overflow(
                    "raw needle reference count",
                ))?;
            Ok(())
        }
        HirKind::Class(class) => collect_ascii_class(class, meter, output, count),
        HirKind::Capture(capture) => {
            collect_refs(&capture.sub, next_depth(depth)?, meter, output, count)
        }
        HirKind::Repetition(repetition) if repetition.min > 0 => {
            collect_refs(&repetition.sub, next_depth(depth)?, meter, output, count)
        }
        HirKind::Concat(children) => {
            let mut best = None;
            for child in children {
                if let Some(metrics) = measure(child, next_depth(depth)?, meter)?
                    && best.is_none_or(|(_, current)| prefer_required_literal(metrics, current))
                {
                    best = Some((child, metrics));
                }
            }
            collect_refs(
                best.map(|(child, _)| child).ok_or(
                    CaptureRequiredLiteralBuildError::InternalInvariant(
                        "proved concat lost its required literal",
                    ),
                )?,
                next_depth(depth)?,
                meter,
                output,
                count,
            )
        }
        HirKind::Alternation(children) => {
            for child in children {
                collect_refs(child, next_depth(depth)?, meter, output, count)?;
            }
            Ok(())
        }
        _ => Err(CaptureRequiredLiteralBuildError::InternalInvariant(
            "proved node lost its required literal",
        )),
    }
}

/// Collect the conservative required-literal alternatives from independently
/// parsed roots. This is the collection counterpart of
/// [`measure_hir_alternation`].
fn collect_hir_alternation<'hir>(
    hirs: &'hir [Hir],
    meter: &mut Meter,
    output: &mut [RawNeedle<'hir>; MAX_INLINE_NEEDLES],
    count: &mut usize,
) -> Result<(), CaptureRequiredLiteralBuildError> {
    for hir in hirs {
        collect_refs(hir, 1, meter, output, count)?;
    }
    Ok(())
}

fn effective_antichain(
    raw: &[RawNeedle<'_>],
    meter: &mut Meter,
) -> Result<([bool; MAX_INLINE_NEEDLES], Metrics), CaptureRequiredLiteralBuildError> {
    let mut retained = [true; MAX_INLINE_NEEDLES];
    for left in 0..raw.len() {
        let right_start = left
            .checked_add(1)
            .ok_or(CaptureRequiredLiteralBuildError::Overflow(
                "antichain pair index",
            ))?;
        for right in right_start..raw.len() {
            // One pair visit and both length inspections are admitted before
            // choosing the only comparison that can remove a redundant item.
            meter.charge(3)?;
            let left_bytes = raw[left].bytes();
            let right_bytes = raw[right].bytes();
            match left_bytes.len().cmp(&right_bytes.len()) {
                core::cmp::Ordering::Equal => {
                    if equal_metered(left_bytes, right_bytes, meter)? {
                        remove_metered(&mut retained, right, meter)?;
                    }
                }
                core::cmp::Ordering::Less => {
                    if contains_metered(right_bytes, left_bytes, meter)? {
                        remove_metered(&mut retained, right, meter)?;
                    }
                }
                core::cmp::Ordering::Greater => {
                    if contains_metered(left_bytes, right_bytes, meter)? {
                        remove_metered(&mut retained, left, meter)?;
                    }
                }
            }
        }
    }

    let mut needles = 0_usize;
    let mut bytes = 0_usize;
    let mut minimum_bytes = usize::MAX;
    for (index, needle) in raw.iter().enumerate() {
        meter.charge(1)?;
        if !retained[index] {
            continue;
        }
        meter.charge(1)?;
        needles = needles
            .checked_add(1)
            .ok_or(CaptureRequiredLiteralBuildError::Overflow(
                "effective needle count",
            ))?;
        bytes = bytes.checked_add(needle.bytes().len()).ok_or(
            CaptureRequiredLiteralBuildError::Overflow("effective needle bytes"),
        )?;
        minimum_bytes = minimum_bytes.min(needle.bytes().len());
    }
    if needles == 0 {
        return Err(CaptureRequiredLiteralBuildError::InternalInvariant(
            "nonempty raw set reduced to an empty antichain",
        ));
    }
    Ok((
        retained,
        Metrics {
            needles,
            bytes,
            minimum_bytes,
        },
    ))
}

fn equal_metered(
    left: &[u8],
    right: &[u8],
    meter: &mut Meter,
) -> Result<bool, CaptureRequiredLiteralBuildError> {
    for (&left_byte, &right_byte) in left.iter().zip(right) {
        meter.charge(1)?;
        if left_byte != right_byte {
            return Ok(false);
        }
    }
    Ok(true)
}

fn contains_metered(
    longer: &[u8],
    shorter: &[u8],
    meter: &mut Meter,
) -> Result<bool, CaptureRequiredLiteralBuildError> {
    let final_start = longer.len().checked_sub(shorter.len()).ok_or(
        CaptureRequiredLiteralBuildError::InternalInvariant(
            "containment comparison received a longer needle that is shorter",
        ),
    )?;
    for start in 0..=final_start {
        meter.charge(1)?;
        let mut equal = true;
        for (offset, &needle_byte) in shorter.iter().enumerate() {
            meter.charge(1)?;
            let longer_index =
                start
                    .checked_add(offset)
                    .ok_or(CaptureRequiredLiteralBuildError::Overflow(
                        "containment byte index",
                    ))?;
            if longer[longer_index] != needle_byte {
                equal = false;
                break;
            }
        }
        if equal {
            return Ok(true);
        }
    }
    Ok(false)
}

fn remove_metered(
    retained: &mut [bool; MAX_INLINE_NEEDLES],
    index: usize,
    meter: &mut Meter,
) -> Result<(), CaptureRequiredLiteralBuildError> {
    if retained[index] {
        meter.charge(1)?;
        retained[index] = false;
    }
    Ok(())
}

fn check_metric_limits(
    metrics: Metrics,
    limits: CaptureRequiredLiteralBuildLimits,
) -> Result<(), CaptureRequiredLiteralBuildError> {
    check_limit("needle count", metrics.needles, limits.max_needles)?;
    check_limit("needle bytes", metrics.bytes, limits.max_needle_bytes)
}

fn arc_block_bytes<T>() -> Result<usize, CaptureRequiredLiteralBuildError> {
    Layout::new::<[usize; 2]>()
        .extend(Layout::new::<T>())
        .map(|(layout, _)| layout.pad_to_align().size())
        .map_err(|_| CaptureRequiredLiteralBuildError::Overflow("Arc block bytes"))
}

const fn map_exact_allocation(
    error: CopyError,
    structure: &'static str,
    items: usize,
) -> CaptureRequiredLiteralBuildError {
    match error {
        CopyError::LayoutOverflow => {
            CaptureRequiredLiteralBuildError::Overflow("exact allocation layout")
        }
        CopyError::AllocationFailed => {
            CaptureRequiredLiteralBuildError::Allocation { structure, items }
        }
    }
}

fn check_limit(
    resource: &'static str,
    required: usize,
    limit: usize,
) -> Result<(), CaptureRequiredLiteralBuildError> {
    if required > limit {
        return Err(CaptureRequiredLiteralBuildError::Resource {
            resource,
            required,
            limit,
        });
    }
    Ok(())
}

fn next_depth(depth: usize) -> Result<usize, CaptureRequiredLiteralBuildError> {
    depth
        .checked_add(1)
        .ok_or(CaptureRequiredLiteralBuildError::Overflow("HIR depth"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fre_syntax::{CanonicalPattern, CompatibilityProfile, ParseRequest, RustProfile};
    use regex::bytes::RegexBuilder;

    const AWS: &str = r#"(('|")((?:ASIA|AKIA|AROA|AIDA)([A-Z0-7]{16}))('|").*?(\n^.*?){0,4}(('|")[a-zA-Z0-9+/]{40}('|"))+|('|")[a-zA-Z0-9+/]{40}('|").*?(\n^.*?){0,3}('|")((?:ASIA|AKIA|AROA|AIDA)([A-Z0-7]{16}))('|"))+"#;

    fn raw64_effective2_pattern() -> String {
        (0..MAX_INLINE_NEEDLES)
            .map(|index| {
                if index < MAX_INLINE_NEEDLES / 2 {
                    "(AB)"
                } else {
                    "(CD)"
                }
            })
            .collect::<Vec<_>>()
            .join("|")
    }

    fn build_detailed(
        pattern: &str,
        limits: CaptureRequiredLiteralBuildLimits,
    ) -> Result<CaptureRequiredLiteralBuildOutcome, CaptureRequiredLiteralBuildFailure> {
        build_detailed_with_unicode(pattern, false, limits)
    }

    fn build_detailed_with_unicode(
        pattern: &str,
        unicode: bool,
        limits: CaptureRequiredLiteralBuildLimits,
    ) -> Result<CaptureRequiredLiteralBuildOutcome, CaptureRequiredLiteralBuildFailure> {
        let mut profile = RustProfile::rebar_1_12_4();
        profile.options.unicode = unicode;
        let parsed = fre_syntax::parse(ParseRequest::rust(
            pattern,
            CompatibilityProfile::RustBytes(profile),
        ))
        .unwrap();
        let key = Arc::new(parsed.key);
        let CanonicalPattern::Rust(rust) = parsed.pattern else {
            panic!("Rust parser returned a non-Rust pattern")
        };
        build_from_hir(&rust.hir, key, limits)
    }

    fn parsed_hir(pattern: &str) -> (CacheKey, Hir) {
        let parsed = fre_syntax::parse(ParseRequest::rust(
            pattern,
            CompatibilityProfile::RustBytes(RustProfile::rebar_1_12_4()),
        ))
        .unwrap();
        let fre_syntax::ParseRecord { key, pattern, .. } = parsed;
        let CanonicalPattern::Rust(rust) = pattern else {
            panic!("Rust parser returned a non-Rust pattern");
        };
        (key, rust.hir)
    }

    fn build(
        pattern: &str,
        limits: CaptureRequiredLiteralBuildLimits,
    ) -> Result<CaptureRequiredLiteralBuildOutcome, CaptureRequiredLiteralBuildError> {
        build_detailed(pattern, limits).map_err(|failure| failure.source)
    }

    fn owned_needles(plan: &CaptureRequiredLiteralPlan) -> Vec<Vec<u8>> {
        plan.build_report()
            .identity
            .needles
            .iter()
            .map(<[u8]>::to_vec)
            .collect()
    }

    fn visit_short_haystacks(
        alphabet: &[u8],
        remaining: usize,
        haystack: &mut Vec<u8>,
        visitor: &mut impl FnMut(&[u8]),
    ) {
        visitor(haystack);
        if remaining == 0 {
            return;
        }
        let next_remaining = remaining
            .checked_sub(1)
            .expect("positive short-haystack depth");
        for &byte in alphabet {
            haystack.push(byte);
            visit_short_haystacks(alphabet, next_remaining, haystack, visitor);
            haystack.pop();
        }
    }

    fn assert_required_literal_never_rejects_match(pattern: &str, alphabet: &[u8], max_len: usize) {
        let plan = build(pattern, CaptureRequiredLiteralBuildLimits::default())
            .unwrap()
            .plan
            .expect("fixture must publish a required-literal plan");
        let reference = RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .expect("pinned byte-regex reference");
        visit_short_haystacks(alphabet, max_len, &mut Vec::new(), &mut |haystack| {
            if reference.is_match(haystack) {
                assert!(
                    plan.is_candidate(haystack, CaptureRequiredLiteralRunLimits::default(),)
                        .unwrap()
                        .candidate,
                    "required-literal plan rejected a reference match for \
                         {pattern:?} on {haystack:?}",
                );
            }
        });
    }

    #[test]
    fn generic_lattice_selects_required_literals_and_preserves_order() {
        let plan = build(
            "(?:(AB|CD)x|(?:EF|GH)y)+",
            CaptureRequiredLiteralBuildLimits::default(),
        )
        .unwrap()
        .plan
        .unwrap();
        assert_eq!(
            owned_needles(&plan),
            vec![
                b"AB".to_vec(),
                b"CD".to_vec(),
                b"EF".to_vec(),
                b"GH".to_vec(),
            ]
        );
        assert!(
            build("(?:AB|)", CaptureRequiredLiteralBuildLimits::default())
                .unwrap()
                .plan
                .is_none()
        );
        assert!(
            build("(?:AB)?", CaptureRequiredLiteralBuildLimits::default())
                .unwrap()
                .plan
                .is_none()
        );
    }

    #[test]
    fn logical_hir_alternation_preserves_nested_union_candidate_soundness() {
        let (identity, first) = parsed_hir("(?:AB|CD)");
        let (_, second) = parsed_hir("(?:EF|GH)");
        let hirs = [first, second];
        let plan = build_from_hirs(
            &hirs,
            Arc::new(identity),
            CaptureRequiredLiteralBuildLimits::default(),
        )
        .unwrap_or_else(|failure| panic!("logical union build failed: {}", failure.source))
        .plan
        .expect("each logical union branch has a bounded required literal");
        assert_eq!(
            owned_needles(&plan),
            vec![
                b"AB".to_vec(),
                b"CD".to_vec(),
                b"EF".to_vec(),
                b"GH".to_vec(),
            ]
        );
        for (haystack, candidate) in [
            (b"AB".as_slice(), true),
            (b"CD".as_slice(), true),
            (b"EF".as_slice(), true),
            (b"GH".as_slice(), true),
            (b"ZZ".as_slice(), false),
        ] {
            assert_eq!(
                plan.is_candidate(haystack, CaptureRequiredLiteralRunLimits::default())
                    .unwrap()
                    .candidate,
                candidate,
            );
        }
    }

    #[test]
    fn candidate_cache_identity_authenticates_the_exact_candidate_operation() {
        let plan = build("(?:AB|CD)+", CaptureRequiredLiteralBuildLimits::default())
            .unwrap()
            .plan
            .expect("mandatory literals");
        let limits = CaptureRequiredLiteralRunLimits {
            max_transitions: 97,
        };
        let identity = plan.candidate_cache_identity(limits);

        assert_eq!(identity.plan, plan.build_report().identity);
        assert_eq!(
            identity.operation,
            CaptureRequiredLiteralSearchOperation::CandidateV1
        );
        assert_eq!(identity.run_limits, limits);
        assert_eq!(plan.is_candidate(b"AB", limits).unwrap().identity, identity);
        assert_ne!(
            identity,
            plan.candidate_cache_identity(CaptureRequiredLiteralRunLimits {
                max_transitions: limits.max_transitions - 1,
            })
        );
    }

    #[test]
    fn small_mandatory_ascii_classes_form_exact_one_byte_alternatives() {
        let plan = build(
            r"(?:[0-9]x?|[A-F]y?)+",
            CaptureRequiredLiteralBuildLimits::default(),
        )
        .unwrap()
        .plan
        .expect("mandatory small ASCII classes");
        let expected = (b'0'..=b'9')
            .chain(b'A'..=b'F')
            .map(|byte| vec![byte])
            .collect::<Vec<_>>();
        assert_eq!(owned_needles(&plan), expected);
        assert_eq!(plan.build_report().accounting.minimum_needle_bytes, 1);

        for (haystack, candidate) in [
            (b"none".as_slice(), false),
            (b"value=5".as_slice(), true),
            (b"value=B".as_slice(), true),
        ] {
            assert_eq!(
                plan.is_candidate(haystack, CaptureRequiredLiteralRunLimits::default())
                    .unwrap()
                    .candidate,
                candidate
            );
        }

        let baseline = plan
            .is_candidate(b"none", CaptureRequiredLiteralRunLimits::default())
            .unwrap();
        let exact = baseline.accounting.transitions_upper_bound;
        assert_eq!(
            plan.is_candidate(
                b"none",
                CaptureRequiredLiteralRunLimits {
                    max_transitions: exact,
                },
            )
            .unwrap()
            .accounting,
            baseline.accounting
        );
        assert!(matches!(
            plan.is_candidate(
                b"none",
                CaptureRequiredLiteralRunLimits {
                    max_transitions: exact - 1,
                },
            ),
            Err(CaptureRequiredLiteralSearchError {
                source: LiteralSetError::TransitionLimit { needed, limit },
                ..
            }) if needed == exact && limit == exact - 1
        ));
    }

    #[test]
    fn concat_prefers_multi_byte_proofs_and_skips_ineligible_classes() {
        let fallback = build(
            r"[\x00-\xFF](?:AB|CD)",
            CaptureRequiredLiteralBuildLimits::default(),
        )
        .unwrap()
        .plan
        .expect("oversized class must not hide a later bounded proof");
        assert_eq!(
            owned_needles(&fallback),
            vec![b"AB".to_vec(), b"CD".to_vec()]
        );

        let preferred = build(
            r"[0-9](?:AB|CD)",
            CaptureRequiredLiteralBuildLimits::default(),
        )
        .unwrap()
        .plan
        .expect("a later multi-byte proof must outrank a small class");
        assert_eq!(
            owned_needles(&preferred),
            vec![b"AB".to_vec(), b"CD".to_vec()]
        );

        let unicode_fallback = build_detailed_with_unicode(
            r"[0-9\u{80}](?:AB|CD)",
            true,
            CaptureRequiredLiteralBuildLimits::default(),
        )
        .unwrap_or_else(|failure| panic!("Unicode fallback build failed: {}", failure.source))
        .plan
        .expect("multi-byte Unicode class must not become a raw-byte proof");
        assert_eq!(
            owned_needles(&unicode_fallback),
            vec![b"AB".to_vec(), b"CD".to_vec()]
        );
    }

    #[test]
    fn concat_ranking_is_selective_deterministic_and_source_independent() {
        let longest = build(
            r"(?:AB|CD)XYZ",
            CaptureRequiredLiteralBuildLimits::default(),
        )
        .unwrap()
        .plan
        .expect("longer required literal");
        assert_eq!(owned_needles(&longest), vec![b"XYZ".to_vec()]);

        let narrower = build(r"(?:AB|CD)XY", CaptureRequiredLiteralBuildLimits::default())
            .unwrap()
            .plan
            .expect("equal-width narrower required literal");
        assert_eq!(owned_needles(&narrower), vec![b"XY".to_vec()]);

        assert!(prefer_required_literal(
            Metrics {
                needles: 2,
                bytes: 5,
                minimum_bytes: 2,
            },
            Metrics {
                needles: 2,
                bytes: 4,
                minimum_bytes: 2,
            },
        ));
        assert!(!prefer_required_literal(
            Metrics {
                needles: 2,
                bytes: 4,
                minimum_bytes: 2,
            },
            Metrics {
                needles: 2,
                bytes: 5,
                minimum_bytes: 2,
            },
        ));

        let uri = build(
            r"[A-Za-z][A-Za-z0-9+.-]*://[^\r\n]*",
            CaptureRequiredLiteralBuildLimits::default(),
        )
        .unwrap()
        .plan
        .expect("URI delimiter is mandatory");
        assert_eq!(owned_needles(&uri), vec![b"://".to_vec()]);

        let date = build(
            r"[0-9]{4}/[0-9]{2}/[0-9]{2}",
            CaptureRequiredLiteralBuildLimits::default(),
        )
        .unwrap()
        .plan
        .expect("date delimiter is mandatory");
        assert_eq!(owned_needles(&date), vec![b"/".to_vec()]);
    }

    #[test]
    fn unicode_ascii_and_raw_byte_classes_are_malformed_safe() {
        let unicode_ascii = build_detailed_with_unicode(
            r"[A-B]",
            true,
            CaptureRequiredLiteralBuildLimits::default(),
        )
        .unwrap_or_else(|failure| panic!("Unicode ASCII class build failed: {}", failure.source))
        .plan
        .expect("two-scalar Unicode ASCII class");
        assert!(
            !unicode_ascii
                .is_candidate(b"\xFF", CaptureRequiredLiteralRunLimits::default())
                .unwrap()
                .candidate
        );
        assert!(
            unicode_ascii
                .is_candidate(b"\xFFA", CaptureRequiredLiteralRunLimits::default())
                .unwrap()
                .candidate
        );

        let byte_class = build(r"[\x80-\x81]", CaptureRequiredLiteralBuildLimits::default())
            .unwrap()
            .plan
            .expect("two-byte raw class");
        assert_eq!(owned_needles(&byte_class), vec![vec![0x80], vec![0x81]]);
        assert!(
            byte_class
                .is_candidate(b"\xFF\x80", CaptureRequiredLiteralRunLimits::default())
                .unwrap()
                .candidate
        );
    }

    #[test]
    fn ascii_class_capacity_and_planner_work_are_exactly_bounded() {
        let at_capacity = build(r"[\x00-\x3F]", CaptureRequiredLiteralBuildLimits::default())
            .unwrap()
            .plan
            .expect("64-byte class is within inline capacity");
        let accounting = at_capacity.build_report().accounting;
        assert_eq!(accounting.raw_needles, MAX_INLINE_NEEDLES);
        assert_eq!(accounting.needles, MAX_INLINE_NEEDLES);
        assert_eq!(accounting.raw_needle_bytes, MAX_INLINE_NEEDLES);
        assert_eq!(accounting.needle_bytes, MAX_INLINE_NEEDLES);

        let exact = CaptureRequiredLiteralBuildLimits {
            max_planner_work: accounting.planner_work,
            ..CaptureRequiredLiteralBuildLimits::default()
        };
        assert_eq!(
            build(r"[\x00-\x3F]", exact)
                .expect("exact class planner-work limit")
                .plan
                .expect("exact limit retains class plan")
                .build_report()
                .accounting
                .planner_work,
            accounting.planner_work
        );

        let mut one_below = exact;
        one_below.max_planner_work -= 1;
        exact_allocation_probe::reset();
        let refusal = build_detailed(r"[\x00-\x3F]", one_below)
            .err()
            .expect("one-below class planner work must refuse");
        assert!(matches!(
            refusal.source,
            CaptureRequiredLiteralBuildError::Resource {
                resource: "planner work",
                required,
                limit,
            } if required == accounting.planner_work && limit == accounting.planner_work - 1
        ));
        assert_eq!(exact_allocation_probe::calls(), 0);

        assert!(
            build(r"[\x00-\x40]", CaptureRequiredLiteralBuildLimits::default())
                .unwrap()
                .plan
                .is_none(),
            "65-byte class exceeds inline capacity without partially enabling a plan"
        );
    }

    #[test]
    fn effective_antichain_retains_singletons_and_preserves_first_order() {
        for redundant in ["(?:(AB)|(AB))", "(?:(AB)|(XAB))", "(?:(XAB)|(AB))"] {
            let plan = build(redundant, CaptureRequiredLiteralBuildLimits::default())
                .unwrap()
                .plan
                .unwrap_or_else(|| panic!("{redundant} must retain its effective singleton"));
            assert_eq!(owned_needles(&plan), vec![b"AB".to_vec()], "{redundant}");
            assert_eq!(plan.build_report().accounting.raw_needles, 2);
            assert_eq!(plan.build_report().accounting.needles, 1);
        }

        let plan = build(
            "(?:(AB)|(CD))",
            CaptureRequiredLiteralBuildLimits::default(),
        )
        .unwrap()
        .plan
        .unwrap();
        let accounting = plan.build_report().accounting;
        assert_eq!(accounting.raw_needles, 2);
        assert_eq!(accounting.needles, 2);
        assert_eq!(accounting.minimum_needle_bytes, 2);
        assert_eq!(owned_needles(&plan), vec![b"AB".to_vec(), b"CD".to_vec()]);
    }

    #[test]
    fn singleton_plan_has_exact_limits_and_line_partition_accounting() {
        let baseline = build("needle", CaptureRequiredLiteralBuildLimits::default())
            .unwrap()
            .plan
            .expect("one mandatory literal is a complete candidate proof");
        let accounting = baseline.build_report().accounting;
        assert_eq!(accounting.raw_needles, 1);
        assert_eq!(accounting.needles, 1);
        assert_eq!(accounting.raw_needle_bytes, 6);
        assert_eq!(accounting.needle_bytes, 6);
        assert_eq!(accounting.minimum_needle_bytes, 6);
        assert!(accounting.line_partition_safe);
        assert_eq!(owned_needles(&baseline), vec![b"needle".to_vec()]);

        for (resource, exact) in [
            ("planner work", accounting.planner_work),
            ("needle count", accounting.needles),
            ("needle bytes", accounting.needle_bytes),
            ("source bytes", accounting.source_bytes),
            ("scratch bytes", accounting.scratch_bytes),
            ("peak bytes", accounting.peak_bytes_upper_bound),
        ] {
            let mut admitted = CaptureRequiredLiteralBuildLimits::default();
            match resource {
                "planner work" => admitted.max_planner_work = exact,
                "needle count" => admitted.max_needles = exact,
                "needle bytes" => admitted.max_needle_bytes = exact,
                "source bytes" => admitted.max_source_bytes = exact,
                "scratch bytes" => admitted.max_scratch_bytes = exact,
                "peak bytes" => admitted.max_peak_bytes = exact,
                _ => unreachable!(),
            }
            exact_allocation_probe::reset();
            assert!(
                build("needle", admitted)
                    .expect("exact singleton resource admission")
                    .plan
                    .is_some()
            );
            assert_eq!(exact_allocation_probe::calls(), 2);

            let mut refused = admitted;
            match resource {
                "planner work" => refused.max_planner_work = exact - 1,
                "needle count" => refused.max_needles = exact - 1,
                "needle bytes" => refused.max_needle_bytes = exact - 1,
                "source bytes" => refused.max_source_bytes = exact - 1,
                "scratch bytes" => refused.max_scratch_bytes = exact - 1,
                "peak bytes" => refused.max_peak_bytes = exact - 1,
                _ => unreachable!(),
            }
            exact_allocation_probe::reset();
            assert!(matches!(
                build("needle", refused),
                Err(CaptureRequiredLiteralBuildError::Resource {
                    resource: actual,
                    ..
                }) if actual == resource
            ));
            assert_eq!(
                exact_allocation_probe::calls(),
                0,
                "{resource} singleton refusal occurred after exact allocation",
            );
        }

        let haystack = b"miss\nneedle here\r\nneed\nneedle";
        let prospective = baseline
            .line_partition_prospective(haystack.len())
            .unwrap()
            .expect("delimiter-free singleton");
        let exact_run = CaptureRequiredLiteralRunLimits {
            max_transitions: prospective.transitions_upper_bound,
        };
        let matches = baseline
            .line_partition_matches(haystack, exact_run)
            .unwrap()
            .expect("singleton line partition")
            .collect::<Vec<_>>();
        assert_eq!(matches, [(5, 11), (23, 29)]);
        assert!(matches!(
            baseline.line_partition_matches(
                haystack,
                CaptureRequiredLiteralRunLimits {
                    max_transitions: prospective.transitions_upper_bound - 1,
                },
            ),
            Err(CaptureRequiredLiteralSearchError {
                source: LiteralSetError::TransitionLimit { needed, limit },
                ..
            }) if needed == prospective.transitions_upper_bound
                && limit == prospective.transitions_upper_bound - 1
        ));
    }

    #[test]
    fn singleton_and_ranked_candidates_differentially_cover_reference_matches() {
        assert_required_literal_never_rejects_match("AB", b"ABX", 3);
        assert_required_literal_never_rejects_match("(?:AB|XAB)", b"ABX", 3);
        assert_required_literal_never_rejects_match(r"[0-9]+/[0-9]+", b"09/", 4);
        assert_required_literal_never_rejects_match(r"(?:AB|CD)XYZ", b"ABCDXYZ", 5);
    }

    #[test]
    fn raw_publication_visits_are_precharged_and_survive_post_loop_failure() {
        let pattern = raw64_effective2_pattern();
        let baseline = build(&pattern, CaptureRequiredLiteralBuildLimits::default())
            .expect("raw-64 baseline")
            .plan
            .expect("effective AB/CD plan");
        let accounting = baseline.build_report().accounting;
        assert_eq!(accounting.raw_needles, 64);
        assert_eq!(accounting.needles, 2);
        assert_eq!(accounting.planner_work, 9_837);
        assert_eq!(
            owned_needles(&baseline),
            vec![b"AB".to_vec(), b"CD".to_vec()]
        );

        let exact = CaptureRequiredLiteralBuildLimits {
            max_planner_work: accounting.planner_work,
            ..CaptureRequiredLiteralBuildLimits::default()
        };
        exact_allocation_probe::reset();
        let admitted = build(&pattern, exact)
            .expect("exact raw publication work")
            .plan
            .expect("exact limit retains plan");
        assert_eq!(
            admitted.build_report().accounting.planner_work,
            accounting.planner_work
        );
        assert_eq!(exact_allocation_probe::calls(), 2);

        let mut one_below = exact;
        one_below.max_planner_work -= 1;
        exact_allocation_probe::reset();
        let refusal = build_detailed(&pattern, one_below)
            .err()
            .expect("one-below publication work must refuse");
        assert!(matches!(
            refusal.source,
            CaptureRequiredLiteralBuildError::Resource {
                resource: "planner work",
                required: 9_837,
                limit: 9_836,
            }
        ));
        assert_eq!(
            exact_allocation_probe::calls(),
            0,
            "raw publication work was not refused before allocation"
        );

        let mut post_loop_failure = CaptureRequiredLiteralBuildLimits::default();
        post_loop_failure.literal_set.max_build_work =
            accounting.literal_set.build_work_upper_bound - 1;
        exact_allocation_probe::reset();
        let failure = build_detailed(&pattern, post_loop_failure)
            .err()
            .expect("post-loop literal-set refusal");
        assert!(matches!(
            failure.source,
            CaptureRequiredLiteralBuildError::LiteralSet(LiteralSetError::BuildWorkLimit { .. })
        ));
        assert_eq!(
            failure.planner_work, accounting.planner_work,
            "post-loop failure lost cumulative raw publication work"
        );
        assert_eq!(
            exact_allocation_probe::calls(),
            2,
            "fixture must fail after both exact publication allocations"
        );
    }

    #[test]
    fn aws_hir_proves_the_access_prefix_set_and_byte_search_is_malformed_safe() {
        let plan = build(AWS, CaptureRequiredLiteralBuildLimits::default())
            .unwrap()
            .plan
            .unwrap();
        assert_eq!(plan.build_report().accounting.raw_needles, 8);
        assert_eq!(plan.build_report().accounting.raw_needle_bytes, 32);
        assert_eq!(plan.build_report().accounting.needles, 4);
        assert_eq!(plan.build_report().accounting.needle_bytes, 16);
        assert_eq!(
            owned_needles(&plan),
            vec![
                b"ASIA".to_vec(),
                b"AKIA".to_vec(),
                b"AROA".to_vec(),
                b"AIDA".to_vec(),
            ]
        );
        assert_eq!(
            plan.build_report().identity.needles.arena.capacity(),
            plan.build_report().identity.needles.byte_len(),
            "the retained arena must have exact capacity"
        );
        let hit = plan
            .is_candidate(
                b"\xFF EASTASIAN",
                CaptureRequiredLiteralRunLimits::default(),
            )
            .unwrap();
        assert!(hit.candidate);
        assert_eq!(hit.accounting.transitions_upper_bound, 12);
        assert!(
            !plan
                .is_candidate(b"\xFF no key", CaptureRequiredLiteralRunLimits::default(),)
                .unwrap()
                .candidate
        );
    }

    #[test]
    fn line_partition_stream_is_single_scan_and_delimiter_literals_fall_back() {
        let safe = build(
            "(?:(AB)|(XY))",
            CaptureRequiredLiteralBuildLimits::default(),
        )
        .unwrap()
        .plan
        .unwrap();
        let haystack = b"ABAB\nA\nB\r\nXY\xFF";
        assert!(safe.build_report().accounting.line_partition_safe);
        let prospective = safe
            .line_partition_prospective(haystack.len())
            .unwrap()
            .expect("construction-proved line partition");
        let limits = CaptureRequiredLiteralRunLimits {
            max_transitions: prospective.transitions_upper_bound,
        };
        let scan = safe
            .line_partition_matches(haystack, limits)
            .unwrap()
            .expect("CR/LF-free effective literals permit one scan");
        assert_eq!(scan.identity().plan, safe.build_report().identity);
        assert_eq!(
            scan.identity().operation,
            CaptureRequiredLiteralSearchOperation::LinePartitionMatchesV1
        );
        assert_eq!(
            scan.identity().build_limits,
            CaptureRequiredLiteralBuildLimits::default()
        );
        assert_eq!(scan.identity().run_limits, limits);
        assert_eq!(scan.accounting().searched_bytes, haystack.len());
        assert_eq!(
            scan.accounting().match_events_upper_bound,
            haystack.len() / 2
        );
        assert_eq!(
            scan.accounting().transitions_upper_bound,
            prospective.transitions_upper_bound
        );
        assert_eq!(scan.collect::<Vec<_>>(), [(0, 2), (2, 4), (10, 12)]);
        assert!(matches!(
            safe.line_partition_matches(
                haystack,
                CaptureRequiredLiteralRunLimits {
                    max_transitions: prospective.transitions_upper_bound - 1,
                },
            ),
            Err(CaptureRequiredLiteralSearchError {
                source: LiteralSetError::TransitionLimit { needed, limit },
                ..
            }) if needed == prospective.transitions_upper_bound
                && limit == prospective.transitions_upper_bound - 1
        ));

        for pattern in [r"(?:(AB\r)|(BC))", r"(?:(AB\n)|(BC))"] {
            let plan = build(pattern, CaptureRequiredLiteralBuildLimits::default())
                .unwrap()
                .plan
                .unwrap();
            assert!(!plan.build_report().accounting.line_partition_safe);
            assert!(
                plan.line_partition_prospective(usize::MAX)
                    .unwrap()
                    .is_none()
            );
            assert!(
                plan.line_partition_matches(
                    b"ABC\r\nBC",
                    CaptureRequiredLiteralRunLimits::default(),
                )
                .unwrap()
                .is_none(),
                "delimiter-bearing literals require independent line searches: {pattern}"
            );
        }
    }

    #[test]
    fn planner_and_search_exact_limits_refuse_one_below() {
        let baseline = build("(?:AB|CD)", CaptureRequiredLiteralBuildLimits::default())
            .unwrap()
            .plan
            .unwrap();
        let accounting = baseline.build_report().accounting;
        for (resource, limit) in [
            ("planner work", accounting.planner_work - 1),
            ("needle count", accounting.needles - 1),
            ("needle bytes", accounting.needle_bytes - 1),
            ("HIR depth", accounting.hir_depth - 1),
            ("scratch bytes", accounting.scratch_bytes - 1),
        ] {
            let mut limits = CaptureRequiredLiteralBuildLimits::default();
            match resource {
                "planner work" => limits.max_planner_work = limit,
                "needle count" => limits.max_needles = limit,
                "needle bytes" => limits.max_needle_bytes = limit,
                "HIR depth" => limits.max_hir_depth = limit,
                "scratch bytes" => limits.max_scratch_bytes = limit,
                _ => unreachable!(),
            }
            assert!(matches!(
                build("(?:AB|CD)", limits),
                Err(CaptureRequiredLiteralBuildError::Resource {
                    resource: actual,
                    ..
                }) if actual == resource
            ));
        }

        for dimension in ["source", "peak", "persistent"] {
            let mut limits = CaptureRequiredLiteralBuildLimits::default();
            match dimension {
                "source" => limits.max_source_bytes = accounting.source_bytes - 1,
                "peak" => limits.max_peak_bytes = accounting.peak_bytes_upper_bound - 1,
                "persistent" => {
                    limits.literal_set.max_persistent_bytes =
                        accounting.literal_set.persistent_bytes - 1;
                }
                _ => unreachable!(),
            }
            assert!(build("(?:AB|CD)", limits).is_err());
        }

        assert!(
            baseline
                .is_candidate(
                    b"zzAB",
                    CaptureRequiredLiteralRunLimits { max_transitions: 5 },
                )
                .unwrap()
                .candidate
        );
        assert!(matches!(
            baseline.is_candidate(
                b"zzAB",
                CaptureRequiredLiteralRunLimits { max_transitions: 4 },
            ),
            Err(CaptureRequiredLiteralSearchError {
                source: LiteralSetError::TransitionLimit {
                    needed: 5,
                    limit: 4
                },
                ..
            })
        ));

        let ranked = build(
            r"(?:[0-9]x|[A-F]y)+",
            CaptureRequiredLiteralBuildLimits::default(),
        )
        .unwrap()
        .plan
        .expect("mandatory branch suffixes");
        assert_eq!(owned_needles(&ranked), vec![b"x".to_vec(), b"y".to_vec()]);
    }

    #[test]
    fn source_scratch_and_peak_refuse_before_any_exact_allocation() {
        let baseline = build("(?:AB|CD)", CaptureRequiredLiteralBuildLimits::default())
            .unwrap()
            .plan
            .unwrap();
        let accounting = baseline.build_report().accounting;

        for (resource, exact) in [
            ("source bytes", accounting.source_bytes),
            ("scratch bytes", accounting.scratch_bytes),
            ("peak bytes", accounting.peak_bytes_upper_bound),
        ] {
            let mut admitted = CaptureRequiredLiteralBuildLimits::default();
            match resource {
                "source bytes" => admitted.max_source_bytes = exact,
                "scratch bytes" => admitted.max_scratch_bytes = exact,
                "peak bytes" => admitted.max_peak_bytes = exact,
                _ => unreachable!(),
            }
            exact_allocation_probe::reset();
            let plan = build("(?:AB|CD)", admitted)
                .expect("exact resource admission")
                .plan
                .expect("exact resource retains plan");
            assert_eq!(
                plan.build_report().accounting.source_bytes,
                accounting.source_bytes
            );
            assert_eq!(exact_allocation_probe::calls(), 2);

            let mut refused = admitted;
            match resource {
                "source bytes" => refused.max_source_bytes = exact - 1,
                "scratch bytes" => refused.max_scratch_bytes = exact - 1,
                "peak bytes" => refused.max_peak_bytes = exact - 1,
                _ => unreachable!(),
            }
            exact_allocation_probe::reset();
            assert!(matches!(
                build("(?:AB|CD)", refused),
                Err(CaptureRequiredLiteralBuildError::Resource {
                    resource: actual,
                    ..
                }) if actual == resource
            ));
            assert_eq!(
                exact_allocation_probe::calls(),
                0,
                "{resource} refusal occurred after an exact allocation"
            );
        }
    }
}
