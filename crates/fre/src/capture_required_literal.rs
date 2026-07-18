//! Bounded required-literal prefilter for capture-preserving operations.

use core::{fmt, mem::size_of};
use std::{alloc::Layout, sync::Arc};

use fre_exact_alloc::{CopyError, ExactVec};
use fre_kernels::{
    LiteralSetAccounting, LiteralSetBuildAccounting, LiteralSetBuildLimits, LiteralSetError,
    LiteralSetPlan, LiteralSetSearchLimits,
};
use fre_syntax::CacheKey;
use regex_syntax::hir::{Hir, HirKind};

/// Versioned algorithm identity for the required-any-literal proof.
pub const CAPTURE_REQUIRED_LITERAL_PLAN_ID: &str = "fre.capture.required-any-literal-dfa.v2";

const MAX_INLINE_NEEDLES: usize = 64;
const NEEDLE_OFFSET_SLOTS: usize = MAX_INLINE_NEEDLES + 1;

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
        Some(&self.arena[self.offsets[index]..self.offsets[index + 1]])
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureRequiredLiteralCacheIdentity {
    pub plan: CaptureRequiredLiteralIdentity,
    pub build_limits: CaptureRequiredLiteralBuildLimits,
    pub run_limits: CaptureRequiredLiteralRunLimits,
}

/// Successful candidate decision and exact DFA accounting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureRequiredLiteralSearchReport {
    pub identity: CaptureRequiredLiteralCacheIdentity,
    pub candidate: bool,
    pub accounting: LiteralSetAccounting,
}

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

#[allow(
    clippy::too_many_lines,
    reason = "the bounded proof, allocation, publication, and DFA receipts remain one auditable transaction"
)]
pub(crate) fn build_from_hir(
    hir: &Hir,
    syntax: Arc<CacheKey>,
    limits: CaptureRequiredLiteralBuildLimits,
) -> Result<CaptureRequiredLiteralBuildOutcome, CaptureRequiredLiteralBuildError> {
    let mut meter = Meter::new(limits);
    let Some(raw_metrics) = measure(hir, 1, &mut meter)? else {
        return Ok(CaptureRequiredLiteralBuildOutcome {
            plan: None,
            planner_work: meter.work,
        });
    };
    if raw_metrics.needles > MAX_INLINE_NEEDLES {
        return Err(CaptureRequiredLiteralBuildError::Resource {
            resource: "raw needle references",
            required: raw_metrics.needles,
            limit: MAX_INLINE_NEEDLES,
        });
    }

    let canonical_scratch = size_of::<[&[u8]; MAX_INLINE_NEEDLES]>()
        .checked_add(size_of::<[bool; MAX_INLINE_NEEDLES]>())
        .ok_or(CaptureRequiredLiteralBuildError::Overflow(
            "canonical antichain scratch",
        ))?;
    check_limit("scratch bytes", canonical_scratch, limits.max_scratch_bytes)?;

    let mut raw_needles = [&[][..]; MAX_INLINE_NEEDLES];
    let mut raw_count = 0_usize;
    collect_refs(hir, 1, &mut meter, &mut raw_needles, &mut raw_count)?;
    if raw_count != raw_metrics.needles {
        return Err(CaptureRequiredLiteralBuildError::InternalInvariant(
            "collected raw needle count differs from proof",
        ));
    }
    let (retained, effective) = effective_antichain(&raw_needles[..raw_count], &mut meter)?;
    check_metric_limits(effective, limits)?;
    if effective.needles < 2 || effective.minimum_bytes < 2 {
        return Ok(CaptureRequiredLiteralBuildOutcome {
            plan: None,
            planner_work: meter.work,
        });
    }

    let reference_scratch = effective.needles.checked_mul(size_of::<&[u8]>()).ok_or(
        CaptureRequiredLiteralBuildError::Overflow("exact reference scratch"),
    )?;
    let scratch_bytes = canonical_scratch.max(reference_scratch);
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

    let mut dfa_limits = limits.literal_set;
    let matcher_arc_block = arc_block_bytes::<LiteralSetPlan>()?;
    let plan_value_bytes = size_of::<CaptureRequiredLiteralPlan>();
    let fixed_persistent = source_before_matcher
        .checked_add(matcher_arc_block)
        .and_then(|bytes| bytes.checked_add(plan_value_bytes))
        .ok_or(CaptureRequiredLiteralBuildError::Overflow(
            "fixed persistent bytes",
        ))?;
    let source_headroom = limits
        .max_source_bytes
        .checked_sub(fixed_persistent)
        .ok_or(CaptureRequiredLiteralBuildError::Resource {
            resource: "source bytes",
            required: fixed_persistent,
            limit: limits.max_source_bytes,
        })?;
    dfa_limits.max_persistent_bytes = dfa_limits.max_persistent_bytes.min(source_headroom);

    let live_before_dfa = fixed_persistent.checked_add(scratch_bytes).ok_or(
        CaptureRequiredLiteralBuildError::Overflow("live bytes before DFA"),
    )?;
    check_limit("peak bytes", live_before_dfa, limits.max_peak_bytes)?;
    dfa_limits.max_build_bytes =
        dfa_limits
            .max_build_bytes
            .min(limits.max_peak_bytes.checked_sub(live_before_dfa).ok_or(
                CaptureRequiredLiteralBuildError::Resource {
                    resource: "peak bytes",
                    required: live_before_dfa,
                    limit: limits.max_peak_bytes,
                },
            )?);
    // Admit every retained offset, byte copy, reference publication, and final
    // publication before either exact allocation or copy work begins.
    let publication_work = effective
        .needles
        .checked_mul(2)
        .and_then(|work| work.checked_add(effective.bytes))
        .and_then(|work| work.checked_add(3))
        .ok_or(CaptureRequiredLiteralBuildError::Overflow(
            "effective needle publication work",
        ))?;
    meter.charge(publication_work)?;

    let mut arena = ExactVec::try_with_capacity(effective.bytes)
        .map_err(|error| map_exact_allocation(error, "effective needle byte", effective.bytes))?;
    let mut offsets = [0_usize; NEEDLE_OFFSET_SLOTS];
    let mut effective_index = 0_usize;
    for (raw_index, needle) in raw_needles[..raw_count].iter().enumerate() {
        if !retained[raw_index] {
            continue;
        }
        offsets[effective_index] = arena.len();
        for &byte in *needle {
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
    let matcher = LiteralSetPlan::new(refs.as_slice(), dfa_limits)
        .map_err(CaptureRequiredLiteralBuildError::LiteralSet)?;
    let literal_set = matcher.build_accounting();

    let source_bytes = fixed_persistent
        .checked_add(literal_set.persistent_bytes)
        .ok_or(CaptureRequiredLiteralBuildError::Overflow(
            "published source bytes",
        ))?;
    check_limit("source bytes", source_bytes, limits.max_source_bytes)?;
    let peak_bytes_upper_bound = live_before_dfa
        .checked_add(literal_set.build_bytes_upper_bound)
        .ok_or(CaptureRequiredLiteralBuildError::Overflow(
            "peak build bytes",
        ))?;
    check_limit("peak bytes", peak_bytes_upper_bound, limits.max_peak_bytes)?;

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
            source_bytes,
            scratch_bytes,
            peak_bytes_upper_bound,
            literal_set,
        },
    };
    Ok(CaptureRequiredLiteralBuildOutcome {
        planner_work: meter.work,
        plan: Some(CaptureRequiredLiteralPlan {
            matcher: Arc::new(matcher),
            build_limits: limits,
            report,
        }),
    })
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

    #[allow(
        clippy::result_large_err,
        reason = "typed refusal retains complete cache identity without an unmetered error-path allocation"
    )]
    pub fn is_candidate(
        &self,
        haystack: &[u8],
        run_limits: CaptureRequiredLiteralRunLimits,
    ) -> Result<CaptureRequiredLiteralSearchReport, CaptureRequiredLiteralSearchError> {
        let identity = CaptureRequiredLiteralCacheIdentity {
            plan: self.report.identity.clone(),
            build_limits: self.build_limits,
            run_limits,
        };
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
}

#[derive(Clone, Copy)]
struct Metrics {
    needles: usize,
    bytes: usize,
    minimum_bytes: usize,
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
        HirKind::Capture(capture) => measure(&capture.sub, next_depth(depth)?, meter),
        HirKind::Repetition(repetition) if repetition.min > 0 => {
            measure(&repetition.sub, next_depth(depth)?, meter)
        }
        HirKind::Concat(children) => {
            for child in children {
                if let Some(metrics) = measure(child, next_depth(depth)?, meter)? {
                    return Ok(Some(metrics));
                }
            }
            Ok(None)
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

fn collect_refs<'hir>(
    hir: &'hir Hir,
    depth: usize,
    meter: &mut Meter,
    output: &mut [&'hir [u8]; MAX_INLINE_NEEDLES],
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
            output[*count] = literal.0.as_ref();
            *count = count
                .checked_add(1)
                .ok_or(CaptureRequiredLiteralBuildError::Overflow(
                    "raw needle reference count",
                ))?;
            Ok(())
        }
        HirKind::Capture(capture) => {
            collect_refs(&capture.sub, next_depth(depth)?, meter, output, count)
        }
        HirKind::Repetition(repetition) if repetition.min > 0 => {
            collect_refs(&repetition.sub, next_depth(depth)?, meter, output, count)
        }
        HirKind::Concat(children) => {
            for child in children {
                if measure(child, next_depth(depth)?, meter)?.is_some() {
                    return collect_refs(child, next_depth(depth)?, meter, output, count);
                }
            }
            Err(CaptureRequiredLiteralBuildError::InternalInvariant(
                "proved concat lost its required literal",
            ))
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

fn effective_antichain(
    raw: &[&[u8]],
    meter: &mut Meter,
) -> Result<([bool; MAX_INLINE_NEEDLES], Metrics), CaptureRequiredLiteralBuildError> {
    let mut retained = [true; MAX_INLINE_NEEDLES];
    for left in 0..raw.len() {
        for right in left + 1..raw.len() {
            // One pair visit and both length inspections are admitted before
            // choosing the only comparison that can remove a redundant item.
            meter.charge(3)?;
            match raw[left].len().cmp(&raw[right].len()) {
                core::cmp::Ordering::Equal => {
                    if equal_metered(raw[left], raw[right], meter)? {
                        remove_metered(&mut retained, right, meter)?;
                    }
                }
                core::cmp::Ordering::Less => {
                    if contains_metered(raw[right], raw[left], meter)? {
                        remove_metered(&mut retained, right, meter)?;
                    }
                }
                core::cmp::Ordering::Greater => {
                    if contains_metered(raw[left], raw[right], meter)? {
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
        bytes =
            bytes
                .checked_add(needle.len())
                .ok_or(CaptureRequiredLiteralBuildError::Overflow(
                    "effective needle bytes",
                ))?;
        minimum_bytes = minimum_bytes.min(needle.len());
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
            if longer[start + offset] != needle_byte {
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

    const AWS: &str = r#"(('|")((?:ASIA|AKIA|AROA|AIDA)([A-Z0-7]{16}))('|").*?(\n^.*?){0,4}(('|")[a-zA-Z0-9+/]{40}('|"))+|('|")[a-zA-Z0-9+/]{40}('|").*?(\n^.*?){0,3}('|")((?:ASIA|AKIA|AROA|AIDA)([A-Z0-7]{16}))('|"))+"#;

    fn build(
        pattern: &str,
        limits: CaptureRequiredLiteralBuildLimits,
    ) -> Result<CaptureRequiredLiteralBuildOutcome, CaptureRequiredLiteralBuildError> {
        let mut profile = RustProfile::rebar_1_12_4();
        profile.options.unicode = false;
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

    fn owned_needles(plan: &CaptureRequiredLiteralPlan) -> Vec<Vec<u8>> {
        plan.build_report()
            .identity
            .needles
            .iter()
            .map(<[u8]>::to_vec)
            .collect()
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
    fn effective_antichain_controls_eligibility_and_preserves_first_order() {
        for redundant in ["(?:(AB)|(AB))", "(?:(AB)|(XAB))", "(?:(XAB)|(AB))"] {
            assert!(
                build(redundant, CaptureRequiredLiteralBuildLimits::default())
                    .unwrap()
                    .plan
                    .is_none(),
                "{redundant} must not activate a redundant any-literal set"
            );
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
    }
}
