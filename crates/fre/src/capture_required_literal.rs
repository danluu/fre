//! Bounded required-literal prefilter for capture-preserving operations.

use core::{fmt, mem::size_of};
use std::{alloc::Layout, sync::Arc};

use fre_kernels::{
    LiteralSetAccounting, LiteralSetBuildAccounting, LiteralSetBuildLimits, LiteralSetError,
    LiteralSetPlan, LiteralSetSearchLimits,
};
use fre_syntax::CacheKey;
use regex_syntax::hir::{Hir, HirKind};

/// Versioned algorithm identity for the required-any-literal proof.
pub const CAPTURE_REQUIRED_LITERAL_PLAN_ID: &str = "fre.capture.required-any-literal-dfa.v1";

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
    pub needles: usize,
    pub needle_bytes: usize,
    pub minimum_needle_bytes: usize,
    pub source_bytes: usize,
    pub scratch_bytes: usize,
    pub peak_bytes_upper_bound: usize,
    pub literal_set: LiteralSetBuildAccounting,
}

/// Immutable proof identity. Source syntax remains distinct even when HIRs agree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureRequiredLiteralIdentity {
    pub syntax: Arc<CacheKey>,
    pub plan_id: &'static str,
    pub needles: Arc<Vec<Vec<u8>>>,
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

pub(crate) fn build_from_hir(
    hir: &Hir,
    syntax: Arc<CacheKey>,
    limits: CaptureRequiredLiteralBuildLimits,
) -> Result<Option<CaptureRequiredLiteralPlan>, CaptureRequiredLiteralBuildError> {
    let mut meter = Meter::new(limits);
    let Some(metrics) = measure(hir, 1, &mut meter)? else {
        return Ok(None);
    };
    check_metric_limits(metrics, limits)?;

    let prospective_needle_bytes = metrics
        .needles
        .checked_mul(size_of::<Vec<u8>>())
        .and_then(|bytes| bytes.checked_add(metrics.bytes))
        .ok_or(CaptureRequiredLiteralBuildError::Overflow(
            "prospective needle bytes",
        ))?;
    let needle_arc_block = arc_block_bytes::<Vec<Vec<u8>>>()?;
    let prospective_source = prospective_needle_bytes
        .checked_add(needle_arc_block)
        .ok_or(CaptureRequiredLiteralBuildError::Overflow(
            "prospective source bytes",
        ))?;
    check_limit("source bytes", prospective_source, limits.max_source_bytes)?;

    let prospective_scratch = metrics.needles.checked_mul(size_of::<&[u8]>()).ok_or(
        CaptureRequiredLiteralBuildError::Overflow("reference scratch"),
    )?;
    check_limit(
        "scratch bytes",
        prospective_scratch,
        limits.max_scratch_bytes,
    )?;

    let mut needles = Vec::new();
    needles.try_reserve_exact(metrics.needles).map_err(|_| {
        CaptureRequiredLiteralBuildError::Allocation {
            structure: "needle",
            items: metrics.needles,
        }
    })?;
    collect(hir, 1, &mut meter, &mut needles)?;
    if needles.len() != metrics.needles {
        return Err(CaptureRequiredLiteralBuildError::InternalInvariant(
            "collected needle count differs from proof",
        ));
    }

    meter.charge(metrics.needles)?;
    let actual_bytes = needles.iter().try_fold(0_usize, |total, needle| {
        total
            .checked_add(needle.len())
            .ok_or(CaptureRequiredLiteralBuildError::Overflow(
                "collected needle bytes",
            ))
    })?;
    if actual_bytes != metrics.bytes {
        return Err(CaptureRequiredLiteralBuildError::InternalInvariant(
            "collected needle bytes differ from proof",
        ));
    }

    meter.charge(metrics.needles)?;
    let needle_capacity_bytes = needle_capacity_bytes(&needles)?;
    let source_before_matcher = needle_capacity_bytes.checked_add(needle_arc_block).ok_or(
        CaptureRequiredLiteralBuildError::Overflow("observed source before matcher"),
    )?;
    check_limit(
        "source bytes",
        source_before_matcher,
        limits.max_source_bytes,
    )?;

    let mut refs = Vec::new();
    refs.try_reserve_exact(metrics.needles).map_err(|_| {
        CaptureRequiredLiteralBuildError::Allocation {
            structure: "needle reference",
            items: metrics.needles,
        }
    })?;
    let scratch_bytes = refs.capacity().checked_mul(size_of::<&[u8]>()).ok_or(
        CaptureRequiredLiteralBuildError::Overflow("observed reference scratch"),
    )?;
    check_limit("scratch bytes", scratch_bytes, limits.max_scratch_bytes)?;
    meter.charge(metrics.needles)?;
    refs.extend(needles.iter().map(Vec::as_slice));

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
    // Charge publication before DFA construction so no later planner refusal
    // can strand already-admitted construction work.
    meter.charge(3)?;
    let matcher = LiteralSetPlan::new(&refs, dfa_limits)
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
            needles: metrics.needles,
            needle_bytes: metrics.bytes,
            minimum_needle_bytes: metrics.minimum_bytes,
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

fn collect(
    hir: &Hir,
    depth: usize,
    meter: &mut Meter,
    output: &mut Vec<Vec<u8>>,
) -> Result<(), CaptureRequiredLiteralBuildError> {
    meter.enter(depth)?;
    match hir.kind() {
        HirKind::Literal(literal) if !literal.0.is_empty() => {
            meter.charge(literal.0.len().checked_add(1).ok_or(
                CaptureRequiredLiteralBuildError::Overflow("needle publication work"),
            )?)?;
            let mut needle = Vec::new();
            needle.try_reserve_exact(literal.0.len()).map_err(|_| {
                CaptureRequiredLiteralBuildError::Allocation {
                    structure: "needle byte",
                    items: literal.0.len(),
                }
            })?;
            check_limit(
                "needle bytes",
                needle.capacity(),
                meter.limits.max_needle_bytes,
            )?;
            needle.extend_from_slice(&literal.0);
            output.push(needle);
            Ok(())
        }
        HirKind::Capture(capture) => collect(&capture.sub, next_depth(depth)?, meter, output),
        HirKind::Repetition(repetition) if repetition.min > 0 => {
            collect(&repetition.sub, next_depth(depth)?, meter, output)
        }
        HirKind::Concat(children) => {
            for child in children {
                if measure(child, next_depth(depth)?, meter)?.is_some() {
                    return collect(child, next_depth(depth)?, meter, output);
                }
            }
            Err(CaptureRequiredLiteralBuildError::InternalInvariant(
                "proved concat lost its required literal",
            ))
        }
        HirKind::Alternation(children) => {
            for child in children {
                collect(child, next_depth(depth)?, meter, output)?;
            }
            Ok(())
        }
        _ => Err(CaptureRequiredLiteralBuildError::InternalInvariant(
            "proved node lost its required literal",
        )),
    }
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

fn needle_capacity_bytes(
    needles: &Vec<Vec<u8>>,
) -> Result<usize, CaptureRequiredLiteralBuildError> {
    let outer = needles.capacity().checked_mul(size_of::<Vec<u8>>()).ok_or(
        CaptureRequiredLiteralBuildError::Overflow("needle vector capacity bytes"),
    )?;
    needles.iter().try_fold(outer, |total, needle| {
        total
            .checked_add(needle.capacity())
            .ok_or(CaptureRequiredLiteralBuildError::Overflow(
                "needle byte capacity",
            ))
    })
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
    ) -> Result<Option<CaptureRequiredLiteralPlan>, CaptureRequiredLiteralBuildError> {
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

    #[test]
    fn generic_lattice_selects_required_literals_and_preserves_order() {
        let plan = build(
            "(?:(AB|CD)x|y(AB|CD))+",
            CaptureRequiredLiteralBuildLimits::default(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            plan.build_report().identity.needles.as_ref(),
            &vec![b"AB".to_vec(), b"CD".to_vec(), b"y".to_vec()]
        );
        assert!(
            build("(?:AB|)", CaptureRequiredLiteralBuildLimits::default())
                .unwrap()
                .is_none()
        );
        assert!(
            build("(?:AB)?", CaptureRequiredLiteralBuildLimits::default())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn aws_hir_proves_the_access_prefix_set_and_byte_search_is_malformed_safe() {
        let plan = build(AWS, CaptureRequiredLiteralBuildLimits::default())
            .unwrap()
            .unwrap();
        assert_eq!(plan.build_report().accounting.needles, 8);
        assert_eq!(plan.build_report().accounting.needle_bytes, 32);
        assert_eq!(
            plan.build_report().identity.needles.as_ref(),
            &vec![
                b"ASIA".to_vec(),
                b"AKIA".to_vec(),
                b"AROA".to_vec(),
                b"AIDA".to_vec(),
                b"ASIA".to_vec(),
                b"AKIA".to_vec(),
                b"AROA".to_vec(),
                b"AIDA".to_vec(),
            ]
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
