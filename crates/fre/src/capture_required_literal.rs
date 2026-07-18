//! Bounded required-literal prefilter for capture-preserving operations.

use core::{fmt, mem::size_of};
use std::sync::Arc;

use fre_kernels::{
    LiteralSetAccounting, LiteralSetBuildAccounting, LiteralSetBuildLimits, LiteralSetError,
    LiteralSetPlan, LiteralSetSearchLimits,
};
use fre_syntax::{
    AdmissionPolicy, AdmissionStatus, CacheKey, CanonicalPattern, CompatibilityProfile,
    ParseSummary, RustProfile, SafetyEnvelope,
};
use regex_syntax::hir::{Hir, HirKind};

/// Versioned algorithm identity for the required-any-literal proof.
pub const CAPTURE_REQUIRED_LITERAL_PLAN_ID: &str = "fre.capture.required-any-literal-dfa.v1";

/// Fixed construction limits included in plan identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureRequiredLiteralBuildLimits {
    pub admission: AdmissionPolicy,
    pub syntax_safety: SafetyEnvelope,
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
            admission: AdmissionPolicy::default(),
            syntax_safety: SafetyEnvelope::default(),
            max_planner_work: 1_000_000,
            max_hir_depth: 250,
            max_needles: 64,
            max_needle_bytes: 4 * 1_024,
            max_source_bytes: 16 * 1_024,
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
    pub admission: AdmissionStatus,
    pub syntax: ParseSummary,
    pub identity: CaptureRequiredLiteralIdentity,
    pub accounting: CaptureRequiredLiteralBuildAccounting,
}

/// Typed construction refusal.
#[derive(Debug)]
#[non_exhaustive]
pub enum CaptureRequiredLiteralBuildError {
    Syntax(fre_syntax::ParseError),
    Unsupported,
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
            Self::Syntax(error) => write!(f, "required-literal syntax failed: {error}"),
            Self::Unsupported => f.write_str("HIR has no bounded required literal set"),
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
            Self::Syntax(error) => Some(error),
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
    pub identity: Box<CaptureRequiredLiteralCacheIdentity>,
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

/// Builder for a generic required-any-literal proof over Rust byte HIR.
#[derive(Clone, Debug)]
pub struct CaptureRequiredLiteralBuilder {
    pattern: String,
    profile: RustProfile,
    limits: CaptureRequiredLiteralBuildLimits,
}

impl CaptureRequiredLiteralBuilder {
    #[must_use]
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            profile: RustProfile::default(),
            limits: CaptureRequiredLiteralBuildLimits::default(),
        }
    }

    #[must_use]
    pub fn profile(mut self, profile: RustProfile) -> Self {
        self.profile = profile;
        self
    }

    #[must_use]
    pub fn unicode(mut self, enabled: bool) -> Self {
        self.profile.options.unicode = enabled;
        self
    }

    #[must_use]
    pub fn case_insensitive(mut self, enabled: bool) -> Self {
        self.profile.options.case_insensitive = enabled;
        self
    }

    #[must_use]
    pub const fn limits(mut self, limits: CaptureRequiredLiteralBuildLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn build(self) -> Result<CaptureRequiredLiteralPlan, CaptureRequiredLiteralBuildError> {
        let profile = CompatibilityProfile::RustBytes(self.profile);
        let parsed = fre_syntax::parse(
            fre_syntax::ParseRequest::rust(self.pattern, profile)
                .with_admission(self.limits.admission)
                .with_safety_envelope(self.limits.syntax_safety),
        )
        .map_err(CaptureRequiredLiteralBuildError::Syntax)?;
        let CanonicalPattern::Rust(rust) = parsed.pattern else {
            return Err(CaptureRequiredLiteralBuildError::InternalInvariant(
                "Rust byte request produced non-Rust syntax",
            ));
        };
        let mut meter = Meter::new(self.limits);
        let Some(metrics) = measure(&rust.hir, 1, &mut meter)? else {
            return Err(CaptureRequiredLiteralBuildError::Unsupported);
        };
        check_metric_limits(metrics, self.limits)?;
        let source_bytes = metrics
            .needles
            .checked_mul(size_of::<Vec<u8>>())
            .and_then(|bytes| bytes.checked_add(metrics.bytes))
            .ok_or(CaptureRequiredLiteralBuildError::Overflow("source bytes"))?;
        check_limit("source bytes", source_bytes, self.limits.max_source_bytes)?;
        let scratch_bytes = metrics.needles.checked_mul(size_of::<&[u8]>()).ok_or(
            CaptureRequiredLiteralBuildError::Overflow("reference scratch"),
        )?;
        check_limit(
            "scratch bytes",
            scratch_bytes,
            self.limits.max_scratch_bytes,
        )?;

        let mut needles = Vec::new();
        needles.try_reserve_exact(metrics.needles).map_err(|_| {
            CaptureRequiredLiteralBuildError::Allocation {
                structure: "needle",
                items: metrics.needles,
            }
        })?;
        collect(&rust.hir, 1, &mut meter, &mut needles)?;
        if needles.len() != metrics.needles {
            return Err(CaptureRequiredLiteralBuildError::InternalInvariant(
                "collected needle count differs from proof",
            ));
        }
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
        let refs = needles.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let mut dfa_limits = self.limits.literal_set;
        let live_source = source_bytes.checked_add(scratch_bytes).ok_or(
            CaptureRequiredLiteralBuildError::Overflow("live source bytes"),
        )?;
        dfa_limits.max_build_bytes = dfa_limits.max_build_bytes.min(
            self.limits.max_peak_bytes.checked_sub(live_source).ok_or(
                CaptureRequiredLiteralBuildError::Resource {
                    resource: "peak bytes",
                    required: live_source,
                    limit: self.limits.max_peak_bytes,
                },
            )?,
        );
        let matcher = LiteralSetPlan::new(&refs, dfa_limits)
            .map_err(CaptureRequiredLiteralBuildError::LiteralSet)?;
        let literal_set = matcher.build_accounting();
        let peak_bytes_upper_bound = live_source
            .checked_add(literal_set.build_bytes_upper_bound)
            .ok_or(CaptureRequiredLiteralBuildError::Overflow(
                "peak build bytes",
            ))?;
        check_limit(
            "peak bytes",
            peak_bytes_upper_bound,
            self.limits.max_peak_bytes,
        )?;
        let needles = Arc::new(needles);
        let identity = CaptureRequiredLiteralIdentity {
            syntax: Arc::new(parsed.key),
            plan_id: CAPTURE_REQUIRED_LITERAL_PLAN_ID,
            needles,
        };
        let report = CaptureRequiredLiteralBuildReport {
            admission: parsed.admission_status,
            syntax: parsed.summary,
            identity,
            accounting: CaptureRequiredLiteralBuildAccounting {
                planner_work: meter.work,
                hir_nodes: meter.nodes,
                hir_depth: meter.depth,
                needles: metrics.needles,
                needle_bytes: metrics.bytes,
                source_bytes,
                scratch_bytes,
                peak_bytes_upper_bound,
                literal_set,
            },
        };
        Ok(CaptureRequiredLiteralPlan {
            matcher: Arc::new(matcher),
            build_limits: self.limits,
            report,
        })
    }
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
                identity: Box::new(identity.clone()),
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
            }
            Ok(Some(Metrics { needles, bytes }))
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
            meter.charge(literal.0.len())?;
            let mut needle = Vec::new();
            needle.try_reserve_exact(literal.0.len()).map_err(|_| {
                CaptureRequiredLiteralBuildError::Allocation {
                    structure: "needle byte",
                    items: literal.0.len(),
                }
            })?;
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

    const AWS: &str = r#"(('|")((?:ASIA|AKIA|AROA|AIDA)([A-Z0-7]{16}))('|\").*?(\n^.*?){0,4}(('|\")[a-zA-Z0-9+/]{40}('|\"))+|('|\")[a-zA-Z0-9+/]{40}('|\").*?(\n^.*?){0,3}('|\")((?:ASIA|AKIA|AROA|AIDA)([A-Z0-7]{16}))('|\"))+"#;

    #[test]
    fn generic_lattice_selects_required_literals_and_preserves_order() {
        let plan = CaptureRequiredLiteralBuilder::new("(?:(AB|CD)x|y(AB|CD))+")
            .unicode(false)
            .build()
            .unwrap();
        assert_eq!(
            plan.build_report().identity.needles.as_ref(),
            &vec![b"AB".to_vec(), b"CD".to_vec(), b"y".to_vec()]
        );
        assert!(
            CaptureRequiredLiteralBuilder::new("(?:AB|)")
                .build()
                .is_err()
        );
        assert!(
            CaptureRequiredLiteralBuilder::new("(?:AB)?")
                .build()
                .is_err()
        );
    }

    #[test]
    fn aws_hir_proves_the_access_prefix_set_and_byte_search_is_malformed_safe() {
        let plan = CaptureRequiredLiteralBuilder::new(AWS)
            .unicode(false)
            .build()
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
        let miss = plan
            .is_candidate(
                b"\xFF EASTASIAN",
                CaptureRequiredLiteralRunLimits::default(),
            )
            .unwrap();
        assert!(miss.candidate);
        assert_eq!(miss.accounting.transitions_upper_bound, 12);
        let clean_miss = plan
            .is_candidate(b"\xFF no key", CaptureRequiredLiteralRunLimits::default())
            .unwrap();
        assert!(!clean_miss.candidate);
    }

    #[test]
    fn planner_and_search_exact_limits_refuse_one_below() {
        let baseline = CaptureRequiredLiteralBuilder::new("(?:AB|CD)")
            .unicode(false)
            .build()
            .unwrap();
        let accounting = baseline.build_report().accounting;
        let mut limits = CaptureRequiredLiteralBuildLimits::default();
        limits.max_planner_work = accounting.planner_work - 1;
        assert!(matches!(
            CaptureRequiredLiteralBuilder::new("(?:AB|CD)")
                .unicode(false)
                .limits(limits)
                .build(),
            Err(CaptureRequiredLiteralBuildError::Resource {
                resource: "planner work",
                ..
            })
        ));
        let exact = baseline
            .is_candidate(
                b"zzAB",
                CaptureRequiredLiteralRunLimits { max_transitions: 5 },
            )
            .unwrap();
        assert!(exact.candidate);
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
