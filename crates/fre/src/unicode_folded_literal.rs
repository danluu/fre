//! Bounded whole-match reducers for one nonempty Unicode folded scalar sequence.
//!
//! This facade is intentionally independent of aggregate-plan selection. It
//! recognizes a canonical Rust-bytes HIR made only from transparent captures,
//! concatenation, valid UTF-8 literals and small Unicode scalar classes. The
//! retained folded-trie owner is built once; Count and matched-byte-sum
//! operations use its start-ordered candidate stream without allocating.

#![allow(
    clippy::large_enum_variant,
    clippy::result_large_err,
    reason = "syntax failures retain the exact owned source and closed parser receipt without an unaccounted post-failure allocation"
)]

use core::{fmt, mem::size_of};

use fre_kernels::{
    FoldedLiteral, FoldedLiteralTrieBuildAccounting, FoldedLiteralTrieBuildAttempt,
    FoldedLiteralTrieBuildError, FoldedLiteralTrieBuildLimits, FoldedLiteralTriePlan,
    FoldedLiteralTrieScanAttemptError, FoldedLiteralTrieScanLimits, FoldedLiteralTrieScanReceipt,
    FoldedLiteralTrieScanUpperBounds, FoldedScalarClass,
};
use fre_syntax::{
    AdmissionPolicy, AdmissionStatus, CacheKey, CanonicalPattern, CompatibilityProfile,
    ParseAttemptError, ParseRequest, ParseSummary, RustConstructor, RustMatchKind, RustProfile,
    SafetyEnvelope, parse_attempt,
};
use regex_syntax::hir::{Class, Hir, HirKind};

/// Stable implementation identity for the product-facing folded-literal facade.
pub const UNICODE_FOLDED_LITERAL_ALGORITHM_ID: &str =
    "fre.unicode-folded-literal.fixed-column-guarded-memchr-trie.v2";
/// Stable Count operation identity.
pub const UNICODE_FOLDED_LITERAL_COUNT_OPERATION_ID: &str = "fre.unicode-folded-literal.count.v2";
/// Stable matched-byte-sum operation identity.
pub const UNICODE_FOLDED_LITERAL_SPAN_SUM_OPERATION_ID: &str =
    "fre.unicode-folded-literal.span-sum.v2";

const MAX_CLASS_MEMBERS: usize = 4;
const REDUCER_WORK_PER_CANDIDATE: usize = 3;

/// Operation fixed at construction.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum UnicodeFoldedLiteralOperation {
    Count,
    SpanSum,
}

impl UnicodeFoldedLiteralOperation {
    /// Stable operation identity.
    #[must_use]
    pub const fn identity(self) -> &'static str {
        match self {
            Self::Count => UNICODE_FOLDED_LITERAL_COUNT_OPERATION_ID,
            Self::SpanSum => UNICODE_FOLDED_LITERAL_SPAN_SUM_OPERATION_ID,
        }
    }
}

/// Structural reason that leaves the existing generic aggregate route eligible.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum UnicodeFoldedLiteralIneligibility {
    Profile,
    Empty,
    UnsupportedHir,
    ClassTooWide { members: usize, maximum: usize },
    RootIsNotNonAsciiFoldClass,
    NoUsefulRootPrefilter,
    NonCanonicalClasses,
}

/// Checked planner limits in addition to the pinned syntax and kernel limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnicodeFoldedLiteralBuildLimits {
    pub admission: AdmissionPolicy,
    pub syntax_safety: SafetyEnvelope,
    pub max_scalar_positions: usize,
    pub max_equivalent_scalars: usize,
    pub max_planner_work: usize,
    pub max_planner_scratch_bytes: usize,
    pub trie: FoldedLiteralTrieBuildLimits,
}

impl Default for UnicodeFoldedLiteralBuildLimits {
    fn default() -> Self {
        Self {
            admission: AdmissionPolicy::default(),
            syntax_safety: SafetyEnvelope::default(),
            max_scalar_positions: 4_096,
            max_equivalent_scalars: 16_384,
            max_planner_work: 1 << 20,
            max_planner_scratch_bytes: 4 << 20,
            trie: FoldedLiteralTrieBuildLimits::default(),
        }
    }
}

/// Exact completed HIR inspection/materialization census.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UnicodeFoldedLiteralPlannerAccounting {
    pub hir_nodes: usize,
    pub scalar_positions: usize,
    pub equivalent_scalars: usize,
    /// Saturating size of the Cartesian finite language represented by all
    /// scalar positions. This lets an outer construction ladder preserve a
    /// smaller incumbent finite-language plan without benchmark metadata.
    pub cartesian_sequences_saturated: usize,
    pub folded_classes: usize,
    pub work: usize,
    pub scratch_bytes: usize,
    pub allocations: usize,
}

/// Immutable construction identity and accounting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnicodeFoldedLiteralBuildReport {
    pub algorithm: &'static str,
    pub operation: UnicodeFoldedLiteralOperation,
    pub syntax_key: CacheKey,
    pub admission: AdmissionStatus,
    pub syntax: ParseSummary,
    pub planner: UnicodeFoldedLiteralPlannerAccounting,
    pub trie: FoldedLiteralTrieBuildAccounting,
}

/// A structural miss is distinct from a selected-plan construction failure.
#[derive(Debug)]
pub enum UnicodeFoldedLiteralBuildAttempt<T> {
    Admitted(T),
    Ineligible {
        reason: UnicodeFoldedLiteralIneligibility,
        planner: UnicodeFoldedLiteralPlannerAccounting,
    },
}

/// Terminal construction failure after this facade's profile or resource
/// transaction has been selected.
#[derive(Debug)]
#[non_exhaustive]
pub enum UnicodeFoldedLiteralBuildError {
    Syntax(ParseAttemptError),
    Resource {
        resource: &'static str,
        needed: usize,
        limit: usize,
    },
    AllocationFailed {
        structure: &'static str,
        items: usize,
    },
    Trie(FoldedLiteralTrieBuildError),
    ArithmeticOverflow {
        computation: &'static str,
    },
    Invariant {
        detail: &'static str,
    },
}

impl fmt::Display for UnicodeFoldedLiteralBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Unicode folded-literal construction failed: {self:?}"
        )
    }
}

impl std::error::Error for UnicodeFoldedLiteralBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Syntax(error) => Some(error),
            Self::Trie(error) => Some(error),
            _ => None,
        }
    }
}

/// Builder whose inputs are only source, the complete Rust profile and
/// explicit limits.
#[derive(Clone, Debug)]
pub struct UnicodeFoldedLiteralBuilder {
    pattern: String,
    profile: RustProfile,
    limits: UnicodeFoldedLiteralBuildLimits,
}

impl UnicodeFoldedLiteralBuilder {
    #[must_use]
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            profile: RustProfile::default(),
            limits: UnicodeFoldedLiteralBuildLimits::default(),
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
    pub const fn limits(mut self, limits: UnicodeFoldedLiteralBuildLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn build_count(
        self,
    ) -> Result<
        UnicodeFoldedLiteralBuildAttempt<UnicodeFoldedLiteralCountRegex>,
        UnicodeFoldedLiteralBuildError,
    > {
        build(self, UnicodeFoldedLiteralOperation::Count).map(|attempt| match attempt {
            UnicodeFoldedLiteralBuildAttempt::Admitted(plan) => {
                UnicodeFoldedLiteralBuildAttempt::Admitted(UnicodeFoldedLiteralCountRegex(plan))
            }
            UnicodeFoldedLiteralBuildAttempt::Ineligible { reason, planner } => {
                UnicodeFoldedLiteralBuildAttempt::Ineligible { reason, planner }
            }
        })
    }

    pub fn build_span_sum(
        self,
    ) -> Result<
        UnicodeFoldedLiteralBuildAttempt<UnicodeFoldedLiteralSpanSumRegex>,
        UnicodeFoldedLiteralBuildError,
    > {
        build(self, UnicodeFoldedLiteralOperation::SpanSum).map(|attempt| match attempt {
            UnicodeFoldedLiteralBuildAttempt::Admitted(plan) => {
                UnicodeFoldedLiteralBuildAttempt::Admitted(UnicodeFoldedLiteralSpanSumRegex(plan))
            }
            UnicodeFoldedLiteralBuildAttempt::Ineligible { reason, planner } => {
                UnicodeFoldedLiteralBuildAttempt::Ineligible { reason, planner }
            }
        })
    }
}

#[derive(Debug)]
struct UnicodeFoldedLiteralPlan {
    trie: FoldedLiteralTriePlan,
    report: UnicodeFoldedLiteralBuildReport,
}

/// Reusable allocation-free Count artifact.
#[derive(Debug)]
pub struct UnicodeFoldedLiteralCountRegex(UnicodeFoldedLiteralPlan);

/// Reusable allocation-free matched-byte-sum artifact.
#[derive(Debug)]
pub struct UnicodeFoldedLiteralSpanSumRegex(UnicodeFoldedLiteralPlan);

/// Complete input-length-derived operation envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnicodeFoldedLiteralRunUpperBounds {
    pub scan: FoldedLiteralTrieScanUpperBounds,
    pub reducer_steps: usize,
    pub count: u64,
    pub span_sum: u64,
    pub work: usize,
    pub scratch_bytes: usize,
}

/// Caller limits for one complete operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnicodeFoldedLiteralRunLimits {
    pub scan: FoldedLiteralTrieScanLimits,
    pub max_reducer_steps: usize,
    pub max_count: u64,
    pub max_span_sum: u64,
    pub max_work: usize,
    pub max_scratch_bytes: usize,
}

impl UnicodeFoldedLiteralRunLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            scan: FoldedLiteralTrieScanLimits::unlimited(),
            max_reducer_steps: usize::MAX,
            max_count: u64::MAX,
            max_span_sum: u64::MAX,
            max_work: usize::MAX,
            max_scratch_bytes: usize::MAX,
        }
    }

    #[must_use]
    pub const fn exact(upper: UnicodeFoldedLiteralRunUpperBounds) -> Self {
        Self {
            scan: FoldedLiteralTrieScanLimits {
                max_input_bytes: upper.scan.input_bytes,
                max_candidate_starts: upper.scan.candidate_starts,
                max_scalar_decodes: upper.scan.scalar_decodes,
                max_decoded_scalars: upper.scan.decoded_scalars,
                max_invalid_bytes: upper.scan.invalid_bytes,
                max_source_byte_reads: upper.scan.source_byte_reads,
                max_transition_probes: upper.scan.transition_probes,
                max_candidate_events: upper.scan.candidate_events,
                max_work: upper.scan.work,
                max_scratch_bytes: upper.scan.scratch_bytes,
            },
            max_reducer_steps: upper.reducer_steps,
            max_count: upper.count,
            max_span_sum: upper.span_sum,
            max_work: upper.work,
            max_scratch_bytes: upper.scratch_bytes,
        }
    }
}

impl Default for UnicodeFoldedLiteralRunLimits {
    fn default() -> Self {
        Self::unlimited()
    }
}

/// Exact completed operation counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnicodeFoldedLiteralRunReceipt {
    pub upper: UnicodeFoldedLiteralRunUpperBounds,
    pub scan: FoldedLiteralTrieScanReceipt,
    pub reducer_steps: usize,
    pub selected_matches: u64,
    pub count: u64,
    pub span_sum: u64,
    pub work: usize,
    pub scratch_bytes: usize,
}

/// Successful value and receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnicodeFoldedLiteralRunResult {
    pub value: u64,
    pub receipt: UnicodeFoldedLiteralRunReceipt,
}

/// Checked operation failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum UnicodeFoldedLiteralRunError {
    Resource {
        resource: &'static str,
        needed: usize,
        limit: usize,
    },
    Scan(FoldedLiteralTrieScanAttemptError),
    ArithmeticOverflow {
        computation: &'static str,
    },
    Invariant {
        detail: &'static str,
    },
}

impl fmt::Display for UnicodeFoldedLiteralRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Unicode folded-literal operation failed: {self:?}"
        )
    }
}

impl std::error::Error for UnicodeFoldedLiteralRunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Scan(error) => Some(error),
            _ => None,
        }
    }
}

macro_rules! impl_regex {
    ($type:ty, $operation:expr) => {
        impl $type {
            #[must_use]
            pub const fn build_report(&self) -> &UnicodeFoldedLiteralBuildReport {
                &self.0.report
            }

            pub fn full_window_upper_bounds(
                &self,
                input_bytes: usize,
            ) -> Result<UnicodeFoldedLiteralRunUpperBounds, UnicodeFoldedLiteralRunError> {
                run_upper_bounds(&self.0.trie, input_bytes)
            }

            pub fn execute(
                &self,
                haystack: &[u8],
                limits: UnicodeFoldedLiteralRunLimits,
            ) -> Result<UnicodeFoldedLiteralRunResult, UnicodeFoldedLiteralRunError> {
                execute(&self.0, haystack, limits, $operation)
            }
        }
    };
}

impl_regex!(
    UnicodeFoldedLiteralCountRegex,
    UnicodeFoldedLiteralOperation::Count
);
impl_regex!(
    UnicodeFoldedLiteralSpanSumRegex,
    UnicodeFoldedLiteralOperation::SpanSum
);

#[derive(Clone, Copy, Debug)]
struct Shape {
    hir_nodes: usize,
    scalar_positions: usize,
    equivalent_scalars: usize,
    cartesian_sequences_saturated: usize,
    folded_classes: usize,
    root_is_nonascii_fold: bool,
    work: usize,
}

impl Default for Shape {
    fn default() -> Self {
        Self {
            hir_nodes: 0,
            scalar_positions: 0,
            equivalent_scalars: 0,
            cartesian_sequences_saturated: 1,
            folded_classes: 0,
            root_is_nonascii_fold: false,
            work: 0,
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "profile selection, two-pass HIR materialization and no-fallback trie publication stay in one auditable transaction"
)]
fn build(
    builder: UnicodeFoldedLiteralBuilder,
    operation: UnicodeFoldedLiteralOperation,
) -> Result<
    UnicodeFoldedLiteralBuildAttempt<UnicodeFoldedLiteralPlan>,
    UnicodeFoldedLiteralBuildError,
> {
    if !eligible_profile(&builder.profile) {
        return Ok(UnicodeFoldedLiteralBuildAttempt::Ineligible {
            reason: UnicodeFoldedLiteralIneligibility::Profile,
            planner: UnicodeFoldedLiteralPlannerAccounting::default(),
        });
    }
    let mut request = ParseRequest::rust(
        builder.pattern,
        CompatibilityProfile::RustBytes(builder.profile),
    )
    .with_admission(builder.limits.admission)
    .with_safety_envelope(builder.limits.syntax_safety);
    let _ = request.bind_attempt_source_owner();
    let attempt = parse_attempt(request).map_err(UnicodeFoldedLiteralBuildError::Syntax)?;
    let (record, _) = attempt.into_parts();
    let CanonicalPattern::Rust(rust) = record.pattern else {
        return Err(UnicodeFoldedLiteralBuildError::Invariant {
            detail: "Rust-bytes folded-literal parse produced a non-Rust pattern",
        });
    };
    let shape = match inspect_hir(&rust.hir)? {
        Ok(shape) => shape,
        Err(reason) => {
            return Ok(UnicodeFoldedLiteralBuildAttempt::Ineligible {
                reason,
                planner: UnicodeFoldedLiteralPlannerAccounting::default(),
            });
        }
    };
    if shape.scalar_positions == 0 {
        return Ok(UnicodeFoldedLiteralBuildAttempt::Ineligible {
            reason: UnicodeFoldedLiteralIneligibility::Empty,
            planner: planner_accounting(shape, 0, 0),
        });
    }
    if !shape.root_is_nonascii_fold {
        return Ok(UnicodeFoldedLiteralBuildAttempt::Ineligible {
            reason: UnicodeFoldedLiteralIneligibility::RootIsNotNonAsciiFoldClass,
            planner: planner_accounting(shape, 0, 0),
        });
    }
    enforce_build_limits(shape, builder.limits)?;
    let scratch_bytes = planner_scratch_bytes(shape)?;
    if scratch_bytes > builder.limits.max_planner_scratch_bytes {
        return Err(UnicodeFoldedLiteralBuildError::Resource {
            resource: "planner scratch bytes",
            needed: scratch_bytes,
            limit: builder.limits.max_planner_scratch_bytes,
        });
    }
    let mut classes = Vec::<Vec<char>>::new();
    classes
        .try_reserve_exact(shape.scalar_positions)
        .map_err(|_| UnicodeFoldedLiteralBuildError::AllocationFailed {
            structure: "folded scalar classes",
            items: shape.scalar_positions,
        })?;
    materialize_hir(&rust.hir, &mut classes)?;
    if classes.len() != shape.scalar_positions {
        return Err(UnicodeFoldedLiteralBuildError::Invariant {
            detail: "folded-literal inspection/materialization position mismatch",
        });
    }
    let mut wrappers = Vec::<FoldedScalarClass<'_>>::new();
    wrappers
        .try_reserve_exact(shape.scalar_positions)
        .map_err(|_| UnicodeFoldedLiteralBuildError::AllocationFailed {
            structure: "folded scalar class views",
            items: shape.scalar_positions,
        })?;
    wrappers.extend(
        classes
            .iter()
            .map(|class| FoldedScalarClass::new(class.as_slice())),
    );
    let literals = [FoldedLiteral::new(&wrappers)];
    let planner_allocations = shape.scalar_positions.checked_add(2).ok_or(
        UnicodeFoldedLiteralBuildError::ArithmeticOverflow {
            computation: "folded planner allocation count",
        },
    )?;
    let trie = match FoldedLiteralTriePlan::build(&literals, builder.limits.trie)
        .map_err(UnicodeFoldedLiteralBuildError::Trie)?
    {
        FoldedLiteralTrieBuildAttempt::Admitted(plan) => plan,
        FoldedLiteralTrieBuildAttempt::DenseFallback(_) => {
            return Ok(UnicodeFoldedLiteralBuildAttempt::Ineligible {
                reason: UnicodeFoldedLiteralIneligibility::NonCanonicalClasses,
                planner: planner_accounting(shape, scratch_bytes, planner_allocations),
            });
        }
    };
    if trie.build_accounting().root_prefilter_needles == 0 {
        return Ok(UnicodeFoldedLiteralBuildAttempt::Ineligible {
            reason: UnicodeFoldedLiteralIneligibility::NoUsefulRootPrefilter,
            planner: planner_accounting(shape, scratch_bytes, planner_allocations),
        });
    }
    let report = UnicodeFoldedLiteralBuildReport {
        algorithm: UNICODE_FOLDED_LITERAL_ALGORITHM_ID,
        operation,
        syntax_key: record.key,
        admission: record.admission_status,
        syntax: record.summary,
        planner: planner_accounting(shape, scratch_bytes, planner_allocations),
        trie: trie.build_accounting(),
    };
    Ok(UnicodeFoldedLiteralBuildAttempt::Admitted(
        UnicodeFoldedLiteralPlan { trie, report },
    ))
}

fn eligible_profile(profile: &RustProfile) -> bool {
    if !profile.options.unicode || !profile.options.case_insensitive {
        return false;
    }
    match profile.constructor {
        RustConstructor::RegexBuilder {
            bytes_syntax_utf8,
            bytes_utf8_empty,
            match_kind,
            ..
        } => !bytes_syntax_utf8 && !bytes_utf8_empty && match_kind == RustMatchKind::LeftmostFirst,
        RustConstructor::RebarMeta {
            syntax_utf8,
            utf8_empty,
            match_kind,
            build_many_ordered,
            ..
        } => {
            !syntax_utf8
                && !utf8_empty
                && build_many_ordered
                && match_kind == RustMatchKind::LeftmostFirst
        }
        RustConstructor::RegexSetBuilder { .. } => false,
    }
}

fn inspect_hir(
    hir: &Hir,
) -> Result<Result<Shape, UnicodeFoldedLiteralIneligibility>, UnicodeFoldedLiteralBuildError> {
    let mut shape = Shape::default();
    if !inspect_sequence(hir, &mut shape)? {
        return Ok(Err(UnicodeFoldedLiteralIneligibility::UnsupportedHir));
    }
    let materialization_work = shape
        .hir_nodes
        .checked_add(shape.scalar_positions)
        .and_then(|work| work.checked_add(shape.equivalent_scalars))
        .ok_or(UnicodeFoldedLiteralBuildError::ArithmeticOverflow {
            computation: "folded materialization work",
        })?;
    shape.work = checked_add(
        shape.work,
        materialization_work,
        "folded total planner work",
    )?;
    Ok(Ok(shape))
}

fn inspect_sequence(hir: &Hir, shape: &mut Shape) -> Result<bool, UnicodeFoldedLiteralBuildError> {
    shape.hir_nodes = checked_add(shape.hir_nodes, 1, "folded HIR nodes")?;
    shape.work = checked_add(shape.work, 1, "folded inspection work")?;
    match hir.kind() {
        HirKind::Empty => Ok(true),
        HirKind::Capture(capture) => inspect_sequence(&capture.sub, shape),
        HirKind::Concat(children) => {
            for child in children {
                if !inspect_sequence(child, shape)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        HirKind::Literal(literal) => {
            let Ok(text) = core::str::from_utf8(literal.0.as_ref()) else {
                return Ok(false);
            };
            for _ in text.chars() {
                record_class(shape, 1, false)?;
            }
            Ok(true)
        }
        HirKind::Class(Class::Unicode(class)) if !class.ranges().is_empty() => {
            let mut members = 0_usize;
            let mut nonascii = false;
            for range in class.ranges() {
                let length = range.len();
                members = checked_add(members, length, "folded class members")?;
                shape.work = checked_add(shape.work, length, "folded class inspection work")?;
                nonascii |= !range.start().is_ascii() || !range.end().is_ascii();
                if members > MAX_CLASS_MEMBERS {
                    return Ok(false);
                }
            }
            let folded = members > 1;
            if shape.scalar_positions == 0 {
                shape.root_is_nonascii_fold = folded && nonascii;
            }
            record_class(shape, members, folded)?;
            Ok(true)
        }
        HirKind::Class(Class::Unicode(_) | Class::Bytes(_))
        | HirKind::Look(_)
        | HirKind::Repetition(_)
        | HirKind::Alternation(_) => Ok(false),
    }
}

fn record_class(
    shape: &mut Shape,
    members: usize,
    folded: bool,
) -> Result<(), UnicodeFoldedLiteralBuildError> {
    shape.scalar_positions = checked_add(shape.scalar_positions, 1, "folded scalar positions")?;
    shape.equivalent_scalars = checked_add(
        shape.equivalent_scalars,
        members,
        "folded equivalent scalars",
    )?;
    shape.cartesian_sequences_saturated =
        shape.cartesian_sequences_saturated.saturating_mul(members);
    shape.folded_classes =
        checked_add(shape.folded_classes, usize::from(folded), "folded classes")?;
    Ok(())
}

fn materialize_hir(
    hir: &Hir,
    output: &mut Vec<Vec<char>>,
) -> Result<(), UnicodeFoldedLiteralBuildError> {
    match hir.kind() {
        HirKind::Empty => {}
        HirKind::Capture(capture) => materialize_hir(&capture.sub, output)?,
        HirKind::Concat(children) => {
            for child in children {
                materialize_hir(child, output)?;
            }
        }
        HirKind::Literal(literal) => {
            let text = core::str::from_utf8(literal.0.as_ref()).map_err(|_| {
                UnicodeFoldedLiteralBuildError::Invariant {
                    detail: "admitted folded literal became invalid UTF-8",
                }
            })?;
            for scalar in text.chars() {
                let mut values = Vec::new();
                values.try_reserve_exact(1).map_err(|_| {
                    UnicodeFoldedLiteralBuildError::AllocationFailed {
                        structure: "folded literal scalar",
                        items: 1,
                    }
                })?;
                values.push(scalar);
                output.push(values);
            }
        }
        HirKind::Class(Class::Unicode(class)) => {
            let members = class
                .ranges()
                .iter()
                .try_fold(0_usize, |total, range| total.checked_add(range.len()))
                .ok_or(UnicodeFoldedLiteralBuildError::ArithmeticOverflow {
                    computation: "materialized folded class members",
                })?;
            let mut values = Vec::new();
            values.try_reserve_exact(members).map_err(|_| {
                UnicodeFoldedLiteralBuildError::AllocationFailed {
                    structure: "folded class members",
                    items: members,
                }
            })?;
            for range in class.ranges() {
                values.extend(range.start()..=range.end());
            }
            output.push(values);
        }
        _ => {
            return Err(UnicodeFoldedLiteralBuildError::Invariant {
                detail: "folded-literal HIR changed after admission",
            });
        }
    }
    Ok(())
}

fn enforce_build_limits(
    shape: Shape,
    limits: UnicodeFoldedLiteralBuildLimits,
) -> Result<(), UnicodeFoldedLiteralBuildError> {
    for (resource, needed, limit) in [
        (
            "scalar positions",
            shape.scalar_positions,
            limits.max_scalar_positions,
        ),
        (
            "equivalent scalars",
            shape.equivalent_scalars,
            limits.max_equivalent_scalars,
        ),
        ("planner work", shape.work, limits.max_planner_work),
    ] {
        if needed > limit {
            return Err(UnicodeFoldedLiteralBuildError::Resource {
                resource,
                needed,
                limit,
            });
        }
    }
    Ok(())
}

fn planner_scratch_bytes(shape: Shape) -> Result<usize, UnicodeFoldedLiteralBuildError> {
    shape
        .scalar_positions
        .checked_mul(size_of::<Vec<char>>())
        .and_then(|bytes| {
            bytes.checked_add(shape.equivalent_scalars.checked_mul(size_of::<char>())?)
        })
        .and_then(|bytes| {
            bytes.checked_add(
                shape
                    .scalar_positions
                    .checked_mul(size_of::<FoldedScalarClass<'_>>())?,
            )
        })
        .ok_or(UnicodeFoldedLiteralBuildError::ArithmeticOverflow {
            computation: "folded planner scratch bytes",
        })
}

const fn planner_accounting(
    shape: Shape,
    scratch_bytes: usize,
    allocations: usize,
) -> UnicodeFoldedLiteralPlannerAccounting {
    UnicodeFoldedLiteralPlannerAccounting {
        hir_nodes: shape.hir_nodes,
        scalar_positions: shape.scalar_positions,
        equivalent_scalars: shape.equivalent_scalars,
        cartesian_sequences_saturated: if shape.scalar_positions == 0 {
            0
        } else {
            shape.cartesian_sequences_saturated
        },
        folded_classes: shape.folded_classes,
        work: shape.work,
        scratch_bytes,
        allocations,
    }
}

fn run_upper_bounds(
    trie: &FoldedLiteralTriePlan,
    input_bytes: usize,
) -> Result<UnicodeFoldedLiteralRunUpperBounds, UnicodeFoldedLiteralRunError> {
    let scan = trie.scan_upper_bounds(input_bytes).map_err(|error| {
        UnicodeFoldedLiteralRunError::Invariant {
            detail: match error {
                fre_kernels::FoldedLiteralTrieScanError::ArithmeticOverflow { computation } => {
                    computation
                }
                _ => "folded scan upper bound failed without source",
            },
        }
    })?;
    let reducer_steps = scan.candidate_events;
    let count = u64::try_from(input_bytes).map_err(|_| {
        UnicodeFoldedLiteralRunError::ArithmeticOverflow {
            computation: "folded count upper bound",
        }
    })?;
    let span_sum = count;
    let reducer_work = reducer_steps
        .checked_mul(REDUCER_WORK_PER_CANDIDATE)
        .ok_or(UnicodeFoldedLiteralRunError::ArithmeticOverflow {
            computation: "folded reducer work upper bound",
        })?;
    let work = scan.work.checked_add(reducer_work).ok_or(
        UnicodeFoldedLiteralRunError::ArithmeticOverflow {
            computation: "folded total work upper bound",
        },
    )?;
    Ok(UnicodeFoldedLiteralRunUpperBounds {
        scan,
        reducer_steps,
        count,
        span_sum,
        work,
        scratch_bytes: 0,
    })
}

fn execute(
    plan: &UnicodeFoldedLiteralPlan,
    haystack: &[u8],
    limits: UnicodeFoldedLiteralRunLimits,
    operation: UnicodeFoldedLiteralOperation,
) -> Result<UnicodeFoldedLiteralRunResult, UnicodeFoldedLiteralRunError> {
    if plan.report.operation != operation {
        return Err(UnicodeFoldedLiteralRunError::Invariant {
            detail: "folded operation differs from construction identity",
        });
    }
    let upper = run_upper_bounds(&plan.trie, haystack.len())?;
    enforce_run_limits(upper, limits, operation)?;
    let mut consumed_through = 0_usize;
    let mut reducer_steps = 0_usize;
    let mut count = 0_u64;
    let mut span_sum = 0_u64;
    let mut arithmetic_overflow = false;
    let scan = plan
        .trie
        .scan(haystack, limits.scan, |candidate| {
            let Some(next_steps) = reducer_steps.checked_add(1) else {
                arithmetic_overflow = true;
                return;
            };
            reducer_steps = next_steps;
            if candidate.start() >= consumed_through {
                let Some(next_count) = count.checked_add(1) else {
                    arithmetic_overflow = true;
                    return;
                };
                let Ok(width) = u64::try_from(candidate.end().saturating_sub(candidate.start()))
                else {
                    arithmetic_overflow = true;
                    return;
                };
                let Some(next_span_sum) = span_sum.checked_add(width) else {
                    arithmetic_overflow = true;
                    return;
                };
                count = next_count;
                span_sum = next_span_sum;
                consumed_through = candidate.end();
            }
        })
        .map_err(UnicodeFoldedLiteralRunError::Scan)?;
    if arithmetic_overflow {
        return Err(UnicodeFoldedLiteralRunError::ArithmeticOverflow {
            computation: "actual folded reducer counters",
        });
    }
    if reducer_steps > upper.reducer_steps || count > upper.count || span_sum > upper.span_sum {
        return Err(UnicodeFoldedLiteralRunError::Invariant {
            detail: "folded reducer actual exceeded prospective",
        });
    }
    let reducer_work = reducer_steps
        .checked_mul(REDUCER_WORK_PER_CANDIDATE)
        .ok_or(UnicodeFoldedLiteralRunError::ArithmeticOverflow {
            computation: "actual folded reducer work",
        })?;
    let work = scan.actual.work.checked_add(reducer_work).ok_or(
        UnicodeFoldedLiteralRunError::ArithmeticOverflow {
            computation: "actual folded total work",
        },
    )?;
    if work > upper.work {
        return Err(UnicodeFoldedLiteralRunError::Invariant {
            detail: "folded actual work exceeded prospective",
        });
    }
    let value = match operation {
        UnicodeFoldedLiteralOperation::Count => count,
        UnicodeFoldedLiteralOperation::SpanSum => span_sum,
    };
    Ok(UnicodeFoldedLiteralRunResult {
        value,
        receipt: UnicodeFoldedLiteralRunReceipt {
            upper,
            scan,
            reducer_steps,
            selected_matches: count,
            count,
            span_sum,
            work,
            scratch_bytes: 0,
        },
    })
}

fn enforce_run_limits(
    upper: UnicodeFoldedLiteralRunUpperBounds,
    limits: UnicodeFoldedLiteralRunLimits,
    operation: UnicodeFoldedLiteralOperation,
) -> Result<(), UnicodeFoldedLiteralRunError> {
    let span_limit = if operation == UnicodeFoldedLiteralOperation::SpanSum {
        limits.max_span_sum
    } else {
        u64::MAX
    };
    for (resource, needed, limit) in [
        (
            "reducer steps",
            upper.reducer_steps,
            limits.max_reducer_steps,
        ),
        ("work", upper.work, limits.max_work),
        (
            "scratch bytes",
            upper.scratch_bytes,
            limits.max_scratch_bytes,
        ),
    ] {
        if needed > limit {
            return Err(UnicodeFoldedLiteralRunError::Resource {
                resource,
                needed,
                limit,
            });
        }
    }
    if upper.count > limits.max_count {
        return Err(UnicodeFoldedLiteralRunError::Resource {
            resource: "count",
            needed: usize::try_from(upper.count).unwrap_or(usize::MAX),
            limit: usize::try_from(limits.max_count).unwrap_or(usize::MAX),
        });
    }
    if upper.span_sum > span_limit {
        return Err(UnicodeFoldedLiteralRunError::Resource {
            resource: "span sum",
            needed: usize::try_from(upper.span_sum).unwrap_or(usize::MAX),
            limit: usize::try_from(span_limit).unwrap_or(usize::MAX),
        });
    }
    Ok(())
}

fn checked_add(
    left: usize,
    right: usize,
    computation: &'static str,
) -> Result<usize, UnicodeFoldedLiteralBuildError> {
    left.checked_add(right)
        .ok_or(UnicodeFoldedLiteralBuildError::ArithmeticOverflow { computation })
}
