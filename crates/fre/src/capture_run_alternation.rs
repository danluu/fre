//! Allocation-free capture counting for two source-derived run alternations.
//!
//! The admitted HIR is either a source-ordered alternation of captures around
//! pairwise-disjoint greedy singleton-byte runs, or a descending alternation
//! of captures around exact repetitions of one shared byte/scalar class.
//! Both shapes have exactly one participating explicit capture per match.

use core::{fmt, mem::size_of};

use fre_syntax::{
    AdmissionPolicy, CanonicalPattern, CompatibilityProfile, RustProfile, SafetyEnvelope,
};
use regex_syntax::hir::{Class, Hir, HirKind};

pub const CAPTURE_RUN_ALTERNATION_PLAN_ID: &str = "capture-run-alternation-linear-v1";
pub const CAPTURE_RUN_ALTERNATION_COUNT_OPERATION_ID: &str =
    "capture-run-alternation.participation-count.v1";
pub const CAPTURE_RUN_ALTERNATION_ALGORITHM_VERSION: u32 = 1;
pub const CAPTURE_RUN_ALTERNATION_ACCOUNTING_VERSION: u32 = 2;

const MAX_CLASS_RANGES: usize = 1_024;
const MAX_EXACT_LENGTH: u32 = 31;
const MAX_UTF8_PROBES_PER_POSITION: usize = 4;
const GROUPS_PER_MATCH: usize = 2;
const DIGEST_OFFSET_A: u64 = 0xcbf2_9ce4_8422_2325;
const DIGEST_OFFSET_B: u64 = 0x8422_2325_cbf2_9ce4;
const DIGEST_PRIME_A: u64 = 0x0000_0100_0000_01b3;
const DIGEST_PRIME_B: u64 = 0x0000_0100_0000_01cf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureRunAlternationKind {
    DisjointByteRuns,
    DescendingExactByteClass,
    DescendingExactUnicodeClass,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureRunAlternationBuildLimits {
    pub admission: AdmissionPolicy,
    pub syntax_safety: SafetyEnvelope,
    pub max_inspection_work: usize,
    pub max_hir_nodes: usize,
    pub max_class_ranges: usize,
    pub max_alternatives: usize,
    pub max_exact_length: u32,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl Default for CaptureRunAlternationBuildLimits {
    fn default() -> Self {
        Self {
            admission: AdmissionPolicy::default(),
            syntax_safety: SafetyEnvelope::default(),
            max_inspection_work: 16_384,
            max_hir_nodes: 4_096,
            max_class_ranges: MAX_CLASS_RANGES,
            max_alternatives: 256,
            max_exact_length: MAX_EXACT_LENGTH,
            max_persistent_bytes: 1 << 20,
            max_peak_bytes: 1 << 20,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureRunAlternationHirAccounting {
    pub hir_nodes: usize,
    pub class_ranges: usize,
    pub alternatives: usize,
    pub captures: usize,
    pub class_equality_work: usize,
    pub mask_initializations: usize,
    pub range_materializations: usize,
    pub inspection_work: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureRunAlternationOperationIdentity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub kind: CaptureRunAlternationKind,
    pub alternatives: usize,
    pub exact_lengths: u32,
    pub minimum_length: u32,
    pub maximum_length: Option<u32>,
    pub class_ranges: usize,
    pub class_digest: [u64; 2],
    pub participating_captures_per_match: usize,
    pub groups_per_match: usize,
    pub line_partition_invariant: bool,
    pub non_overlapping: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureRunAlternationPlanIdentity {
    pub profile: RustProfile,
    pub source_digest: [u64; 2],
    pub algorithm_version: u32,
    pub accounting_version: u32,
    pub operation: CaptureRunAlternationOperationIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureRunAlternationBuildReport {
    pub identity: CaptureRunAlternationPlanIdentity,
    pub hir: CaptureRunAlternationHirAccounting,
    pub retained_class_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum CaptureRunAlternationBuildError {
    Syntax(fre_syntax::ParseError),
    Unsupported(&'static str),
    Resource {
        resource: &'static str,
        needed: usize,
        limit: usize,
    },
    AllocationFailure {
        resource: &'static str,
        bytes: usize,
    },
    ArithmeticOverflow(&'static str),
    InternalInvariant(&'static str),
}

impl fmt::Display for CaptureRunAlternationBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(error) => write!(formatter, "capture run-alternation syntax: {error}"),
            Self::Unsupported(reason) => {
                write!(
                    formatter,
                    "unsupported capture run-alternation shape: {reason}"
                )
            }
            Self::Resource {
                resource,
                needed,
                limit,
            } => write!(
                formatter,
                "capture run-alternation {resource} needs {needed}, limit is {limit}"
            ),
            Self::AllocationFailure { resource, bytes } => write!(
                formatter,
                "capture run-alternation failed to allocate {bytes} bytes for {resource}"
            ),
            Self::ArithmeticOverflow(computation) => write!(
                formatter,
                "capture run-alternation overflow while computing {computation}"
            ),
            Self::InternalInvariant(message) => {
                write!(formatter, "capture run-alternation invariant: {message}")
            }
        }
    }
}

impl std::error::Error for CaptureRunAlternationBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Syntax(error) => Some(error),
            Self::Unsupported(_)
            | Self::Resource { .. }
            | Self::AllocationFailure { .. }
            | Self::ArithmeticOverflow(_)
            | Self::InternalInvariant(_) => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureRunAlternationRunLimits {
    pub max_input_bytes: usize,
    pub max_source_reads: usize,
    pub max_decoded_units: usize,
    pub max_class_comparisons: usize,
    pub max_run_events: usize,
    pub max_matches: usize,
    pub max_capture_count: usize,
    pub max_work: usize,
    pub max_sequential_bytes: usize,
    pub max_peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureRunAlternationRunUpperBounds {
    pub input_bytes: usize,
    pub source_reads: usize,
    pub decoded_units: usize,
    pub class_comparisons: usize,
    pub run_events: usize,
    pub matches: usize,
    pub capture_count: usize,
    pub work: usize,
    pub sequential_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CaptureRunAlternationRunActual {
    pub source_reads: usize,
    pub decoded_units: usize,
    pub class_comparisons: usize,
    pub run_events: usize,
    pub matches: usize,
    pub capture_count: usize,
    pub work: usize,
    pub sequential_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureRunAlternationCountResult {
    pub identity: CaptureRunAlternationOperationIdentity,
    pub capture_count: usize,
    pub upper_bounds: CaptureRunAlternationRunUpperBounds,
    pub actual: CaptureRunAlternationRunActual,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureRunAlternationRunResource {
    InputBytes,
    SourceReads,
    DecodedUnits,
    ClassComparisons,
    RunEvents,
    Matches,
    CaptureCount,
    Work,
    SequentialBytes,
    PeakBytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CaptureRunAlternationRunError {
    Resource {
        resource: CaptureRunAlternationRunResource,
        needed: usize,
        limit: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    AccountingInvariant {
        resource: CaptureRunAlternationRunResource,
        actual: usize,
        upper: usize,
    },
}

impl fmt::Display for CaptureRunAlternationRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "capture run-alternation reduction failed: {self:?}"
        )
    }
}

impl std::error::Error for CaptureRunAlternationRunError {}

#[derive(Clone, Copy, Debug, Default)]
struct ScalarRange {
    start: u32,
    end: u32,
}

#[derive(Clone, Debug)]
enum CaptureRunAlternationMatcher {
    DisjointByteRuns {
        members: [u64; 4],
    },
    ExactByteClass {
        members: [u64; 4],
        exact_lengths: u32,
    },
    ExactUnicodeClass {
        ranges: Box<[ScalarRange]>,
        exact_lengths: u32,
    },
}

#[derive(Clone, Debug)]
pub struct CaptureRunAlternationBuilder {
    pattern: String,
    profile: RustProfile,
    limits: CaptureRunAlternationBuildLimits,
}

impl CaptureRunAlternationBuilder {
    #[must_use]
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            profile: RustProfile::default(),
            limits: CaptureRunAlternationBuildLimits::default(),
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
    pub const fn limits(mut self, limits: CaptureRunAlternationBuildLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn build(self) -> Result<CaptureRunAlternationPlan, CaptureRunAlternationBuildError> {
        if self.profile.options.case_insensitive {
            return Err(CaptureRunAlternationBuildError::Unsupported(
                "case-insensitive alternatives are not admitted",
            ));
        }
        let profile = self.profile;
        let parsed = fre_syntax::parse(
            fre_syntax::ParseRequest::rust(
                self.pattern,
                CompatibilityProfile::RustBytes(profile.clone()),
            )
            .with_admission(self.limits.admission)
            .with_safety_envelope(self.limits.syntax_safety),
        )
        .map_err(CaptureRunAlternationBuildError::Syntax)?;
        let source_digest = digest_bytes(parsed.key.pattern.as_bytes());
        let summary = parsed.summary;
        let CanonicalPattern::Rust(rust) = parsed.pattern else {
            return Err(CaptureRunAlternationBuildError::InternalInvariant(
                "Rust byte request produced a non-Rust HIR",
            ));
        };
        let inspection = inspect(&rust.hir, profile.options.unicode, self.limits)?;
        let explicit_captures = usize::try_from(summary.captures).map_err(|_| {
            CaptureRunAlternationBuildError::ArithmeticOverflow("explicit capture count")
        })?;
        if explicit_captures != inspection.accounting.captures
            || explicit_captures != inspection.accounting.alternatives
        {
            return Err(CaptureRunAlternationBuildError::InternalInvariant(
                "parse capture count differs from direct alternatives",
            ));
        }
        let retained_class_bytes = match &inspection.matcher {
            CaptureRunAlternationMatcher::ExactUnicodeClass { ranges, .. } => {
                ranges.len().checked_mul(size_of::<ScalarRange>()).ok_or(
                    CaptureRunAlternationBuildError::ArithmeticOverflow("retained class bytes"),
                )?
            }
            CaptureRunAlternationMatcher::DisjointByteRuns { .. }
            | CaptureRunAlternationMatcher::ExactByteClass { .. } => 0,
        };
        let persistent_bytes = size_of::<CaptureRunAlternationPlan>()
            .checked_add(retained_class_bytes)
            .ok_or(CaptureRunAlternationBuildError::ArithmeticOverflow(
                "persistent bytes",
            ))?;
        enforce_build(
            "persistent bytes",
            persistent_bytes,
            self.limits.max_persistent_bytes,
        )?;
        enforce_build("peak bytes", persistent_bytes, self.limits.max_peak_bytes)?;
        let operation = CaptureRunAlternationOperationIdentity {
            plan_id: CAPTURE_RUN_ALTERNATION_PLAN_ID,
            operation_id: CAPTURE_RUN_ALTERNATION_COUNT_OPERATION_ID,
            kind: inspection.kind,
            alternatives: inspection.accounting.alternatives,
            exact_lengths: inspection.exact_lengths,
            minimum_length: inspection.minimum_length,
            maximum_length: inspection.maximum_length,
            class_ranges: inspection.accounting.class_ranges,
            class_digest: inspection.class_digest,
            participating_captures_per_match: 1,
            groups_per_match: GROUPS_PER_MATCH,
            line_partition_invariant: true,
            non_overlapping: true,
        };
        let report = CaptureRunAlternationBuildReport {
            identity: CaptureRunAlternationPlanIdentity {
                profile,
                source_digest,
                algorithm_version: CAPTURE_RUN_ALTERNATION_ALGORITHM_VERSION,
                accounting_version: CAPTURE_RUN_ALTERNATION_ACCOUNTING_VERSION,
                operation,
            },
            hir: inspection.accounting,
            retained_class_bytes,
            persistent_bytes,
            peak_bytes: persistent_bytes,
        };
        Ok(CaptureRunAlternationPlan {
            matcher: inspection.matcher,
            report,
        })
    }
}

#[derive(Clone, Debug)]
pub struct CaptureRunAlternationPlan {
    matcher: CaptureRunAlternationMatcher,
    report: CaptureRunAlternationBuildReport,
}

impl CaptureRunAlternationPlan {
    #[must_use]
    pub const fn build_report(&self) -> &CaptureRunAlternationBuildReport {
        &self.report
    }

    /// Verify that the public report still closes over the retained matcher.
    #[must_use]
    pub fn authenticates_identity(&self) -> bool {
        let report = &self.report;
        let operation = report.identity.operation;
        let hir = report.hir;
        let Some(expected_hir_nodes) = operation
            .alternatives
            .checked_mul(3)
            .and_then(|value| value.checked_add(1))
        else {
            return false;
        };
        let Some(expected_inspection_work) = hir
            .hir_nodes
            .checked_add(operation.alternatives)
            .and_then(|value| value.checked_add(hir.class_equality_work))
            .and_then(|value| value.checked_add(hir.mask_initializations))
            .and_then(|value| value.checked_add(hir.range_materializations))
        else {
            return false;
        };
        let matcher_closes = match &self.matcher {
            CaptureRunAlternationMatcher::DisjointByteRuns { members } => {
                operation.kind == CaptureRunAlternationKind::DisjointByteRuns
                    && !report.identity.profile.options.unicode
                    && operation.exact_lengths == 0
                    && operation.minimum_length == 1
                    && operation.maximum_length.is_none()
                    && operation.class_ranges == 0
                    && operation.class_digest == digest_words(*members)
                    && usize::try_from(members.iter().map(|word| word.count_ones()).sum::<u32>())
                        .is_ok_and(|members| members == operation.alternatives)
                    && hir.class_equality_work == 0
                    && hir.mask_initializations == operation.alternatives
                    && hir.range_materializations == 0
            }
            CaptureRunAlternationMatcher::ExactByteClass {
                members,
                exact_lengths,
            } => {
                operation.kind == CaptureRunAlternationKind::DescendingExactByteClass
                    && !report.identity.profile.options.unicode
                    && exact_length_identity_closes(operation, *exact_lengths)
                    && byte_range_count(*members) == operation.class_ranges
                    && operation.class_ranges > 0
                    && operation.class_digest == digest_words(*members)
                    && expected_class_equality_work(operation.alternatives, operation.class_ranges)
                        .is_some_and(|expected| hir.class_equality_work == expected)
                    && hir.mask_initializations
                        == usize::try_from(
                            members.iter().map(|word| word.count_ones()).sum::<u32>(),
                        )
                        .unwrap_or(usize::MAX)
                    && hir.range_materializations == operation.class_ranges
            }
            CaptureRunAlternationMatcher::ExactUnicodeClass {
                ranges,
                exact_lengths,
            } => {
                operation.kind == CaptureRunAlternationKind::DescendingExactUnicodeClass
                    && report.identity.profile.options.unicode
                    && exact_length_identity_closes(operation, *exact_lengths)
                    && operation.class_ranges == ranges.len()
                    && operation.class_ranges > 0
                    && operation.class_digest == digest_ranges(ranges)
                    && expected_class_equality_work(operation.alternatives, operation.class_ranges)
                        .is_some_and(|expected| hir.class_equality_work == expected)
                    && hir.mask_initializations == 0
                    && ranges
                        .len()
                        .checked_mul(2)
                        .is_some_and(|expected| hir.range_materializations == expected)
            }
        };
        let retained_class_bytes = match &self.matcher {
            CaptureRunAlternationMatcher::ExactUnicodeClass { ranges, .. } => {
                ranges.len().checked_mul(size_of::<ScalarRange>())
            }
            CaptureRunAlternationMatcher::DisjointByteRuns { .. }
            | CaptureRunAlternationMatcher::ExactByteClass { .. } => Some(0),
        };
        matcher_closes
            && report.identity.algorithm_version == CAPTURE_RUN_ALTERNATION_ALGORITHM_VERSION
            && report.identity.accounting_version == CAPTURE_RUN_ALTERNATION_ACCOUNTING_VERSION
            && operation.plan_id == CAPTURE_RUN_ALTERNATION_PLAN_ID
            && operation.operation_id == CAPTURE_RUN_ALTERNATION_COUNT_OPERATION_ID
            && operation.alternatives >= 2
            && operation.participating_captures_per_match == 1
            && operation.groups_per_match == GROUPS_PER_MATCH
            && operation.line_partition_invariant
            && operation.non_overlapping
            && !report.identity.profile.options.case_insensitive
            && hir.hir_nodes == expected_hir_nodes
            && hir.class_ranges == operation.class_ranges
            && hir.alternatives == operation.alternatives
            && hir.captures == operation.alternatives
            && hir.inspection_work == expected_inspection_work
            && retained_class_bytes == Some(report.retained_class_bytes)
            && size_of::<Self>()
                .checked_add(report.retained_class_bytes)
                .is_some_and(|expected| report.persistent_bytes == expected)
            && report.peak_bytes == report.persistent_bytes
    }

    pub fn run_upper_bounds(
        &self,
        input_bytes: usize,
    ) -> Result<CaptureRunAlternationRunUpperBounds, CaptureRunAlternationRunError> {
        let identity = self.report.identity.operation;
        let minimum = usize::try_from(identity.minimum_length).map_err(|_| {
            CaptureRunAlternationRunError::ArithmeticOverflow {
                computation: "minimum length as usize",
            }
        })?;
        let matches = match identity.kind {
            CaptureRunAlternationKind::DisjointByteRuns => input_bytes,
            CaptureRunAlternationKind::DescendingExactByteClass
            | CaptureRunAlternationKind::DescendingExactUnicodeClass => input_bytes
                .checked_div(minimum)
                .ok_or(CaptureRunAlternationRunError::ArithmeticOverflow {
                    computation: "input bytes divided by minimum length",
                })?,
        };
        let capture_count = matches.checked_mul(GROUPS_PER_MATCH).ok_or(
            CaptureRunAlternationRunError::ArithmeticOverflow {
                computation: "capture-count upper bound",
            },
        )?;
        let (source_reads, comparisons_per_unit) = match &self.matcher {
            CaptureRunAlternationMatcher::ExactUnicodeClass { ranges, .. } => {
                let source_reads = input_bytes
                    .checked_mul(MAX_UTF8_PROBES_PER_POSITION)
                    .ok_or(CaptureRunAlternationRunError::ArithmeticOverflow {
                        computation: "Unicode source-read upper bound",
                    })?;
                (source_reads, binary_search_comparison_bound(ranges.len()))
            }
            CaptureRunAlternationMatcher::DisjointByteRuns { .. }
            | CaptureRunAlternationMatcher::ExactByteClass { .. } => (input_bytes, 0),
        };
        let class_comparisons = input_bytes.checked_mul(comparisons_per_unit).ok_or(
            CaptureRunAlternationRunError::ArithmeticOverflow {
                computation: "class-comparison upper bound",
            },
        )?;
        let work = source_reads
            .checked_add(input_bytes)
            .and_then(|value| value.checked_add(input_bytes))
            .and_then(|value| value.checked_add(class_comparisons))
            .and_then(|value| value.checked_add(matches))
            .ok_or(CaptureRunAlternationRunError::ArithmeticOverflow {
                computation: "work upper bound",
            })?;
        Ok(CaptureRunAlternationRunUpperBounds {
            input_bytes,
            source_reads,
            decoded_units: input_bytes,
            class_comparisons,
            run_events: input_bytes,
            matches,
            capture_count,
            work,
            sequential_bytes: source_reads,
            peak_bytes: self.report.persistent_bytes,
        })
    }

    pub fn capture_count(
        &self,
        haystack: &[u8],
        limits: CaptureRunAlternationRunLimits,
    ) -> Result<CaptureRunAlternationCountResult, CaptureRunAlternationRunError> {
        let upper = self.run_upper_bounds(haystack.len())?;
        enforce_run_limits(upper, limits)?;
        let actual = match &self.matcher {
            CaptureRunAlternationMatcher::DisjointByteRuns { members } => {
                scan_disjoint_byte_runs(haystack, *members)?
            }
            CaptureRunAlternationMatcher::ExactByteClass {
                members,
                exact_lengths,
            } => scan_exact_byte_class(haystack, *members, *exact_lengths)?,
            CaptureRunAlternationMatcher::ExactUnicodeClass {
                ranges,
                exact_lengths,
            } => scan_exact_unicode_class(haystack, ranges, *exact_lengths)?,
        };
        verify_actual(actual, upper)?;
        Ok(CaptureRunAlternationCountResult {
            identity: self.report.identity.operation,
            capture_count: actual.capture_count,
            upper_bounds: upper,
            actual,
        })
    }
}

struct Inspection {
    kind: CaptureRunAlternationKind,
    matcher: CaptureRunAlternationMatcher,
    exact_lengths: u32,
    minimum_length: u32,
    maximum_length: Option<u32>,
    class_digest: [u64; 2],
    accounting: CaptureRunAlternationHirAccounting,
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "the preceding nonzero-mask check proves leading_zeros is at most 31"
)]
fn exact_length_identity_closes(
    operation: CaptureRunAlternationOperationIdentity,
    retained_mask: u32,
) -> bool {
    retained_mask != 0
        && operation.exact_lengths == retained_mask
        && usize::try_from(retained_mask.count_ones())
            .is_ok_and(|count| count == operation.alternatives)
        && operation.minimum_length == retained_mask.trailing_zeros()
        && operation.maximum_length == Some(u32::BITS - 1 - retained_mask.leading_zeros())
}

fn expected_class_equality_work(alternatives: usize, class_ranges: usize) -> Option<usize> {
    alternatives
        .checked_sub(1)?
        .checked_mul(class_ranges.checked_add(1)?)
}

fn inspect(
    hir: &Hir,
    unicode: bool,
    limits: CaptureRunAlternationBuildLimits,
) -> Result<Inspection, CaptureRunAlternationBuildError> {
    let HirKind::Alternation(alternatives) = hir.kind() else {
        return Err(CaptureRunAlternationBuildError::Unsupported(
            "root must be a capture alternation",
        ));
    };
    if alternatives.len() < 2 {
        return Err(CaptureRunAlternationBuildError::Unsupported(
            "capture alternation must contain at least two branches",
        ));
    }
    enforce_build("alternatives", alternatives.len(), limits.max_alternatives)?;
    let HirKind::Capture(first_capture) = alternatives[0].kind() else {
        return Err(CaptureRunAlternationBuildError::Unsupported(
            "every alternative must be one direct capture",
        ));
    };
    let HirKind::Repetition(first_repetition) = first_capture.sub.kind() else {
        return Err(CaptureRunAlternationBuildError::Unsupported(
            "every capture must directly contain one repetition",
        ));
    };
    if first_repetition.min == 1 && first_repetition.max.is_none() {
        inspect_disjoint_byte_runs(alternatives, unicode, limits)
    } else {
        inspect_exact_class_runs(alternatives, unicode, limits)
    }
}

fn base_accounting(
    alternatives: usize,
) -> Result<CaptureRunAlternationHirAccounting, CaptureRunAlternationBuildError> {
    let branch_nodes =
        alternatives
            .checked_mul(3)
            .ok_or(CaptureRunAlternationBuildError::ArithmeticOverflow(
                "branch HIR nodes",
            ))?;
    let hir_nodes =
        branch_nodes
            .checked_add(1)
            .ok_or(CaptureRunAlternationBuildError::ArithmeticOverflow(
                "total HIR nodes",
            ))?;
    Ok(CaptureRunAlternationHirAccounting {
        hir_nodes,
        class_ranges: 0,
        alternatives,
        captures: alternatives,
        class_equality_work: 0,
        mask_initializations: 0,
        range_materializations: 0,
        inspection_work: hir_nodes,
    })
}

fn inspect_disjoint_byte_runs(
    alternatives: &[Hir],
    unicode: bool,
    limits: CaptureRunAlternationBuildLimits,
) -> Result<Inspection, CaptureRunAlternationBuildError> {
    if unicode {
        return Err(CaptureRunAlternationBuildError::Unsupported(
            "disjoint singleton-byte runs require Unicode off",
        ));
    }
    let mut accounting = base_accounting(alternatives.len())?;
    enforce_build("HIR nodes", accounting.hir_nodes, limits.max_hir_nodes)?;
    let mut members = [0_u64; 4];
    for alternative in alternatives {
        charge_inspection(&mut accounting, 1, limits)?;
        let HirKind::Capture(capture) = alternative.kind() else {
            return Err(CaptureRunAlternationBuildError::Unsupported(
                "every alternative must be one direct capture",
            ));
        };
        let HirKind::Repetition(repetition) = capture.sub.kind() else {
            return Err(CaptureRunAlternationBuildError::Unsupported(
                "every capture must contain one singleton-byte run",
            ));
        };
        if repetition.min != 1 || repetition.max.is_some() || !repetition.greedy {
            return Err(CaptureRunAlternationBuildError::Unsupported(
                "singleton-byte runs must be greedy one-or-more",
            ));
        }
        let HirKind::Literal(literal) = repetition.sub.kind() else {
            return Err(CaptureRunAlternationBuildError::Unsupported(
                "run body must be one literal byte",
            ));
        };
        let [byte] = literal.0.as_ref() else {
            return Err(CaptureRunAlternationBuildError::Unsupported(
                "run literal must contain exactly one byte",
            ));
        };
        if matches!(*byte, b'\r' | b'\n') {
            return Err(CaptureRunAlternationBuildError::Unsupported(
                "run literals must be invariant under line partitioning",
            ));
        }
        let word = usize::from(*byte) / 64;
        let bit = 1_u64 << (usize::from(*byte) % 64);
        if members[word] & bit != 0 {
            return Err(CaptureRunAlternationBuildError::Unsupported(
                "singleton-byte runs must be pairwise disjoint",
            ));
        }
        charge_mask_initializations(&mut accounting, 1, limits)?;
        members[word] |= bit;
    }
    Ok(Inspection {
        kind: CaptureRunAlternationKind::DisjointByteRuns,
        matcher: CaptureRunAlternationMatcher::DisjointByteRuns { members },
        exact_lengths: 0,
        minimum_length: 1,
        maximum_length: None,
        class_digest: digest_words(members),
        accounting,
    })
}

fn inspect_exact_class_runs(
    alternatives: &[Hir],
    unicode: bool,
    limits: CaptureRunAlternationBuildLimits,
) -> Result<Inspection, CaptureRunAlternationBuildError> {
    let mut accounting = base_accounting(alternatives.len())?;
    enforce_build("HIR nodes", accounting.hir_nodes, limits.max_hir_nodes)?;
    let mut shared_class = None::<&Class>;
    let mut exact_lengths = 0_u32;
    let mut previous = None::<u32>;
    let mut maximum = None::<u32>;
    let mut minimum = 0_u32;
    for alternative in alternatives {
        charge_inspection(&mut accounting, 1, limits)?;
        let HirKind::Capture(capture) = alternative.kind() else {
            return Err(CaptureRunAlternationBuildError::Unsupported(
                "every alternative must be one direct capture",
            ));
        };
        let HirKind::Repetition(repetition) = capture.sub.kind() else {
            return Err(CaptureRunAlternationBuildError::Unsupported(
                "every capture must contain one exact class repetition",
            ));
        };
        if repetition.min == 0 || repetition.max != Some(repetition.min) || !repetition.greedy {
            return Err(CaptureRunAlternationBuildError::Unsupported(
                "class repetitions must be positive, exact and greedy",
            ));
        }
        if previous.is_some_and(|prior| prior <= repetition.min) {
            return Err(CaptureRunAlternationBuildError::Unsupported(
                "exact repetitions must be in strictly descending source order",
            ));
        }
        if repetition.min > MAX_EXACT_LENGTH {
            return Err(CaptureRunAlternationBuildError::Unsupported(
                "exact repetition exceeds the intrinsic length-mask width",
            ));
        }
        if repetition.min > limits.max_exact_length {
            return Err(CaptureRunAlternationBuildError::Resource {
                resource: "exact repetition length",
                needed: usize::try_from(repetition.min).unwrap_or(usize::MAX),
                limit: usize::try_from(limits.max_exact_length).unwrap_or(usize::MAX),
            });
        }
        let HirKind::Class(class) = repetition.sub.kind() else {
            return Err(CaptureRunAlternationBuildError::Unsupported(
                "exact repetition body must be one class",
            ));
        };
        let range_count = class_range_count(class);
        enforce_intrinsic_class_ranges(range_count)?;
        enforce_build("class ranges", range_count, limits.max_class_ranges)?;
        if let Some(shared) = shared_class {
            let equality_work = class_range_count(shared)
                .max(range_count)
                .checked_add(1)
                .ok_or(CaptureRunAlternationBuildError::ArithmeticOverflow(
                    "class equality work",
                ))?;
            charge_class_equality(&mut accounting, equality_work, limits)?;
            if shared != class {
                return Err(CaptureRunAlternationBuildError::Unsupported(
                    "every exact repetition must use the same class",
                ));
            }
        }
        shared_class.get_or_insert(class);
        maximum.get_or_insert(repetition.min);
        minimum = repetition.min;
        previous = Some(repetition.min);
        exact_lengths |= 1_u32 << repetition.min;
    }
    let class = shared_class.ok_or(CaptureRunAlternationBuildError::InternalInvariant(
        "nonempty alternatives lost their shared class",
    ))?;
    let (kind, matcher, class_ranges, class_digest) =
        build_exact_matcher(class, unicode, exact_lengths, &mut accounting, limits)?;
    accounting.class_ranges = class_ranges;
    Ok(Inspection {
        kind,
        matcher,
        exact_lengths,
        minimum_length: minimum,
        maximum_length: maximum,
        class_digest,
        accounting,
    })
}

fn build_exact_matcher(
    class: &Class,
    unicode: bool,
    exact_lengths: u32,
    accounting: &mut CaptureRunAlternationHirAccounting,
    limits: CaptureRunAlternationBuildLimits,
) -> Result<
    (
        CaptureRunAlternationKind,
        CaptureRunAlternationMatcher,
        usize,
        [u64; 2],
    ),
    CaptureRunAlternationBuildError,
> {
    match (unicode, class) {
        (false, Class::Bytes(class)) => {
            let range_count = class.ranges().len();
            enforce_intrinsic_class_ranges(range_count)?;
            enforce_build("class ranges", range_count, limits.max_class_ranges)?;
            let mut initializations = 0_usize;
            for range in class.ranges() {
                let width = usize::from(range.end())
                    .checked_sub(usize::from(range.start()))
                    .and_then(|value| value.checked_add(1))
                    .ok_or(CaptureRunAlternationBuildError::ArithmeticOverflow(
                        "byte-mask initialization work",
                    ))?;
                initializations = initializations.checked_add(width).ok_or(
                    CaptureRunAlternationBuildError::ArithmeticOverflow(
                        "byte-mask initialization work",
                    ),
                )?;
            }
            charge_range_materializations(accounting, range_count, limits)?;
            charge_mask_initializations(accounting, initializations, limits)?;
            let mut members = [0_u64; 4];
            for range in class.ranges() {
                for byte in range.start()..=range.end() {
                    if matches!(byte, b'\r' | b'\n') {
                        return Err(CaptureRunAlternationBuildError::Unsupported(
                            "shared byte class must exclude line terminators",
                        ));
                    }
                    members[usize::from(byte) / 64] |= 1_u64 << (usize::from(byte) % 64);
                }
            }
            Ok((
                CaptureRunAlternationKind::DescendingExactByteClass,
                CaptureRunAlternationMatcher::ExactByteClass {
                    members,
                    exact_lengths,
                },
                range_count,
                digest_words(members),
            ))
        }
        (true, Class::Unicode(class)) => {
            let range_count = class.ranges().len();
            enforce_intrinsic_class_ranges(range_count)?;
            enforce_build("class ranges", range_count, limits.max_class_ranges)?;
            let range_work = range_count.checked_mul(2).ok_or(
                CaptureRunAlternationBuildError::ArithmeticOverflow(
                    "Unicode range validation and materialization work",
                ),
            )?;
            charge_range_materializations(accounting, range_work, limits)?;
            let retained_class_bytes = range_count.checked_mul(size_of::<ScalarRange>()).ok_or(
                CaptureRunAlternationBuildError::ArithmeticOverflow("retained class bytes"),
            )?;
            let persistent_bytes = size_of::<CaptureRunAlternationPlan>()
                .checked_add(retained_class_bytes)
                .ok_or(CaptureRunAlternationBuildError::ArithmeticOverflow(
                    "persistent bytes",
                ))?;
            enforce_build(
                "persistent bytes",
                persistent_bytes,
                limits.max_persistent_bytes,
            )?;
            enforce_build("peak bytes", persistent_bytes, limits.max_peak_bytes)?;
            for range in class.ranges() {
                if (range.start() <= '\n' && '\n' <= range.end())
                    || (range.start() <= '\r' && '\r' <= range.end())
                {
                    return Err(CaptureRunAlternationBuildError::Unsupported(
                        "shared Unicode class must exclude line terminators",
                    ));
                }
            }
            let mut ranges = Vec::new();
            ranges.try_reserve_exact(range_count).map_err(|_| {
                CaptureRunAlternationBuildError::AllocationFailure {
                    resource: "retained Unicode class ranges",
                    bytes: retained_class_bytes,
                }
            })?;
            for range in class.ranges() {
                ranges.push(ScalarRange {
                    start: u32::from(range.start()),
                    end: u32::from(range.end()),
                });
            }
            let digest = digest_ranges(&ranges);
            Ok((
                CaptureRunAlternationKind::DescendingExactUnicodeClass,
                CaptureRunAlternationMatcher::ExactUnicodeClass {
                    ranges: ranges.into_boxed_slice(),
                    exact_lengths,
                },
                range_count,
                digest,
            ))
        }
        (false, Class::Unicode(_)) | (true, Class::Bytes(_)) => {
            Err(CaptureRunAlternationBuildError::Unsupported(
                "class representation differs from Unicode mode",
            ))
        }
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "the cursor only increments while it is strictly below the slice length"
)]
fn scan_disjoint_byte_runs(
    haystack: &[u8],
    members: [u64; 4],
) -> Result<CaptureRunAlternationRunActual, CaptureRunAlternationRunError> {
    let mut matches = 0_usize;
    let mut run_events = 0_usize;
    let mut previous_member = None::<u8>;
    for &byte in haystack {
        if previous_member == Some(byte) {
            continue;
        }
        if byte_member(members, byte) {
            matches += 1;
            run_events += 1;
            previous_member = Some(byte);
        } else {
            previous_member = None;
        }
    }
    finish_actual(haystack.len(), haystack.len(), 0, run_events, matches)
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "the cursor and run length only increment while consuming the bounded slice"
)]
fn scan_exact_byte_class(
    haystack: &[u8],
    members: [u64; 4],
    exact_lengths: u32,
) -> Result<CaptureRunAlternationRunActual, CaptureRunAlternationRunError> {
    let mut matches = 0_usize;
    let mut run_events = 0_usize;
    let mut run_length = 0_usize;
    for &byte in haystack {
        if byte_member(members, byte) {
            if run_length == 0 {
                run_events += 1;
            }
            run_length += 1;
        } else if run_length != 0 {
            matches += count_run_matches(run_length, exact_lengths)?;
            run_length = 0;
        }
    }
    if run_length != 0 {
        matches += count_run_matches(run_length, exact_lengths)?;
    }
    finish_actual(haystack.len(), haystack.len(), 0, run_events, matches)
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "UTF-8 widths are validated against the remaining slice before cursor advancement"
)]
fn scan_exact_unicode_class(
    haystack: &[u8],
    ranges: &[ScalarRange],
    exact_lengths: u32,
) -> Result<CaptureRunAlternationRunActual, CaptureRunAlternationRunError> {
    let mut position = 0_usize;
    let mut source_reads = 0_usize;
    let mut decoded_units = 0_usize;
    let mut comparisons = 0_usize;
    let mut run_length = 0_usize;
    let mut run_events = 0_usize;
    let mut matches = 0_usize;
    while position < haystack.len() {
        let decoded = decode_first(&haystack[position..]);
        let in_class = decoded
            .scalar
            .is_some_and(|scalar| scalar_member(ranges, scalar, &mut comparisons));
        position += decoded.width;
        source_reads += decoded.source_reads;
        decoded_units += 1;
        if in_class {
            if run_length == 0 {
                run_events += 1;
            }
            run_length += 1;
        } else if run_length != 0 {
            matches += count_run_matches(run_length, exact_lengths)?;
            run_length = 0;
        }
    }
    if run_length != 0 {
        matches += count_run_matches(run_length, exact_lengths)?;
    }
    finish_actual(
        source_reads,
        decoded_units,
        comparisons,
        run_events,
        matches,
    )
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "construction proves a nonzero length mask bounded to bits 1..=31; modulo makes the tail smaller than its positive maximum"
)]
fn count_run_matches(
    mut run_length: usize,
    exact_lengths: u32,
) -> Result<usize, CaptureRunAlternationRunError> {
    let maximum = usize::try_from(u32::BITS - 1 - exact_lengths.leading_zeros()).map_err(|_| {
        CaptureRunAlternationRunError::ArithmeticOverflow {
            computation: "maximum exact length as usize",
        }
    })?;
    let minimum = usize::try_from(exact_lengths.trailing_zeros()).map_err(|_| {
        CaptureRunAlternationRunError::ArithmeticOverflow {
            computation: "minimum exact length as usize",
        }
    })?;
    let mut matches = run_length / maximum;
    run_length %= maximum;
    while run_length >= minimum {
        let eligible = exact_lengths
            & ((1_u32
                << u32::try_from(run_length + 1).map_err(|_| {
                    CaptureRunAlternationRunError::ArithmeticOverflow {
                        computation: "remaining run length as u32",
                    }
                })?)
                - 1);
        if eligible == 0 {
            break;
        }
        let width = usize::try_from(u32::BITS - 1 - eligible.leading_zeros()).map_err(|_| {
            CaptureRunAlternationRunError::ArithmeticOverflow {
                computation: "eligible exact length as usize",
            }
        })?;
        matches =
            matches
                .checked_add(1)
                .ok_or(CaptureRunAlternationRunError::ArithmeticOverflow {
                    computation: "run match count",
                })?;
        run_length = run_length.checked_sub(width).ok_or(
            CaptureRunAlternationRunError::ArithmeticOverflow {
                computation: "run remainder",
            },
        )?;
    }
    Ok(matches)
}

fn finish_actual(
    source_reads: usize,
    decoded_units: usize,
    class_comparisons: usize,
    run_events: usize,
    matches: usize,
) -> Result<CaptureRunAlternationRunActual, CaptureRunAlternationRunError> {
    let capture_count = matches.checked_mul(GROUPS_PER_MATCH).ok_or(
        CaptureRunAlternationRunError::ArithmeticOverflow {
            computation: "actual capture count",
        },
    )?;
    let work = source_reads
        .checked_add(decoded_units)
        .and_then(|value| value.checked_add(class_comparisons))
        .and_then(|value| value.checked_add(run_events))
        .and_then(|value| value.checked_add(matches))
        .ok_or(CaptureRunAlternationRunError::ArithmeticOverflow {
            computation: "actual work",
        })?;
    Ok(CaptureRunAlternationRunActual {
        source_reads,
        decoded_units,
        class_comparisons,
        run_events,
        matches,
        capture_count,
        work,
        sequential_bytes: source_reads,
    })
}

fn verify_actual(
    actual: CaptureRunAlternationRunActual,
    upper: CaptureRunAlternationRunUpperBounds,
) -> Result<(), CaptureRunAlternationRunError> {
    for (resource, actual, upper) in [
        (
            CaptureRunAlternationRunResource::SourceReads,
            actual.source_reads,
            upper.source_reads,
        ),
        (
            CaptureRunAlternationRunResource::DecodedUnits,
            actual.decoded_units,
            upper.decoded_units,
        ),
        (
            CaptureRunAlternationRunResource::ClassComparisons,
            actual.class_comparisons,
            upper.class_comparisons,
        ),
        (
            CaptureRunAlternationRunResource::RunEvents,
            actual.run_events,
            upper.run_events,
        ),
        (
            CaptureRunAlternationRunResource::Matches,
            actual.matches,
            upper.matches,
        ),
        (
            CaptureRunAlternationRunResource::CaptureCount,
            actual.capture_count,
            upper.capture_count,
        ),
        (
            CaptureRunAlternationRunResource::Work,
            actual.work,
            upper.work,
        ),
        (
            CaptureRunAlternationRunResource::SequentialBytes,
            actual.sequential_bytes,
            upper.sequential_bytes,
        ),
    ] {
        if actual > upper {
            return Err(CaptureRunAlternationRunError::AccountingInvariant {
                resource,
                actual,
                upper,
            });
        }
    }
    Ok(())
}

fn enforce_run_limits(
    upper: CaptureRunAlternationRunUpperBounds,
    limits: CaptureRunAlternationRunLimits,
) -> Result<(), CaptureRunAlternationRunError> {
    for (resource, needed, limit) in [
        (
            CaptureRunAlternationRunResource::InputBytes,
            upper.input_bytes,
            limits.max_input_bytes,
        ),
        (
            CaptureRunAlternationRunResource::SourceReads,
            upper.source_reads,
            limits.max_source_reads,
        ),
        (
            CaptureRunAlternationRunResource::DecodedUnits,
            upper.decoded_units,
            limits.max_decoded_units,
        ),
        (
            CaptureRunAlternationRunResource::ClassComparisons,
            upper.class_comparisons,
            limits.max_class_comparisons,
        ),
        (
            CaptureRunAlternationRunResource::RunEvents,
            upper.run_events,
            limits.max_run_events,
        ),
        (
            CaptureRunAlternationRunResource::Matches,
            upper.matches,
            limits.max_matches,
        ),
        (
            CaptureRunAlternationRunResource::CaptureCount,
            upper.capture_count,
            limits.max_capture_count,
        ),
        (
            CaptureRunAlternationRunResource::Work,
            upper.work,
            limits.max_work,
        ),
        (
            CaptureRunAlternationRunResource::SequentialBytes,
            upper.sequential_bytes,
            limits.max_sequential_bytes,
        ),
        (
            CaptureRunAlternationRunResource::PeakBytes,
            upper.peak_bytes,
            limits.max_peak_bytes,
        ),
    ] {
        if needed > limit {
            return Err(CaptureRunAlternationRunError::Resource {
                resource,
                needed,
                limit,
            });
        }
    }
    Ok(())
}

fn enforce_build(
    resource: &'static str,
    needed: usize,
    limit: usize,
) -> Result<(), CaptureRunAlternationBuildError> {
    if needed > limit {
        return Err(CaptureRunAlternationBuildError::Resource {
            resource,
            needed,
            limit,
        });
    }
    Ok(())
}

fn class_range_count(class: &Class) -> usize {
    match class {
        Class::Bytes(class) => class.ranges().len(),
        Class::Unicode(class) => class.ranges().len(),
    }
}

fn enforce_intrinsic_class_ranges(
    range_count: usize,
) -> Result<(), CaptureRunAlternationBuildError> {
    if range_count == 0 {
        return Err(CaptureRunAlternationBuildError::Unsupported(
            "shared class must be nonempty",
        ));
    }
    if range_count > MAX_CLASS_RANGES {
        return Err(CaptureRunAlternationBuildError::Unsupported(
            "class exceeds the intrinsic retained-range capacity",
        ));
    }
    Ok(())
}

fn charge_inspection(
    accounting: &mut CaptureRunAlternationHirAccounting,
    amount: usize,
    limits: CaptureRunAlternationBuildLimits,
) -> Result<(), CaptureRunAlternationBuildError> {
    let needed = accounting.inspection_work.checked_add(amount).ok_or(
        CaptureRunAlternationBuildError::ArithmeticOverflow("inspection work"),
    )?;
    enforce_build("inspection work", needed, limits.max_inspection_work)?;
    accounting.inspection_work = needed;
    Ok(())
}

fn charge_class_equality(
    accounting: &mut CaptureRunAlternationHirAccounting,
    amount: usize,
    limits: CaptureRunAlternationBuildLimits,
) -> Result<(), CaptureRunAlternationBuildError> {
    let component = accounting.class_equality_work.checked_add(amount).ok_or(
        CaptureRunAlternationBuildError::ArithmeticOverflow("class equality work"),
    )?;
    charge_inspection(accounting, amount, limits)?;
    accounting.class_equality_work = component;
    Ok(())
}

fn charge_mask_initializations(
    accounting: &mut CaptureRunAlternationHirAccounting,
    amount: usize,
    limits: CaptureRunAlternationBuildLimits,
) -> Result<(), CaptureRunAlternationBuildError> {
    let component = accounting.mask_initializations.checked_add(amount).ok_or(
        CaptureRunAlternationBuildError::ArithmeticOverflow("byte-mask initializations"),
    )?;
    charge_inspection(accounting, amount, limits)?;
    accounting.mask_initializations = component;
    Ok(())
}

fn charge_range_materializations(
    accounting: &mut CaptureRunAlternationHirAccounting,
    amount: usize,
    limits: CaptureRunAlternationBuildLimits,
) -> Result<(), CaptureRunAlternationBuildError> {
    let component = accounting
        .range_materializations
        .checked_add(amount)
        .ok_or(CaptureRunAlternationBuildError::ArithmeticOverflow(
            "range materializations",
        ))?;
    charge_inspection(accounting, amount, limits)?;
    accounting.range_materializations = component;
    Ok(())
}

fn byte_member(members: [u64; 4], byte: u8) -> bool {
    members[usize::from(byte) / 64] & (1_u64 << (usize::from(byte) % 64)) != 0
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "the fixed 256-byte domain can start at most 128 disjoint nonempty ranges"
)]
fn byte_range_count(members: [u64; 4]) -> usize {
    let mut ranges = 0_usize;
    let mut previous = false;
    for byte in u8::MIN..=u8::MAX {
        let current = byte_member(members, byte);
        if current && !previous {
            ranges += 1;
        }
        previous = current;
    }
    ranges
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "comparison count is bounded by the immutable range array and checked against the prospective after execution"
)]
fn scalar_member(ranges: &[ScalarRange], scalar: char, comparisons: &mut usize) -> bool {
    let scalar = u32::from(scalar);
    let mut lower = 0_usize;
    let mut upper = ranges.len();
    while lower < upper {
        *comparisons += 1;
        let middle = lower + (upper - lower) / 2;
        let range = ranges[middle];
        if scalar < range.start {
            upper = middle;
        } else if scalar > range.end {
            lower = middle + 1;
        } else {
            return true;
        }
    }
    false
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DecodedUnit {
    scalar: Option<char>,
    width: usize,
    source_reads: usize,
}

impl DecodedUnit {
    const fn valid(scalar: char, width: usize, source_reads: usize) -> Self {
        Self {
            scalar: Some(scalar),
            width,
            source_reads,
        }
    }

    const fn invalid(source_reads: usize) -> Self {
        Self {
            scalar: None,
            width: 1,
            source_reads,
        }
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "a UTF-8 scalar has at most four bytes, and each successful bounded probe increments this local counter once"
)]
fn probe_byte(bytes: &[u8], index: usize, source_reads: &mut usize) -> Option<u8> {
    let byte = bytes.get(index).copied()?;
    *source_reads += 1;
    Some(byte)
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "validated UTF-8 payload masks and fixed shifts construct one Unicode scalar"
)]
fn decode_first(bytes: &[u8]) -> DecodedUnit {
    let mut source_reads = 0_usize;
    let first = probe_byte(bytes, 0, &mut source_reads)
        .expect("Unicode scan only decodes a known nonempty suffix");
    match first {
        0x00..=0x7f => DecodedUnit::valid(char::from(first), 1, source_reads),
        0xc2..=0xdf => {
            let Some(second) = probe_byte(bytes, 1, &mut source_reads) else {
                return DecodedUnit::invalid(source_reads);
            };
            if !is_utf8_continuation(second) {
                return DecodedUnit::invalid(source_reads);
            }
            let scalar = (u32::from(first & 0x1f) << 6) | u32::from(second & 0x3f);
            DecodedUnit::valid(
                char::from_u32(scalar).expect("validated two-byte UTF-8 is a scalar"),
                2,
                source_reads,
            )
        }
        0xe0..=0xef => {
            let Some(second) = probe_byte(bytes, 1, &mut source_reads) else {
                return DecodedUnit::invalid(source_reads);
            };
            let valid_second = match first {
                0xe0 => (0xa0..=0xbf).contains(&second),
                0xed => (0x80..=0x9f).contains(&second),
                _ => is_utf8_continuation(second),
            };
            if !valid_second {
                return DecodedUnit::invalid(source_reads);
            }
            let Some(third) = probe_byte(bytes, 2, &mut source_reads) else {
                return DecodedUnit::invalid(source_reads);
            };
            if !is_utf8_continuation(third) {
                return DecodedUnit::invalid(source_reads);
            }
            let scalar = (u32::from(first & 0x0f) << 12)
                | (u32::from(second & 0x3f) << 6)
                | u32::from(third & 0x3f);
            DecodedUnit::valid(
                char::from_u32(scalar).expect("validated three-byte UTF-8 is a scalar"),
                3,
                source_reads,
            )
        }
        0xf0..=0xf4 => {
            let Some(second) = probe_byte(bytes, 1, &mut source_reads) else {
                return DecodedUnit::invalid(source_reads);
            };
            let valid_second = match first {
                0xf0 => (0x90..=0xbf).contains(&second),
                0xf4 => (0x80..=0x8f).contains(&second),
                _ => is_utf8_continuation(second),
            };
            if !valid_second {
                return DecodedUnit::invalid(source_reads);
            }
            let Some(third) = probe_byte(bytes, 2, &mut source_reads) else {
                return DecodedUnit::invalid(source_reads);
            };
            if !is_utf8_continuation(third) {
                return DecodedUnit::invalid(source_reads);
            }
            let Some(fourth) = probe_byte(bytes, 3, &mut source_reads) else {
                return DecodedUnit::invalid(source_reads);
            };
            if !is_utf8_continuation(fourth) {
                return DecodedUnit::invalid(source_reads);
            }
            let scalar = (u32::from(first & 0x07) << 18)
                | (u32::from(second & 0x3f) << 12)
                | (u32::from(third & 0x3f) << 6)
                | u32::from(fourth & 0x3f);
            DecodedUnit::valid(
                char::from_u32(scalar).expect("validated four-byte UTF-8 is a scalar"),
                4,
                source_reads,
            )
        }
        _ => DecodedUnit::invalid(source_reads),
    }
}

const fn is_utf8_continuation(byte: u8) -> bool {
    matches!(byte, 0x80..=0xbf)
}

fn binary_search_comparison_bound(items: usize) -> usize {
    if items == 0 {
        0
    } else {
        usize::try_from(usize::BITS)
            .expect("usize bit width fits usize")
            .checked_sub(
                usize::try_from(items.leading_zeros())
                    .expect("usize leading-zero count fits usize"),
            )
            .expect("nonzero usize has fewer leading zeros than its bit width")
    }
}

fn digest_bytes(bytes: &[u8]) -> [u64; 2] {
    let mut digest = [DIGEST_OFFSET_A, DIGEST_OFFSET_B];
    for &byte in bytes {
        digest[0] = (digest[0] ^ u64::from(byte)).wrapping_mul(DIGEST_PRIME_A);
        digest[1] = (digest[1] ^ u64::from(byte)).wrapping_mul(DIGEST_PRIME_B);
    }
    digest
}

fn digest_words(words: [u64; 4]) -> [u64; 2] {
    let mut bytes = [0_u8; 32];
    for (chunk, word) in bytes.chunks_exact_mut(8).zip(words) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    digest_bytes(&bytes)
}

fn digest_ranges(ranges: &[ScalarRange]) -> [u64; 2] {
    let mut digest = [DIGEST_OFFSET_A, DIGEST_OFFSET_B];
    for range in ranges {
        for byte in range
            .start
            .to_le_bytes()
            .into_iter()
            .chain(range.end.to_le_bytes())
        {
            digest[0] = (digest[0] ^ u64::from(byte)).wrapping_mul(DIGEST_PRIME_A);
            digest[1] = (digest[1] ^ u64::from(byte)).wrapping_mul(DIGEST_PRIME_B);
        }
    }
    digest
}

#[cfg(test)]
mod tests {
    use core::fmt::Write as _;

    use regex::bytes::RegexBuilder;

    use super::{
        CaptureRunAlternationBuildError, CaptureRunAlternationBuildLimits,
        CaptureRunAlternationBuilder, CaptureRunAlternationKind, CaptureRunAlternationRunLimits,
    };

    fn exact_limits(
        plan: &super::CaptureRunAlternationPlan,
        input: usize,
    ) -> CaptureRunAlternationRunLimits {
        let upper = plan.run_upper_bounds(input).unwrap();
        CaptureRunAlternationRunLimits {
            max_input_bytes: upper.input_bytes,
            max_source_reads: upper.source_reads,
            max_decoded_units: upper.decoded_units,
            max_class_comparisons: upper.class_comparisons,
            max_run_events: upper.run_events,
            max_matches: upper.matches,
            max_capture_count: upper.capture_count,
            max_work: upper.work,
            max_sequential_bytes: upper.sequential_bytes,
            max_peak_bytes: upper.peak_bytes,
        }
    }

    fn reference(pattern: &str, unicode: bool, haystack: &[u8]) -> usize {
        RegexBuilder::new(pattern)
            .unicode(unicode)
            .build()
            .unwrap()
            .captures_iter(haystack)
            .map(|captures| captures.iter().flatten().count())
            .sum()
    }

    fn wide_class_pattern(ranges: usize) -> String {
        let mut class = String::from("[");
        for ordinal in 0..ranges {
            let scalar = u32::try_from(ordinal)
                .unwrap()
                .checked_mul(2)
                .and_then(|value| value.checked_add(0x1000))
                .unwrap();
            write!(&mut class, r"\u{{{scalar:x}}}").unwrap();
        }
        class.push(']');
        format!("({class}{{3}})|({class}{{2}})")
    }

    #[test]
    fn disjoint_byte_runs_match_capture_iteration() {
        let pattern = r"(?:(a+)|(b+)|(c+))";
        let plan = CaptureRunAlternationBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        assert_eq!(
            plan.build_report().identity.operation.kind,
            CaptureRunAlternationKind::DisjointByteRuns
        );
        for haystack in [b"".as_slice(), b"aaabbc", b"xaaabcccy", b"a\xffbb"] {
            let result = plan
                .capture_count(haystack, exact_limits(&plan, haystack.len()))
                .unwrap();
            assert_eq!(result.capture_count, reference(pattern, false, haystack));
        }
    }

    #[test]
    fn descending_exact_classes_match_ascii_and_unicode() {
        for (pattern, unicode, haystack) in [
            (
                r"([A-Za-z]{4})|([A-Za-z]{3})|([A-Za-z]{2})",
                false,
                b"abcdef x yz".as_slice(),
            ),
            (
                r"(\p{L}{4})|(\p{L}{3})|(\p{L}{2})",
                true,
                "abcdef βγδε жз".as_bytes(),
            ),
        ] {
            let plan = CaptureRunAlternationBuilder::new(pattern)
                .unicode(unicode)
                .build()
                .unwrap();
            let result = plan
                .capture_count(haystack, exact_limits(&plan, haystack.len()))
                .unwrap();
            assert_eq!(result.capture_count, reference(pattern, unicode, haystack));
        }
    }

    #[test]
    fn exact_length_mask_closes_identity_and_rejects_forgery() {
        let plan = CaptureRunAlternationBuilder::new(r"([A-Za-z]{5})|([A-Za-z]{3})|([A-Za-z]{2})")
            .unicode(false)
            .build()
            .unwrap();
        let operation = plan.build_report().identity.operation;
        assert_eq!(
            operation.exact_lengths,
            (1_u32 << 5) | (1_u32 << 3) | (1_u32 << 2)
        );
        assert_eq!(operation.exact_lengths.count_ones(), 3);
        assert_eq!(operation.minimum_length, 2);
        assert_eq!(operation.maximum_length, Some(5));
        assert!(plan.authenticates_identity());

        let mut forged = plan.clone();
        forged.report.identity.operation.exact_lengths ^= 1_u32 << 4;
        assert!(!forged.authenticates_identity());
        forged.report.identity.operation.exact_lengths = operation.exact_lengths;
        forged.report.identity.operation.minimum_length = 1;
        assert!(!forged.authenticates_identity());
    }

    #[test]
    fn gapped_exact_widths_match_every_short_maximal_run() {
        let pattern = r"([ab]{5})|([ab]{3})|([ab]{2})";
        let plan = CaptureRunAlternationBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        for length in 0..=16 {
            let haystack = "a".repeat(length);
            let result = plan
                .capture_count(haystack.as_bytes(), exact_limits(&plan, haystack.len()))
                .unwrap();
            assert_eq!(
                result.capture_count,
                reference(pattern, false, haystack.as_bytes()),
                "maximal run length {length}"
            );
        }
    }

    #[test]
    fn build_work_charges_equality_masks_ranges_and_exact_boundary() {
        for (pattern, unicode) in [
            (r"(?:(a+)|(b+)|(c+))", false),
            (r"([A-Za-z]{4})|([A-Za-z]{3})|([A-Za-z]{2})", false),
            (r"(\p{L}{4})|(\p{L}{3})|(\p{L}{2})", true),
        ] {
            let plan = CaptureRunAlternationBuilder::new(pattern)
                .unicode(unicode)
                .build()
                .unwrap();
            let report = plan.build_report();
            let expected = report
                .hir
                .hir_nodes
                .checked_add(report.hir.alternatives)
                .and_then(|value| value.checked_add(report.hir.class_equality_work))
                .and_then(|value| value.checked_add(report.hir.mask_initializations))
                .and_then(|value| value.checked_add(report.hir.range_materializations))
                .unwrap();
            assert_eq!(report.hir.inspection_work, expected);
            match report.identity.operation.kind {
                CaptureRunAlternationKind::DisjointByteRuns => {
                    assert_eq!(report.hir.class_equality_work, 0);
                    assert_eq!(report.hir.mask_initializations, 3);
                    assert_eq!(report.hir.range_materializations, 0);
                }
                CaptureRunAlternationKind::DescendingExactByteClass => {
                    assert_eq!(report.hir.class_equality_work, 6);
                    assert_eq!(report.hir.mask_initializations, 52);
                    assert_eq!(report.hir.range_materializations, 2);
                }
                CaptureRunAlternationKind::DescendingExactUnicodeClass => {
                    let ranges = report.hir.class_ranges;
                    assert_eq!(report.hir.class_equality_work, 2 * ranges.saturating_add(1));
                    assert_eq!(report.hir.mask_initializations, 0);
                    assert_eq!(report.hir.range_materializations, 2 * ranges);
                }
            }

            let defaults = CaptureRunAlternationBuildLimits::default();
            let exact = CaptureRunAlternationBuildLimits {
                max_inspection_work: report.hir.inspection_work,
                ..defaults
            };
            let rebuilt = CaptureRunAlternationBuilder::new(pattern)
                .unicode(unicode)
                .limits(exact)
                .build()
                .expect("exact inspection-work boundary");
            assert_eq!(
                rebuilt.build_report().hir.inspection_work,
                report.hir.inspection_work
            );
            let one_below = CaptureRunAlternationBuildLimits {
                max_inspection_work: report.hir.inspection_work - 1,
                ..defaults
            };
            assert!(matches!(
                CaptureRunAlternationBuilder::new(pattern)
                    .unicode(unicode)
                    .limits(one_below)
                    .build(),
                Err(CaptureRunAlternationBuildError::Resource {
                    resource: "inspection work",
                    ..
                })
            ));
        }
    }

    #[test]
    fn unicode_retained_storage_is_preflighted_at_exact_boundaries() {
        let pattern = r"(\p{L}{4})|(\p{L}{3})|(\p{L}{2})";
        let plan = CaptureRunAlternationBuilder::new(pattern)
            .unicode(true)
            .build()
            .unwrap();
        let needed = plan.build_report().persistent_bytes;
        let defaults = CaptureRunAlternationBuildLimits::default();
        let exact = CaptureRunAlternationBuildLimits {
            max_persistent_bytes: needed,
            max_peak_bytes: needed,
            ..defaults
        };
        CaptureRunAlternationBuilder::new(pattern)
            .unicode(true)
            .limits(exact)
            .build()
            .expect("exact retained and peak byte boundaries");

        for limits in [
            CaptureRunAlternationBuildLimits {
                max_persistent_bytes: needed - 1,
                ..defaults
            },
            CaptureRunAlternationBuildLimits {
                max_peak_bytes: needed - 1,
                ..defaults
            },
        ] {
            assert!(matches!(
                CaptureRunAlternationBuilder::new(pattern)
                    .unicode(true)
                    .limits(limits)
                    .build(),
                Err(CaptureRunAlternationBuildError::Resource { .. })
            ));
        }
    }

    #[test]
    fn malformed_unicode_probes_are_explicit_bounded_and_semantic() {
        for (bytes, scalar, width, source_reads) in [
            ("💩".as_bytes(), Some('💩'), 4_usize, 4_usize),
            (&[0xf0, 0x90, 0x80, b'A'][..], None, 1, 4),
            (&[0xe2, 0x82][..], None, 1, 2),
            (&[0xed, 0xa0, 0x80][..], None, 1, 2),
            (&[0x80][..], None, 1, 1),
        ] {
            let decoded = super::decode_first(bytes);
            assert_eq!(decoded.scalar, scalar);
            assert_eq!(decoded.width, width);
            assert_eq!(decoded.source_reads, source_reads);
        }

        let pattern = r"(\p{L}{3})|(\p{L}{2})";
        let haystack = [b'a', b'b', 0xf0, 0x90, 0x80, b'A', b'c', b'd', 0xe2, 0x82];
        let plan = CaptureRunAlternationBuilder::new(pattern)
            .unicode(true)
            .build()
            .unwrap();
        let result = plan
            .capture_count(&haystack, exact_limits(&plan, haystack.len()))
            .unwrap();
        assert_eq!(result.capture_count, reference(pattern, true, &haystack));
        assert_eq!(result.actual.source_reads, 14);
        assert_eq!(result.actual.sequential_bytes, 14);
        assert_eq!(result.actual.decoded_units, haystack.len());
        assert!(result.actual.source_reads <= result.upper_bounds.source_reads);
        assert_eq!(
            result.upper_bounds.source_reads,
            haystack.len() * super::MAX_UTF8_PROBES_PER_POSITION
        );
    }

    #[test]
    fn intrinsic_caps_fall_back_while_caller_quotas_refuse() {
        assert!(matches!(
            CaptureRunAlternationBuilder::new(r"([a-z]{32})|([a-z]{31})")
                .unicode(false)
                .build(),
            Err(CaptureRunAlternationBuildError::Unsupported(_))
        ));
        assert!(matches!(
            CaptureRunAlternationBuilder::new(wide_class_pattern(super::MAX_CLASS_RANGES + 1))
                .unicode(true)
                .build(),
            Err(CaptureRunAlternationBuildError::Unsupported(_))
        ));
        assert!(matches!(
            CaptureRunAlternationBuilder::new(r"([a&&b]{3})|([a&&b]{2})")
                .unicode(false)
                .build(),
            Err(CaptureRunAlternationBuildError::Unsupported(_))
        ));

        let defaults = CaptureRunAlternationBuildLimits::default();
        assert!(matches!(
            CaptureRunAlternationBuilder::new(r"([a-z]{4})|([a-z]{3})")
                .unicode(false)
                .limits(CaptureRunAlternationBuildLimits {
                    max_exact_length: 3,
                    ..defaults
                })
                .build(),
            Err(CaptureRunAlternationBuildError::Resource {
                resource: "exact repetition length",
                ..
            })
        ));
        assert!(matches!(
            CaptureRunAlternationBuilder::new(r"([A-Za-z]{4})|([A-Za-z]{3})")
                .unicode(false)
                .limits(CaptureRunAlternationBuildLimits {
                    max_class_ranges: 1,
                    ..defaults
                })
                .build(),
            Err(CaptureRunAlternationBuildError::Resource {
                resource: "class ranges",
                ..
            })
        ));
    }

    #[test]
    fn exact_work_limit_refuses_before_execution() {
        let pattern = r"([A-Za-z]{4})|([A-Za-z]{3})|([A-Za-z]{2})";
        let haystack = b"abcdef xyz";
        let plan = CaptureRunAlternationBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        let mut limits = exact_limits(&plan, haystack.len());
        limits.max_work -= 1;
        assert!(matches!(
            plan.capture_count(haystack, limits),
            Err(super::CaptureRunAlternationRunError::Resource {
                resource: super::CaptureRunAlternationRunResource::Work,
                ..
            })
        ));
    }

    #[test]
    fn alternating_boundaries_are_single_read_and_exactly_accounted() {
        let haystack = b"aaXaaXbbYbbb";
        for pattern in [r"(?:(a+)|(b+))", r"([ab]{3})|([ab]{2})"] {
            let plan = CaptureRunAlternationBuilder::new(pattern)
                .unicode(false)
                .build()
                .unwrap();
            let result = plan
                .capture_count(haystack, exact_limits(&plan, haystack.len()))
                .unwrap();
            assert_eq!(result.capture_count, reference(pattern, false, haystack));
            assert_eq!(result.actual.source_reads, haystack.len());
            assert_eq!(result.actual.decoded_units, haystack.len());
            assert_eq!(result.actual.sequential_bytes, haystack.len());
            assert_eq!(result.actual.run_events, 4);
        }
    }

    #[test]
    fn nearby_shapes_are_refused() {
        for pattern in [
            r"(a+)|(a+)",
            r"(a+?)|(b+)",
            r"([a-z]{2})|([A-Z]{3})",
            r"([a-z]{2})|([a-z]{3})",
        ] {
            assert!(
                CaptureRunAlternationBuilder::new(pattern)
                    .unicode(false)
                    .build()
                    .is_err(),
                "{pattern}"
            );
        }
    }
}
