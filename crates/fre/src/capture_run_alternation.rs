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
pub const CAPTURE_RUN_ALTERNATION_ACCOUNTING_VERSION: u32 = 1;

const MAX_CLASS_RANGES: usize = 1_024;
const MAX_EXACT_LENGTH: u32 = 31;
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
    pub inspection_work: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureRunAlternationOperationIdentity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub kind: CaptureRunAlternationKind,
    pub alternatives: usize,
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
        let comparisons_per_unit = match &self.matcher {
            CaptureRunAlternationMatcher::ExactUnicodeClass { ranges, .. } => {
                binary_search_comparison_bound(ranges.len())
            }
            CaptureRunAlternationMatcher::DisjointByteRuns { .. }
            | CaptureRunAlternationMatcher::ExactByteClass { .. } => 0,
        };
        let class_comparisons = input_bytes.checked_mul(comparisons_per_unit).ok_or(
            CaptureRunAlternationRunError::ArithmeticOverflow {
                computation: "class-comparison upper bound",
            },
        )?;
        let work = input_bytes
            .checked_mul(3)
            .and_then(|value| value.checked_add(class_comparisons))
            .and_then(|value| value.checked_add(matches))
            .ok_or(CaptureRunAlternationRunError::ArithmeticOverflow {
                computation: "work upper bound",
            })?;
        Ok(CaptureRunAlternationRunUpperBounds {
            input_bytes,
            source_reads: input_bytes,
            decoded_units: input_bytes,
            class_comparisons,
            run_events: input_bytes,
            matches,
            capture_count,
            work,
            sequential_bytes: input_bytes,
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
    minimum_length: u32,
    maximum_length: Option<u32>,
    class_digest: [u64; 2],
    accounting: CaptureRunAlternationHirAccounting,
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
        members[word] |= bit;
    }
    Ok(Inspection {
        kind: CaptureRunAlternationKind::DisjointByteRuns,
        matcher: CaptureRunAlternationMatcher::DisjointByteRuns { members },
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
        let max_exact = limits.max_exact_length.min(MAX_EXACT_LENGTH);
        if repetition.min > max_exact {
            return Err(CaptureRunAlternationBuildError::Resource {
                resource: "exact repetition length",
                needed: usize::try_from(repetition.min).unwrap_or(usize::MAX),
                limit: usize::try_from(max_exact).unwrap_or(usize::MAX),
            });
        }
        let HirKind::Class(class) = repetition.sub.kind() else {
            return Err(CaptureRunAlternationBuildError::Unsupported(
                "exact repetition body must be one class",
            ));
        };
        if shared_class.is_some_and(|shared| shared != class) {
            return Err(CaptureRunAlternationBuildError::Unsupported(
                "every exact repetition must use the same class",
            ));
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
        build_exact_matcher(class, unicode, exact_lengths, limits)?;
    accounting.class_ranges = class_ranges;
    charge_inspection(&mut accounting, class_ranges, limits)?;
    Ok(Inspection {
        kind,
        matcher,
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
            enforce_build(
                "class ranges",
                class.ranges().len(),
                limits.max_class_ranges.min(MAX_CLASS_RANGES),
            )?;
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
                class.ranges().len(),
                digest_words(members),
            ))
        }
        (true, Class::Unicode(class)) => {
            let range_count = class.ranges().len();
            enforce_build(
                "class ranges",
                range_count,
                limits.max_class_ranges.min(MAX_CLASS_RANGES),
            )?;
            let mut ranges = Vec::new();
            ranges.try_reserve_exact(range_count).map_err(|_| {
                CaptureRunAlternationBuildError::Resource {
                    resource: "class range allocation",
                    needed: range_count,
                    limit: limits.max_class_ranges.min(MAX_CLASS_RANGES),
                }
            })?;
            for range in class.ranges() {
                if (range.start() <= '\n' && '\n' <= range.end())
                    || (range.start() <= '\r' && '\r' <= range.end())
                {
                    return Err(CaptureRunAlternationBuildError::Unsupported(
                        "shared Unicode class must exclude line terminators",
                    ));
                }
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
    let mut decoded_units = 0_usize;
    let mut comparisons = 0_usize;
    let mut run_length = 0_usize;
    let mut run_events = 0_usize;
    let mut matches = 0_usize;
    while position < haystack.len() {
        let decoded = decode_first(&haystack[position..]);
        let (in_class, width) = if let Some((scalar, width)) = decoded {
            (scalar_member(ranges, scalar, &mut comparisons), width)
        } else {
            (false, 1)
        };
        position += width;
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
        haystack.len(),
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

fn byte_member(members: [u64; 4], byte: u8) -> bool {
    members[usize::from(byte) / 64] & (1_u64 << (usize::from(byte) % 64)) != 0
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

fn decode_first(bytes: &[u8]) -> Option<(char, usize)> {
    let first = *bytes.first()?;
    let width = utf8_width(first)?;
    let prefix = bytes.get(..width)?;
    let text = core::str::from_utf8(prefix).ok()?;
    Some((text.chars().next()?, width))
}

const fn utf8_width(first: u8) -> Option<usize> {
    match first {
        0x00..=0x7f => Some(1),
        0xc2..=0xdf => Some(2),
        0xe0..=0xef => Some(3),
        0xf0..=0xf4 => Some(4),
        _ => None,
    }
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
    use regex::bytes::RegexBuilder;

    use super::{
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
