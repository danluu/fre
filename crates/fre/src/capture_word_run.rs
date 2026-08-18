//! Generic single-pass `grep-captures` reduction for bounded whole-word
//! capture alternatives.
//!
//! The admitted HIR is
//!
//! ```text
//! word-boundary (capture(CLASS{N}) | ... ) word-boundary
//! ```
//!
//! where every alternative uses the same nonempty class, every exact length
//! is bounded, and the class is proved to be a subset of the boundary's word
//! predicate. Consequently each maximal class run can contribute at most one
//! match and exactly one explicit capture. Line partitioning cannot change the
//! result because LF and CR are outside both admitted word predicates and
//! outside the consuming class.

use core::{fmt, mem::size_of};

use fre_kernels::{
    ASCII_WIDE_BYTES, AsciiByteSet, AsciiByteSetClassifier, DispatchPolicy, SimdDispatchContext,
};
use fre_syntax::{
    AdmissionPolicy, CanonicalPattern, CompatibilityProfile, RustProfile, SafetyEnvelope,
};
use memchr::memchr_iter;
use regex_syntax::hir::{Class, Hir, HirKind, Look};

pub const CAPTURE_WORD_RUN_PLAN_ID: &str = "capture-bounded-word-run-linear-v1";
pub const CAPTURE_WORD_RUN_COUNT_OPERATION_ID: &str =
    "capture-bounded-word-run.grep-participation-count.v1";
pub const CAPTURE_WORD_RUN_RECORD_OPERATION_ID: &str =
    "capture-bounded-word-run.grep-record-visit.v1";
pub const CAPTURE_WORD_RUN_ALGORITHM_VERSION: u32 = 2;
pub const CAPTURE_WORD_RUN_ACCOUNTING_VERSION: u32 = 3;

const MAX_CLASS_RANGES: usize = 64;
const MAX_EXACT_LENGTH: u32 = 31;
const GROUPS_PER_MATCH: usize = 2;
const DIGEST_OFFSET_A: u64 = 0xcbf2_9ce4_8422_2325;
const DIGEST_OFFSET_B: u64 = 0x8422_2325_cbf2_9ce4;
const DIGEST_PRIME_A: u64 = 0x0000_0100_0000_01b3;
const DIGEST_PRIME_B: u64 = 0x0000_0100_0000_01cf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureWordRunMode {
    Ascii,
    Unicode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureWordRunBuildLimits {
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

impl Default for CaptureWordRunBuildLimits {
    fn default() -> Self {
        Self {
            admission: AdmissionPolicy::default(),
            syntax_safety: SafetyEnvelope::default(),
            max_inspection_work: 8_192,
            max_hir_nodes: 1_024,
            max_class_ranges: MAX_CLASS_RANGES,
            max_alternatives: 31,
            max_exact_length: MAX_EXACT_LENGTH,
            max_persistent_bytes: 1 << 20,
            max_peak_bytes: 1 << 20,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureWordRunHirAccounting {
    pub hir_nodes: usize,
    pub class_ranges: usize,
    pub class_scalar_probes: usize,
    pub alternatives: usize,
    pub captures: usize,
    /// Explicit captures carrying a canonical name. Record materializers that
    /// do not retain names must prove this is zero before selecting the plan.
    pub named_captures: usize,
    pub inspection_work: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each bit authenticates a separate immutable regex semantic"
)]
pub struct CaptureWordRunOperationIdentity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub mode: CaptureWordRunMode,
    pub exact_lengths: u32,
    pub minimum_length: u32,
    pub maximum_length: u32,
    pub class_ranges: usize,
    pub class_digest: [u64; 2],
    pub participating_captures_per_match: usize,
    pub groups_per_match: usize,
    pub complete_word_boundaries: bool,
    pub invalid_bytes_are_non_word: bool,
    pub line_partition_invariant: bool,
    pub non_overlapping: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each bit authenticates a separate immutable regex semantic"
)]
pub struct CaptureWordRunRecordOperationIdentity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub mode: CaptureWordRunMode,
    pub exact_lengths: u32,
    pub minimum_length: u32,
    pub maximum_length: u32,
    pub class_ranges: usize,
    pub class_digest: [u64; 2],
    pub numeric_groups: usize,
    pub participating_groups_per_match: usize,
    pub endpoints_per_participating_group: usize,
    pub group_by_length_digest: [u64; 2],
    pub fixed_numeric_schema: bool,
    pub first_source_branch_for_duplicate_length: bool,
    pub complete_word_boundaries: bool,
    pub invalid_bytes_are_non_word: bool,
    pub non_overlapping: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureWordRunPlanIdentity {
    pub profile: RustProfile,
    pub source_digest: [u64; 2],
    pub algorithm_version: u32,
    pub accounting_version: u32,
    pub operation: CaptureWordRunOperationIdentity,
    pub record_operation: CaptureWordRunRecordOperationIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureWordRunBuildReport {
    pub identity: CaptureWordRunPlanIdentity,
    pub hir: CaptureWordRunHirAccounting,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum CaptureWordRunBuildError {
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

impl fmt::Display for CaptureWordRunBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(error) => write!(formatter, "capture word-run syntax: {error}"),
            Self::Unsupported(reason) => {
                write!(formatter, "unsupported capture word-run shape: {reason}")
            }
            Self::Resource {
                resource,
                needed,
                limit,
            } => write!(
                formatter,
                "capture word-run {resource} needs {needed}, limit is {limit}"
            ),
            Self::ArithmeticOverflow(computation) => {
                write!(
                    formatter,
                    "capture word-run overflow while computing {computation}"
                )
            }
            Self::InternalInvariant(message) => {
                write!(formatter, "capture word-run invariant: {message}")
            }
        }
    }
}

impl std::error::Error for CaptureWordRunBuildError {
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
pub struct CaptureWordRunRunLimits {
    pub max_input_bytes: usize,
    pub max_source_reads: usize,
    pub max_decoded_units: usize,
    pub max_block_events: usize,
    pub max_class_comparisons: usize,
    pub max_boundary_probes: usize,
    pub max_matches: usize,
    pub max_capture_count: usize,
    pub max_work: usize,
    pub max_sequential_bytes: usize,
    pub max_peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureWordRunRunUpperBounds {
    pub input_bytes: usize,
    pub source_reads: usize,
    pub decoded_units: usize,
    pub block_events: usize,
    pub class_comparisons: usize,
    pub boundary_probes: usize,
    pub matches: usize,
    pub capture_count: usize,
    pub work: usize,
    pub sequential_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CaptureWordRunRunActual {
    pub source_reads: usize,
    pub decoded_units: usize,
    pub block_events: usize,
    pub class_comparisons: usize,
    pub boundary_probes: usize,
    pub matches: usize,
    pub capture_count: usize,
    pub work: usize,
    pub sequential_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureWordRunCountResult {
    pub identity: CaptureWordRunOperationIdentity,
    pub capture_count: usize,
    pub upper_bounds: CaptureWordRunRunUpperBounds,
    pub actual: CaptureWordRunRunActual,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureWordRunSpan {
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureWordRunRecord {
    overall: CaptureWordRunSpan,
    participating_group: usize,
    numeric_groups: usize,
}

impl CaptureWordRunRecord {
    #[must_use]
    pub const fn len(self) -> usize {
        self.numeric_groups
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.numeric_groups == 0
    }

    #[must_use]
    pub const fn participating_group(self) -> usize {
        self.participating_group
    }

    #[must_use]
    pub const fn span(self, group: usize) -> Option<CaptureWordRunSpan> {
        if group == 0 || group == self.participating_group {
            Some(self.overall)
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureWordRunRecordRunLimits {
    pub max_input_bytes: usize,
    pub max_line_domains: usize,
    pub max_source_reads: usize,
    pub max_decoded_units: usize,
    pub max_block_events: usize,
    pub max_class_comparisons: usize,
    pub max_boundary_probes: usize,
    pub max_matches: usize,
    pub max_capture_count: usize,
    pub max_capture_events: usize,
    pub max_endpoint_reads: usize,
    pub max_reducer_events: usize,
    pub max_work: usize,
    pub max_sequential_bytes: usize,
    pub max_peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureWordRunRecordRunUpperBounds {
    pub input_bytes: usize,
    pub line_domains: usize,
    pub source_reads: usize,
    pub decoded_units: usize,
    pub block_events: usize,
    pub class_comparisons: usize,
    pub boundary_probes: usize,
    pub matches: usize,
    pub capture_count: usize,
    pub capture_events: usize,
    pub endpoint_reads: usize,
    pub reducer_events: usize,
    pub work: usize,
    pub sequential_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureWordRunRecordVisitReport {
    pub identity: CaptureWordRunRecordOperationIdentity,
    pub input_bytes: usize,
    pub line_domains: usize,
    pub source_reads: usize,
    pub decoded_units: usize,
    pub block_events: usize,
    pub class_comparisons: usize,
    pub boundary_probes: usize,
    pub matches: usize,
    pub capture_count: usize,
    pub capture_events: usize,
    pub endpoint_reads: usize,
    pub reducer_events: usize,
    pub work: usize,
    pub sequential_bytes: usize,
    pub allocations: usize,
    pub scratch_bytes: usize,
    pub output_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureWordRunRunResource {
    InputBytes,
    LineDomains,
    SourceReads,
    DecodedUnits,
    BlockEvents,
    ClassComparisons,
    BoundaryProbes,
    Matches,
    CaptureCount,
    CaptureEvents,
    EndpointReads,
    ReducerEvents,
    Work,
    SequentialBytes,
    PeakBytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CaptureWordRunRunError {
    Resource {
        resource: CaptureWordRunRunResource,
        needed: usize,
        limit: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    AccountingInvariant {
        resource: CaptureWordRunRunResource,
        actual: usize,
        upper: usize,
    },
}

impl fmt::Display for CaptureWordRunRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "capture word-run reduction failed: {self:?}")
    }
}

impl std::error::Error for CaptureWordRunRunError {}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ScalarRange {
    start: u32,
    end: u32,
}

#[derive(Clone, Copy, Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "both fixed matcher artifacts stay inline to avoid an unaccounted plan allocation"
)]
enum CaptureWordRunMatcher {
    Ascii {
        class_classifier: AsciiByteSetClassifier,
        word_classifier: AsciiByteSetClassifier,
    },
    Unicode {
        ranges: [ScalarRange; MAX_CLASS_RANGES],
        range_count: usize,
    },
}

#[derive(Clone, Debug)]
pub struct CaptureWordRunBuilder {
    pattern: String,
    profile: RustProfile,
    limits: CaptureWordRunBuildLimits,
}

impl CaptureWordRunBuilder {
    #[must_use]
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            profile: RustProfile::default(),
            limits: CaptureWordRunBuildLimits::default(),
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
    pub const fn limits(mut self, limits: CaptureWordRunBuildLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn build(self) -> Result<CaptureWordRunPlan, CaptureWordRunBuildError> {
        if self.profile.options.case_insensitive {
            return Err(CaptureWordRunBuildError::Unsupported(
                "case-insensitive classes are not admitted",
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
        .map_err(CaptureWordRunBuildError::Syntax)?;
        let source_digest = digest_source(parsed.key.pattern.as_bytes());
        let summary = parsed.summary;
        let CanonicalPattern::Rust(rust) = parsed.pattern else {
            return Err(CaptureWordRunBuildError::InternalInvariant(
                "Rust byte request produced a non-Rust HIR",
            ));
        };
        let mode = if profile.options.unicode {
            CaptureWordRunMode::Unicode
        } else {
            CaptureWordRunMode::Ascii
        };
        let inspection = inspect(&rust.hir, mode, self.limits)?;
        let explicit_captures = usize::try_from(summary.captures)
            .map_err(|_| CaptureWordRunBuildError::ArithmeticOverflow("explicit capture count"))?;
        if explicit_captures != inspection.accounting.captures
            || explicit_captures != inspection.accounting.alternatives
        {
            return Err(CaptureWordRunBuildError::InternalInvariant(
                "parse capture count differs from direct capture alternatives",
            ));
        }
        let numeric_groups = explicit_captures.checked_add(1).ok_or(
            CaptureWordRunBuildError::ArithmeticOverflow("numeric capture schema size"),
        )?;
        for &group in &inspection.group_by_length {
            let group = usize::try_from(group).map_err(|_| {
                CaptureWordRunBuildError::ArithmeticOverflow("capture group index as usize")
            })?;
            if group >= numeric_groups {
                return Err(CaptureWordRunBuildError::InternalInvariant(
                    "retained capture group escaped the fixed numeric schema",
                ));
            }
        }
        let matcher = build_matcher(inspection.class, mode, self.limits)?;
        let persistent_bytes = size_of::<CaptureWordRunPlan>();
        enforce_build(
            "persistent bytes",
            persistent_bytes,
            self.limits.max_persistent_bytes,
        )?;
        enforce_build("peak bytes", persistent_bytes, self.limits.max_peak_bytes)?;
        let operation = CaptureWordRunOperationIdentity {
            plan_id: CAPTURE_WORD_RUN_PLAN_ID,
            operation_id: CAPTURE_WORD_RUN_COUNT_OPERATION_ID,
            mode,
            exact_lengths: inspection.exact_lengths,
            minimum_length: inspection.minimum_length,
            maximum_length: inspection.maximum_length,
            class_ranges: inspection.accounting.class_ranges,
            class_digest: digest_class(inspection.class, mode),
            participating_captures_per_match: 1,
            groups_per_match: GROUPS_PER_MATCH,
            complete_word_boundaries: true,
            invalid_bytes_are_non_word: true,
            line_partition_invariant: true,
            non_overlapping: true,
        };
        let record_operation = CaptureWordRunRecordOperationIdentity {
            plan_id: CAPTURE_WORD_RUN_PLAN_ID,
            operation_id: CAPTURE_WORD_RUN_RECORD_OPERATION_ID,
            mode,
            exact_lengths: inspection.exact_lengths,
            minimum_length: inspection.minimum_length,
            maximum_length: inspection.maximum_length,
            class_ranges: inspection.accounting.class_ranges,
            class_digest: digest_class(inspection.class, mode),
            numeric_groups,
            participating_groups_per_match: GROUPS_PER_MATCH,
            endpoints_per_participating_group: 2,
            group_by_length_digest: digest_group_by_length(
                &inspection.group_by_length,
                numeric_groups,
            ),
            fixed_numeric_schema: true,
            first_source_branch_for_duplicate_length: true,
            complete_word_boundaries: true,
            invalid_bytes_are_non_word: true,
            non_overlapping: true,
        };
        let report = CaptureWordRunBuildReport {
            identity: CaptureWordRunPlanIdentity {
                profile,
                source_digest,
                algorithm_version: CAPTURE_WORD_RUN_ALGORITHM_VERSION,
                accounting_version: CAPTURE_WORD_RUN_ACCOUNTING_VERSION,
                operation,
                record_operation,
            },
            hir: inspection.accounting,
            persistent_bytes,
            peak_bytes: persistent_bytes,
        };
        Ok(CaptureWordRunPlan {
            matcher,
            exact_lengths: inspection.exact_lengths,
            group_by_length: inspection.group_by_length,
            report,
        })
    }
}

#[derive(Clone, Debug)]
pub struct CaptureWordRunPlan {
    matcher: CaptureWordRunMatcher,
    exact_lengths: u32,
    group_by_length: [u32; 32],
    report: CaptureWordRunBuildReport,
}

impl CaptureWordRunPlan {
    #[must_use]
    pub const fn build_report(&self) -> &CaptureWordRunBuildReport {
        &self.report
    }

    pub fn run_upper_bounds(
        &self,
        input_bytes: usize,
    ) -> Result<CaptureWordRunRunUpperBounds, CaptureWordRunRunError> {
        let identity = self.report.identity.operation;
        let minimum = usize::try_from(identity.minimum_length).map_err(|_| {
            CaptureWordRunRunError::ArithmeticOverflow {
                computation: "minimum exact length as usize",
            }
        })?;
        let matches =
            input_bytes
                .checked_div(minimum)
                .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                    computation: "input bytes divided by minimum exact length",
                })?;
        let capture_count = matches.checked_mul(GROUPS_PER_MATCH).ok_or(
            CaptureWordRunRunError::ArithmeticOverflow {
                computation: "capture-count upper bound",
            },
        )?;
        let (block_events, class_comparisons, boundary_probes, work) = match &self.matcher {
            CaptureWordRunMatcher::Ascii { .. } => {
                let block_events = input_bytes
                    .checked_div(ASCII_WIDE_BYTES)
                    .and_then(|blocks| blocks.checked_add(1))
                    .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                        computation: "ASCII block events",
                    })?;
                let shifts = exact_length_shift_work(self.exact_lengths)?;
                let block_work =
                    shifts
                        .checked_add(2)
                        .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                            computation: "ASCII block work",
                        })?;
                let work = input_bytes
                    .checked_add(block_events.checked_mul(block_work).ok_or(
                        CaptureWordRunRunError::ArithmeticOverflow {
                            computation: "ASCII block work upper bound",
                        },
                    )?)
                    .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                        computation: "ASCII total work upper bound",
                    })?;
                (block_events, 0, 0, work)
            }
            CaptureWordRunMatcher::Unicode { range_count, .. } => {
                let comparisons_per_unit = binary_search_comparison_bound(*range_count);
                let class_comparisons = input_bytes.checked_mul(comparisons_per_unit).ok_or(
                    CaptureWordRunRunError::ArithmeticOverflow {
                        computation: "Unicode class-comparison upper bound",
                    },
                )?;
                let boundary_probes = input_bytes.checked_mul(2).ok_or(
                    CaptureWordRunRunError::ArithmeticOverflow {
                        computation: "Unicode boundary-probe upper bound",
                    },
                )?;
                let work = input_bytes
                    .checked_mul(2)
                    .and_then(|value| value.checked_add(class_comparisons))
                    .and_then(|value| value.checked_add(boundary_probes))
                    .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                        computation: "Unicode total work upper bound",
                    })?;
                (0, class_comparisons, boundary_probes, work)
            }
        };
        Ok(CaptureWordRunRunUpperBounds {
            input_bytes,
            source_reads: input_bytes,
            decoded_units: input_bytes,
            block_events,
            class_comparisons,
            boundary_probes,
            matches,
            capture_count,
            work,
            sequential_bytes: input_bytes,
            peak_bytes: self.report.persistent_bytes,
        })
    }

    pub fn grep_capture_count(
        &self,
        haystack: &[u8],
        limits: CaptureWordRunRunLimits,
    ) -> Result<CaptureWordRunCountResult, CaptureWordRunRunError> {
        let upper = self.run_upper_bounds(haystack.len())?;
        enforce_run_limits(upper, limits)?;
        let actual = match &self.matcher {
            CaptureWordRunMatcher::Ascii {
                class_classifier,
                word_classifier,
            } => scan_ascii(
                haystack,
                class_classifier,
                word_classifier,
                self.exact_lengths,
            )?,
            CaptureWordRunMatcher::Unicode {
                ranges,
                range_count,
            } => scan_unicode(haystack, &ranges[..*range_count], self.exact_lengths)?,
        };
        verify_actual(actual, upper)?;
        Ok(CaptureWordRunCountResult {
            identity: self.report.identity.operation,
            capture_count: actual.capture_count,
            upper_bounds: upper,
            actual,
        })
    }

    pub fn grep_capture_record_upper_bounds(
        &self,
        input_bytes: usize,
    ) -> Result<CaptureWordRunRecordRunUpperBounds, CaptureWordRunRunError> {
        let identity = self.report.identity.record_operation;
        let minimum = usize::try_from(identity.minimum_length).map_err(|_| {
            CaptureWordRunRunError::ArithmeticOverflow {
                computation: "record minimum exact length as usize",
            }
        })?;
        let matches =
            input_bytes
                .checked_div(minimum)
                .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                    computation: "record input bytes divided by minimum exact length",
                })?;
        let capture_count = matches.checked_mul(GROUPS_PER_MATCH).ok_or(
            CaptureWordRunRunError::ArithmeticOverflow {
                computation: "record capture-count upper bound",
            },
        )?;
        let capture_events = matches.checked_mul(identity.numeric_groups).ok_or(
            CaptureWordRunRunError::ArithmeticOverflow {
                computation: "record numeric-group event upper bound",
            },
        )?;
        let endpoint_reads =
            capture_count
                .checked_mul(2)
                .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                    computation: "record endpoint-read upper bound",
                })?;
        let line_domains = input_bytes;
        let reducer_events = line_domains.checked_add(capture_events).ok_or(
            CaptureWordRunRunError::ArithmeticOverflow {
                computation: "record reducer-event upper bound",
            },
        )?;
        let source_reads =
            input_bytes
                .checked_mul(2)
                .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                    computation: "record source-read upper bound",
                })?;
        let sequential_bytes = source_reads;
        let (block_events, class_comparisons, boundary_probes, matcher_work) = match &self.matcher {
            CaptureWordRunMatcher::Ascii { .. } => {
                let block_events = input_bytes;
                let block_work = exact_length_shift_work(self.exact_lengths)?
                    .checked_add(2)
                    .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                        computation: "record ASCII block work",
                    })?;
                let matcher_work = input_bytes
                    .checked_add(block_events.checked_mul(block_work).ok_or(
                        CaptureWordRunRunError::ArithmeticOverflow {
                            computation: "record ASCII block-work upper bound",
                        },
                    )?)
                    .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                        computation: "record ASCII matcher-work upper bound",
                    })?;
                (block_events, 0, 0, matcher_work)
            }
            CaptureWordRunMatcher::Unicode { range_count, .. } => {
                let comparisons_per_unit = binary_search_comparison_bound(*range_count);
                let class_comparisons = input_bytes.checked_mul(comparisons_per_unit).ok_or(
                    CaptureWordRunRunError::ArithmeticOverflow {
                        computation: "record Unicode class-comparison upper bound",
                    },
                )?;
                let boundary_probes = input_bytes.checked_mul(2).ok_or(
                    CaptureWordRunRunError::ArithmeticOverflow {
                        computation: "record Unicode boundary-probe upper bound",
                    },
                )?;
                let matcher_work = input_bytes
                    .checked_mul(2)
                    .and_then(|value| value.checked_add(class_comparisons))
                    .and_then(|value| value.checked_add(boundary_probes))
                    .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                        computation: "record Unicode matcher-work upper bound",
                    })?;
                (0, class_comparisons, boundary_probes, matcher_work)
            }
        };
        let work = input_bytes
            .checked_add(matcher_work)
            .and_then(|value| value.checked_add(line_domains))
            .and_then(|value| value.checked_add(capture_events))
            .and_then(|value| value.checked_add(endpoint_reads))
            .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                computation: "record total-work upper bound",
            })?;
        Ok(CaptureWordRunRecordRunUpperBounds {
            input_bytes,
            line_domains,
            source_reads,
            decoded_units: input_bytes,
            block_events,
            class_comparisons,
            boundary_probes,
            matches,
            capture_count,
            capture_events,
            endpoint_reads,
            reducer_events,
            work,
            sequential_bytes,
            peak_bytes: self.report.persistent_bytes,
        })
    }

    pub fn visit_grep_capture_records(
        &self,
        haystack: &[u8],
        limits: CaptureWordRunRecordRunLimits,
        mut visitor: impl FnMut(usize, usize, CaptureWordRunRecord),
    ) -> Result<CaptureWordRunRecordVisitReport, CaptureWordRunRunError> {
        // This is the sole fallible execution phase. In particular, the
        // worst case charges one padded SIMD tail for every possible line,
        // so no source-dependent resource decision remains after callbacks
        // begin.
        let upper = self.grep_capture_record_upper_bounds(haystack.len())?;
        enforce_record_run_limits(upper, limits)?;

        let identity = self.report.identity.record_operation;
        let mut actual = CaptureWordRunRecordVisitReport {
            identity,
            input_bytes: haystack.len(),
            line_domains: 0,
            source_reads: haystack.len(),
            decoded_units: 0,
            block_events: 0,
            class_comparisons: 0,
            boundary_probes: 0,
            matches: 0,
            capture_count: 0,
            capture_events: 0,
            endpoint_reads: 0,
            reducer_events: 0,
            work: haystack.len(),
            sequential_bytes: haystack.len(),
            allocations: 0,
            scratch_bytes: 0,
            output_bytes: 0,
            persistent_bytes: self.report.persistent_bytes,
            peak_bytes: self.report.peak_bytes,
        };
        let mut line_start = 0_usize;
        let mut line_index = 0_usize;
        for line_feed in memchr_iter(b'\n', haystack) {
            let mut line_end = line_feed;
            if line_end > line_start {
                let previous = line_end.checked_sub(1).ok_or(
                    CaptureWordRunRunError::ArithmeticOverflow {
                        computation: "record CRLF semantic line end",
                    },
                )?;
                if haystack[previous] == b'\r' {
                    line_end = previous;
                }
            }
            self.visit_one_record_line(
                line_index,
                &haystack[line_start..line_end],
                &mut actual,
                &mut visitor,
            )?;
            line_index = checked_add(line_index, 1, "record line index")?;
            line_start = checked_add(line_feed, 1, "record line cursor")?;
        }
        if line_start < haystack.len() {
            self.visit_one_record_line(
                line_index,
                &haystack[line_start..],
                &mut actual,
                &mut visitor,
            )?;
        }

        actual.capture_count = actual.matches.checked_mul(GROUPS_PER_MATCH).ok_or(
            CaptureWordRunRunError::ArithmeticOverflow {
                computation: "record actual capture count",
            },
        )?;
        actual.capture_events = actual.matches.checked_mul(identity.numeric_groups).ok_or(
            CaptureWordRunRunError::ArithmeticOverflow {
                computation: "record actual capture events",
            },
        )?;
        actual.endpoint_reads = actual.capture_count.checked_mul(2).ok_or(
            CaptureWordRunRunError::ArithmeticOverflow {
                computation: "record actual endpoint reads",
            },
        )?;
        actual.reducer_events = checked_add(
            actual.line_domains,
            actual.capture_events,
            "record actual reducer events",
        )?;
        actual.work = checked_add(
            actual.work,
            actual.capture_events,
            "record capture-event work",
        )?;
        actual.work = checked_add(
            actual.work,
            actual.endpoint_reads,
            "record endpoint-read work",
        )?;
        verify_record_actual(&actual, upper)?;
        Ok(actual)
    }

    fn visit_one_record_line(
        &self,
        line_index: usize,
        line: &[u8],
        actual: &mut CaptureWordRunRecordVisitReport,
        visitor: &mut impl FnMut(usize, usize, CaptureWordRunRecord),
    ) -> Result<(), CaptureWordRunRunError> {
        actual.line_domains = checked_add(actual.line_domains, 1, "record line domains")?;
        actual.work = checked_add(actual.work, 1, "record line work")?;
        actual.source_reads = checked_add(
            actual.source_reads,
            line.len(),
            "record semantic source reads",
        )?;
        actual.sequential_bytes = checked_add(
            actual.sequential_bytes,
            line.len(),
            "record semantic sequential bytes",
        )?;
        match &self.matcher {
            CaptureWordRunMatcher::Ascii {
                class_classifier,
                word_classifier,
            } => visit_ascii_records(
                line_index,
                line,
                class_classifier,
                word_classifier,
                self.exact_lengths,
                &self.group_by_length,
                self.report.identity.record_operation.numeric_groups,
                actual,
                visitor,
            )?,
            CaptureWordRunMatcher::Unicode {
                ranges,
                range_count,
            } => visit_unicode_records(
                line_index,
                line,
                &ranges[..*range_count],
                self.exact_lengths,
                &self.group_by_length,
                self.report.identity.record_operation.numeric_groups,
                actual,
                visitor,
            )?,
        }
        Ok(())
    }
}

struct Inspection<'a> {
    class: &'a Class,
    exact_lengths: u32,
    group_by_length: [u32; 32],
    minimum_length: u32,
    maximum_length: u32,
    accounting: CaptureWordRunHirAccounting,
}

#[allow(
    clippy::too_many_lines,
    reason = "one bounded structural traversal publishes the complete proof or a typed refusal"
)]
fn inspect(
    hir: &Hir,
    mode: CaptureWordRunMode,
    limits: CaptureWordRunBuildLimits,
) -> Result<Inspection<'_>, CaptureWordRunBuildError> {
    let mut accounting = CaptureWordRunHirAccounting {
        hir_nodes: 1,
        class_ranges: 0,
        class_scalar_probes: 0,
        alternatives: 0,
        captures: 0,
        named_captures: 0,
        inspection_work: 1,
    };
    enforce_build("HIR nodes", accounting.hir_nodes, limits.max_hir_nodes)?;
    let HirKind::Concat(root) = hir.kind() else {
        return Err(CaptureWordRunBuildError::Unsupported(
            "root must be a three-item concatenation",
        ));
    };
    if root.len() != 3 {
        return Err(CaptureWordRunBuildError::Unsupported(
            "root must contain two boundaries and one capture alternation",
        ));
    }
    account_node(&mut accounting, limits)?;
    let expected_look = match mode {
        CaptureWordRunMode::Ascii => Look::WordAscii,
        CaptureWordRunMode::Unicode => Look::WordUnicode,
    };
    if !matches!(root[0].kind(), HirKind::Look(actual) if *actual == expected_look)
        || !matches!(root[2].kind(), HirKind::Look(actual) if *actual == expected_look)
    {
        return Err(CaptureWordRunBuildError::Unsupported(
            "both outer assertions must be positive word boundaries",
        ));
    }
    account_node(&mut accounting, limits)?;

    let alternatives: &[Hir] = match root[1].kind() {
        HirKind::Alternation(branches) => branches,
        HirKind::Capture(_) => core::slice::from_ref(&root[1]),
        _ => {
            return Err(CaptureWordRunBuildError::Unsupported(
                "middle item must be a capture or capture alternation",
            ));
        }
    };
    if alternatives.is_empty() {
        return Err(CaptureWordRunBuildError::Unsupported(
            "capture alternation must be nonempty",
        ));
    }
    enforce_build("alternatives", alternatives.len(), limits.max_alternatives)?;

    let mut canonical_class = None;
    let mut exact_lengths = 0_u32;
    let mut group_by_length = [0_u32; 32];
    let mut minimum_length = u32::MAX;
    let mut maximum_length = 0_u32;
    for branch in alternatives {
        accounting.alternatives = accounting.alternatives.checked_add(1).ok_or(
            CaptureWordRunBuildError::ArithmeticOverflow("alternative count"),
        )?;
        account_node(&mut accounting, limits)?;
        let HirKind::Capture(capture) = branch.kind() else {
            return Err(CaptureWordRunBuildError::Unsupported(
                "every alternative must be one direct capture",
            ));
        };
        if capture.index == 0 {
            return Err(CaptureWordRunBuildError::InternalInvariant(
                "an explicit capture used group zero",
            ));
        }
        accounting.captures = accounting.captures.checked_add(1).ok_or(
            CaptureWordRunBuildError::ArithmeticOverflow("capture count"),
        )?;
        if capture.name.is_some() {
            accounting.named_captures = accounting.named_captures.checked_add(1).ok_or(
                CaptureWordRunBuildError::ArithmeticOverflow("named capture count"),
            )?;
        }
        account_node(&mut accounting, limits)?;
        let HirKind::Repetition(repetition) = capture.sub.kind() else {
            return Err(CaptureWordRunBuildError::Unsupported(
                "each capture must contain one exact repetition",
            ));
        };
        if !repetition.greedy || repetition.max != Some(repetition.min) || repetition.min == 0 {
            return Err(CaptureWordRunBuildError::Unsupported(
                "capture repetitions must be positive, exact and greedy",
            ));
        }
        let max_exact_length = limits.max_exact_length.min(MAX_EXACT_LENGTH);
        if repetition.min > max_exact_length {
            return Err(CaptureWordRunBuildError::Resource {
                resource: "exact repetition length",
                needed: usize::try_from(repetition.min).unwrap_or(usize::MAX),
                limit: usize::try_from(max_exact_length).unwrap_or(usize::MAX),
            });
        }
        account_node(&mut accounting, limits)?;
        let HirKind::Class(class) = repetition.sub.kind() else {
            return Err(CaptureWordRunBuildError::Unsupported(
                "exact repetition body must be one character class",
            ));
        };
        if let Some(canonical) = canonical_class {
            if canonical != class {
                return Err(CaptureWordRunBuildError::Unsupported(
                    "every alternative must repeat the same class",
                ));
            }
        } else {
            canonical_class = Some(class);
        }
        let length_index = usize::try_from(repetition.min).map_err(|_| {
            CaptureWordRunBuildError::ArithmeticOverflow("exact length as map index")
        })?;
        if group_by_length[length_index] == 0 {
            group_by_length[length_index] = capture.index;
        }
        exact_lengths |= 1_u32 << repetition.min;
        minimum_length = minimum_length.min(repetition.min);
        maximum_length = maximum_length.max(repetition.min);
    }
    let class = canonical_class.ok_or(CaptureWordRunBuildError::InternalInvariant(
        "nonempty alternatives did not retain a class",
    ))?;
    let (class_ranges, class_scalar_probes) = inspect_class_subset(class, mode, limits)?;
    accounting.class_ranges = class_ranges;
    accounting.class_scalar_probes = class_scalar_probes;
    charge_inspection(&mut accounting, class_ranges, limits)?;
    charge_inspection(&mut accounting, class_scalar_probes, limits)?;
    Ok(Inspection {
        class,
        exact_lengths,
        group_by_length,
        minimum_length,
        maximum_length,
        accounting,
    })
}

fn inspect_class_subset(
    class: &Class,
    mode: CaptureWordRunMode,
    limits: CaptureWordRunBuildLimits,
) -> Result<(usize, usize), CaptureWordRunBuildError> {
    match (mode, class) {
        (CaptureWordRunMode::Ascii, Class::Bytes(class)) => {
            enforce_build(
                "class ranges",
                class.ranges().len(),
                limits.max_class_ranges.min(MAX_CLASS_RANGES),
            )?;
            let mut probes = 0_usize;
            for range in class.ranges() {
                for byte in range.start()..=range.end() {
                    probes = probes.checked_add(1).ok_or(
                        CaptureWordRunBuildError::ArithmeticOverflow("ASCII class probes"),
                    )?;
                    if !is_ascii_word(byte) {
                        return Err(CaptureWordRunBuildError::Unsupported(
                            "consuming byte class must be a subset of ASCII word",
                        ));
                    }
                }
            }
            Ok((class.ranges().len(), probes))
        }
        (CaptureWordRunMode::Unicode, Class::Unicode(class)) => {
            enforce_build(
                "class ranges",
                class.ranges().len(),
                limits.max_class_ranges.min(MAX_CLASS_RANGES),
            )?;
            let mut probes = 0_usize;
            for range in class.ranges() {
                for scalar in u32::from(range.start())..=u32::from(range.end()) {
                    probes = probes.checked_add(1).ok_or(
                        CaptureWordRunBuildError::ArithmeticOverflow("Unicode class probes"),
                    )?;
                    let prospective = probes.checked_add(class.ranges().len()).ok_or(
                        CaptureWordRunBuildError::ArithmeticOverflow(
                            "Unicode class inspection work",
                        ),
                    )?;
                    if prospective > limits.max_inspection_work {
                        return Err(CaptureWordRunBuildError::Resource {
                            resource: "inspection work",
                            needed: prospective,
                            limit: limits.max_inspection_work,
                        });
                    }
                    let scalar = char::from_u32(scalar).ok_or(
                        CaptureWordRunBuildError::InternalInvariant(
                            "canonical Unicode class contains a non-scalar",
                        ),
                    )?;
                    if !is_unicode_word(scalar) {
                        return Err(CaptureWordRunBuildError::Unsupported(
                            "consuming Unicode class must be a subset of Unicode word",
                        ));
                    }
                }
            }
            Ok((class.ranges().len(), probes))
        }
        (CaptureWordRunMode::Ascii, Class::Unicode(_))
        | (CaptureWordRunMode::Unicode, Class::Bytes(_)) => {
            Err(CaptureWordRunBuildError::Unsupported(
                "class representation differs from the selected boundary mode",
            ))
        }
    }
}

fn build_matcher(
    class: &Class,
    mode: CaptureWordRunMode,
    limits: CaptureWordRunBuildLimits,
) -> Result<CaptureWordRunMatcher, CaptureWordRunBuildError> {
    match (mode, class) {
        (CaptureWordRunMode::Ascii, Class::Bytes(class)) => {
            let mut words = [0_u64; 2];
            for range in class.ranges() {
                for byte in range.start()..=range.end() {
                    let index = usize::from(byte) / 64;
                    let shift = usize::from(byte) % 64;
                    words[index] |= 1_u64 << shift;
                }
            }
            let dispatch = SimdDispatchContext::capture();
            let class_classifier = dispatch
                .ascii_byte_set_classifier(AsciiByteSet::from_words(words), DispatchPolicy::Auto)
                .expect("automatic ASCII classifier dispatch retains a scalar fallback");
            let word_classifier = dispatch
                .ascii_byte_set_classifier(ascii_word_set(), DispatchPolicy::Auto)
                .expect("automatic ASCII classifier dispatch retains a scalar fallback");
            Ok(CaptureWordRunMatcher::Ascii {
                class_classifier,
                word_classifier,
            })
        }
        (CaptureWordRunMode::Unicode, Class::Unicode(class)) => {
            let mut ranges = [ScalarRange::default(); MAX_CLASS_RANGES];
            if class.ranges().len() > limits.max_class_ranges.min(MAX_CLASS_RANGES) {
                return Err(CaptureWordRunBuildError::Resource {
                    resource: "class ranges",
                    needed: class.ranges().len(),
                    limit: limits.max_class_ranges.min(MAX_CLASS_RANGES),
                });
            }
            for (slot, range) in ranges.iter_mut().zip(class.ranges()) {
                *slot = ScalarRange {
                    start: u32::from(range.start()),
                    end: u32::from(range.end()),
                };
            }
            Ok(CaptureWordRunMatcher::Unicode {
                ranges,
                range_count: class.ranges().len(),
            })
        }
        _ => Err(CaptureWordRunBuildError::InternalInvariant(
            "inspected class representation changed before publication",
        )),
    }
}

fn scan_ascii(
    haystack: &[u8],
    class_classifier: &AsciiByteSetClassifier,
    word_classifier: &AsciiByteSetClassifier,
    exact_lengths: u32,
) -> Result<CaptureWordRunRunActual, CaptureWordRunRunError> {
    let mut matches = 0_usize;
    let mut previous_class_mask = 0_u32;
    let mut previous_word_mask = 0_u32;
    let mut block_events = 0_usize;
    let mut chunks = haystack.chunks_exact(ASCII_WIDE_BYTES);
    for chunk in &mut chunks {
        let block: &[u8; ASCII_WIDE_BYTES] =
            chunk
                .try_into()
                .map_err(|_| CaptureWordRunRunError::AccountingInvariant {
                    resource: CaptureWordRunRunResource::BlockEvents,
                    actual: chunk.len(),
                    upper: ASCII_WIDE_BYTES,
                })?;
        let current_class_mask = class_classifier.classify_32(block).member_mask();
        let current_word_mask = word_classifier.classify_32(block).member_mask();
        matches = matches
            .checked_add(count_exact_run_ends(
                previous_class_mask,
                current_class_mask,
                previous_word_mask,
                current_word_mask,
                exact_lengths,
            )?)
            .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                computation: "ASCII match count",
            })?;
        previous_class_mask = current_class_mask;
        previous_word_mask = current_word_mask;
        block_events =
            block_events
                .checked_add(1)
                .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                    computation: "ASCII block events",
                })?;
    }
    let remainder = chunks.remainder();
    let mut padded = [0_u8; ASCII_WIDE_BYTES];
    padded[..remainder.len()].copy_from_slice(remainder);
    let current_class_mask = class_classifier.classify_32(&padded).member_mask();
    let current_word_mask = word_classifier.classify_32(&padded).member_mask();
    matches = matches
        .checked_add(count_exact_run_ends(
            previous_class_mask,
            current_class_mask,
            previous_word_mask,
            current_word_mask,
            exact_lengths,
        )?)
        .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
            computation: "ASCII tail match count",
        })?;
    block_events =
        block_events
            .checked_add(1)
            .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                computation: "ASCII tail block event",
            })?;
    let capture_count = matches.checked_mul(GROUPS_PER_MATCH).ok_or(
        CaptureWordRunRunError::ArithmeticOverflow {
            computation: "ASCII capture count",
        },
    )?;
    let block_work = exact_length_shift_work(exact_lengths)?
        .checked_add(2)
        .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
            computation: "ASCII block work",
        })?;
    let work = haystack
        .len()
        .checked_add(block_events.checked_mul(block_work).ok_or(
            CaptureWordRunRunError::ArithmeticOverflow {
                computation: "ASCII block work",
            },
        )?)
        .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
            computation: "ASCII total work",
        })?;
    Ok(CaptureWordRunRunActual {
        source_reads: haystack.len(),
        decoded_units: haystack.len(),
        block_events,
        matches,
        capture_count,
        work,
        sequential_bytes: haystack.len(),
        ..CaptureWordRunRunActual::default()
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "the authenticated fixed record schema and scanner artifacts stay explicit"
)]
fn visit_ascii_records<F>(
    line_index: usize,
    line: &[u8],
    class_classifier: &AsciiByteSetClassifier,
    word_classifier: &AsciiByteSetClassifier,
    exact_lengths: u32,
    group_by_length: &[u32; 32],
    numeric_groups: usize,
    actual: &mut CaptureWordRunRecordVisitReport,
    visitor: &mut F,
) -> Result<(), CaptureWordRunRunError>
where
    F: FnMut(usize, usize, CaptureWordRunRecord),
{
    let mut previous_class_mask = 0_u32;
    let mut previous_word_mask = 0_u32;
    let mut block_start = 0_usize;
    let mut line_block_events = 0_usize;
    let mut chunks = line.chunks_exact(ASCII_WIDE_BYTES);
    for chunk in &mut chunks {
        let block: &[u8; ASCII_WIDE_BYTES] = chunk
            .try_into()
            .expect("chunks_exact yields one complete ASCII-wide block");
        let current_class_mask = class_classifier.classify_32(block).member_mask();
        let current_word_mask = word_classifier.classify_32(block).member_mask();
        visit_ascii_block_records(
            line_index,
            line.len(),
            block_start,
            previous_class_mask,
            current_class_mask,
            previous_word_mask,
            current_word_mask,
            exact_lengths,
            group_by_length,
            numeric_groups,
            actual,
            visitor,
        )?;
        previous_class_mask = current_class_mask;
        previous_word_mask = current_word_mask;
        block_start = checked_add(block_start, ASCII_WIDE_BYTES, "record ASCII block cursor")?;
        line_block_events = checked_add(line_block_events, 1, "record ASCII line block events")?;
    }
    let remainder = chunks.remainder();
    let mut padded = [0_u8; ASCII_WIDE_BYTES];
    padded[..remainder.len()].copy_from_slice(remainder);
    let current_class_mask = class_classifier.classify_32(&padded).member_mask();
    let current_word_mask = word_classifier.classify_32(&padded).member_mask();
    visit_ascii_block_records(
        line_index,
        line.len(),
        block_start,
        previous_class_mask,
        current_class_mask,
        previous_word_mask,
        current_word_mask,
        exact_lengths,
        group_by_length,
        numeric_groups,
        actual,
        visitor,
    )?;
    line_block_events = checked_add(line_block_events, 1, "record ASCII tail block event")?;
    actual.decoded_units = checked_add(
        actual.decoded_units,
        line.len(),
        "record ASCII decoded units",
    )?;
    actual.block_events = checked_add(
        actual.block_events,
        line_block_events,
        "record ASCII block events",
    )?;
    let block_work = line_block_events
        .checked_mul(record_ascii_block_work(exact_lengths)?)
        .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
            computation: "record ASCII block work",
        })?;
    actual.work = checked_add(actual.work, line.len(), "record ASCII byte work")?;
    actual.work = checked_add(actual.work, block_work, "record ASCII block work")?;
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the two adjacent SIMD masks and fixed record schema are the complete block state"
)]
fn visit_ascii_block_records<F>(
    line_index: usize,
    line_len: usize,
    block_start: usize,
    previous_class_mask: u32,
    current_class_mask: u32,
    previous_word_mask: u32,
    current_word_mask: u32,
    exact_lengths: u32,
    group_by_length: &[u32; 32],
    numeric_groups: usize,
    actual: &mut CaptureWordRunRecordVisitReport,
    visitor: &mut F,
) -> Result<(), CaptureWordRunRunError>
where
    F: FnMut(usize, usize, CaptureWordRunRecord),
{
    let joined_class = u64::from(previous_class_mask) | (u64::from(current_class_mask) << 32);
    let joined_word = u64::from(previous_word_mask) | (u64::from(current_word_mask) << 32);
    let mut endpoint_lengths = [0_u8; ASCII_WIDE_BYTES];
    let mut endpoint_mask = 0_u32;
    let mut remaining = exact_lengths;
    while remaining != 0 {
        let length = remaining.trailing_zeros();
        remaining &=
            remaining
                .checked_sub(1)
                .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                    computation: "record nonempty exact-length mask decrement",
                })?;
        let mut endings = !joined_word;
        for shift in 1..=length {
            endings &= joined_class << shift;
        }
        let left_boundary_shift =
            length
                .checked_add(1)
                .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                    computation: "record exact-run left-boundary shift",
                })?;
        endings &= !(joined_word << left_boundary_shift);
        let mut current_endings = u32::try_from(endings >> 32).map_err(|_| {
            CaptureWordRunRunError::ArithmeticOverflow {
                computation: "record ASCII endpoint mask as u32",
            }
        })?;
        while current_endings != 0 {
            let endpoint_in_block = usize::try_from(current_endings.trailing_zeros()).map_err(
                |_| CaptureWordRunRunError::ArithmeticOverflow {
                    computation: "record ASCII endpoint offset as usize",
                },
            )?;
            current_endings &= current_endings.checked_sub(1).ok_or(
                CaptureWordRunRunError::ArithmeticOverflow {
                    computation: "record ASCII endpoint-mask decrement",
                },
            )?;
            let endpoint = checked_add(block_start, endpoint_in_block, "record ASCII endpoint")?;
            if endpoint > line_len {
                continue;
            }
            if endpoint_lengths[endpoint_in_block] != 0 {
                return Err(CaptureWordRunRunError::AccountingInvariant {
                    resource: CaptureWordRunRunResource::Matches,
                    actual: usize::from(endpoint_lengths[endpoint_in_block]),
                    upper: 0,
                });
            }
            endpoint_lengths[endpoint_in_block] = u8::try_from(length).map_err(|_| {
                CaptureWordRunRunError::ArithmeticOverflow {
                    computation: "record ASCII exact length as u8",
                }
            })?;
            endpoint_mask |= 1_u32 << endpoint_in_block;
        }
    }
    while endpoint_mask != 0 {
        let endpoint_in_block = usize::try_from(endpoint_mask.trailing_zeros()).map_err(|_| {
            CaptureWordRunRunError::ArithmeticOverflow {
                computation: "record ASCII ordered endpoint offset as usize",
            }
        })?;
        endpoint_mask &=
            endpoint_mask
                .checked_sub(1)
                .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                    computation: "record ASCII ordered endpoint-mask decrement",
                })?;
        let length = usize::from(endpoint_lengths[endpoint_in_block]);
        let end = checked_add(
            block_start,
            endpoint_in_block,
            "record ASCII emitted endpoint",
        )?;
        let group = usize::try_from(group_by_length[length]).map_err(|_| {
            CaptureWordRunRunError::ArithmeticOverflow {
                computation: "record ASCII capture group as usize",
            }
        })?;
        if group == 0 || group >= numeric_groups {
            return Err(CaptureWordRunRunError::AccountingInvariant {
                resource: CaptureWordRunRunResource::CaptureEvents,
                actual: group,
                upper: numeric_groups.saturating_sub(1),
            });
        }
        let start = end
            .checked_sub(length)
            .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                computation: "record ASCII emitted start",
            })?;
        actual.matches = checked_add(actual.matches, 1, "record ASCII matches")?;
        visitor(
            line_index,
            line_len,
            CaptureWordRunRecord {
                overall: CaptureWordRunSpan { start, end },
                participating_group: group,
                numeric_groups,
            },
        );
    }
    Ok(())
}

fn record_ascii_block_work(exact_lengths: u32) -> Result<usize, CaptureWordRunRunError> {
    let mut work = 2_usize;
    let mut remaining = exact_lengths;
    while remaining != 0 {
        let length = usize::try_from(remaining.trailing_zeros()).map_err(|_| {
            CaptureWordRunRunError::ArithmeticOverflow {
                computation: "record ASCII work length as usize",
            }
        })?;
        remaining &=
            remaining
                .checked_sub(1)
                .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                    computation: "record ASCII work-mask decrement",
                })?;
        let length_work =
            length
                .checked_add(2)
                .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                    computation: "record ASCII per-length work",
                })?;
        work = checked_add(work, length_work, "record ASCII total block work")?;
    }
    Ok(work)
}

fn count_exact_run_ends(
    previous_class_mask: u32,
    current_class_mask: u32,
    previous_word_mask: u32,
    current_word_mask: u32,
    exact_lengths: u32,
) -> Result<usize, CaptureWordRunRunError> {
    let joined_class = u64::from(previous_class_mask) | (u64::from(current_class_mask) << 32);
    let joined_word = u64::from(previous_word_mask) | (u64::from(current_word_mask) << 32);
    let mut count = 0_usize;
    let mut remaining = exact_lengths;
    while remaining != 0 {
        let length = remaining.trailing_zeros();
        remaining &=
            remaining
                .checked_sub(1)
                .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                    computation: "nonempty exact-length mask decrement",
                })?;
        let mut endings = !joined_word;
        for shift in 1..=length {
            endings &= joined_class << shift;
        }
        let left_boundary_shift =
            length
                .checked_add(1)
                .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                    computation: "exact-run left-boundary shift",
                })?;
        endings &= !(joined_word << left_boundary_shift);
        let current_endings = u32::try_from(endings >> 32).map_err(|_| {
            CaptureWordRunRunError::ArithmeticOverflow {
                computation: "ASCII endpoint mask as u32",
            }
        })?;
        count = count
            .checked_add(usize::try_from(current_endings.count_ones()).map_err(|_| {
                CaptureWordRunRunError::ArithmeticOverflow {
                    computation: "ASCII endpoint count as usize",
                }
            })?)
            .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                computation: "ASCII exact-run endpoint count",
            })?;
    }
    Ok(count)
}

fn scan_unicode(
    haystack: &[u8],
    ranges: &[ScalarRange],
    exact_lengths: u32,
) -> Result<CaptureWordRunRunActual, CaptureWordRunRunError> {
    let mut actual = CaptureWordRunRunActual {
        sequential_bytes: haystack.len(),
        ..CaptureWordRunRunActual::default()
    };
    let mut position = 0_usize;
    let mut previous_scalar = None;
    let mut run_length = 0_u32;
    let mut run_left_boundary = false;
    while position < haystack.len() {
        let (scalar, width) = decode_first(&haystack[position..])
            .map_or((None, 1), |(scalar, width)| (Some(scalar), width));
        actual.source_reads = checked_add(actual.source_reads, width, "Unicode source reads")?;
        actual.decoded_units = checked_add(actual.decoded_units, 1, "Unicode decoded units")?;
        actual.work = checked_add(actual.work, 2, "Unicode base work")?;
        let in_class = if let Some(scalar) = scalar {
            class_contains(ranges, scalar, &mut actual)?
        } else {
            false
        };
        if in_class {
            if run_length == 0 {
                actual.boundary_probes =
                    checked_add(actual.boundary_probes, 1, "Unicode boundary probes")?;
                actual.work = checked_add(actual.work, 1, "Unicode boundary work")?;
                run_left_boundary = !previous_scalar.is_some_and(is_unicode_word);
            }
            run_length =
                run_length
                    .checked_add(1)
                    .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                        computation: "Unicode class-run length",
                    })?;
        } else if run_length != 0 {
            actual.boundary_probes =
                checked_add(actual.boundary_probes, 1, "Unicode boundary probes")?;
            actual.work = checked_add(actual.work, 1, "Unicode boundary work")?;
            let right_boundary = !scalar.is_some_and(is_unicode_word);
            if run_left_boundary
                && right_boundary
                && exact_length_is_admitted(exact_lengths, run_length)
            {
                actual.matches = checked_add(actual.matches, 1, "Unicode matches")?;
            }
            run_length = 0;
        }
        previous_scalar = scalar;
        position = checked_add(position, width, "Unicode input cursor")?;
    }
    if run_length != 0 && run_left_boundary && exact_length_is_admitted(exact_lengths, run_length) {
        actual.boundary_probes =
            checked_add(actual.boundary_probes, 1, "Unicode EOF boundary probe")?;
        actual.work = checked_add(actual.work, 1, "Unicode EOF boundary work")?;
        actual.matches = checked_add(actual.matches, 1, "Unicode EOF match")?;
    }
    actual.capture_count = actual.matches.checked_mul(GROUPS_PER_MATCH).ok_or(
        CaptureWordRunRunError::ArithmeticOverflow {
            computation: "Unicode capture count",
        },
    )?;
    Ok(actual)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the authenticated fixed record schema and scalar scanner state stay explicit"
)]
fn visit_unicode_records<F>(
    line_index: usize,
    line: &[u8],
    ranges: &[ScalarRange],
    exact_lengths: u32,
    group_by_length: &[u32; 32],
    numeric_groups: usize,
    actual: &mut CaptureWordRunRecordVisitReport,
    visitor: &mut F,
) -> Result<(), CaptureWordRunRunError>
where
    F: FnMut(usize, usize, CaptureWordRunRecord),
{
    let mut position = 0_usize;
    let mut previous_scalar = None;
    let mut run_start = 0_usize;
    let mut run_length = 0_u32;
    let mut run_left_boundary = false;
    while position < line.len() {
        let (scalar, width) = decode_first(&line[position..])
            .map_or((None, 1), |(scalar, width)| (Some(scalar), width));
        actual.decoded_units =
            checked_add(actual.decoded_units, 1, "record Unicode decoded units")?;
        actual.work = checked_add(actual.work, 2, "record Unicode base work")?;
        let in_class = if let Some(scalar) = scalar {
            record_class_contains(ranges, scalar, actual)?
        } else {
            false
        };
        if in_class {
            if run_length == 0 {
                actual.boundary_probes = checked_add(
                    actual.boundary_probes,
                    1,
                    "record Unicode left-boundary probes",
                )?;
                actual.work = checked_add(actual.work, 1, "record Unicode boundary work")?;
                run_start = position;
                run_left_boundary = !previous_scalar.is_some_and(is_unicode_word);
            }
            run_length =
                run_length
                    .checked_add(1)
                    .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                        computation: "record Unicode class-run length",
                    })?;
        } else if run_length != 0 {
            actual.boundary_probes = checked_add(
                actual.boundary_probes,
                1,
                "record Unicode right-boundary probes",
            )?;
            actual.work = checked_add(actual.work, 1, "record Unicode boundary work")?;
            let right_boundary = !scalar.is_some_and(is_unicode_word);
            if run_left_boundary
                && right_boundary
                && exact_length_is_admitted(exact_lengths, run_length)
            {
                let length = usize::try_from(run_length).map_err(|_| {
                    CaptureWordRunRunError::ArithmeticOverflow {
                        computation: "record Unicode run length as usize",
                    }
                })?;
                let group = usize::try_from(group_by_length[length]).map_err(|_| {
                    CaptureWordRunRunError::ArithmeticOverflow {
                        computation: "record Unicode capture group as usize",
                    }
                })?;
                if group == 0 || group >= numeric_groups {
                    return Err(CaptureWordRunRunError::AccountingInvariant {
                        resource: CaptureWordRunRunResource::CaptureEvents,
                        actual: group,
                        upper: numeric_groups.saturating_sub(1),
                    });
                }
                actual.matches = checked_add(actual.matches, 1, "record Unicode matches")?;
                visitor(
                    line_index,
                    line.len(),
                    CaptureWordRunRecord {
                        overall: CaptureWordRunSpan {
                            start: run_start,
                            end: position,
                        },
                        participating_group: group,
                        numeric_groups,
                    },
                );
            }
            run_length = 0;
        }
        previous_scalar = scalar;
        position = checked_add(position, width, "record Unicode input cursor")?;
    }
    if run_length != 0 && run_left_boundary && exact_length_is_admitted(exact_lengths, run_length) {
        actual.boundary_probes = checked_add(
            actual.boundary_probes,
            1,
            "record Unicode EOF boundary probe",
        )?;
        actual.work = checked_add(actual.work, 1, "record Unicode EOF boundary work")?;
        let length = usize::try_from(run_length).map_err(|_| {
            CaptureWordRunRunError::ArithmeticOverflow {
                computation: "record Unicode EOF run length as usize",
            }
        })?;
        let group = usize::try_from(group_by_length[length]).map_err(|_| {
            CaptureWordRunRunError::ArithmeticOverflow {
                computation: "record Unicode EOF capture group as usize",
            }
        })?;
        if group == 0 || group >= numeric_groups {
            return Err(CaptureWordRunRunError::AccountingInvariant {
                resource: CaptureWordRunRunResource::CaptureEvents,
                actual: group,
                upper: numeric_groups.saturating_sub(1),
            });
        }
        actual.matches = checked_add(actual.matches, 1, "record Unicode EOF match")?;
        visitor(
            line_index,
            line.len(),
            CaptureWordRunRecord {
                overall: CaptureWordRunSpan {
                    start: run_start,
                    end: line.len(),
                },
                participating_group: group,
                numeric_groups,
            },
        );
    }
    Ok(())
}

fn record_class_contains(
    ranges: &[ScalarRange],
    scalar: char,
    actual: &mut CaptureWordRunRecordVisitReport,
) -> Result<bool, CaptureWordRunRunError> {
    let scalar = u32::from(scalar);
    let mut lower = 0_usize;
    let mut upper = ranges.len();
    while lower < upper {
        actual.class_comparisons = checked_add(
            actual.class_comparisons,
            1,
            "record Unicode class comparisons",
        )?;
        actual.work = checked_add(actual.work, 1, "record Unicode class-comparison work")?;
        let span = upper
            .checked_sub(lower)
            .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                computation: "record Unicode class-search span",
            })?;
        let middle =
            lower
                .checked_add(span / 2)
                .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                    computation: "record Unicode class-search midpoint",
                })?;
        let range = ranges[middle];
        if scalar < range.start {
            upper = middle;
        } else if scalar > range.end {
            lower = middle
                .checked_add(1)
                .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                    computation: "record Unicode class-search lower bound",
                })?;
        } else {
            return Ok(true);
        }
    }
    Ok(false)
}

fn class_contains(
    ranges: &[ScalarRange],
    scalar: char,
    actual: &mut CaptureWordRunRunActual,
) -> Result<bool, CaptureWordRunRunError> {
    let scalar = u32::from(scalar);
    let mut lower = 0_usize;
    let mut upper = ranges.len();
    while lower < upper {
        actual.class_comparisons =
            checked_add(actual.class_comparisons, 1, "Unicode class comparisons")?;
        actual.work = checked_add(actual.work, 1, "Unicode class comparison work")?;
        let span = upper
            .checked_sub(lower)
            .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                computation: "Unicode class-search span",
            })?;
        let middle =
            lower
                .checked_add(span / 2)
                .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                    computation: "Unicode class-search midpoint",
                })?;
        let range = ranges[middle];
        if scalar < range.start {
            upper = middle;
        } else if scalar > range.end {
            lower = middle
                .checked_add(1)
                .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                    computation: "Unicode class-search lower bound",
                })?;
        } else {
            return Ok(true);
        }
    }
    Ok(false)
}

fn exact_length_shift_work(exact_lengths: u32) -> Result<usize, CaptureWordRunRunError> {
    let mut work = 0_usize;
    let mut remaining = exact_lengths;
    while remaining != 0 {
        let length = remaining.trailing_zeros();
        remaining &=
            remaining
                .checked_sub(1)
                .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                    computation: "nonempty exact-length work mask decrement",
                })?;
        work = work
            .checked_add(usize::try_from(length).map_err(|_| {
                CaptureWordRunRunError::ArithmeticOverflow {
                    computation: "exact length as usize",
                }
            })?)
            .and_then(|value| value.checked_add(2))
            .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                computation: "exact-length shift work",
            })?;
    }
    Ok(work)
}

const fn exact_length_is_admitted(exact_lengths: u32, length: u32) -> bool {
    length < u32::BITS && exact_lengths & (1_u32 << length) != 0
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

fn enforce_run_limits(
    upper: CaptureWordRunRunUpperBounds,
    limits: CaptureWordRunRunLimits,
) -> Result<(), CaptureWordRunRunError> {
    for (resource, needed, limit) in [
        (
            CaptureWordRunRunResource::InputBytes,
            upper.input_bytes,
            limits.max_input_bytes,
        ),
        (
            CaptureWordRunRunResource::SourceReads,
            upper.source_reads,
            limits.max_source_reads,
        ),
        (
            CaptureWordRunRunResource::DecodedUnits,
            upper.decoded_units,
            limits.max_decoded_units,
        ),
        (
            CaptureWordRunRunResource::BlockEvents,
            upper.block_events,
            limits.max_block_events,
        ),
        (
            CaptureWordRunRunResource::ClassComparisons,
            upper.class_comparisons,
            limits.max_class_comparisons,
        ),
        (
            CaptureWordRunRunResource::BoundaryProbes,
            upper.boundary_probes,
            limits.max_boundary_probes,
        ),
        (
            CaptureWordRunRunResource::Matches,
            upper.matches,
            limits.max_matches,
        ),
        (
            CaptureWordRunRunResource::CaptureCount,
            upper.capture_count,
            limits.max_capture_count,
        ),
        (CaptureWordRunRunResource::Work, upper.work, limits.max_work),
        (
            CaptureWordRunRunResource::SequentialBytes,
            upper.sequential_bytes,
            limits.max_sequential_bytes,
        ),
        (
            CaptureWordRunRunResource::PeakBytes,
            upper.peak_bytes,
            limits.max_peak_bytes,
        ),
    ] {
        if needed > limit {
            return Err(CaptureWordRunRunError::Resource {
                resource,
                needed,
                limit,
            });
        }
    }
    Ok(())
}

fn enforce_record_run_limits(
    upper: CaptureWordRunRecordRunUpperBounds,
    limits: CaptureWordRunRecordRunLimits,
) -> Result<(), CaptureWordRunRunError> {
    for (resource, needed, limit) in [
        (
            CaptureWordRunRunResource::InputBytes,
            upper.input_bytes,
            limits.max_input_bytes,
        ),
        (
            CaptureWordRunRunResource::LineDomains,
            upper.line_domains,
            limits.max_line_domains,
        ),
        (
            CaptureWordRunRunResource::SourceReads,
            upper.source_reads,
            limits.max_source_reads,
        ),
        (
            CaptureWordRunRunResource::DecodedUnits,
            upper.decoded_units,
            limits.max_decoded_units,
        ),
        (
            CaptureWordRunRunResource::BlockEvents,
            upper.block_events,
            limits.max_block_events,
        ),
        (
            CaptureWordRunRunResource::ClassComparisons,
            upper.class_comparisons,
            limits.max_class_comparisons,
        ),
        (
            CaptureWordRunRunResource::BoundaryProbes,
            upper.boundary_probes,
            limits.max_boundary_probes,
        ),
        (
            CaptureWordRunRunResource::Matches,
            upper.matches,
            limits.max_matches,
        ),
        (
            CaptureWordRunRunResource::CaptureCount,
            upper.capture_count,
            limits.max_capture_count,
        ),
        (
            CaptureWordRunRunResource::CaptureEvents,
            upper.capture_events,
            limits.max_capture_events,
        ),
        (
            CaptureWordRunRunResource::EndpointReads,
            upper.endpoint_reads,
            limits.max_endpoint_reads,
        ),
        (
            CaptureWordRunRunResource::ReducerEvents,
            upper.reducer_events,
            limits.max_reducer_events,
        ),
        (CaptureWordRunRunResource::Work, upper.work, limits.max_work),
        (
            CaptureWordRunRunResource::SequentialBytes,
            upper.sequential_bytes,
            limits.max_sequential_bytes,
        ),
        (
            CaptureWordRunRunResource::PeakBytes,
            upper.peak_bytes,
            limits.max_peak_bytes,
        ),
    ] {
        if needed > limit {
            return Err(CaptureWordRunRunError::Resource {
                resource,
                needed,
                limit,
            });
        }
    }
    Ok(())
}

fn verify_record_actual(
    actual: &CaptureWordRunRecordVisitReport,
    upper: CaptureWordRunRecordRunUpperBounds,
) -> Result<(), CaptureWordRunRunError> {
    for (resource, observed, bound) in [
        (
            CaptureWordRunRunResource::LineDomains,
            actual.line_domains,
            upper.line_domains,
        ),
        (
            CaptureWordRunRunResource::SourceReads,
            actual.source_reads,
            upper.source_reads,
        ),
        (
            CaptureWordRunRunResource::DecodedUnits,
            actual.decoded_units,
            upper.decoded_units,
        ),
        (
            CaptureWordRunRunResource::BlockEvents,
            actual.block_events,
            upper.block_events,
        ),
        (
            CaptureWordRunRunResource::ClassComparisons,
            actual.class_comparisons,
            upper.class_comparisons,
        ),
        (
            CaptureWordRunRunResource::BoundaryProbes,
            actual.boundary_probes,
            upper.boundary_probes,
        ),
        (
            CaptureWordRunRunResource::Matches,
            actual.matches,
            upper.matches,
        ),
        (
            CaptureWordRunRunResource::CaptureCount,
            actual.capture_count,
            upper.capture_count,
        ),
        (
            CaptureWordRunRunResource::CaptureEvents,
            actual.capture_events,
            upper.capture_events,
        ),
        (
            CaptureWordRunRunResource::EndpointReads,
            actual.endpoint_reads,
            upper.endpoint_reads,
        ),
        (
            CaptureWordRunRunResource::ReducerEvents,
            actual.reducer_events,
            upper.reducer_events,
        ),
        (CaptureWordRunRunResource::Work, actual.work, upper.work),
        (
            CaptureWordRunRunResource::SequentialBytes,
            actual.sequential_bytes,
            upper.sequential_bytes,
        ),
    ] {
        if observed > bound {
            return Err(CaptureWordRunRunError::AccountingInvariant {
                resource,
                actual: observed,
                upper: bound,
            });
        }
    }
    let expected_capture_count = actual.matches.checked_mul(GROUPS_PER_MATCH).ok_or(
        CaptureWordRunRunError::ArithmeticOverflow {
            computation: "record actual capture-count closure",
        },
    )?;
    let expected_capture_events = actual
        .matches
        .checked_mul(actual.identity.numeric_groups)
        .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
            computation: "record actual capture-event closure",
        })?;
    let expected_endpoint_reads =
        actual
            .capture_count
            .checked_mul(2)
            .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
                computation: "record actual endpoint-read closure",
            })?;
    let expected_reducer_events = actual
        .line_domains
        .checked_add(actual.capture_events)
        .ok_or(CaptureWordRunRunError::ArithmeticOverflow {
            computation: "record actual reducer-event closure",
        })?;
    if actual.capture_count != expected_capture_count
        || actual.capture_events != expected_capture_events
        || actual.endpoint_reads != expected_endpoint_reads
        || actual.reducer_events != expected_reducer_events
    {
        return Err(CaptureWordRunRunError::AccountingInvariant {
            resource: CaptureWordRunRunResource::CaptureEvents,
            actual: actual.capture_events,
            upper: expected_capture_events,
        });
    }
    Ok(())
}

fn verify_actual(
    actual: CaptureWordRunRunActual,
    upper: CaptureWordRunRunUpperBounds,
) -> Result<(), CaptureWordRunRunError> {
    for (resource, actual, upper) in [
        (
            CaptureWordRunRunResource::SourceReads,
            actual.source_reads,
            upper.source_reads,
        ),
        (
            CaptureWordRunRunResource::DecodedUnits,
            actual.decoded_units,
            upper.decoded_units,
        ),
        (
            CaptureWordRunRunResource::BlockEvents,
            actual.block_events,
            upper.block_events,
        ),
        (
            CaptureWordRunRunResource::ClassComparisons,
            actual.class_comparisons,
            upper.class_comparisons,
        ),
        (
            CaptureWordRunRunResource::BoundaryProbes,
            actual.boundary_probes,
            upper.boundary_probes,
        ),
        (
            CaptureWordRunRunResource::Matches,
            actual.matches,
            upper.matches,
        ),
        (
            CaptureWordRunRunResource::CaptureCount,
            actual.capture_count,
            upper.capture_count,
        ),
        (CaptureWordRunRunResource::Work, actual.work, upper.work),
        (
            CaptureWordRunRunResource::SequentialBytes,
            actual.sequential_bytes,
            upper.sequential_bytes,
        ),
    ] {
        if actual > upper {
            return Err(CaptureWordRunRunError::AccountingInvariant {
                resource,
                actual,
                upper,
            });
        }
    }
    if actual.source_reads != upper.input_bytes
        || actual.sequential_bytes != upper.input_bytes
        || actual.capture_count != actual.matches.saturating_mul(GROUPS_PER_MATCH)
    {
        return Err(CaptureWordRunRunError::AccountingInvariant {
            resource: CaptureWordRunRunResource::CaptureCount,
            actual: actual.capture_count,
            upper: actual.matches.saturating_mul(GROUPS_PER_MATCH),
        });
    }
    Ok(())
}

fn account_node(
    accounting: &mut CaptureWordRunHirAccounting,
    limits: CaptureWordRunBuildLimits,
) -> Result<(), CaptureWordRunBuildError> {
    accounting.hir_nodes =
        accounting
            .hir_nodes
            .checked_add(1)
            .ok_or(CaptureWordRunBuildError::ArithmeticOverflow(
                "HIR node count",
            ))?;
    enforce_build("HIR nodes", accounting.hir_nodes, limits.max_hir_nodes)?;
    charge_inspection(accounting, 1, limits)
}

fn charge_inspection(
    accounting: &mut CaptureWordRunHirAccounting,
    work: usize,
    limits: CaptureWordRunBuildLimits,
) -> Result<(), CaptureWordRunBuildError> {
    accounting.inspection_work = accounting.inspection_work.checked_add(work).ok_or(
        CaptureWordRunBuildError::ArithmeticOverflow("inspection work"),
    )?;
    enforce_build(
        "inspection work",
        accounting.inspection_work,
        limits.max_inspection_work,
    )
}

fn enforce_build(
    resource: &'static str,
    needed: usize,
    limit: usize,
) -> Result<(), CaptureWordRunBuildError> {
    if needed > limit {
        return Err(CaptureWordRunBuildError::Resource {
            resource,
            needed,
            limit,
        });
    }
    Ok(())
}

fn checked_add(
    value: usize,
    addend: usize,
    computation: &'static str,
) -> Result<usize, CaptureWordRunRunError> {
    value
        .checked_add(addend)
        .ok_or(CaptureWordRunRunError::ArithmeticOverflow { computation })
}

const fn is_ascii_word(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn ascii_word_set() -> AsciiByteSet {
    let mut words = [0_u64; 2];
    for byte in 0_u8..=0x7f {
        if is_ascii_word(byte) {
            let index = usize::from(byte) / 64;
            let shift = usize::from(byte) % 64;
            words[index] |= 1_u64 << shift;
        }
    }
    AsciiByteSet::from_words(words)
}

fn is_unicode_word(scalar: char) -> bool {
    if scalar.is_ascii() {
        return scalar == '_' || scalar.is_ascii_alphanumeric();
    }
    regex_syntax::try_is_word_character(scalar)
        .expect("fre enables regex-syntax's Unicode Perl tables")
}

fn decode_first(bytes: &[u8]) -> Option<(char, usize)> {
    let first = *bytes.first()?;
    if first.is_ascii() {
        return Some((char::from(first), 1));
    }
    let width = match first {
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => return None,
    };
    let scalar = core::str::from_utf8(bytes.get(..width)?)
        .ok()?
        .chars()
        .next()?;
    Some((scalar, width))
}

#[derive(Clone, Copy)]
struct StructuralDigest {
    words: [u64; 2],
}

impl StructuralDigest {
    const fn new() -> Self {
        Self {
            words: [DIGEST_OFFSET_A, DIGEST_OFFSET_B],
        }
    }

    fn byte(&mut self, byte: u8) {
        self.words[0] = (self.words[0] ^ u64::from(byte)).wrapping_mul(DIGEST_PRIME_A);
        self.words[1] = (self.words[1] ^ u64::from(byte)).wrapping_mul(DIGEST_PRIME_B);
    }

    fn usize(&mut self, value: usize) {
        for byte in value.to_le_bytes() {
            self.byte(byte);
        }
    }

    fn u32(&mut self, value: u32) {
        for byte in value.to_le_bytes() {
            self.byte(byte);
        }
    }

    const fn finish(self) -> [u64; 2] {
        self.words
    }
}

fn digest_source(source: &[u8]) -> [u64; 2] {
    let mut digest = StructuralDigest::new();
    digest.byte(0x53);
    digest.usize(source.len());
    for &byte in source {
        digest.byte(byte);
    }
    digest.finish()
}

fn digest_class(class: &Class, mode: CaptureWordRunMode) -> [u64; 2] {
    let mut digest = StructuralDigest::new();
    digest.byte(match mode {
        CaptureWordRunMode::Ascii => 0x41,
        CaptureWordRunMode::Unicode => 0x55,
    });
    match class {
        Class::Bytes(class) => {
            digest.usize(class.ranges().len());
            for range in class.ranges() {
                digest.byte(range.start());
                digest.byte(range.end());
            }
        }
        Class::Unicode(class) => {
            digest.usize(class.ranges().len());
            for range in class.ranges() {
                digest.u32(u32::from(range.start()));
                digest.u32(u32::from(range.end()));
            }
        }
    }
    digest.finish()
}

fn digest_group_by_length(group_by_length: &[u32; 32], numeric_groups: usize) -> [u64; 2] {
    let mut digest = StructuralDigest::new();
    digest.byte(0x47);
    digest.usize(numeric_groups);
    for (length, &group) in group_by_length.iter().enumerate() {
        digest.usize(length);
        digest.u32(group);
    }
    digest.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::bytes::RegexBuilder;

    fn exact_limits(plan: &CaptureWordRunPlan, input_bytes: usize) -> CaptureWordRunRunLimits {
        let upper = plan.run_upper_bounds(input_bytes).expect("upper bounds");
        CaptureWordRunRunLimits {
            max_input_bytes: upper.input_bytes,
            max_source_reads: upper.source_reads,
            max_decoded_units: upper.decoded_units,
            max_block_events: upper.block_events,
            max_class_comparisons: upper.class_comparisons,
            max_boundary_probes: upper.boundary_probes,
            max_matches: upper.matches,
            max_capture_count: upper.capture_count,
            max_work: upper.work,
            max_sequential_bytes: upper.sequential_bytes,
            max_peak_bytes: upper.peak_bytes,
        }
    }

    fn reference_capture_count(pattern: &str, unicode: bool, haystack: &[u8]) -> usize {
        let regex = RegexBuilder::new(pattern)
            .unicode(unicode)
            .build()
            .expect("reference regex");
        regex
            .captures_iter(haystack)
            .map(|captures| captures.iter().flatten().count())
            .sum()
    }

    #[test]
    fn ascii_exact_runs_cross_blocks_and_close_at_eof() {
        let plan = CaptureWordRunBuilder::new(r"\b(?:(\w{6})|(\w{5}))\b")
            .unicode(false)
            .build()
            .expect("ASCII word-run plan");
        let mut haystack = b"one alpha longer sixes ".to_vec();
        haystack.extend_from_slice(&[b' '; 8]);
        haystack.extend_from_slice(b"bravo");
        haystack.extend_from_slice(&[b' '; 27]);
        haystack.extend_from_slice(b"planet");
        let result = plan
            .grep_capture_count(&haystack, exact_limits(&plan, haystack.len()))
            .expect("count");
        assert_eq!(result.actual.matches, 5);
        assert_eq!(result.capture_count, 10);
        assert_eq!(
            result.identity.operation_id,
            CAPTURE_WORD_RUN_COUNT_OPERATION_ID
        );
    }

    #[test]
    fn unicode_class_requires_full_word_boundaries() {
        let plan =
            CaptureWordRunBuilder::new(r"\b(?:([\w&&\p{Cyrillic}]{6})|([\w&&\p{Cyrillic}]{5}))\b")
                .unicode(true)
                .build()
                .expect("Unicode word-run plan");
        let haystack = " привет слово xслово слово7 абвгд абвгде ".as_bytes();
        let result = plan
            .grep_capture_count(haystack, exact_limits(&plan, haystack.len()))
            .expect("count");
        assert_eq!(result.actual.matches, 4);
        assert_eq!(result.capture_count, 8);
    }

    #[test]
    fn nearby_shapes_are_refused() {
        for pattern in [
            r"(?:(\w{6})|(\w{5}))\b",
            r"\b(?:\w{6}|\w{5})\b",
            r"\b(?:(\w{32})|(\w{5}))\b",
            r"\b(?:(\w{6})|([a-z]{5}))\b",
            r"\b(?:(\S{6})|(\S{5}))\b",
        ] {
            assert!(
                CaptureWordRunBuilder::new(pattern)
                    .unicode(false)
                    .build()
                    .is_err(),
                "{pattern}"
            );
        }
    }

    #[test]
    fn ascii_subclass_uses_full_word_context_across_blocks() {
        let pattern = r"\b([A-Za-z]{3})\b";
        let plan = CaptureWordRunBuilder::new(pattern)
            .unicode(false)
            .build()
            .expect("ASCII subclass plan");
        for haystack in [
            b"foo1".as_slice(),
            b"_foo".as_slice(),
            b"foo_".as_slice(),
            b"1foo".as_slice(),
            b" foo ".as_slice(),
            b"\xfffoo\xff".as_slice(),
        ] {
            let actual = plan
                .grep_capture_count(haystack, exact_limits(&plan, haystack.len()))
                .expect("subclass count")
                .capture_count;
            assert_eq!(
                actual,
                reference_capture_count(pattern, false, haystack),
                "{haystack:?}"
            );
        }

        for padding in [29_usize, 30, 31, 32, 61, 62, 63, 64] {
            let mut haystack = vec![b' '; padding];
            haystack.extend_from_slice(b"foo foo1 _foo foo_ 1foo bar ");
            let actual = plan
                .grep_capture_count(&haystack, exact_limits(&plan, haystack.len()))
                .expect("cross-block count")
                .capture_count;
            assert_eq!(
                actual,
                reference_capture_count(pattern, false, &haystack),
                "padding={padding}"
            );
        }
    }

    #[test]
    fn ascii_differential_covers_arbitrary_bytes_and_block_tails() {
        let pattern = r"\b(?:(\w{6})|(\w{5}))\b";
        let plan = CaptureWordRunBuilder::new(pattern)
            .unicode(false)
            .build()
            .expect("ASCII word plan");
        let alphabet = b"ab_Z09 -.\r\n\x80\xff";
        let mut state = 0x9e37_79b9_u32;
        for length in 0..=193_usize {
            let mut haystack = Vec::with_capacity(length);
            for _ in 0..length {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let state_index = usize::try_from(state).expect("u32 state fits usize");
                haystack.push(alphabet[state_index % alphabet.len()]);
            }
            let actual = plan
                .grep_capture_count(&haystack, exact_limits(&plan, haystack.len()))
                .expect("differential count")
                .capture_count;
            assert_eq!(
                actual,
                reference_capture_count(pattern, false, &haystack),
                "length={length}, haystack={haystack:?}"
            );
        }
    }

    #[test]
    fn unicode_differential_covers_word_neighbors_and_invalid_utf8() {
        let pattern = r"\b(?:([\w&&\p{Cyrillic}]{6})|([\w&&\p{Cyrillic}]{5}))\b";
        let plan = CaptureWordRunBuilder::new(pattern)
            .unicode(true)
            .build()
            .expect("Unicode word plan");
        let mut haystack = "привет слово xслово слово7 _слово абвгд абвгде\nёжики"
            .as_bytes()
            .to_vec();
        haystack.extend_from_slice(b"\xff");
        haystack.extend_from_slice("слово".as_bytes());
        haystack.extend_from_slice(b"\xfe");
        let actual = plan
            .grep_capture_count(&haystack, exact_limits(&plan, haystack.len()))
            .expect("Unicode differential count")
            .capture_count;
        assert_eq!(actual, reference_capture_count(pattern, true, &haystack));
    }
}
