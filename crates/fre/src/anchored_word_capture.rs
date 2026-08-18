//! Generic line-local capture counting for two deterministic anchored word
//! shapes.
//!
//! The builder admits either:
//!
//! ```text
//! ^ SPACE* capture(WORD+) (SPACE+ capture(WORD+))+
//! ^ capture(CLASS{N})... WORD_BOUNDARY
//! ```
//!
//! Every capture is mandatory and positive, so a successful line contributes
//! the whole-match group plus every explicit capture without materializing
//! spans. Construction derives the route solely from canonical HIR.

use core::{fmt, mem::size_of};

use fre_syntax::{
    AdmissionPolicy, CanonicalPattern, CompatibilityProfile, RustProfile, SafetyEnvelope,
};
use memchr::memchr_iter;
use regex_syntax::hir::{Class, Hir, HirKind, Look};

pub const ANCHORED_WORD_CAPTURE_PLAN_ID: &str = "anchored-word-capture-linear-v1";
pub const ANCHORED_WORD_CAPTURE_COUNT_OPERATION_ID: &str =
    "anchored-word-capture.grep-participation-count.v1";
pub const ANCHORED_WORD_CAPTURE_RECORD_OPERATION_ID: &str =
    "anchored-word-capture.grep-record-visit.v1";
pub const ANCHORED_WORD_CAPTURE_ALGORITHM_VERSION: u32 = 2;
pub const ANCHORED_WORD_CAPTURE_ACCOUNTING_VERSION: u32 = 2;

const MAX_CLASS_RANGES: usize = 64;
const MAX_RECORD_GROUPS: usize = MAX_CLASS_RANGES + 1;
const MAX_FIXED_UNITS: u32 = 64;
const UNICODE_WORD_RANGE_COUNT: usize = 796;
const ASCII_WORD_RANGES: [(u8, u8); 4] = [(b'0', b'9'), (b'A', b'Z'), (b'_', b'_'), (b'a', b'z')];
const UNICODE_NON_WHITESPACE_RANGES: [(char, char); 11] = [
    ('\0', '\u{8}'),
    ('\u{e}', '\u{1f}'),
    ('!', '\u{84}'),
    ('\u{86}', '\u{9f}'),
    ('¡', '\u{167f}'),
    ('\u{1681}', '\u{1fff}'),
    ('\u{200b}', '\u{2027}'),
    ('\u{202a}', '\u{202e}'),
    ('\u{2030}', '\u{205e}'),
    ('\u{2060}', '\u{2fff}'),
    ('\u{3001}', '\u{10ffff}'),
];
const DIGEST_OFFSET_A: u64 = 0xcbf2_9ce4_8422_2325;
const DIGEST_OFFSET_B: u64 = 0x8422_2325_cbf2_9ce4;
const DIGEST_PRIME_A: u64 = 0x0000_0100_0000_01b3;
const DIGEST_PRIME_B: u64 = 0x0000_0100_0000_01cf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchoredWordCaptureMode {
    Ascii,
    Unicode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchoredWordCaptureKind {
    WordFields,
    FixedClassWordBoundary,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchoredWordCaptureBuildLimits {
    pub admission: AdmissionPolicy,
    pub syntax_safety: SafetyEnvelope,
    pub max_inspection_work: usize,
    pub max_hir_nodes: usize,
    pub max_class_ranges: usize,
    pub max_captures: usize,
    pub max_fixed_units: u32,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl Default for AnchoredWordCaptureBuildLimits {
    fn default() -> Self {
        Self {
            admission: AdmissionPolicy::default(),
            syntax_safety: SafetyEnvelope::default(),
            max_inspection_work: 8_192,
            max_hir_nodes: 1_024,
            max_class_ranges: 1_024,
            max_captures: 64,
            max_fixed_units: MAX_FIXED_UNITS,
            max_persistent_bytes: 1 << 20,
            max_peak_bytes: 1 << 20,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchoredWordCaptureHirAccounting {
    pub hir_nodes: usize,
    pub class_ranges: usize,
    pub captures: usize,
    pub repetitions: usize,
    pub property_probes: usize,
    pub inspection_work: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each bit authenticates a separate immutable regex semantic"
)]
pub struct AnchoredWordCaptureOperationIdentity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub mode: AnchoredWordCaptureMode,
    pub kind: AnchoredWordCaptureKind,
    pub explicit_captures: usize,
    pub groups_per_match: usize,
    pub word_fields: usize,
    pub fixed_units: u32,
    pub class_ranges: usize,
    pub structural_digest: [u64; 2],
    pub absolute_start_per_line: bool,
    pub crlf_stripped: bool,
    pub invalid_bytes_are_non_word: bool,
    pub uniform_participation: bool,
    pub non_overlapping_per_line: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchoredWordCapturePlanIdentity {
    pub profile: RustProfile,
    pub source_digest: [u64; 2],
    pub algorithm_version: u32,
    pub accounting_version: u32,
    pub operation: AnchoredWordCaptureOperationIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchoredWordCaptureBuildReport {
    pub identity: AnchoredWordCapturePlanIdentity,
    pub hir: AnchoredWordCaptureHirAccounting,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum AnchoredWordCaptureBuildError {
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

impl fmt::Display for AnchoredWordCaptureBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(error) => write!(formatter, "anchored word-capture syntax: {error}"),
            Self::Unsupported(reason) => {
                write!(
                    formatter,
                    "unsupported anchored word-capture shape: {reason}"
                )
            }
            Self::Resource {
                resource,
                needed,
                limit,
            } => write!(
                formatter,
                "anchored word-capture {resource} needs {needed}, limit is {limit}"
            ),
            Self::ArithmeticOverflow(computation) => write!(
                formatter,
                "anchored word-capture overflow while computing {computation}"
            ),
            Self::InternalInvariant(message) => {
                write!(formatter, "anchored word-capture invariant: {message}")
            }
        }
    }
}

impl std::error::Error for AnchoredWordCaptureBuildError {
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
pub struct AnchoredWordCaptureRunLimits {
    pub max_input_bytes: usize,
    pub max_source_reads: usize,
    pub max_decoded_units: usize,
    pub max_class_comparisons: usize,
    pub max_word_probes: usize,
    pub max_lines: usize,
    pub max_matches: usize,
    pub max_capture_count: usize,
    pub max_work: usize,
    pub max_sequential_bytes: usize,
    pub max_peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchoredWordCaptureRunUpperBounds {
    pub input_bytes: usize,
    pub source_reads: usize,
    pub decoded_units: usize,
    pub class_comparisons: usize,
    pub word_probes: usize,
    pub lines: usize,
    pub matches: usize,
    pub capture_count: usize,
    pub work: usize,
    pub sequential_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AnchoredWordCaptureRunActual {
    pub delimiter_reads: usize,
    pub matcher_reads: usize,
    pub source_reads: usize,
    pub decoded_units: usize,
    pub class_comparisons: usize,
    pub word_probes: usize,
    pub lines: usize,
    pub matches: usize,
    pub capture_count: usize,
    pub work: usize,
    pub sequential_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchoredWordCaptureCountResult {
    pub identity: AnchoredWordCaptureOperationIdentity,
    pub capture_count: usize,
    pub upper_bounds: AnchoredWordCaptureRunUpperBounds,
    pub actual: AnchoredWordCaptureRunActual,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AnchoredWordCaptureSpan {
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchoredWordCaptureRecordUpperBounds {
    pub input_bytes: usize,
    pub line_domains: usize,
    pub matches: usize,
    pub capture_count: usize,
    pub reducer_events: usize,
    pub endpoint_writes: usize,
    pub work: usize,
    pub sequential_bytes: usize,
    pub allocations: usize,
    pub scratch_bytes: usize,
    pub output_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchoredWordCaptureRecordVisitReport {
    pub operation_id: &'static str,
    pub source_digest: [u64; 2],
    pub line_domains: usize,
    pub matches: usize,
    pub capture_count: usize,
    pub reducer_events: usize,
    pub endpoint_writes: usize,
    pub work: usize,
    pub sequential_bytes: usize,
    pub allocations: usize,
    pub scratch_bytes: usize,
    pub output_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
    pub run: AnchoredWordCaptureRunActual,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchoredWordCaptureRunResource {
    InputBytes,
    SourceReads,
    DecodedUnits,
    ClassComparisons,
    WordProbes,
    Lines,
    Matches,
    CaptureCount,
    Work,
    SequentialBytes,
    PeakBytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AnchoredWordCaptureRunError {
    Resource {
        resource: AnchoredWordCaptureRunResource,
        needed: usize,
        limit: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    AccountingInvariant {
        resource: AnchoredWordCaptureRunResource,
        actual: usize,
        upper: usize,
    },
}

impl fmt::Display for AnchoredWordCaptureRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "anchored word-capture reduction failed: {self:?}"
        )
    }
}

impl std::error::Error for AnchoredWordCaptureRunError {}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ScalarRange {
    start: u32,
    end: u32,
}

#[derive(Clone, Copy, Debug)]
struct FixedCaptureSchema {
    widths: [u32; MAX_CLASS_RANGES],
    captures: usize,
    all_unnamed: bool,
}

#[derive(Clone, Copy, Debug)]
struct FixedMatchOffsets {
    end: usize,
    capture_ends: [usize; MAX_CLASS_RANGES],
}

#[derive(Clone, Copy, Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "all matcher artifacts stay inline so the sealed plan has no unaccounted allocation"
)]
enum Program {
    WordFields {
        fields: usize,
    },
    FixedAscii {
        class_words: [u64; 4],
        units: u32,
    },
    FixedUnicode {
        ranges: [ScalarRange; MAX_CLASS_RANGES],
        range_count: usize,
        units: u32,
    },
    FixedUnicodeNonWhitespace {
        units: u32,
    },
}

#[derive(Clone, Debug)]
pub struct AnchoredWordCaptureBuilder {
    pattern: String,
    profile: RustProfile,
    limits: AnchoredWordCaptureBuildLimits,
}

impl AnchoredWordCaptureBuilder {
    #[must_use]
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            profile: RustProfile::default(),
            limits: AnchoredWordCaptureBuildLimits::default(),
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
    pub const fn limits(mut self, limits: AnchoredWordCaptureBuildLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn build(self) -> Result<AnchoredWordCapturePlan, AnchoredWordCaptureBuildError> {
        if self.profile.options.case_insensitive {
            return Err(AnchoredWordCaptureBuildError::Unsupported(
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
        .map_err(AnchoredWordCaptureBuildError::Syntax)?;
        let source_digest = digest_source(parsed.key.pattern.as_bytes());
        let explicit_captures = usize::try_from(parsed.summary.captures).map_err(|_| {
            AnchoredWordCaptureBuildError::ArithmeticOverflow("explicit capture count")
        })?;
        let CanonicalPattern::Rust(rust) = parsed.pattern else {
            return Err(AnchoredWordCaptureBuildError::InternalInvariant(
                "Rust byte request produced a non-Rust HIR",
            ));
        };
        let mode = if profile.options.unicode {
            AnchoredWordCaptureMode::Unicode
        } else {
            AnchoredWordCaptureMode::Ascii
        };
        let inspection = inspect(&rust.hir, mode, self.limits)?;
        if inspection.accounting.captures != explicit_captures || explicit_captures == 0 {
            return Err(AnchoredWordCaptureBuildError::InternalInvariant(
                "parse capture count differs from mandatory structural captures",
            ));
        }
        let groups_per_match = explicit_captures.checked_add(1).ok_or(
            AnchoredWordCaptureBuildError::ArithmeticOverflow("groups per match"),
        )?;
        let persistent_bytes = size_of::<AnchoredWordCapturePlan>();
        enforce_build(
            "persistent bytes",
            persistent_bytes,
            self.limits.max_persistent_bytes,
        )?;
        enforce_build("peak bytes", persistent_bytes, self.limits.max_peak_bytes)?;
        let operation = AnchoredWordCaptureOperationIdentity {
            plan_id: ANCHORED_WORD_CAPTURE_PLAN_ID,
            operation_id: ANCHORED_WORD_CAPTURE_COUNT_OPERATION_ID,
            mode,
            kind: inspection.kind,
            explicit_captures,
            groups_per_match,
            word_fields: if inspection.kind == AnchoredWordCaptureKind::WordFields {
                explicit_captures
            } else {
                0
            },
            fixed_units: inspection.fixed_units,
            class_ranges: inspection.accounting.class_ranges,
            structural_digest: inspection.structural_digest,
            absolute_start_per_line: true,
            crlf_stripped: true,
            invalid_bytes_are_non_word: true,
            uniform_participation: true,
            non_overlapping_per_line: true,
        };
        let report = AnchoredWordCaptureBuildReport {
            identity: AnchoredWordCapturePlanIdentity {
                profile,
                source_digest,
                algorithm_version: ANCHORED_WORD_CAPTURE_ALGORITHM_VERSION,
                accounting_version: ANCHORED_WORD_CAPTURE_ACCOUNTING_VERSION,
                operation,
            },
            hir: inspection.accounting,
            persistent_bytes,
            peak_bytes: persistent_bytes,
        };
        Ok(AnchoredWordCapturePlan {
            program: inspection.program,
            fixed_schema: inspection.fixed_schema,
            report,
        })
    }
}

#[derive(Clone, Debug)]
pub struct AnchoredWordCapturePlan {
    program: Program,
    fixed_schema: Option<FixedCaptureSchema>,
    report: AnchoredWordCaptureBuildReport,
}

impl AnchoredWordCapturePlan {
    #[must_use]
    pub const fn build_report(&self) -> &AnchoredWordCaptureBuildReport {
        &self.report
    }

    pub fn run_upper_bounds(
        &self,
        input_bytes: usize,
    ) -> Result<AnchoredWordCaptureRunUpperBounds, AnchoredWordCaptureRunError> {
        let source_reads =
            input_bytes
                .checked_mul(4)
                .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
                    computation: "source-read upper bound",
                })?;
        let decoded_units =
            input_bytes
                .checked_mul(2)
                .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
                    computation: "decoded-unit upper bound",
                })?;
        let word_probes =
            input_bytes
                .checked_mul(2)
                .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
                    computation: "word-probe upper bound",
                })?;
        let class_comparisons = match self.program {
            Program::FixedUnicode { range_count, .. } => input_bytes
                .checked_mul(binary_search_comparison_bound(range_count))
                .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
                    computation: "class-comparison upper bound",
                })?,
            Program::FixedUnicodeNonWhitespace { .. } => input_bytes,
            Program::WordFields { .. } | Program::FixedAscii { .. } => 0,
        };
        let lines = input_bytes;
        let matches = lines;
        let capture_count = matches
            .checked_mul(self.report.identity.operation.groups_per_match)
            .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
                computation: "capture-count upper bound",
            })?;
        let work = source_reads
            .checked_add(decoded_units)
            .and_then(|value| value.checked_add(class_comparisons))
            .and_then(|value| value.checked_add(word_probes))
            .and_then(|value| value.checked_add(lines))
            .and_then(|value| value.checked_add(matches))
            .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
                computation: "work upper bound",
            })?;
        Ok(AnchoredWordCaptureRunUpperBounds {
            input_bytes,
            source_reads,
            decoded_units,
            class_comparisons,
            word_probes,
            lines,
            matches,
            capture_count,
            work,
            sequential_bytes: source_reads,
            peak_bytes: self.report.persistent_bytes,
        })
    }

    pub fn grep_capture_count(
        &self,
        haystack: &[u8],
        limits: AnchoredWordCaptureRunLimits,
    ) -> Result<AnchoredWordCaptureCountResult, AnchoredWordCaptureRunError> {
        let upper = self.run_upper_bounds(haystack.len())?;
        enforce_run_limits(upper, limits)?;
        let mut actual = AnchoredWordCaptureRunActual {
            delimiter_reads: haystack.len(),
            ..AnchoredWordCaptureRunActual::default()
        };
        let mut line_start = 0_usize;
        for index in memchr_iter(b'\n', haystack) {
            let previous = index.checked_sub(1).and_then(|at| haystack.get(at));
            let content_end = if index > line_start && previous == Some(&b'\r') {
                index
                    .checked_sub(1)
                    .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
                        computation: "CRLF content end",
                    })?
            } else {
                index
            };
            self.execute_line(&haystack[line_start..content_end], &mut actual)?;
            line_start =
                index
                    .checked_add(1)
                    .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
                        computation: "next line start",
                    })?;
        }
        if line_start < haystack.len() {
            self.execute_line(&haystack[line_start..], &mut actual)?;
        }
        actual.source_reads = actual
            .delimiter_reads
            .checked_add(actual.matcher_reads)
            .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
                computation: "actual source reads",
            })?;
        actual.capture_count = actual
            .matches
            .checked_mul(self.report.identity.operation.groups_per_match)
            .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
                computation: "actual capture count",
            })?;
        actual.work = actual
            .source_reads
            .checked_add(actual.decoded_units)
            .and_then(|value| value.checked_add(actual.class_comparisons))
            .and_then(|value| value.checked_add(actual.word_probes))
            .and_then(|value| value.checked_add(actual.lines))
            .and_then(|value| value.checked_add(actual.matches))
            .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
                computation: "actual work",
            })?;
        actual.sequential_bytes = actual.source_reads;
        verify_actual(actual, upper)?;
        Ok(AnchoredWordCaptureCountResult {
            identity: self.report.identity.operation,
            capture_count: actual.capture_count,
            upper_bounds: upper,
            actual,
        })
    }

    pub fn grep_capture_record_upper_bounds(
        &self,
        input_bytes: usize,
    ) -> Result<Option<AnchoredWordCaptureRecordUpperBounds>, AnchoredWordCaptureRunError> {
        let Some(schema) = self.fixed_schema.filter(|schema| schema.all_unnamed) else {
            return Ok(None);
        };
        let run = self.run_upper_bounds(input_bytes)?;
        let capture_count = run
            .matches
            .checked_mul(schema.captures.checked_add(1).ok_or(
                AnchoredWordCaptureRunError::ArithmeticOverflow {
                    computation: "record groups per match",
                },
            )?)
            .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
                computation: "record capture-count bound",
            })?;
        let reducer_events = run.lines.checked_add(capture_count).ok_or(
            AnchoredWordCaptureRunError::ArithmeticOverflow {
                computation: "record reducer-event bound",
            },
        )?;
        let endpoint_writes = capture_count.checked_mul(2).ok_or(
            AnchoredWordCaptureRunError::ArithmeticOverflow {
                computation: "record endpoint-write bound",
            },
        )?;
        let work = run
            .work
            .checked_add(capture_count)
            .and_then(|value| value.checked_add(endpoint_writes))
            .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
                computation: "record work bound",
            })?;
        Ok(Some(AnchoredWordCaptureRecordUpperBounds {
            input_bytes,
            line_domains: run.lines,
            matches: run.matches,
            capture_count,
            reducer_events,
            endpoint_writes,
            work,
            sequential_bytes: run.sequential_bytes,
            allocations: 0,
            scratch_bytes: 0,
            output_bytes: 0,
            persistent_bytes: self.report.persistent_bytes,
            peak_bytes: self.report.persistent_bytes,
        }))
    }

    pub fn visit_grep_capture_records(
        &self,
        haystack: &[u8],
        limits: AnchoredWordCaptureRunLimits,
        mut visitor: impl FnMut(usize, &[AnchoredWordCaptureSpan]),
    ) -> Result<Option<AnchoredWordCaptureRecordVisitReport>, AnchoredWordCaptureRunError> {
        let Some(schema) = self.fixed_schema.filter(|schema| schema.all_unnamed) else {
            return Ok(None);
        };
        let upper = self
            .grep_capture_record_upper_bounds(haystack.len())?
            .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
                computation: "record support changed after preflight",
            })?;
        let run_upper = self.run_upper_bounds(haystack.len())?;
        enforce_run_limits(run_upper, limits)?;
        let mut actual = AnchoredWordCaptureRunActual {
            delimiter_reads: haystack.len(),
            ..AnchoredWordCaptureRunActual::default()
        };
        let mut spans = [AnchoredWordCaptureSpan::default(); MAX_RECORD_GROUPS];
        let mut endpoint_writes = 0_usize;
        let mut line_start = 0_usize;
        for index in memchr_iter(b'\n', haystack) {
            let previous = index.checked_sub(1).and_then(|at| haystack.get(at));
            let content_end = if index > line_start && previous == Some(&b'\r') {
                index
                    .checked_sub(1)
                    .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
                        computation: "record CRLF content end",
                    })?
            } else {
                index
            };
            self.visit_fixed_line_record(
                &haystack[line_start..content_end],
                schema,
                &mut spans,
                &mut actual,
                &mut endpoint_writes,
                &mut visitor,
            )?;
            line_start =
                index
                    .checked_add(1)
                    .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
                        computation: "record next line start",
                    })?;
        }
        if line_start < haystack.len() {
            self.visit_fixed_line_record(
                &haystack[line_start..],
                schema,
                &mut spans,
                &mut actual,
                &mut endpoint_writes,
                &mut visitor,
            )?;
        }
        actual.source_reads = actual
            .delimiter_reads
            .checked_add(actual.matcher_reads)
            .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
                computation: "record actual source reads",
            })?;
        actual.capture_count = actual
            .matches
            .checked_mul(schema.captures.checked_add(1).ok_or(
                AnchoredWordCaptureRunError::ArithmeticOverflow {
                    computation: "record actual groups per match",
                },
            )?)
            .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
                computation: "record actual capture count",
            })?;
        actual.work = actual
            .source_reads
            .checked_add(actual.decoded_units)
            .and_then(|value| value.checked_add(actual.class_comparisons))
            .and_then(|value| value.checked_add(actual.word_probes))
            .and_then(|value| value.checked_add(actual.lines))
            .and_then(|value| value.checked_add(actual.matches))
            .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
                computation: "record actual run work",
            })?;
        actual.sequential_bytes = actual.source_reads;
        verify_actual(actual, run_upper)?;
        let reducer_events = actual.lines.checked_add(actual.capture_count).ok_or(
            AnchoredWordCaptureRunError::ArithmeticOverflow {
                computation: "record actual reducer events",
            },
        )?;
        let work = actual
            .work
            .checked_add(actual.capture_count)
            .and_then(|value| value.checked_add(endpoint_writes))
            .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
                computation: "record actual work",
            })?;
        for (observed, bound) in [
            (actual.lines, upper.line_domains),
            (actual.matches, upper.matches),
            (actual.capture_count, upper.capture_count),
            (reducer_events, upper.reducer_events),
            (endpoint_writes, upper.endpoint_writes),
            (work, upper.work),
        ] {
            if observed > bound {
                return Err(AnchoredWordCaptureRunError::AccountingInvariant {
                    resource: AnchoredWordCaptureRunResource::Work,
                    actual: observed,
                    upper: bound,
                });
            }
        }
        Ok(Some(AnchoredWordCaptureRecordVisitReport {
            operation_id: ANCHORED_WORD_CAPTURE_RECORD_OPERATION_ID,
            source_digest: self.report.identity.source_digest,
            line_domains: actual.lines,
            matches: actual.matches,
            capture_count: actual.capture_count,
            reducer_events,
            endpoint_writes,
            work,
            sequential_bytes: actual.sequential_bytes,
            allocations: 0,
            scratch_bytes: 0,
            output_bytes: 0,
            persistent_bytes: self.report.persistent_bytes,
            peak_bytes: self.report.peak_bytes,
            run: actual,
        }))
    }

    fn visit_fixed_line_record(
        &self,
        line: &[u8],
        schema: FixedCaptureSchema,
        spans: &mut [AnchoredWordCaptureSpan; MAX_RECORD_GROUPS],
        actual: &mut AnchoredWordCaptureRunActual,
        endpoint_writes: &mut usize,
        visitor: &mut impl FnMut(usize, &[AnchoredWordCaptureSpan]),
    ) -> Result<(), AnchoredWordCaptureRunError> {
        actual.lines = checked_add(actual.lines, 1, "record line events")?;
        let Some(offsets) = self.match_fixed_line(line, schema, actual)? else {
            return Ok(());
        };
        actual.matches = checked_add(actual.matches, 1, "record matches")?;
        let group_count = schema.captures.checked_add(1).ok_or(
            AnchoredWordCaptureRunError::ArithmeticOverflow {
                computation: "record group count",
            },
        )?;
        spans[0] = AnchoredWordCaptureSpan {
            start: 0,
            end: offsets.end,
        };
        let mut start = 0_usize;
        for (capture, &end) in offsets.capture_ends[..schema.captures].iter().enumerate() {
            spans[capture + 1] = AnchoredWordCaptureSpan { start, end };
            start = end;
        }
        *endpoint_writes = checked_add(
            *endpoint_writes,
            group_count
                .checked_mul(2)
                .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
                    computation: "record endpoint writes",
                })?,
            "record endpoint writes",
        )?;
        visitor(line.len(), &spans[..group_count]);
        Ok(())
    }

    fn match_fixed_line(
        &self,
        line: &[u8],
        schema: FixedCaptureSchema,
        actual: &mut AnchoredWordCaptureRunActual,
    ) -> Result<Option<FixedMatchOffsets>, AnchoredWordCaptureRunError> {
        match self.program {
            Program::FixedAscii { class_words, units } => {
                match_fixed_ascii(line, class_words, units, schema, actual)
            }
            Program::FixedUnicode {
                ranges,
                range_count,
                units,
            } => match_fixed_unicode(line, &ranges[..range_count], units, schema, actual),
            Program::FixedUnicodeNonWhitespace { units } => {
                match_fixed_unicode_non_whitespace(line, units, schema, actual)
            }
            Program::WordFields { .. } => Ok(None),
        }
    }

    fn execute_line(
        &self,
        line: &[u8],
        actual: &mut AnchoredWordCaptureRunActual,
    ) -> Result<(), AnchoredWordCaptureRunError> {
        actual.lines = checked_add(actual.lines, 1, "line events")?;
        let matched = match self.program {
            Program::WordFields { fields } => match self.report.identity.operation.mode {
                AnchoredWordCaptureMode::Ascii => match_word_fields_ascii(line, fields, actual)?,
                AnchoredWordCaptureMode::Unicode => {
                    match_word_fields_unicode(line, fields, actual)?
                }
            },
            Program::FixedAscii { class_words, units } => match_fixed_ascii(
                line,
                class_words,
                units,
                self.fixed_schema
                    .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
                        computation: "fixed ASCII capture schema",
                    })?,
                actual,
            )?
            .is_some(),
            Program::FixedUnicode {
                ranges,
                range_count,
                units,
            } => match_fixed_unicode(
                line,
                &ranges[..range_count],
                units,
                self.fixed_schema
                    .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
                        computation: "fixed Unicode capture schema",
                    })?,
                actual,
            )?
            .is_some(),
            Program::FixedUnicodeNonWhitespace { units } => match_fixed_unicode_non_whitespace(
                line,
                units,
                self.fixed_schema
                    .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
                        computation: "fixed Unicode non-whitespace capture schema",
                    })?,
                actual,
            )?
            .is_some(),
        };
        if matched {
            actual.matches = checked_add(actual.matches, 1, "matches")?;
        }
        Ok(())
    }
}

struct Inspection {
    program: Program,
    fixed_schema: Option<FixedCaptureSchema>,
    kind: AnchoredWordCaptureKind,
    fixed_units: u32,
    structural_digest: [u64; 2],
    accounting: AnchoredWordCaptureHirAccounting,
}

struct Inspector {
    mode: AnchoredWordCaptureMode,
    limits: AnchoredWordCaptureBuildLimits,
    accounting: AnchoredWordCaptureHirAccounting,
    digest: StructuralDigest,
}

impl Inspector {
    fn new(mode: AnchoredWordCaptureMode, limits: AnchoredWordCaptureBuildLimits) -> Self {
        Self {
            mode,
            limits,
            accounting: AnchoredWordCaptureHirAccounting {
                hir_nodes: 0,
                class_ranges: 0,
                captures: 0,
                repetitions: 0,
                property_probes: 0,
                inspection_work: 0,
            },
            digest: StructuralDigest::new(),
        }
    }

    fn inspect(mut self, hir: &Hir) -> Result<Inspection, AnchoredWordCaptureBuildError> {
        self.node()?;
        let HirKind::Concat(root) = hir.kind() else {
            return Err(AnchoredWordCaptureBuildError::Unsupported(
                "root must be a concatenation",
            ));
        };
        if root.len() < 3 {
            return Err(AnchoredWordCaptureBuildError::Unsupported(
                "root concatenation is too short",
            ));
        }
        self.node()?;
        if !matches!(root[0].kind(), HirKind::Look(Look::Start)) {
            return Err(AnchoredWordCaptureBuildError::Unsupported(
                "root must begin with absolute Start",
            ));
        }
        self.digest.byte(0x01);
        if matches!(root[1].kind(), HirKind::Repetition(_)) {
            let program = self.inspect_word_fields(root)?;
            return Ok(Inspection {
                program,
                fixed_schema: None,
                kind: AnchoredWordCaptureKind::WordFields,
                fixed_units: 0,
                structural_digest: self.digest.finish(),
                accounting: self.accounting,
            });
        }

        let mut fixed = Inspector::new(self.mode, self.limits);
        fixed.node()?;
        fixed.node()?;
        fixed.digest.byte(0x01);
        let (program, units, fixed_schema) = fixed.inspect_fixed_boundary(root)?;
        Ok(Inspection {
            program,
            fixed_schema: Some(fixed_schema),
            kind: AnchoredWordCaptureKind::FixedClassWordBoundary,
            fixed_units: units,
            structural_digest: fixed.digest.finish(),
            accounting: fixed.accounting,
        })
    }

    fn inspect_word_fields(
        &mut self,
        root: &[Hir],
    ) -> Result<Program, AnchoredWordCaptureBuildError> {
        if root.len() < 3 || root.len().is_multiple_of(2) {
            return Err(AnchoredWordCaptureBuildError::Unsupported(
                "word fields require prefix spaces and alternating captures",
            ));
        }
        self.inspect_space_repeat(&root[1], 0)?;
        let mut fields = 0_usize;
        let mut canonical_class = None;
        for (offset, item) in root[2..].iter().enumerate() {
            if offset % 2 == 0 {
                self.node()?;
                let HirKind::Capture(capture) = item.kind() else {
                    return Err(AnchoredWordCaptureBuildError::Unsupported(
                        "each word field must be one direct capture",
                    ));
                };
                self.accounting.captures = self.accounting.captures.checked_add(1).ok_or(
                    AnchoredWordCaptureBuildError::ArithmeticOverflow("capture count"),
                )?;
                enforce_build(
                    "captures",
                    self.accounting.captures,
                    self.limits.max_captures,
                )?;
                self.node()?;
                let HirKind::Repetition(repetition) = capture.sub.kind() else {
                    return Err(AnchoredWordCaptureBuildError::Unsupported(
                        "word captures must contain one repetition",
                    ));
                };
                if repetition.min != 1 || repetition.max.is_some() || !repetition.greedy {
                    return Err(AnchoredWordCaptureBuildError::Unsupported(
                        "word captures must use greedy positive unbounded repetition",
                    ));
                }
                self.accounting.repetitions = self.accounting.repetitions.checked_add(1).ok_or(
                    AnchoredWordCaptureBuildError::ArithmeticOverflow("repetition count"),
                )?;
                self.node()?;
                let HirKind::Class(class) = repetition.sub.kind() else {
                    return Err(AnchoredWordCaptureBuildError::Unsupported(
                        "word repetition body must be one class",
                    ));
                };
                if let Some(expected) = canonical_class {
                    if expected != class {
                        return Err(AnchoredWordCaptureBuildError::Unsupported(
                            "every word field must use the same canonical class",
                        ));
                    }
                } else {
                    self.inspect_canonical_word_class(class)?;
                    canonical_class = Some(class);
                }
                fields = fields.checked_add(1).ok_or(
                    AnchoredWordCaptureBuildError::ArithmeticOverflow("word field count"),
                )?;
                self.digest.byte(0x20);
                self.digest.usize(fields);
            } else {
                self.inspect_space_repeat(item, 1)?;
            }
        }
        if fields == 0 {
            return Err(AnchoredWordCaptureBuildError::Unsupported(
                "word-field plan needs at least one capture",
            ));
        }
        Ok(Program::WordFields { fields })
    }

    fn inspect_fixed_boundary(
        &mut self,
        root: &[Hir],
    ) -> Result<(Program, u32, FixedCaptureSchema), AnchoredWordCaptureBuildError> {
        let expected = match self.mode {
            AnchoredWordCaptureMode::Ascii => Look::WordAscii,
            AnchoredWordCaptureMode::Unicode => Look::WordUnicode,
        };
        self.node()?;
        if !matches!(root.last().map(Hir::kind), Some(HirKind::Look(actual)) if *actual == expected)
        {
            return Err(AnchoredWordCaptureBuildError::Unsupported(
                "fixed captured classes must end in the selected word boundary",
            ));
        }
        let last =
            root.len()
                .checked_sub(1)
                .ok_or(AnchoredWordCaptureBuildError::InternalInvariant(
                    "fixed boundary root lost its terminal assertion",
                ))?;
        let middle = &root[1..last];
        if middle.is_empty() {
            return Err(AnchoredWordCaptureBuildError::Unsupported(
                "fixed boundary plan needs captured units",
            ));
        }
        let mut canonical_class = None;
        let mut units = 0_u32;
        let mut schema = FixedCaptureSchema {
            widths: [0; MAX_CLASS_RANGES],
            captures: 0,
            all_unnamed: true,
        };
        for item in middle {
            self.node()?;
            let HirKind::Capture(capture) = item.kind() else {
                return Err(AnchoredWordCaptureBuildError::Unsupported(
                    "every fixed unit group must be one direct capture",
                ));
            };
            let expected_index = self.accounting.captures.checked_add(1).ok_or(
                AnchoredWordCaptureBuildError::ArithmeticOverflow("capture schema index"),
            )?;
            if usize::try_from(capture.index) != Ok(expected_index) {
                return Err(AnchoredWordCaptureBuildError::Unsupported(
                    "fixed captures must retain numeric source order",
                ));
            }
            self.accounting.captures = self.accounting.captures.checked_add(1).ok_or(
                AnchoredWordCaptureBuildError::ArithmeticOverflow("capture count"),
            )?;
            enforce_build(
                "captures",
                self.accounting.captures,
                self.limits.max_captures,
            )?;
            self.node()?;
            let (class, width) = match capture.sub.kind() {
                HirKind::Class(class) => (class, 1),
                HirKind::Repetition(repetition) => {
                    if !repetition.greedy
                        || repetition.min == 0
                        || repetition.max != Some(repetition.min)
                    {
                        return Err(AnchoredWordCaptureBuildError::Unsupported(
                            "fixed captures require a positive exact greedy repetition",
                        ));
                    }
                    self.accounting.repetitions =
                        self.accounting.repetitions.checked_add(1).ok_or(
                            AnchoredWordCaptureBuildError::ArithmeticOverflow("repetition count"),
                        )?;
                    self.node()?;
                    let HirKind::Class(class) = repetition.sub.kind() else {
                        return Err(AnchoredWordCaptureBuildError::Unsupported(
                            "fixed repetition body must be one class",
                        ));
                    };
                    (class, repetition.min)
                }
                _ => {
                    return Err(AnchoredWordCaptureBuildError::Unsupported(
                        "fixed captures must contain a class or exact class repetition",
                    ));
                }
            };
            if let Some(expected) = canonical_class {
                if expected != class {
                    return Err(AnchoredWordCaptureBuildError::Unsupported(
                        "every fixed capture must use the same class",
                    ));
                }
            } else {
                canonical_class = Some(class);
            }
            units = units.checked_add(width).ok_or(
                AnchoredWordCaptureBuildError::ArithmeticOverflow("fixed unit count"),
            )?;
            let fixed_limit = self.limits.max_fixed_units.min(MAX_FIXED_UNITS);
            if units > fixed_limit {
                return Err(AnchoredWordCaptureBuildError::Resource {
                    resource: "fixed units",
                    needed: usize::try_from(units).unwrap_or(usize::MAX),
                    limit: usize::try_from(fixed_limit).unwrap_or(usize::MAX),
                });
            }
            let schema_slot = schema.widths.get_mut(schema.captures).ok_or(
                AnchoredWordCaptureBuildError::Resource {
                    resource: "fixed capture schema",
                    needed: schema.captures.saturating_add(1),
                    limit: MAX_CLASS_RANGES,
                },
            )?;
            *schema_slot = width;
            schema.captures = schema.captures.checked_add(1).ok_or(
                AnchoredWordCaptureBuildError::ArithmeticOverflow("fixed capture schema"),
            )?;
            schema.all_unnamed &= capture.name.is_none();
            self.digest.byte(0x30);
            self.digest.u32(width);
        }
        let class = canonical_class.ok_or(AnchoredWordCaptureBuildError::InternalInvariant(
            "nonempty fixed captures did not retain a class",
        ))?;
        let program = self.build_fixed_program(class, units)?;
        Ok((program, units, schema))
    }

    fn inspect_space_repeat(
        &mut self,
        hir: &Hir,
        minimum: u32,
    ) -> Result<(), AnchoredWordCaptureBuildError> {
        self.node()?;
        let HirKind::Repetition(repetition) = hir.kind() else {
            return Err(AnchoredWordCaptureBuildError::Unsupported(
                "field separators must be literal-space repetitions",
            ));
        };
        if repetition.min != minimum || repetition.max.is_some() || !repetition.greedy {
            return Err(AnchoredWordCaptureBuildError::Unsupported(
                "field separators have the wrong repetition bounds",
            ));
        }
        self.accounting.repetitions = self.accounting.repetitions.checked_add(1).ok_or(
            AnchoredWordCaptureBuildError::ArithmeticOverflow("repetition count"),
        )?;
        self.node()?;
        if !matches!(
            repetition.sub.kind(),
            HirKind::Literal(literal) if literal.0.as_ref() == b" "
        ) {
            return Err(AnchoredWordCaptureBuildError::Unsupported(
                "field separators must contain only ASCII space",
            ));
        }
        self.digest.byte(0x10);
        self.digest.u32(minimum);
        Ok(())
    }

    fn inspect_canonical_word_class(
        &mut self,
        class: &Class,
    ) -> Result<(), AnchoredWordCaptureBuildError> {
        match (self.mode, class) {
            (AnchoredWordCaptureMode::Ascii, Class::Bytes(class)) => {
                enforce_build(
                    "class ranges",
                    class.ranges().len(),
                    self.limits.max_class_ranges,
                )?;
                self.accounting.class_ranges = class.ranges().len();
                self.charge(class.ranges().len())?;
                let exact = class.ranges().len() == ASCII_WORD_RANGES.len()
                    && class.ranges().iter().zip(ASCII_WORD_RANGES).all(
                        |(actual, (start, end))| actual.start() == start && actual.end() == end,
                    );
                if !exact {
                    return Err(AnchoredWordCaptureBuildError::Unsupported(
                        "word fields require the canonical ASCII word class",
                    ));
                }
            }
            (AnchoredWordCaptureMode::Unicode, Class::Unicode(class)) => {
                enforce_build(
                    "class ranges",
                    class.ranges().len(),
                    self.limits.max_class_ranges,
                )?;
                self.accounting.class_ranges = class.ranges().len();
                self.charge(class.ranges().len())?;
                if class.ranges().len() != UNICODE_WORD_RANGE_COUNT {
                    return Err(AnchoredWordCaptureBuildError::Unsupported(
                        "word fields require the canonical Unicode word class",
                    ));
                }
                for range in class.ranges() {
                    for scalar in [
                        Some(range.start()),
                        Some(range.end()),
                        previous_scalar(range.start()),
                        next_scalar(range.end()),
                    ] {
                        let Some(scalar) = scalar else {
                            continue;
                        };
                        self.accounting.property_probes =
                            self.accounting.property_probes.checked_add(1).ok_or(
                                AnchoredWordCaptureBuildError::ArithmeticOverflow(
                                    "word property probes",
                                ),
                            )?;
                        self.charge(1)?;
                        let actual = is_unicode_word(scalar);
                        let endpoint = scalar == range.start() || scalar == range.end();
                        if actual != endpoint {
                            return Err(AnchoredWordCaptureBuildError::Unsupported(
                                "Unicode word class ranges are not complete maximal intervals",
                            ));
                        }
                    }
                }
            }
            _ => {
                return Err(AnchoredWordCaptureBuildError::Unsupported(
                    "word class representation differs from profile mode",
                ));
            }
        }
        self.digest.byte(0x21);
        self.digest.usize(self.accounting.class_ranges);
        Ok(())
    }

    fn build_fixed_program(
        &mut self,
        class: &Class,
        units: u32,
    ) -> Result<Program, AnchoredWordCaptureBuildError> {
        self.digest_class(class);
        match (self.mode, class) {
            (AnchoredWordCaptureMode::Ascii, Class::Bytes(class)) => {
                enforce_build(
                    "class ranges",
                    class.ranges().len(),
                    self.limits.max_class_ranges,
                )?;
                self.accounting.class_ranges = class.ranges().len();
                self.charge(class.ranges().len())?;
                let mut class_words = [0_u64; 4];
                for range in class.ranges() {
                    let mut byte = range.start();
                    loop {
                        let word = usize::from(byte) / 64;
                        let shift = usize::from(byte) % 64;
                        class_words[word] |= 1_u64 << shift;
                        self.charge(1)?;
                        if byte == range.end() {
                            break;
                        }
                        byte = byte.checked_add(1).ok_or(
                            AnchoredWordCaptureBuildError::ArithmeticOverflow(
                                "byte class expansion",
                            ),
                        )?;
                    }
                }
                Ok(Program::FixedAscii { class_words, units })
            }
            (AnchoredWordCaptureMode::Unicode, Class::Unicode(class)) => {
                let range_limit = self.limits.max_class_ranges.min(MAX_CLASS_RANGES);
                enforce_build("class ranges", class.ranges().len(), range_limit)?;
                self.accounting.class_ranges = class.ranges().len();
                self.charge(class.ranges().len())?;
                if class.ranges().len() == UNICODE_NON_WHITESPACE_RANGES.len()
                    && class
                        .ranges()
                        .iter()
                        .zip(UNICODE_NON_WHITESPACE_RANGES)
                        .all(|(actual, (start, end))| {
                            actual.start() == start && actual.end() == end
                        })
                {
                    return Ok(Program::FixedUnicodeNonWhitespace { units });
                }
                let mut ranges = [ScalarRange::default(); MAX_CLASS_RANGES];
                for (slot, range) in ranges.iter_mut().zip(class.ranges()) {
                    *slot = ScalarRange {
                        start: u32::from(range.start()),
                        end: u32::from(range.end()),
                    };
                }
                Ok(Program::FixedUnicode {
                    ranges,
                    range_count: class.ranges().len(),
                    units,
                })
            }
            _ => Err(AnchoredWordCaptureBuildError::Unsupported(
                "fixed class representation differs from profile mode",
            )),
        }
    }

    fn digest_class(&mut self, class: &Class) {
        self.digest.byte(0x40);
        match class {
            Class::Bytes(class) => {
                self.digest.usize(class.ranges().len());
                for range in class.ranges() {
                    self.digest.byte(range.start());
                    self.digest.byte(range.end());
                }
            }
            Class::Unicode(class) => {
                self.digest.usize(class.ranges().len());
                for range in class.ranges() {
                    self.digest.u32(u32::from(range.start()));
                    self.digest.u32(u32::from(range.end()));
                }
            }
        }
    }

    fn node(&mut self) -> Result<(), AnchoredWordCaptureBuildError> {
        self.accounting.hir_nodes = self.accounting.hir_nodes.checked_add(1).ok_or(
            AnchoredWordCaptureBuildError::ArithmeticOverflow("HIR node count"),
        )?;
        enforce_build(
            "HIR nodes",
            self.accounting.hir_nodes,
            self.limits.max_hir_nodes,
        )?;
        self.charge(1)
    }

    fn charge(&mut self, work: usize) -> Result<(), AnchoredWordCaptureBuildError> {
        self.accounting.inspection_work = self.accounting.inspection_work.checked_add(work).ok_or(
            AnchoredWordCaptureBuildError::ArithmeticOverflow("inspection work"),
        )?;
        enforce_build(
            "inspection work",
            self.accounting.inspection_work,
            self.limits.max_inspection_work,
        )
    }
}

fn inspect(
    hir: &Hir,
    mode: AnchoredWordCaptureMode,
    limits: AnchoredWordCaptureBuildLimits,
) -> Result<Inspection, AnchoredWordCaptureBuildError> {
    Inspector::new(mode, limits).inspect(hir)
}

fn match_word_fields_ascii(
    line: &[u8],
    fields: usize,
    actual: &mut AnchoredWordCaptureRunActual,
) -> Result<bool, AnchoredWordCaptureRunError> {
    let mut position = 0_usize;
    while position < line.len() {
        charge_matcher_reads(actual, 1)?;
        if line[position] != b' ' {
            break;
        }
        position = checked_add(position, 1, "ASCII leading-space cursor")?;
    }
    for field in 0..fields {
        let start = position;
        while position < line.len() {
            charge_matcher_reads(actual, 1)?;
            actual.decoded_units = checked_add(actual.decoded_units, 1, "ASCII decoded units")?;
            actual.word_probes = checked_add(actual.word_probes, 1, "ASCII word probes")?;
            if !is_ascii_word(line[position]) {
                break;
            }
            position = checked_add(position, 1, "ASCII word cursor")?;
        }
        if position == start {
            return Ok(false);
        }
        if field.checked_add(1) == Some(fields) {
            return Ok(true);
        }
        let separator_start = position;
        while position < line.len() {
            charge_matcher_reads(actual, 1)?;
            if line[position] != b' ' {
                break;
            }
            position = checked_add(position, 1, "ASCII separator cursor")?;
        }
        if position == separator_start {
            return Ok(false);
        }
    }
    Ok(false)
}

fn match_word_fields_unicode(
    line: &[u8],
    fields: usize,
    actual: &mut AnchoredWordCaptureRunActual,
) -> Result<bool, AnchoredWordCaptureRunError> {
    let mut position = 0_usize;
    while position < line.len() {
        charge_matcher_reads(actual, 1)?;
        if line[position] != b' ' {
            break;
        }
        position = checked_add(position, 1, "Unicode leading-space cursor")?;
    }
    for field in 0..fields {
        let start = position;
        while position < line.len() {
            let (scalar, width) = decode_first(&line[position..])
                .map_or((None, 1), |(scalar, width)| (Some(scalar), width));
            charge_matcher_reads(actual, width)?;
            actual.decoded_units = checked_add(actual.decoded_units, 1, "Unicode decoded units")?;
            actual.word_probes = checked_add(actual.word_probes, 1, "Unicode word probes")?;
            if !scalar.is_some_and(is_unicode_word) {
                break;
            }
            position = checked_add(position, width, "Unicode word cursor")?;
        }
        if position == start {
            return Ok(false);
        }
        if field.checked_add(1) == Some(fields) {
            return Ok(true);
        }
        let separator_start = position;
        while position < line.len() {
            charge_matcher_reads(actual, 1)?;
            if line[position] != b' ' {
                break;
            }
            position = checked_add(position, 1, "Unicode separator cursor")?;
        }
        if position == separator_start {
            return Ok(false);
        }
    }
    Ok(false)
}

fn match_fixed_ascii(
    line: &[u8],
    class_words: [u64; 4],
    units: u32,
    schema: FixedCaptureSchema,
    actual: &mut AnchoredWordCaptureRunActual,
) -> Result<Option<FixedMatchOffsets>, AnchoredWordCaptureRunError> {
    let units =
        usize::try_from(units).map_err(|_| AnchoredWordCaptureRunError::ArithmeticOverflow {
            computation: "fixed ASCII units as usize",
        })?;
    if line.len() < units {
        charge_matcher_reads(actual, line.len())?;
        actual.decoded_units = checked_add(
            actual.decoded_units,
            line.len(),
            "ASCII fixed decoded units",
        )?;
        return Ok(None);
    }
    for &byte in &line[..units] {
        charge_matcher_reads(actual, 1)?;
        actual.decoded_units = checked_add(actual.decoded_units, 1, "ASCII fixed decoded units")?;
        if !byte_class_contains(class_words, byte) {
            return Ok(None);
        }
    }
    let previous_index =
        units
            .checked_sub(1)
            .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
                computation: "positive fixed ASCII units lost final byte",
            })?;
    let previous_word = is_ascii_word(line[previous_index]);
    actual.word_probes = checked_add(actual.word_probes, 1, "ASCII left boundary probe")?;
    let next_word = if let Some(&byte) = line.get(units) {
        charge_matcher_reads(actual, 1)?;
        actual.word_probes = checked_add(actual.word_probes, 1, "ASCII right boundary probe")?;
        is_ascii_word(byte)
    } else {
        false
    };
    if previous_word == next_word {
        return Ok(None);
    }
    let mut unit_ends = [0_usize; MAX_CLASS_RANGES];
    for (index, end) in unit_ends[..units].iter_mut().enumerate() {
        *end = index
            .checked_add(1)
            .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
                computation: "fixed ASCII unit end",
            })?;
    }
    fixed_offsets_from_unit_ends(&unit_ends[..units], schema).map(Some)
}

fn match_fixed_unicode(
    line: &[u8],
    ranges: &[ScalarRange],
    units: u32,
    schema: FixedCaptureSchema,
    actual: &mut AnchoredWordCaptureRunActual,
) -> Result<Option<FixedMatchOffsets>, AnchoredWordCaptureRunError> {
    let mut position = 0_usize;
    let mut previous = None;
    let mut unit_ends = [0_usize; MAX_CLASS_RANGES];
    for unit in 0..units {
        if position == line.len() {
            return Ok(None);
        }
        let Some((scalar, width)) = decode_first(&line[position..]) else {
            charge_matcher_reads(actual, 1)?;
            actual.decoded_units =
                checked_add(actual.decoded_units, 1, "Unicode fixed invalid unit")?;
            return Ok(None);
        };
        charge_matcher_reads(actual, width)?;
        actual.decoded_units = checked_add(actual.decoded_units, 1, "Unicode fixed decoded units")?;
        if !scalar_class_contains(ranges, scalar, actual)? {
            return Ok(None);
        }
        previous = Some(scalar);
        position = checked_add(position, width, "Unicode fixed cursor")?;
        let slot =
            usize::try_from(unit).map_err(|_| AnchoredWordCaptureRunError::ArithmeticOverflow {
                computation: "Unicode fixed unit slot",
            })?;
        unit_ends[slot] = position;
    }
    let previous = previous.ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
        computation: "positive fixed Unicode units lost final scalar",
    })?;
    actual.word_probes = checked_add(actual.word_probes, 1, "Unicode left boundary probe")?;
    let previous_word = is_unicode_word(previous);
    let next_word = if position < line.len() {
        let (scalar, width) = decode_first(&line[position..])
            .map_or((None, 1), |(scalar, width)| (Some(scalar), width));
        charge_matcher_reads(actual, width)?;
        actual.decoded_units =
            checked_add(actual.decoded_units, 1, "Unicode boundary decoded unit")?;
        actual.word_probes = checked_add(actual.word_probes, 1, "Unicode right boundary probe")?;
        scalar.is_some_and(is_unicode_word)
    } else {
        false
    };
    if previous_word == next_word {
        return Ok(None);
    }
    let units =
        usize::try_from(units).map_err(|_| AnchoredWordCaptureRunError::ArithmeticOverflow {
            computation: "fixed Unicode units as usize",
        })?;
    fixed_offsets_from_unit_ends(&unit_ends[..units], schema).map(Some)
}

fn match_fixed_unicode_non_whitespace(
    line: &[u8],
    units: u32,
    schema: FixedCaptureSchema,
    actual: &mut AnchoredWordCaptureRunActual,
) -> Result<Option<FixedMatchOffsets>, AnchoredWordCaptureRunError> {
    let mut position = 0_usize;
    let mut previous = None;
    let mut unit_ends = [0_usize; MAX_CLASS_RANGES];
    for unit in 0..units {
        if position == line.len() {
            return Ok(None);
        }
        let Some((scalar, width)) = decode_first(&line[position..]) else {
            charge_matcher_reads(actual, 1)?;
            actual.decoded_units =
                checked_add(actual.decoded_units, 1, "Unicode fixed invalid unit")?;
            return Ok(None);
        };
        charge_matcher_reads(actual, width)?;
        actual.decoded_units = checked_add(actual.decoded_units, 1, "Unicode fixed decoded units")?;
        actual.class_comparisons = checked_add(
            actual.class_comparisons,
            1,
            "Unicode whitespace comparisons",
        )?;
        if is_unicode_whitespace(scalar) {
            return Ok(None);
        }
        previous = Some(scalar);
        position = checked_add(position, width, "Unicode fixed cursor")?;
        let slot =
            usize::try_from(unit).map_err(|_| AnchoredWordCaptureRunError::ArithmeticOverflow {
                computation: "Unicode fixed non-whitespace unit slot",
            })?;
        unit_ends[slot] = position;
    }
    let previous = previous.ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
        computation: "positive fixed Unicode units lost final scalar",
    })?;
    actual.word_probes = checked_add(actual.word_probes, 1, "Unicode left boundary probe")?;
    let previous_word = is_unicode_word(previous);
    let next_word = if position < line.len() {
        let (scalar, width) = decode_first(&line[position..])
            .map_or((None, 1), |(scalar, width)| (Some(scalar), width));
        charge_matcher_reads(actual, width)?;
        actual.decoded_units =
            checked_add(actual.decoded_units, 1, "Unicode boundary decoded unit")?;
        actual.word_probes = checked_add(actual.word_probes, 1, "Unicode right boundary probe")?;
        scalar.is_some_and(is_unicode_word)
    } else {
        false
    };
    if previous_word == next_word {
        return Ok(None);
    }
    let units =
        usize::try_from(units).map_err(|_| AnchoredWordCaptureRunError::ArithmeticOverflow {
            computation: "fixed Unicode non-whitespace units as usize",
        })?;
    fixed_offsets_from_unit_ends(&unit_ends[..units], schema).map(Some)
}

fn fixed_offsets_from_unit_ends(
    unit_ends: &[usize],
    schema: FixedCaptureSchema,
) -> Result<FixedMatchOffsets, AnchoredWordCaptureRunError> {
    let end = unit_ends
        .last()
        .copied()
        .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
            computation: "positive fixed capture lost its final unit",
        })?;
    let mut capture_ends = [0_usize; MAX_CLASS_RANGES];
    let mut units = 0_usize;
    for (capture, &width) in schema.widths[..schema.captures].iter().enumerate() {
        units = units
            .checked_add(usize::try_from(width).map_err(|_| {
                AnchoredWordCaptureRunError::ArithmeticOverflow {
                    computation: "fixed capture width as usize",
                }
            })?)
            .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
                computation: "fixed capture unit boundary",
            })?;
        let unit = units
            .checked_sub(1)
            .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
                computation: "positive fixed capture width",
            })?;
        capture_ends[capture] =
            *unit_ends
                .get(unit)
                .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
                    computation: "fixed capture endpoint lookup",
                })?;
    }
    let final_capture = schema.captures.checked_sub(1).ok_or(
        AnchoredWordCaptureRunError::ArithmeticOverflow {
            computation: "positive fixed capture schema lost all captures",
        },
    )?;
    if units != unit_ends.len() || capture_ends.get(final_capture).copied() != Some(end) {
        return Err(AnchoredWordCaptureRunError::ArithmeticOverflow {
            computation: "fixed capture schema closure",
        });
    }
    Ok(FixedMatchOffsets { end, capture_ends })
}

fn scalar_class_contains(
    ranges: &[ScalarRange],
    scalar: char,
    actual: &mut AnchoredWordCaptureRunActual,
) -> Result<bool, AnchoredWordCaptureRunError> {
    let scalar = u32::from(scalar);
    let mut lower = 0_usize;
    let mut upper = ranges.len();
    while lower < upper {
        actual.class_comparisons = checked_add(actual.class_comparisons, 1, "class comparisons")?;
        let span =
            upper
                .checked_sub(lower)
                .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
                    computation: "class-search span",
                })?;
        let middle =
            lower
                .checked_add(span / 2)
                .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
                    computation: "class-search midpoint",
                })?;
        let range = ranges[middle];
        if scalar < range.start {
            upper = middle;
        } else if scalar > range.end {
            lower =
                middle
                    .checked_add(1)
                    .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow {
                        computation: "class-search lower bound",
                    })?;
        } else {
            return Ok(true);
        }
    }
    Ok(false)
}

fn charge_matcher_reads(
    actual: &mut AnchoredWordCaptureRunActual,
    reads: usize,
) -> Result<(), AnchoredWordCaptureRunError> {
    actual.matcher_reads = checked_add(actual.matcher_reads, reads, "matcher reads")?;
    Ok(())
}

fn enforce_run_limits(
    upper: AnchoredWordCaptureRunUpperBounds,
    limits: AnchoredWordCaptureRunLimits,
) -> Result<(), AnchoredWordCaptureRunError> {
    for (resource, needed, limit) in [
        (
            AnchoredWordCaptureRunResource::InputBytes,
            upper.input_bytes,
            limits.max_input_bytes,
        ),
        (
            AnchoredWordCaptureRunResource::SourceReads,
            upper.source_reads,
            limits.max_source_reads,
        ),
        (
            AnchoredWordCaptureRunResource::DecodedUnits,
            upper.decoded_units,
            limits.max_decoded_units,
        ),
        (
            AnchoredWordCaptureRunResource::ClassComparisons,
            upper.class_comparisons,
            limits.max_class_comparisons,
        ),
        (
            AnchoredWordCaptureRunResource::WordProbes,
            upper.word_probes,
            limits.max_word_probes,
        ),
        (
            AnchoredWordCaptureRunResource::Lines,
            upper.lines,
            limits.max_lines,
        ),
        (
            AnchoredWordCaptureRunResource::Matches,
            upper.matches,
            limits.max_matches,
        ),
        (
            AnchoredWordCaptureRunResource::CaptureCount,
            upper.capture_count,
            limits.max_capture_count,
        ),
        (
            AnchoredWordCaptureRunResource::Work,
            upper.work,
            limits.max_work,
        ),
        (
            AnchoredWordCaptureRunResource::SequentialBytes,
            upper.sequential_bytes,
            limits.max_sequential_bytes,
        ),
        (
            AnchoredWordCaptureRunResource::PeakBytes,
            upper.peak_bytes,
            limits.max_peak_bytes,
        ),
    ] {
        if needed > limit {
            return Err(AnchoredWordCaptureRunError::Resource {
                resource,
                needed,
                limit,
            });
        }
    }
    Ok(())
}

fn verify_actual(
    actual: AnchoredWordCaptureRunActual,
    upper: AnchoredWordCaptureRunUpperBounds,
) -> Result<(), AnchoredWordCaptureRunError> {
    for (resource, actual, upper) in [
        (
            AnchoredWordCaptureRunResource::SourceReads,
            actual.source_reads,
            upper.source_reads,
        ),
        (
            AnchoredWordCaptureRunResource::DecodedUnits,
            actual.decoded_units,
            upper.decoded_units,
        ),
        (
            AnchoredWordCaptureRunResource::ClassComparisons,
            actual.class_comparisons,
            upper.class_comparisons,
        ),
        (
            AnchoredWordCaptureRunResource::WordProbes,
            actual.word_probes,
            upper.word_probes,
        ),
        (
            AnchoredWordCaptureRunResource::Lines,
            actual.lines,
            upper.lines,
        ),
        (
            AnchoredWordCaptureRunResource::Matches,
            actual.matches,
            upper.matches,
        ),
        (
            AnchoredWordCaptureRunResource::CaptureCount,
            actual.capture_count,
            upper.capture_count,
        ),
        (
            AnchoredWordCaptureRunResource::Work,
            actual.work,
            upper.work,
        ),
        (
            AnchoredWordCaptureRunResource::SequentialBytes,
            actual.sequential_bytes,
            upper.sequential_bytes,
        ),
    ] {
        if actual > upper {
            return Err(AnchoredWordCaptureRunError::AccountingInvariant {
                resource,
                actual,
                upper,
            });
        }
    }
    Ok(())
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

fn enforce_build(
    resource: &'static str,
    needed: usize,
    limit: usize,
) -> Result<(), AnchoredWordCaptureBuildError> {
    if needed > limit {
        return Err(AnchoredWordCaptureBuildError::Resource {
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
) -> Result<usize, AnchoredWordCaptureRunError> {
    value
        .checked_add(addend)
        .ok_or(AnchoredWordCaptureRunError::ArithmeticOverflow { computation })
}

fn byte_class_contains(words: [u64; 4], byte: u8) -> bool {
    let word = usize::from(byte) / 64;
    let bit = usize::from(byte) % 64;
    words[word] & (1_u64 << bit) != 0
}

const fn is_ascii_word(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn is_unicode_word(scalar: char) -> bool {
    if scalar.is_ascii() {
        return scalar == '_' || scalar.is_ascii_alphanumeric();
    }
    if is_common_cyrillic_word(scalar) {
        return true;
    }
    regex_syntax::try_is_word_character(scalar)
        .expect("fre enables regex-syntax's Unicode Perl tables")
}

const fn is_common_cyrillic_word(scalar: char) -> bool {
    matches!(scalar, '\u{401}' | '\u{410}'..='\u{44f}' | '\u{451}')
}

const fn is_unicode_whitespace(scalar: char) -> bool {
    matches!(
        scalar,
        '\u{9}'..='\u{d}'
            | '\u{20}'
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'..='\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

fn previous_scalar(scalar: char) -> Option<char> {
    let codepoint = u32::from(scalar).checked_sub(1)?;
    if codepoint == 0xDFFF {
        Some('\u{D7FF}')
    } else {
        char::from_u32(codepoint)
    }
}

fn next_scalar(scalar: char) -> Option<char> {
    let codepoint = u32::from(scalar).checked_add(1)?;
    if codepoint == 0xD800 {
        Some('\u{E000}')
    } else {
        char::from_u32(codepoint)
    }
}

fn decode_first(bytes: &[u8]) -> Option<(char, usize)> {
    let first = *bytes.first()?;
    if first.is_ascii() {
        return Some((char::from(first), 1));
    }
    if !matches!(first, 0xc2..=0xf4) {
        return None;
    }
    let second = *bytes.get(1)?;
    if !is_utf8_continuation(second) {
        return None;
    }
    if matches!(first, 0xc2..=0xdf) {
        let scalar = (u32::from(first & 0x1f) << 6) | u32::from(second & 0x3f);
        return char::from_u32(scalar).map(|scalar| (scalar, 2));
    }
    let third = *bytes.get(2)?;
    if !is_utf8_continuation(third)
        || (first == 0xe0 && second < 0xa0)
        || (first == 0xed && second >= 0xa0)
    {
        return None;
    }
    if matches!(first, 0xe0..=0xef) {
        let scalar = (u32::from(first & 0x0f) << 12)
            | (u32::from(second & 0x3f) << 6)
            | u32::from(third & 0x3f);
        return char::from_u32(scalar).map(|scalar| (scalar, 3));
    }
    let fourth = *bytes.get(3)?;
    if !is_utf8_continuation(fourth)
        || !matches!(first, 0xf0..=0xf4)
        || (first == 0xf0 && second < 0x90)
        || (first == 0xf4 && second >= 0x90)
    {
        return None;
    }
    let scalar = (u32::from(first & 0x07) << 18)
        | (u32::from(second & 0x3f) << 12)
        | (u32::from(third & 0x3f) << 6)
        | u32::from(fourth & 0x3f);
    char::from_u32(scalar).map(|scalar| (scalar, 4))
}

const fn is_utf8_continuation(byte: u8) -> bool {
    matches!(byte, 0x80..=0xbf)
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

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        reason = "the reference-only line splitter uses indices proved in bounds by its loop guards"
    )]

    use super::*;
    use regex::bytes::RegexBuilder;

    fn exact_limits(
        plan: &AnchoredWordCapturePlan,
        input_bytes: usize,
    ) -> AnchoredWordCaptureRunLimits {
        let upper = plan.run_upper_bounds(input_bytes).expect("upper bounds");
        AnchoredWordCaptureRunLimits {
            max_input_bytes: upper.input_bytes,
            max_source_reads: upper.source_reads,
            max_decoded_units: upper.decoded_units,
            max_class_comparisons: upper.class_comparisons,
            max_word_probes: upper.word_probes,
            max_lines: upper.lines,
            max_matches: upper.matches,
            max_capture_count: upper.capture_count,
            max_work: upper.work,
            max_sequential_bytes: upper.sequential_bytes,
            max_peak_bytes: upper.peak_bytes,
        }
    }

    fn reference_lines(pattern: &str, unicode: bool, haystack: &[u8]) -> usize {
        let regex = RegexBuilder::new(pattern)
            .unicode(unicode)
            .build()
            .expect("reference regex");
        let mut count = 0_usize;
        let mut start = 0_usize;
        for (index, &byte) in haystack.iter().enumerate() {
            if byte != b'\n' {
                continue;
            }
            let end = if index > start && haystack[index - 1] == b'\r' {
                index - 1
            } else {
                index
            };
            count += regex
                .captures_iter(&haystack[start..end])
                .map(|captures| captures.iter().flatten().count())
                .sum::<usize>();
            start = index + 1;
        }
        if start < haystack.len() {
            count += regex
                .captures_iter(&haystack[start..])
                .map(|captures| captures.iter().flatten().count())
                .sum::<usize>();
        }
        count
    }

    fn reference_records(
        pattern: &str,
        unicode: bool,
        haystack: &[u8],
    ) -> Vec<(usize, Vec<AnchoredWordCaptureSpan>)> {
        let regex = RegexBuilder::new(pattern)
            .unicode(unicode)
            .build()
            .expect("reference regex");
        let mut records = Vec::new();
        let mut start = 0_usize;
        for (index, &byte) in haystack.iter().enumerate() {
            if byte != b'\n' {
                continue;
            }
            let end = if index > start && haystack[index - 1] == b'\r' {
                index - 1
            } else {
                index
            };
            let line = &haystack[start..end];
            for captures in regex.captures_iter(line) {
                records.push((
                    line.len(),
                    captures
                        .iter()
                        .map(|matched| {
                            let matched = matched.expect("mandatory fixed capture");
                            AnchoredWordCaptureSpan {
                                start: matched.start(),
                                end: matched.end(),
                            }
                        })
                        .collect(),
                ));
            }
            start = index + 1;
        }
        if start < haystack.len() {
            let line = &haystack[start..];
            for captures in regex.captures_iter(line) {
                records.push((
                    line.len(),
                    captures
                        .iter()
                        .map(|matched| {
                            let matched = matched.expect("mandatory fixed capture");
                            AnchoredWordCaptureSpan {
                                start: matched.start(),
                                end: matched.end(),
                            }
                        })
                        .collect(),
                ));
            }
        }
        records
    }

    fn assert_matches_reference(
        pattern: &str,
        unicode: bool,
        haystack: &[u8],
    ) -> AnchoredWordCapturePlan {
        let plan = AnchoredWordCaptureBuilder::new(pattern)
            .unicode(unicode)
            .build()
            .expect("anchored word plan");
        let result = plan
            .grep_capture_count(haystack, exact_limits(&plan, haystack.len()))
            .expect("anchored word count");
        assert_eq!(
            result.capture_count,
            reference_lines(pattern, unicode, haystack),
            "{haystack:?}"
        );
        plan
    }

    #[test]
    fn canonical_word_fields_match_ascii_unicode_crlf_and_invalid_bytes() {
        let pattern = r"^ *(\w+) +(\w+) +(\w+)";
        let ascii = b"one two three\n one  two three four\r\none two\n\xff one two three";
        let plan = assert_matches_reference(pattern, false, ascii);
        assert_eq!(
            plan.build_report().identity.operation.kind,
            AnchoredWordCaptureKind::WordFields
        );

        let mut unicode = "раз два три\n один  два три четыре\r\nраз два\n"
            .as_bytes()
            .to_vec();
        unicode.extend_from_slice(b"\xff ");
        unicode.extend_from_slice("раз два три".as_bytes());
        assert_matches_reference(pattern, true, &unicode);
    }

    #[test]
    fn fixed_class_boundary_matches_both_modes_and_contexts() {
        let pattern = r"^(\S{8})(\S)\b";
        for haystack in [
            b"abcdefghx\nabcdefgh \nabcdefghxZ\n123456789\r\nshort\n".as_slice(),
            b"abcdefg\xffx\nabcdefghi_\n".as_slice(),
        ] {
            let plan = assert_matches_reference(pattern, false, haystack);
            assert_eq!(
                plan.build_report().identity.operation.kind,
                AnchoredWordCaptureKind::FixedClassWordBoundary
            );
        }
        let unicode = "абвгдежзи\nабвгдежз \nabcdefghi_\r\nабвгдежзи7\n";
        let unicode_plan = assert_matches_reference(pattern, true, unicode.as_bytes());
        match unicode_plan.program {
            Program::FixedUnicodeNonWhitespace { units: 9 } => {}
            Program::FixedUnicode {
                ranges,
                range_count,
                ..
            } => panic!(
                "unexpected Unicode non-whitespace ranges: {:?}",
                &ranges[..range_count]
            ),
            _ => panic!("unexpected Unicode non-whitespace program"),
        }
    }

    #[test]
    fn fixed_boundary_record_visit_matches_line_relative_reference_and_is_atomic() {
        let pattern = r"^(\S{8})(\S)\b";
        let mut haystack = "абвгдежзи tail\nабвгдежз \nabcdefghi_\r\nабвгдежзи7\n"
            .as_bytes()
            .to_vec();
        haystack.extend_from_slice(b"abcdefg\xffx\n123456789\nshort");
        for unicode in [false, true] {
            let plan = AnchoredWordCaptureBuilder::new(pattern)
                .unicode(unicode)
                .build()
                .expect("fixed record plan");
            let expected = reference_records(pattern, unicode, &haystack);
            let mut actual = Vec::new();
            let report = plan
                .visit_grep_capture_records(
                    &haystack,
                    exact_limits(&plan, haystack.len()),
                    |line_len, spans| actual.push((line_len, spans.to_vec())),
                )
                .expect("fixed record visit")
                .expect("fixed record route");
            assert_eq!(actual, expected);
            assert_eq!(
                report.operation_id,
                ANCHORED_WORD_CAPTURE_RECORD_OPERATION_ID
            );
            assert_eq!(report.matches, expected.len());
            assert_eq!(report.capture_count, expected.len() * 3);
            assert_eq!(report.endpoint_writes, report.capture_count * 2);
            assert_eq!(
                report.reducer_events,
                report.line_domains + report.capture_count
            );

            let mut one_below = exact_limits(&plan, haystack.len());
            one_below.max_source_reads -= 1;
            let mut callbacks = 0_usize;
            assert!(matches!(
                plan.visit_grep_capture_records(&haystack, one_below, |_, _| callbacks += 1),
                Err(AnchoredWordCaptureRunError::Resource {
                    resource: AnchoredWordCaptureRunResource::SourceReads,
                    ..
                })
            ));
            assert_eq!(callbacks, 0);
        }

        let named = AnchoredWordCaptureBuilder::new(r"^(?P<left>\S{8})(?P<right>\S)\b")
            .unicode(true)
            .build()
            .expect("named count plan remains admitted");
        assert!(
            named
                .grep_capture_record_upper_bounds(haystack.len())
                .expect("named record preflight")
                .is_none()
        );
        let mut callbacks = 0_usize;
        assert!(
            named
                .visit_grep_capture_records(
                    &haystack,
                    exact_limits(&named, haystack.len()),
                    |_, _| callbacks += 1,
                )
                .expect("named record refusal")
                .is_none()
        );
        assert_eq!(callbacks, 0);
    }

    #[test]
    fn admitted_shapes_match_reference_on_mixed_valid_and_invalid_bytes() {
        let mut haystack = Vec::with_capacity(65_536);
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        for line in 0..512_usize {
            let width = line % 73;
            for _ in 0..width {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                haystack.push(state.to_le_bytes()[0]);
            }
            match line % 5 {
                0 => haystack.extend_from_slice(b"\r\n"),
                1 => haystack.push(b'\n'),
                2 => haystack.extend_from_slice(" раз два три\n".as_bytes()),
                3 => haystack.extend_from_slice("абвгдежзи\n".as_bytes()),
                _ => haystack.extend_from_slice(b" one  two three tail\n"),
            }
        }
        for (pattern, unicode) in [
            (r"^ *(\w+) +(\w+) +(\w+)", false),
            (r"^ *(\w+) +(\w+) +(\w+)", true),
            (r"^(\S{8})(\S)\b", false),
            (r"^(\S{8})(\S)\b", true),
        ] {
            assert_matches_reference(pattern, unicode, &haystack);
        }
    }

    #[test]
    fn utf8_decoder_and_specialized_properties_match_independent_oracles() {
        const EDGE_BYTES: [u8; 14] = [
            0x00, 0x01, 0x7f, 0x80, 0x8f, 0x90, 0x9f, 0xa0, 0xbf, 0xc0, 0xed, 0xf0, 0xf4, 0xff,
        ];

        for codepoint in 0_u32..=0x10_ffff {
            let Some(scalar) = char::from_u32(codepoint) else {
                continue;
            };
            let mut encoded = [0_u8; 4];
            let bytes = scalar.encode_utf8(&mut encoded).as_bytes();
            assert_eq!(decode_first(bytes), Some((scalar, bytes.len())));
            assert_eq!(is_unicode_whitespace(scalar), scalar.is_whitespace());
            if is_common_cyrillic_word(scalar) {
                assert!(
                    regex_syntax::try_is_word_character(scalar)
                        .expect("Unicode word property table")
                );
            }
        }

        for first in 0_u8..=u8::MAX {
            for second in EDGE_BYTES {
                for third in EDGE_BYTES {
                    for fourth in EDGE_BYTES {
                        let bytes = [first, second, third, fourth];
                        let reference = match first {
                            0x00..=0x7f => Some(1),
                            0xc2..=0xdf => Some(2),
                            0xe0..=0xef => Some(3),
                            0xf0..=0xf4 => Some(4),
                            _ => None,
                        }
                        .and_then(|width| {
                            core::str::from_utf8(&bytes[..width])
                                .ok()?
                                .chars()
                                .next()
                                .map(|scalar| (scalar, width))
                        });
                        assert_eq!(decode_first(&bytes), reference, "{bytes:02x?}");
                    }
                }
            }
        }
    }

    #[test]
    fn nearby_shapes_are_refused() {
        for (pattern, unicode) in [
            (r" *(\w+) +(\w+) +(\w+)", true),
            (r"^ *(\w+)\s+(\w+) +(\w+)", true),
            (r"^ *(\w*) +(\w+) +(\w+)", true),
            (r"^(\S{8})(\S)", true),
            (r"^(\S{8})(\w)\b", true),
            (r"^(\S{65})\b", false),
        ] {
            assert!(
                AnchoredWordCaptureBuilder::new(pattern)
                    .unicode(unicode)
                    .build()
                    .is_err(),
                "{pattern}"
            );
        }
    }
}
