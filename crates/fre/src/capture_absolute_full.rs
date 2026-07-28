//! Source-independent capture counting for one mandatory absolute full-byte
//! match.
//!
//! This plan is admitted only when canonical HIR proves a single linear path
//! with exactly one `[\x00-\xFF]*` between absolute start and end assertions.
//! Capture nodes may wrap or neighbor that path, but they cannot occur inside
//! the repetition and no optional or alternative topology is accepted. Every
//! explicit capture therefore participates exactly once for every byte
//! haystack, as does the implicit whole-match group.

use core::{fmt, mem::size_of};

use fre_syntax::{
    AdmissionPolicy, CanonicalPattern, CompatibilityProfile, RustProfile, SafetyEnvelope,
};
use regex_syntax::hir::{Class, Hir, HirKind, Look};

pub const ABSOLUTE_FULL_CAPTURE_PLAN_ID: &str = "capture-absolute-full-byte-star-v1";
pub const ABSOLUTE_FULL_CAPTURE_COUNT_OPERATION_ID: &str =
    "capture-absolute-full-byte-star.participation-count.v1";
pub const ABSOLUTE_FULL_CAPTURE_ALGORITHM_VERSION: u32 = 1;
pub const ABSOLUTE_FULL_CAPTURE_ACCOUNTING_VERSION: u32 = 1;

const WHOLE_MATCH_GROUPS: usize = 1;
const DIGEST_OFFSET_A: u64 = 0xcbf2_9ce4_8422_2325;
const DIGEST_OFFSET_B: u64 = 0x8422_2325_cbf2_9ce4;
const DIGEST_PRIME_A: u64 = 0x0000_0100_0000_01b3;
const DIGEST_PRIME_B: u64 = 0x0000_0100_0000_01cf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbsoluteFullCaptureBuildLimits {
    pub admission: AdmissionPolicy,
    pub syntax_safety: SafetyEnvelope,
    pub max_inspection_work: usize,
    pub max_hir_nodes: usize,
    pub max_captures: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl Default for AbsoluteFullCaptureBuildLimits {
    fn default() -> Self {
        Self {
            admission: AdmissionPolicy::default(),
            syntax_safety: SafetyEnvelope::default(),
            max_inspection_work: 8_192,
            max_hir_nodes: 1_024,
            max_captures: 1_024,
            max_persistent_bytes: 1 << 20,
            max_peak_bytes: 1 << 20,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbsoluteFullCaptureHirAccounting {
    pub hir_nodes: usize,
    pub captures: usize,
    pub repetitions: usize,
    pub classes: usize,
    pub looks: usize,
    pub inspection_work: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each bit authenticates a separate immutable regex semantic"
)]
pub struct AbsoluteFullCaptureOperationIdentity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub explicit_captures: usize,
    pub groups_per_match: usize,
    pub absolute_start: bool,
    pub absolute_end: bool,
    pub complete_byte_star: bool,
    pub greedy: bool,
    pub one_match_for_every_input: bool,
    pub mandatory_capture_participation: bool,
    pub source_independent: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbsoluteFullCapturePlanIdentity {
    pub profile: RustProfile,
    pub source_digest: [u64; 2],
    pub algorithm_version: u32,
    pub accounting_version: u32,
    pub operation: AbsoluteFullCaptureOperationIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbsoluteFullCaptureBuildReport {
    pub identity: AbsoluteFullCapturePlanIdentity,
    pub hir: AbsoluteFullCaptureHirAccounting,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum AbsoluteFullCaptureBuildError {
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

impl fmt::Display for AbsoluteFullCaptureBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(error) => write!(formatter, "absolute-full capture syntax: {error}"),
            Self::Unsupported(reason) => {
                write!(
                    formatter,
                    "unsupported absolute-full capture shape: {reason}"
                )
            }
            Self::Resource {
                resource,
                needed,
                limit,
            } => write!(
                formatter,
                "absolute-full capture {resource} needs {needed}, limit is {limit}"
            ),
            Self::ArithmeticOverflow(computation) => write!(
                formatter,
                "absolute-full capture overflow while computing {computation}"
            ),
            Self::InternalInvariant(message) => {
                write!(formatter, "absolute-full capture invariant: {message}")
            }
        }
    }
}

impl std::error::Error for AbsoluteFullCaptureBuildError {
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
pub struct AbsoluteFullCaptureRunLimits {
    pub max_input_bytes: usize,
    pub max_matches: usize,
    pub max_capture_count: usize,
    pub max_work: usize,
    pub max_sequential_bytes: usize,
    pub max_peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbsoluteFullCaptureRunUpperBounds {
    pub input_bytes: usize,
    pub source_reads: usize,
    pub matches: usize,
    pub capture_count: usize,
    pub work: usize,
    pub sequential_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbsoluteFullCaptureRunActual {
    pub source_reads: usize,
    pub matches: usize,
    pub capture_count: usize,
    pub work: usize,
    pub sequential_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbsoluteFullCaptureCountResult {
    pub identity: AbsoluteFullCaptureOperationIdentity,
    pub capture_count: usize,
    pub upper_bounds: AbsoluteFullCaptureRunUpperBounds,
    pub actual: AbsoluteFullCaptureRunActual,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbsoluteFullCaptureRunResource {
    InputBytes,
    Matches,
    CaptureCount,
    Work,
    SequentialBytes,
    PeakBytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AbsoluteFullCaptureRunError {
    Resource {
        resource: AbsoluteFullCaptureRunResource,
        needed: usize,
        limit: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    AccountingInvariant {
        resource: AbsoluteFullCaptureRunResource,
        actual: usize,
        upper: usize,
    },
}

impl fmt::Display for AbsoluteFullCaptureRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "absolute-full capture reduction failed: {self:?}"
        )
    }
}

impl std::error::Error for AbsoluteFullCaptureRunError {}

#[derive(Clone, Debug)]
pub struct AbsoluteFullCaptureBuilder {
    pattern: String,
    profile: RustProfile,
    limits: AbsoluteFullCaptureBuildLimits,
}

impl AbsoluteFullCaptureBuilder {
    #[must_use]
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            profile: RustProfile::default(),
            limits: AbsoluteFullCaptureBuildLimits::default(),
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
    pub const fn limits(mut self, limits: AbsoluteFullCaptureBuildLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn build(self) -> Result<AbsoluteFullCapturePlan, AbsoluteFullCaptureBuildError> {
        if self.profile.options.unicode {
            return Err(AbsoluteFullCaptureBuildError::Unsupported(
                "Unicode mode is not admitted",
            ));
        }
        if self.profile.options.case_insensitive {
            return Err(AbsoluteFullCaptureBuildError::Unsupported(
                "case-insensitive mode is not admitted",
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
        .map_err(AbsoluteFullCaptureBuildError::Syntax)?;
        let source_digest = digest_source(parsed.key.pattern.as_bytes());
        let summary = parsed.summary;
        let CanonicalPattern::Rust(rust) = parsed.pattern else {
            return Err(AbsoluteFullCaptureBuildError::InternalInvariant(
                "Rust byte request produced a non-Rust HIR",
            ));
        };
        let hir = inspect(&rust.hir, self.limits)?;
        let explicit_captures = usize::try_from(summary.captures).map_err(|_| {
            AbsoluteFullCaptureBuildError::ArithmeticOverflow("explicit capture count")
        })?;
        if explicit_captures != hir.captures {
            return Err(AbsoluteFullCaptureBuildError::InternalInvariant(
                "parse capture count differs from mandatory linear-path captures",
            ));
        }
        if explicit_captures == 0 {
            return Err(AbsoluteFullCaptureBuildError::Unsupported(
                "capture-count specialization requires an explicit capture",
            ));
        }
        let groups_per_match = explicit_captures.checked_add(WHOLE_MATCH_GROUPS).ok_or(
            AbsoluteFullCaptureBuildError::ArithmeticOverflow("groups per match"),
        )?;
        enforce_build("captures", explicit_captures, self.limits.max_captures)?;
        let persistent_bytes = size_of::<AbsoluteFullCapturePlan>();
        enforce_build(
            "persistent bytes",
            persistent_bytes,
            self.limits.max_persistent_bytes,
        )?;
        enforce_build("peak bytes", persistent_bytes, self.limits.max_peak_bytes)?;
        let operation = AbsoluteFullCaptureOperationIdentity {
            plan_id: ABSOLUTE_FULL_CAPTURE_PLAN_ID,
            operation_id: ABSOLUTE_FULL_CAPTURE_COUNT_OPERATION_ID,
            explicit_captures,
            groups_per_match,
            absolute_start: true,
            absolute_end: true,
            complete_byte_star: true,
            greedy: true,
            one_match_for_every_input: true,
            mandatory_capture_participation: true,
            source_independent: true,
        };
        let report = AbsoluteFullCaptureBuildReport {
            identity: AbsoluteFullCapturePlanIdentity {
                profile,
                source_digest,
                algorithm_version: ABSOLUTE_FULL_CAPTURE_ALGORITHM_VERSION,
                accounting_version: ABSOLUTE_FULL_CAPTURE_ACCOUNTING_VERSION,
                operation,
            },
            hir,
            persistent_bytes,
            peak_bytes: persistent_bytes,
        };
        Ok(AbsoluteFullCapturePlan { report })
    }
}

#[derive(Clone, Debug)]
pub struct AbsoluteFullCapturePlan {
    report: AbsoluteFullCaptureBuildReport,
}

impl AbsoluteFullCapturePlan {
    #[must_use]
    pub const fn build_report(&self) -> &AbsoluteFullCaptureBuildReport {
        &self.report
    }

    pub fn run_upper_bounds(
        &self,
        input_bytes: usize,
    ) -> Result<AbsoluteFullCaptureRunUpperBounds, AbsoluteFullCaptureRunError> {
        let capture_count = self.report.identity.operation.groups_per_match;
        let work = capture_count.checked_add(1).ok_or(
            AbsoluteFullCaptureRunError::ArithmeticOverflow {
                computation: "match plus capture reducer work",
            },
        )?;
        Ok(AbsoluteFullCaptureRunUpperBounds {
            input_bytes,
            source_reads: 0,
            matches: 1,
            capture_count,
            work,
            sequential_bytes: 0,
            peak_bytes: self.report.persistent_bytes,
        })
    }

    pub fn count_captures(
        &self,
        haystack: &[u8],
        limits: AbsoluteFullCaptureRunLimits,
    ) -> Result<AbsoluteFullCaptureCountResult, AbsoluteFullCaptureRunError> {
        let upper = self.run_upper_bounds(haystack.len())?;
        enforce_run_limits(upper, limits)?;
        let actual = AbsoluteFullCaptureRunActual {
            source_reads: 0,
            matches: 1,
            capture_count: upper.capture_count,
            work: upper.work,
            sequential_bytes: 0,
        };
        if actual.capture_count != self.report.identity.operation.groups_per_match
            || actual.work != upper.work
        {
            return Err(AbsoluteFullCaptureRunError::AccountingInvariant {
                resource: AbsoluteFullCaptureRunResource::CaptureCount,
                actual: actual.capture_count,
                upper: upper.capture_count,
            });
        }
        Ok(AbsoluteFullCaptureCountResult {
            identity: self.report.identity.operation,
            capture_count: actual.capture_count,
            upper_bounds: upper,
            actual,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Position {
    BeforeStart,
    BeforeStar,
    BeforeEnd,
    AfterEnd,
}

struct Inspection {
    position: Position,
    accounting: AbsoluteFullCaptureHirAccounting,
}

fn inspect(
    hir: &Hir,
    limits: AbsoluteFullCaptureBuildLimits,
) -> Result<AbsoluteFullCaptureHirAccounting, AbsoluteFullCaptureBuildError> {
    let mut inspection = Inspection {
        position: Position::BeforeStart,
        accounting: AbsoluteFullCaptureHirAccounting {
            hir_nodes: 0,
            captures: 0,
            repetitions: 0,
            classes: 0,
            looks: 0,
            inspection_work: 0,
        },
    };
    inspect_node(hir, &mut inspection, limits)?;
    if inspection.position != Position::AfterEnd
        || inspection.accounting.repetitions != 1
        || inspection.accounting.classes != 1
        || inspection.accounting.looks != 2
    {
        return Err(AbsoluteFullCaptureBuildError::Unsupported(
            "linear path must contain one absolute start, one full-byte star and one absolute end",
        ));
    }
    Ok(inspection.accounting)
}

fn inspect_node(
    hir: &Hir,
    inspection: &mut Inspection,
    limits: AbsoluteFullCaptureBuildLimits,
) -> Result<(), AbsoluteFullCaptureBuildError> {
    account_node(&mut inspection.accounting, limits)?;
    match hir.kind() {
        HirKind::Empty => Ok(()),
        HirKind::Capture(capture) => {
            inspection.accounting.captures = inspection.accounting.captures.checked_add(1).ok_or(
                AbsoluteFullCaptureBuildError::ArithmeticOverflow("capture count"),
            )?;
            enforce_build(
                "captures",
                inspection.accounting.captures,
                limits.max_captures,
            )?;
            inspect_node(&capture.sub, inspection, limits)
        }
        HirKind::Concat(parts) => {
            for part in parts {
                inspect_node(part, inspection, limits)?;
            }
            Ok(())
        }
        HirKind::Look(Look::Start) if inspection.position == Position::BeforeStart => {
            inspection.accounting.looks = inspection.accounting.looks.checked_add(1).ok_or(
                AbsoluteFullCaptureBuildError::ArithmeticOverflow("look count"),
            )?;
            inspection.position = Position::BeforeStar;
            Ok(())
        }
        HirKind::Look(Look::End) if inspection.position == Position::BeforeEnd => {
            inspection.accounting.looks = inspection.accounting.looks.checked_add(1).ok_or(
                AbsoluteFullCaptureBuildError::ArithmeticOverflow("look count"),
            )?;
            inspection.position = Position::AfterEnd;
            Ok(())
        }
        HirKind::Look(_) => Err(AbsoluteFullCaptureBuildError::Unsupported(
            "only one ordered absolute start and end assertion is admitted",
        )),
        HirKind::Repetition(repetition) if inspection.position == Position::BeforeStar => {
            if repetition.min != 0 || repetition.max.is_some() {
                return Err(AbsoluteFullCaptureBuildError::Unsupported(
                    "the sole repetition must be unbounded star",
                ));
            }
            if !repetition.greedy {
                return Err(AbsoluteFullCaptureBuildError::Unsupported(
                    "lazy full-byte star is not admitted",
                ));
            }
            inspection.accounting.repetitions =
                inspection.accounting.repetitions.checked_add(1).ok_or(
                    AbsoluteFullCaptureBuildError::ArithmeticOverflow("repetition count"),
                )?;
            account_node(&mut inspection.accounting, limits)?;
            let HirKind::Class(Class::Bytes(class)) = repetition.sub.kind() else {
                return Err(AbsoluteFullCaptureBuildError::Unsupported(
                    "star body must be a canonical byte class",
                ));
            };
            let [range] = class.ranges() else {
                return Err(AbsoluteFullCaptureBuildError::Unsupported(
                    "star class must contain exactly one complete byte range",
                ));
            };
            if range.start() != 0 || range.end() != u8::MAX {
                return Err(AbsoluteFullCaptureBuildError::Unsupported(
                    "star class must cover every byte",
                ));
            }
            inspection.accounting.classes = inspection.accounting.classes.checked_add(1).ok_or(
                AbsoluteFullCaptureBuildError::ArithmeticOverflow("class count"),
            )?;
            inspection.position = Position::BeforeEnd;
            Ok(())
        }
        HirKind::Repetition(_) => Err(AbsoluteFullCaptureBuildError::Unsupported(
            "exactly one repetition is admitted between the absolute assertions",
        )),
        HirKind::Literal(_) | HirKind::Class(_) | HirKind::Alternation(_) => {
            Err(AbsoluteFullCaptureBuildError::Unsupported(
                "the absolute path cannot consume anything outside its full-byte star",
            ))
        }
    }
}

fn account_node(
    accounting: &mut AbsoluteFullCaptureHirAccounting,
    limits: AbsoluteFullCaptureBuildLimits,
) -> Result<(), AbsoluteFullCaptureBuildError> {
    accounting.hir_nodes = accounting.hir_nodes.checked_add(1).ok_or(
        AbsoluteFullCaptureBuildError::ArithmeticOverflow("HIR node count"),
    )?;
    accounting.inspection_work = accounting.inspection_work.checked_add(1).ok_or(
        AbsoluteFullCaptureBuildError::ArithmeticOverflow("inspection work"),
    )?;
    enforce_build("HIR nodes", accounting.hir_nodes, limits.max_hir_nodes)?;
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
) -> Result<(), AbsoluteFullCaptureBuildError> {
    if needed > limit {
        return Err(AbsoluteFullCaptureBuildError::Resource {
            resource,
            needed,
            limit,
        });
    }
    Ok(())
}

fn enforce_run_limits(
    upper: AbsoluteFullCaptureRunUpperBounds,
    limits: AbsoluteFullCaptureRunLimits,
) -> Result<(), AbsoluteFullCaptureRunError> {
    for (resource, needed, limit) in [
        (
            AbsoluteFullCaptureRunResource::InputBytes,
            upper.input_bytes,
            limits.max_input_bytes,
        ),
        (
            AbsoluteFullCaptureRunResource::Matches,
            upper.matches,
            limits.max_matches,
        ),
        (
            AbsoluteFullCaptureRunResource::CaptureCount,
            upper.capture_count,
            limits.max_capture_count,
        ),
        (
            AbsoluteFullCaptureRunResource::Work,
            upper.work,
            limits.max_work,
        ),
        (
            AbsoluteFullCaptureRunResource::SequentialBytes,
            upper.sequential_bytes,
            limits.max_sequential_bytes,
        ),
        (
            AbsoluteFullCaptureRunResource::PeakBytes,
            upper.peak_bytes,
            limits.max_peak_bytes,
        ),
    ] {
        if needed > limit {
            return Err(AbsoluteFullCaptureRunError::Resource {
                resource,
                needed,
                limit,
            });
        }
    }
    Ok(())
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
    use super::*;
    use regex::bytes::RegexBuilder;

    fn exact_limits(
        plan: &AbsoluteFullCapturePlan,
        input_bytes: usize,
    ) -> AbsoluteFullCaptureRunLimits {
        let upper = plan.run_upper_bounds(input_bytes).expect("upper bounds");
        AbsoluteFullCaptureRunLimits {
            max_input_bytes: upper.input_bytes,
            max_matches: upper.matches,
            max_capture_count: upper.capture_count,
            max_work: upper.work,
            max_sequential_bytes: upper.sequential_bytes,
            max_peak_bytes: upper.peak_bytes,
        }
    }

    fn reference_capture_count(pattern: &str, haystack: &[u8]) -> usize {
        let regex = RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .expect("reference regex");
        regex
            .captures_iter(haystack)
            .map(|captures| captures.iter().flatten().count())
            .sum()
    }

    #[test]
    fn benchmark_shape_is_source_independent_and_exact() {
        let pattern = r"(?s)^((.*)()()($))";
        let plan = AbsoluteFullCaptureBuilder::new(pattern)
            .unicode(false)
            .build()
            .expect("absolute-full plan");
        for haystack in [
            b"".as_slice(),
            b"abc".as_slice(),
            b"a\nb\r\nc".as_slice(),
            &[0, 0xff, 0x80, b'\n'][..],
        ] {
            let result = plan
                .count_captures(haystack, exact_limits(&plan, haystack.len()))
                .expect("capture count");
            assert_eq!(
                result.capture_count,
                reference_capture_count(pattern, haystack)
            );
            assert_eq!(result.capture_count, 6);
            assert_eq!(result.actual.source_reads, 0);
            assert_eq!(result.actual.sequential_bytes, 0);
        }
    }

    #[test]
    fn mandatory_empty_and_nested_captures_are_admitted() {
        for pattern in [r"(?s)()^((.*))$()", r"(?s)(^(.*)$)", r"(?s)^((.*)($))"] {
            let plan = AbsoluteFullCaptureBuilder::new(pattern)
                .unicode(false)
                .build()
                .expect("absolute-full plan");
            let haystack = b"\xffbytes\n";
            let result = plan
                .count_captures(haystack, exact_limits(&plan, haystack.len()))
                .expect("capture count");
            assert_eq!(
                result.capture_count,
                reference_capture_count(pattern, haystack)
            );
        }
    }

    #[test]
    fn neighboring_shapes_fail_closed() {
        for pattern in [
            r"(?s)^((.*?))$",
            r"(?s)^((.+))$",
            r"(?s)^(([^\n]*))$",
            r"(?s)^((.*)x)$",
            r"(?s)((.*))$",
            r"(?s)^((.*))",
            r"(?s)^((.*)|(.*))$",
            r"(?s)^(((.)*))$",
            r"(?m)^((.*))$",
        ] {
            assert!(
                matches!(
                    AbsoluteFullCaptureBuilder::new(pattern)
                        .unicode(false)
                        .build(),
                    Err(AbsoluteFullCaptureBuildError::Unsupported(_))
                ),
                "unexpectedly admitted {pattern}"
            );
        }
        assert!(matches!(
            AbsoluteFullCaptureBuilder::new(r"(?s)^((.*))$")
                .unicode(true)
                .build(),
            Err(AbsoluteFullCaptureBuildError::Unsupported(_))
        ));
        assert!(matches!(
            AbsoluteFullCaptureBuilder::new(r"(?s)^((.*))$")
                .unicode(false)
                .case_insensitive(true)
                .build(),
            Err(AbsoluteFullCaptureBuildError::Unsupported(_))
        ));
    }

    #[test]
    fn exact_limits_fail_one_resource_at_a_time() {
        let plan = AbsoluteFullCaptureBuilder::new(r"(?s)^((.*)())$")
            .unicode(false)
            .build()
            .expect("absolute-full plan");
        let haystack = b"data";
        let exact = exact_limits(&plan, haystack.len());
        for limits in [
            AbsoluteFullCaptureRunLimits {
                max_input_bytes: exact.max_input_bytes - 1,
                ..exact
            },
            AbsoluteFullCaptureRunLimits {
                max_matches: 0,
                ..exact
            },
            AbsoluteFullCaptureRunLimits {
                max_capture_count: exact.max_capture_count - 1,
                ..exact
            },
            AbsoluteFullCaptureRunLimits {
                max_work: exact.max_work - 1,
                ..exact
            },
            AbsoluteFullCaptureRunLimits {
                max_peak_bytes: exact.max_peak_bytes - 1,
                ..exact
            },
        ] {
            assert!(matches!(
                plan.count_captures(haystack, limits),
                Err(AbsoluteFullCaptureRunError::Resource { .. })
            ));
        }
    }
}
