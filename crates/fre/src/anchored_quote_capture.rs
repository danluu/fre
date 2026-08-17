//! Direct exact-record visitor for structurally deterministic quoted lines.
//!
//! The admitted HIR is an absolute-start/end concatenation containing a
//! greedy ASCII prefix-class repetition, an ASCII delimiter class, one greedy
//! captured repetition of every Unicode scalar except LF, and the identical
//! delimiter class. The two delimiter classes are disjoint from the prefix
//! class. These facts make both group endpoints deterministic while retaining
//! Rust byte-regex Unicode validity semantics.

use core::{fmt, mem::size_of};

use fre_kernels::{AnchoredLineCaptureRunError, AnchoredLineCaptureRunLimits};
use fre_syntax::{CanonicalPattern, CompatibilityProfile, RustProfile};
use memchr::memchr_iter;
use regex_syntax::hir::{Class, Hir, HirKind, Look, Repetition};

use crate::{
    AnchoredLineCaptureBuildLimits, AnchoredLineCaptureRecordUpperBounds, AnchoredLineCaptureSpan,
};

pub const ANCHORED_QUOTE_CAPTURE_PLAN_ID: &str = "anchored-quote-capture.record-visit.plan.v1";
pub const ANCHORED_QUOTE_CAPTURE_RECORD_OPERATION_ID: &str =
    "anchored-quote-capture.grep-record-visit.v1";
pub const ANCHORED_QUOTE_CAPTURE_ALGORITHM_VERSION: u32 = 1;
pub const ANCHORED_QUOTE_CAPTURE_ACCOUNTING_VERSION: u32 = 1;

const DIGEST_OFFSET_A: u64 = 0xcbf2_9ce4_8422_2325;
const DIGEST_OFFSET_B: u64 = 0x8422_2325_cbf2_9ce4;
const DIGEST_PRIME_A: u64 = 0x0000_0100_0000_01b3;
const DIGEST_PRIME_B: u64 = 0x0000_0100_0000_01cf;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct AsciiMask([u64; 2]);

impl AsciiMask {
    fn insert_range(&mut self, start: u8, end: u8) {
        for byte in start..=end {
            let word = usize::from(byte) / 64;
            self.0[word] |= 1_u64 << (byte % 64);
        }
    }

    #[inline]
    fn contains(self, byte: u8) -> bool {
        byte < 128 && (self.0[usize::from(byte) / 64] & (1_u64 << (byte % 64))) != 0
    }

    const fn is_empty(self) -> bool {
        self.0[0] == 0 && self.0[1] == 0
    }

    const fn intersects(self, other: Self) -> bool {
        (self.0[0] & other.0[0]) != 0 || (self.0[1] & other.0[1]) != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchoredQuoteCaptureHirAccounting {
    pub hir_nodes: usize,
    pub class_ranges: usize,
    pub repetitions: usize,
    pub captures: usize,
    pub inspection_work: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchoredQuoteCapturePlanIdentity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub profile: RustProfile,
    pub source_digest: [u64; 2],
    pub algorithm_version: u32,
    pub accounting_version: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchoredQuoteCaptureBuildReport {
    pub identity: AnchoredQuoteCapturePlanIdentity,
    pub hir: AnchoredQuoteCaptureHirAccounting,
    pub minimum_match_bytes: usize,
    pub explicit_captures: usize,
    pub groups_per_match: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchoredQuoteCaptureRecordVisitReport {
    pub operation_id: &'static str,
    pub source_digest: [u64; 2],
    pub line_domains: usize,
    pub matches: usize,
    pub capture_count: usize,
    pub reducer_events: usize,
    pub input_loads: usize,
    pub prefix_probes: usize,
    pub utf8_bytes: usize,
    pub endpoint_writes: usize,
    pub work: usize,
    pub sequential_bytes: usize,
    pub allocations: usize,
    pub scratch_bytes: usize,
    pub output_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum AnchoredQuoteCaptureBuildError {
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

impl fmt::Display for AnchoredQuoteCaptureBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(error) => write!(formatter, "anchored quote-capture syntax: {error}"),
            Self::Unsupported(reason) => {
                write!(
                    formatter,
                    "unsupported anchored quote-capture shape: {reason}"
                )
            }
            Self::Resource {
                resource,
                needed,
                limit,
            } => write!(
                formatter,
                "anchored quote-capture {resource} needs {needed}, limit is {limit}"
            ),
            Self::ArithmeticOverflow(computation) => write!(
                formatter,
                "anchored quote-capture overflow while computing {computation}"
            ),
            Self::InternalInvariant(message) => {
                write!(formatter, "anchored quote-capture invariant: {message}")
            }
        }
    }
}

impl std::error::Error for AnchoredQuoteCaptureBuildError {
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

#[derive(Clone, Debug)]
pub struct AnchoredQuoteCaptureBuilder {
    pattern: String,
    profile: RustProfile,
    limits: AnchoredLineCaptureBuildLimits,
}

impl AnchoredQuoteCaptureBuilder {
    #[must_use]
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            profile: RustProfile::default(),
            limits: AnchoredLineCaptureBuildLimits::default(),
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
    pub const fn limits(mut self, limits: AnchoredLineCaptureBuildLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn build(self) -> Result<AnchoredQuoteCapturePlan, AnchoredQuoteCaptureBuildError> {
        let profile = self.profile;
        let parsed = fre_syntax::parse(
            fre_syntax::ParseRequest::rust(
                self.pattern,
                CompatibilityProfile::RustBytes(profile.clone()),
            )
            .with_admission(self.limits.admission)
            .with_safety_envelope(self.limits.syntax_safety),
        )
        .map_err(AnchoredQuoteCaptureBuildError::Syntax)?;
        let source_digest = digest_source(parsed.key.pattern.as_bytes());
        let summary = parsed.summary;
        let CanonicalPattern::Rust(rust) = parsed.pattern else {
            return Err(AnchoredQuoteCaptureBuildError::InternalInvariant(
                "Rust byte request produced a non-Rust HIR",
            ));
        };
        let (prefix, delimiter, hir) = inspect(&rust.hir, self.limits)?;
        if summary.captures != 1 || hir.captures != 1 {
            return Err(AnchoredQuoteCaptureBuildError::Unsupported(
                "shape requires exactly one explicit capture",
            ));
        }
        let persistent_bytes = size_of::<AnchoredQuoteCapturePlan>();
        enforce_resource(
            "persistent bytes",
            persistent_bytes,
            self.limits.max_persistent_bytes,
        )?;
        enforce_resource("peak bytes", persistent_bytes, self.limits.max_peak_bytes)?;
        Ok(AnchoredQuoteCapturePlan {
            prefix,
            delimiter,
            report: AnchoredQuoteCaptureBuildReport {
                identity: AnchoredQuoteCapturePlanIdentity {
                    plan_id: ANCHORED_QUOTE_CAPTURE_PLAN_ID,
                    operation_id: ANCHORED_QUOTE_CAPTURE_RECORD_OPERATION_ID,
                    profile,
                    source_digest,
                    algorithm_version: ANCHORED_QUOTE_CAPTURE_ALGORITHM_VERSION,
                    accounting_version: ANCHORED_QUOTE_CAPTURE_ACCOUNTING_VERSION,
                },
                hir,
                minimum_match_bytes: 2,
                explicit_captures: 1,
                groups_per_match: 2,
                persistent_bytes,
                peak_bytes: persistent_bytes,
            },
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchoredQuoteCapturePlan {
    prefix: AsciiMask,
    delimiter: AsciiMask,
    report: AnchoredQuoteCaptureBuildReport,
}

impl AnchoredQuoteCapturePlan {
    #[must_use]
    pub const fn build_report(&self) -> &AnchoredQuoteCaptureBuildReport {
        &self.report
    }

    pub fn grep_capture_record_upper_bounds(
        &self,
        input_bytes: usize,
    ) -> Result<AnchoredLineCaptureRecordUpperBounds, AnchoredLineCaptureRunError> {
        let line_domains = input_bytes;
        let matches = line_domains;
        let capture_count =
            matches
                .checked_mul(2)
                .ok_or(AnchoredLineCaptureRunError::ArithmeticOverflow {
                    computation: "quote record capture-count bound",
                })?;
        let reducer_events = line_domains.checked_add(capture_count).ok_or(
            AnchoredLineCaptureRunError::ArithmeticOverflow {
                computation: "quote record reducer-event bound",
            },
        )?;
        let sequential_bytes =
            input_bytes
                .checked_mul(5)
                .ok_or(AnchoredLineCaptureRunError::ArithmeticOverflow {
                    computation: "quote record sequential-byte bound",
                })?;
        let work = input_bytes
            .checked_mul(14)
            .and_then(|value| value.checked_add(1))
            .ok_or(AnchoredLineCaptureRunError::ArithmeticOverflow {
                computation: "quote record work bound",
            })?;
        Ok(AnchoredLineCaptureRecordUpperBounds {
            input_bytes,
            line_domains,
            matches,
            capture_count,
            reducer_events,
            work,
            sequential_bytes,
            allocations: 0,
            scratch_bytes: 0,
            output_bytes: 0,
            persistent_bytes: self.report.persistent_bytes,
            peak_bytes: self.report.peak_bytes,
        })
    }

    pub fn visit_grep_capture_records(
        &self,
        haystack: &[u8],
        limits: AnchoredLineCaptureRunLimits,
        mut visitor: impl FnMut(usize, &[AnchoredLineCaptureSpan]),
    ) -> Result<AnchoredQuoteCaptureRecordVisitReport, AnchoredLineCaptureRunError> {
        let upper = self.grep_capture_record_upper_bounds(haystack.len())?;
        for (resource, needed, limit) in [
            ("input bytes", upper.input_bytes, limits.max_input_bytes),
            ("lines", upper.line_domains, limits.max_lines),
            ("matches", upper.matches, limits.max_matches),
            (
                "capture count",
                upper.capture_count,
                limits.max_capture_count,
            ),
            (
                "reducer events",
                upper.reducer_events,
                limits.max_reducer_events,
            ),
            ("work", upper.work, limits.max_work),
            (
                "sequential bytes",
                upper.sequential_bytes,
                limits.max_sequential_bytes,
            ),
            ("peak bytes", upper.peak_bytes, limits.max_peak_bytes),
        ] {
            if needed > limit {
                return Err(AnchoredLineCaptureRunError::Resource {
                    resource,
                    needed,
                    limit,
                });
            }
        }

        let mut actual = AnchoredQuoteCaptureRecordVisitReport {
            operation_id: ANCHORED_QUOTE_CAPTURE_RECORD_OPERATION_ID,
            source_digest: self.report.identity.source_digest,
            line_domains: 0,
            matches: 0,
            capture_count: 0,
            reducer_events: 0,
            input_loads: haystack.len(),
            prefix_probes: 0,
            utf8_bytes: 0,
            endpoint_writes: 0,
            work: 0,
            sequential_bytes: 0,
            allocations: 0,
            scratch_bytes: 0,
            output_bytes: 0,
            persistent_bytes: self.report.persistent_bytes,
            peak_bytes: self.report.peak_bytes,
        };
        let mut line_start = 0_usize;
        for line_feed in memchr_iter(b'\n', haystack) {
            let mut line_end = line_feed;
            if line_end > line_start {
                actual.input_loads = checked_add(actual.input_loads, 1, "quote CR probe")?;
                if haystack[line_end - 1] == b'\r' {
                    line_end -= 1;
                }
            }
            self.visit_one_line(&haystack[line_start..line_end], &mut actual, &mut visitor)?;
            line_start = line_feed.checked_add(1).ok_or(
                AnchoredLineCaptureRunError::ArithmeticOverflow {
                    computation: "quote line cursor",
                },
            )?;
        }
        if line_start < haystack.len() {
            self.visit_one_line(&haystack[line_start..], &mut actual, &mut visitor)?;
        }
        actual.sequential_bytes = actual.input_loads;
        actual.work = 1_usize
            .checked_add(actual.input_loads)
            .and_then(|value| value.checked_add(actual.line_domains))
            .and_then(|value| value.checked_add(actual.reducer_events))
            .and_then(|value| value.checked_add(actual.endpoint_writes))
            .ok_or(AnchoredLineCaptureRunError::ArithmeticOverflow {
                computation: "quote record actual work",
            })?;
        for (resource, observed, bound) in [
            ("lines", actual.line_domains, upper.line_domains),
            ("matches", actual.matches, upper.matches),
            ("capture count", actual.capture_count, upper.capture_count),
            (
                "reducer events",
                actual.reducer_events,
                upper.reducer_events,
            ),
            ("work", actual.work, upper.work),
            (
                "sequential bytes",
                actual.sequential_bytes,
                upper.sequential_bytes,
            ),
        ] {
            if observed > bound {
                return Err(AnchoredLineCaptureRunError::AccountingInvariant {
                    resource,
                    actual: observed,
                    bound,
                });
            }
        }
        Ok(actual)
    }

    fn visit_one_line(
        &self,
        line: &[u8],
        actual: &mut AnchoredQuoteCaptureRecordVisitReport,
        visitor: &mut impl FnMut(usize, &[AnchoredLineCaptureSpan]),
    ) -> Result<(), AnchoredLineCaptureRunError> {
        actual.line_domains = checked_add(actual.line_domains, 1, "quote line domains")?;
        actual.reducer_events = checked_add(actual.reducer_events, 1, "quote line events")?;
        if line.len() < self.report.minimum_match_bytes {
            return Ok(());
        }
        actual.input_loads = checked_add(actual.input_loads, 1, "quote closing probe")?;
        if !line
            .last()
            .copied()
            .is_some_and(|byte| self.delimiter.contains(byte))
        {
            return Ok(());
        }
        let mut opening = 0_usize;
        while opening < line.len() {
            actual.input_loads = checked_add(actual.input_loads, 1, "quote prefix probe")?;
            actual.prefix_probes = checked_add(actual.prefix_probes, 1, "quote prefix probes")?;
            if self.prefix.contains(line[opening]) {
                opening += 1;
            } else {
                break;
            }
        }
        if opening >= line.len() - 1 || !self.delimiter.contains(line[opening]) {
            return Ok(());
        }
        actual.input_loads = checked_add(actual.input_loads, line.len(), "quote UTF-8 bytes")?;
        actual.utf8_bytes = checked_add(actual.utf8_bytes, line.len(), "quote UTF-8 bytes")?;
        if core::str::from_utf8(line).is_err() {
            return Ok(());
        }
        let groups = [
            AnchoredLineCaptureSpan {
                start: 0,
                end: line.len(),
            },
            AnchoredLineCaptureSpan {
                start: opening + 1,
                end: line.len() - 1,
            },
        ];
        actual.matches = checked_add(actual.matches, 1, "quote matches")?;
        actual.capture_count = checked_add(actual.capture_count, 2, "quote capture count")?;
        actual.reducer_events = checked_add(actual.reducer_events, 2, "quote capture events")?;
        actual.endpoint_writes = checked_add(actual.endpoint_writes, 4, "quote endpoints")?;
        visitor(line.len(), &groups);
        Ok(())
    }
}

fn inspect(
    hir: &Hir,
    limits: AnchoredLineCaptureBuildLimits,
) -> Result<(AsciiMask, AsciiMask, AnchoredQuoteCaptureHirAccounting), AnchoredQuoteCaptureBuildError>
{
    let mut accounting = AnchoredQuoteCaptureHirAccounting {
        hir_nodes: 0,
        class_ranges: 0,
        repetitions: 0,
        captures: 0,
        inspection_work: 0,
    };
    node(&mut accounting, limits)?;
    let HirKind::Concat(children) = hir.kind() else {
        return Err(AnchoredQuoteCaptureBuildError::Unsupported(
            "root must be a concatenation",
        ));
    };
    if children.len() != 6 {
        return Err(AnchoredQuoteCaptureBuildError::Unsupported(
            "root must have start, prefix, delimiter, capture, delimiter, and end",
        ));
    }
    node(&mut accounting, limits)?;
    if !matches!(children[0].kind(), HirKind::Look(Look::Start)) {
        return Err(AnchoredQuoteCaptureBuildError::Unsupported(
            "root must begin with absolute Start",
        ));
    }
    let prefix = greedy_ascii_class_repetition(&children[1], &mut accounting, limits)?;
    let delimiter = ascii_class(&children[2], &mut accounting, limits)?;
    node(&mut accounting, limits)?;
    let HirKind::Capture(capture) = children[3].kind() else {
        return Err(AnchoredQuoteCaptureBuildError::Unsupported(
            "quoted body must be one direct capture",
        ));
    };
    accounting.captures = checked_build_add(accounting.captures, 1, "capture count")?;
    charge(&mut accounting, 1, limits)?;
    enforce_resource("captures", accounting.captures, limits.max_captures)?;
    if capture.index != 1 {
        return Err(AnchoredQuoteCaptureBuildError::Unsupported(
            "quoted body capture must be numeric group 1",
        ));
    }
    any_scalar_except_lf_repetition(capture.sub.as_ref(), &mut accounting, limits)?;
    let closing = ascii_class(&children[4], &mut accounting, limits)?;
    node(&mut accounting, limits)?;
    if !matches!(children[5].kind(), HirKind::Look(Look::End)) {
        return Err(AnchoredQuoteCaptureBuildError::Unsupported(
            "root must end with absolute End",
        ));
    }
    if delimiter.is_empty() || closing != delimiter {
        return Err(AnchoredQuoteCaptureBuildError::Unsupported(
            "opening and closing delimiter classes must be identical and nonempty",
        ));
    }
    if prefix.intersects(delimiter) {
        return Err(AnchoredQuoteCaptureBuildError::Unsupported(
            "prefix and delimiter classes must be disjoint",
        ));
    }
    Ok((prefix, delimiter, accounting))
}

fn greedy_ascii_class_repetition(
    hir: &Hir,
    accounting: &mut AnchoredQuoteCaptureHirAccounting,
    limits: AnchoredLineCaptureBuildLimits,
) -> Result<AsciiMask, AnchoredQuoteCaptureBuildError> {
    node(accounting, limits)?;
    let HirKind::Repetition(repetition) = hir.kind() else {
        return Err(AnchoredQuoteCaptureBuildError::Unsupported(
            "prefix must be a repetition",
        ));
    };
    account_repetition(repetition, accounting, limits)?;
    if repetition.min != 0 || repetition.max.is_some() || !repetition.greedy {
        return Err(AnchoredQuoteCaptureBuildError::Unsupported(
            "prefix repetition must be greedy star",
        ));
    }
    ascii_class(repetition.sub.as_ref(), accounting, limits)
}

fn any_scalar_except_lf_repetition(
    hir: &Hir,
    accounting: &mut AnchoredQuoteCaptureHirAccounting,
    limits: AnchoredLineCaptureBuildLimits,
) -> Result<(), AnchoredQuoteCaptureBuildError> {
    node(accounting, limits)?;
    let HirKind::Repetition(repetition) = hir.kind() else {
        return Err(AnchoredQuoteCaptureBuildError::Unsupported(
            "captured body must be a repetition",
        ));
    };
    account_repetition(repetition, accounting, limits)?;
    if repetition.min != 0 || repetition.max.is_some() || !repetition.greedy {
        return Err(AnchoredQuoteCaptureBuildError::Unsupported(
            "captured body repetition must be greedy star",
        ));
    }
    node(accounting, limits)?;
    let HirKind::Class(Class::Unicode(class)) = repetition.sub.kind() else {
        return Err(AnchoredQuoteCaptureBuildError::Unsupported(
            "captured body must be a Unicode scalar class",
        ));
    };
    let ranges = class.ranges();
    account_ranges(accounting, ranges.len(), limits)?;
    if ranges.len() != 2
        || ranges[0].start() != '\0'
        || ranges[0].end() != '\t'
        || ranges[1].start() != '\u{b}'
        || ranges[1].end() != '\u{10ffff}'
    {
        return Err(AnchoredQuoteCaptureBuildError::Unsupported(
            "captured body must accept every Unicode scalar except LF",
        ));
    }
    Ok(())
}

fn ascii_class(
    hir: &Hir,
    accounting: &mut AnchoredQuoteCaptureHirAccounting,
    limits: AnchoredLineCaptureBuildLimits,
) -> Result<AsciiMask, AnchoredQuoteCaptureBuildError> {
    node(accounting, limits)?;
    let HirKind::Class(Class::Unicode(class)) = hir.kind() else {
        return Err(AnchoredQuoteCaptureBuildError::Unsupported(
            "boundary class must be a Unicode class",
        ));
    };
    account_ranges(accounting, class.ranges().len(), limits)?;
    let mut mask = AsciiMask::default();
    for range in class.ranges() {
        if u32::from(range.end()) > 0x7f {
            return Err(AnchoredQuoteCaptureBuildError::Unsupported(
                "boundary classes must contain only ASCII scalars",
            ));
        }
        let start = u8::try_from(u32::from(range.start())).map_err(|_| {
            AnchoredQuoteCaptureBuildError::InternalInvariant(
                "ASCII class start did not fit one byte",
            )
        })?;
        let end = u8::try_from(u32::from(range.end())).map_err(|_| {
            AnchoredQuoteCaptureBuildError::InternalInvariant(
                "ASCII class end did not fit one byte",
            )
        })?;
        mask.insert_range(start, end);
    }
    if mask.is_empty() || mask.contains(b'\n') {
        return Err(AnchoredQuoteCaptureBuildError::Unsupported(
            "boundary classes must be nonempty and exclude LF",
        ));
    }
    Ok(mask)
}

fn account_repetition(
    _repetition: &Repetition,
    accounting: &mut AnchoredQuoteCaptureHirAccounting,
    limits: AnchoredLineCaptureBuildLimits,
) -> Result<(), AnchoredQuoteCaptureBuildError> {
    accounting.repetitions = checked_build_add(accounting.repetitions, 1, "repetition count")?;
    enforce_resource(
        "repetitions",
        accounting.repetitions,
        limits.max_repetitions,
    )?;
    charge(accounting, 2, limits)
}

fn account_ranges(
    accounting: &mut AnchoredQuoteCaptureHirAccounting,
    count: usize,
    limits: AnchoredLineCaptureBuildLimits,
) -> Result<(), AnchoredQuoteCaptureBuildError> {
    accounting.class_ranges = checked_build_add(accounting.class_ranges, count, "class ranges")?;
    enforce_resource(
        "class ranges",
        accounting.class_ranges,
        limits.max_class_ranges,
    )?;
    charge(accounting, count, limits)
}

fn node(
    accounting: &mut AnchoredQuoteCaptureHirAccounting,
    limits: AnchoredLineCaptureBuildLimits,
) -> Result<(), AnchoredQuoteCaptureBuildError> {
    accounting.hir_nodes = checked_build_add(accounting.hir_nodes, 1, "HIR nodes")?;
    enforce_resource("HIR nodes", accounting.hir_nodes, limits.max_hir_nodes)?;
    charge(accounting, 1, limits)
}

fn charge(
    accounting: &mut AnchoredQuoteCaptureHirAccounting,
    amount: usize,
    limits: AnchoredLineCaptureBuildLimits,
) -> Result<(), AnchoredQuoteCaptureBuildError> {
    accounting.inspection_work =
        checked_build_add(accounting.inspection_work, amount, "inspection work")?;
    enforce_resource(
        "inspection work",
        accounting.inspection_work,
        limits.max_inspection_work,
    )
}

fn enforce_resource(
    resource: &'static str,
    needed: usize,
    limit: usize,
) -> Result<(), AnchoredQuoteCaptureBuildError> {
    if needed > limit {
        return Err(AnchoredQuoteCaptureBuildError::Resource {
            resource,
            needed,
            limit,
        });
    }
    Ok(())
}

fn checked_build_add(
    value: usize,
    amount: usize,
    computation: &'static str,
) -> Result<usize, AnchoredQuoteCaptureBuildError> {
    value
        .checked_add(amount)
        .ok_or(AnchoredQuoteCaptureBuildError::ArithmeticOverflow(
            computation,
        ))
}

fn checked_add(
    value: usize,
    amount: usize,
    computation: &'static str,
) -> Result<usize, AnchoredLineCaptureRunError> {
    value
        .checked_add(amount)
        .ok_or(AnchoredLineCaptureRunError::ArithmeticOverflow { computation })
}

fn digest_source(source: &[u8]) -> [u64; 2] {
    let mut words = [DIGEST_OFFSET_A, DIGEST_OFFSET_B];
    for byte in core::iter::once(0x53_u8)
        .chain(source.len().to_le_bytes())
        .chain(source.iter().copied())
    {
        words[0] = (words[0] ^ u64::from(byte)).wrapping_mul(DIGEST_PRIME_A);
        words[1] = (words[1] ^ u64::from(byte)).wrapping_mul(DIGEST_PRIME_B);
    }
    words
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::bytes::RegexBuilder;

    const TARGET: &str = r#"^(?i)[urb]*['\"](?P<raw>.*)['\"]$"#;

    fn build(pattern: &str) -> AnchoredQuoteCapturePlan {
        AnchoredQuoteCaptureBuilder::new(pattern)
            .profile(RustProfile::rebar_1_12_4())
            .unicode(true)
            .build()
            .expect("structural quote plan")
    }

    fn run_limits(plan: &AnchoredQuoteCapturePlan, len: usize) -> AnchoredLineCaptureRunLimits {
        let upper = plan.grep_capture_record_upper_bounds(len).unwrap();
        AnchoredLineCaptureRunLimits {
            max_input_bytes: upper.input_bytes,
            max_lines: upper.line_domains,
            max_matches: upper.matches,
            max_capture_count: upper.capture_count,
            max_reducer_events: upper.reducer_events,
            max_work: upper.work,
            max_sequential_bytes: upper.sequential_bytes,
            max_peak_bytes: upper.peak_bytes,
        }
    }

    #[test]
    fn exact_records_cover_crlf_empty_mixed_greedy_and_malformed_lines() {
        let plan = build(TARGET);
        let haystack = b"''\n'\nr\"alpha'\r\nU'\xce\xb2\"\nb\"a'b\"\n'\xff'\nnot quoted\n";
        let mut records = Vec::new();
        let report = plan
            .visit_grep_capture_records(
                haystack,
                run_limits(&plan, haystack.len()),
                |len, spans| {
                    records.push((len, spans.to_vec()));
                },
            )
            .unwrap();
        assert_eq!(report.line_domains, 7);
        assert_eq!(report.matches, 4);
        assert_eq!(report.capture_count, 8);
        assert_eq!(report.reducer_events, 15);
        assert_eq!(records.len(), report.matches);
        assert_eq!(
            records,
            vec![
                (
                    2,
                    vec![
                        AnchoredLineCaptureSpan { start: 0, end: 2 },
                        AnchoredLineCaptureSpan { start: 1, end: 1 },
                    ],
                ),
                (
                    8,
                    vec![
                        AnchoredLineCaptureSpan { start: 0, end: 8 },
                        AnchoredLineCaptureSpan { start: 2, end: 7 },
                    ],
                ),
                (
                    5,
                    vec![
                        AnchoredLineCaptureSpan { start: 0, end: 5 },
                        AnchoredLineCaptureSpan { start: 2, end: 4 },
                    ],
                ),
                (
                    6,
                    vec![
                        AnchoredLineCaptureSpan { start: 0, end: 6 },
                        AnchoredLineCaptureSpan { start: 2, end: 5 },
                    ],
                ),
            ]
        );
    }

    #[test]
    fn endpoints_match_rust_regex_for_valid_and_malformed_domains() {
        let plan = build(TARGET);
        let reference = RegexBuilder::new(TARGET).unicode(true).build().unwrap();
        let lines: &[&[u8]] = &[
            b"",
            b"'",
            b"''",
            b"r\"alpha'",
            b"U'\xce\xb2\"",
            b"b\"a'b\"",
            b"rrr\"\"",
            b"x\"no\"",
            b"'\xff'",
            b"\xff''",
        ];
        for &line in lines {
            let mut actual = Vec::new();
            let _ = plan
                .visit_grep_capture_records(line, run_limits(&plan, line.len()), |_, spans| {
                    actual.push(
                        spans
                            .iter()
                            .map(|span| (span.start, span.end))
                            .collect::<Vec<_>>(),
                    );
                })
                .unwrap();
            let expected = reference.captures(line).map(|captures| {
                (0..captures.len())
                    .map(|index| {
                        let matched = captures.get(index).unwrap();
                        (matched.start(), matched.end())
                    })
                    .collect::<Vec<_>>()
            });
            assert_eq!(actual.first(), expected.as_ref(), "line {line:?}");
            assert_eq!(actual.len(), usize::from(expected.is_some()));
        }
    }

    #[test]
    fn construction_is_structural_not_source_or_capture_name_dispatch() {
        let plan = build(r#"^[xy]*[!?](?P<any_name>.*)[!?]$"#);
        let line = b"xy!body?";
        let mut records = Vec::new();
        plan.visit_grep_capture_records(line, run_limits(&plan, line.len()), |_, spans| {
            records.push(spans.to_vec());
        })
        .unwrap();
        assert_eq!(
            records,
            vec![vec![
                AnchoredLineCaptureSpan { start: 0, end: 8 },
                AnchoredLineCaptureSpan { start: 3, end: 7 },
            ]]
        );
    }

    #[test]
    fn construction_refuses_semantically_distinct_shapes() {
        for pattern in [
            r#"(?i)[urb]*['\"](?P<raw>.*)['\"]$"#,
            r#"^(?i)[urb]*['\"](?P<raw>.*)['\"]"#,
            r#"^(?i)[urb]*['\"](?P<raw>.*?)['\"]$"#,
            r#"^(?i)[urb]*['\"](?P<raw>.+)['\"]$"#,
            r#"^(?i)[urb]*['\"](?P<raw>.*)[!]$"#,
            r#"^[x!]*[!?](?P<raw>.*)[!?]$"#,
            r#"^(?i)[urb]*['\"](?P<raw>[^x]*)['\"]$"#,
            r#"^(?i)[urb]*['\"](?P<a>.*)(?P<b>.*)['\"]$"#,
        ] {
            assert!(
                matches!(
                    AnchoredQuoteCaptureBuilder::new(pattern)
                        .profile(RustProfile::rebar_1_12_4())
                        .unicode(true)
                        .build(),
                    Err(AnchoredQuoteCaptureBuildError::Unsupported(_))
                ),
                "pattern {pattern:?}"
            );
        }
    }

    #[test]
    fn operation_limits_refuse_before_source_access_or_callbacks() {
        let plan = build(TARGET);
        let haystack = b"'matched'";
        let mut limits = run_limits(&plan, haystack.len());
        limits.max_work -= 1;
        let mut callbacks = 0;
        assert!(matches!(
            plan.visit_grep_capture_records(haystack, limits, |_, _| callbacks += 1),
            Err(AnchoredLineCaptureRunError::Resource {
                resource: "work",
                ..
            })
        ));
        assert_eq!(callbacks, 0);
    }
}
