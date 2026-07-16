//! Capture-preserving persistent-history facade for the certified Rust-byte subset.

use core::fmt;
use std::sync::Arc;

use fre_aggregate::{
    CompileAccounting as SelectorCompileAccounting, CompileLimits as SelectorCompileLimits,
    CompiledRegex as SelectorRegex, Error as SelectorError,
    ExecutionAccounting as SelectorExecutionAccounting,
    OperationCertificate as SelectorOperationCertificate,
    OperationLimits as SelectorOperationLimits, PlanId as SelectorPlanId,
    RustByteProfile as SelectorProfile, Strategy as SelectorStrategy,
};
use fre_capture_lab::{
    AggregateLimits, AggregateOutcome, Ast, BuildError as EngineBuildError,
    BuildLimits as EngineBuildLimits, BuildReport as EngineBuildReport, CaptureCountOutcome,
    CaptureProfile, CaptureRecord, Greed, HistoryRegex, Program, ResourceKind as EngineResource,
    SearchError as EngineSearchError, Span as EngineSpan, Window,
};
use fre_syntax::{
    AdmissionPolicy, AdmissionStatus, CacheKey, CanonicalPattern, CompatibilityProfile, ParseError,
    ParseSummary, RustProfile, SafetyEnvelope,
};
use regex_syntax::{
    hir::{Class, ClassUnicode, Hir, HirKind, Look},
    utf8::Utf8Sequences,
};

/// Capture-aware operation included in construction and execution identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureOperation {
    /// Sum participating groups over a non-overlapping sequence of non-empty matches.
    CountParticipatingNonempty,
}

/// Production plan selected for the admitted capture operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapturePlanKind {
    /// One operation-wide span selector plus exact-span persistent-history replay.
    LinearSelectorPersistentHistory,
}

/// HIR forms deliberately outside the certified capture compiler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureUnsupported {
    /// A look assertion has not been implemented by the tagged program.
    Look(Look),
}

/// Checked HIR-to-capture-AST accounting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CaptureHirAccounting {
    /// HIR nodes converted.
    pub hir_nodes: usize,
    /// Maximum conversion recursion depth.
    pub hir_depth: usize,
    /// Literal bytes copied into byte atoms.
    pub literal_bytes: usize,
    /// Byte-class ranges copied.
    pub class_ranges: usize,
    /// Metered conversion work.
    pub work: usize,
}

/// Construction limits whose exact values participate in cache identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureBuildLimits {
    /// Syntax admission policy.
    pub admission: AdmissionPolicy,
    /// Hard syntax safety envelope.
    pub syntax_safety: SafetyEnvelope,
    /// Maximum HIR-to-AST conversion work.
    pub max_hir_work: usize,
    /// Maximum HIR conversion depth.
    pub max_hir_depth: usize,
    /// Persistent-history compiler limits.
    pub engine: EngineBuildLimits,
    /// Capture-erased operation-wide span-selector compiler limits.
    pub selector: SelectorCompileLimits,
}

impl Default for CaptureBuildLimits {
    fn default() -> Self {
        let engine = EngineBuildLimits {
            max_ast_nodes: 65_536,
            ..EngineBuildLimits::default()
        };
        Self {
            admission: AdmissionPolicy::default(),
            syntax_safety: SafetyEnvelope::default(),
            max_hir_work: 1_000_000,
            max_hir_depth: 250,
            engine,
            selector: SelectorCompileLimits::default(),
        }
    }
}

/// Execution limits included verbatim in the execution cache identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureRunLimits {
    /// Limits for exact-span tagged replay and capture reduction.
    pub aggregate: AggregateLimits,
    /// Limits for the complete operation-wide span selection.
    pub selector: SelectorOperationLimits,
    /// Maximum logical dynamic bytes across selector execution or retained
    /// selector output plus one exact-span replay.
    pub max_combined_peak_bytes: usize,
}

impl Default for CaptureRunLimits {
    fn default() -> Self {
        Self {
            aggregate: AggregateLimits::default(),
            selector: SelectorOperationLimits::default(),
            max_combined_peak_bytes: 512 * 1_048_576,
        }
    }
}

/// Immutable plan identity. Source syntax remains distinct even when HIRs agree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturePlanIdentity {
    /// Complete syntax/profile/admission key.
    pub syntax: Arc<CacheKey>,
    /// Capture-aware operation.
    pub operation: CaptureOperation,
    /// Selected engine family.
    pub plan: CapturePlanKind,
    /// Versioned capture semantic profile.
    pub capture_profile: CaptureProfile,
    /// Exact capture-erased selector program identity.
    pub selector_plan_id: SelectorPlanId,
}

/// Construction report for one immutable capture plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureBuildReport {
    /// What constructor admission has established.
    pub admission: AdmissionStatus,
    /// Bounded syntax facts.
    pub syntax: ParseSummary,
    /// Checked HIR conversion accounting.
    pub hir: CaptureHirAccounting,
    /// Tagged-program construction and allocation accounting.
    pub engine: EngineBuildReport,
    /// Capture-erased selector construction accounting.
    pub selector: SelectorCompileAccounting,
    /// Complete immutable plan identity.
    pub plan_identity: CapturePlanIdentity,
}

/// Execution/cache identity for a capture reducer invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureCacheIdentity {
    /// Immutable plan identity.
    pub plan: CapturePlanIdentity,
    /// Construction limits used to publish the plan.
    pub build_limits: CaptureBuildLimits,
    /// Execution limits used for this invocation.
    pub run_limits: CaptureRunLimits,
}

/// Typed capture construction failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum CaptureBuildError {
    /// Syntax/profile/admission failure.
    Syntax(fre_syntax::ParseError),
    /// Syntax is valid but outside the certified capture subset.
    Unsupported(CaptureUnsupported),
    /// HIR conversion work or depth exceeded its explicit limit.
    HirResource {
        /// Resource dimension.
        resource: &'static str,
        /// Required amount.
        required: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// A checked HIR conversion allocation failed.
    Allocation {
        /// Structure being allocated.
        structure: &'static str,
        /// Requested items.
        items: usize,
    },
    /// Tagged-program construction refused or faulted.
    Engine(EngineBuildError),
    /// Operation-wide capture-erased span selector refused or faulted.
    Selector(SelectorError),
    /// Facade invariant failure.
    InternalInvariant(&'static str),
}

impl fmt::Display for CaptureBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(error) => write!(formatter, "capture syntax failed: {error}"),
            Self::Unsupported(feature) => {
                write!(formatter, "unsupported capture HIR feature: {feature:?}")
            }
            Self::HirResource {
                resource,
                required,
                limit,
            } => write!(
                formatter,
                "capture HIR {resource} needs {required}, exceeding {limit}"
            ),
            Self::Allocation { structure, items } => {
                write!(
                    formatter,
                    "capture HIR failed to reserve {items} {structure} items"
                )
            }
            Self::Engine(error) => write!(formatter, "capture engine build failed: {error}"),
            Self::Selector(error) => write!(formatter, "capture selector build failed: {error}"),
            Self::InternalInvariant(detail) => {
                write!(formatter, "capture facade invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for CaptureBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Syntax(error) => Some(error),
            Self::Engine(error) => Some(error),
            Self::Selector(error) => Some(error),
            _ => None,
        }
    }
}

/// Typed source of a capture operation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaptureExecutionSource {
    /// Complete capture-erased span selection failed before tagged replay.
    Selector(SelectorError),
    /// Exact-span persistent-history replay or reduction failed.
    History(EngineSearchError),
    /// Selector and tagged replay disagreed despite sharing one canonical HIR.
    InternalInvariant(&'static str),
}

impl fmt::Display for CaptureExecutionSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Selector(error) => error.fmt(formatter),
            Self::History(error) => error.fmt(formatter),
            Self::InternalInvariant(detail) => {
                write!(formatter, "capture operation invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for CaptureExecutionSource {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Selector(error) => Some(error),
            Self::History(error) => Some(error),
            Self::InternalInvariant(_) => None,
        }
    }
}

/// Capture execution failure retaining the exact plan and limit identity.
#[derive(Debug)]
pub struct CaptureExecutionError {
    /// Complete invocation identity.
    pub identity: Box<CaptureCacheIdentity>,
    /// Typed selector/history/reducer failure.
    pub source: CaptureExecutionSource,
}

impl fmt::Display for CaptureExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "capture execution failed: {}", self.source)
    }
}

impl std::error::Error for CaptureExecutionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Successful reducer value and exact allocation/work counters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureExecutionReport {
    /// Complete invocation identity.
    pub identity: CaptureCacheIdentity,
    /// Persistent-history and reducer accounting.
    pub accounting: CaptureCountOutcome,
    /// Whole-operation selector certificate.
    pub selector_certificate: SelectorOperationCertificate,
    /// Exact selector work and storage accounting.
    pub selector_accounting: SelectorExecutionAccounting,
    /// Conservative logical dynamic peak across selection and exact replay.
    pub combined_peak_bytes: usize,
}

/// Plan selected for bounded materialized capture iteration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureIterationPlanKind {
    /// Independently bounded leftmost searches with persistent tagged history
    /// and Rust byte-regex empty-match progression.
    RestartedPersistentHistory,
}

/// Production identity for the bounded persistent-history capture iterator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureIterationIdentity {
    /// Complete syntax/profile/admission key.
    pub syntax: Arc<CacheKey>,
    /// Versioned capture semantic profile.
    pub capture_profile: CaptureProfile,
    /// Exact materializing iterator formulation.
    pub plan: CaptureIterationPlanKind,
    /// Construction limits used to publish the immutable tagged program.
    pub build_limits: CaptureBuildLimits,
    /// Aggregate limits used for this repeated-search invocation.
    pub run_limits: AggregateLimits,
}

/// Successful complete capture sequence and bounded execution accounting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureIterationReport {
    /// Complete operation identity.
    pub identity: CaptureIterationIdentity,
    /// Every match, with one stable numeric/name/span entry for every group.
    /// Unmatched groups remain explicit `None` entries and empty participating
    /// groups retain their zero-width spans.
    pub captures: Vec<CaptureRecord>,
    /// Number of independently bounded searches, including the final miss
    /// unless iteration ended at a terminal empty match.
    pub searches: usize,
    /// Total Thompson state visits.
    pub total_state_visits: usize,
    /// Total persistent-history nodes.
    pub total_history_nodes: usize,
}

/// Checked capture-iteration failure retaining exact source and limit identity.
#[derive(Debug)]
pub struct CaptureIterationError {
    /// Complete attempted operation identity.
    pub identity: Box<CaptureIterationIdentity>,
    /// Persistent-history search or aggregate resource failure.
    pub source: EngineSearchError,
}

/// Construction evidence for the exact-HIR Rust text capture slice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortableTextCaptureBuildReport {
    /// Public Rust text profile proved before capture construction.
    pub profile: CompatibilityProfile,
    /// Bounded public `RustText` parse.
    pub text_syntax: ParseSummary,
    /// Independently parsed same-option `RustBytes` proof HIR.
    pub bytes_syntax: ParseSummary,
    /// Construction report for the byte-stable tagged executor.
    pub capture: CaptureBuildReport,
}

/// Failure to prove or construct the Rust text capture slice.
#[derive(Debug)]
#[non_exhaustive]
pub enum PortableTextCaptureBuildError {
    /// Public `RustText` parsing rejected the pattern.
    TextSyntax(ParseError),
    /// Independent same-option `RustBytes` proof parsing rejected the pattern.
    BytesProofSyntax(ParseError),
    /// The two capture-preserving HIRs are not exactly equal.
    ProfileHirMismatch,
    /// The common HIR does not guarantee valid UTF-8 for every non-empty
    /// whole match.
    InvalidUtf8Hir,
    /// The exact-HIR tagged executor refused construction.
    Capture(CaptureBuildError),
    /// An impossible profile state was observed.
    InternalInvariant(&'static str),
}

impl fmt::Display for PortableTextCaptureBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TextSyntax(error) => {
                write!(formatter, "Rust text capture syntax failed: {error}")
            }
            Self::BytesProofSyntax(error) => {
                write!(formatter, "Rust bytes capture proof syntax failed: {error}")
            }
            Self::ProfileHirMismatch => {
                formatter.write_str("Rust text and byte capture HIRs differ")
            }
            Self::InvalidUtf8Hir => {
                formatter.write_str("capture HIR does not guarantee valid UTF-8 matches")
            }
            Self::Capture(error) => write!(formatter, "capture construction failed: {error}"),
            Self::InternalInvariant(detail) => {
                write!(formatter, "text capture invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for PortableTextCaptureBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TextSyntax(error) | Self::BytesProofSyntax(error) => Some(error),
            Self::Capture(error) => Some(error),
            Self::ProfileHirMismatch | Self::InvalidUtf8Hir | Self::InternalInvariant(_) => None,
        }
    }
}

/// Text-specific capture iteration failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum PortableTextCaptureIterationError {
    /// The bounded tagged executor refused execution.
    Capture(CaptureIterationError),
    /// The tagged executor published a record without participating group
    /// zero.
    MissingOverall { match_index: usize },
    /// A retained match or group span violated the proved UTF-8 boundary
    /// contract.
    InvalidUtf8Capture {
        match_index: usize,
        group_index: usize,
        start: usize,
        end: usize,
    },
}

impl fmt::Display for PortableTextCaptureIterationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capture(error) => error.fmt(formatter),
            Self::MissingOverall { match_index } => {
                write!(
                    formatter,
                    "text capture match {match_index} lacks group zero"
                )
            }
            Self::InvalidUtf8Capture {
                match_index,
                group_index,
                start,
                end,
            } => write!(
                formatter,
                "text capture match {match_index} group {group_index} has non-boundary span [{start}, {end})",
            ),
        }
    }
}

impl std::error::Error for PortableTextCaptureIterationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Capture(error) => Some(error),
            Self::MissingOverall { .. } | Self::InvalidUtf8Capture { .. } => None,
        }
    }
}

/// Builder for the exact-HIR Rust text capture subset.
#[derive(Clone, Debug)]
pub struct PortableTextCaptureBuilder {
    pattern: String,
    profile: RustProfile,
    limits: CaptureBuildLimits,
}

impl PortableTextCaptureBuilder {
    /// Start from pinned Rust text defaults.
    #[must_use]
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            profile: RustProfile::default(),
            limits: CaptureBuildLimits::default(),
        }
    }

    /// Replace the complete public Rust text profile.
    #[must_use]
    pub fn profile(mut self, profile: RustProfile) -> Self {
        self.profile = profile;
        self
    }

    /// Replace every checked capture construction limit.
    #[must_use]
    pub const fn limits(mut self, limits: CaptureBuildLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Prove exact capture-preserving HIR equivalence and build the tagged
    /// byte-stable executor.
    pub fn build(self) -> Result<PortableTextCaptureRegex, PortableTextCaptureBuildError> {
        let text_profile = CompatibilityProfile::RustText(self.profile.clone());
        let text = fre_syntax::parse(
            fre_syntax::ParseRequest::rust(self.pattern.clone(), text_profile.clone())
                .with_admission(self.limits.admission)
                .with_safety_envelope(self.limits.syntax_safety),
        )
        .map_err(PortableTextCaptureBuildError::TextSyntax)?;
        let text_syntax = text.summary.clone();
        let CanonicalPattern::Rust(text_pattern) = text.pattern else {
            return Err(PortableTextCaptureBuildError::InternalInvariant(
                "RustText parse produced non-Rust syntax",
            ));
        };

        let bytes_profile = self.profile.clone();
        let bytes = fre_syntax::parse(
            fre_syntax::ParseRequest::rust(
                self.pattern.clone(),
                CompatibilityProfile::RustBytes(bytes_profile.clone()),
            )
            .with_admission(self.limits.admission)
            .with_safety_envelope(self.limits.syntax_safety),
        )
        .map_err(PortableTextCaptureBuildError::BytesProofSyntax)?;
        let bytes_syntax = bytes.summary.clone();
        let CanonicalPattern::Rust(bytes_pattern) = bytes.pattern else {
            return Err(PortableTextCaptureBuildError::InternalInvariant(
                "RustBytes proof parse produced non-Rust syntax",
            ));
        };
        if text_pattern.hir != bytes_pattern.hir {
            return Err(PortableTextCaptureBuildError::ProfileHirMismatch);
        }
        if !text_pattern.hir.properties().is_utf8() {
            return Err(PortableTextCaptureBuildError::InvalidUtf8Hir);
        }
        let inner = CaptureBuilder::new(self.pattern)
            .profile(bytes_profile)
            .limits(self.limits)
            .build()
            .map_err(PortableTextCaptureBuildError::Capture)?;
        let report = PortableTextCaptureBuildReport {
            profile: text_profile,
            text_syntax,
            bytes_syntax,
            capture: inner.build_report().clone(),
        };
        Ok(PortableTextCaptureRegex { inner, report })
    }
}

/// Immutable exact-HIR Rust text capture matcher.
#[derive(Clone, Debug)]
pub struct PortableTextCaptureRegex {
    inner: CaptureRegex,
    report: PortableTextCaptureBuildReport,
}

impl PortableTextCaptureRegex {
    /// Text/bytes equivalence and tagged construction evidence.
    #[must_use]
    pub const fn build_report(&self) -> &PortableTextCaptureBuildReport {
        &self.report
    }

    /// Materialize complete text captures while removing only empty records
    /// that fall inside a UTF-8 scalar. Non-empty matches and every retained
    /// group span must satisfy the independently proved boundary contract.
    pub fn captures_iter(
        &self,
        haystack: &str,
        limits: AggregateLimits,
    ) -> Result<CaptureIterationReport, PortableTextCaptureIterationError> {
        let mut report = self
            .inner
            .captures_iter(haystack.as_bytes(), limits)
            .map_err(PortableTextCaptureIterationError::Capture)?;
        for (match_index, record) in report.captures.iter().enumerate() {
            if record.overall().is_none() {
                return Err(PortableTextCaptureIterationError::MissingOverall { match_index });
            }
        }
        report.captures.retain(|record| {
            record
                .overall()
                .is_some_and(|span| span.start != span.end || haystack.is_char_boundary(span.start))
        });
        for (match_index, record) in report.captures.iter().enumerate() {
            for (group_index, group) in record.groups.iter().enumerate() {
                let Some(span) = group.span else {
                    continue;
                };
                if !haystack.is_char_boundary(span.start) || !haystack.is_char_boundary(span.end) {
                    return Err(PortableTextCaptureIterationError::InvalidUtf8Capture {
                        match_index,
                        group_index,
                        start: span.start,
                        end: span.end,
                    });
                }
            }
        }
        Ok(report)
    }
}

impl fmt::Display for CaptureIterationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "capture iteration failed: {}", self.source)
    }
}

impl std::error::Error for CaptureIterationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Builder for the capture-preserving persistent-history plan.
#[derive(Clone, Debug)]
pub struct CaptureBuilder {
    pattern: String,
    profile: RustProfile,
    limits: CaptureBuildLimits,
}

impl CaptureBuilder {
    /// Start from the pinned Rust byte profile. Unicode defaults to enabled;
    /// scalar classes lower to checked canonical UTF-8 byte sequences.
    #[must_use]
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            profile: RustProfile::default(),
            limits: CaptureBuildLimits::default(),
        }
    }

    /// Select the complete Rust constructor/profile identity.
    #[must_use]
    pub fn profile(mut self, profile: RustProfile) -> Self {
        self.profile = profile;
        self
    }

    /// Select Unicode syntax mode.
    #[must_use]
    pub fn unicode(mut self, enabled: bool) -> Self {
        self.profile.options.unicode = enabled;
        self
    }

    /// Select case-insensitive syntax lowering.
    #[must_use]
    pub fn case_insensitive(mut self, enabled: bool) -> Self {
        self.profile.options.case_insensitive = enabled;
        self
    }

    /// Replace all checked construction limits.
    #[must_use]
    pub const fn limits(mut self, limits: CaptureBuildLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Compile a capture-participation reducer for non-empty matches.
    pub fn build(self) -> Result<CaptureRegex, CaptureBuildError> {
        let limits = self.limits;
        let unicode = self.profile.options.unicode;
        let profile = CompatibilityProfile::RustBytes(self.profile);
        let parsed = fre_syntax::parse(
            fre_syntax::ParseRequest::rust(self.pattern, profile)
                .with_admission(limits.admission)
                .with_safety_envelope(limits.syntax_safety),
        )
        .map_err(CaptureBuildError::Syntax)?;
        let syntax_key = Arc::new(parsed.key);
        let admission = parsed.admission_status;
        let syntax = parsed.summary;
        let CanonicalPattern::Rust(rust) = parsed.pattern else {
            return Err(CaptureBuildError::InternalInvariant(
                "Rust byte request produced non-Rust syntax",
            ));
        };
        let mut accounting = CaptureHirAccounting::default();
        let selector_profile = if unicode {
            SelectorProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE
        } else {
            SelectorProfile::PINNED_1_12_4
        };
        let selector = SelectorRegex::from_hir_erasing_captures_for_whole_match(
            &rust.hir,
            selector_profile,
            limits.selector,
        )
        .map_err(CaptureBuildError::Selector)?;
        let selector_accounting = selector.compile_accounting();
        let ast = lower_hir(&rust.hir, 1, &limits, &mut accounting)?;
        let program =
            Arc::new(Program::compile(&ast, limits.engine).map_err(CaptureBuildError::Engine)?);
        let engine_report = program.build_report().clone();
        let syntax_captures = usize::try_from(syntax.captures).map_err(|_| {
            CaptureBuildError::InternalInvariant("syntax capture count does not fit usize")
        })?;
        if engine_report.captures != syntax_captures {
            return Err(CaptureBuildError::InternalInvariant(
                "capture compiler count differs from parsed HIR",
            ));
        }
        let plan_identity = CapturePlanIdentity {
            syntax: syntax_key,
            operation: CaptureOperation::CountParticipatingNonempty,
            plan: CapturePlanKind::LinearSelectorPersistentHistory,
            capture_profile: CaptureProfile::RustRegexBytes1_12_4,
            selector_plan_id: selector.plan_id(),
        };
        let report = CaptureBuildReport {
            admission,
            syntax,
            hir: accounting,
            engine: engine_report,
            selector: selector_accounting,
            plan_identity,
        };
        Ok(CaptureRegex {
            engine: HistoryRegex::from_program(program),
            selector: Arc::new(selector),
            build_limits: limits,
            report,
        })
    }
}

/// Immutable capture-preserving reducer plan.
#[derive(Clone, Debug)]
pub struct CaptureRegex {
    engine: HistoryRegex,
    selector: Arc<SelectorRegex>,
    build_limits: CaptureBuildLimits,
    report: CaptureBuildReport,
}

impl CaptureRegex {
    /// Construction and plan identity.
    #[must_use]
    pub const fn build_report(&self) -> &CaptureBuildReport {
        &self.report
    }

    /// Exact cache identity for these execution limits.
    #[must_use]
    pub fn cache_identity(&self, run_limits: CaptureRunLimits) -> CaptureCacheIdentity {
        CaptureCacheIdentity {
            plan: self.report.plan_identity.clone(),
            build_limits: self.build_limits,
            run_limits,
        }
    }

    /// Complete identity for one bounded capture-iteration invocation.
    #[must_use]
    pub fn iteration_identity(&self, run_limits: AggregateLimits) -> CaptureIterationIdentity {
        CaptureIterationIdentity {
            syntax: Arc::clone(&self.report.plan_identity.syntax),
            capture_profile: self.report.plan_identity.capture_profile,
            plan: CaptureIterationPlanKind::RestartedPersistentHistory,
            build_limits: self.build_limits,
            run_limits,
        }
    }

    /// Collect every non-overlapping leftmost-first match and every capture
    /// slot, including empty participating spans and explicit unmatched slots.
    ///
    /// This bounded persistent-history formulation can restart at successive
    /// match boundaries. It is the correctness path for materialized capture
    /// records; the existing selector/replay reducer remains the linear path
    /// for participation counts.
    pub fn captures_iter(
        &self,
        haystack: &[u8],
        limits: AggregateLimits,
    ) -> Result<CaptureIterationReport, CaptureIterationError> {
        let identity = self.iteration_identity(limits);
        let AggregateOutcome {
            captures,
            searches,
            total_state_visits,
            total_slot_copies: _,
            total_history_nodes,
        } = self
            .engine
            .captures_iter(haystack, Window::all(haystack), limits)
            .map_err(|source| CaptureIterationError {
                identity: Box::new(identity.clone()),
                source,
            })?;
        Ok(CaptureIterationReport {
            identity,
            captures,
            searches,
            total_state_visits,
            total_history_nodes,
        })
    }

    /// Reduce all non-overlapping non-empty matches over the complete byte haystack.
    #[allow(
        clippy::too_many_lines,
        reason = "selector, replay, and complete checked reducer accounting stay locally auditable"
    )]
    pub fn count_captures(
        &self,
        haystack: &[u8],
        limits: CaptureRunLimits,
    ) -> Result<CaptureExecutionReport, CaptureExecutionError> {
        let identity = self.cache_identity(limits);
        let mut selector_limits = limits.selector;
        selector_limits.max_peak_bytes = selector_limits
            .max_peak_bytes
            .min(limits.max_combined_peak_bytes);
        let selected = self
            .selector
            .admit_spans(
                haystack,
                0..haystack.len(),
                SelectorStrategy::ReverseSequentialRows,
                selector_limits,
            )
            .map_err(|source| CaptureExecutionError {
                identity: Box::new(identity.clone()),
                source: CaptureExecutionSource::Selector(source),
            })?;
        let selector_accounting = selected.accounting();
        let replay_scratch_limit = limits
            .max_combined_peak_bytes
            .checked_sub(selector_accounting.output_bytes)
            .ok_or_else(|| CaptureExecutionError {
                identity: Box::new(identity.clone()),
                source: CaptureExecutionSource::InternalInvariant(
                    "selector output exceeded the admitted combined peak",
                ),
            })?;
        let mut combined_peak_bytes = selector_accounting.peak_bytes;
        let mut accounting = CaptureCountOutcome {
            count: 0,
            matches: 0,
            searches: 0,
            total_state_visits: 0,
            total_history_nodes: 0,
            total_history_walk: 0,
            peak_threads: 0,
        };
        let mut capture_events = 0_usize;
        let window = Window::all(haystack);
        for selected_span in selected.as_slice() {
            if selected_span.start == selected_span.end {
                return Err(Self::history_error(
                    &identity,
                    EngineSearchError::EmptyMatch,
                ));
            }
            accounting.searches = checked_capture_add(
                &identity,
                accounting.searches,
                1,
                EngineResource::Searches,
                limits.aggregate.max_searches,
            )?;
            accounting.matches = checked_capture_add(
                &identity,
                accounting.matches,
                1,
                EngineResource::Results,
                limits.aggregate.max_results,
            )?;
            let mut per_search = limits.aggregate.per_search;
            per_search.max_scratch_bytes = per_search.max_scratch_bytes.min(replay_scratch_limit);
            per_search.max_state_visits = per_search.max_state_visits.min(capture_remaining(
                &identity,
                limits.aggregate.max_total_state_visits,
                accounting.total_state_visits,
                EngineResource::AggregateStateVisits,
            )?);
            per_search.max_history_nodes = per_search.max_history_nodes.min(capture_remaining(
                &identity,
                limits.aggregate.max_total_history_nodes,
                accounting.total_history_nodes,
                EngineResource::AggregateHistoryNodes,
            )?);
            per_search.max_history_walk = per_search.max_history_walk.min(capture_remaining(
                &identity,
                limits.aggregate.max_total_history_walk,
                accounting.total_history_walk,
                EngineResource::AggregateHistoryWalk,
            )?);
            let span = EngineSpan {
                start: selected_span.start,
                end: selected_span.end,
            };
            let replay = self
                .engine
                .captures_exact(haystack, window, span, per_search)
                .map_err(|source| Self::history_error(&identity, source))?;
            let replay_combined_peak = selector_accounting
                .output_bytes
                .checked_add(replay.report.admitted_scratch_bytes)
                .ok_or_else(|| CaptureExecutionError {
                    identity: Box::new(identity.clone()),
                    source: CaptureExecutionSource::InternalInvariant(
                        "combined selector/replay peak overflowed usize",
                    ),
                })?;
            combined_peak_bytes = combined_peak_bytes.max(replay_combined_peak);
            let captures = replay.captures.ok_or_else(|| CaptureExecutionError {
                identity: Box::new(identity.clone()),
                source: CaptureExecutionSource::InternalInvariant(
                    "selector-certified span produced no tagged winner",
                ),
            })?;
            accounting.total_state_visits = checked_capture_add(
                &identity,
                accounting.total_state_visits,
                replay.report.state_visits,
                EngineResource::AggregateStateVisits,
                limits.aggregate.max_total_state_visits,
            )?;
            accounting.total_history_nodes = checked_capture_add(
                &identity,
                accounting.total_history_nodes,
                replay.report.history_nodes,
                EngineResource::AggregateHistoryNodes,
                limits.aggregate.max_total_history_nodes,
            )?;
            accounting.total_history_walk = checked_capture_add(
                &identity,
                accounting.total_history_walk,
                replay.report.history_walk,
                EngineResource::AggregateHistoryWalk,
                limits.aggregate.max_total_history_walk,
            )?;
            accounting.peak_threads = accounting.peak_threads.max(replay.report.peak_threads);
            for group in captures.groups {
                capture_events = checked_capture_add(
                    &identity,
                    capture_events,
                    1,
                    EngineResource::CaptureEvents,
                    limits.aggregate.max_capture_events,
                )?;
                if group.span.is_some() {
                    accounting.count = checked_capture_add(
                        &identity,
                        accounting.count,
                        1,
                        EngineResource::CaptureCount,
                        limits.aggregate.max_capture_count,
                    )?;
                }
            }
        }
        Ok(CaptureExecutionReport {
            identity,
            accounting,
            selector_certificate: selected.certificate().clone(),
            selector_accounting,
            combined_peak_bytes,
        })
    }

    fn history_error(
        identity: &CaptureCacheIdentity,
        source: EngineSearchError,
    ) -> CaptureExecutionError {
        CaptureExecutionError {
            identity: Box::new(identity.clone()),
            source: CaptureExecutionSource::History(source),
        }
    }
}

fn capture_remaining(
    identity: &CaptureCacheIdentity,
    limit: usize,
    used: usize,
    resource: EngineResource,
) -> Result<usize, CaptureExecutionError> {
    limit
        .checked_sub(used)
        .ok_or_else(|| CaptureExecutionError {
            identity: Box::new(identity.clone()),
            source: CaptureExecutionSource::History(EngineSearchError::BoundOverflow(resource)),
        })
}

fn checked_capture_add(
    identity: &CaptureCacheIdentity,
    current: usize,
    amount: usize,
    resource: EngineResource,
    limit: usize,
) -> Result<usize, CaptureExecutionError> {
    let required = current
        .checked_add(amount)
        .ok_or_else(|| CaptureExecutionError {
            identity: Box::new(identity.clone()),
            source: CaptureExecutionSource::History(EngineSearchError::BoundOverflow(resource)),
        })?;
    if required > limit {
        return Err(CaptureExecutionError {
            identity: Box::new(identity.clone()),
            source: CaptureExecutionSource::History(EngineSearchError::Resource {
                kind: resource,
                required,
                limit,
            }),
        });
    }
    Ok(required)
}

#[allow(
    clippy::too_many_lines,
    reason = "the complete checked HIR-to-capture-AST mapping remains locally auditable"
)]
fn lower_hir(
    hir: &Hir,
    depth: usize,
    limits: &CaptureBuildLimits,
    accounting: &mut CaptureHirAccounting,
) -> Result<Ast, CaptureBuildError> {
    if depth > limits.max_hir_depth {
        return Err(CaptureBuildError::HirResource {
            resource: "depth",
            required: depth,
            limit: limits.max_hir_depth,
        });
    }
    accounting.hir_depth = accounting.hir_depth.max(depth);
    charge_hir(accounting, 1, limits.max_hir_work)?;
    accounting.hir_nodes =
        accounting
            .hir_nodes
            .checked_add(1)
            .ok_or(CaptureBuildError::HirResource {
                resource: "nodes",
                required: usize::MAX,
                limit: limits.max_hir_work,
            })?;
    match hir.kind() {
        HirKind::Empty => Ok(Ast::Empty),
        HirKind::Literal(literal) => {
            charge_hir(accounting, literal.0.len(), limits.max_hir_work)?;
            accounting.literal_bytes = checked_dimension_add(
                accounting.literal_bytes,
                literal.0.len(),
                "literal bytes",
                limits.max_hir_work,
            )?;
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(literal.0.len()).map_err(|_| {
                CaptureBuildError::Allocation {
                    structure: "literal",
                    items: literal.0.len(),
                }
            })?;
            bytes.extend(literal.0.iter().copied().map(Ast::Byte));
            Ok(concat_or_empty(bytes))
        }
        HirKind::Class(Class::Bytes(class)) => {
            let ranges_len = class.ranges().len();
            charge_hir(accounting, ranges_len, limits.max_hir_work)?;
            accounting.class_ranges = checked_dimension_add(
                accounting.class_ranges,
                ranges_len,
                "class ranges",
                limits.max_hir_work,
            )?;
            let mut ranges = Vec::new();
            ranges
                .try_reserve_exact(ranges_len)
                .map_err(|_| CaptureBuildError::Allocation {
                    structure: "class range",
                    items: ranges_len,
                })?;
            ranges.extend(
                class
                    .ranges()
                    .iter()
                    .map(|range| (range.start(), range.end())),
            );
            Ok(Ast::Class(ranges))
        }
        HirKind::Class(Class::Unicode(class)) => lower_unicode_class(class, limits, accounting),
        HirKind::Look(Look::Start) => Ok(Ast::Start),
        HirKind::Look(Look::End) => Ok(Ast::End),
        HirKind::Look(look) => Err(CaptureBuildError::Unsupported(CaptureUnsupported::Look(
            *look,
        ))),
        HirKind::Capture(capture) => Ok(Ast::Capture {
            index: capture.index,
            name: capture.name.as_ref().map(ToString::to_string),
            child: Box::new(lower_hir(
                capture.sub.as_ref(),
                next_depth(depth)?,
                limits,
                accounting,
            )?),
        }),
        HirKind::Repetition(repetition) => Ok(Ast::Repeat {
            child: Box::new(lower_hir(
                repetition.sub.as_ref(),
                next_depth(depth)?,
                limits,
                accounting,
            )?),
            min: repetition.min,
            max: repetition.max,
            greed: if repetition.greedy {
                Greed::Greedy
            } else {
                Greed::Lazy
            },
        }),
        HirKind::Concat(children) => {
            lower_children(children, depth, limits, accounting, Ast::Concat)
        }
        HirKind::Alternation(children) => {
            lower_children(children, depth, limits, accounting, Ast::Alt)
        }
    }
}

fn lower_unicode_class(
    class: &ClassUnicode,
    limits: &CaptureBuildLimits,
    accounting: &mut CaptureHirAccounting,
) -> Result<Ast, CaptureBuildError> {
    let mut branches = Vec::new();
    for scalar_range in class.ranges() {
        charge_hir(accounting, 1, limits.max_hir_work)?;
        for sequence in Utf8Sequences::new(scalar_range.start(), scalar_range.end()) {
            charge_hir(accounting, 1, limits.max_hir_work)?;
            let byte_ranges = sequence.as_slice();
            charge_hir(accounting, byte_ranges.len(), limits.max_hir_work)?;
            let mut parts = Vec::new();
            parts.try_reserve_exact(byte_ranges.len()).map_err(|_| {
                CaptureBuildError::Allocation {
                    structure: "Unicode class sequence",
                    items: byte_ranges.len(),
                }
            })?;
            for range in byte_ranges {
                accounting.class_ranges = checked_dimension_add(
                    accounting.class_ranges,
                    1,
                    "class ranges",
                    limits.max_hir_work,
                )?;
                let mut ranges = Vec::new();
                ranges
                    .try_reserve_exact(1)
                    .map_err(|_| CaptureBuildError::Allocation {
                        structure: "Unicode byte range",
                        items: 1,
                    })?;
                ranges.push((range.start, range.end));
                parts.push(Ast::Class(ranges));
            }
            branches
                .try_reserve(1)
                .map_err(|_| CaptureBuildError::Allocation {
                    structure: "Unicode class branch",
                    items: 1,
                })?;
            branches.push(concat_or_empty(parts));
        }
    }
    Ok(match branches.len() {
        0 => Ast::Class(Vec::new()),
        1 => branches
            .into_iter()
            .next()
            .unwrap_or(Ast::Class(Vec::new())),
        _ => Ast::Alt(branches),
    })
}

fn lower_children(
    children: &[Hir],
    depth: usize,
    limits: &CaptureBuildLimits,
    accounting: &mut CaptureHirAccounting,
    construct: fn(Vec<Ast>) -> Ast,
) -> Result<Ast, CaptureBuildError> {
    let mut lowered = Vec::new();
    lowered
        .try_reserve_exact(children.len())
        .map_err(|_| CaptureBuildError::Allocation {
            structure: "child",
            items: children.len(),
        })?;
    let child_depth = next_depth(depth)?;
    for child in children {
        lowered.push(lower_hir(child, child_depth, limits, accounting)?);
    }
    Ok(construct(lowered))
}

fn concat_or_empty(children: Vec<Ast>) -> Ast {
    match children.len() {
        0 => Ast::Empty,
        1 => children.into_iter().next().unwrap_or(Ast::Empty),
        _ => Ast::Concat(children),
    }
}

fn next_depth(depth: usize) -> Result<usize, CaptureBuildError> {
    depth.checked_add(1).ok_or(CaptureBuildError::HirResource {
        resource: "depth",
        required: usize::MAX,
        limit: usize::MAX,
    })
}

fn charge_hir(
    accounting: &mut CaptureHirAccounting,
    amount: usize,
    limit: usize,
) -> Result<(), CaptureBuildError> {
    let required = accounting
        .work
        .checked_add(amount)
        .ok_or(CaptureBuildError::HirResource {
            resource: "work",
            required: usize::MAX,
            limit,
        })?;
    if required > limit {
        return Err(CaptureBuildError::HirResource {
            resource: "work",
            required,
            limit,
        });
    }
    accounting.work = required;
    Ok(())
}

fn checked_dimension_add(
    current: usize,
    amount: usize,
    resource: &'static str,
    limit: usize,
) -> Result<usize, CaptureBuildError> {
    let required = current
        .checked_add(amount)
        .ok_or(CaptureBuildError::HirResource {
            resource,
            required: usize::MAX,
            limit,
        })?;
    if required > limit {
        return Err(CaptureBuildError::HirResource {
            resource,
            required,
            limit,
        });
    }
    Ok(required)
}
