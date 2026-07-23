//! Capture-preserving persistent-history facade for the certified Rust-byte subset.

use core::fmt;
use std::sync::Arc;

use fre_aggregate::{
    CompileAccounting as SelectorCompileAccounting, CompileLimits as SelectorCompileLimits,
    CompiledRegex as SelectorRegex, Error as SelectorError,
    ExecutionAccounting as SelectorExecutionAccounting,
    OperationAttemptError as SelectorOperationAttemptError,
    OperationAttemptReceipt as SelectorOperationAttemptReceipt,
    OperationCertificate as SelectorOperationCertificate,
    OperationLimits as SelectorOperationLimits,
    OperationProspective as SelectorOperationProspective, PlanId as SelectorPlanId,
    Resource as SelectorResource, RustByteProfile as SelectorProfile, Strategy as SelectorStrategy,
};
use fre_capture_lab::{
    AggregateLimits, AggregateOutcome, Assertion as CaptureAssertion, Ast,
    BuildError as EngineBuildError, BuildLimits as EngineBuildLimits,
    BuildReport as EngineBuildReport, CaptureCountOutcome, CaptureProfile, CaptureRecord, Greed,
    HistoryRegex, Program, ResourceKind as EngineResource, RunReport as EngineSearchAccounting,
    SearchConfig as CaptureSearchConfig, SearchError as EngineSearchError,
    SearchLimits as EngineSearchLimits, SearchOutcome as EngineSearchOutcome, Span as EngineSpan,
    Window,
};
use fre_kernels::{
    LiteralSetError, PrefixClassAlternationBuildError, PrefixClassAlternationPlan,
    PrefixClassUniformParticipationAccounting, PrefixClassUniformParticipationBuildAccounting,
    PrefixClassUniformParticipationBuildError, PrefixClassUniformParticipationBuildLimits,
    PrefixClassUniformParticipationError, PrefixClassUniformParticipationIdentity,
    PrefixClassUniformParticipationLimits, PrefixClassUniformParticipationProspective,
    PrefixClassUniformParticipationSchema,
};
use fre_syntax::{
    AdmissionPolicy, AdmissionStatus, CacheKey, CanonicalPattern, CompatibilityProfile, ParseError,
    ParseSummary, RustProfile, SafetyEnvelope,
};
use regex_syntax::{
    hir::{Class, ClassBytesRange, ClassUnicode, Hir, HirKind, Look},
    utf8::Utf8Sequences,
};

use crate::aggregate::{
    PrefixClassInspection, PrefixClassInspectionError, inspect_prefix_class_alternation,
    prefix_class_selection_work,
};
use crate::capture_required_literal::{
    self, CaptureRequiredLiteralBuildAccounting, CaptureRequiredLiteralBuildError,
    CaptureRequiredLiteralBuildLimits, CaptureRequiredLiteralIdentity, CaptureRequiredLiteralPlan,
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
    /// Direct capture Count for two ordered `LITERAL BYTE_CLASS+` arms, with
    /// one canonical-HIR-proved participating group per selected match.
    UniformPrefixClassParticipation,
    /// One operation-wide span selector plus a construction-time proof of a
    /// fixed participating-capture cardinality for every selected match.
    LinearSelectorUniformParticipation,
    /// One operation-wide span selector plus exact-span persistent-history replay.
    LinearSelectorPersistentHistory,
}

/// Typed compatibility receipt for HIR forms outside the certified capture compiler.
///
/// The pinned `regex-syntax` look set is currently implemented. This type is
/// retained so future upstream look variants can remain explicit refusals.
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
    /// Numeric user-capture slots implied by the greatest surviving HIR index.
    pub capture_slots: usize,
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
    /// Optional required-literal proof and DFA limits. `None` performs no
    /// additional HIR traversal and preserves the legacy capture artifact.
    pub required_literal: Option<CaptureRequiredLiteralBuildLimits>,
    /// Independent canonical-HIR inspection ceiling for the optional direct
    /// two-arm prefix/class capture route.
    pub max_prefix_class_participation_planner_work: usize,
    /// Construction limits for the optional direct prefix/class kernel.
    pub prefix_class_participation: PrefixClassUniformParticipationBuildLimits,
}

impl Default for CaptureBuildLimits {
    fn default() -> Self {
        // These checked ceilings admit the pinned 2,500-scalar dot repeat and
        // 50-scalar Unicode-letter repeat. They do not preallocate their
        // maximum state or patch capacities.
        let engine = EngineBuildLimits {
            max_ast_nodes: 65_536,
            // The authenticated Rebar lexer surface contains 65 user
            // captures. This remains a checked construction ceiling, not a
            // preallocation: the compiler charges every capture and all
            // resulting states before publishing a program.
            max_captures: 1_024,
            max_repeat_expansion: 2_500,
            max_states: 524_288,
            max_patch_entries: 524_288,
            ..EngineBuildLimits::default()
        };
        let selector = SelectorCompileLimits {
            max_repeat_bound: 2_500,
            // The authenticated Rebar overlapping-word capture pair expands
            // ten ordered Unicode-letter repetitions into more than 2^18
            // capture-erased selector states. Construction remains metered
            // and bounded; these ceilings do not preallocate either buffer.
            max_program_states: 524_288,
            max_temporary_states: 524_288,
            max_program_bytes: 32 * 1_048_576,
            ..SelectorCompileLimits::default()
        };
        Self {
            admission: AdmissionPolicy::default(),
            syntax_safety: SafetyEnvelope::default(),
            max_hir_work: 1_000_000,
            max_hir_depth: 250,
            engine,
            selector,
            required_literal: None,
            max_prefix_class_participation_planner_work: 4_096,
            prefix_class_participation: PrefixClassUniformParticipationBuildLimits::default(),
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
    /// Independent direct-operation limits. These are inactive for selector
    /// and persistent-history plans but remain part of invocation identity.
    pub prefix_class_participation: PrefixClassUniformParticipationLimits,
}

impl Default for CaptureRunLimits {
    fn default() -> Self {
        Self {
            aggregate: AggregateLimits::default(),
            selector: SelectorOperationLimits::default(),
            max_combined_peak_bytes: 512 * 1_048_576,
            prefix_class_participation: PrefixClassUniformParticipationLimits::default(),
        }
    }
}

/// Exact direct-route identity proved from canonical HIR.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapturePrefixClassParticipationIdentity {
    /// Distinct capture-aware physical operation identity.
    pub kernel: PrefixClassUniformParticipationIdentity,
    /// Numeric capture index around each ordered branch's greedy class.
    pub participating_capture_indices: [u32; 2],
    /// The only route allowed when direct construction refuses before plan
    /// publication.
    pub declared_prepublication_fallback: CapturePlanKind,
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
    /// Optional generic required-any-literal proof sharing this exact syntax.
    pub required_literal: Option<CaptureRequiredLiteralIdentity>,
    /// Direct physical route and its declared U3 fallback, when selected.
    pub prefix_class_participation: Option<CapturePrefixClassParticipationIdentity>,
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
    /// Exact explicit-capture participation per selected match when the HIR
    /// proves that cardinality independent of input and branch choice.
    pub uniform_participating_captures: Option<usize>,
    /// Optional bounded required-literal construction receipt.
    pub required_literal: Option<CaptureRequiredLiteralBuildAccounting>,
    /// Additional canonical-HIR work used to accept or refuse the optional
    /// direct prefix/class route.
    pub prefix_class_participation_planner_work: usize,
    /// Successful direct-kernel construction accounting.
    pub prefix_class_participation: Option<PrefixClassUniformParticipationBuildAccounting>,
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
    /// Direct prefix/class construction reached a non-optional terminal.
    PrefixClassParticipation(PrefixClassUniformParticipationBuildError),
    /// Optional required-literal proof or DFA construction refused.
    RequiredLiteral(CaptureRequiredLiteralBuildError),
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
            Self::PrefixClassParticipation(error) => {
                write!(formatter, "capture prefix/class build failed: {error}")
            }
            Self::RequiredLiteral(error) => {
                write!(formatter, "capture required-literal build failed: {error}")
            }
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
            Self::PrefixClassParticipation(error) => Some(error),
            Self::RequiredLiteral(error) => Some(error),
            _ => None,
        }
    }
}

/// Typed source of a capture operation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaptureExecutionSource {
    /// Direct prefix/class participation route refused or faulted. Once its
    /// prospective is published this is terminal and never selects U3.
    PrefixClassParticipation(PrefixClassUniformParticipationError),
    /// Immutable selector/history/direct plans plus direct operation state, or
    /// the mandatory U3 control envelope, exceed the caller's peak before
    /// source access.
    CombinedPeak {
        /// Required co-live bytes.
        needed: usize,
        /// Caller limit.
        limit: usize,
    },
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
            Self::PrefixClassParticipation(error) => error.fmt(formatter),
            Self::CombinedPeak { needed, limit } => write!(
                formatter,
                "capture co-live peak needs {needed} bytes, exceeding {limit}"
            ),
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
            Self::PrefixClassParticipation(error) => Some(error),
            Self::CombinedPeak { .. } => None,
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
    /// Complete Count-attempt receipt when the uniform-participation route
    /// reached its prospective selector boundary.
    pub selector_receipt: Option<SelectorOperationAttemptReceipt>,
    /// Published direct-operation prospective when failure occurred after its
    /// owner-local publication boundary.
    pub prefix_class_participation_prospective: Option<PrefixClassUniformParticipationProspective>,
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
    pub selector_certificate: Option<SelectorOperationCertificate>,
    /// Exact selector work and storage accounting.
    pub selector_accounting: Option<SelectorExecutionAccounting>,
    /// Complete selector Count receipt for the positive-width uniform route.
    /// Span-bearing selector/replay routes retain `None`.
    pub selector_receipt: Option<SelectorOperationAttemptReceipt>,
    /// Complete direct prefix/class P/A accounting. Selector-backed routes
    /// retain `None`.
    pub prefix_class_participation: Option<PrefixClassUniformParticipationAccounting>,
    /// Complete capture-schema entries logically inspected by the reducer.
    pub capture_events: usize,
    /// Conservative retained/operation peak for the selected route, never
    /// below the mandatory U3 control envelope. Selector routes retain their
    /// existing dynamic interpretation.
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
    /// Match-end selection and start-injection policy.
    pub search: CaptureSearchConfig,
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
    /// The requested search window is not a valid UTF-8 substring boundary.
    InvalidUtf8Window {
        /// Inclusive search start.
        start: usize,
        /// Exclusive search end.
        end: usize,
    },
}

/// Failure from one bounded Rust text capture search.
#[derive(Debug)]
#[non_exhaustive]
pub enum PortableTextCaptureSearchError {
    /// The persistent-history executor refused the bounded search.
    Capture(EngineSearchError),
    /// A selected capture record did not contain its whole-match slot.
    MissingOverall,
    /// A selected record's vector position and declared group index differed.
    InvalidCaptureIndex {
        /// Position in the selected record.
        expected: usize,
        /// Index declared by the capture engine.
        actual: u32,
    },
    /// A selected group span was not a valid slice of the UTF-8 haystack.
    InvalidUtf8Capture {
        /// Numeric capture slot.
        group_index: usize,
        /// Inclusive byte offset.
        start: usize,
        /// Exclusive byte offset.
        end: usize,
    },
}

impl fmt::Display for PortableTextCaptureSearchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capture(error) => error.fmt(formatter),
            Self::MissingOverall => formatter.write_str("text capture match lacks group zero"),
            Self::InvalidCaptureIndex { expected, actual } => write!(
                formatter,
                "text capture slot {expected} declared group index {actual}",
            ),
            Self::InvalidUtf8Capture {
                group_index,
                start,
                end,
            } => write!(
                formatter,
                "text capture group {group_index} has non-boundary span [{start}, {end})",
            ),
        }
    }
}

impl std::error::Error for PortableTextCaptureSearchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Capture(error) => Some(error),
            Self::MissingOverall
            | Self::InvalidCaptureIndex { .. }
            | Self::InvalidUtf8Capture { .. } => None,
        }
    }
}

/// One borrowed UTF-8 capture match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortableTextCaptureMatch<'h> {
    haystack: &'h str,
    span: EngineSpan,
}

impl<'h> PortableTextCaptureMatch<'h> {
    /// Inclusive byte offset in the original haystack.
    #[must_use]
    pub const fn start(self) -> usize {
        self.span.start
    }

    /// Exclusive byte offset in the original haystack.
    #[must_use]
    pub const fn end(self) -> usize {
        self.span.end
    }

    /// Borrow the matched text with the haystack's lifetime.
    #[must_use]
    pub fn as_str(self) -> &'h str {
        &self.haystack[self.span.start..self.span.end]
    }
}

/// Borrowed capture groups from one selected Rust text match.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortableTextCaptures<'h> {
    haystack: &'h str,
    record: CaptureRecord,
}

impl<'h> PortableTextCaptures<'h> {
    /// Number of capture slots, including group zero.
    #[must_use]
    pub fn len(&self) -> usize {
        self.record.groups.len()
    }

    /// Capture records always include group zero.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.record.groups.is_empty()
    }

    /// Return one participating capture by numeric index.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<PortableTextCaptureMatch<'h>> {
        let group = self.record.groups.get(index)?;
        let span = group.span?;
        Some(PortableTextCaptureMatch {
            haystack: self.haystack,
            span,
        })
    }

    /// Return one participating capture by name.
    #[must_use]
    pub fn name(&self, name: &str) -> Option<PortableTextCaptureMatch<'h>> {
        let group = self
            .record
            .groups
            .iter()
            .find(|group| group.name.as_deref() == Some(name))?;
        let span = group.span?;
        Some(PortableTextCaptureMatch {
            haystack: self.haystack,
            span,
        })
    }
}

impl core::ops::Index<usize> for PortableTextCaptures<'_> {
    type Output = str;

    fn index(&self, index: usize) -> &Self::Output {
        self.get(index)
            .unwrap_or_else(|| panic!("capture group {index} did not participate"))
            .as_str()
    }
}

impl core::ops::Index<&str> for PortableTextCaptures<'_> {
    type Output = str;

    fn index(&self, name: &str) -> &Self::Output {
        self.name(name)
            .unwrap_or_else(|| {
                panic!("capture group {name:?} does not exist or did not participate")
            })
            .as_str()
    }
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
            Self::InvalidUtf8Window { start, end } => write!(
                formatter,
                "text capture window [{start}, {end}) is not a valid UTF-8 substring",
            ),
        }
    }
}

impl std::error::Error for PortableTextCaptureIterationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Capture(error) => Some(error),
            Self::MissingOverall { .. }
            | Self::InvalidUtf8Capture { .. }
            | Self::InvalidUtf8Window { .. } => None,
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

    /// Return the selected leftmost-first capture record while borrowing every
    /// participating group from the original UTF-8 haystack.
    ///
    /// # Errors
    ///
    /// Returns [`PortableTextCaptureSearchError::Capture`] when the bounded
    /// persistent-history search is refused. Any violation of the
    /// construction-time UTF-8 proof is reported as a typed invariant error.
    pub fn captures<'h>(
        &self,
        haystack: &'h str,
        limits: EngineSearchLimits,
    ) -> Result<
        (Option<PortableTextCaptures<'h>>, EngineSearchAccounting),
        PortableTextCaptureSearchError,
    > {
        self.captures_with_config(haystack, CaptureSearchConfig::LEFTMOST, limits)
    }

    /// Return one capture record under explicit match-end, match-priority and
    /// start-injection policies.
    pub fn captures_with_config<'h>(
        &self,
        haystack: &'h str,
        config: CaptureSearchConfig,
        limits: EngineSearchLimits,
    ) -> Result<
        (Option<PortableTextCaptures<'h>>, EngineSearchAccounting),
        PortableTextCaptureSearchError,
    > {
        self.captures_window_with_config(haystack, Window::all(haystack.as_bytes()), config, limits)
    }

    /// Return the first text capture record inside `window` under an explicit
    /// match-end selection and start-injection policy.
    pub fn captures_window_with_config<'h>(
        &self,
        haystack: &'h str,
        window: Window,
        config: CaptureSearchConfig,
        limits: EngineSearchLimits,
    ) -> Result<
        (Option<PortableTextCaptures<'h>>, EngineSearchAccounting),
        PortableTextCaptureSearchError,
    > {
        if !text_capture_window_is_valid(haystack, window) {
            return Err(PortableTextCaptureSearchError::Capture(
                EngineSearchError::InvalidWindow,
            ));
        }
        let outcome = self
            .inner
            .captures_window_with_config(haystack.as_bytes(), window, config, limits)
            .map_err(PortableTextCaptureSearchError::Capture)?;
        portable_text_capture_outcome(haystack, outcome)
    }

    /// Query whether `span` is an exact UTF-8 match inside `window`, returning
    /// its prioritized capture history when it is. An ordinary non-match is a
    /// successful outcome with no capture record.
    pub fn captures_exact_window<'h>(
        &self,
        haystack: &'h str,
        window: Window,
        span: EngineSpan,
        limits: EngineSearchLimits,
    ) -> Result<
        (Option<PortableTextCaptures<'h>>, EngineSearchAccounting),
        PortableTextCaptureSearchError,
    > {
        if !text_capture_window_is_valid(haystack, window)
            || span.start > span.end
            || span.start < window.start
            || span.end > window.end
            || !haystack.is_char_boundary(span.start)
            || !haystack.is_char_boundary(span.end)
        {
            return Err(PortableTextCaptureSearchError::Capture(
                EngineSearchError::InvalidWindow,
            ));
        }
        let outcome = self
            .inner
            .captures_exact_window(haystack.as_bytes(), window, span, limits)
            .map_err(PortableTextCaptureSearchError::Capture)?;
        portable_text_capture_outcome(haystack, outcome)
    }

    /// Materialize complete text captures while removing only empty records
    /// that fall inside a UTF-8 scalar. Non-empty matches and every retained
    /// group span must satisfy the independently proved boundary contract.
    pub fn captures_iter(
        &self,
        haystack: &str,
        limits: AggregateLimits,
    ) -> Result<CaptureIterationReport, PortableTextCaptureIterationError> {
        self.captures_iter_window_with_config(
            haystack,
            Window::all(haystack.as_bytes()),
            CaptureSearchConfig::LEFTMOST,
            limits,
        )
    }

    /// Materialize complete text captures whose whole-match spans are
    /// constrained to `window`, while assertions retain original-haystack
    /// context.
    pub fn captures_iter_window(
        &self,
        haystack: &str,
        window: Window,
        limits: AggregateLimits,
    ) -> Result<CaptureIterationReport, PortableTextCaptureIterationError> {
        self.captures_iter_window_with_config(
            haystack,
            window,
            CaptureSearchConfig::LEFTMOST,
            limits,
        )
    }

    /// Materialize complete text captures under explicit match-end,
    /// match-priority and start-injection policies.
    pub fn captures_iter_window_with_config(
        &self,
        haystack: &str,
        window: Window,
        config: CaptureSearchConfig,
        limits: AggregateLimits,
    ) -> Result<CaptureIterationReport, PortableTextCaptureIterationError> {
        if window.start > window.end
            || window.end > haystack.len()
            || !haystack.is_char_boundary(window.start)
            || !haystack.is_char_boundary(window.end)
        {
            return Err(PortableTextCaptureIterationError::InvalidUtf8Window {
                start: window.start,
                end: window.end,
            });
        }
        let mut report = self
            .inner
            .captures_iter_window_with_config(haystack.as_bytes(), window, config, limits)
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

fn text_capture_window_is_valid(haystack: &str, window: Window) -> bool {
    window.start <= window.end
        && window.end <= haystack.len()
        && haystack.is_char_boundary(window.start)
        && haystack.is_char_boundary(window.end)
}

fn portable_text_capture_outcome(
    haystack: &str,
    outcome: EngineSearchOutcome,
) -> Result<
    (Option<PortableTextCaptures<'_>>, EngineSearchAccounting),
    PortableTextCaptureSearchError,
> {
    let accounting = outcome.report;
    let Some(record) = outcome.captures else {
        return Ok((None, accounting));
    };
    if record.overall().is_none() {
        return Err(PortableTextCaptureSearchError::MissingOverall);
    }
    for (group_index, group) in record.groups.iter().enumerate() {
        if usize::try_from(group.index) != Ok(group_index) {
            return Err(PortableTextCaptureSearchError::InvalidCaptureIndex {
                expected: group_index,
                actual: group.index,
            });
        }
        let Some(span) = group.span else {
            continue;
        };
        if span.start > span.end
            || span.end > haystack.len()
            || !haystack.is_char_boundary(span.start)
            || !haystack.is_char_boundary(span.end)
        {
            return Err(PortableTextCaptureSearchError::InvalidUtf8Capture {
                group_index,
                start: span.start,
                end: span.end,
            });
        }
    }
    Ok((Some(PortableTextCaptures { haystack, record }), accounting))
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

fn optional_required_literal_refusal(error: &CaptureRequiredLiteralBuildError) -> bool {
    match error {
        CaptureRequiredLiteralBuildError::Resource { .. }
        | CaptureRequiredLiteralBuildError::Allocation { .. } => true,
        CaptureRequiredLiteralBuildError::LiteralSet(source) => matches!(
            source,
            LiteralSetError::PatternLimit { .. }
                | LiteralSetError::PatternBytesLimit { .. }
                | LiteralSetError::BuildWorkLimit { .. }
                | LiteralSetError::BuildBytesLimit { .. }
                | LiteralSetError::PersistentBytesLimit { .. }
        ),
        CaptureRequiredLiteralBuildError::Overflow(_)
        | CaptureRequiredLiteralBuildError::InternalInvariant(_) => false,
    }
}

#[derive(Debug)]
struct CapturePrefixClassParticipationPlan {
    engine: PrefixClassAlternationPlan,
    schema: PrefixClassUniformParticipationSchema,
    participating_capture_indices: [u32; 2],
}

impl CapturePrefixClassParticipationPlan {
    fn identity(&self) -> CapturePrefixClassParticipationIdentity {
        CapturePrefixClassParticipationIdentity {
            kernel: self.engine.uniform_participation_identity(self.schema),
            participating_capture_indices: self.participating_capture_indices,
            declared_prepublication_fallback: CapturePlanKind::LinearSelectorUniformParticipation,
        }
    }
}

struct CapturePrefixClassParticipationBuild {
    plan: Option<Arc<CapturePrefixClassParticipationPlan>>,
    planner_work: usize,
}

fn optional_prefix_class_build_refusal(error: &PrefixClassUniformParticipationBuildError) -> bool {
    match error {
        PrefixClassUniformParticipationBuildError::Kernel(error) => matches!(
            error,
            PrefixClassAlternationBuildError::EmptyPrefix { .. }
                | PrefixClassAlternationBuildError::SelfOverlappingPrefix { .. }
                | PrefixClassAlternationBuildError::EmptyClass { .. }
                | PrefixClassAlternationBuildError::NonCanonicalClass { .. }
                | PrefixClassAlternationBuildError::ShapeLimit { .. }
                | PrefixClassAlternationBuildError::WorkLimit { .. }
                | PrefixClassAlternationBuildError::ScratchLimit { .. }
                | PrefixClassAlternationBuildError::PersistentLimit { .. }
                | PrefixClassAlternationBuildError::PeakLimit { .. }
        ),
        PrefixClassUniformParticipationBuildError::AllocationsLimit { .. }
        | PrefixClassUniformParticipationBuildError::CopiedPrefixBytesLimit { .. }
        | PrefixClassUniformParticipationBuildError::FinderPreprocessInputBytesLimit { .. }
        | PrefixClassUniformParticipationBuildError::InitializedBitmapBytesLimit { .. }
        | PrefixClassUniformParticipationBuildError::RetainedCapacityBytesLimit { .. } => true,
        _ => false,
    }
}

fn build_prefix_class_participation(
    hir: &Hir,
    syntax: &ParseSummary,
    unicode: bool,
    case_insensitive: bool,
    selector_has_terminal_frontier: bool,
    uniform_participating_captures: Option<usize>,
    limits: &CaptureBuildLimits,
    accounting: &mut CaptureHirAccounting,
) -> Result<CapturePrefixClassParticipationBuild, CaptureBuildError> {
    let ineligible = || CapturePrefixClassParticipationBuild {
        plan: None,
        planner_work: 0,
    };
    if unicode
        || case_insensitive
        || selector_has_terminal_frontier
        || limits.required_literal.is_some()
        || uniform_participating_captures != Some(1)
        || syntax.captures != 2
    {
        return Ok(ineligible());
    }
    let Some(selection_work) = prefix_class_selection_work(syntax) else {
        return Ok(ineligible());
    };
    let remaining_hir_work =
        limits
            .max_hir_work
            .checked_sub(accounting.work)
            .ok_or(CaptureBuildError::HirResource {
                resource: "work",
                required: accounting.work,
                limit: limits.max_hir_work,
            })?;
    if selection_work > limits.max_prefix_class_participation_planner_work
        || selection_work > remaining_hir_work
    {
        return Ok(ineligible());
    }
    let inspection =
        inspect_prefix_class_alternation(hir, selection_work).map_err(|error| match error {
            PrefixClassInspectionError::WorkLimit { needed, limit } => {
                CaptureBuildError::HirResource {
                    resource: "prefix/class participation work",
                    required: needed,
                    limit,
                }
            }
            PrefixClassInspectionError::Overflow => CaptureBuildError::InternalInvariant(
                "prefix/class participation inspection overflowed",
            ),
        })?;
    match inspection {
        PrefixClassInspection::Ineligible { work } => {
            charge_hir(accounting, work, limits.max_hir_work)?;
            Ok(CapturePrefixClassParticipationBuild {
                plan: None,
                planner_work: work,
            })
        }
        PrefixClassInspection::Eligible {
            prefixes,
            classes,
            work,
            hir_nodes,
            captures,
            uniform_participating_capture_indices,
        } => {
            charge_hir(accounting, work, limits.max_hir_work)?;
            let expected_nodes = usize::try_from(syntax.hir_nodes).map_err(|_| {
                CaptureBuildError::InternalInvariant("syntax HIR nodes do not fit usize")
            })?;
            let expected_captures = usize::try_from(syntax.captures).map_err(|_| {
                CaptureBuildError::InternalInvariant("syntax captures do not fit usize")
            })?;
            if hir_nodes != expected_nodes || captures != expected_captures {
                return Err(CaptureBuildError::InternalInvariant(
                    "syntax summary differs from shared prefix/class inspection",
                ));
            }
            let Some(participating_capture_indices) = uniform_participating_capture_indices else {
                return Ok(CapturePrefixClassParticipationBuild {
                    plan: None,
                    planner_work: work,
                });
            };
            let engine = match PrefixClassAlternationPlan::build_uniform_participation(
                prefixes,
                [
                    classes[0]
                        .ranges()
                        .iter()
                        .copied()
                        .map(capture_class_bytes_range_tuple),
                    classes[1]
                        .ranges()
                        .iter()
                        .copied()
                        .map(capture_class_bytes_range_tuple),
                ],
                limits.prefix_class_participation,
            ) {
                Ok(engine) => engine,
                Err(error) if optional_prefix_class_build_refusal(&error) => {
                    return Ok(CapturePrefixClassParticipationBuild {
                        plan: None,
                        planner_work: work,
                    });
                }
                Err(error) => {
                    return Err(CaptureBuildError::PrefixClassParticipation(error));
                }
            };
            Ok(CapturePrefixClassParticipationBuild {
                plan: Some(Arc::new(CapturePrefixClassParticipationPlan {
                    engine,
                    schema: PrefixClassUniformParticipationSchema {
                        participating_with_overall: 2,
                        capture_schema_slots: 3,
                    },
                    participating_capture_indices,
                })),
                planner_work: work,
            })
        }
    }
}

fn capture_class_bytes_range_tuple(range: ClassBytesRange) -> (u8, u8) {
    (range.start(), range.end())
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
    /// scalar classes lower to compact canonical-scalar transitions with
    /// checked bounded UTF-8 decoding.
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
    #[allow(
        clippy::too_many_lines,
        reason = "the single-parse proof, selector, replay, identity, and accounting publication remain locally auditable"
    )]
    pub fn build(self) -> Result<CaptureRegex, CaptureBuildError> {
        let limits = self.limits;
        let unicode = self.profile.options.unicode;
        let case_insensitive = self.profile.options.case_insensitive;
        let line_terminator = self.profile.options.line_terminator;
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
        let explicit_captures = usize::try_from(syntax.captures).map_err(|_| {
            CaptureBuildError::InternalInvariant("syntax capture count does not fit usize")
        })?;
        if explicit_captures != rust.hir.properties().explicit_captures_len() {
            return Err(CaptureBuildError::InternalInvariant(
                "syntax capture count differs from HIR properties",
            ));
        }
        let mut accounting = CaptureHirAccounting::default();
        let required_literal = if let Some(mut required_limits) = limits.required_literal {
            let remaining_hir_work = limits.max_hir_work.checked_sub(accounting.work).ok_or(
                CaptureBuildError::HirResource {
                    resource: "work",
                    required: accounting.work,
                    limit: limits.max_hir_work,
                },
            )?;
            required_limits.max_planner_work =
                required_limits.max_planner_work.min(remaining_hir_work);
            required_limits.max_hir_depth = required_limits.max_hir_depth.min(limits.max_hir_depth);
            match capture_required_literal::build_from_hir(
                &rust.hir,
                Arc::clone(&syntax_key),
                required_limits,
            ) {
                Ok(outcome) => {
                    charge_hir(&mut accounting, outcome.planner_work, limits.max_hir_work)?;
                    outcome.plan
                }
                Err(failure) => {
                    charge_hir(&mut accounting, failure.planner_work, limits.max_hir_work)?;
                    if optional_required_literal_refusal(&failure.source) {
                        None
                    } else {
                        return Err(CaptureBuildError::RequiredLiteral(failure.source));
                    }
                }
            }
        } else {
            None
        };
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
        let uniform_participating_captures =
            capture_participation(&rust.hir, 1, &limits, &mut accounting)?.uniform;
        let prefix_class_participation = build_prefix_class_participation(
            &rust.hir,
            &syntax,
            unicode,
            case_insensitive,
            selector.has_terminal_frontier(),
            uniform_participating_captures,
            &limits,
            &mut accounting,
        )?;
        let ast = lower_hir(&rust.hir, 1, line_terminator, &limits, &mut accounting)?;
        let program =
            Arc::new(Program::compile(&ast, limits.engine).map_err(CaptureBuildError::Engine)?);
        let engine_report = program.build_report().clone();
        if engine_report.captures != accounting.capture_slots {
            return Err(CaptureBuildError::InternalInvariant(
                "capture compiler schema differs from parsed HIR",
            ));
        }
        let plan_identity = CapturePlanIdentity {
            syntax: syntax_key,
            operation: CaptureOperation::CountParticipatingNonempty,
            plan: if prefix_class_participation.plan.is_some() {
                CapturePlanKind::UniformPrefixClassParticipation
            } else if uniform_participating_captures.is_some() {
                CapturePlanKind::LinearSelectorUniformParticipation
            } else {
                CapturePlanKind::LinearSelectorPersistentHistory
            },
            capture_profile: CaptureProfile::RustRegexBytes1_12_4,
            selector_plan_id: selector.plan_id(),
            required_literal: required_literal
                .as_ref()
                .map(|plan| plan.build_report().identity.clone()),
            prefix_class_participation: prefix_class_participation
                .plan
                .as_ref()
                .map(|plan| plan.identity()),
        };
        let prefix_class_participation_build = prefix_class_participation
            .plan
            .as_ref()
            .map(|plan| plan.engine.uniform_participation_build_accounting());
        let report = CaptureBuildReport {
            admission,
            syntax,
            hir: accounting,
            engine: engine_report,
            selector: selector_accounting,
            uniform_participating_captures,
            required_literal: required_literal
                .as_ref()
                .map(|plan| plan.build_report().accounting),
            prefix_class_participation_planner_work: prefix_class_participation.planner_work,
            prefix_class_participation: prefix_class_participation_build,
            plan_identity,
        };
        Ok(CaptureRegex {
            engine: HistoryRegex::from_program(program),
            selector: Arc::new(selector),
            required_literal,
            prefix_class_participation: prefix_class_participation.plan,
            uniform_count_minimum_match_bytes: uniform_participating_captures
                .and_then(|_| rust.hir.properties().minimum_len())
                .filter(|minimum| *minimum > 0),
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
    required_literal: Option<CaptureRequiredLiteralPlan>,
    prefix_class_participation: Option<Arc<CapturePrefixClassParticipationPlan>>,
    /// Positive whole-match minimum from the same canonical HIR that proved
    /// uniform capture participation. `None` retains the span validator for
    /// nullable or empty-language plans.
    uniform_count_minimum_match_bytes: Option<usize>,
    build_limits: CaptureBuildLimits,
    report: CaptureBuildReport,
}

impl CaptureRegex {
    /// Construction and plan identity.
    #[must_use]
    pub const fn build_report(&self) -> &CaptureBuildReport {
        &self.report
    }

    /// Optional generic line-candidate proof built from this exact capture HIR.
    #[must_use]
    pub const fn required_literal_plan(&self) -> Option<&CaptureRequiredLiteralPlan> {
        self.required_literal.as_ref()
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
        self.iteration_identity_with_config(run_limits, CaptureSearchConfig::LEFTMOST)
    }

    /// Complete identity for one bounded capture-iteration invocation under
    /// an explicit search policy.
    #[must_use]
    pub fn iteration_identity_with_config(
        &self,
        run_limits: AggregateLimits,
        search: CaptureSearchConfig,
    ) -> CaptureIterationIdentity {
        CaptureIterationIdentity {
            syntax: Arc::clone(&self.report.plan_identity.syntax),
            capture_profile: self.report.plan_identity.capture_profile,
            plan: CaptureIterationPlanKind::RestartedPersistentHistory,
            search,
            build_limits: self.build_limits,
            run_limits,
        }
    }

    /// Return the first leftmost-first capture record under explicit
    /// per-search limits, together with exact execution accounting.
    pub fn captures(
        &self,
        haystack: &[u8],
        limits: EngineSearchLimits,
    ) -> Result<EngineSearchOutcome, EngineSearchError> {
        self.captures_with_config(haystack, CaptureSearchConfig::LEFTMOST, limits)
    }

    /// Return the first capture record under explicit match-end,
    /// match-priority and start-injection policies.
    pub fn captures_with_config(
        &self,
        haystack: &[u8],
        config: CaptureSearchConfig,
        limits: EngineSearchLimits,
    ) -> Result<EngineSearchOutcome, EngineSearchError> {
        self.captures_window_with_config(haystack, Window::all(haystack), config, limits)
    }

    /// Return the first capture record inside `window` under an explicit
    /// match-end selection and start-injection policy. Consuming transitions
    /// stay inside the window while assertions retain original-haystack
    /// context.
    pub fn captures_window_with_config(
        &self,
        haystack: &[u8],
        window: Window,
        config: CaptureSearchConfig,
        limits: EngineSearchLimits,
    ) -> Result<EngineSearchOutcome, EngineSearchError> {
        self.engine
            .captures_with_config(haystack, window, config, limits)
    }

    /// Query whether `span` is an exact match inside `window`, returning its
    /// prioritized capture history when it is. An ordinary non-match is a
    /// successful outcome with no capture record.
    pub fn captures_exact_window(
        &self,
        haystack: &[u8],
        window: Window,
        span: EngineSpan,
        limits: EngineSearchLimits,
    ) -> Result<EngineSearchOutcome, EngineSearchError> {
        self.engine.captures_exact(haystack, window, span, limits)
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
        self.captures_iter_window_with_config(
            haystack,
            Window::all(haystack),
            CaptureSearchConfig::LEFTMOST,
            limits,
        )
    }

    /// Collect every match wholly inside `window` while retaining assertion
    /// context from the original haystack.
    pub fn captures_iter_window(
        &self,
        haystack: &[u8],
        window: Window,
        limits: AggregateLimits,
    ) -> Result<CaptureIterationReport, CaptureIterationError> {
        self.captures_iter_window_with_config(
            haystack,
            window,
            CaptureSearchConfig::LEFTMOST,
            limits,
        )
    }

    /// Collect every match under explicit match-end, match-priority and
    /// start-injection policies.
    pub fn captures_iter_window_with_config(
        &self,
        haystack: &[u8],
        window: Window,
        config: CaptureSearchConfig,
        limits: AggregateLimits,
    ) -> Result<CaptureIterationReport, CaptureIterationError> {
        let identity = self.iteration_identity_with_config(limits, config);
        let AggregateOutcome {
            captures,
            searches,
            total_state_visits,
            total_slot_copies: _,
            total_history_nodes,
        } = self
            .engine
            .captures_iter_with_config(haystack, window, config, limits)
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
        clippy::result_large_err,
        clippy::too_many_lines,
        reason = "selector, replay, and complete checked reducer accounting stay locally auditable; terminal errors retain the allocation-free Count P/A receipt inline"
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
        if let Some(plan) = &self.prefix_class_participation {
            return self.count_prefix_class_participation(
                plan,
                haystack,
                limits,
                selector_limits,
                identity,
            );
        }
        if let Some(participating) = self.report.uniform_participating_captures {
            if let Some(minimum_match_bytes) = self.uniform_count_minimum_match_bytes {
                return self.count_uniform_captures(
                    haystack,
                    limits,
                    selector_limits,
                    identity,
                    participating,
                    minimum_match_bytes,
                );
            }
            let selected = self
                .selector
                .admit_spans_observed(
                    haystack,
                    0..haystack.len(),
                    SelectorStrategy::ReverseSequentialRows,
                    selector_limits,
                )
                .map_err(|source| CaptureExecutionError {
                    identity: Box::new(identity.clone()),
                    source: CaptureExecutionSource::Selector(source),
                    selector_receipt: None,
                    prefix_class_participation_prospective: None,
                })?;
            let selector_accounting = selected.accounting();
            let mut matches = 0_usize;
            for span in selected.as_slice() {
                if span.start == span.end {
                    return Err(Self::history_error(
                        &identity,
                        EngineSearchError::EmptyMatch,
                    ));
                }
                matches = checked_capture_add(
                    &identity,
                    matches,
                    1,
                    EngineResource::Results,
                    limits.aggregate.max_results,
                )?;
            }
            let participating_with_overall =
                participating
                    .checked_add(1)
                    .ok_or_else(|| CaptureExecutionError {
                        identity: Box::new(identity.clone()),
                        source: CaptureExecutionSource::InternalInvariant(
                            "uniform capture participation overflowed usize",
                        ),
                        selector_receipt: None,
                        prefix_class_participation_prospective: None,
                    })?;
            let count = checked_capture_mul(
                &identity,
                matches,
                participating_with_overall,
                EngineResource::CaptureCount,
                limits.aggregate.max_capture_count,
            )?;
            let all_groups = self.report.engine.captures.checked_add(1).ok_or_else(|| {
                CaptureExecutionError {
                    identity: Box::new(identity.clone()),
                    source: CaptureExecutionSource::InternalInvariant(
                        "capture schema overflowed usize",
                    ),
                    selector_receipt: None,
                    prefix_class_participation_prospective: None,
                }
            })?;
            let capture_events = checked_capture_mul(
                &identity,
                matches,
                all_groups,
                EngineResource::CaptureEvents,
                limits.aggregate.max_capture_events,
            )?;
            return Ok(CaptureExecutionReport {
                identity,
                accounting: CaptureCountOutcome {
                    count,
                    matches,
                    searches: 0,
                    total_state_visits: 0,
                    total_history_nodes: 0,
                    total_history_walk: 0,
                    peak_threads: 0,
                },
                selector_certificate: Some(selected.certificate().clone()),
                selector_accounting: Some(selector_accounting),
                selector_receipt: None,
                prefix_class_participation: None,
                capture_events,
                combined_peak_bytes: selector_accounting.peak_bytes,
            });
        }
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
                selector_receipt: None,
                prefix_class_participation_prospective: None,
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
                selector_receipt: None,
                prefix_class_participation_prospective: None,
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
                    selector_receipt: None,
                    prefix_class_participation_prospective: None,
                })?;
            combined_peak_bytes = combined_peak_bytes.max(replay_combined_peak);
            let captures = replay.captures.ok_or_else(|| CaptureExecutionError {
                identity: Box::new(identity.clone()),
                source: CaptureExecutionSource::InternalInvariant(
                    "selector-certified span produced no tagged winner",
                ),
                selector_receipt: None,
                prefix_class_participation_prospective: None,
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
            selector_certificate: Some(selected.certificate().clone()),
            selector_accounting: Some(selector_accounting),
            selector_receipt: None,
            prefix_class_participation: None,
            capture_events,
            combined_peak_bytes,
        })
    }

    #[allow(
        clippy::result_large_err,
        clippy::too_many_lines,
        reason = "direct terminals retain the complete fixed-layout prospective inline beside source-free U3-control admission and co-live publication"
    )]
    fn count_prefix_class_participation(
        &self,
        plan: &CapturePrefixClassParticipationPlan,
        haystack: &[u8],
        limits: CaptureRunLimits,
        selector_limits: SelectorOperationLimits,
        identity: CaptureCacheIdentity,
    ) -> Result<CaptureExecutionReport, CaptureExecutionError> {
        let prospective = plan
            .engine
            .uniform_participation_prospective(
                haystack.len(),
                plan.schema,
                limits.prefix_class_participation,
            )
            .map_err(|source| CaptureExecutionError {
                identity: Box::new(identity.clone()),
                source: CaptureExecutionSource::PrefixClassParticipation(source),
                selector_receipt: None,
                prefix_class_participation_prospective: None,
            })?;
        let selector_control = self
            .selector
            .fixed_scalar_dense_count_prospective(
                haystack.len(),
                SelectorStrategy::ReverseSequentialRows,
            )
            .map_err(|source| CaptureExecutionError {
                identity: Box::new(identity.clone()),
                source: CaptureExecutionSource::Selector(source),
                selector_receipt: None,
                prefix_class_participation_prospective: Some(prospective),
            })?;
        let minimum_match_bytes =
            self.uniform_count_minimum_match_bytes
                .ok_or_else(|| CaptureExecutionError {
                    identity: Box::new(identity.clone()),
                    source: CaptureExecutionSource::InternalInvariant(
                        "direct prefix/class plan lost its positive minimum width",
                    ),
                    selector_receipt: None,
                    prefix_class_participation_prospective: Some(prospective),
                })?;
        let selector_control = uniform_capture_prospective(
            &selector_control,
            haystack.len(),
            minimum_match_bytes,
            plan.schema.participating_with_overall,
            plan.schema.capture_schema_slots,
            limits.aggregate,
        )
        .map_err(|source| CaptureExecutionError {
            identity: Box::new(identity.clone()),
            source: CaptureExecutionSource::History(source),
            selector_receipt: None,
            prefix_class_participation_prospective: Some(prospective),
        })?;
        if selector_control.selector.terminal_frontier
            || selector_control.matches != prospective.results
            || selector_control.capture_count != prospective.capture_count
            || selector_control.capture_events != prospective.capture_events
        {
            return Err(CaptureExecutionError {
                identity: Box::new(identity.clone()),
                source: CaptureExecutionSource::InternalInvariant(
                    "direct prefix/class envelope diverged from its retained U3 control",
                ),
                selector_receipt: None,
                prefix_class_participation_prospective: Some(prospective),
            });
        }
        let retained_fallback_bytes = self
            .report
            .engine
            .program_bytes
            .checked_add(self.report.selector.program_bytes)
            .ok_or_else(|| CaptureExecutionError {
                identity: Box::new(identity.clone()),
                source: CaptureExecutionSource::InternalInvariant(
                    "capture retained fallback bytes overflowed usize",
                ),
                selector_receipt: None,
                prefix_class_participation_prospective: Some(prospective),
            })?;
        let direct_peak_bytes = retained_fallback_bytes
            .checked_add(prospective.peak_bytes)
            .ok_or_else(|| CaptureExecutionError {
                identity: Box::new(identity.clone()),
                source: CaptureExecutionSource::InternalInvariant(
                    "capture direct co-live peak overflowed usize",
                ),
                selector_receipt: None,
                prefix_class_participation_prospective: Some(prospective),
            })?;
        let combined_peak_bytes = direct_peak_bytes.max(selector_control.selector.peak_bytes);
        if combined_peak_bytes > limits.max_combined_peak_bytes {
            return Err(CaptureExecutionError {
                identity: Box::new(identity),
                source: CaptureExecutionSource::CombinedPeak {
                    needed: combined_peak_bytes,
                    limit: limits.max_combined_peak_bytes,
                },
                selector_receipt: None,
                prefix_class_participation_prospective: Some(prospective),
            });
        }
        enforce_selector_control(selector_control.selector, selector_limits).map_err(|source| {
            CaptureExecutionError {
                identity: Box::new(identity.clone()),
                source: CaptureExecutionSource::Selector(source),
                selector_receipt: None,
                prefix_class_participation_prospective: Some(prospective),
            }
        })?;
        let result = plan
            .engine
            .count_uniform_participation(haystack, plan.schema, limits.prefix_class_participation)
            .map_err(|source| CaptureExecutionError {
                identity: Box::new(identity.clone()),
                source: CaptureExecutionSource::PrefixClassParticipation(source),
                selector_receipt: None,
                prefix_class_participation_prospective: Some(prospective),
            })?;
        if result.accounting.prospective != prospective
            || identity.plan.prefix_class_participation != Some(plan.identity())
            || identity.plan.plan != CapturePlanKind::UniformPrefixClassParticipation
        {
            return Err(CaptureExecutionError {
                identity: Box::new(identity),
                source: CaptureExecutionSource::InternalInvariant(
                    "direct prefix/class execution diverged from its published plan",
                ),
                selector_receipt: None,
                prefix_class_participation_prospective: Some(prospective),
            });
        }
        Ok(CaptureExecutionReport {
            identity,
            accounting: CaptureCountOutcome {
                count: result.capture_count,
                matches: result.matches,
                searches: 0,
                total_state_visits: 0,
                total_history_nodes: 0,
                total_history_walk: 0,
                peak_threads: 0,
            },
            selector_certificate: None,
            selector_accounting: None,
            selector_receipt: None,
            prefix_class_participation: Some(result.accounting),
            capture_events: result.accounting.actual.capture_events,
            combined_peak_bytes,
        })
    }

    #[allow(
        clippy::result_large_err,
        clippy::too_many_lines,
        reason = "the uniform route preserves its complete selector P/A receipt on every terminal and keeps prospective publication adjacent to reduction"
    )]
    fn count_uniform_captures(
        &self,
        haystack: &[u8],
        limits: CaptureRunLimits,
        selector_limits: SelectorOperationLimits,
        identity: CaptureCacheIdentity,
        participating: usize,
        minimum_match_bytes: usize,
    ) -> Result<CaptureExecutionReport, CaptureExecutionError> {
        let participating_with_overall =
            participating
                .checked_add(1)
                .ok_or_else(|| CaptureExecutionError {
                    identity: Box::new(identity.clone()),
                    source: CaptureExecutionSource::InternalInvariant(
                        "uniform capture participation overflowed usize",
                    ),
                    selector_receipt: None,
                    prefix_class_participation_prospective: None,
                })?;
        let all_groups =
            self.report
                .engine
                .captures
                .checked_add(1)
                .ok_or_else(|| CaptureExecutionError {
                    identity: Box::new(identity.clone()),
                    source: CaptureExecutionSource::InternalInvariant(
                        "capture schema overflowed usize",
                    ),
                    selector_receipt: None,
                    prefix_class_participation_prospective: None,
                })?;
        let terminal_frontier = self.selector.has_terminal_frontier();
        let mut published = None;
        let mut owner_refusal = None;
        let mut observer =
            |selector: SelectorOperationProspective| match uniform_capture_prospective(
                &selector,
                haystack.len(),
                minimum_match_bytes,
                participating_with_overall,
                all_groups,
                limits.aggregate,
            ) {
                Ok(prospective) => {
                    published = Some(prospective);
                    Ok(())
                }
                Err(source) => {
                    owner_refusal = Some(source);
                    Err(SelectorError::InternalInvariant(
                        "capture uniform Count prospective refused",
                    ))
                }
            };
        let attempt = if terminal_frontier {
            self.selector
                .admit_count_with_terminal_frontier_receipt_observer(
                    haystack,
                    0..haystack.len(),
                    SelectorStrategy::ReverseSequentialRows,
                    selector_limits,
                    usize::MAX,
                    &mut observer,
                )
        } else {
            self.selector.admit_count_with_receipt_observer(
                haystack,
                0..haystack.len(),
                SelectorStrategy::ReverseSequentialRows,
                selector_limits,
                usize::MAX,
                &mut observer,
            )
        };
        let attempt = match attempt {
            Ok(attempt) => attempt,
            Err(SelectorOperationAttemptError { source, receipt }) => {
                let source = owner_refusal.map_or(
                    CaptureExecutionSource::Selector(source),
                    CaptureExecutionSource::History,
                );
                return Err(CaptureExecutionError {
                    identity: Box::new(identity),
                    source,
                    selector_receipt: Some(receipt),
                    prefix_class_participation_prospective: None,
                });
            }
        };
        if owner_refusal.is_some() {
            return Err(CaptureExecutionError {
                identity: Box::new(identity),
                source: CaptureExecutionSource::InternalInvariant(
                    "selector succeeded after capture owner refused its prospective",
                ),
                selector_receipt: Some(attempt.receipt),
                prefix_class_participation_prospective: None,
            });
        }
        let prospective = published.ok_or_else(|| CaptureExecutionError {
            identity: Box::new(identity.clone()),
            source: CaptureExecutionSource::InternalInvariant(
                "uniform Count succeeded without publishing its prospective",
            ),
            selector_receipt: Some(attempt.receipt.clone()),
            prefix_class_participation_prospective: None,
        })?;
        if prospective.selector.terminal_frontier != terminal_frontier
            || attempt.receipt.prospective != Some(prospective.selector)
        {
            return Err(CaptureExecutionError {
                identity: Box::new(identity),
                source: CaptureExecutionSource::InternalInvariant(
                    "uniform Count route diverged from its published prospective",
                ),
                selector_receipt: Some(attempt.receipt),
                prefix_class_participation_prospective: None,
            });
        }
        let selected = attempt.admitted;
        let selector_receipt = attempt.receipt;
        let selector_accounting = selected.accounting();
        let matches = selected.value();
        if matches > prospective.matches
            || selector_accounting.emitted_matches != matches
            || selector_accounting.output_bytes != 0
        {
            return Err(CaptureExecutionError {
                identity: Box::new(identity),
                source: CaptureExecutionSource::InternalInvariant(
                    "uniform Count actual escaped its positive-width prospective",
                ),
                selector_receipt: Some(selector_receipt),
                prefix_class_participation_prospective: None,
            });
        }
        let count = matches
            .checked_mul(participating_with_overall)
            .ok_or_else(|| CaptureExecutionError {
                identity: Box::new(identity.clone()),
                source: CaptureExecutionSource::History(EngineSearchError::BoundOverflow(
                    EngineResource::CaptureCount,
                )),
                selector_receipt: Some(selector_receipt.clone()),
                prefix_class_participation_prospective: None,
            })?;
        let capture_events =
            matches
                .checked_mul(all_groups)
                .ok_or_else(|| CaptureExecutionError {
                    identity: Box::new(identity.clone()),
                    source: CaptureExecutionSource::History(EngineSearchError::BoundOverflow(
                        EngineResource::CaptureEvents,
                    )),
                    selector_receipt: Some(selector_receipt.clone()),
                    prefix_class_participation_prospective: None,
                })?;
        if count > prospective.capture_count || capture_events > prospective.capture_events {
            return Err(CaptureExecutionError {
                identity: Box::new(identity),
                source: CaptureExecutionSource::InternalInvariant(
                    "uniform capture arithmetic escaped its prospective",
                ),
                selector_receipt: Some(selector_receipt),
                prefix_class_participation_prospective: None,
            });
        }
        Ok(CaptureExecutionReport {
            identity,
            accounting: CaptureCountOutcome {
                count,
                matches,
                searches: 0,
                total_state_visits: 0,
                total_history_nodes: 0,
                total_history_walk: 0,
                peak_threads: 0,
            },
            selector_certificate: Some(selected.certificate().clone()),
            selector_accounting: Some(selector_accounting),
            selector_receipt: Some(selector_receipt),
            prefix_class_participation: None,
            capture_events,
            combined_peak_bytes: selector_accounting.peak_bytes,
        })
    }

    fn history_error(
        identity: &CaptureCacheIdentity,
        source: EngineSearchError,
    ) -> CaptureExecutionError {
        CaptureExecutionError {
            identity: Box::new(identity.clone()),
            source: CaptureExecutionSource::History(source),
            selector_receipt: None,
            prefix_class_participation_prospective: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UniformCaptureProspective {
    selector: SelectorOperationProspective,
    matches: usize,
    capture_count: usize,
    capture_events: usize,
}

fn enforce_selector_control(
    prospective: SelectorOperationProspective,
    limits: SelectorOperationLimits,
) -> Result<(), SelectorError> {
    for (required, limit, resource) in [
        (
            prospective.boundaries,
            limits.max_boundaries,
            SelectorResource::Boundaries,
        ),
        (
            prospective.table_cells,
            limits.max_table_cells,
            SelectorResource::TableCells,
        ),
        (
            prospective.random_access_bytes,
            limits.max_random_access_bytes,
            SelectorResource::RandomAccessBytes,
        ),
        (
            prospective.scratch_bytes,
            limits.max_scratch_bytes,
            SelectorResource::ScratchBytes,
        ),
        (
            prospective.log_bytes,
            limits.max_log_bytes,
            SelectorResource::LogBytes,
        ),
        (
            prospective.sequential_bytes,
            limits.max_sequential_bytes,
            SelectorResource::SequentialBytes,
        ),
        (
            prospective.match_events,
            limits.max_match_events,
            SelectorResource::MatchEvents,
        ),
        (
            prospective.output_matches,
            limits.max_output_matches,
            SelectorResource::OutputMatches,
        ),
        (
            prospective.output_bytes,
            limits.max_output_bytes,
            SelectorResource::OutputBytes,
        ),
        (
            prospective.span_sum,
            limits.max_span_sum,
            SelectorResource::SpanSum,
        ),
        (
            prospective.peak_bytes,
            limits.max_peak_bytes,
            SelectorResource::PeakBytes,
        ),
        (
            prospective.work_bound,
            limits.max_work,
            SelectorResource::ExecutionWork,
        ),
    ] {
        if required > limit {
            return Err(SelectorError::ResourceLimit {
                resource,
                required,
                limit,
            });
        }
    }
    Ok(())
}

fn uniform_capture_prospective(
    selector: &SelectorOperationProspective,
    haystack_len: usize,
    minimum_match_bytes: usize,
    participating_with_overall: usize,
    all_groups: usize,
    limits: AggregateLimits,
) -> Result<UniformCaptureProspective, EngineSearchError> {
    if minimum_match_bytes == 0 || selector.output_bytes != 0 {
        return Err(EngineSearchError::InvalidProgram);
    }
    let matches = haystack_len
        .checked_div(minimum_match_bytes)
        .ok_or(EngineSearchError::InvalidProgram)?;
    if matches > selector.output_matches {
        return Err(EngineSearchError::InvalidProgram);
    }
    let capture_count =
        matches
            .checked_mul(participating_with_overall)
            .ok_or(EngineSearchError::BoundOverflow(
                EngineResource::CaptureCount,
            ))?;
    let capture_events =
        matches
            .checked_mul(all_groups)
            .ok_or(EngineSearchError::BoundOverflow(
                EngineResource::CaptureEvents,
            ))?;
    enforce_capture_prospective(matches, limits.max_results, EngineResource::Results)?;
    enforce_capture_prospective(
        capture_count,
        limits.max_capture_count,
        EngineResource::CaptureCount,
    )?;
    enforce_capture_prospective(
        capture_events,
        limits.max_capture_events,
        EngineResource::CaptureEvents,
    )?;
    Ok(UniformCaptureProspective {
        selector: *selector,
        matches,
        capture_count,
        capture_events,
    })
}

fn enforce_capture_prospective(
    required: usize,
    limit: usize,
    resource: EngineResource,
) -> Result<(), EngineSearchError> {
    if required > limit {
        return Err(EngineSearchError::Resource {
            kind: resource,
            required,
            limit,
        });
    }
    Ok(())
}

#[allow(
    clippy::result_large_err,
    reason = "capture terminals retain the complete allocation-free selector P/A receipt inline"
)]
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
            selector_receipt: None,
            prefix_class_participation_prospective: None,
        })
}

#[allow(
    clippy::result_large_err,
    reason = "capture terminals retain the complete allocation-free selector P/A receipt inline"
)]
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
            selector_receipt: None,
            prefix_class_participation_prospective: None,
        })?;
    if required > limit {
        return Err(CaptureExecutionError {
            identity: Box::new(identity.clone()),
            source: CaptureExecutionSource::History(EngineSearchError::Resource {
                kind: resource,
                required,
                limit,
            }),
            selector_receipt: None,
            prefix_class_participation_prospective: None,
        });
    }
    Ok(required)
}

#[allow(
    clippy::result_large_err,
    reason = "capture terminals retain the complete allocation-free selector P/A receipt inline"
)]
fn checked_capture_mul(
    identity: &CaptureCacheIdentity,
    left: usize,
    right: usize,
    resource: EngineResource,
    limit: usize,
) -> Result<usize, CaptureExecutionError> {
    let required = left
        .checked_mul(right)
        .ok_or_else(|| CaptureExecutionError {
            identity: Box::new(identity.clone()),
            source: CaptureExecutionSource::History(EngineSearchError::BoundOverflow(resource)),
            selector_receipt: None,
            prefix_class_participation_prospective: None,
        })?;
    if required > limit {
        return Err(CaptureExecutionError {
            identity: Box::new(identity.clone()),
            source: CaptureExecutionSource::History(EngineSearchError::Resource {
                kind: resource,
                required,
                limit,
            }),
            selector_receipt: None,
            prefix_class_participation_prospective: None,
        });
    }
    Ok(required)
}

#[derive(Clone, Copy)]
struct CaptureParticipation {
    uniform: Option<usize>,
    stable_set: bool,
    can_participate: bool,
}

impl CaptureParticipation {
    const CAPTURE_FREE: Self = Self {
        uniform: Some(0),
        stable_set: true,
        can_participate: false,
    };
}

/// Prove only the cardinality needed by the reducer while charging this
/// auxiliary traversal to the same construction-work ledger as lowering.
fn capture_participation(
    hir: &Hir,
    depth: usize,
    limits: &CaptureBuildLimits,
    accounting: &mut CaptureHirAccounting,
) -> Result<CaptureParticipation, CaptureBuildError> {
    if depth > limits.max_hir_depth {
        return Err(CaptureBuildError::HirResource {
            resource: "depth",
            required: depth,
            limit: limits.max_hir_depth,
        });
    }
    charge_hir(accounting, 1, limits.max_hir_work)?;
    match hir.kind() {
        HirKind::Empty | HirKind::Literal(_) | HirKind::Class(_) | HirKind::Look(_) => {
            Ok(CaptureParticipation::CAPTURE_FREE)
        }
        HirKind::Capture(capture) => {
            let child = capture_participation(
                capture.sub.as_ref(),
                next_depth(depth)?,
                limits,
                accounting,
            )?;
            let uniform = child
                .uniform
                .map(|count| {
                    checked_dimension_add(count, 1, "capture participation", limits.max_hir_work)
                })
                .transpose()?;
            Ok(CaptureParticipation {
                uniform,
                stable_set: child.stable_set,
                can_participate: true,
            })
        }
        HirKind::Repetition(repetition) => {
            let child = capture_participation(
                repetition.sub.as_ref(),
                next_depth(depth)?,
                limits,
                accounting,
            )?;
            if repetition.max == Some(0) || !child.can_participate {
                return Ok(CaptureParticipation::CAPTURE_FREE);
            }
            let can_repeat = match repetition.max {
                Some(maximum) => maximum > 1,
                None => true,
            };
            if repetition.min == 0 || (can_repeat && !child.stable_set) {
                return Ok(CaptureParticipation {
                    uniform: None,
                    stable_set: false,
                    can_participate: true,
                });
            }
            Ok(child)
        }
        HirKind::Concat(children) => {
            let mut combined = CaptureParticipation::CAPTURE_FREE;
            for child in children {
                let child = capture_participation(child, next_depth(depth)?, limits, accounting)?;
                charge_hir(accounting, 1, limits.max_hir_work)?;
                combined = CaptureParticipation {
                    uniform: match (combined.uniform, child.uniform) {
                        (Some(left), Some(right)) => Some(checked_dimension_add(
                            left,
                            right,
                            "capture participation",
                            limits.max_hir_work,
                        )?),
                        _ => None,
                    },
                    stable_set: combined.stable_set && child.stable_set,
                    can_participate: combined.can_participate || child.can_participate,
                };
            }
            Ok(combined)
        }
        HirKind::Alternation(children) => {
            let mut uniform = None;
            let mut can_participate = false;
            for (index, child) in children.iter().enumerate() {
                let child = capture_participation(child, next_depth(depth)?, limits, accounting)?;
                charge_hir(accounting, 1, limits.max_hir_work)?;
                uniform = if index == 0 || uniform == child.uniform {
                    child.uniform
                } else {
                    None
                };
                can_participate |= child.can_participate;
            }
            Ok(CaptureParticipation {
                uniform,
                // Capture IDs are unique HIR nodes, so distinct alternatives
                // have one stable set only when all of them are capture-free.
                stable_set: !can_participate,
                can_participate,
            })
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the complete checked HIR-to-capture-AST mapping remains locally auditable"
)]
fn lower_hir(
    hir: &Hir,
    depth: usize,
    line_terminator: u8,
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
        HirKind::Look(Look::StartLF) if line_terminator == b'\n' => {
            Ok(Ast::Assert(CaptureAssertion::StartLf))
        }
        HirKind::Look(Look::EndLF) if line_terminator == b'\n' => {
            Ok(Ast::Assert(CaptureAssertion::EndLf))
        }
        HirKind::Look(Look::StartLF) => {
            Ok(Ast::Assert(CaptureAssertion::StartLine(line_terminator)))
        }
        HirKind::Look(Look::EndLF) => Ok(Ast::Assert(CaptureAssertion::EndLine(line_terminator))),
        HirKind::Look(Look::WordAscii) => Ok(Ast::Assert(CaptureAssertion::WordAscii)),
        HirKind::Look(Look::WordAsciiNegate) => Ok(Ast::Assert(CaptureAssertion::WordAsciiNegate)),
        HirKind::Look(Look::WordStartAscii) => Ok(Ast::Assert(CaptureAssertion::WordStartAscii)),
        HirKind::Look(Look::WordEndAscii) => Ok(Ast::Assert(CaptureAssertion::WordEndAscii)),
        HirKind::Look(Look::WordStartHalfAscii) => {
            Ok(Ast::Assert(CaptureAssertion::WordStartHalfAscii))
        }
        HirKind::Look(Look::WordEndHalfAscii) => {
            Ok(Ast::Assert(CaptureAssertion::WordEndHalfAscii))
        }
        HirKind::Look(Look::WordUnicode) => Ok(Ast::Assert(CaptureAssertion::WordUnicode)),
        HirKind::Look(Look::StartCRLF) => Ok(Ast::Assert(CaptureAssertion::StartCrlf)),
        HirKind::Look(Look::EndCRLF) => Ok(Ast::Assert(CaptureAssertion::EndCrlf)),
        HirKind::Look(Look::WordUnicodeNegate) => {
            Ok(Ast::Assert(CaptureAssertion::WordUnicodeNegate))
        }
        HirKind::Look(Look::WordStartUnicode) => {
            Ok(Ast::Assert(CaptureAssertion::WordStartUnicode))
        }
        HirKind::Look(Look::WordEndUnicode) => Ok(Ast::Assert(CaptureAssertion::WordEndUnicode)),
        HirKind::Look(Look::WordStartHalfUnicode) => {
            Ok(Ast::Assert(CaptureAssertion::WordStartHalfUnicode))
        }
        HirKind::Look(Look::WordEndHalfUnicode) => {
            Ok(Ast::Assert(CaptureAssertion::WordEndHalfUnicode))
        }
        HirKind::Capture(capture) => {
            accounting.capture_slots =
                accounting
                    .capture_slots
                    .max(usize::try_from(capture.index).map_err(|_| {
                        CaptureBuildError::InternalInvariant("capture index does not fit usize")
                    })?);
            Ok(Ast::Capture {
                index: capture.index,
                name: capture.name.as_ref().map(ToString::to_string),
                child: Box::new(lower_hir(
                    capture.sub.as_ref(),
                    next_depth(depth)?,
                    line_terminator,
                    limits,
                    accounting,
                )?),
            })
        }
        HirKind::Repetition(repetition) => Ok(Ast::Repeat {
            child: Box::new(lower_hir(
                repetition.sub.as_ref(),
                next_depth(depth)?,
                line_terminator,
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
        HirKind::Concat(children) => lower_children(
            children,
            depth,
            line_terminator,
            limits,
            accounting,
            Ast::Concat,
        ),
        HirKind::Alternation(children) => lower_children(
            children,
            depth,
            line_terminator,
            limits,
            accounting,
            Ast::Alt,
        ),
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
    line_terminator: u8,
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
        lowered.push(lower_hir(
            child,
            child_depth,
            line_terminator,
            limits,
            accounting,
        )?);
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
