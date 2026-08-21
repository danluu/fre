//! Capture-preserving composition over an ordinary Span selector.
//!
//! Capture output is deliberately separate from [`crate::OutputContract`].
//! The selector remains an independently serializable capture-free semantic
//! program. A separately authenticated `CaptureProgramV1` replays only the
//! selected span into fixed caller-owned group storage.

use core::{fmt, mem::size_of};

pub use fre_capture_lab::{
    CaptureGroupSlot, CaptureProgramV1, CaptureProgramV1Error, CaptureProgramV1Limits,
    CaptureProgramV1Usage, HirProgramBuildError, HirProgramBuildLimits, HirProgramBuildReport,
    HistoryExactWorkspaceUsage, OnePassCaptureBuildError, OnePassCaptureBuildFailure,
    OnePassCaptureBuildLimits, OnePassCaptureBuildReport, OnePassCaptureWorkspaceUsage, RunReport,
    SearchError as CaptureSearchError, SearchLimits as CaptureSearchLimits,
};
use fre_capture_lab::{
    HistoryExactWorkspace, OnePassCapturePlan, OnePassCaptureWorkspace, Span as CaptureSpan,
    Window as CaptureWindow, build_program_from_hir,
};
use fre_lower::OperationSemantics;
use fre_syntax::{
    CanonicalPattern, CompatibilityProfile, ParseRequest, RustConstructor, RustMatchKind,
    RustProfile,
};

use crate::{
    CompileError, CompileLimitsV1, CompileMode, CompiledProgram, CompiledRegex,
    CompiledRegexWorkspace, MatchResult, OutputContract, SearchWindow, SlowAotLimits, Target,
    finite_language, rust_profile_compiled_size_limit, set_rust_profile_compiled_size_limit,
};

/// Capture projection selected by this first stable operation.
///
/// The initial public slice intentionally exposes only complete capture
/// semantics. Future projections can be added without changing either stable
/// program format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CaptureLevel {
    /// Group zero and every explicit numeric/named group.
    All,
}

/// Independent resource envelopes for one capture compilation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CaptureCompileLimits {
    /// Ordinary capture-free Span selector limits.
    pub selector: CompileLimitsV1,
    /// Optional optimizing slow-AOT completion limits for the selector.
    pub selector_slow_aot: SlowAotLimits,
    /// Canonical-HIR to tagged capture-program limits.
    pub capture_hir: HirProgramBuildLimits,
    /// Stable capture-program seal/restore limits.
    pub capture_program: CaptureProgramV1Limits,
    /// Optional construction-complete one-pass sidecar limits.
    pub onepass: OnePassCaptureBuildLimits,
}

/// Complete request for one capture-preserving AOT operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureCompileRequest {
    pub pattern: String,
    pub profile: RustProfile,
    pub level: CaptureLevel,
    pub target: Target,
    pub mode: CompileMode,
    pub limits: CaptureCompileLimits,
}

impl CaptureCompileRequest {
    /// Construct a pinned Rust-bytes `All` capture request.
    #[must_use]
    pub fn new(pattern: impl Into<String>, target: Target) -> Self {
        let profile = RustProfile::default();
        let mut limits = CaptureCompileLimits::default();
        if let Some(limit) = rust_profile_compiled_size_limit(&profile) {
            limits.selector.max_program_bytes = limit;
        }
        Self {
            pattern: pattern.into(),
            profile,
            level: CaptureLevel::All,
            target,
            mode: CompileMode::Optimizing,
            limits,
        }
    }

    #[must_use]
    pub fn profile(mut self, profile: RustProfile) -> Self {
        self.profile = profile;
        self.limits.selector.max_program_bytes = rust_profile_compiled_size_limit(&self.profile)
            .unwrap_or(CompileLimitsV1::default().max_program_bytes);
        self
    }

    #[must_use]
    pub const fn mode(mut self, mode: CompileMode) -> Self {
        self.mode = mode;
        self
    }

    #[must_use]
    pub const fn limits(mut self, limits: CaptureCompileLimits) -> Self {
        self.limits = limits;
        set_rust_profile_compiled_size_limit(&mut self.profile, limits.selector.max_program_bytes);
        self
    }

    /// Set the maximum bytes in the capture operation's FRE selector program.
    /// Capture schema/replay programs retain their separately typed limits.
    #[must_use]
    pub fn size_limit(mut self, bytes: usize) -> Self {
        set_rust_profile_compiled_size_limit(&mut self.profile, bytes);
        self.limits.selector.max_program_bytes = bytes;
        self
    }

    /// Retain the Rust-like lazy-DFA cache option. FRE's capture compiler does
    /// not use that cache, so this does not change compilation or execution.
    #[must_use]
    pub fn dfa_size_limit(mut self, bytes: usize) -> Self {
        if let RustConstructor::RegexBuilder { dfa_size_limit, .. } = &mut self.profile.constructor
        {
            *dfa_size_limit = u64::try_from(bytes).unwrap_or(u64::MAX);
        }
        self
    }
}

/// Composite identity for two independently stable semantic programs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureArtifactIdentity {
    selector_sha256: [u8; 32],
    capture_sha256: [u8; 32],
    line_terminator: u8,
    level: CaptureLevel,
    groups: usize,
    slots: usize,
}

impl CaptureArtifactIdentity {
    #[must_use]
    pub const fn selector_sha256(self) -> [u8; 32] {
        self.selector_sha256
    }

    #[must_use]
    pub const fn capture_sha256(self) -> [u8; 32] {
        self.capture_sha256
    }

    #[must_use]
    pub const fn line_terminator(self) -> u8 {
        self.line_terminator
    }

    #[must_use]
    pub const fn level(self) -> CaptureLevel {
        self.level
    }

    #[must_use]
    pub const fn groups(self) -> usize {
        self.groups
    }

    #[must_use]
    pub const fn slots(self) -> usize {
        self.slots
    }

    /// Authenticate independently restored selector and capture artifacts as
    /// this exact composite. Each deserializer remains responsible for its
    /// own wire digest and canonicality before this cross-artifact check.
    pub fn authenticate(
        self,
        selector: &CompiledProgram,
        capture: &CaptureProgramV1,
    ) -> Result<(), CaptureAuthenticationError> {
        if selector.output_contract() != OutputContract::Span {
            return Err(CaptureAuthenticationError::SelectorOutput);
        }
        if selector.artifact_identity() != self.selector_sha256 {
            return Err(CaptureAuthenticationError::SelectorDigest);
        }
        if *capture.semantic_digest() != self.capture_sha256 {
            return Err(CaptureAuthenticationError::CaptureDigest);
        }
        if selector.line_terminator() != self.line_terminator {
            return Err(CaptureAuthenticationError::LineTerminator);
        }
        if self.level != CaptureLevel::All {
            return Err(CaptureAuthenticationError::CaptureLevel);
        }
        if capture.schema().group_count() != self.groups
            || capture.schema().slot_count() != self.slots
        {
            return Err(CaptureAuthenticationError::Schema);
        }
        Ok(())
    }
}

/// Failed cross-artifact authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureAuthenticationError {
    SelectorOutput,
    SelectorDigest,
    CaptureDigest,
    LineTerminator,
    CaptureLevel,
    Schema,
}

impl fmt::Display for CaptureAuthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "capture artifact authentication failed: {self:?}"
        )
    }
}

impl std::error::Error for CaptureAuthenticationError {}

fn onepass_build_declines(source: &OnePassCaptureBuildError) -> bool {
    matches!(
        source,
        OnePassCaptureBuildError::Resource { .. } | OnePassCaptureBuildError::NotOnePass(_)
    )
}

fn replay_resource_declines_to_history(source: &CaptureSearchError) -> bool {
    matches!(source, CaptureSearchError::Resource { .. })
}

/// Recorded terminal of the optional source-independent one-pass build.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaptureOnePassDisposition {
    Selected(OnePassCaptureBuildReport),
    Declined {
        source: OnePassCaptureBuildError,
        compile_work: usize,
    },
}

/// Complete construction receipt for one capture operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureCompileReceipt {
    pub identity: CaptureArtifactIdentity,
    pub profile: RustProfile,
    pub source_bytes: usize,
    /// Requested optional slow-AOT limits passed to selector compilation,
    /// including when that optional route declines.
    pub selector_slow_aot: SlowAotLimits,
    pub capture_hir: HirProgramBuildReport,
    pub capture_program: CaptureProgramV1Usage,
    pub onepass: CaptureOnePassDisposition,
}

/// Failure before a capture operation is published.
#[derive(Debug)]
pub enum CaptureCompileError {
    UnsupportedProfile(&'static str),
    Syntax(fre_syntax::ParseError),
    CaptureBuild(HirProgramBuildError),
    CaptureProgram(CaptureProgramV1Error),
    Selector(CompileError),
    OnePass(OnePassCaptureBuildFailure),
    InternalInvariant(&'static str),
}

impl fmt::Display for CaptureCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProfile(detail) => {
                write!(formatter, "unsupported capture profile: {detail}")
            }
            Self::Syntax(source) => write!(formatter, "capture syntax error: {source}"),
            Self::CaptureBuild(source) => write!(formatter, "capture HIR build failed: {source}"),
            Self::CaptureProgram(source) => write!(formatter, "capture program failed: {source}"),
            Self::Selector(source) => write!(formatter, "capture selector failed: {source}"),
            Self::OnePass(source) => write!(formatter, "one-pass capture build failed: {source}"),
            Self::InternalInvariant(detail) => {
                write!(formatter, "capture compiler invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for CaptureCompileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Syntax(source) => Some(source),
            Self::CaptureBuild(source) => Some(source),
            Self::CaptureProgram(source) => Some(source),
            Self::Selector(source) => Some(source),
            Self::OnePass(source) => Some(source),
            Self::UnsupportedProfile(_) | Self::InternalInvariant(_) => None,
        }
    }
}

/// One compiled selector plus its independently stable capture replay.
#[derive(Debug)]
pub struct CompiledCaptureRegex {
    selector: CompiledRegex,
    capture: CaptureProgramV1,
    onepass: Option<OnePassCapturePlan>,
    receipt: CaptureCompileReceipt,
}

impl CompiledCaptureRegex {
    #[must_use]
    pub const fn selector(&self) -> &CompiledRegex {
        &self.selector
    }

    #[must_use]
    pub const fn capture_program(&self) -> &CaptureProgramV1 {
        &self.capture
    }

    #[must_use]
    pub const fn receipt(&self) -> &CaptureCompileReceipt {
        &self.receipt
    }

    /// Recheck the two current immutable owners against their composite seal.
    pub fn authenticate(&self) -> Result<(), CaptureAuthenticationError> {
        self.receipt
            .identity
            .authenticate(self.selector.program(), &self.capture)
    }

    /// Prepare every source-dependent operation buffer and permanently select
    /// an exact-replay route.
    #[allow(
        clippy::too_many_lines,
        reason = "prospective admission and every fallible allocation remain in one auditable transaction"
    )]
    pub fn prepare_session(
        &self,
        limits: CaptureSessionLimits,
    ) -> Result<CaptureSession, CapturePrepareError> {
        self.authenticate()
            .map_err(CapturePrepareError::Authentication)?;
        let groups = self.capture.schema().group_count();
        if groups > limits.max_groups {
            return Err(CapturePrepareError::Resource {
                resource: CaptureSessionResource::Groups,
                required: groups,
                limit: limits.max_groups,
            });
        }
        if limits.max_window_bytes > limits.max_haystack_bytes {
            return Err(CapturePrepareError::InvalidLimits(
                "maximum window exceeds maximum haystack",
            ));
        }
        let maximum_span = CaptureSpan {
            start: 0,
            end: limits.max_window_bytes,
        };
        let replay_prospective = if let Some(plan) = &self.onepass {
            match plan.exact_workspace_usage(maximum_span, limits.replay) {
                Ok(usage) => CaptureSessionReplayProspective::OnePass(usage),
                Err(source) if replay_resource_declines_to_history(&source) => {
                    CaptureSessionReplayProspective::History(
                        self.capture
                            .history_exact_workspace_usage(limits.max_window_bytes, limits.replay)
                            .map_err(CapturePrepareError::Replay)?,
                    )
                }
                Err(source) => return Err(CapturePrepareError::Replay(source)),
            }
        } else {
            CaptureSessionReplayProspective::History(
                self.capture
                    .history_exact_workspace_usage(limits.max_window_bytes, limits.replay)
                    .map_err(CapturePrepareError::Replay)?,
            )
        };
        let replay_bytes = replay_prospective.persistent_bytes();
        let output_bytes = groups
            .checked_mul(size_of::<CaptureGroupSlot>())
            .and_then(|bytes| bytes.checked_mul(2))
            .ok_or(CapturePrepareError::ArithmeticOverflow(
                "capture session output bytes",
            ))?;
        let persistent_bytes = replay_bytes.checked_add(output_bytes).ok_or(
            CapturePrepareError::ArithmeticOverflow("capture session persistent bytes"),
        )?;
        if persistent_bytes > limits.max_capture_persistent_bytes {
            return Err(CapturePrepareError::Resource {
                resource: CaptureSessionResource::CapturePersistentBytes,
                required: persistent_bytes,
                limit: limits.max_capture_persistent_bytes,
            });
        }
        let replay = match replay_prospective {
            CaptureSessionReplayProspective::OnePass(expected) => {
                let plan = self.onepass.as_ref().ok_or(CapturePrepareError::Replay(
                    CaptureSearchError::InvalidProgram,
                ))?;
                let workspace = plan
                    .create_workspace(limits.replay)
                    .map_err(CapturePrepareError::Replay)?;
                if workspace.usage() != expected {
                    return Err(CapturePrepareError::Replay(
                        CaptureSearchError::InvalidProgram,
                    ));
                }
                CaptureSessionReplay::OnePass(workspace)
            }
            CaptureSessionReplayProspective::History(expected) => {
                let workspace = self
                    .capture
                    .prepare_history_exact_workspace(limits.max_window_bytes, limits.replay)
                    .map_err(CapturePrepareError::Replay)?;
                if workspace.usage() != expected {
                    return Err(CapturePrepareError::Replay(
                        CaptureSearchError::InvalidProgram,
                    ));
                }
                CaptureSessionReplay::History(workspace)
            }
        };
        if replay.persistent_bytes() != replay_bytes {
            return Err(CapturePrepareError::Replay(
                CaptureSearchError::InvalidProgram,
            ));
        }
        let staging = fixed_group_array(groups)?;
        let published = fixed_group_array(groups)?;
        let selector = self
            .selector
            .prepare_workspace()
            .map_err(CapturePrepareError::Selector)?;
        Ok(CaptureSession {
            identity: self.receipt.identity,
            selector,
            replay,
            staging,
            published,
            limits,
            persistent_bytes,
        })
    }

    /// Select one leftmost-first span and replay all captures without
    /// operation-time allocation.
    pub fn capture_with_session(
        &self,
        session: &mut CaptureSession,
        haystack: &[u8],
        window: SearchWindow,
    ) -> Result<CaptureRunReport, CaptureRunError> {
        if session.identity != self.receipt.identity {
            return Err(CaptureRunError::Authentication(
                CaptureAuthenticationError::CaptureDigest,
            ));
        }
        let window_bytes =
            window
                .end()
                .checked_sub(window.start())
                .ok_or(CaptureRunError::InvalidWindow {
                    start: window.start(),
                    end: window.end(),
                    haystack_len: haystack.len(),
                })?;
        if window.end() > haystack.len()
            || haystack.len() > session.limits.max_haystack_bytes
            || window_bytes > session.limits.max_window_bytes
        {
            return Err(CaptureRunError::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len: haystack.len(),
            });
        }
        let selected = self
            .selector
            .search_with_workspace(haystack, window, &mut session.selector)
            .map_err(CaptureRunError::Selector)?;
        let MatchResult::Span(selected) = selected else {
            return Err(CaptureRunError::InternalInvariant(
                "capture selector did not return Span",
            ));
        };
        let Some((start, end)) = selected else {
            session.staging.fill(CaptureGroupSlot::UNMATCHED);
            core::mem::swap(&mut session.staging, &mut session.published);
            return Ok(CaptureRunReport {
                matched: false,
                span: None,
                replay_strategy: session.replay.strategy(),
                replay: None,
            });
        };
        if start < window.start() || end > window.end() || start > end {
            return Err(CaptureRunError::InternalInvariant(
                "selector returned a span outside its search window",
            ));
        }
        let capture_window = CaptureWindow {
            start: window.start(),
            end: window.end(),
        };
        let span = CaptureSpan { start, end };
        let replay = match (&self.onepass, &mut session.replay) {
            (Some(plan), CaptureSessionReplay::OnePass(workspace)) => {
                self.capture.captures_exact_slots_with_onepass_workspace(
                    plan,
                    workspace,
                    haystack,
                    capture_window,
                    span,
                    &mut session.staging,
                    session.limits.replay,
                )
            }
            (_, CaptureSessionReplay::History(workspace)) => {
                self.capture.captures_exact_slots_with_history_workspace(
                    workspace,
                    haystack,
                    capture_window,
                    span,
                    &mut session.staging,
                )
            }
            (None, CaptureSessionReplay::OnePass(_)) => {
                return Err(CaptureRunError::InternalInvariant(
                    "one-pass session has no compiled plan",
                ));
            }
        }
        .map_err(CaptureRunError::Replay)?;
        if !replay.matched || session.staging.first().and_then(|slot| slot.span()) != Some(span) {
            return Err(CaptureRunError::InternalInvariant(
                "capture replay did not authenticate the selected group zero",
            ));
        }
        core::mem::swap(&mut session.staging, &mut session.published);
        Ok(CaptureRunReport {
            matched: true,
            span: Some((start, end)),
            replay_strategy: session.replay.strategy(),
            replay: Some(replay.report),
        })
    }
}

/// Compile one `All` capture operation from a single canonical HIR.
pub fn compile_captures(
    request: CaptureCompileRequest,
) -> Result<CompiledCaptureRegex, CaptureCompileError> {
    validate_profile(&request.profile)?;
    let CaptureCompileRequest {
        pattern,
        profile,
        level,
        target,
        mode,
        mut limits,
    } = request;
    if let Some(profile_limit) = rust_profile_compiled_size_limit(&profile) {
        limits.selector.max_program_bytes = limits.selector.max_program_bytes.min(profile_limit);
    }
    if level != CaptureLevel::All {
        return Err(CaptureCompileError::InternalInvariant(
            "unknown capture level reached compiler",
        ));
    }
    let source_bytes = pattern.len();
    let line_terminator = profile.options.line_terminator;
    let compatibility = CompatibilityProfile::RustBytes(profile.clone());
    let parsed = fre_syntax::parse(ParseRequest::rust(pattern, compatibility))
        .map_err(CaptureCompileError::Syntax)?;
    let CanonicalPattern::Rust(parsed) = parsed.pattern else {
        return Err(CaptureCompileError::InternalInvariant(
            "Rust capture request produced a non-Rust syntax tree",
        ));
    };

    let built = build_program_from_hir(&parsed.hir, line_terminator, limits.capture_hir)
        .map_err(CaptureCompileError::CaptureBuild)?;
    let capture_hir = built.report().clone();
    let capture = CaptureProgramV1::from_program(built.into_program(), limits.capture_program)
        .map_err(CaptureCompileError::CaptureProgram)?;
    let (onepass, onepass_disposition) =
        match capture.try_onepass_capture_plan_accounted(limits.onepass) {
            Ok(plan) => {
                let report = *plan.build_report();
                (Some(plan), CaptureOnePassDisposition::Selected(report))
            }
            Err(failure) if onepass_build_declines(&failure.source) => {
                let disposition = CaptureOnePassDisposition::Declined {
                    source: failure.source,
                    compile_work: failure.compile_work,
                };
                (None, disposition)
            }
            Err(failure) => return Err(CaptureCompileError::OnePass(failure)),
        };

    let raw = fre_lower::lower_raw_general(
        &parsed,
        OperationSemantics::CaptureFree,
        limits.selector.lower,
    )
    .map_err(|source| CaptureCompileError::Selector(source.into()))?;
    let native_finite_language_candidate = (mode == CompileMode::Optimizing)
        .then(|| {
            finite_language::NativeFiniteLanguageCandidate::analyze(&parsed, OutputContract::Span)
        })
        .flatten();
    let selector = super::compile_raw_with_line_terminator_and_slow_aot_limits(
        source_bytes,
        raw.into_plan(),
        line_terminator,
        OutputContract::Span,
        native_finite_language_candidate,
        target,
        mode,
        limits.selector,
        limits.selector_slow_aot,
        crate::ExactFiniteSelectedEndTeddyPolicyV2::Automatic,
    )
    .map_err(CaptureCompileError::Selector)?;
    let identity = CaptureArtifactIdentity {
        selector_sha256: selector.program().artifact_identity(),
        capture_sha256: *capture.semantic_digest(),
        line_terminator,
        level,
        groups: capture.schema().group_count(),
        slots: capture.schema().slot_count(),
    };
    identity
        .authenticate(selector.program(), &capture)
        .map_err(|_| {
            CaptureCompileError::InternalInvariant("fresh capture identity did not close")
        })?;
    let receipt = CaptureCompileReceipt {
        identity,
        profile,
        source_bytes,
        selector_slow_aot: limits.selector_slow_aot,
        capture_hir,
        capture_program: capture.usage(),
        onepass: onepass_disposition,
    };
    Ok(CompiledCaptureRegex {
        selector,
        capture,
        onepass,
        receipt,
    })
}

fn validate_profile(profile: &RustProfile) -> Result<(), CaptureCompileError> {
    let compatible = match &profile.constructor {
        RustConstructor::RegexBuilder {
            bytes_syntax_utf8,
            bytes_utf8_empty,
            match_kind,
            ..
        } => {
            !*bytes_syntax_utf8 && !*bytes_utf8_empty && *match_kind == RustMatchKind::LeftmostFirst
        }
        RustConstructor::RegexSetBuilder { .. } | RustConstructor::RebarMeta { .. } => false,
    };
    if compatible {
        Ok(())
    } else {
        Err(CaptureCompileError::UnsupportedProfile(
            "leftmost-first regex::bytes::RegexBuilder with byte-progress empty semantics",
        ))
    }
}

/// Session-time fixed resource envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureSessionLimits {
    pub max_haystack_bytes: usize,
    pub max_window_bytes: usize,
    pub replay: CaptureSearchLimits,
    pub max_groups: usize,
    /// Logical bytes for capture replay storage and the two transactional
    /// group arrays. The independently prepared selector workspace is governed
    /// by the selector's own executor contract.
    pub max_capture_persistent_bytes: usize,
}

impl Default for CaptureSessionLimits {
    fn default() -> Self {
        Self {
            max_haystack_bytes: 16 * 1024 * 1024,
            max_window_bytes: 16 * 1024 * 1024,
            replay: CaptureSearchLimits::default(),
            max_groups: 65,
            max_capture_persistent_bytes: 256 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureSessionResource {
    Groups,
    CapturePersistentBytes,
}

#[derive(Debug)]
pub enum CapturePrepareError {
    Authentication(CaptureAuthenticationError),
    Selector(CompileError),
    Replay(CaptureSearchError),
    Resource {
        resource: CaptureSessionResource,
        required: usize,
        limit: usize,
    },
    Allocation {
        structure: &'static str,
        entries: usize,
    },
    ArithmeticOverflow(&'static str),
    InvalidLimits(&'static str),
}

impl fmt::Display for CapturePrepareError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "capture session preparation failed: {self:?}")
    }
}

impl std::error::Error for CapturePrepareError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureReplayStrategy {
    OnePass,
    PersistentHistory,
}

#[allow(
    clippy::large_enum_variant,
    reason = "prepared workspaces stay inline so every retained allocation is explicit and preflighted"
)]
#[derive(Debug)]
enum CaptureSessionReplay {
    OnePass(OnePassCaptureWorkspace),
    History(HistoryExactWorkspace),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CaptureSessionReplayProspective {
    OnePass(OnePassCaptureWorkspaceUsage),
    History(HistoryExactWorkspaceUsage),
}

impl CaptureSessionReplayProspective {
    const fn persistent_bytes(self) -> usize {
        match self {
            Self::OnePass(usage) => usage.persistent_bytes,
            Self::History(usage) => usage.persistent_bytes,
        }
    }
}

impl CaptureSessionReplay {
    const fn strategy(&self) -> CaptureReplayStrategy {
        match self {
            Self::OnePass(_) => CaptureReplayStrategy::OnePass,
            Self::History(_) => CaptureReplayStrategy::PersistentHistory,
        }
    }

    fn persistent_bytes(&self) -> usize {
        match self {
            Self::OnePass(workspace) => workspace.scratch_bytes(),
            Self::History(workspace) => workspace.usage().persistent_bytes,
        }
    }
}

/// Caller-owned warm execution state and transactional capture slots.
#[derive(Debug)]
pub struct CaptureSession {
    identity: CaptureArtifactIdentity,
    selector: CompiledRegexWorkspace,
    replay: CaptureSessionReplay,
    staging: Vec<CaptureGroupSlot>,
    published: Vec<CaptureGroupSlot>,
    limits: CaptureSessionLimits,
    persistent_bytes: usize,
}

impl CaptureSession {
    #[must_use]
    pub fn groups(&self) -> &[CaptureGroupSlot] {
        &self.published
    }

    #[must_use]
    pub const fn replay_strategy(&self) -> CaptureReplayStrategy {
        self.replay.strategy()
    }

    #[must_use]
    pub const fn limits(&self) -> CaptureSessionLimits {
        self.limits
    }

    #[must_use]
    pub const fn capture_persistent_bytes(&self) -> usize {
        self.persistent_bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureRunReport {
    pub matched: bool,
    pub span: Option<(usize, usize)>,
    pub replay_strategy: CaptureReplayStrategy,
    pub replay: Option<RunReport>,
}

#[derive(Debug)]
pub enum CaptureRunError {
    Authentication(CaptureAuthenticationError),
    InvalidWindow {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
    Selector(CompileError),
    Replay(CaptureSearchError),
    InternalInvariant(&'static str),
}

impl fmt::Display for CaptureRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "capture execution failed: {self:?}")
    }
}

impl std::error::Error for CaptureRunError {}

fn fixed_group_array(groups: usize) -> Result<Vec<CaptureGroupSlot>, CapturePrepareError> {
    let mut slots = Vec::new();
    slots
        .try_reserve_exact(groups)
        .map_err(|_| CapturePrepareError::Allocation {
            structure: "capture group array",
            entries: groups,
        })?;
    if slots.capacity() != groups {
        return Err(CapturePrepareError::Allocation {
            structure: "capture group array exact capacity",
            entries: groups,
        });
    }
    slots.resize(groups, CaptureGroupSlot::UNMATCHED);
    Ok(slots)
}

#[cfg(test)]
mod tests {
    use fre_capture_lab::{OnePassCaptureBuildResource, OnePassCaptureRefusal, ResourceKind};

    use super::{
        CaptureSearchError, OnePassCaptureBuildError, onepass_build_declines,
        replay_resource_declines_to_history,
    };

    #[test]
    fn allocation_and_overflow_are_terminal_not_optional_route_declines() {
        assert!(onepass_build_declines(
            &OnePassCaptureBuildError::Resource {
                resource: OnePassCaptureBuildResource::States,
                required: 2,
                limit: 1,
            }
        ));
        assert!(onepass_build_declines(
            &OnePassCaptureBuildError::NotOnePass(OnePassCaptureRefusal::ConflictingTransition,)
        ));
        assert!(!onepass_build_declines(
            &OnePassCaptureBuildError::Allocation(OnePassCaptureBuildResource::ImmutableBytes)
        ));
        assert!(!onepass_build_declines(
            &OnePassCaptureBuildError::Overflow(OnePassCaptureBuildResource::CompileWork)
        ));

        assert!(replay_resource_declines_to_history(
            &CaptureSearchError::Resource {
                kind: ResourceKind::ScratchBytes,
                required: 2,
                limit: 1,
            }
        ));
        assert!(!replay_resource_declines_to_history(
            &CaptureSearchError::Allocation(ResourceKind::ScratchBytes)
        ));
        assert!(!replay_resource_declines_to_history(
            &CaptureSearchError::BoundOverflow(ResourceKind::ScratchBytes)
        ));
    }
}
