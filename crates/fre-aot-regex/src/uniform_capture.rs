//! Uniform capture-participation proof paired with an ordinary native Span selector.
//!
//! This layer deliberately owns no parser and no capture theorem. It consumes
//! one caller-owned canonical [`RustParsed`], asks [`fre_lower`] for its paired
//! proof/selector transaction, and feeds that exact `RawPlan` into the ordinary
//! AOT compiler. The returned selector is therefore the same program, module,
//! object, and route that an ordinary Span compilation would have selected.

use core::fmt;

use fre_lower::{
    OperationSemantics, UniformCaptureLoweringError, UniformCaptureParticipationDecline,
    UniformCaptureParticipationDisposition, UniformCaptureParticipationError,
    UniformCaptureParticipationLimits, UniformCaptureParticipationReceipt,
    lower_raw_general_with_uniform_capture_participation,
};
use fre_syntax::{RustParsed, RustProfile};
use sha2::{Digest, Sha256};

use crate::{
    CompileError, CompileLimitsV1, CompileMode, CompiledRegex, OutputContract,
    PreparedAggregateExports, SlowAotLimits, SymbolBinding, SymbolKind, Target,
    rust_profile_compiled_size_limit, set_rust_profile_compiled_size_limit,
};

/// Complete resource and target request for one already-parsed capture selector.
///
/// `source_bytes` is retained solely for the ordinary compiler receipt. The
/// semantic input is `RustParsed` passed to [`compile_uniform_capture_selector`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UniformCaptureCompileRequest {
    pub source_bytes: usize,
    pub profile: RustProfile,
    pub target: Target,
    pub mode: CompileMode,
    pub selector_limits: CompileLimitsV1,
    pub selector_slow_aot_limits: SlowAotLimits,
    pub participation_limits: UniformCaptureParticipationLimits,
}

impl UniformCaptureCompileRequest {
    /// Construct an optimizing LF request with the ordinary compiler limits.
    #[must_use]
    pub fn new(source_bytes: usize, target: Target) -> Self {
        let profile = RustProfile::default();
        let mut selector_limits = CompileLimitsV1::default();
        if let Some(limit) = rust_profile_compiled_size_limit(&profile) {
            selector_limits.max_program_bytes = limit;
        }
        Self {
            source_bytes,
            profile,
            target,
            mode: CompileMode::Optimizing,
            selector_limits,
            selector_slow_aot_limits: SlowAotLimits::default(),
            participation_limits: UniformCaptureParticipationLimits::default(),
        }
    }

    #[must_use]
    pub fn profile(mut self, profile: RustProfile) -> Self {
        self.profile = profile;
        self.selector_limits.max_program_bytes = rust_profile_compiled_size_limit(&self.profile)
            .unwrap_or(CompileLimitsV1::default().max_program_bytes);
        self
    }

    #[must_use]
    pub const fn mode(mut self, mode: CompileMode) -> Self {
        self.mode = mode;
        self
    }

    #[must_use]
    pub const fn selector_limits(mut self, limits: CompileLimitsV1) -> Self {
        self.selector_limits = limits;
        set_rust_profile_compiled_size_limit(&mut self.profile, limits.max_program_bytes);
        self
    }

    /// Set the maximum stable semantic-program bytes on both the profile and
    /// the explicit selector envelope, matching [`crate::CompileRequest`].
    #[must_use]
    pub fn size_limit(mut self, bytes: usize) -> Self {
        set_rust_profile_compiled_size_limit(&mut self.profile, bytes);
        self.selector_limits.max_program_bytes = bytes;
        self
    }

    #[must_use]
    pub const fn selector_slow_aot_limits(mut self, limits: SlowAotLimits) -> Self {
        self.selector_slow_aot_limits = limits;
        self
    }

    #[must_use]
    pub const fn participation_limits(mut self, limits: UniformCaptureParticipationLimits) -> Self {
        self.participation_limits = limits;
        self
    }
}

/// Why an immutable selector no longer authenticates as this operation's
/// exact helper-free ordinary Span artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum UniformCaptureAuthenticationError {
    ProofIdentity,
    SelectorOutput,
    SelectorTarget,
    SelectorLineTerminator,
    SelectorAutomatonDigest,
    SelectorProgramDigest,
    SelectorObjectDigest,
    RuntimeDependency,
    PreparedRoute,
    OrdinaryEntry,
}

impl fmt::Display for UniformCaptureAuthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "uniform capture selector authentication failed: {self:?}"
        )
    }
}

impl std::error::Error for UniformCaptureAuthenticationError {}

/// Positive theorem bound to one exact ordinary selector artifact.
///
/// The private fields make this a compiler-issued receipt. The three digests
/// bind the same-HIR theorem transaction to the lowered automaton, stable
/// semantic program, and final relocatable object respectively.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UniformCaptureCompileReceipt {
    participation: UniformCaptureParticipationReceipt,
    selector_automaton_sha256: [u8; 32],
    selector_program_sha256: [u8; 32],
    selector_object_sha256: [u8; 32],
    target: Target,
    line_terminator: u8,
}

impl UniformCaptureCompileReceipt {
    #[must_use]
    pub const fn participation(self) -> UniformCaptureParticipationReceipt {
        self.participation
    }

    #[must_use]
    pub const fn selector_automaton_sha256(self) -> [u8; 32] {
        self.selector_automaton_sha256
    }

    #[must_use]
    pub const fn selector_program_sha256(self) -> [u8; 32] {
        self.selector_program_sha256
    }

    #[must_use]
    pub const fn selector_object_sha256(self) -> [u8; 32] {
        self.selector_object_sha256
    }

    #[must_use]
    pub const fn target(self) -> Target {
        self.target
    }

    #[must_use]
    pub const fn line_terminator(self) -> u8 {
        self.line_terminator
    }

    /// Re-authenticate the theorem against an immutable compiled selector.
    pub fn authenticate(
        self,
        selector: &CompiledRegex,
    ) -> Result<(), UniformCaptureAuthenticationError> {
        if !self.participation.identity().authenticates_current() {
            return Err(UniformCaptureAuthenticationError::ProofIdentity);
        }
        authenticate_ordinary_native_span(selector)?;
        let compiler = selector.receipt();
        if compiler.output != OutputContract::Span {
            return Err(UniformCaptureAuthenticationError::SelectorOutput);
        }
        if compiler.target != self.target || selector.module().target() != self.target {
            return Err(UniformCaptureAuthenticationError::SelectorTarget);
        }
        if compiler.line_terminator != self.line_terminator
            || selector.program().line_terminator() != self.line_terminator
        {
            return Err(UniformCaptureAuthenticationError::SelectorLineTerminator);
        }
        if compiler.automaton_sha256 != self.selector_automaton_sha256 {
            return Err(UniformCaptureAuthenticationError::SelectorAutomatonDigest);
        }
        if compiler.program_sha256 != self.selector_program_sha256
            || selector.program().artifact_identity() != self.selector_program_sha256
        {
            return Err(UniformCaptureAuthenticationError::SelectorProgramDigest);
        }
        let mut actual_object_sha256 = [0_u8; 32];
        actual_object_sha256.copy_from_slice(&Sha256::digest(selector.object()));
        if compiler.object_sha256 != self.selector_object_sha256
            || actual_object_sha256 != self.selector_object_sha256
        {
            return Err(UniformCaptureAuthenticationError::SelectorObjectDigest);
        }
        Ok(())
    }
}

/// Positive uniform proof or an explicit conservative semantic decline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UniformCaptureCompileDisposition {
    Proven(UniformCaptureCompileReceipt),
    Declined(UniformCaptureParticipationDecline),
}

impl UniformCaptureCompileDisposition {
    #[must_use]
    pub const fn receipt(self) -> Option<UniformCaptureCompileReceipt> {
        match self {
            Self::Proven(receipt) => Some(receipt),
            Self::Declined(_) => None,
        }
    }

    #[must_use]
    pub const fn decline(self) -> Option<UniformCaptureParticipationDecline> {
        match self {
            Self::Proven(_) => None,
            Self::Declined(decline) => Some(decline),
        }
    }
}

/// One unchanged ordinary native selector and its same-HIR proof outcome.
#[derive(Debug)]
pub struct CompiledUniformCaptureSelector {
    selector: CompiledRegex,
    disposition: UniformCaptureCompileDisposition,
}

impl CompiledUniformCaptureSelector {
    #[must_use]
    pub const fn selector(&self) -> &CompiledRegex {
        &self.selector
    }

    #[must_use]
    pub const fn disposition(&self) -> UniformCaptureCompileDisposition {
        self.disposition
    }

    /// Recheck the helper-free ordinary route and any positive theorem seal.
    pub fn authenticate(&self) -> Result<(), UniformCaptureAuthenticationError> {
        authenticate_ordinary_native_span(&self.selector)?;
        if let UniformCaptureCompileDisposition::Proven(receipt) = self.disposition {
            receipt.authenticate(&self.selector)?;
        }
        Ok(())
    }

    #[must_use]
    pub fn into_parts(self) -> (CompiledRegex, UniformCaptureCompileDisposition) {
        (self.selector, self.disposition)
    }
}

/// Terminal failure before an ordinary selector/proof outcome is published.
#[derive(Debug)]
#[non_exhaustive]
pub enum UniformCaptureCompileError {
    Participation(UniformCaptureParticipationError),
    Lower(fre_lower::LowerError),
    LoweringTransaction(UniformCaptureLoweringError),
    Selector(CompileError),
    Authentication(UniformCaptureAuthenticationError),
}

impl fmt::Display for UniformCaptureCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Participation(source) => source.fmt(formatter),
            Self::Lower(source) => source.fmt(formatter),
            Self::LoweringTransaction(source) => source.fmt(formatter),
            Self::Selector(source) => {
                write!(formatter, "uniform capture selector failed: {source}")
            }
            Self::Authentication(source) => source.fmt(formatter),
        }
    }
}

impl std::error::Error for UniformCaptureCompileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Participation(source) => Some(source),
            Self::Lower(source) => Some(source),
            Self::LoweringTransaction(source) => Some(source),
            Self::Selector(source) => Some(source),
            Self::Authentication(source) => Some(source),
        }
    }
}

/// Compile one canonical HIR through the paired uniform-proof/selector path.
///
/// A semantic proof decline remains an ordinary successful native selector
/// and is published explicitly in the disposition. Proof resource,
/// allocation, overflow, and invariant failures are terminal, as are lower,
/// AOT compile, and fresh route-authentication failures. No source text is
/// parsed or inspected by this function.
pub fn compile_uniform_capture_selector(
    parsed: &RustParsed,
    mut request: UniformCaptureCompileRequest,
) -> Result<CompiledUniformCaptureSelector, UniformCaptureCompileError> {
    if let Some(profile_limit) = rust_profile_compiled_size_limit(&request.profile) {
        request.selector_limits.max_program_bytes =
            request.selector_limits.max_program_bytes.min(profile_limit);
    }
    let line_terminator = request.profile.options.line_terminator;
    let paired = lower_raw_general_with_uniform_capture_participation(
        parsed,
        OperationSemantics::CaptureFree,
        request.selector_limits.lower,
        request.participation_limits,
    )
    .map_err(|source| match source {
        UniformCaptureLoweringError::Participation(source) => {
            UniformCaptureCompileError::Participation(source)
        }
        UniformCaptureLoweringError::Lower(source) => UniformCaptureCompileError::Lower(source),
        #[allow(
            unreachable_patterns,
            reason = "fre-lower marks this cross-crate enum non-exhaustive"
        )]
        source => UniformCaptureCompileError::LoweringTransaction(source),
    })?;
    let (lowered, participation) = paired.into_parts();
    let native_finite_language_candidate = (request.mode == CompileMode::Optimizing)
        .then(|| {
            crate::finite_language::NativeFiniteLanguageCandidate::analyze(
                parsed,
                OutputContract::Span,
            )
        })
        .flatten();
    let selector = super::compile_raw_with_line_terminator_and_slow_aot_limits(
        request.source_bytes,
        lowered.into_plan(),
        line_terminator,
        OutputContract::Span,
        native_finite_language_candidate,
        request.target,
        request.mode,
        request.selector_limits,
        request.selector_slow_aot_limits,
    )
    .map_err(UniformCaptureCompileError::Selector)?;
    authenticate_ordinary_native_span(&selector)
        .map_err(UniformCaptureCompileError::Authentication)?;

    let disposition = match participation {
        UniformCaptureParticipationDisposition::Declined(decline) => {
            UniformCaptureCompileDisposition::Declined(decline)
        }
        UniformCaptureParticipationDisposition::Proven(participation) => {
            let compiler = selector.receipt();
            let receipt = UniformCaptureCompileReceipt {
                participation,
                selector_automaton_sha256: compiler.automaton_sha256,
                selector_program_sha256: compiler.program_sha256,
                selector_object_sha256: compiler.object_sha256,
                target: compiler.target,
                line_terminator: compiler.line_terminator,
            };
            receipt
                .authenticate(&selector)
                .map_err(UniformCaptureCompileError::Authentication)?;
            UniformCaptureCompileDisposition::Proven(receipt)
        }
    };
    Ok(CompiledUniformCaptureSelector {
        selector,
        disposition,
    })
}

fn authenticate_ordinary_native_span(
    selector: &CompiledRegex,
) -> Result<(), UniformCaptureAuthenticationError> {
    let compiler = selector.receipt();
    if compiler.output != OutputContract::Span {
        return Err(UniformCaptureAuthenticationError::SelectorOutput);
    }
    let module = selector.module();
    let has_unresolved_relocation = module.symbols().iter().enumerate().any(|(index, symbol)| {
        symbol.section.is_none()
            && module
                .relocations()
                .iter()
                .any(|relocation| relocation.symbol == index)
    });
    if compiler.runtime_helper_required
        || module.required_runtime_symbols().next().is_some()
        || has_unresolved_relocation
        || module.required_runtime_program().is_some()
    {
        return Err(UniformCaptureAuthenticationError::RuntimeDependency);
    }
    if module.prepared_entry_symbol().is_some()
        || module.prepared_span_fill_symbol().is_some()
        || module.prepared_exists_batch_symbol().is_some()
        || module.prepared_count_symbol().is_some()
        || module.prepared_span_sum_symbol().is_some()
        || module.prepared_grep_count_symbol().is_some()
        || module.prepared_bulk_strategy().is_some()
        || module.prepared_aggregate_exports() != PreparedAggregateExports::NONE
        || module.required_prepare_capabilities() != 0
    {
        return Err(UniformCaptureAuthenticationError::PreparedRoute);
    }
    let entry_name = module.entry_symbol();
    let entry = module
        .symbols()
        .iter()
        .find(|symbol| symbol.name == entry_name)
        .ok_or(UniformCaptureAuthenticationError::OrdinaryEntry)?;
    if entry.binding != SymbolBinding::Global
        || entry.kind != SymbolKind::Function
        || entry.section.is_none()
        || entry.size == 0
    {
        return Err(UniformCaptureAuthenticationError::OrdinaryEntry);
    }
    Ok(())
}
