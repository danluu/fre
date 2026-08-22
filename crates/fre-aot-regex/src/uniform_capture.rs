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
    analyze_uniform_capture_participation, lower_raw_general,
    lower_raw_general_with_uniform_capture_participation,
};
use fre_syntax::{RustParsed, RustProfile};
use sha2::{Digest, Sha256};

use crate::{
    CompileError, CompileLimitsV1, CompileMode, CompiledRegex, EngineKind, OutputContract,
    PREPARED_CAPABILITY_ORDERED_NFA_V15, PreparedAggregateExports, PreparedBulkStrategy,
    SlowAotLimits, SymbolBinding, SymbolKind, Target, rust_profile_compiled_size_limit,
    set_rust_profile_compiled_size_limit,
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
        None,
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

const ORDERED_NFA_COMPATIBILITY_RUNTIME_SYMBOLS: [&str; 3] = [
    "fre_aot_regex_runtime_search_v1",
    "fre_aot_regex_runtime_search_exclusive_v1",
    "fre_aot_regex_runtime_fill_spans_exclusive_v1",
];

/// Why a compiler-issued uniform prepared `SpanFill` route no longer closes.
///
/// This authentication is deliberately narrower than general prepared-search
/// support. It accepts only the object-local Ordered-TNFA loop whose selected
/// path requires a runtime V3 handle carrying
/// [`PREPARED_CAPABILITY_ORDERED_NFA_V15`]. Compatibility helpers may remain
/// linked for legacy handles, but they are not the authenticated operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum UniformCapturePreparedSpanFillAuthenticationError {
    ProofIdentity,
    SelectorOutput,
    SelectorEngine,
    SelectorTarget,
    SelectorLineTerminator,
    SelectorAutomatonDigest,
    SelectorProgramDigest,
    SelectorObjectDigest,
    PreparedEntry,
    PreparedSpanFillEntry,
    PreparedBulkStrategy,
    PreparedCapabilities,
    PreparedSurface,
    CompatibilityRuntimeSurface,
}

impl fmt::Display for UniformCapturePreparedSpanFillAuthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "uniform capture prepared SpanFill authentication failed: {self:?}"
        )
    }
}

impl std::error::Error for UniformCapturePreparedSpanFillAuthenticationError {}

/// Uniform participation proof bound to one exact prepared native `SpanFill`.
///
/// A consumer must prepare this program through runtime prepare V3 while
/// requiring [`Self::required_prepare_capabilities`]. A handle lacking that
/// exact capability does not authenticate this receipt and must not invoke the
/// selected operation. The ordinary and legacy prepared compatibility entries
/// remain part of the object, but are outside this receipt's selected route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UniformCapturePreparedSpanFillCompileReceipt {
    participation: UniformCaptureParticipationReceipt,
    selector_automaton_sha256: [u8; 32],
    selector_program_sha256: [u8; 32],
    selector_object_sha256: [u8; 32],
    prepared_entry_symbol_sha256: [u8; 32],
    prepared_span_fill_symbol_sha256: [u8; 32],
    target: Target,
    line_terminator: u8,
    required_prepare_capabilities: u64,
}

impl UniformCapturePreparedSpanFillCompileReceipt {
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

    /// Exact capability mask that runtime prepare V3 must require.
    #[must_use]
    pub const fn required_prepare_capabilities(self) -> u64 {
        self.required_prepare_capabilities
    }

    /// Re-authenticate the theorem and exact selected operation against an
    /// immutable compiled selector.
    pub fn authenticate(
        self,
        selector: &CompiledRegex,
    ) -> Result<(), UniformCapturePreparedSpanFillAuthenticationError> {
        if !self.participation.identity().authenticates_current() {
            return Err(UniformCapturePreparedSpanFillAuthenticationError::ProofIdentity);
        }
        authenticate_ordered_nfa_prepared_span_fill(selector)?;
        let compiler = selector.receipt();
        if compiler.target != self.target || selector.module().target() != self.target {
            return Err(UniformCapturePreparedSpanFillAuthenticationError::SelectorTarget);
        }
        if compiler.line_terminator != self.line_terminator
            || selector.program().line_terminator() != self.line_terminator
        {
            return Err(UniformCapturePreparedSpanFillAuthenticationError::SelectorLineTerminator);
        }
        if compiler.automaton_sha256 != self.selector_automaton_sha256 {
            return Err(UniformCapturePreparedSpanFillAuthenticationError::SelectorAutomatonDigest);
        }
        if compiler.program_sha256 != self.selector_program_sha256
            || selector.program().artifact_identity() != self.selector_program_sha256
        {
            return Err(UniformCapturePreparedSpanFillAuthenticationError::SelectorProgramDigest);
        }
        let mut actual_object_sha256 = [0_u8; 32];
        actual_object_sha256.copy_from_slice(&Sha256::digest(selector.object()));
        if compiler.object_sha256 != self.selector_object_sha256
            || actual_object_sha256 != self.selector_object_sha256
        {
            return Err(UniformCapturePreparedSpanFillAuthenticationError::SelectorObjectDigest);
        }
        let module = selector.module();
        let prepared_entry = module
            .prepared_entry_symbol()
            .ok_or(UniformCapturePreparedSpanFillAuthenticationError::PreparedEntry)?;
        if sha256(prepared_entry.as_bytes()) != self.prepared_entry_symbol_sha256 {
            return Err(UniformCapturePreparedSpanFillAuthenticationError::PreparedEntry);
        }
        let span_fill = module
            .prepared_span_fill_symbol()
            .ok_or(UniformCapturePreparedSpanFillAuthenticationError::PreparedSpanFillEntry)?;
        if sha256(span_fill.as_bytes()) != self.prepared_span_fill_symbol_sha256 {
            return Err(UniformCapturePreparedSpanFillAuthenticationError::PreparedSpanFillEntry);
        }
        if self.required_prepare_capabilities != PREPARED_CAPABILITY_ORDERED_NFA_V15
            || compiler.required_prepare_capabilities != self.required_prepare_capabilities
            || module.required_prepare_capabilities() != self.required_prepare_capabilities
        {
            return Err(UniformCapturePreparedSpanFillAuthenticationError::PreparedCapabilities);
        }
        Ok(())
    }
}

/// One positive theorem and its exact capability-bound prepared `SpanFill`.
#[derive(Clone, Debug)]
pub struct CompiledUniformCapturePreparedSpanFillSelector {
    selector: CompiledRegex,
    receipt: UniformCapturePreparedSpanFillCompileReceipt,
}

impl CompiledUniformCapturePreparedSpanFillSelector {
    #[must_use]
    pub const fn selector(&self) -> &CompiledRegex {
        &self.selector
    }

    #[must_use]
    pub const fn receipt(&self) -> UniformCapturePreparedSpanFillCompileReceipt {
        self.receipt
    }

    #[must_use]
    pub fn prepared_entry_symbol(&self) -> &str {
        self.selector
            .module()
            .prepared_entry_symbol()
            .expect("compiler-issued prepared SpanFill receipt lost its prepared entry")
    }

    #[must_use]
    pub fn prepared_span_fill_symbol(&self) -> &str {
        self.selector
            .module()
            .prepared_span_fill_symbol()
            .expect("compiler-issued prepared SpanFill receipt lost its SpanFill entry")
    }

    pub fn authenticate(&self) -> Result<(), UniformCapturePreparedSpanFillAuthenticationError> {
        self.receipt.authenticate(&self.selector)
    }

    #[must_use]
    pub fn into_parts(self) -> (CompiledRegex, UniformCapturePreparedSpanFillCompileReceipt) {
        (self.selector, self.receipt)
    }
}

/// Result of the prospective uniform theorem and selected prepared compiler.
///
/// `Declined` is the only result that authorizes a caller to choose another
/// capture backend. It is published before selector lowering or object
/// construction. After a positive theorem, all failures are terminal errors.
#[derive(Clone, Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "boxing would add an untyped allocation after the selected backend has completed"
)]
pub enum UniformCapturePreparedSpanFillCompileDisposition {
    Selected(CompiledUniformCapturePreparedSpanFillSelector),
    Declined(UniformCaptureParticipationDecline),
}

impl UniformCapturePreparedSpanFillCompileDisposition {
    #[must_use]
    pub const fn selected(&self) -> Option<&CompiledUniformCapturePreparedSpanFillSelector> {
        match self {
            Self::Selected(selected) => Some(selected),
            Self::Declined(_) => None,
        }
    }

    #[must_use]
    pub const fn decline(&self) -> Option<UniformCaptureParticipationDecline> {
        match self {
            Self::Selected(_) => None,
            Self::Declined(decline) => Some(*decline),
        }
    }

    #[must_use]
    pub fn into_selected(self) -> Option<CompiledUniformCapturePreparedSpanFillSelector> {
        match self {
            Self::Selected(selected) => Some(selected),
            Self::Declined(_) => None,
        }
    }
}

/// Terminal failure after prospective proof selection begins.
#[derive(Debug)]
#[non_exhaustive]
pub enum UniformCapturePreparedSpanFillCompileError {
    Participation(UniformCaptureParticipationError),
    Lower(fre_lower::LowerError),
    Selector(CompileError),
    Authentication(UniformCapturePreparedSpanFillAuthenticationError),
}

impl fmt::Display for UniformCapturePreparedSpanFillCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Participation(source) => source.fmt(formatter),
            Self::Lower(source) => source.fmt(formatter),
            Self::Selector(source) => {
                write!(
                    formatter,
                    "uniform capture prepared SpanFill failed: {source}"
                )
            }
            Self::Authentication(source) => source.fmt(formatter),
        }
    }
}

impl std::error::Error for UniformCapturePreparedSpanFillCompileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Participation(source) => Some(source),
            Self::Lower(source) => Some(source),
            Self::Selector(source) => Some(source),
            Self::Authentication(source) => Some(source),
        }
    }
}

/// Prospectively prove uniform participation, then construct exactly one
/// capability-bound prepared native `SpanFill` selector.
///
/// A semantic theorem decline returns before general lowering or selector
/// construction. A positive theorem commits this call to the prepared
/// Ordered-TNFA backend: lower, allocation, compile, object, or exact route
/// authentication failures are returned unchanged as terminal errors and are
/// never converted into fallback permission.
pub fn compile_uniform_capture_prepared_span_fill_selector(
    parsed: &RustParsed,
    mut request: UniformCaptureCompileRequest,
) -> Result<
    UniformCapturePreparedSpanFillCompileDisposition,
    UniformCapturePreparedSpanFillCompileError,
> {
    if let Some(profile_limit) = rust_profile_compiled_size_limit(&request.profile) {
        request.selector_limits.max_program_bytes =
            request.selector_limits.max_program_bytes.min(profile_limit);
    }
    let participation = analyze_uniform_capture_participation(parsed, request.participation_limits)
        .map_err(UniformCapturePreparedSpanFillCompileError::Participation)?;
    let participation = match participation {
        UniformCaptureParticipationDisposition::Declined(decline) => {
            return Ok(UniformCapturePreparedSpanFillCompileDisposition::Declined(
                decline,
            ));
        }
        UniformCaptureParticipationDisposition::Proven(participation) => participation,
    };

    let lowered = lower_raw_general(
        parsed,
        OperationSemantics::CaptureFree,
        request.selector_limits.lower,
    )
    .map_err(UniformCapturePreparedSpanFillCompileError::Lower)?;
    if participation.canonical_capture_annotations() != lowered.stats().erased_captures() {
        return Err(UniformCapturePreparedSpanFillCompileError::Participation(
            UniformCaptureParticipationError::InternalInvariant {
                detail: "proof and selector capture censuses diverged",
            },
        ));
    }

    let line_terminator = request.profile.options.line_terminator;
    let selector = super::compile_raw_prepared_ordered_nfa_v15(
        request.source_bytes,
        lowered.into_plan(),
        line_terminator,
        OutputContract::Span,
        request.target,
        request.mode,
        request.selector_limits,
        PreparedAggregateExports::NONE,
        request.selector_slow_aot_limits.max_native_data_bytes,
    )
    .map_err(UniformCapturePreparedSpanFillCompileError::Selector)?;
    authenticate_ordered_nfa_prepared_span_fill(&selector)
        .map_err(UniformCapturePreparedSpanFillCompileError::Authentication)?;

    let compiler = selector.receipt();
    let module = selector.module();
    let prepared_entry = module.prepared_entry_symbol().ok_or(
        UniformCapturePreparedSpanFillCompileError::Authentication(
            UniformCapturePreparedSpanFillAuthenticationError::PreparedEntry,
        ),
    )?;
    let span_fill = module.prepared_span_fill_symbol().ok_or(
        UniformCapturePreparedSpanFillCompileError::Authentication(
            UniformCapturePreparedSpanFillAuthenticationError::PreparedSpanFillEntry,
        ),
    )?;
    let receipt = UniformCapturePreparedSpanFillCompileReceipt {
        participation,
        selector_automaton_sha256: compiler.automaton_sha256,
        selector_program_sha256: compiler.program_sha256,
        selector_object_sha256: compiler.object_sha256,
        prepared_entry_symbol_sha256: sha256(prepared_entry.as_bytes()),
        prepared_span_fill_symbol_sha256: sha256(span_fill.as_bytes()),
        target: compiler.target,
        line_terminator: compiler.line_terminator,
        required_prepare_capabilities: compiler.required_prepare_capabilities,
    };
    receipt
        .authenticate(&selector)
        .map_err(UniformCapturePreparedSpanFillCompileError::Authentication)?;
    Ok(UniformCapturePreparedSpanFillCompileDisposition::Selected(
        CompiledUniformCapturePreparedSpanFillSelector { selector, receipt },
    ))
}

fn authenticate_ordered_nfa_prepared_span_fill(
    selector: &CompiledRegex,
) -> Result<(), UniformCapturePreparedSpanFillAuthenticationError> {
    let compiler = selector.receipt();
    if compiler.output != OutputContract::Span {
        return Err(UniformCapturePreparedSpanFillAuthenticationError::SelectorOutput);
    }
    if compiler.engine != EngineKind::OrderedNfa {
        return Err(UniformCapturePreparedSpanFillAuthenticationError::SelectorEngine);
    }
    let module = selector.module();
    if module.prepared_bulk_strategy() != Some(PreparedBulkStrategy::NativeOrderedNfaLoop) {
        return Err(UniformCapturePreparedSpanFillAuthenticationError::PreparedBulkStrategy);
    }
    if compiler.required_prepare_capabilities != PREPARED_CAPABILITY_ORDERED_NFA_V15
        || module.required_prepare_capabilities() != PREPARED_CAPABILITY_ORDERED_NFA_V15
    {
        return Err(UniformCapturePreparedSpanFillAuthenticationError::PreparedCapabilities);
    }
    let prepared_entry = module
        .prepared_entry_symbol()
        .ok_or(UniformCapturePreparedSpanFillAuthenticationError::PreparedEntry)?;
    authenticate_global_defined_function(module, prepared_entry)
        .map_err(|()| UniformCapturePreparedSpanFillAuthenticationError::PreparedEntry)?;
    let span_fill = module
        .prepared_span_fill_symbol()
        .ok_or(UniformCapturePreparedSpanFillAuthenticationError::PreparedSpanFillEntry)?;
    authenticate_global_defined_function(module, span_fill)
        .map_err(|()| UniformCapturePreparedSpanFillAuthenticationError::PreparedSpanFillEntry)?;
    if module.prepared_exists_batch_symbol().is_some()
        || module.prepared_count_symbol().is_some()
        || module.prepared_span_sum_symbol().is_some()
        || module.prepared_grep_count_symbol().is_some()
        || module.prepared_aggregate_exports() != PreparedAggregateExports::NONE
        || module.prepared_aggregate_strategy().is_some()
        || compiler.prepared_aggregate_exports != PreparedAggregateExports::NONE
        || compiler.prepared_aggregate_strategy.is_some()
    {
        return Err(UniformCapturePreparedSpanFillAuthenticationError::PreparedSurface);
    }
    if !compiler.runtime_helper_required
        || !runtime_program_matches(module, compiler.program_sha256)
        || !module
            .required_runtime_symbols()
            .eq(ORDERED_NFA_COMPATIBILITY_RUNTIME_SYMBOLS)
        || module.relocations().iter().any(|relocation| {
            let Some(symbol) = module.symbols().get(relocation.symbol) else {
                return true;
            };
            symbol.section.is_none()
                && (symbol.binding != SymbolBinding::Global
                    || symbol.kind != SymbolKind::Function
                    || !ORDERED_NFA_COMPATIBILITY_RUNTIME_SYMBOLS.contains(&symbol.name.as_str()))
        })
    {
        return Err(UniformCapturePreparedSpanFillAuthenticationError::CompatibilityRuntimeSurface);
    }
    Ok(())
}

fn runtime_program_matches(module: &crate::CompiledModule, expected_sha256: [u8; 32]) -> bool {
    let Some((name, expected_bytes)) = module.required_runtime_program() else {
        return false;
    };
    let mut matches = module.symbols().iter().filter(|symbol| symbol.name == name);
    let Some(symbol) = matches.next() else {
        return false;
    };
    if matches.next().is_some()
        || symbol.binding != SymbolBinding::Global
        || symbol.kind != SymbolKind::Object
        || usize::try_from(symbol.size) != Ok(expected_bytes)
    {
        return false;
    }
    let Some(section) = symbol.section.and_then(|index| module.sections().get(index)) else {
        return false;
    };
    let Ok(start) = usize::try_from(symbol.offset) else {
        return false;
    };
    let Some(end) = start.checked_add(expected_bytes) else {
        return false;
    };
    section
        .bytes()
        .get(start..end)
        .is_some_and(|program| sha256(program) == expected_sha256)
}

fn authenticate_global_defined_function(
    module: &crate::CompiledModule,
    name: &str,
) -> Result<(), ()> {
    let mut matches = module.symbols().iter().filter(|symbol| symbol.name == name);
    let symbol = matches.next().ok_or(())?;
    if matches.next().is_some()
        || symbol.binding != SymbolBinding::Global
        || symbol.kind != SymbolKind::Function
        || symbol.section.is_none()
        || symbol.size == 0
    {
        return Err(());
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    output
}
