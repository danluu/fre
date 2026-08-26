//! Uniform capture-participation proof paired with an ordinary native Span selector.
//!
//! This layer deliberately owns no parser and no capture theorem. It consumes
//! one caller-owned canonical [`RustParsed`], asks [`fre_lower`] for its paired
//! proof/selector transaction, and feeds that exact `RawPlan` into the ordinary
//! AOT compiler. The returned selector is therefore the same program, module,
//! object, and route that an ordinary Span compilation would have selected.

use core::{fmt, num::NonZeroU64};

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
    Architecture, CallAbi, CompileError, CompileLimitsV1, CompileMode, CompileReceipt,
    CompileResource, CompiledModule, CompiledProgram, CompiledRegex, EngineKind, EntryAbi,
    ObjectError, ObjectFormat, OperatingSystem, OutputContract,
    PREPARED_CAPABILITY_ORDERED_NFA_V15, PreparedAggregateExports, PreparedAggregateStrategy,
    PreparedBulkStrategy, PreparedOrderedNfaV15CompileDecline,
    PreparedOrderedNfaV15CompileDisposition, RelocationKind, SectionKind, SlowAotLimits,
    SymbolBinding, SymbolKind, Target, emit_object, rust_profile_compiled_size_limit,
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
        super::NativeFiniteLanguageAttachPolicy::Optional,
        None,
        request.target,
        request.mode,
        request.selector_limits,
        request.selector_slow_aot_limits,
        crate::ExactFiniteSelectedEndTeddyPolicyV2::Automatic,
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

/// Whole-operation capture projection selected after a uniform theorem.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum UniformCaptureReducerOperation {
    CountCaptures,
    GrepCaptures,
}

impl UniformCaptureReducerOperation {
    #[must_use]
    pub const fn domain(self) -> UniformCaptureReducerDomain {
        match self {
            Self::CountCaptures => UniformCaptureReducerDomain::WholeHaystack,
            Self::GrepCaptures => UniformCaptureReducerDomain::ByteSliceLinesLfCrLf,
        }
    }

    pub(crate) const fn native_domain(self) -> crate::module::NativeUniformCaptureReducerDomain {
        match self {
            Self::CountCaptures => {
                crate::module::NativeUniformCaptureReducerDomain::WholeHaystack
            }
            Self::GrepCaptures => {
                crate::module::NativeUniformCaptureReducerDomain::ByteSliceLines
            }
        }
    }
}

/// Exact byte domain owned by a native uniform-capture reducer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum UniformCaptureReducerDomain {
    WholeHaystack,
    /// Rust `bstr::ByteSlice::lines`: LF-delimited, one immediately preceding
    /// CR stripped, no line for empty input, and no extra line after final LF.
    ByteSliceLinesLfCrLf,
}

/// Why a compiler-issued uniform-capture reducer no longer closes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum UniformCaptureReducerAuthenticationError {
    ProofIdentity,
    ProofBinding,
    ProofMultiplier,
    OperationDomain,
    SelectorOutput,
    SelectorTarget,
    SelectorLineTerminator,
    SelectorAutomatonDigest,
    SelectorProgramDigest,
    SelectorObjectDigest,
    AggregateRoute,
    CountSymbol,
    ReducerSymbol,
    NativeClosure,
    LinkedRowClosure,
    LinkedReducerClosure,
    LinkedReducerObject,
    LinkedReceipt,
}

impl fmt::Display for UniformCaptureReducerAuthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "uniform capture reducer authentication failed: {self:?}"
        )
    }
}

impl std::error::Error for UniformCaptureReducerAuthenticationError {}

/// Same-HIR theorem and final native reducer identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UniformCaptureReducerCompileReceipt {
    participation: UniformCaptureParticipationReceipt,
    operation: UniformCaptureReducerOperation,
    domain: UniformCaptureReducerDomain,
    multiplier: NonZeroU64,
    proof_identity_sha256: [u8; 32],
    selector_automaton_sha256: [u8; 32],
    selector_program_sha256: [u8; 32],
    selector_object_sha256: [u8; 32],
    count_symbol_sha256: [u8; 32],
    reducer_symbol_sha256: [u8; 32],
    target: Target,
    line_terminator: u8,
    aggregate_strategy: PreparedAggregateStrategy,
    required_prepare_capabilities: u64,
}

impl UniformCaptureReducerCompileReceipt {
    #[must_use]
    pub const fn participation(self) -> UniformCaptureParticipationReceipt {
        self.participation
    }

    #[must_use]
    pub const fn operation(self) -> UniformCaptureReducerOperation {
        self.operation
    }

    #[must_use]
    pub const fn domain(self) -> UniformCaptureReducerDomain {
        self.domain
    }

    #[must_use]
    pub const fn multiplier(self) -> NonZeroU64 {
        self.multiplier
    }

    /// Identity of the exact proof facts authorizing native multiplication.
    #[must_use]
    pub const fn proof_identity_sha256(self) -> [u8; 32] {
        self.proof_identity_sha256
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
    pub const fn count_symbol_sha256(self) -> [u8; 32] {
        self.count_symbol_sha256
    }

    #[must_use]
    pub const fn reducer_symbol_sha256(self) -> [u8; 32] {
        self.reducer_symbol_sha256
    }

    #[must_use]
    pub const fn target(self) -> Target {
        self.target
    }

    #[must_use]
    pub const fn line_terminator(self) -> u8 {
        self.line_terminator
    }

    #[must_use]
    pub const fn aggregate_strategy(self) -> PreparedAggregateStrategy {
        self.aggregate_strategy
    }

    #[must_use]
    pub const fn required_prepare_capabilities(self) -> u64 {
        self.required_prepare_capabilities
    }

    /// Re-authenticate every proof, object, route, and local-call identity.
    pub fn authenticate(
        self,
        compiled: &CompiledRegex,
        reducer_symbol: &str,
    ) -> Result<(), UniformCaptureReducerAuthenticationError> {
        if !self.participation.identity().authenticates_current() {
            return Err(UniformCaptureReducerAuthenticationError::ProofIdentity);
        }
        let proof_multiplier = u64::try_from(
            self.participation
                .participating_groups_per_match()
                .get(),
        )
        .ok()
        .and_then(NonZeroU64::new);
        if proof_multiplier != Some(self.multiplier) {
            return Err(UniformCaptureReducerAuthenticationError::ProofMultiplier);
        }
        let proof_identity = uniform_capture_proof_identity(
            self.participation,
            self.selector_program_sha256,
        )?;
        if proof_identity != self.proof_identity_sha256 {
            return Err(UniformCaptureReducerAuthenticationError::ProofBinding);
        }
        if self.operation.domain() != self.domain {
            return Err(UniformCaptureReducerAuthenticationError::OperationDomain);
        }
        let compiler = compiled.receipt();
        let module = compiled.module();
        if compiler.output != OutputContract::Span {
            return Err(UniformCaptureReducerAuthenticationError::SelectorOutput);
        }
        if compiler.target != self.target || module.target() != self.target {
            return Err(UniformCaptureReducerAuthenticationError::SelectorTarget);
        }
        if compiler.line_terminator != self.line_terminator
            || compiled.program().line_terminator() != self.line_terminator
        {
            return Err(UniformCaptureReducerAuthenticationError::SelectorLineTerminator);
        }
        if compiler.automaton_sha256 != self.selector_automaton_sha256 {
            return Err(UniformCaptureReducerAuthenticationError::SelectorAutomatonDigest);
        }
        if compiler.program_sha256 != self.selector_program_sha256
            || compiled.program().artifact_identity() != self.selector_program_sha256
        {
            return Err(UniformCaptureReducerAuthenticationError::SelectorProgramDigest);
        }
        if compiled.object().is_empty()
            || compiler.object_bytes != compiled.object().len()
            || compiler.object_sha256 != self.selector_object_sha256
            || sha256(compiled.object()) != self.selector_object_sha256
        {
            return Err(UniformCaptureReducerAuthenticationError::SelectorObjectDigest);
        }
        let ordered = self.aggregate_strategy
            == PreparedAggregateStrategy::NativeOrderedNfaFused;
        let operation_only = ordered && compiler.entry_abi == EntryAbi::PreparedScalarReduceV1;
        let aggregate_route_is_exact = if operation_only {
            !compiler.runtime_helper_required
                && module.prepared_bulk_strategy().is_none()
                && module.prepared_entry_symbol().is_none()
                && module.prepared_span_fill_symbol().is_none()
                && module.required_runtime_symbols().next().is_none()
                && self.required_prepare_capabilities
                    == PREPARED_CAPABILITY_ORDERED_NFA_V15
        } else if ordered {
            compiler.entry_abi == EntryAbi::SpanSearchV1
                && compiler.runtime_helper_required
                && module.prepared_bulk_strategy()
                    == Some(PreparedBulkStrategy::NativeOrderedNfaLoop)
                && module.prepared_entry_symbol().is_some()
                && module.prepared_span_fill_symbol().is_some()
                && has_exact_runtime_symbol_closure(
                    module,
                    &ORDERED_NFA_UNIFORM_COUNT_COMPATIBILITY_RUNTIME_SYMBOLS,
                )
                && self.required_prepare_capabilities
                    == PREPARED_CAPABILITY_ORDERED_NFA_V15
        } else {
            compiler.entry_abi == EntryAbi::SpanSearchV1
                && !compiler.runtime_helper_required
                && module.prepared_bulk_strategy().is_none()
                && module.prepared_entry_symbol().is_none()
                && module.prepared_span_fill_symbol().is_none()
                && module.required_runtime_symbols().next().is_none()
                && self.required_prepare_capabilities == 0
        };
        if !matches!(
            self.aggregate_strategy,
            PreparedAggregateStrategy::NativeFused
                | PreparedAggregateStrategy::NativeOrderedNfaFused
        ) || compiler.prepared_aggregate_exports != PreparedAggregateExports::COUNT
            || module.prepared_aggregate_exports() != PreparedAggregateExports::COUNT
            || compiler.prepared_aggregate_strategy != Some(self.aggregate_strategy)
            || module.prepared_aggregate_strategy() != Some(self.aggregate_strategy)
            || compiler.required_prepare_capabilities != self.required_prepare_capabilities
            || module.required_prepare_capabilities() != self.required_prepare_capabilities
            || (ordered && compiler.engine != EngineKind::OrderedNfa)
            || !aggregate_route_is_exact
            || module.prepared_span_sum_symbol().is_some()
            || module.prepared_grep_count_symbol().is_some()
            || module.required_runtime_program().is_none()
        {
            return Err(UniformCaptureReducerAuthenticationError::AggregateRoute);
        }
        let count_symbol = module
            .prepared_count_symbol()
            .ok_or(UniformCaptureReducerAuthenticationError::CountSymbol)?;
        if sha256(count_symbol.as_bytes()) != self.count_symbol_sha256 {
            return Err(UniformCaptureReducerAuthenticationError::CountSymbol);
        }
        if (operation_only && count_symbol != module.entry_symbol())
            || count_symbol == reducer_symbol
            || module.entry_symbol() == reducer_symbol
        {
            return Err(UniformCaptureReducerAuthenticationError::CountSymbol);
        }
        if sha256(reducer_symbol.as_bytes()) != self.reducer_symbol_sha256 {
            return Err(UniformCaptureReducerAuthenticationError::ReducerSymbol);
        }
        module
            .authenticate_native_uniform_capture_reducer(
                self.operation.native_domain(),
                self.multiplier.get(),
                self.selector_program_sha256,
                self.proof_identity_sha256,
                reducer_symbol,
            )
            .map_err(|_| UniformCaptureReducerAuthenticationError::NativeClosure)
    }
}

const ORDERED_NFA_UNIFORM_COUNT_COMPATIBILITY_RUNTIME_SYMBOLS: [&str; 4] = [
    "fre_aot_regex_runtime_search_v1",
    "fre_aot_regex_runtime_search_exclusive_v1",
    "fre_aot_regex_runtime_fill_spans_exclusive_v1",
    "fre_aot_regex_runtime_compiler_private_count_exclusive_v1",
];

fn has_exact_runtime_symbol_closure(module: &CompiledModule, expected: &[&str]) -> bool {
    module.required_runtime_symbols().count() == expected.len()
        && expected.iter().all(|expected| {
            module
                .required_runtime_symbols()
                .any(|actual| actual == *expected)
        })
}

/// One exact native selector/Count closure and its capture reducer.
#[derive(Clone, Debug)]
pub struct CompiledUniformCaptureReducer {
    compiled: CompiledRegex,
    reducer_symbol: String,
    receipt: UniformCaptureReducerCompileReceipt,
}

impl CompiledUniformCaptureReducer {
    #[must_use]
    pub const fn compiled(&self) -> &CompiledRegex {
        &self.compiled
    }

    #[must_use]
    pub fn reducer_symbol(&self) -> &str {
        &self.reducer_symbol
    }

    #[must_use]
    pub const fn receipt(&self) -> UniformCaptureReducerCompileReceipt {
        self.receipt
    }

    pub fn authenticate(&self) -> Result<(), UniformCaptureReducerAuthenticationError> {
        self.receipt
            .authenticate(&self.compiled, &self.reducer_symbol)
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        CompiledRegex,
        String,
        UniformCaptureReducerCompileReceipt,
    ) {
        (self.compiled, self.reducer_symbol, self.receipt)
    }
}

/// Receipt schema for a separately linked strict-RowSearch capture reducer.
pub const LINKED_PREPARED_ROW_UNIFORM_CAPTURE_REDUCER_V1_RECEIPT_VERSION: u32 = 1;

/// One exact external call from the capture reducer object to its strict row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkedPreparedRowUniformCaptureRelocationV1 {
    offset: u64,
    kind: RelocationKind,
    addend: i64,
}

impl LinkedPreparedRowUniformCaptureRelocationV1 {
    #[must_use]
    pub const fn offset(self) -> u64 {
        self.offset
    }

    #[must_use]
    pub const fn kind(self) -> RelocationKind {
        self.kind
    }

    #[must_use]
    pub const fn addend(self) -> i64 {
        self.addend
    }
}

/// Closed two-object receipt for one strict prepared row and one native
/// CountCaptures/GrepCaptures wrapper.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkedPreparedRowUniformCaptureReducerReceiptV1 {
    schema_version: u32,
    participation: UniformCaptureParticipationReceipt,
    operation: UniformCaptureReducerOperation,
    domain: UniformCaptureReducerDomain,
    multiplier: NonZeroU64,
    proof_identity_sha256: [u8; 32],
    target: Target,
    line_terminator: u8,
    row_automaton_sha256: [u8; 32],
    row_program_sha256: [u8; 32],
    row_object_sha256: [u8; 32],
    row_object_bytes: usize,
    row_entry_symbol: String,
    count_symbol: String,
    reducer_symbol: String,
    reducer_code_sha256: [u8; 32],
    reducer_object_sha256: [u8; 32],
    reducer_object_bytes: usize,
    max_object_bytes: usize,
    row_relocation: LinkedPreparedRowUniformCaptureRelocationV1,
    semantic_runtime_calls: usize,
    artifact_identity_sha256: [u8; 32],
}

impl LinkedPreparedRowUniformCaptureReducerReceiptV1 {
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }
    #[must_use]
    pub const fn participation(&self) -> UniformCaptureParticipationReceipt {
        self.participation
    }
    #[must_use]
    pub const fn operation(&self) -> UniformCaptureReducerOperation {
        self.operation
    }
    #[must_use]
    pub const fn domain(&self) -> UniformCaptureReducerDomain {
        self.domain
    }
    #[must_use]
    pub const fn multiplier(&self) -> NonZeroU64 {
        self.multiplier
    }
    #[must_use]
    pub const fn proof_identity_sha256(&self) -> [u8; 32] {
        self.proof_identity_sha256
    }
    #[must_use]
    pub const fn target(&self) -> Target {
        self.target
    }
    #[must_use]
    pub const fn line_terminator(&self) -> u8 {
        self.line_terminator
    }
    #[must_use]
    pub const fn row_automaton_sha256(&self) -> [u8; 32] {
        self.row_automaton_sha256
    }
    #[must_use]
    pub const fn row_program_sha256(&self) -> [u8; 32] {
        self.row_program_sha256
    }
    #[must_use]
    pub const fn row_object_sha256(&self) -> [u8; 32] {
        self.row_object_sha256
    }
    #[must_use]
    pub const fn row_object_bytes(&self) -> usize {
        self.row_object_bytes
    }
    #[must_use]
    pub fn row_entry_symbol(&self) -> &str {
        &self.row_entry_symbol
    }
    #[must_use]
    pub fn count_symbol(&self) -> &str {
        &self.count_symbol
    }
    #[must_use]
    pub fn reducer_symbol(&self) -> &str {
        &self.reducer_symbol
    }
    #[must_use]
    pub const fn reducer_code_sha256(&self) -> [u8; 32] {
        self.reducer_code_sha256
    }
    #[must_use]
    pub const fn reducer_object_sha256(&self) -> [u8; 32] {
        self.reducer_object_sha256
    }
    #[must_use]
    pub const fn reducer_object_bytes(&self) -> usize {
        self.reducer_object_bytes
    }
    #[must_use]
    pub const fn max_object_bytes(&self) -> usize {
        self.max_object_bytes
    }
    #[must_use]
    pub const fn row_relocation(&self) -> LinkedPreparedRowUniformCaptureRelocationV1 {
        self.row_relocation
    }
    #[must_use]
    pub const fn semantic_runtime_calls(&self) -> usize {
        self.semantic_runtime_calls
    }
    #[must_use]
    pub const fn artifact_identity_sha256(&self) -> [u8; 32] {
        self.artifact_identity_sha256
    }
}

/// Strict prepared row plus its separately linkable whole-operation reducer.
#[derive(Clone, Debug)]
pub struct LinkedPreparedRowUniformCaptureReducerV1 {
    row: CompiledRegex,
    reducer_module: CompiledModule,
    reducer_object: Box<[u8]>,
    receipt: LinkedPreparedRowUniformCaptureReducerReceiptV1,
}

impl LinkedPreparedRowUniformCaptureReducerV1 {
    #[must_use]
    pub const fn row(&self) -> &CompiledRegex {
        &self.row
    }

    #[must_use]
    pub const fn reducer_module(&self) -> &CompiledModule {
        &self.reducer_module
    }

    #[must_use]
    pub fn reducer_object(&self) -> &[u8] {
        &self.reducer_object
    }

    #[must_use]
    pub const fn receipt(&self) -> &LinkedPreparedRowUniformCaptureReducerReceiptV1 {
        &self.receipt
    }

    #[must_use]
    pub fn reducer_symbol(&self) -> &str {
        self.receipt.reducer_symbol()
    }

    #[cfg(test)]
    fn test_flip_row_text_byte(&mut self, offset: usize) -> bool {
        self.row.module.test_flip_text_byte(offset)
    }

    pub fn authenticate(&self) -> Result<(), UniformCaptureReducerAuthenticationError> {
        authenticate_linked_prepared_row_uniform_capture_reducer(self)
    }
}

/// Additive compiler result used by linkers that can retain two objects.
/// Existing users of [`compile_uniform_capture_reducer`] keep the original
/// one-object API and behavior unchanged.
#[derive(Clone, Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "boxing would allocate after a selected compiler transaction"
)]
pub enum UniformCaptureReducerLinkCompileDispositionV1 {
    Combined(CompiledUniformCaptureReducer),
    PreparedRowSearch(LinkedPreparedRowUniformCaptureReducerV1),
    Declined(UniformCaptureParticipationDecline),
}

impl UniformCaptureReducerLinkCompileDispositionV1 {
    #[must_use]
    pub const fn combined(&self) -> Option<&CompiledUniformCaptureReducer> {
        match self {
            Self::Combined(value) => Some(value),
            Self::PreparedRowSearch(_) | Self::Declined(_) => None,
        }
    }

    #[must_use]
    pub const fn prepared_row_search(&self) -> Option<&LinkedPreparedRowUniformCaptureReducerV1> {
        match self {
            Self::PreparedRowSearch(value) => Some(value),
            Self::Combined(_) | Self::Declined(_) => None,
        }
    }

    #[must_use]
    pub const fn decline(&self) -> Option<UniformCaptureParticipationDecline> {
        match self {
            Self::Declined(value) => Some(*value),
            Self::Combined(_) | Self::PreparedRowSearch(_) => None,
        }
    }
}

/// Positive native selection or the uniform theorem's sole fallback permit.
#[derive(Clone, Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "boxing would allocate after a selected compiler transaction"
)]
pub enum UniformCaptureReducerCompileDisposition {
    Selected(CompiledUniformCaptureReducer),
    Declined(UniformCaptureParticipationDecline),
}

impl UniformCaptureReducerCompileDisposition {
    #[must_use]
    pub const fn selected(&self) -> Option<&CompiledUniformCaptureReducer> {
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
    pub fn into_selected(self) -> Option<CompiledUniformCaptureReducer> {
        match self {
            Self::Selected(selected) => Some(selected),
            Self::Declined(_) => None,
        }
    }
}

/// Terminal failure after a positive theorem starts native selection.
#[derive(Debug)]
#[non_exhaustive]
pub enum UniformCaptureReducerCompileError {
    Participation(UniformCaptureParticipationError),
    Ordinary(UniformCaptureCompileError),
    OperationOnly(CompileError),
    RowSearch(CompileError),
    Prepared(UniformCapturePreparedSpanFillCompileError),
    Finalization(CompileError),
    Authentication(UniformCaptureReducerAuthenticationError),
}

impl fmt::Display for UniformCaptureReducerCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Participation(source) => source.fmt(formatter),
            Self::Ordinary(source) => source.fmt(formatter),
            Self::OperationOnly(source) => {
                write!(formatter, "uniform capture operation-only V15 failed: {source}")
            }
            Self::RowSearch(source) => {
                write!(
                    formatter,
                    "uniform capture strict RowSearch V15 failed: {source}"
                )
            }
            Self::Prepared(source) => source.fmt(formatter),
            Self::Finalization(source) => {
                write!(formatter, "uniform capture reducer finalization failed: {source}")
            }
            Self::Authentication(source) => source.fmt(formatter),
        }
    }
}

impl std::error::Error for UniformCaptureReducerCompileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Participation(source) => Some(source),
            Self::Ordinary(source) => Some(source),
            Self::OperationOnly(source) => Some(source),
            Self::RowSearch(source) => Some(source),
            Self::Prepared(source) => Some(source),
            Self::Finalization(source) => Some(source),
            Self::Authentication(source) => Some(source),
        }
    }
}

fn native_symbol_identity<'a>(symbol: &'a str, prefix: &str) -> Option<&'a str> {
    let suffix = symbol.strip_prefix(prefix)?;
    (suffix.len() == 64
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then_some(suffix)
}

fn authenticate_strict_prepared_row(
    row: &CompiledRegex,
) -> Result<(), UniformCaptureReducerAuthenticationError> {
    let receipt = row.receipt();
    let module = row.module();
    let Some(entry) = module.prepared_entry_symbol() else {
        return Err(UniformCaptureReducerAuthenticationError::LinkedRowClosure);
    };
    let Some((program, program_bytes)) = module.required_runtime_program() else {
        return Err(UniformCaptureReducerAuthenticationError::LinkedRowClosure);
    };
    let entry_identity = native_symbol_identity(entry, "fre_aot_regex_search_exclusive_v1_");
    let program_identity = native_symbol_identity(program, "fre_aot_regex_runtime_program_v1_");
    let global_functions = module
        .symbols()
        .iter()
        .filter(|symbol| {
            symbol.binding == SymbolBinding::Global
                && symbol.kind == SymbolKind::Function
                && symbol.section.is_some()
        })
        .collect::<Vec<_>>();
    let global_objects = module
        .symbols()
        .iter()
        .filter(|symbol| {
            symbol.binding == SymbolBinding::Global
                && symbol.kind == SymbolKind::Object
                && symbol.section.is_some()
        })
        .collect::<Vec<_>>();
    if receipt.output != OutputContract::Span
        || receipt.entry_abi != EntryAbi::PreparedSpanSearchV1
        || receipt.engine != EngineKind::OrderedNfa
        || receipt.runtime_helper_required
        || receipt.target != module.target()
        || receipt.line_terminator != row.program().line_terminator()
        || receipt.program_sha256 != row.program().artifact_identity()
        || row.object().is_empty()
        || receipt.object_bytes != row.object().len()
        || receipt.object_sha256 != sha256(row.object())
        || receipt.prepared_aggregate_exports != PreparedAggregateExports::NONE
        || receipt.prepared_aggregate_strategy.is_some()
        || receipt.required_prepare_capabilities != PREPARED_CAPABILITY_ORDERED_NFA_V15
        || module.required_prepare_capabilities() != PREPARED_CAPABILITY_ORDERED_NFA_V15
        || module.entry_symbol() != entry
        || module.prepared_bulk_strategy().is_some()
        || module.prepared_span_fill_symbol().is_some()
        || module.prepared_exists_batch_symbol().is_some()
        || module.direct_exists_batch_symbol().is_some()
        || module.prepared_count_symbol().is_some()
        || module.prepared_span_sum_symbol().is_some()
        || module.prepared_grep_count_symbol().is_some()
        || module.prepared_aggregate_exports() != PreparedAggregateExports::NONE
        || module.prepared_aggregate_strategy().is_some()
        || module.required_runtime_symbols().next().is_some()
        || program_bytes == 0
        || program_bytes != receipt.program_bytes
        || entry_identity.is_none()
        || entry_identity != program_identity
        || entry == program
        || global_functions.len() != 1
        || global_functions[0].name != entry
        || global_objects.len() != 1
        || global_objects[0].name != program
        || module
            .symbols()
            .iter()
            .any(|symbol| symbol.section.is_none())
        || module.relocations().iter().any(|relocation| {
            module
                .symbols()
                .get(relocation.symbol)
                .is_none_or(|symbol| symbol.section.is_none())
        })
    {
        return Err(UniformCaptureReducerAuthenticationError::LinkedRowClosure);
    }

    let reemitted = emit_object(
        module,
        ObjectFormat::for_target(receipt.target),
        receipt.object_bytes,
    )
    .map_err(|_| UniformCaptureReducerAuthenticationError::LinkedRowClosure)?;
    if reemitted.as_slice() != row.object() {
        return Err(UniformCaptureReducerAuthenticationError::LinkedRowClosure);
    }

    let serialized = row
        .program()
        .serialize()
        .map_err(|_| UniformCaptureReducerAuthenticationError::LinkedRowClosure)?;
    let program_symbol = global_objects[0];
    let section = program_symbol
        .section
        .and_then(|index| module.sections().get(index))
        .ok_or(UniformCaptureReducerAuthenticationError::LinkedRowClosure)?;
    let start = usize::try_from(program_symbol.offset)
        .map_err(|_| UniformCaptureReducerAuthenticationError::LinkedRowClosure)?;
    let end = start
        .checked_add(program_bytes)
        .ok_or(UniformCaptureReducerAuthenticationError::LinkedRowClosure)?;
    if serialized.len() != program_bytes
        || section.bytes().get(start..end) != Some(serialized.as_slice())
    {
        return Err(UniformCaptureReducerAuthenticationError::LinkedRowClosure);
    }
    Ok(())
}

fn linked_reducer_external_row_relocation(
    module: &CompiledModule,
    row_entry: &str,
) -> Result<LinkedPreparedRowUniformCaptureRelocationV1, UniformCaptureReducerAuthenticationError> {
    let mut row_symbols = module.symbols().iter().enumerate().filter(|(_, symbol)| {
        symbol.name == row_entry
            && symbol.binding == SymbolBinding::Global
            && symbol.kind == SymbolKind::Function
            && symbol.section.is_none()
            && symbol.offset == 0
            && symbol.size == 0
    });
    let Some((row_symbol, _)) = row_symbols.next() else {
        return Err(UniformCaptureReducerAuthenticationError::LinkedReducerClosure);
    };
    if row_symbols.next().is_some() {
        return Err(UniformCaptureReducerAuthenticationError::LinkedReducerClosure);
    }
    let mut row_relocations = module
        .relocations()
        .iter()
        .filter(|relocation| relocation.symbol == row_symbol);
    let Some(relocation) = row_relocations.next().copied() else {
        return Err(UniformCaptureReducerAuthenticationError::LinkedReducerClosure);
    };
    if row_relocations.next().is_some()
        || module
            .sections()
            .get(relocation.section)
            .is_none_or(|section| section.kind != SectionKind::Text)
        || match module.target().architecture {
            Architecture::X86_64 => {
                relocation.kind != RelocationKind::X86PltRelative32 || relocation.addend != -4
            }
            Architecture::Aarch64 => {
                relocation.kind != RelocationKind::Aarch64Branch26 || relocation.addend != 0
            }
        }
    {
        return Err(UniformCaptureReducerAuthenticationError::LinkedReducerClosure);
    }
    Ok(LinkedPreparedRowUniformCaptureRelocationV1 {
        offset: relocation.offset,
        kind: relocation.kind,
        addend: relocation.addend,
    })
}

fn linked_target_bytes(target: Target) -> [u8; 4] {
    [
        match target.architecture {
            Architecture::X86_64 => 1,
            Architecture::Aarch64 => 2,
        },
        match target.operating_system {
            OperatingSystem::Linux => 1,
            OperatingSystem::Macos => 2,
        },
        match target.abi {
            CallAbi::SystemV => 1,
            CallAbi::Aapcs64 => 2,
        },
        0,
    ]
}

fn linked_update_usize(
    digest: &mut Sha256,
    value: usize,
) -> Result<(), UniformCaptureReducerAuthenticationError> {
    digest.update(
        u64::try_from(value)
            .map_err(|_| UniformCaptureReducerAuthenticationError::LinkedReceipt)?
            .to_le_bytes(),
    );
    Ok(())
}

fn linked_update_bytes(
    digest: &mut Sha256,
    bytes: &[u8],
) -> Result<(), UniformCaptureReducerAuthenticationError> {
    linked_update_usize(digest, bytes.len())?;
    digest.update(bytes);
    Ok(())
}

fn linked_uniform_capture_artifact_identity(
    receipt: &LinkedPreparedRowUniformCaptureReducerReceiptV1,
) -> Result<[u8; 32], UniformCaptureReducerAuthenticationError> {
    let mut digest = Sha256::new();
    digest.update(b"fre-aot-regex/linked-prepared-row-uniform-capture-artifact/v1\0");
    digest.update(receipt.schema_version.to_le_bytes());
    digest.update([match receipt.operation {
        UniformCaptureReducerOperation::CountCaptures => 1,
        UniformCaptureReducerOperation::GrepCaptures => 2,
    }]);
    digest.update([match receipt.domain {
        UniformCaptureReducerDomain::WholeHaystack => 1,
        UniformCaptureReducerDomain::ByteSliceLinesLfCrLf => 2,
    }]);
    digest.update(receipt.multiplier.get().to_le_bytes());
    digest.update(receipt.proof_identity_sha256);
    digest.update(linked_target_bytes(receipt.target));
    digest.update(receipt.target.features.bits().to_le_bytes());
    digest.update([receipt.line_terminator]);
    digest.update(receipt.row_automaton_sha256);
    digest.update(receipt.row_program_sha256);
    digest.update(receipt.row_object_sha256);
    linked_update_usize(&mut digest, receipt.row_object_bytes)?;
    linked_update_bytes(&mut digest, receipt.row_entry_symbol.as_bytes())?;
    linked_update_bytes(&mut digest, receipt.count_symbol.as_bytes())?;
    linked_update_bytes(&mut digest, receipt.reducer_symbol.as_bytes())?;
    digest.update(receipt.reducer_code_sha256);
    digest.update(receipt.reducer_object_sha256);
    linked_update_usize(&mut digest, receipt.reducer_object_bytes)?;
    linked_update_usize(&mut digest, receipt.max_object_bytes)?;
    digest.update(receipt.row_relocation.offset.to_le_bytes());
    digest.update([match receipt.row_relocation.kind {
        RelocationKind::X86PcRelative32 => 1,
        RelocationKind::X86PltRelative32 => 2,
        RelocationKind::Aarch64Page21 => 3,
        RelocationKind::Aarch64PageOff12 => 4,
        RelocationKind::Aarch64Branch26 => 5,
    }]);
    digest.update(receipt.row_relocation.addend.to_le_bytes());
    linked_update_usize(&mut digest, receipt.semantic_runtime_calls)?;
    Ok(digest.finalize().into())
}

fn authenticate_linked_prepared_row_uniform_capture_reducer(
    artifact: &LinkedPreparedRowUniformCaptureReducerV1,
) -> Result<(), UniformCaptureReducerAuthenticationError> {
    let receipt = artifact.receipt();
    authenticate_strict_prepared_row(artifact.row())?;
    let row_receipt = artifact.row().receipt();
    let multiplier = u64::try_from(receipt.participation.participating_groups_per_match().get())
        .ok()
        .and_then(NonZeroU64::new);
    let proof_identity =
        uniform_capture_proof_identity(receipt.participation, receipt.row_program_sha256)?;
    if receipt.schema_version != LINKED_PREPARED_ROW_UNIFORM_CAPTURE_REDUCER_V1_RECEIPT_VERSION
        || !receipt.participation.identity().authenticates_current()
        || multiplier != Some(receipt.multiplier)
        || proof_identity != receipt.proof_identity_sha256
        || receipt.operation.domain() != receipt.domain
        || receipt.target != row_receipt.target
        || receipt.line_terminator != row_receipt.line_terminator
        || receipt.row_automaton_sha256 != row_receipt.automaton_sha256
        || receipt.row_program_sha256 != row_receipt.program_sha256
        || receipt.row_object_sha256 != row_receipt.object_sha256
        || receipt.row_object_bytes != artifact.row().object().len()
        || receipt.row_object_bytes > receipt.max_object_bytes
        || receipt.row_entry_symbol != artifact.row().module().entry_symbol()
        || receipt.semantic_runtime_calls != 0
    {
        return Err(UniformCaptureReducerAuthenticationError::LinkedReceipt);
    }

    let (rebuilt, count_symbol, reducer_symbol) =
        crate::module::lower_linked_prepared_row_uniform_capture_reducer(
            receipt.target,
            receipt.operation.native_domain(),
            receipt.multiplier.get(),
            receipt.row_program_sha256,
            receipt.proof_identity_sha256,
            &receipt.row_entry_symbol,
        )
        .map_err(|_| UniformCaptureReducerAuthenticationError::LinkedReducerClosure)?;
    if artifact.reducer_module != rebuilt
        || receipt.count_symbol != count_symbol
        || receipt.reducer_symbol != reducer_symbol
        || artifact.reducer_module.entry_symbol() != receipt.reducer_symbol
        || artifact.reducer_module.target() != receipt.target
        || artifact.reducer_module.prepared_entry_symbol().is_some()
        || artifact
            .reducer_module
            .prepared_span_fill_symbol()
            .is_some()
        || artifact
            .reducer_module
            .prepared_exists_batch_symbol()
            .is_some()
        || artifact
            .reducer_module
            .direct_exists_batch_symbol()
            .is_some()
        || artifact.reducer_module.prepared_count_symbol().is_some()
        || artifact.reducer_module.prepared_span_sum_symbol().is_some()
        || artifact
            .reducer_module
            .prepared_grep_count_symbol()
            .is_some()
        || !artifact
            .reducer_module
            .prepared_aggregate_exports()
            .is_empty()
        || artifact
            .reducer_module
            .prepared_aggregate_strategy()
            .is_some()
        || artifact.reducer_module.required_prepare_capabilities() != 0
    {
        return Err(UniformCaptureReducerAuthenticationError::LinkedReducerClosure);
    }

    let undefined = artifact
        .reducer_module
        .symbols()
        .iter()
        .filter(|symbol| symbol.section.is_none())
        .collect::<Vec<_>>();
    let global_defined_functions = artifact
        .reducer_module
        .symbols()
        .iter()
        .filter(|symbol| {
            symbol.binding == SymbolBinding::Global
                && symbol.kind == SymbolKind::Function
                && symbol.section.is_some()
        })
        .collect::<Vec<_>>();
    let local_defined_functions = artifact
        .reducer_module
        .symbols()
        .iter()
        .filter(|symbol| {
            symbol.binding == SymbolBinding::Local
                && symbol.kind == SymbolKind::Function
                && symbol.section.is_some()
        })
        .collect::<Vec<_>>();
    let semantic_runtime_calls = artifact
        .reducer_module
        .required_runtime_symbols()
        .filter(|symbol| symbol.starts_with("fre_aot_regex_runtime_"))
        .count();
    if undefined.len() != 1
        || undefined[0].name != receipt.row_entry_symbol
        || global_defined_functions.len() != 1
        || global_defined_functions[0].name != receipt.reducer_symbol
        || local_defined_functions.len() != 1
        || local_defined_functions[0].name != receipt.count_symbol
        || artifact.reducer_module.required_runtime_symbols().count() != 1
        || artifact.reducer_module.required_runtime_symbols().next()
            != Some(receipt.row_entry_symbol.as_str())
        || semantic_runtime_calls != receipt.semantic_runtime_calls
        || linked_reducer_external_row_relocation(
            &artifact.reducer_module,
            &receipt.row_entry_symbol,
        )? != receipt.row_relocation
    {
        return Err(UniformCaptureReducerAuthenticationError::LinkedReducerClosure);
    }

    let text = artifact
        .reducer_module
        .sections()
        .iter()
        .find(|section| section.kind == SectionKind::Text)
        .ok_or(UniformCaptureReducerAuthenticationError::LinkedReducerClosure)?;
    let object = emit_object(
        &rebuilt,
        ObjectFormat::for_target(receipt.target),
        receipt.max_object_bytes,
    )
    .map_err(|_| UniformCaptureReducerAuthenticationError::LinkedReducerObject)?;
    if receipt.reducer_code_sha256 != sha256(text.bytes())
        || receipt.reducer_object_bytes != artifact.reducer_object.len()
        || receipt.reducer_object_bytes > receipt.max_object_bytes
        || receipt.reducer_object_sha256 != sha256(&artifact.reducer_object)
        || object.as_slice() != artifact.reducer_object.as_ref()
        || receipt.artifact_identity_sha256 != linked_uniform_capture_artifact_identity(receipt)?
    {
        return Err(UniformCaptureReducerAuthenticationError::LinkedReducerObject);
    }
    Ok(())
}

enum LinkedPreparedRowUniformCaptureFinalization {
    Selected(LinkedPreparedRowUniformCaptureReducerV1),
    ObjectBytes,
}

fn finalize_linked_prepared_row_uniform_capture_reducer(
    row: CompiledRegex,
    participation: UniformCaptureParticipationReceipt,
    operation: UniformCaptureReducerOperation,
    max_object_bytes: usize,
) -> Result<LinkedPreparedRowUniformCaptureFinalization, UniformCaptureReducerCompileError> {
    authenticate_strict_prepared_row(&row)
        .map_err(UniformCaptureReducerCompileError::Authentication)?;
    let multiplier = u64::try_from(participation.participating_groups_per_match().get())
        .ok()
        .and_then(NonZeroU64::new)
        .ok_or(UniformCaptureReducerCompileError::Authentication(
            UniformCaptureReducerAuthenticationError::ProofMultiplier,
        ))?;
    let proof_identity =
        uniform_capture_proof_identity(participation, row.program().artifact_identity())
            .map_err(UniformCaptureReducerCompileError::Authentication)?;
    let row_entry = row.module().entry_symbol().to_owned();
    let (reducer_module, count_symbol, reducer_symbol) =
        crate::module::lower_linked_prepared_row_uniform_capture_reducer(
            row.receipt().target,
            operation.native_domain(),
            multiplier.get(),
            row.receipt().program_sha256,
            proof_identity,
            &row_entry,
        )
        .map_err(CompileError::from)
        .map_err(UniformCaptureReducerCompileError::Finalization)?;
    let reducer_object = match emit_object(
        &reducer_module,
        ObjectFormat::for_target(row.receipt().target),
        max_object_bytes,
    ) {
        Ok(object) => object,
        Err(ObjectError::Resource {
            resource: CompileResource::ObjectBytes,
            ..
        }) => return Ok(LinkedPreparedRowUniformCaptureFinalization::ObjectBytes),
        Err(error) => {
            return Err(UniformCaptureReducerCompileError::Finalization(
                CompileError::Object(error),
            ));
        }
    };
    let text = reducer_module
        .sections()
        .iter()
        .find(|section| section.kind == SectionKind::Text)
        .ok_or(UniformCaptureReducerCompileError::Authentication(
            UniformCaptureReducerAuthenticationError::LinkedReducerClosure,
        ))?;
    let row_relocation = linked_reducer_external_row_relocation(&reducer_module, &row_entry)
        .map_err(UniformCaptureReducerCompileError::Authentication)?;
    let mut receipt = LinkedPreparedRowUniformCaptureReducerReceiptV1 {
        schema_version: LINKED_PREPARED_ROW_UNIFORM_CAPTURE_REDUCER_V1_RECEIPT_VERSION,
        participation,
        operation,
        domain: operation.domain(),
        multiplier,
        proof_identity_sha256: proof_identity,
        target: row.receipt().target,
        line_terminator: row.receipt().line_terminator,
        row_automaton_sha256: row.receipt().automaton_sha256,
        row_program_sha256: row.receipt().program_sha256,
        row_object_sha256: row.receipt().object_sha256,
        row_object_bytes: row.object().len(),
        row_entry_symbol: row_entry,
        count_symbol,
        reducer_symbol,
        reducer_code_sha256: sha256(text.bytes()),
        reducer_object_sha256: sha256(&reducer_object),
        reducer_object_bytes: reducer_object.len(),
        max_object_bytes,
        row_relocation,
        semantic_runtime_calls: 0,
        artifact_identity_sha256: [0; 32],
    };
    receipt.artifact_identity_sha256 = linked_uniform_capture_artifact_identity(&receipt)
        .map_err(UniformCaptureReducerCompileError::Authentication)?;
    let artifact = LinkedPreparedRowUniformCaptureReducerV1 {
        row,
        reducer_module,
        reducer_object: reducer_object.into_boxed_slice(),
        receipt,
    };
    artifact
        .authenticate()
        .map_err(UniformCaptureReducerCompileError::Authentication)?;
    Ok(LinkedPreparedRowUniformCaptureFinalization::Selected(
        artifact,
    ))
}

/// Prove one nonzero uniform multiplier and compile the complete capture
/// operation into one generated scalar ABI entry.
///
/// An ordinary helper-free selector is preferred. Only its explicit
/// `RuntimeDependency` authentication refusal may select the independently
/// capability-authenticated Ordered-NFA V15 route. Semantic proof decline is
/// returned before selector construction; all later failures are terminal.
pub fn compile_uniform_capture_reducer(
    parsed: &RustParsed,
    request: UniformCaptureCompileRequest,
    operation: UniformCaptureReducerOperation,
) -> Result<UniformCaptureReducerCompileDisposition, UniformCaptureReducerCompileError> {
    match compile_uniform_capture_reducer_internal(parsed, request, operation, false)? {
        InternalUniformCaptureReducerCompileDisposition::Combined(selected) => {
            Ok(UniformCaptureReducerCompileDisposition::Selected(selected))
        }
        InternalUniformCaptureReducerCompileDisposition::PreparedRowSearch(_) => {
            Err(UniformCaptureReducerCompileError::Authentication(
                UniformCaptureReducerAuthenticationError::LinkedReceipt,
            ))
        }
        InternalUniformCaptureReducerCompileDisposition::Declined(decline) => {
            Ok(UniformCaptureReducerCompileDisposition::Declined(decline))
        }
    }
}

/// Compile a uniform capture reducer for a linker that can retain two objects.
///
/// This is additive to [`compile_uniform_capture_reducer`]. It first runs that
/// API's exact portfolio. Only a typed operation-only V15 `ObjectBytes`
/// decline may try the strict helper-free RowSearch plus separate reducer
/// topology; every safe decline then resumes the unchanged compatibility
/// compiler.
pub fn compile_uniform_capture_reducer_linked_v1(
    parsed: &RustParsed,
    request: UniformCaptureCompileRequest,
    operation: UniformCaptureReducerOperation,
) -> Result<UniformCaptureReducerLinkCompileDispositionV1, UniformCaptureReducerCompileError> {
    match compile_uniform_capture_reducer_internal(parsed, request, operation, true)? {
        InternalUniformCaptureReducerCompileDisposition::Combined(selected) => Ok(
            UniformCaptureReducerLinkCompileDispositionV1::Combined(selected),
        ),
        InternalUniformCaptureReducerCompileDisposition::PreparedRowSearch(selected) => {
            Ok(UniformCaptureReducerLinkCompileDispositionV1::PreparedRowSearch(selected))
        }
        InternalUniformCaptureReducerCompileDisposition::Declined(decline) => Ok(
            UniformCaptureReducerLinkCompileDispositionV1::Declined(decline),
        ),
    }
}

enum InternalUniformCaptureReducerCompileDisposition {
    Combined(CompiledUniformCaptureReducer),
    PreparedRowSearch(LinkedPreparedRowUniformCaptureReducerV1),
    Declined(UniformCaptureParticipationDecline),
}

fn compile_uniform_capture_reducer_internal(
    parsed: &RustParsed,
    request: UniformCaptureCompileRequest,
    operation: UniformCaptureReducerOperation,
    allow_linked_row_search: bool,
) -> Result<InternalUniformCaptureReducerCompileDisposition, UniformCaptureReducerCompileError> {
    let prospective = analyze_uniform_capture_participation(parsed, request.participation_limits)
        .map_err(UniformCaptureReducerCompileError::Participation)?;
    let prospective = match prospective {
        UniformCaptureParticipationDisposition::Declined(decline) => {
            return Ok(InternalUniformCaptureReducerCompileDisposition::Declined(
                decline,
            ));
        }
        UniformCaptureParticipationDisposition::Proven(receipt) => receipt,
    };
    let max_object_bytes = request.selector_limits.max_object_bytes;
    let ordinary = compile_uniform_capture_selector(parsed, request.clone());
    let (compiled, participation, count_is_already_appended) = match ordinary {
        Ok(compiled) => {
            compiled
                .authenticate()
                .map_err(|_| {
                    UniformCaptureReducerCompileError::Authentication(
                        UniformCaptureReducerAuthenticationError::NativeClosure,
                    )
                })?;
            let (selector, disposition) = compiled.into_parts();
            let proof = match disposition {
                UniformCaptureCompileDisposition::Proven(receipt) => receipt,
                UniformCaptureCompileDisposition::Declined(_) => {
                    return Err(UniformCaptureReducerCompileError::Authentication(
                        UniformCaptureReducerAuthenticationError::ProofIdentity,
                    ));
                }
            };
            proof
                .authenticate(&selector)
                .map_err(|_| {
                    UniformCaptureReducerCompileError::Authentication(
                        UniformCaptureReducerAuthenticationError::ProofIdentity,
                    )
                })?;
            (selector, proof.participation(), false)
        }
        Err(UniformCaptureCompileError::Authentication(
            UniformCaptureAuthenticationError::RuntimeDependency,
        )) => {
            let lowered = lower_raw_general(
                parsed,
                OperationSemantics::CaptureFree,
                request.selector_limits.lower,
            )
            .map_err(UniformCaptureCompileError::Lower)
            .map_err(UniformCaptureReducerCompileError::Ordinary)?;
            if prospective.canonical_capture_annotations() != lowered.stats().erased_captures() {
                return Err(UniformCaptureReducerCompileError::Authentication(
                    UniformCaptureReducerAuthenticationError::ProofIdentity,
                ));
            }
            let operation_only =
                super::compile_raw_prepared_ordered_nfa_v15_scalar_operation_reported(
                    request.source_bytes,
                    lowered.into_plan(),
                    request.profile.options.line_terminator,
                    OutputContract::Span,
                    request.target,
                    request.mode,
                    request.selector_limits,
                    PreparedAggregateExports::COUNT,
                    request.selector_slow_aot_limits.max_native_data_bytes,
                );
            match classify_uniform_capture_operation_only_attempt(operation_only)? {
                UniformCaptureOperationOnlyAttempt::Compiled(count) => {
                    authenticate_operation_only_uniform_capture_count(&count)
                        .map_err(UniformCaptureReducerCompileError::Authentication)?;
                    (count, prospective, true)
                }
                UniformCaptureOperationOnlyAttempt::ResumePreparedSpanFill(decline) => {
                    if allow_linked_row_search
                        && matches!(
                            decline,
                            PreparedOrderedNfaV15CompileDecline::ObjectBytes { .. }
                        )
                    {
                        if let Some(selected) = try_compile_linked_prepared_row_uniform_capture(
                            parsed,
                            &request,
                            prospective,
                            operation,
                        )? {
                            return Ok(
                                InternalUniformCaptureReducerCompileDisposition::PreparedRowSearch(
                                    selected,
                                ),
                            );
                        }
                    }
                    let prepared =
                        compile_uniform_capture_prepared_span_fill_selector(parsed, request)
                            .map_err(UniformCaptureReducerCompileError::Prepared)?;
                    let selected = match prepared {
                        UniformCapturePreparedSpanFillCompileDisposition::Selected(selected) => {
                            selected
                        }
                        UniformCapturePreparedSpanFillCompileDisposition::Declined(_) => {
                            return Err(UniformCaptureReducerCompileError::Authentication(
                                UniformCaptureReducerAuthenticationError::ProofIdentity,
                            ));
                        }
                    };
                    selected.authenticate().map_err(|_| {
                        UniformCaptureReducerCompileError::Authentication(
                            UniformCaptureReducerAuthenticationError::NativeClosure,
                        )
                    })?;
                    let (selector, receipt) = selected.into_parts();
                    (selector, receipt.participation(), false)
                }
            }
        }
        Err(error) => return Err(UniformCaptureReducerCompileError::Ordinary(error)),
    };
    if participation != prospective {
        return Err(UniformCaptureReducerCompileError::Authentication(
            UniformCaptureReducerAuthenticationError::ProofIdentity,
        ));
    }
    if count_is_already_appended {
        finalize_uniform_capture_reducer_from_count_aggregate(
            compiled,
            participation,
            operation,
            max_object_bytes,
        )
    } else {
        finalize_uniform_capture_reducer(
            compiled,
            participation,
            operation,
            max_object_bytes,
        )
    }
    .map(InternalUniformCaptureReducerCompileDisposition::Combined)
}

fn try_compile_linked_prepared_row_uniform_capture(
    parsed: &RustParsed,
    request: &UniformCaptureCompileRequest,
    prospective: UniformCaptureParticipationReceipt,
    operation: UniformCaptureReducerOperation,
) -> Result<Option<LinkedPreparedRowUniformCaptureReducerV1>, UniformCaptureReducerCompileError> {
    let lowered = lower_raw_general(
        parsed,
        OperationSemantics::CaptureFree,
        request.selector_limits.lower,
    )
    .map_err(UniformCaptureCompileError::Lower)
    .map_err(UniformCaptureReducerCompileError::Ordinary)?;
    if prospective.canonical_capture_annotations() != lowered.stats().erased_captures() {
        return Err(UniformCaptureReducerCompileError::Authentication(
            UniformCaptureReducerAuthenticationError::ProofIdentity,
        ));
    }
    let attempt = super::compile_raw_prepared_ordered_nfa_v15_row_search_reported(
        request.source_bytes,
        lowered.into_plan(),
        request.profile.options.line_terminator,
        OutputContract::Span,
        request.target,
        request.mode,
        request.selector_limits,
        request.selector_slow_aot_limits.max_native_data_bytes,
    );
    let row = match classify_uniform_capture_row_search_attempt(attempt)? {
        UniformCaptureRowSearchAttempt::Compiled(compiled) => compiled,
        UniformCaptureRowSearchAttempt::ResumeCompatibility(_) => return Ok(None),
    };
    match finalize_linked_prepared_row_uniform_capture_reducer(
        row,
        prospective,
        operation,
        request.selector_limits.max_object_bytes,
    )? {
        LinkedPreparedRowUniformCaptureFinalization::Selected(selected) => Ok(Some(selected)),
        LinkedPreparedRowUniformCaptureFinalization::ObjectBytes => Ok(None),
    }
}

#[derive(Debug)]
enum UniformCaptureRowSearchAttempt {
    Compiled(CompiledRegex),
    ResumeCompatibility(PreparedOrderedNfaV15CompileDecline),
}

fn classify_uniform_capture_row_search_attempt(
    attempt: Result<PreparedOrderedNfaV15CompileDisposition, CompileError>,
) -> Result<UniformCaptureRowSearchAttempt, UniformCaptureReducerCompileError> {
    match attempt {
        Ok(PreparedOrderedNfaV15CompileDisposition::Compiled(compiled)) => {
            Ok(UniformCaptureRowSearchAttempt::Compiled(compiled))
        }
        Ok(PreparedOrderedNfaV15CompileDisposition::Declined(
            decline @ (PreparedOrderedNfaV15CompileDecline::ObjectBytes { .. }
            | PreparedOrderedNfaV15CompileDecline::NativeDataBytes { .. }),
        )) => Ok(UniformCaptureRowSearchAttempt::ResumeCompatibility(
            decline,
        )),
        Ok(PreparedOrderedNfaV15CompileDisposition::Declined(
            PreparedOrderedNfaV15CompileDecline::Unsupported,
        )) => Err(UniformCaptureReducerCompileError::RowSearch(
            CompileError::InternalInvariant(
                "strict RowSearch became unsupported after operation-only ObjectBytes decline",
            ),
        )),
        Err(error) => Err(UniformCaptureReducerCompileError::RowSearch(error)),
    }
}

#[derive(Debug)]
enum UniformCaptureOperationOnlyAttempt {
    Compiled(CompiledRegex),
    ResumePreparedSpanFill(PreparedOrderedNfaV15CompileDecline),
}

fn classify_uniform_capture_operation_only_attempt(
    attempt: Result<PreparedOrderedNfaV15CompileDisposition, CompileError>,
) -> Result<UniformCaptureOperationOnlyAttempt, UniformCaptureReducerCompileError> {
    match attempt {
        Ok(PreparedOrderedNfaV15CompileDisposition::Compiled(compiled)) => {
            Ok(UniformCaptureOperationOnlyAttempt::Compiled(compiled))
        }
        Ok(PreparedOrderedNfaV15CompileDisposition::Declined(
            decline @ (PreparedOrderedNfaV15CompileDecline::Unsupported
            | PreparedOrderedNfaV15CompileDecline::NativeDataBytes { .. }
            | PreparedOrderedNfaV15CompileDecline::ObjectBytes { .. }),
        )) => Ok(UniformCaptureOperationOnlyAttempt::ResumePreparedSpanFill(
            decline,
        )),
        Err(error) => Err(UniformCaptureReducerCompileError::OperationOnly(error)),
    }
}

#[cfg(test)]
mod operation_only_fallback_policy_tests {
    use super::*;

    #[test]
    fn only_typed_declines_resume_span_fill_and_allocation_is_terminal() {
        let declines = [
            PreparedOrderedNfaV15CompileDecline::Unsupported,
            PreparedOrderedNfaV15CompileDecline::NativeDataBytes {
                limit: 7,
                required: 8,
            },
            PreparedOrderedNfaV15CompileDecline::ObjectBytes {
                limit: 11,
                required: 12,
            },
        ];
        for decline in declines {
            let selected = classify_uniform_capture_operation_only_attempt(Ok(
                PreparedOrderedNfaV15CompileDisposition::Declined(decline),
            ))
            .expect("typed operation-only decline");
            assert!(matches!(
                selected,
                UniformCaptureOperationOnlyAttempt::ResumePreparedSpanFill(actual)
                    if actual == decline
            ));
        }

        let terminal = classify_uniform_capture_operation_only_attempt(Err(
            CompileError::Object(crate::ObjectError::Allocation(
                "injected uniform-capture operation-only allocation",
            )),
        ));
        assert!(matches!(
            terminal,
            Err(UniformCaptureReducerCompileError::OperationOnly(
                CompileError::Object(crate::ObjectError::Allocation(
                    "injected uniform-capture operation-only allocation"
                ))
            ))
        ));
    }

    #[test]
    fn linked_row_resumes_only_numeric_declines_and_keeps_allocation_terminal() {
        for decline in [
            PreparedOrderedNfaV15CompileDecline::NativeDataBytes {
                limit: 7,
                required: 8,
            },
            PreparedOrderedNfaV15CompileDecline::ObjectBytes {
                limit: 11,
                required: 12,
            },
        ] {
            let classified = classify_uniform_capture_row_search_attempt(Ok(
                PreparedOrderedNfaV15CompileDisposition::Declined(decline),
            ))
            .expect("numeric strict-row decline");
            assert!(matches!(
                classified,
                UniformCaptureRowSearchAttempt::ResumeCompatibility(actual)
                    if actual == decline
            ));
        }
        assert!(matches!(
            classify_uniform_capture_row_search_attempt(Ok(
                PreparedOrderedNfaV15CompileDisposition::Declined(
                    PreparedOrderedNfaV15CompileDecline::Unsupported,
                ),
            )),
            Err(UniformCaptureReducerCompileError::RowSearch(
                CompileError::InternalInvariant(_)
            ))
        ));
        assert!(matches!(
            classify_uniform_capture_row_search_attempt(Err(CompileError::Object(
                ObjectError::Allocation("injected strict-row allocation"),
            ))),
            Err(UniformCaptureReducerCompileError::RowSearch(
                CompileError::Object(ObjectError::Allocation("injected strict-row allocation"))
            ))
        ));
    }
}

#[cfg(test)]
mod linked_row_compiler_tests {
    use super::*;
    use fre_syntax::{CanonicalPattern, CompatibilityProfile, ParseRequest, parse};

    const FIXTURE: &str = r"\b(?:([\w&&\p{Cyrillic}]{6})|([\w&&\p{Cyrillic}]{5}))\b";

    fn parsed_fixture() -> RustParsed {
        let parsed = parse(ParseRequest::rust(
            FIXTURE,
            CompatibilityProfile::RustBytes(RustProfile::rebar_1_12_4()),
        ))
        .expect("parse linked-row fixture");
        match parsed.pattern {
            CanonicalPattern::Rust(parsed) => parsed,
            CanonicalPattern::Re2(_) | CanonicalPattern::Re2Literal(_) => {
                panic!("Rust fixture produced a non-Rust pattern")
            }
        }
    }

    fn operation_only_object_decline_cap(parsed: &RustParsed, target: Target) -> usize {
        let request = UniformCaptureCompileRequest::new(FIXTURE.len(), target)
            .profile(RustProfile::rebar_1_12_4());
        let lowered = lower_raw_general(
            parsed,
            OperationSemantics::CaptureFree,
            request.selector_limits.lower,
        )
        .expect("lower linked-row fixture");
        let raw = lowered.into_plan();
        let mut cap = request.selector_limits.max_object_bytes;
        for _ in 0..16 {
            let mut limits = request.selector_limits;
            limits.max_object_bytes = cap;
            let attempt =
                super::super::compile_raw_prepared_ordered_nfa_v15_scalar_operation_reported(
                    request.source_bytes,
                    raw.clone(),
                    request.profile.options.line_terminator,
                    OutputContract::Span,
                    target,
                    request.mode,
                    limits,
                    PreparedAggregateExports::COUNT,
                    request.selector_slow_aot_limits.max_native_data_bytes,
                )
                .expect("operation-only sizing compile");
            match attempt {
                PreparedOrderedNfaV15CompileDisposition::Compiled(compiled) => {
                    cap = compiled
                        .object()
                        .len()
                        .checked_sub(1)
                        .expect("operation-only object is nonempty");
                }
                PreparedOrderedNfaV15CompileDisposition::Declined(
                    PreparedOrderedNfaV15CompileDecline::ObjectBytes { limit, required },
                ) => {
                    assert_eq!(limit, cap);
                    assert!(required > limit);
                    return cap;
                }
                PreparedOrderedNfaV15CompileDisposition::Declined(other) => {
                    panic!("operation-only sizing reached a non-object decline: {other:?}")
                }
            }
        }
        panic!("operation-only object retries did not converge")
    }

    #[test]
    fn object_decline_selects_two_object_row_reducer_cross_target_and_authenticates() {
        let parsed = parsed_fixture();
        for target in [Target::x86_64_linux(), Target::aarch64_linux()] {
            let cap = operation_only_object_decline_cap(&parsed, target);
            for operation in [
                UniformCaptureReducerOperation::CountCaptures,
                UniformCaptureReducerOperation::GrepCaptures,
            ] {
                let mut limits = CompileLimitsV1::default();
                limits.max_object_bytes = cap;
                let disposition = compile_uniform_capture_reducer_linked_v1(
                    &parsed,
                    UniformCaptureCompileRequest::new(FIXTURE.len(), target)
                        .profile(RustProfile::rebar_1_12_4())
                        .selector_limits(limits),
                    operation,
                )
                .unwrap_or_else(|error| {
                    panic!("linked-row compile failed for {target:?}/{operation:?}: {error}")
                });
                let selected = disposition.prepared_row_search().unwrap_or_else(|| {
                    panic!("linked-row route was not selected for {target:?}/{operation:?}")
                });
                selected.authenticate().expect("fresh linked-row receipt");
                let receipt = selected.receipt();
                assert_eq!(receipt.operation(), operation);
                assert_eq!(receipt.target(), target);
                assert_eq!(receipt.multiplier().get(), 2);
                assert_eq!(receipt.semantic_runtime_calls(), 0);
                assert!(receipt.row_object_bytes() <= cap);
                assert!(receipt.reducer_object_bytes() <= cap);
                assert_eq!(receipt.max_object_bytes(), cap);
                assert_eq!(
                    selected
                        .reducer_module()
                        .required_runtime_symbols()
                        .collect::<Vec<_>>(),
                    [selected.row().module().entry_symbol()],
                );
                assert_eq!(
                    selected.row().receipt().entry_abi,
                    EntryAbi::PreparedSpanSearchV1
                );
                assert_eq!(
                    selected.row().module().required_prepare_capabilities(),
                    PREPARED_CAPABILITY_ORDERED_NFA_V15,
                );

                let mut tampered = selected.clone();
                assert!(tampered.reducer_module.test_flip_text_byte(0));
                assert!(matches!(
                    tampered.authenticate(),
                    Err(UniformCaptureReducerAuthenticationError::LinkedReducerClosure)
                ));

                let mut row_tampered = selected.clone();
                assert!(row_tampered.test_flip_row_text_byte(0));
                assert!(matches!(
                    row_tampered.authenticate(),
                    Err(UniformCaptureReducerAuthenticationError::LinkedRowClosure)
                ));
            }
        }
    }
}

fn authenticate_operation_only_uniform_capture_count(
    compiled: &CompiledRegex,
) -> Result<(), UniformCaptureReducerAuthenticationError> {
    let receipt = compiled.receipt();
    let module = compiled.module();
    let count = module
        .prepared_count_symbol()
        .ok_or(UniformCaptureReducerAuthenticationError::CountSymbol)?;
    if receipt.output != OutputContract::Span
        || receipt.engine != EngineKind::OrderedNfa
        || receipt.entry_abi != EntryAbi::PreparedScalarReduceV1
        || receipt.prepared_aggregate_exports != PreparedAggregateExports::COUNT
        || receipt.prepared_aggregate_strategy
            != Some(PreparedAggregateStrategy::NativeOrderedNfaFused)
        || receipt.required_prepare_capabilities != PREPARED_CAPABILITY_ORDERED_NFA_V15
        || receipt.runtime_helper_required
        || module.prepared_aggregate_exports() != PreparedAggregateExports::COUNT
        || module.prepared_aggregate_strategy()
            != Some(PreparedAggregateStrategy::NativeOrderedNfaFused)
        || module.required_prepare_capabilities() != PREPARED_CAPABILITY_ORDERED_NFA_V15
        || module.prepared_bulk_strategy().is_some()
        || module.prepared_entry_symbol().is_some()
        || module.prepared_span_fill_symbol().is_some()
        || module.required_runtime_symbols().next().is_some()
        || module.required_runtime_program().is_none()
        || count != module.entry_symbol()
    {
        return Err(UniformCaptureReducerAuthenticationError::AggregateRoute);
    }
    Ok(())
}

fn finalize_uniform_capture_reducer(
    compiled: CompiledRegex,
    participation: UniformCaptureParticipationReceipt,
    operation: UniformCaptureReducerOperation,
    max_object_bytes: usize,
) -> Result<CompiledUniformCaptureReducer, UniformCaptureReducerCompileError> {
    let multiplier = u64::try_from(participation.participating_groups_per_match().get())
        .ok()
        .and_then(NonZeroU64::new)
        .ok_or(UniformCaptureReducerCompileError::Authentication(
            UniformCaptureReducerAuthenticationError::ProofMultiplier,
        ))?;
    let proof_identity = uniform_capture_proof_identity(
        participation,
        compiled.program().artifact_identity(),
    )
    .map_err(UniformCaptureReducerCompileError::Authentication)?;
    let CompiledRegex {
        program,
        module,
        object,
        receipt,
    } = compiled;
    drop(object);
    let artifact_identity = program.artifact_identity();
    let serialized_program = program
        .serialize()
        .map_err(CompileError::from)
        .map_err(UniformCaptureReducerCompileError::Finalization)?;
    let module = module
        .append_prepared_aggregate_exports(
            PreparedAggregateExports::COUNT,
            artifact_identity,
            &serialized_program,
        )
        .map_err(CompileError::from)
        .map_err(UniformCaptureReducerCompileError::Finalization)?;
    let finalized = finalize_native_uniform_capture_reducer_parts(
        program,
        module,
        receipt,
        operation,
        multiplier,
        proof_identity,
        max_object_bytes,
    )?;
    seal_finalized_uniform_capture_reducer(
        finalized,
        participation,
        operation,
        multiplier,
        proof_identity,
    )
}

fn finalize_uniform_capture_reducer_from_count_aggregate(
    compiled: CompiledRegex,
    participation: UniformCaptureParticipationReceipt,
    operation: UniformCaptureReducerOperation,
    max_object_bytes: usize,
) -> Result<CompiledUniformCaptureReducer, UniformCaptureReducerCompileError> {
    let multiplier = u64::try_from(participation.participating_groups_per_match().get())
        .ok()
        .and_then(NonZeroU64::new)
        .ok_or(UniformCaptureReducerCompileError::Authentication(
            UniformCaptureReducerAuthenticationError::ProofMultiplier,
        ))?;
    let proof_identity = uniform_capture_proof_identity(
        participation,
        compiled.program().artifact_identity(),
    )
    .map_err(UniformCaptureReducerCompileError::Authentication)?;
    let finalized = append_native_uniform_capture_reducer_to_count_aggregate(
        compiled,
        operation,
        multiplier,
        proof_identity,
        max_object_bytes,
    )?;
    seal_finalized_uniform_capture_reducer(
        finalized,
        participation,
        operation,
        multiplier,
        proof_identity,
    )
}

fn seal_finalized_uniform_capture_reducer(
    finalized: FinalizedNativeUniformCaptureReducer,
    participation: UniformCaptureParticipationReceipt,
    operation: UniformCaptureReducerOperation,
    multiplier: NonZeroU64,
    proof_identity: [u8; 32],
) -> Result<CompiledUniformCaptureReducer, UniformCaptureReducerCompileError> {
    let compiled = finalized.compiled;
    let reducer_symbol = finalized.reducer_symbol;
    let compiler = compiled.receipt();
    let capture_receipt = UniformCaptureReducerCompileReceipt {
        participation,
        operation,
        domain: operation.domain(),
        multiplier,
        proof_identity_sha256: proof_identity,
        selector_automaton_sha256: compiler.automaton_sha256,
        selector_program_sha256: compiler.program_sha256,
        selector_object_sha256: compiler.object_sha256,
        count_symbol_sha256: finalized.count_symbol_sha256,
        reducer_symbol_sha256: sha256(reducer_symbol.as_bytes()),
        target: compiler.target,
        line_terminator: compiler.line_terminator,
        aggregate_strategy: finalized.aggregate_strategy,
        required_prepare_capabilities: compiler.required_prepare_capabilities,
    };
    let selected = CompiledUniformCaptureReducer {
        compiled,
        reducer_symbol,
        receipt: capture_receipt,
    };
    selected
        .authenticate()
        .map_err(UniformCaptureReducerCompileError::Authentication)?;
    Ok(selected)
}

/// Final native wrapper state shared by the one-pattern proof and an
/// independently authenticated ordered-many capture proof.
#[derive(Debug)]
pub(crate) struct FinalizedNativeUniformCaptureReducer {
    pub(crate) compiled: CompiledRegex,
    pub(crate) reducer_symbol: String,
    pub(crate) count_symbol_sha256: [u8; 32],
    pub(crate) aggregate_strategy: PreparedAggregateStrategy,
}

/// Append the same one-call multiplier wrapper to an already emitted exact
/// native Count aggregate. `proof_identity` is caller-issued and must bind the
/// independently authenticated source/proof transaction authorizing
/// `multiplier`; it is included in the generated symbol identity and checked
/// again against the final module.
///
/// This crate-private seam intentionally does not accept a generic runtime
/// operation program. Its input object must already close as one exact native
/// Count aggregate, and allocator/object-cap failures remain terminal.
pub(crate) fn append_native_uniform_capture_reducer_to_count_aggregate(
    compiled: CompiledRegex,
    operation: UniformCaptureReducerOperation,
    multiplier: NonZeroU64,
    proof_identity: [u8; 32],
    max_object_bytes: usize,
) -> Result<FinalizedNativeUniformCaptureReducer, UniformCaptureReducerCompileError> {
    if compiled.object().is_empty()
        || compiled.receipt().object_bytes != compiled.object().len()
        || compiled.receipt().object_sha256 != sha256(compiled.object())
        || compiled.receipt().program_sha256 != compiled.program().artifact_identity()
    {
        return Err(UniformCaptureReducerCompileError::Authentication(
            UniformCaptureReducerAuthenticationError::SelectorObjectDigest,
        ));
    }
    let CompiledRegex {
        program,
        module,
        object,
        receipt,
    } = compiled;
    drop(object);
    finalize_native_uniform_capture_reducer_parts(
        program,
        module,
        receipt,
        operation,
        multiplier,
        proof_identity,
        max_object_bytes,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the final object transaction has explicit semantic and resource identities"
)]
fn finalize_native_uniform_capture_reducer_parts(
    program: CompiledProgram,
    module: CompiledModule,
    mut receipt: CompileReceipt,
    operation: UniformCaptureReducerOperation,
    multiplier: NonZeroU64,
    proof_identity: [u8; 32],
    max_object_bytes: usize,
) -> Result<FinalizedNativeUniformCaptureReducer, UniformCaptureReducerCompileError> {
    if proof_identity == [0; 32]
        || receipt.output != OutputContract::Span
        || receipt.target != module.target()
        || receipt.program_sha256 != program.artifact_identity()
        || module.prepared_aggregate_exports() != PreparedAggregateExports::COUNT
    {
        return Err(UniformCaptureReducerCompileError::Authentication(
            UniformCaptureReducerAuthenticationError::AggregateRoute,
        ));
    }
    let aggregate_strategy = module.prepared_aggregate_strategy().ok_or(
        UniformCaptureReducerCompileError::Authentication(
            UniformCaptureReducerAuthenticationError::AggregateRoute,
        ),
    )?;
    if !matches!(
        aggregate_strategy,
        PreparedAggregateStrategy::NativeFused
            | PreparedAggregateStrategy::NativeOrderedNfaFused
    ) {
        return Err(UniformCaptureReducerCompileError::Authentication(
            UniformCaptureReducerAuthenticationError::AggregateRoute,
        ));
    }
    let artifact_identity = program.artifact_identity();
    let (module, reducer_symbol) = module
        .append_native_uniform_capture_reducer(
            operation.native_domain(),
            multiplier.get(),
            artifact_identity,
            proof_identity,
        )
        .map_err(CompileError::from)
        .map_err(UniformCaptureReducerCompileError::Finalization)?;
    module
        .authenticate_native_uniform_capture_reducer(
            operation.native_domain(),
            multiplier.get(),
            artifact_identity,
            proof_identity,
            &reducer_symbol,
        )
        .map_err(|_| {
            UniformCaptureReducerCompileError::Authentication(
                UniformCaptureReducerAuthenticationError::NativeClosure,
            )
        })?;
    let count_symbol = module.prepared_count_symbol().ok_or(
        UniformCaptureReducerCompileError::Authentication(
            UniformCaptureReducerAuthenticationError::CountSymbol,
        ),
    )?;
    let count_symbol_sha256 = sha256(count_symbol.as_bytes());
    let object = emit_object(
        &module,
        ObjectFormat::for_target(receipt.target),
        max_object_bytes,
    )
    .map_err(CompileError::from)
    .map_err(UniformCaptureReducerCompileError::Finalization)?;
    let object_sha256 = sha256(&object);
    receipt.object_sha256 = object_sha256;
    receipt.runtime_helper_required = module.required_runtime_symbols().next().is_some();
    receipt.prepared_aggregate_exports = module.prepared_aggregate_exports();
    receipt.prepared_aggregate_strategy = module.prepared_aggregate_strategy();
    receipt.required_prepare_capabilities = module.required_prepare_capabilities();
    receipt.code_bytes = module.code_bytes();
    receipt.data_bytes = module
        .sections()
        .iter()
        .filter(|section| section.kind == SectionKind::ReadOnlyData)
        .map(|section| section.data.len())
        .sum();
    receipt.object_bytes = object.len();
    Ok(FinalizedNativeUniformCaptureReducer {
        compiled: CompiledRegex {
            program,
            module,
            object: object.into_boxed_slice(),
            receipt,
        },
        reducer_symbol,
        count_symbol_sha256,
        aggregate_strategy,
    })
}

fn uniform_capture_proof_identity(
    participation: UniformCaptureParticipationReceipt,
    selector_program_sha256: [u8; 32],
) -> Result<[u8; 32], UniformCaptureReducerAuthenticationError> {
    if !participation.identity().authenticates_current() {
        return Err(UniformCaptureReducerAuthenticationError::ProofIdentity);
    }
    let to_u64 = |value: usize| {
        u64::try_from(value).map_err(|_| UniformCaptureReducerAuthenticationError::ProofBinding)
    };
    let identity = participation.identity();
    let mut digest = Sha256::new();
    digest.update(b"fre-aot-regex/uniform-capture-proof-binding/v1\0");
    digest.update(identity.algorithm_version().to_le_bytes());
    digest.update(identity.accounting_version().to_le_bytes());
    digest.update(selector_program_sha256);
    digest.update(to_u64(participation.minimum_match_bytes().get())?.to_le_bytes());
    digest.update(to_u64(participation.participating_user_captures())?.to_le_bytes());
    digest.update(to_u64(participation.participating_groups_per_match().get())?.to_le_bytes());
    digest.update(to_u64(participation.canonical_capture_annotations())?.to_le_bytes());
    digest.update(participation.work().to_le_bytes());
    digest.update(to_u64(participation.peak_stack_items())?.to_le_bytes());
    Ok(digest.finalize().into())
}
