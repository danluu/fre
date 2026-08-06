//! General, self-contained AOT compilation for FRE's capture-free automata.
//!
//! Unlike the legacy template compiler, this crate admits a pattern because
//! [`fre_lower`] can lower it to a validated prioritized Thompson automaton,
//! not because its source or graph matches a small recipe list. The fast mode
//! freezes the universal ordered-TNFA representation. The optimizing mode
//! additionally performs complete byte-local or contextual ordered
//! determinization, reverse-machine construction for exact span recovery,
//! alphabet reduction, and target lowering under explicit resource limits.
//!
//! Object production is deterministic and does not invoke LLVM, a C compiler,
//! an assembler, a linker, or any subprocess.

#![forbid(unsafe_code)]

mod bounded_suffix_retry;
mod context_dfa;
mod context_native;
mod dfa;
mod dfa_loop_skip;
mod error;
mod module;
mod object;
mod prefix_block;
mod prefix_fast_forward;
mod prefix_predicate;
mod prefix_relation;
mod program;
mod required_literals;
mod seeded_reverse;

use fre_automata::{Automaton, RawPlan};
use fre_lower::{LowerLimits, OperationSemantics};
use fre_syntax::{CanonicalPattern, CompatibilityProfile, ParseRequest, RustProfile};
use sha2::{Digest, Sha256};

pub use context_dfa::{ContextDfaDecline, ContextDfaResource, ContextDfaStats};
pub use dfa::{
    DeterminizationDecline, DeterminizationReport, DeterminizationResource, DeterminizationStage,
    DeterminizeLimits, DfaStats, MAX_STABLE_DFA_BUILD_WORK, MAX_STABLE_DFA_STATES,
    MAX_STABLE_DFA_TRANSITIONS,
};
pub use error::{CompileError, CompileResource, ObjectError};
pub use module::{
    Architecture, CallAbi, CompiledModule, CpuFeature, FeatureSet, ModuleRelocation, ModuleSection,
    ModuleSymbol, OperatingSystem, RelocationKind, SectionKind, StartAccelerator, SymbolBinding,
    SymbolKind, Target,
};
pub use object::{ObjectFormat, emit_object};
pub use program::{
    AnchoredPrefixStats, CompiledProgram, ContextDeterminizationReport, DynamicNativeRowsV1,
    EngineKind,
    EngineSelectionReason, MAX_ANCHORED_PREFIX_BYTES, MAX_SERIALIZED_PROGRAM_BYTES, MatchResult,
    OutputContract, PROGRAM_HEADER_LEN, PartialDfaStats, ProgramFormatError, ProgramStats,
    ProgramWorkspace, RetainedPartialPreflight, SearchWindow,
};

/// Stable compiler pipeline identity.
pub const COMPILER_VERSION: u32 = 1;
/// Stable optimizer/cost-model identity.
pub const OPTIMIZER_VERSION: u32 = 1;

/// Deterministic pass identity retained in every compiler receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OptimizationPass {
    ValidateAutomaton,
    CanonicalDigest,
    AnchoredPrefixAnalysis,
    UniversalOrderedTnfa,
    OrderedDeterminization,
    ContextOrderedDeterminization,
    ContextNativeLowering,
    DfaStateMinimization,
    ReverseStartRecovery,
    ExactWidthStartRecovery,
    AlphabetPartition,
    AlphabetColumnCoalescing,
    RemoveUnusedReverseMachine,
    OutputContractSpecialization,
    ConstantFold,
    StrengthReduceRowAddressing,
    StartStateScanAcceleration,
    AnchoredPrefixCandidateFilter,
    TargetInstructionSelection,
    FixedRegisterAssignment,
    CheckedBranchFixup,
    RuntimeAdapterLowering,
    PositionIndependentDataLayout,
    RelocatableObjectSerialization,
}

/// User-selected compilation strategy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompileMode {
    /// Freeze the general ordered-TNFA plan with minimal analysis.
    Fast,
    /// Run complete ordered determinization and target optimization.
    Optimizing,
}

/// Checked limits for one complete compilation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompileLimitsV1 {
    pub lower: LowerLimits,
    pub determinize: DeterminizeLimits,
    pub max_program_bytes: usize,
    pub max_object_bytes: usize,
}

impl Default for CompileLimitsV1 {
    fn default() -> Self {
        Self {
            lower: LowerLimits::default(),
            determinize: DeterminizeLimits::default(),
            max_program_bytes: 256 * 1024 * 1024,
            max_object_bytes: 512 * 1024 * 1024,
        }
    }
}

/// Complete explicit compiler request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompileRequest {
    pub pattern: String,
    pub profile: RustProfile,
    pub output: OutputContract,
    pub target: Target,
    pub mode: CompileMode,
    pub limits: CompileLimitsV1,
}

impl CompileRequest {
    #[must_use]
    pub fn new(pattern: impl Into<String>, target: Target) -> Self {
        Self {
            pattern: pattern.into(),
            profile: RustProfile::default(),
            output: OutputContract::Span,
            target,
            mode: CompileMode::Optimizing,
            limits: CompileLimitsV1::default(),
        }
    }

    #[must_use]
    pub const fn output(mut self, output: OutputContract) -> Self {
        self.output = output;
        self
    }

    #[must_use]
    pub const fn mode(mut self, mode: CompileMode) -> Self {
        self.mode = mode;
        self
    }

    #[must_use]
    pub const fn limits(mut self, limits: CompileLimitsV1) -> Self {
        self.limits = limits;
        self
    }

    #[must_use]
    pub fn profile(mut self, profile: RustProfile) -> Self {
        self.profile = profile;
        self
    }
}

/// Structural, source-independent record of the selected compiler route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompileReceipt {
    pub compiler_version: u32,
    pub optimizer_version: u32,
    pub mode: CompileMode,
    pub output: OutputContract,
    pub target: Target,
    /// Byte configured as the line terminator for this semantic program.
    pub line_terminator: u8,
    pub automaton_sha256: [u8; 32],
    /// SHA-256 of [`CompiledProgram::serialize`] for this compilation.
    pub program_sha256: [u8; 32],
    /// SHA-256 of the complete emitted relocatable object.
    pub object_sha256: [u8; 32],
    pub engine: EngineKind,
    pub engine_selection_reason: EngineSelectionReason,
    /// Requested/effective limits, completed stages, and any exact resource
    /// decline from target-neutral determinization.
    pub determinization: DeterminizationReport,
    pub source_bytes: usize,
    pub thompson_states: usize,
    pub thompson_edges: usize,
    pub dfa: Option<DfaStats>,
    /// Fresh contextual-determinization outcome. This is absent when no
    /// contextual attempt occurred and after stable program deserialization.
    pub context_determinization: Option<ContextDeterminizationReport>,
    /// Bounded, graph-only required-prefix facts derived for this program.
    pub anchored_prefix: AnchoredPrefixStats,
    /// Consumed byte width shared by every accepting path, when proved from
    /// the complete lowered graph under a fixed work ceiling.
    pub exact_match_width: Option<usize>,
    pub passes: Box<[OptimizationPass]>,
    pub runtime_helper_required: bool,
    /// Graph-derived start scanner actually present in the native module.
    pub start_accelerator: StartAccelerator,
    /// Required prefix depth checked before a native start candidate enters
    /// the DFA, or zero when no multi-byte filter was emitted.
    pub anchored_prefix_filter_bytes: u8,
    pub program_bytes: usize,
    pub code_bytes: usize,
    pub data_bytes: usize,
    pub object_bytes: usize,
}

/// One complete compiler result.
#[derive(Clone, Debug)]
pub struct CompiledRegex {
    program: CompiledProgram,
    module: CompiledModule,
    object: Box<[u8]>,
    receipt: CompileReceipt,
}

/// Reusable execution storage prepared by an AOT compiler result.
///
/// This wrapper is intentionally distinct from [`ProgramWorkspace`]. It lets
/// the AOT facade select a retained partial-DFA entry without adding a field
/// load or branch to [`CompiledProgram::search_with_workspace`].
#[derive(Debug)]
pub struct CompiledRegexWorkspace {
    program: ProgramWorkspace,
}

impl CompiledRegex {
    #[must_use]
    pub const fn program(&self) -> &CompiledProgram {
        &self.program
    }

    #[must_use]
    pub const fn module(&self) -> &CompiledModule {
        &self.module
    }

    #[must_use]
    pub fn object(&self) -> &[u8] {
        &self.object
    }

    #[must_use]
    pub const fn receipt(&self) -> &CompileReceipt {
        &self.receipt
    }

    /// Allocate reusable execution storage for this compiler result.
    ///
    /// # Errors
    ///
    /// Returns a portable executor error if the universal NFA workspace
    /// cannot be prepared.
    pub fn prepare_workspace(&self) -> Result<CompiledRegexWorkspace, CompileError> {
        Ok(CompiledRegexWorkspace {
            program: self.program.prepare_workspace()?,
        })
    }

    /// Execute with storage prepared by this AOT compiler result.
    ///
    /// Retained rows are selected through the program's separate optimizing
    /// entry, outside the ordinary semantic dispatch. Short windows use the
    /// exact ordinary prepared entry because retained-row setup has a fixed
    /// cost that they cannot amortize.
    ///
    /// # Errors
    ///
    /// Returns a typed invalid-window error before reading the haystack, a
    /// portable executor error, or an invariant error if `workspace` belongs
    /// to a different semantic program.
    #[inline(never)]
    pub fn search_with_workspace(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut CompiledRegexWorkspace,
    ) -> Result<MatchResult, CompileError> {
        self.program
            .search_optimized_with_workspace(haystack, window, &mut workspace.program)
    }

    /// Execute the compiler's target-neutral semantic program.
    ///
    /// This is the differential-testing and portable-adoption boundary. Native
    /// consumers link the emitted object and the versioned runtime entry
    /// declared by [`CompiledModule::required_runtime_symbol`].
    ///
    /// # Errors
    ///
    /// Returns a typed error for an invalid search window.
    pub fn search(
        &self,
        haystack: &[u8],
        window: SearchWindow,
    ) -> Result<MatchResult, CompileError> {
        let mut workspace = self.prepare_workspace()?;
        self.search_with_workspace(haystack, window, &mut workspace)
    }
}

impl CompiledModule {
    /// Return the unresolved runtime helper required when linking this module.
    ///
    /// Direct native byte-local and contextual DFA modules return `None`. The existing
    /// [`Self::runtime_symbol`] method remains a compatibility accessor for the
    /// stable helper name, even when no helper is required.
    #[must_use]
    pub fn required_runtime_symbol(&self) -> Option<&str> {
        let compatibility_name = self.runtime_symbol();
        self.symbols()
            .iter()
            .find(|symbol| symbol.section.is_none() && symbol.name == compatibility_name)
            .map(|symbol| symbol.name.as_str())
    }
}

/// Compile a Rust byte regex through the general AOT pipeline.
///
/// Every pattern that reaches lowering enters the same automaton pipeline.
/// Selection depends only on the validated graph, output contract, explicit
/// target, mode, and limits. The returned [`CompileReceipt`] records the exact
/// structural engine-selection reason and SHA-256 identities for both the
/// semantic program and emitted object.
///
/// # Errors
///
/// Returns a typed syntax, lowering, resource, determinization, target, or
/// object-production failure.
pub fn compile(request: CompileRequest) -> Result<CompiledRegex, CompileError> {
    let CompileRequest {
        pattern,
        profile,
        output,
        target,
        mode,
        limits,
    } = request;
    let source_bytes = pattern.len();
    let line_terminator = profile.options.line_terminator;
    let profile = CompatibilityProfile::RustBytes(profile);
    let parsed = fre_syntax::parse(ParseRequest::rust(pattern, profile))?;
    let CanonicalPattern::Rust(parsed) = parsed.pattern else {
        return Err(CompileError::InternalInvariant(
            "Rust byte request produced a non-Rust syntax tree",
        ));
    };
    let lowered =
        fre_lower::lower_raw_general(&parsed, OperationSemantics::CaptureFree, limits.lower)?;
    compile_raw_with_line_terminator(
        source_bytes,
        lowered.into_plan(),
        line_terminator,
        output,
        target,
        mode,
        limits,
    )
}

/// Compile an already-lowered canonical automaton.
///
/// This entry is primarily useful for exhaustive and generated semantic tests;
/// production source compilation should use [`compile`].
///
/// # Errors
///
/// Returns a typed validation, resource, determinization, target, or object
/// failure.
pub fn compile_raw(
    source_bytes: usize,
    raw: RawPlan,
    output: OutputContract,
    target: Target,
    mode: CompileMode,
    limits: CompileLimitsV1,
) -> Result<CompiledRegex, CompileError> {
    compile_raw_with_line_terminator(source_bytes, raw, b'\n', output, target, mode, limits)
}

/// Compile an already-lowered canonical automaton with explicit line
/// semantics.
///
/// The lowered graph must have been produced with the same line terminator
/// when syntax such as `.` depends on that byte. Contextual multiline
/// assertions use `line_terminator` directly at execution time.
///
/// # Errors
///
/// Returns a typed validation, resource, determinization, target, or object
/// failure.
pub fn compile_raw_with_line_terminator(
    source_bytes: usize,
    raw: RawPlan,
    line_terminator: u8,
    output: OutputContract,
    target: Target,
    mode: CompileMode,
    limits: CompileLimitsV1,
) -> Result<CompiledRegex, CompileError> {
    let digest = program::automaton_digest(&raw, line_terminator);
    let automaton = Automaton::from_raw(raw.clone(), limits.lower.automata)?
        .with_line_terminator(line_terminator);
    let stats = automaton.stats();
    let program = CompiledProgram::build(
        raw,
        automaton,
        output,
        mode,
        limits.determinize,
        limits.max_program_bytes,
    )?;
    let program_bytes = program.serialized_len()?;
    let program_sha256 = program.artifact_identity();
    let module = CompiledModule::lower(&program, target)?;
    let format = ObjectFormat::for_target(target);
    let object = emit_object(&module, format, limits.max_object_bytes)?;
    let object_sha256 = Sha256::digest(&object).into();
    let engine_selection_reason =
        program
            .engine_selection_reason()
            .ok_or(CompileError::InternalInvariant(
                "newly compiled program lost engine-selection provenance",
            ))?;
    let determinization =
        program
            .determinization_report()
            .cloned()
            .ok_or(CompileError::InternalInvariant(
                "newly compiled program lost determinization provenance",
            ))?;
    let receipt = CompileReceipt {
        compiler_version: COMPILER_VERSION,
        optimizer_version: OPTIMIZER_VERSION,
        mode,
        output,
        target,
        line_terminator,
        automaton_sha256: digest,
        program_sha256,
        object_sha256,
        engine: program.engine_kind(),
        engine_selection_reason,
        determinization,
        source_bytes,
        thompson_states: stats.states(),
        thompson_edges: stats.edges(),
        dfa: program.dfa_stats(),
        context_determinization: program.context_determinization_report().cloned(),
        anchored_prefix: program.anchored_prefix_stats(),
        exact_match_width: program.exact_match_width(),
        passes: selected_passes(&program, &module).into_boxed_slice(),
        runtime_helper_required: module.required_runtime_symbol().is_some(),
        start_accelerator: module.start_accelerator(),
        anchored_prefix_filter_bytes: module.anchored_prefix_filter_bytes(),
        program_bytes,
        code_bytes: module.code_bytes(),
        data_bytes: module
            .sections()
            .iter()
            .filter(|section| section.kind == SectionKind::ReadOnlyData)
            .map(|section| section.data.len())
            .sum(),
        object_bytes: object.len(),
    };
    Ok(CompiledRegex {
        program,
        module,
        object: object.into_boxed_slice(),
        receipt,
    })
}

fn selected_passes(program: &CompiledProgram, module: &CompiledModule) -> Vec<OptimizationPass> {
    let mut passes = vec![
        OptimizationPass::ValidateAutomaton,
        OptimizationPass::CanonicalDigest,
        OptimizationPass::AnchoredPrefixAnalysis,
    ];
    if let Some(report) = program.determinization_report() {
        for &stage in report.completed_stages.as_ref() {
            passes.push(match stage {
                DeterminizationStage::AlphabetPartition => OptimizationPass::AlphabetPartition,
                DeterminizationStage::ForwardSubsetConstruction => {
                    OptimizationPass::OrderedDeterminization
                }
                DeterminizationStage::ReverseSubsetConstruction => {
                    OptimizationPass::ReverseStartRecovery
                }
                DeterminizationStage::DfaStateMinimization => {
                    OptimizationPass::DfaStateMinimization
                }
                DeterminizationStage::AlphabetColumnCoalescing => {
                    OptimizationPass::AlphabetColumnCoalescing
                }
            });
        }
    }
    match program.engine_kind() {
        EngineKind::OrderedNfa if module.required_runtime_symbol().is_some() => passes
            .extend_from_slice(&[
                OptimizationPass::UniversalOrderedTnfa,
                OptimizationPass::RuntimeAdapterLowering,
            ]),
        EngineKind::OrderedNfa => {
            // A resource decline can leave a complete retained forward
            // transducer even though the stable semantic engine remains the
            // universal ordered TNFA. When that table is lowered directly,
            // report the native passes actually present in the object rather
            // than claiming that a runtime adapter was emitted.
            passes.push(OptimizationPass::UniversalOrderedTnfa);
            append_native_dfa_passes(&mut passes, program, module, true);
        }
        EngineKind::OrderedDfa => {
            let reverse_unused = program
                .dfa_stats()
                .is_some_and(|stats| stats.reverse_states == 0);
            append_native_dfa_passes(&mut passes, program, module, reverse_unused);
        }
        EngineKind::OrderedContextDfa => {
            passes.extend_from_slice(&[
                OptimizationPass::AlphabetPartition,
                OptimizationPass::ContextOrderedDeterminization,
                OptimizationPass::ReverseStartRecovery,
                OptimizationPass::OutputContractSpecialization,
                OptimizationPass::ConstantFold,
                OptimizationPass::StrengthReduceRowAddressing,
            ]);
            if module.start_accelerator() != StartAccelerator::None {
                passes.push(OptimizationPass::StartStateScanAcceleration);
            }
            if module.anchored_prefix_filter_bytes() != 0 {
                passes.push(OptimizationPass::AnchoredPrefixCandidateFilter);
            }
            passes.extend_from_slice(&[
                OptimizationPass::ContextNativeLowering,
                OptimizationPass::TargetInstructionSelection,
                OptimizationPass::FixedRegisterAssignment,
                OptimizationPass::CheckedBranchFixup,
            ]);
        }
    }
    passes.extend_from_slice(&[
        OptimizationPass::PositionIndependentDataLayout,
        OptimizationPass::RelocatableObjectSerialization,
    ]);
    passes
}

fn append_native_dfa_passes(
    passes: &mut Vec<OptimizationPass>,
    program: &CompiledProgram,
    module: &CompiledModule,
    reverse_unused: bool,
) {
    if reverse_unused {
        passes.push(OptimizationPass::RemoveUnusedReverseMachine);
    }
    if program.output_contract() == OutputContract::Span && program.exact_match_width().is_some() {
        passes.push(OptimizationPass::ExactWidthStartRecovery);
    }
    passes.extend_from_slice(&[
        OptimizationPass::OutputContractSpecialization,
        OptimizationPass::ConstantFold,
        OptimizationPass::StrengthReduceRowAddressing,
    ]);
    if module.start_accelerator() != StartAccelerator::None {
        passes.push(OptimizationPass::StartStateScanAcceleration);
    }
    if module.anchored_prefix_filter_bytes() != 0 {
        passes.push(OptimizationPass::AnchoredPrefixCandidateFilter);
    }
    passes.extend_from_slice(&[
        OptimizationPass::TargetInstructionSelection,
        OptimizationPass::FixedRegisterAssignment,
        OptimizationPass::CheckedBranchFixup,
    ]);
}

#[cfg(test)]
mod tests;
