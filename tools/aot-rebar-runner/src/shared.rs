use std::{collections::BTreeMap, fmt, time::Duration};

use fre_aot_regex::{
    compile, compile_ordered_many_aot_reported, compile_rebar_single_capture_aot_v1,
    compile_rebar_single_capture_participation_aot_v1,
    compile_uniform_capture_prepared_span_fill_selector, compile_uniform_capture_reducer,
    compile_uniform_capture_selector,
    compile_with_prepared_aggregate_exports_and_slow_aot_limits,
    compile_with_prepared_ordered_nfa_v15_reported, compile_with_slow_aot_limits, Architecture,
    CaptureCompileError, CaptureCompileLimits, CompileError, CompileLimitsV1, CompileMode,
    CompileRequest, CompiledRegex, DeterminizeLimits, EngineKind, FeatureSet,
    NativeParticipationAotErrorV1, NativeParticipationAotLimitsV1,
    NativeParticipationAotResourceV1, NativeParticipationAotStrategyV1, OperatingSystem,
    OrderedManyAotArtifact, OrderedManyAotCompileDecline, OrderedManyAotCompileDisposition,
    OrderedManyAotCompileLimits, OrderedManyAotCompileRequest, OrderedManyPatternId, OrderedManyRow,
    OutputContract, PreparedAggregateExports, PreparedAggregateStrategy, PreparedBulkStrategy,
    PreparedOrderedNfaV15CompileDisposition, RebarSingleCaptureAotArtifactV1,
    RebarSingleCaptureAotRequestV1, RebarSingleCaptureParticipationAotArtifactV1,
    RebarSingleCaptureParticipationAotErrorV1, SectionKind, SlowAotLimits, SymbolBinding,
    SymbolKind, Target, UniformCaptureAuthenticationError, UniformCaptureCompileDisposition,
    UniformCaptureCompileError, UniformCaptureCompileReceipt, UniformCaptureCompileRequest,
    UniformCapturePreparedSpanFillCompileDisposition, UniformCapturePreparedSpanFillCompileError,
    UniformCapturePreparedSpanFillCompileReceipt, UniformCaptureReducerCompileDisposition,
    UniformCaptureReducerCompileError, UniformCaptureReducerOperation,
    PREPARED_CAPABILITY_ORDERED_NFA_V15,
};
use fre_lower::{LowerError, LowerResource};
use fre_syntax::{parse, CanonicalPattern, CompatibilityProfile, ParseRequest, RustProfile};

pub const MAX_KLV_BYTES: u64 = 64 * 1_048_576;
/// Maximum source rows accepted by the additive independent-native-row bridge.
///
/// This matches the ordinary multi-pattern facade's default construction
/// envelope. It is checked before any row compilation or build-script output.
pub const MAX_NATIVE_ROW_BRIDGE_PATTERNS: usize = 4_096;
/// Maximum combined bytes of distinct relocatable row objects linked into one
/// job-specialized bridge binary.
pub const MAX_NATIVE_ROW_BRIDGE_OBJECT_BYTES: usize = 256 * 1_048_576;
/// Maximum group-zero-inclusive slot count accepted by the strict capture
/// adapter. This keeps its one caller-owned result allocation inside the same
/// deliberately small cardinality envelope as the native-row bridge.
pub const MAX_STRICT_CAPTURE_GROUPS: usize = 4_096;
/// Public Rebar adapter-local lowering work ceiling.
///
/// This is deliberately additive to the general compiler defaults. The public
/// suite contains otherwise ordinary selector graphs just beyond the
/// default construction envelope; raising a limit cannot change the emitted
/// graph for requests already below it.
pub const REBAR_MAX_LOWER_WORK: u64 = 32_000_000;
/// State ceiling for the optional DFA after a default lowering-work decline.
///
/// Zero is intentional: on the recovered public jobs, even constructing the
/// first subset closure can dominate build time before a positive state cap is
/// observed. The complete ordered-NFA program is already the bounded universal
/// incumbent, so the adapter skips this optional optimizer on its retry.
pub const REBAR_RECOVERY_MAX_DFA_STATES: usize = 0;
/// Transition ceiling paired with [`REBAR_RECOVERY_MAX_DFA_STATES`].
pub const REBAR_RECOVERY_MAX_DFA_TRANSITIONS: usize = 0;
/// Work ceiling paired with [`REBAR_RECOVERY_MAX_DFA_STATES`].
pub const REBAR_RECOVERY_MAX_DFA_WORK: u64 = 0;
/// One adapter-local retry ceiling for exact-span participation DFA states.
///
/// The default transaction remains authoritative. A retry is permitted only
/// when native participation construction reports that exact default numeric
/// ceiling. The retry changes only this ceiling and its predetermined
/// construction-work envelope; allocation, object, authentication and every
/// other initial resource failure remain terminal.
pub const REBAR_PARTICIPATION_RETRY_MAX_DFA_STATES: usize = 131_072;
/// Construction-work ceiling paired with
/// [`REBAR_PARTICIPATION_RETRY_MAX_DFA_STATES`].
pub const REBAR_PARTICIPATION_RETRY_MAX_BUILD_WORK: usize = 256 * 1_048_576;
/// Stable, statically visible marker invoked immediately before the exact
/// stock capture fallback on a selector-positive line.
pub const REBAR_SELECTOR_CAPTURE_POSITIVE_FALLBACK_SYMBOL: &str =
    "fre_aot_rebar_runner_stock_capture_positive_fallback_v1";

/// Recovery envelope used only after the public, job-specialized Rebar
/// adapter observes the default lowering-work ceiling. Runtime semantics and
/// all stable compiler defaults remain unchanged.
#[must_use]
pub fn rebar_recovery_compile_limits() -> CompileLimitsV1 {
    let mut limits = CompileLimitsV1::default();
    limits.lower.max_work = REBAR_MAX_LOWER_WORK;
    limits.determinize = DeterminizeLimits {
        max_states: REBAR_RECOVERY_MAX_DFA_STATES,
        max_transitions: REBAR_RECOVERY_MAX_DFA_TRANSITIONS,
        max_work: REBAR_RECOVERY_MAX_DFA_WORK,
    };
    limits
}

/// Slow-AOT envelope paired with [`rebar_recovery_compile_limits`].
///
/// The first/default transaction has already exhausted only the semantic
/// lowering-work budget. The retry retains the ordinary native-data and
/// allocation ceilings but skips a second, optional determinization pass.
#[must_use]
pub fn rebar_recovery_slow_aot_limits() -> SlowAotLimits {
    native_row_bridge_no_optional_dfa_limits()
}

fn native_row_bridge_no_optional_dfa_limits() -> SlowAotLimits {
    SlowAotLimits {
        determinize: DeterminizeLimits {
            max_states: REBAR_RECOVERY_MAX_DFA_STATES,
            max_transitions: REBAR_RECOVERY_MAX_DFA_TRANSITIONS,
            max_work: REBAR_RECOVERY_MAX_DFA_WORK,
        },
        ..SlowAotLimits::default()
    }
}

fn is_lower_work_limit(error: &CompileError) -> bool {
    matches!(
        error,
        CompileError::Lower(LowerError::ResourceLimit {
            resource: LowerResource::Work,
            ..
        })
    )
}

fn is_uniform_lower_work_limit(error: &UniformCaptureCompileError) -> bool {
    matches!(
        error,
        UniformCaptureCompileError::Lower(LowerError::ResourceLimit {
            resource: LowerResource::Work,
            ..
        })
    )
}

fn is_uniform_reducer_lower_work_limit(error: &UniformCaptureReducerCompileError) -> bool {
    matches!(
        error,
        UniformCaptureReducerCompileError::Ordinary(source)
            if is_uniform_lower_work_limit(source)
    ) || matches!(
        error,
        UniformCaptureReducerCompileError::Prepared(
            UniformCapturePreparedSpanFillCompileError::Lower(LowerError::ResourceLimit {
                resource: LowerResource::Work,
                ..
            })
        )
    )
}

fn is_rebar_participation_lower_work_limit(
    error: &RebarSingleCaptureParticipationAotErrorV1,
) -> bool {
    matches!(
        error,
        RebarSingleCaptureParticipationAotErrorV1::Capture(
            CaptureCompileError::Selector(source)
        ) if is_lower_work_limit(source)
    )
}

fn is_rebar_participation_dfa_state_limit(
    error: &RebarSingleCaptureParticipationAotErrorV1,
    attempted_limit: usize,
) -> bool {
    matches!(
        error,
        RebarSingleCaptureParticipationAotErrorV1::Participation(
            NativeParticipationAotErrorV1::Resource {
                resource: NativeParticipationAotResourceV1::DfaStates,
                required,
                limit,
            }
        ) if *limit == attempted_limit && *required == attempted_limit.saturating_add(1)
    )
}

fn rebar_participation_native_retry_limits(
    mut limits: NativeParticipationAotLimitsV1,
) -> NativeParticipationAotLimitsV1 {
    limits.max_dfa_states = REBAR_PARTICIPATION_RETRY_MAX_DFA_STATES;
    limits.max_build_work = REBAR_PARTICIPATION_RETRY_MAX_BUILD_WORK;
    limits
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Model {
    Compile,
    Count,
    SpanSum,
    CountCaptures,
    GrepCount,
    GrepCaptures,
    RegexRedux,
}

impl Model {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "compile" => Err(
                "general AOT object emission is not a search-ready Rebar compile operation"
                    .to_owned(),
            ),
            "count" => Ok(Self::Count),
            "count-spans" => Ok(Self::SpanSum),
            "count-captures" => Ok(Self::CountCaptures),
            "grep" => Ok(Self::GrepCount),
            "grep-captures" => Ok(Self::GrepCaptures),
            "regex-redux" => Ok(Self::RegexRedux),
            other => Err(format!(
                "general AOT Rebar runner does not support model {other:?}"
            )),
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Compile => "compile",
            Self::Count => "count",
            Self::SpanSum => "count-spans",
            Self::CountCaptures => "count-captures",
            Self::GrepCount => "grep",
            Self::GrepCaptures => "grep-captures",
            Self::RegexRedux => "regex-redux",
        }
    }

    pub const fn adapter(self) -> &'static str {
        match self {
            Self::Compile => "general-aot-optimizing-object-linked-count-verify-prepared-v2",
            Self::Count => "general-aot-identity-suffixed-exclusive-count-prepared-v2",
            Self::SpanSum => "general-aot-linked-complete-spans-prepared-v2",
            Self::CountCaptures => "general-aot-uniform-capture-native-row-count-adapter-loop-v1",
            Self::GrepCount => "general-aot-linked-native-grep-count-reducer-prepared-v2",
            Self::GrepCaptures => "general-aot-uniform-capture-native-row-grep-adapter-loop-v1",
            Self::RegexRedux => "general-aot-linked-fixed-regex-redux-span-entries-v1",
        }
    }

    /// Exact linked adapter label after the compiler receipt selects the
    /// prepare ABI. Incumbent objects retain V2 byte-for-byte; a native
    /// Ordered-TNFA aggregate requires the additive V3 capability contract.
    pub const fn adapter_for_required_capabilities(
        self,
        required_capabilities: u64,
    ) -> &'static str {
        if required_capabilities == 0 {
            return self.adapter();
        }
        match self {
            Self::Compile => {
                "general-aot-optimizing-object-linked-count-verify-prepared-v3-required-ordered-nfa-v15"
            }
            Self::Count => {
                "general-aot-identity-suffixed-exclusive-count-prepared-v3-required-ordered-nfa-v15"
            }
            Self::SpanSum => {
                "general-aot-linked-complete-spans-prepared-v3-required-ordered-nfa-v15"
            }
            Self::CountCaptures => "general-aot-uniform-capture-native-row-count-adapter-loop-v1",
            Self::GrepCount => {
                "general-aot-linked-native-grep-count-reducer-prepared-v3-required-ordered-nfa-v15"
            }
            Self::GrepCaptures => "general-aot-uniform-capture-native-row-grep-adapter-loop-v1",
            Self::RegexRedux => "general-aot-linked-fixed-regex-redux-span-entries-v1",
        }
    }

    /// Exact operation declaration supplied to prepared-runtime ABI V2 or V3.
    ///
    /// These wire bits are duplicated here because this module is also built
    /// by the runner build script, which intentionally does not link the
    /// runtime crate. The package test below binds them to the public runtime
    /// constants.
    pub const fn prepare_operation_flags(self) -> u64 {
        match self {
            Self::Compile | Self::Count => 1 << 1,
            Self::SpanSum => 1 << 2,
            Self::GrepCount => 1 << 3,
            Self::CountCaptures | Self::GrepCaptures => 0,
            Self::RegexRedux => 0,
        }
    }

    /// Operation declaration used by a capability-bearing prepared route.
    /// A V15 GrepCount reducer calls the compiler-produced private search and
    /// therefore requests the Count bit that prepares its Ordered-NFA owner.
    /// Capability-free artifacts retain their established operation flags.
    pub const fn prepare_operation_flags_for_required_capabilities(
        self,
        required_capabilities: u64,
    ) -> u64 {
        if required_capabilities == PREPARED_CAPABILITY_ORDERED_NFA_V15
            && matches!(self, Self::GrepCount)
        {
            return 1 << 1;
        }
        self.prepare_operation_flags()
    }

    pub const fn exports(self) -> PreparedAggregateExports {
        match self {
            Self::Compile | Self::Count => PreparedAggregateExports::COUNT,
            Self::SpanSum => PreparedAggregateExports::SPAN_SUM,
            Self::GrepCount => PreparedAggregateExports::GREP_COUNT,
            Self::CountCaptures | Self::GrepCaptures => PreparedAggregateExports::NONE,
            Self::RegexRedux => PreparedAggregateExports::NONE,
        }
    }

    pub const fn output(self) -> OutputContract {
        match self {
            Self::GrepCount => OutputContract::Exists,
            Self::RegexRedux => OutputContract::Span,
            Self::Compile
            | Self::Count
            | Self::SpanSum
            | Self::CountCaptures
            | Self::GrepCaptures => OutputContract::Span,
        }
    }

    #[must_use]
    pub const fn is_capture(self) -> bool {
        matches!(self, Self::CountCaptures | Self::GrepCaptures)
    }
}

/// Whether the selected prepared aggregate is a compiler-generated native
/// reducer for the complete scalar Rebar operation.
///
/// This deliberately excludes every `*WithRuntimeHelper` strategy. Even when
/// the requested Count or `SpanSum` export happens to be native, a mixed
/// aggregate receipt is not a closed proof that the selected operation entry
/// has no semantic-helper path. Consumers authenticate the narrower exact
/// strategies before treating one reducer call as the whole timed operation.
#[must_use]
pub const fn is_native_whole_scalar_reducer(
    model: Model,
    strategy: Option<PreparedAggregateStrategy>,
) -> bool {
    matches!(model, Model::Count | Model::SpanSum)
        && matches!(
            strategy,
            Some(
                PreparedAggregateStrategy::NativeFused
                    | PreparedAggregateStrategy::NativeOrderedNfaFused
            )
        )
}

/// Authenticate that the selected Count or `SpanSum` export is one complete
/// generated text function over the exact linked program.
///
/// The aggregate strategy is only the first gate. This also closes the export
/// set, prepared capability/bulk shape, canonical program/reducer identity,
/// defined-text extent, and every unresolved aggregate relocation. Other
/// unresolved symbols owned by the ordinary search object do not make the
/// selected reducer a helper; only an edge originating inside that reducer is
/// relevant to the operation boundary.
pub fn authenticate_native_whole_scalar_reducer(
    model: Model,
    compiled: &CompiledRegex,
) -> Result<bool, String> {
    let receipt = compiled.receipt();
    let module = compiled.module();
    let strategy = receipt.prepared_aggregate_strategy;
    if !is_native_whole_scalar_reducer(model, strategy) {
        return Ok(false);
    }

    let (reducer_name, reducer_prefix, compatibility_helper) = match model {
        Model::Count => (
            module.prepared_count_symbol(),
            "fre_aot_regex_count_exclusive_v1_",
            "fre_aot_regex_runtime_compiler_private_count_exclusive_v1",
        ),
        Model::SpanSum => (
            module.prepared_span_sum_symbol(),
            "fre_aot_regex_span_sum_exclusive_v1_",
            "fre_aot_regex_runtime_compiler_private_span_sum_exclusive_v1",
        ),
        _ => unreachable!("native whole scalar reducer is restricted to Count and SpanSum"),
    };
    let reducer_name = reducer_name
        .ok_or_else(|| "native scalar strategy has no model-specific reducer symbol".to_owned())?;
    canonical_symbol_identity(reducer_name, reducer_prefix)
        .ok_or_else(|| "native scalar reducer symbol is not canonical".to_owned())?;
    let (program_name, program_len) = module
        .required_runtime_program()
        .ok_or_else(|| "native scalar reducer has no preparation program".to_owned())?;
    canonical_symbol_identity(program_name, "fre_aot_regex_runtime_program_v1_")
        .ok_or_else(|| "native scalar preparation program symbol is not canonical".to_owned())?;

    let ordered_nfa = strategy == Some(PreparedAggregateStrategy::NativeOrderedNfaFused);
    let bulk_shape_is_exact = if ordered_nfa {
        receipt.engine == EngineKind::OrderedNfa
            && module.prepared_bulk_strategy() == Some(PreparedBulkStrategy::NativeOrderedNfaLoop)
            && receipt.required_prepare_capabilities == PREPARED_CAPABILITY_ORDERED_NFA_V15
    } else {
        matches!(
            module.prepared_bulk_strategy(),
            None | Some(
                PreparedBulkStrategy::NativePreparedLoop | PreparedBulkStrategy::NativeFrozenLoop
            )
        ) && receipt.required_prepare_capabilities == 0
    };
    if receipt.mode != CompileMode::Optimizing
        || receipt.output != OutputContract::Span
        || receipt.prepared_aggregate_exports != model.exports()
        || module.prepared_aggregate_exports() != model.exports()
        || module.prepared_aggregate_strategy() != strategy
        || module.required_prepare_capabilities() != receipt.required_prepare_capabilities
        || !bulk_shape_is_exact
        || reducer_name == program_name
        || program_len == 0
        || receipt.program_sha256 == [0; 32]
        || receipt.object_sha256 == [0; 32]
        || receipt.object_bytes != compiled.object().len()
        || compiled.object().is_empty()
    {
        return Err("native scalar reducer failed its receipt and route closure".to_owned());
    }

    let mut reducer_symbols = module
        .symbols()
        .iter()
        .filter(|symbol| symbol.name == reducer_name);
    let reducer = reducer_symbols
        .next()
        .ok_or_else(|| "native scalar reducer is absent from its module".to_owned())?;
    if reducer_symbols.next().is_some()
        || reducer.binding != SymbolBinding::Global
        || reducer.kind != SymbolKind::Function
        || reducer.size == 0
    {
        return Err("native scalar reducer is not one unique defined function".to_owned());
    }
    let section_index = reducer
        .section
        .ok_or_else(|| "native scalar reducer is undefined".to_owned())?;
    let section = module
        .sections()
        .get(section_index)
        .ok_or_else(|| "native scalar reducer section is absent".to_owned())?;
    let reducer_start = usize::try_from(reducer.offset)
        .map_err(|_| "native scalar reducer offset does not fit usize".to_owned())?;
    let reducer_size = usize::try_from(reducer.size)
        .map_err(|_| "native scalar reducer size does not fit usize".to_owned())?;
    let reducer_end = reducer_start
        .checked_add(reducer_size)
        .ok_or_else(|| "native scalar reducer extent overflowed".to_owned())?;
    let reducer_end_u64 = reducer
        .offset
        .checked_add(reducer.size)
        .ok_or_else(|| "native scalar reducer relocation extent overflowed".to_owned())?;
    if section.kind != SectionKind::Text || reducer_end > section.bytes().len() {
        return Err("native scalar reducer is not wholly defined in text".to_owned());
    }

    let external_targets = module
        .relocations()
        .iter()
        .filter(|relocation| {
            relocation.section == section_index
                && relocation.offset >= reducer.offset
                && relocation.offset < reducer_end_u64
        })
        .filter_map(|relocation| {
            module
                .symbols()
                .get(relocation.symbol)
                .filter(|target| target.section.is_none())
                .map(|target| target.name.as_str())
        })
        .collect::<Vec<_>>();
    let expected_external_targets = if ordered_nfa {
        vec![compatibility_helper]
    } else {
        Vec::new()
    };
    if external_targets != expected_external_targets {
        return Err(format!(
            "native scalar reducer has unexpected unresolved call targets: {external_targets:?}"
        ));
    }

    let aggregate_helpers = module
        .required_runtime_symbols()
        .filter(|symbol| {
            matches!(
                *symbol,
                "fre_aot_regex_runtime_compiler_private_count_exclusive_v1"
                    | "fre_aot_regex_runtime_compiler_private_span_sum_exclusive_v1"
                    | "fre_aot_regex_runtime_compiler_private_grep_count_exclusive_v1"
            )
        })
        .collect::<Vec<_>>();
    if aggregate_helpers != expected_external_targets {
        return Err("native scalar reducer has an unexpected aggregate helper surface".to_owned());
    }
    Ok(true)
}

fn canonical_symbol_identity<'a>(symbol: &'a str, prefix: &str) -> Option<&'a str> {
    let suffix = symbol.strip_prefix(prefix)?;
    (suffix.len() == 64
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then_some(suffix)
}

/// Exact fixed regex suite used by Rebar's public `regex-redux` model.
///
/// These declarations are benchmark semantics, not a workload classifier:
/// the model has no external patterns and every conforming invocation runs
/// this complete ordered stage list.
pub const REGEX_REDUX_VARIANTS: [&str; 9] = [
    r"agggtaaa|tttaccct",
    r"[cgt]gggtaaa|tttaccc[acg]",
    r"a[act]ggtaaa|tttacc[agt]t",
    r"ag[act]gtaaa|tttac[agt]ct",
    r"agg[act]taaa|ttta[agt]cct",
    r"aggg[acg]aaa|ttt[cgt]ccct",
    r"agggt[cgt]aa|tt[acg]accct",
    r"agggta[cgt]a|t[acg]taccct",
    r"agggtaa[cgt]|[acg]ttaccct",
];

pub const REGEX_REDUX_FLATTEN_PATTERN: &str = r">[^\n]*\n|\n";

pub const REGEX_REDUX_SUBSTITUTIONS: [(&str, &str); 5] = [
    (r"tHa[Nt]", "<4>"),
    (r"aND|caN|Ha[DS]|WaS", "<3>"),
    (r"a[NSt]|BY", "<2>"),
    (r"<[^>]*>", "|"),
    (r"\|[^|][^|]*\|", "-"),
];

pub const REGEX_REDUX_VARIANT_BASE: usize = 1;
pub const REGEX_REDUX_SUBSTITUTION_BASE: usize =
    REGEX_REDUX_VARIANT_BASE.saturating_add(REGEX_REDUX_VARIANTS.len());
pub const REGEX_REDUX_COMPONENTS: usize =
    REGEX_REDUX_SUBSTITUTION_BASE.saturating_add(REGEX_REDUX_SUBSTITUTIONS.len());

#[must_use]
pub const fn regex_redux_variant_component(variant: usize) -> Option<usize> {
    if variant < REGEX_REDUX_VARIANTS.len() {
        REGEX_REDUX_VARIANT_BASE.checked_add(variant)
    } else {
        None
    }
}

#[must_use]
pub const fn regex_redux_substitution_component(substitution: usize) -> Option<usize> {
    if substitution < REGEX_REDUX_SUBSTITUTIONS.len() {
        REGEX_REDUX_SUBSTITUTION_BASE.checked_add(substitution)
    } else {
        None
    }
}

#[must_use]
pub const fn regex_redux_pattern(component: usize) -> Option<&'static str> {
    if component == 0 {
        return Some(REGEX_REDUX_FLATTEN_PATTERN);
    }
    let Some(variant) = component.checked_sub(REGEX_REDUX_VARIANT_BASE) else {
        return None;
    };
    if variant < REGEX_REDUX_VARIANTS.len() {
        return Some(REGEX_REDUX_VARIANTS[variant]);
    }
    let Some(substitution) = component.checked_sub(REGEX_REDUX_SUBSTITUTION_BASE) else {
        return None;
    };
    if substitution < REGEX_REDUX_SUBSTITUTIONS.len() {
        return Some(REGEX_REDUX_SUBSTITUTIONS[substitution].0);
    }
    None
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Benchmark {
    pub name: String,
    pub model: Model,
    pub patterns: Vec<String>,
    pub case_insensitive: bool,
    pub unicode: bool,
    pub haystack: Vec<u8>,
    pub max_iters: u64,
    pub max_warmup_iters: u64,
    pub max_time: Duration,
    pub max_warmup_time: Duration,
}

impl Benchmark {
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "delimiter positions prove both one-byte slice advances are in bounds"
    )]
    pub fn parse(mut input: &[u8]) -> Result<Self, String> {
        let mut name = None;
        let mut model = None;
        let mut patterns = Vec::new();
        let mut case_insensitive = None;
        let mut unicode = None;
        let mut haystack = None;
        let mut max_iters = None;
        let mut max_warmup_iters = None;
        let mut max_time = None;
        let mut max_warmup_time = None;

        while !input.is_empty() {
            let key_end = input
                .iter()
                .position(|&byte| byte == b':')
                .ok_or_else(|| "KLV field has no key delimiter".to_owned())?;
            let key = std::str::from_utf8(&input[..key_end])
                .map_err(|error| format!("KLV key is not UTF-8: {error}"))?;
            input = &input[key_end + 1..];
            let length_end = input
                .iter()
                .position(|&byte| byte == b':')
                .ok_or_else(|| "KLV field has no length delimiter".to_owned())?;
            let length = text(&input[..length_end], "length")?
                .parse::<usize>()
                .map_err(|error| format!("KLV length is invalid: {error}"))?;
            input = &input[length_end + 1..];
            let value_end = length
                .checked_add(1)
                .ok_or_else(|| "KLV field length overflow".to_owned())?;
            if input.len() < value_end || input[length] != b'\n' {
                return Err("KLV field is truncated or lacks its trailing newline".to_owned());
            }
            let value = &input[..length];
            input = &input[value_end..];

            match key {
                "name" => set_once(&mut name, text(value, key)?.to_owned(), key)?,
                "model" => set_once(&mut model, Model::parse(text(value, key)?)?, key)?,
                "pattern" => patterns.push(text(value, key)?.to_owned()),
                "case-insensitive" => {
                    set_once(&mut case_insensitive, parse_bool(value, key)?, key)?;
                }
                "unicode" => set_once(&mut unicode, parse_bool(value, key)?, key)?,
                "haystack" => set_once(&mut haystack, value.to_vec(), key)?,
                "max-iters" => set_once(&mut max_iters, parse_u64(value, key)?, key)?,
                "max-warmup-iters" => {
                    set_once(&mut max_warmup_iters, parse_u64(value, key)?, key)?;
                }
                "max-time" => set_once(
                    &mut max_time,
                    Duration::from_nanos(parse_u64(value, key)?),
                    key,
                )?,
                "max-warmup-time" => set_once(
                    &mut max_warmup_time,
                    Duration::from_nanos(parse_u64(value, key)?),
                    key,
                )?,
                unknown => return Err(format!("unrecognized KLV key {unknown:?}")),
            }
        }

        let benchmark = Self {
            name: required(name, "name")?,
            model: required(model, "model")?,
            patterns,
            case_insensitive: required(case_insensitive, "case-insensitive")?,
            unicode: required(unicode, "unicode")?,
            haystack: required(haystack, "haystack")?,
            max_iters: required(max_iters, "max-iters")?,
            max_warmup_iters: required(max_warmup_iters, "max-warmup-iters")?,
            max_time: required(max_time, "max-time")?,
            max_warmup_time: required(max_warmup_time, "max-warmup-time")?,
        };
        if benchmark.model == Model::RegexRedux {
            if !benchmark.patterns.is_empty() {
                return Err(format!(
                    "linked general-AOT regex-redux operation requires zero patterns, got {}",
                    benchmark.patterns.len()
                ));
            }
        } else {
            if benchmark.patterns.is_empty() {
                return Err(
                    "current linked general-AOT operation requires at least one pattern".to_owned(),
                );
            }
            if benchmark.patterns.len() > 1
                && !matches!(
                    benchmark.model,
                    Model::Count
                        | Model::SpanSum
                        | Model::CountCaptures
                        | Model::GrepCount
                        | Model::GrepCaptures
                )
            {
                return Err(format!(
                    "current linked general-AOT multi-pattern bridge does not support model {:?} with {} patterns",
                    benchmark.model,
                    benchmark.patterns.len()
                ));
            }
        }
        if benchmark.patterns.len() > MAX_NATIVE_ROW_BRIDGE_PATTERNS {
            return Err(format!(
                "general-AOT native-row bridge pattern count {} exceeds limit {}",
                benchmark.patterns.len(),
                MAX_NATIVE_ROW_BRIDGE_PATTERNS
            ));
        }
        if benchmark.max_iters == 0 {
            return Err("max-iters must be greater than zero".to_owned());
        }
        Ok(benchmark)
    }

    pub fn pattern(&self) -> &str {
        debug_assert_eq!(
            self.patterns.len(),
            1,
            "single-pattern accessor used for a native-row bridge"
        );
        &self.patterns[0]
    }

    #[must_use]
    pub fn uses_native_row_bridge(&self) -> bool {
        self.patterns.len() > 1 && !self.model.is_capture()
    }

    #[must_use]
    pub const fn uses_uniform_capture_bridge(&self) -> bool {
        self.model.is_capture()
    }

    pub fn same_compilation_identity(&self, other: &Self) -> bool {
        self.name == other.name
            && self.model == other.model
            && self.patterns == other.patterns
            && self.case_insensitive == other.case_insensitive
            && self.unicode == other.unicode
    }
}

pub fn target_from_parts(
    architecture: &str,
    operating_system: &str,
    feature_bits: u64,
) -> Result<Target, String> {
    let architecture = match architecture {
        "x86_64" => Architecture::X86_64,
        "aarch64" => Architecture::Aarch64,
        other => return Err(format!("unsupported AOT target architecture {other:?}")),
    };
    let operating_system = match operating_system {
        "linux" => OperatingSystem::Linux,
        "macos" => OperatingSystem::Macos,
        other => return Err(format!("unsupported AOT target operating system {other:?}")),
    };
    let features = FeatureSet::from_bits(feature_bits)
        .ok_or_else(|| format!("unknown AOT feature bits {feature_bits:#018x}"))?;
    Target::new(architecture, operating_system, features)
        .map_err(|error| format!("invalid AOT target: {error}"))
}

pub fn compile_benchmark(benchmark: &Benchmark, target: Target) -> Result<CompiledRegex, String> {
    if benchmark.model.is_capture() {
        return Err(
            "capture models require the paired uniform-capture compiler or strict capture compiler"
                .to_owned(),
        );
    }
    if benchmark.uses_native_row_bridge() {
        return Err(
            "single-artifact compilation cannot compile a multi-pattern native-row bridge"
                .to_owned(),
        );
    }
    if benchmark.model == Model::RegexRedux {
        return Err(
            "regex-redux is a fixed multi-artifact composite; compile its components explicitly"
                .to_owned(),
        );
    }
    let mut profile = RustProfile::rebar_1_12_4();
    profile.options.unicode = benchmark.unicode;
    profile.options.case_insensitive = benchmark.case_insensitive;
    let compile_with_limits = |limits, slow_aot_limits| {
        compile_with_prepared_aggregate_exports_and_slow_aot_limits(
            CompileRequest::new(benchmark.pattern(), target)
                .profile(profile.clone())
                .output(benchmark.model.output())
                .mode(CompileMode::Optimizing)
                .limits(limits),
            benchmark.model.exports(),
            slow_aot_limits,
        )
    };
    let (compiled, selected_limits, recovered_lower_work) =
        match compile_with_limits(CompileLimitsV1::default(), SlowAotLimits::default()) {
            Ok(compiled) => (compiled, CompileLimitsV1::default(), false),
            Err(error) if is_lower_work_limit(&error) => {
                let limits = rebar_recovery_compile_limits();
                let compiled = compile_with_limits(limits, rebar_recovery_slow_aot_limits())
                    .map_err(|error| format!("general AOT recovery compilation failed: {error}"))?;
                (compiled, limits, true)
            }
            Err(error) => return Err(format!("general AOT compilation failed: {error}")),
        };
    if recovered_lower_work
        && recovered_scalar_requires_prepared_ordered_nfa(benchmark.model, &compiled)
    {
        let recovered_stats = compiled
            .program()
            .stats()
            .map_err(|error| format!("general AOT recovery stats failed: {error}"))?;
        let disposition = compile_with_prepared_ordered_nfa_v15_reported(
            CompileRequest::new(benchmark.pattern(), target)
                .profile(profile)
                .output(OutputContract::Span)
                .mode(CompileMode::Optimizing)
                .limits(selected_limits),
            benchmark.model.exports(),
        )
        .map_err(|error| {
            format!(
                "general AOT explicit prepared Ordered-NFA compilation failed for {} states/{} edges: {error}",
                recovered_stats.thompson_states, recovered_stats.thompson_edges,
            )
        })?;
        let selected =
            select_prepared_ordered_nfa_v15_or_recovered(benchmark.model, compiled, disposition)?;
        authenticate_native_whole_scalar_reducer(benchmark.model, &selected)?;
        return Ok(selected);
    }
    if benchmark.model != Model::GrepCount {
        authenticate_native_whole_scalar_reducer(benchmark.model, &compiled)?;
        return Ok(compiled);
    }
    if compiled.module().required_prepare_capabilities() == PREPARED_CAPABILITY_ORDERED_NFA_V15 {
        authenticate_prepared_v15_grep(&compiled)?;
        return Ok(compiled);
    }
    if !ordinary_grep_requires_prepared_v15(&compiled) {
        authenticate_direct_native_grep(&compiled)?;
        return Ok(compiled);
    }
    let disposition = compile_with_prepared_ordered_nfa_v15_reported(
        CompileRequest::new(benchmark.pattern(), target)
            .profile(profile)
            .output(OutputContract::Span)
            .mode(CompileMode::Optimizing)
            .limits(selected_limits),
        PreparedAggregateExports::GREP_COUNT,
    )
    .map_err(|error| format!("general AOT prepared V15 grep compilation failed: {error}"))?;
    select_prepared_v15_grep_or_incumbent(compiled, disposition)
}

fn select_prepared_ordered_nfa_v15_or_recovered(
    model: Model,
    recovered: CompiledRegex,
    disposition: PreparedOrderedNfaV15CompileDisposition,
) -> Result<CompiledRegex, String> {
    match disposition {
        PreparedOrderedNfaV15CompileDisposition::Compiled(selected) => {
            authenticate_prepared_ordered_nfa_scalar(model, &selected)?;
            Ok(selected)
        }
        PreparedOrderedNfaV15CompileDisposition::Declined(_) => Ok(recovered),
    }
}

fn recovered_scalar_requires_prepared_ordered_nfa(model: Model, compiled: &CompiledRegex) -> bool {
    recovered_scalar_route_shape(
        model,
        compiled.receipt().engine,
        compiled.module().prepared_bulk_strategy(),
        compiled.module().prepared_aggregate_strategy(),
        compiled.module().required_prepare_capabilities(),
    )
}

const fn recovered_scalar_route_shape(
    model: Model,
    engine: EngineKind,
    bulk: Option<PreparedBulkStrategy>,
    aggregate: Option<PreparedAggregateStrategy>,
    required_prepare_capabilities: u64,
) -> bool {
    matches!(model, Model::Count | Model::SpanSum)
        && matches!(engine, EngineKind::OrderedNfa)
        && matches!(
            bulk,
            Some(PreparedBulkStrategy::NativeTrustedPreflightRuntimeBulk)
        )
        && matches!(aggregate, Some(PreparedAggregateStrategy::RuntimeHelper))
        && required_prepare_capabilities == 0
}

fn authenticate_prepared_ordered_nfa_scalar(
    model: Model,
    compiled: &CompiledRegex,
) -> Result<(), String> {
    let module = compiled.module();
    let receipt = compiled.receipt();
    let reducer_is_present = match model {
        Model::Count => module.prepared_count_symbol().is_some(),
        Model::SpanSum => module.prepared_span_sum_symbol().is_some(),
        _ => false,
    };
    if receipt.mode != CompileMode::Optimizing
        || receipt.output != OutputContract::Span
        || receipt.engine != EngineKind::OrderedNfa
        || receipt.prepared_aggregate_exports != model.exports()
        || receipt.prepared_aggregate_strategy
            != Some(PreparedAggregateStrategy::NativeOrderedNfaFused)
        || receipt.required_prepare_capabilities != PREPARED_CAPABILITY_ORDERED_NFA_V15
        || module.prepared_aggregate_exports() != model.exports()
        || module.prepared_aggregate_strategy()
            != Some(PreparedAggregateStrategy::NativeOrderedNfaFused)
        || module.prepared_bulk_strategy() != Some(PreparedBulkStrategy::NativeOrderedNfaLoop)
        || module.required_prepare_capabilities() != PREPARED_CAPABILITY_ORDERED_NFA_V15
        || module.prepared_entry_symbol().is_none()
        || module.prepared_span_fill_symbol().is_none()
        || module.required_runtime_program().is_none()
        || !reducer_is_present
        || compiled.object().is_empty()
        || compiled.object().len() > MAX_NATIVE_ROW_BRIDGE_OBJECT_BYTES
    {
        return Err(format!(
            "explicit prepared Ordered-NFA scalar route failed authentication: model={} engine={:?} aggregate={:?} bulk={:?} capabilities={:#x}",
            model.name(),
            receipt.engine,
            module.prepared_aggregate_strategy(),
            module.prepared_bulk_strategy(),
            module.required_prepare_capabilities(),
        ));
    }
    Ok(())
}

fn select_prepared_v15_grep_or_incumbent(
    incumbent: CompiledRegex,
    disposition: PreparedOrderedNfaV15CompileDisposition,
) -> Result<CompiledRegex, String> {
    match disposition {
        PreparedOrderedNfaV15CompileDisposition::Compiled(selected) => {
            authenticate_prepared_v15_grep(&selected)?;
            Ok(selected)
        }
        PreparedOrderedNfaV15CompileDisposition::Declined(_) => Ok(incumbent),
    }
}

const ORDINARY_GREP_RUNTIME_SYMBOLS: [&str; 4] = [
    "fre_aot_regex_runtime_search_v1",
    "fre_aot_regex_runtime_search_exclusive_v1",
    "fre_aot_regex_runtime_is_match_batch_exclusive_v1",
    "fre_aot_regex_runtime_compiler_private_grep_count_exclusive_v1",
];
const PREPARED_V15_GREP_RUNTIME_SYMBOLS: [&str; 3] = [
    "fre_aot_regex_runtime_search_v1",
    "fre_aot_regex_runtime_search_exclusive_v1",
    "fre_aot_regex_runtime_fill_spans_exclusive_v1",
];
const PREPARED_V15_ROW_RUNTIME_SYMBOLS: [&str; 3] = [
    "fre_aot_regex_runtime_search_v1",
    "fre_aot_regex_runtime_search_exclusive_v1",
    "fre_aot_regex_runtime_fill_spans_exclusive_v1",
];
const PREPARED_V15_SHARED_COUNT_RUNTIME_SYMBOLS: [&str; 4] = [
    "fre_aot_regex_runtime_search_v1",
    "fre_aot_regex_runtime_search_exclusive_v1",
    "fre_aot_regex_runtime_fill_spans_exclusive_v1",
    "fre_aot_regex_runtime_compiler_private_count_exclusive_v1",
];
const PREPARED_V15_SHARED_SPAN_SUM_RUNTIME_SYMBOLS: [&str; 4] = [
    "fre_aot_regex_runtime_search_v1",
    "fre_aot_regex_runtime_search_exclusive_v1",
    "fre_aot_regex_runtime_fill_spans_exclusive_v1",
    "fre_aot_regex_runtime_compiler_private_span_sum_exclusive_v1",
];
const FROZEN_LOOP_RUNTIME_SYMBOL: &str = "fre_aot_regex_runtime_scan_frozen_loop_v2";

fn unresolved_runtime_function_names(compiled: &CompiledRegex) -> Option<Vec<&str>> {
    let module = compiled.module();
    let mut names = Vec::new();
    for (index, symbol) in module.symbols().iter().enumerate() {
        let referenced = module
            .relocations()
            .iter()
            .any(|relocation| relocation.symbol == index);
        if symbol.section.is_some() || !referenced {
            continue;
        }
        if symbol.binding != SymbolBinding::Global || symbol.kind != SymbolKind::Function {
            return None;
        }
        names.push(symbol.name.as_str());
    }
    Some(names)
}

fn has_exact_runtime_symbol_closure(compiled: &CompiledRegex, expected: &[&str]) -> bool {
    unresolved_runtime_function_names(compiled)
        .is_some_and(|actual| has_exact_symbol_name_closure(&actual, expected))
}

fn has_exact_symbol_name_closure(actual: &[&str], expected: &[&str]) -> bool {
    if actual.len() != expected.len() {
        return false;
    }
    let expected_len = expected.len();
    let actual = actual
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    let expected = expected
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    actual.len() == expected_len && expected.len() == expected_len && actual == expected
}

fn has_exact_optional_symbol_name_closure(
    actual: &[&str],
    expected: &[Option<&str>],
) -> bool {
    let expected = expected.iter().flatten().copied().collect::<Vec<_>>();
    has_exact_symbol_name_closure(actual, &expected)
}

/// Authenticate the complete helper surface published by the current module
/// itself for a caps-zero native dynamic loop. This artifact is never linked
/// by the row bridge: the closed surface is only a typed witness permitting a
/// fresh, independently authenticated V15 compilation of the same program.
fn native_dynamic_loop_runtime_symbols_are_closed(compiled: &CompiledRegex) -> bool {
    let module = compiled.module();
    let Some(actual) = unresolved_runtime_function_names(compiled) else {
        return false;
    };
    let runtime = module.runtime_symbol();
    if !matches!(
        runtime,
        "fre_aot_regex_runtime_search_v1"
            | "fre_aot_regex_runtime_search_without_endpoint_oracle_v1"
    ) {
        return false;
    }
    let prepared_runtime = module.required_prepared_runtime_symbol();
    if prepared_runtime.is_some_and(|symbol| {
        !matches!(
            symbol,
            "fre_aot_regex_runtime_search_exclusive_from_partial_preflight_compact_v2"
                | "fre_aot_regex_runtime_search_exclusive_from_partial_preflight_compact_v3"
                | "fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_continue_v3"
                | "fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_continue_v4"
        )
    }) {
        return false;
    }
    let expected = [
        Some(runtime),
        prepared_runtime,
        module.required_prepared_fallback_runtime_symbol(),
        module.required_prepared_static_prefix_retire_runtime_symbol(),
        module.required_prepared_admission_runtime_symbol(),
        module.required_prepared_preflight_runtime_symbol(),
        module.required_prepared_dynamic_rows_deopt_runtime_symbol(),
        module.required_prepared_dynamic_rows_continue_runtime_symbol(),
        module.required_prepared_dynamic_rows_span_recovery_runtime_symbol(),
        module.required_prepared_dynamic_rows_loop_scan_runtime_symbol(),
        module.required_prepared_span_recovery_runtime_symbol(),
        module.required_prepared_lazy_static_prefix_span_recovery_runtime_symbol(),
    ];
    has_exact_optional_symbol_name_closure(&actual, &expected)
}

fn native_prepared_loop_runtime_symbols_are_closed(compiled: &CompiledRegex) -> bool {
    compiled
        .module()
        .prepared_bulk_strategy()
        == Some(PreparedBulkStrategy::NativePreparedLoop)
        && native_dynamic_loop_runtime_symbols_are_closed(compiled)
}

fn native_frozen_loop_runtime_symbols_are_closed(compiled: &CompiledRegex) -> bool {
    let module = compiled.module();
    module.prepared_bulk_strategy() == Some(PreparedBulkStrategy::NativeFrozenLoop)
        && module.required_prepared_dynamic_rows_loop_scan_runtime_symbol()
        == Some(FROZEN_LOOP_RUNTIME_SYMBOL)
        && native_dynamic_loop_runtime_symbols_are_closed(compiled)
}

fn has_defined_symbol(
    compiled: &CompiledRegex,
    name: &str,
    kind: SymbolKind,
    exact_size: Option<usize>,
) -> bool {
    compiled.module().symbols().iter().any(|symbol| {
        symbol.name == name
            && symbol.binding == SymbolBinding::Global
            && symbol.kind == kind
            && symbol.section.is_some()
            && symbol.size != 0
            && exact_size.is_none_or(|size| usize::try_from(symbol.size).ok() == Some(size))
    })
}

fn native_symbol_identity<'a>(symbol: &'a str, prefix: &str) -> Option<&'a str> {
    let suffix = symbol.strip_prefix(prefix)?;
    (suffix.len() == 64
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then_some(suffix)
}

fn prepared_row_symbol_identities_are_closed(
    ordinary_entry: &str,
    prepared_entry: &str,
    span_fill: &str,
    program: &str,
) -> bool {
    let Some(ordinary_identity) =
        native_symbol_identity(ordinary_entry, "fre_aot_regex_search_v1_")
    else {
        return false;
    };
    let Some(prepared_identity) =
        native_symbol_identity(prepared_entry, "fre_aot_regex_search_exclusive_v1_")
    else {
        return false;
    };
    let Some(span_fill_identity) =
        native_symbol_identity(span_fill, "fre_aot_regex_fill_spans_exclusive_v1_")
    else {
        return false;
    };
    let Some(program_identity) =
        native_symbol_identity(program, "fre_aot_regex_runtime_program_v1_")
    else {
        return false;
    };
    ordinary_identity == prepared_identity
        && ordinary_identity == span_fill_identity
        && ordinary_identity == program_identity
}

fn prepared_v15_grep_symbol_identities_are_closed(
    ordinary_entry: &str,
    prepared_entry: &str,
    span_fill: &str,
    reducer: &str,
    program: &str,
) -> bool {
    let Some(ordinary_identity) =
        native_symbol_identity(ordinary_entry, "fre_aot_regex_search_v1_")
    else {
        return false;
    };
    let Some(prepared_identity) =
        native_symbol_identity(prepared_entry, "fre_aot_regex_search_exclusive_v1_")
    else {
        return false;
    };
    let Some(span_fill_identity) =
        native_symbol_identity(span_fill, "fre_aot_regex_fill_spans_exclusive_v1_")
    else {
        return false;
    };
    let Some(reducer_identity) =
        native_symbol_identity(reducer, "fre_aot_regex_grep_count_exclusive_v1_")
    else {
        return false;
    };
    let Some(program_identity) =
        native_symbol_identity(program, "fre_aot_regex_runtime_program_v1_")
    else {
        return false;
    };
    ordinary_identity == prepared_identity
        && ordinary_identity == span_fill_identity
        && ordinary_identity == program_identity
        && reducer_identity != ordinary_identity
}

fn direct_native_grep_symbol_identities_are_closed(
    ordinary_entry: &str,
    reducer: &str,
    program: &str,
) -> bool {
    let Some(ordinary_identity) =
        native_symbol_identity(ordinary_entry, "fre_aot_regex_search_v1_")
    else {
        return false;
    };
    let Some(reducer_identity) =
        native_symbol_identity(reducer, "fre_aot_regex_grep_count_exclusive_v1_")
    else {
        return false;
    };
    let Some(program_identity) =
        native_symbol_identity(program, "fre_aot_regex_runtime_program_v1_")
    else {
        return false;
    };
    reducer_identity == program_identity && reducer_identity != ordinary_identity
}

fn shared_ordered_many_v15_symbol_identities_are_closed(
    model: Model,
    ordinary_entry: &str,
    prepared_entry: &str,
    span_fill: &str,
    reducer: &str,
    program: &str,
) -> bool {
    let Some(ordinary_identity) =
        native_symbol_identity(ordinary_entry, "fre_aot_regex_search_v1_")
    else {
        return false;
    };
    let Some(prepared_identity) =
        native_symbol_identity(prepared_entry, "fre_aot_regex_search_exclusive_v1_")
    else {
        return false;
    };
    let Some(span_fill_identity) =
        native_symbol_identity(span_fill, "fre_aot_regex_fill_spans_exclusive_v1_")
    else {
        return false;
    };
    let reducer_prefix = match model {
        Model::Count => "fre_aot_regex_count_exclusive_v1_",
        Model::SpanSum => "fre_aot_regex_span_sum_exclusive_v1_",
        _ => return false,
    };
    let Some(reducer_identity) = native_symbol_identity(reducer, reducer_prefix) else {
        return false;
    };
    let Some(program_identity) =
        native_symbol_identity(program, "fre_aot_regex_runtime_program_v1_")
    else {
        return false;
    };
    ordinary_identity == prepared_identity
        && ordinary_identity == span_fill_identity
        && ordinary_identity == program_identity
        && reducer_identity != ordinary_identity
}

fn shared_ordered_many_native_fused_symbol_identities_are_closed(
    model: Model,
    ordinary_entry: &str,
    reducer: &str,
    program: &str,
) -> bool {
    let reducer_prefix = match model {
        Model::Count => "fre_aot_regex_count_exclusive_v1_",
        Model::SpanSum => "fre_aot_regex_span_sum_exclusive_v1_",
        _ => return false,
    };
    native_symbol_identity(ordinary_entry, "fre_aot_regex_search_v1_").is_some()
        && native_symbol_identity(reducer, reducer_prefix).is_some()
        && native_symbol_identity(program, "fre_aot_regex_runtime_program_v1_").is_some()
        && [ordinary_entry, reducer, program]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == 3
}

fn defined_function_has_no_unresolved_relocations(compiled: &CompiledRegex, name: &str) -> bool {
    let module = compiled.module();
    let mut matches = module.symbols().iter().filter(|symbol| symbol.name == name);
    let Some(symbol) = matches.next() else {
        return false;
    };
    if matches.next().is_some()
        || symbol.binding != SymbolBinding::Global
        || symbol.kind != SymbolKind::Function
        || symbol.size == 0
    {
        return false;
    }
    let Some(section_index) = symbol.section else {
        return false;
    };
    let Some(section) = module.sections().get(section_index) else {
        return false;
    };
    let Ok(start) = usize::try_from(symbol.offset) else {
        return false;
    };
    let Ok(size) = usize::try_from(symbol.size) else {
        return false;
    };
    let Some(end) = start.checked_add(size) else {
        return false;
    };
    let Some(end_u64) = symbol.offset.checked_add(symbol.size) else {
        return false;
    };
    section.kind == SectionKind::Text
        && end <= section.bytes().len()
        && module
            .relocations()
            .iter()
            .filter(|relocation| {
                relocation.section == section_index
                    && relocation.offset >= symbol.offset
                    && relocation.offset < end_u64
            })
            .all(|relocation| {
                module
                    .symbols()
                    .get(relocation.symbol)
                    .is_some_and(|target| target.section.is_some())
            })
}

fn ordinary_grep_symbol_identities_are_closed(
    ordinary_entry: &str,
    prepared_entry: &str,
    exists_batch: &str,
    reducer: &str,
    program: &str,
) -> bool {
    let Some(ordinary_identity) =
        native_symbol_identity(ordinary_entry, "fre_aot_regex_search_v1_")
    else {
        return false;
    };
    let Some(prepared_identity) =
        native_symbol_identity(prepared_entry, "fre_aot_regex_search_exclusive_v1_")
    else {
        return false;
    };
    let Some(exists_batch_identity) =
        native_symbol_identity(exists_batch, "fre_aot_regex_is_match_batch_exclusive_v1_")
    else {
        return false;
    };
    let Some(reducer_identity) =
        native_symbol_identity(reducer, "fre_aot_regex_grep_count_exclusive_v1_")
    else {
        return false;
    };
    let Some(program_identity) =
        native_symbol_identity(program, "fre_aot_regex_runtime_program_v1_")
    else {
        return false;
    };
    ordinary_identity == prepared_identity
        && ordinary_identity == exists_batch_identity
        && ordinary_identity == program_identity
        && reducer_identity != ordinary_identity
}

fn ordinary_grep_runtime_bulk_is_authenticated(
    bulk: Option<PreparedBulkStrategy>,
    exists_batch: Option<&str>,
    exists_batch_is_defined: bool,
) -> bool {
    matches!(bulk, Some(PreparedBulkStrategy::RuntimeHelper))
        && exists_batch.is_some_and(|symbol| !symbol.is_empty())
        && exists_batch_is_defined
}

fn ordinary_grep_requires_prepared_v15(compiled: &CompiledRegex) -> bool {
    let module = compiled.module();
    let receipt = compiled.receipt();
    let Some(prepared_entry) = module.prepared_entry_symbol() else {
        return false;
    };
    let Some(reducer) = module.prepared_grep_count_symbol() else {
        return false;
    };
    let exists_batch = module.prepared_exists_batch_symbol();
    let exists_batch_is_defined = exists_batch
        .is_some_and(|symbol| has_defined_symbol(compiled, symbol, SymbolKind::Function, None));
    let Some(exists_batch) = exists_batch else {
        return false;
    };
    let Some((program, program_len)) = module.required_runtime_program() else {
        return false;
    };
    receipt.mode == CompileMode::Optimizing
        && receipt.output == OutputContract::Exists
        && receipt.engine == EngineKind::OrderedNfa
        && receipt.runtime_helper_required
        && receipt.prepared_aggregate_exports == PreparedAggregateExports::GREP_COUNT
        && receipt.prepared_aggregate_strategy == Some(PreparedAggregateStrategy::RuntimeHelper)
        && receipt.required_prepare_capabilities == 0
        && module.prepared_aggregate_exports() == PreparedAggregateExports::GREP_COUNT
        && module.prepared_aggregate_strategy() == Some(PreparedAggregateStrategy::RuntimeHelper)
        && ordinary_grep_runtime_bulk_is_authenticated(
            module.prepared_bulk_strategy(),
            Some(exists_batch),
            exists_batch_is_defined,
        )
        && module.required_prepare_capabilities() == 0
        && module.prepared_span_fill_symbol().is_none()
        && module.prepared_count_symbol().is_none()
        && module.prepared_span_sum_symbol().is_none()
        && program_len != 0
        && has_exact_runtime_symbol_closure(compiled, &ORDINARY_GREP_RUNTIME_SYMBOLS)
        && has_defined_symbol(compiled, module.entry_symbol(), SymbolKind::Function, None)
        && has_defined_symbol(compiled, prepared_entry, SymbolKind::Function, None)
        && has_defined_symbol(compiled, reducer, SymbolKind::Function, None)
        && has_defined_symbol(compiled, program, SymbolKind::Object, Some(program_len))
        && ordinary_grep_symbol_identities_are_closed(
            module.entry_symbol(),
            prepared_entry,
            exists_batch,
            reducer,
            program,
        )
        && [
            module.entry_symbol(),
            prepared_entry,
            exists_batch,
            reducer,
            program,
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
            == 5
}

fn authenticate_direct_native_grep(compiled: &CompiledRegex) -> Result<(), String> {
    let module = compiled.module();
    let receipt = compiled.receipt();
    let reducer = module
        .prepared_grep_count_symbol()
        .ok_or_else(|| "direct native grep has no reducer".to_owned())?;
    let (program, program_len) = module
        .required_runtime_program()
        .ok_or_else(|| "direct native grep has no serialized program".to_owned())?;
    if receipt.mode != CompileMode::Optimizing
        || receipt.output != OutputContract::Exists
        || receipt.runtime_helper_required
        || receipt.prepared_aggregate_exports != PreparedAggregateExports::GREP_COUNT
        || receipt.prepared_aggregate_strategy != Some(PreparedAggregateStrategy::NativeFused)
        || receipt.required_prepare_capabilities != 0
        || module.prepared_aggregate_exports() != PreparedAggregateExports::GREP_COUNT
        || module.prepared_aggregate_strategy() != Some(PreparedAggregateStrategy::NativeFused)
        || module.required_prepare_capabilities() != 0
        || module.prepared_bulk_strategy().is_some()
        || module.prepared_entry_symbol().is_some()
        || module.prepared_span_fill_symbol().is_some()
        || module.prepared_exists_batch_symbol().is_some()
        || module.prepared_count_symbol().is_some()
        || module.prepared_span_sum_symbol().is_some()
        || program_len == 0
        || !has_exact_runtime_symbol_closure(compiled, &[])
        || !has_defined_symbol(compiled, module.entry_symbol(), SymbolKind::Function, None)
        || !has_defined_symbol(compiled, reducer, SymbolKind::Function, None)
        || !has_defined_symbol(compiled, program, SymbolKind::Object, Some(program_len))
        || !direct_native_grep_symbol_identities_are_closed(
            module.entry_symbol(),
            reducer,
            program,
        )
        || [module.entry_symbol(), reducer, program]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != 3
        || compiled.object().is_empty()
    {
        return Err(format!(
            "direct native grep failed exact reducer authentication: mode={:?} output={:?} engine={:?} runtime_helper={} receipt_exports={:?} module_exports={:?} aggregate={:?} bulk={:?} capabilities={:#x} prepared_entry={} span_fill={} exists_batch={} count={} span_sum={} program_len={} entry={:?} reducer={reducer:?} program={program:?} identities_closed={} runtime_symbols={:?}",
            receipt.mode,
            receipt.output,
            receipt.engine,
            receipt.runtime_helper_required,
            receipt.prepared_aggregate_exports,
            module.prepared_aggregate_exports(),
            module.prepared_aggregate_strategy(),
            module.prepared_bulk_strategy(),
            module.required_prepare_capabilities(),
            module.prepared_entry_symbol().is_some(),
            module.prepared_span_fill_symbol().is_some(),
            module.prepared_exists_batch_symbol().is_some(),
            module.prepared_count_symbol().is_some(),
            module.prepared_span_sum_symbol().is_some(),
            program_len,
            module.entry_symbol(),
            direct_native_grep_symbol_identities_are_closed(module.entry_symbol(), reducer, program),
            unresolved_runtime_function_names(compiled),
        ));
    }
    Ok(())
}

fn authenticate_prepared_v15_grep(compiled: &CompiledRegex) -> Result<(), String> {
    let module = compiled.module();
    let receipt = compiled.receipt();
    let reducer = module
        .prepared_grep_count_symbol()
        .ok_or_else(|| "prepared V15 grep has no reducer".to_owned())?;
    let prepared_entry = module
        .prepared_entry_symbol()
        .ok_or_else(|| "prepared V15 grep has no prepared entry".to_owned())?;
    let span_fill = module
        .prepared_span_fill_symbol()
        .ok_or_else(|| "prepared V15 grep has no SpanFill entry".to_owned())?;
    let (program, program_len) = module
        .required_runtime_program()
        .ok_or_else(|| "prepared V15 grep has no serialized program".to_owned())?;
    if receipt.mode != CompileMode::Optimizing
        || receipt.output != OutputContract::Span
        || receipt.engine != EngineKind::OrderedNfa
        || !receipt.runtime_helper_required
        || receipt.prepared_aggregate_exports != PreparedAggregateExports::GREP_COUNT
        || receipt.prepared_aggregate_strategy
            != Some(PreparedAggregateStrategy::NativeOrderedNfaFused)
        || receipt.required_prepare_capabilities != PREPARED_CAPABILITY_ORDERED_NFA_V15
        || module.prepared_aggregate_exports() != PreparedAggregateExports::GREP_COUNT
        || module.prepared_aggregate_strategy()
            != Some(PreparedAggregateStrategy::NativeOrderedNfaFused)
        || module.required_prepare_capabilities() != PREPARED_CAPABILITY_ORDERED_NFA_V15
        || module.prepared_bulk_strategy() != Some(PreparedBulkStrategy::NativeOrderedNfaLoop)
        || module.prepared_count_symbol().is_some()
        || module.prepared_span_sum_symbol().is_some()
        || program_len == 0
        || !has_exact_runtime_symbol_closure(compiled, &PREPARED_V15_GREP_RUNTIME_SYMBOLS)
        || !has_defined_symbol(compiled, module.entry_symbol(), SymbolKind::Function, None)
        || !has_defined_symbol(compiled, prepared_entry, SymbolKind::Function, None)
        || !has_defined_symbol(compiled, span_fill, SymbolKind::Function, None)
        || !has_defined_symbol(compiled, reducer, SymbolKind::Function, None)
        || !has_defined_symbol(compiled, program, SymbolKind::Object, Some(program_len))
        || !prepared_v15_grep_symbol_identities_are_closed(
            module.entry_symbol(),
            prepared_entry,
            span_fill,
            reducer,
            program,
        )
        || [
            module.entry_symbol(),
            prepared_entry,
            span_fill,
            reducer,
            program,
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
            != 5
        || compiled.object().is_empty()
    {
        return Err(
            "prepared V15 grep failed exact capability and reducer authentication".to_owned(),
        );
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeRowRoute {
    /// The ordinary optimizer selected a helper-free public Span entry.
    Ordinary,
    /// The ordinary artifact was well-formed but runtime-dependent, so this
    /// row uses the explicit capability-authenticated prepared V15 entry.
    PreparedOrderedNfaV15,
}

impl NativeRowRoute {
    #[must_use]
    pub const fn is_prepared(self) -> bool {
        matches!(self, Self::PreparedOrderedNfaV15)
    }
}

/// One distinct authenticated native `Span` object in source-priority order.
#[derive(Clone, Debug)]
pub struct NativeRowArtifact {
    pub compiled: CompiledRegex,
    pub first_source_ordinal: usize,
    pub route: NativeRowRoute,
}

impl NativeRowArtifact {
    #[must_use]
    pub fn entry_symbol(&self) -> &str {
        match self.route {
            NativeRowRoute::Ordinary => self.compiled.module().entry_symbol(),
            NativeRowRoute::PreparedOrderedNfaV15 => self
                .compiled
                .module()
                .prepared_entry_symbol()
                .expect("authenticated prepared V15 row lost its entry"),
        }
    }
}

/// Build-time result for the independent native-row bridge.
#[derive(Clone, Debug)]
pub struct NativeRowBridge {
    pub artifacts: Vec<NativeRowArtifact>,
    pub source_to_artifact: Vec<usize>,
    pub total_object_bytes: usize,
}

/// Compile one genuine shared-scan ordered multi-pattern reducer.
///
/// This route joins independently parsed canonical HIRs into one ordered
/// automaton and emits one native Count or SpanSum entry. The combined program
/// compares the full ordinary optimizing portfolio first, so an exact
/// helper-free `NativeFused` reducer remains incumbent ahead of explicit V15.
/// It never invokes or retains the independent native-row bridge. The caller
/// may fall back only after classifying the returned typed error outside this
/// function.
pub fn compile_shared_ordered_many_aggregate(
    benchmark: &Benchmark,
    target: Target,
) -> Result<OrderedManyAotArtifact, String> {
    match try_compile_shared_ordered_many_aggregate(benchmark, target)? {
        SharedOrderedManyAggregateDisposition::Compiled(artifact) => Ok(artifact),
        SharedOrderedManyAggregateDisposition::Declined(decline) => Err(format!(
            "shared ordered-many AOT compilation declined: {decline:?}"
        )),
    }
}

/// The only result that authorizes the build adapter to retain its complete
/// independent-row incumbent.
#[derive(Clone, Debug)]
pub enum SharedOrderedManyAggregateDisposition {
    Compiled(OrderedManyAotArtifact),
    Declined(OrderedManyAotCompileDecline),
}

/// Attempt the shared route without swallowing allocator, invariant, object or
/// authentication failures.
pub fn try_compile_shared_ordered_many_aggregate(
    benchmark: &Benchmark,
    target: Target,
) -> Result<SharedOrderedManyAggregateDisposition, String> {
    if benchmark.patterns.len() <= 1
        || benchmark.patterns.len() > fre_aot_regex::ORDERED_MANY_AOT_MAX_ROWS
        || !matches!(benchmark.model, Model::Count | Model::SpanSum)
    {
        return Err(format!(
            "shared ordered-many AOT requires a 2..={} row Count/SpanSum job, got model={} rows={}",
            fre_aot_regex::ORDERED_MANY_AOT_MAX_ROWS,
            benchmark.model.name(),
            benchmark.patterns.len(),
        ));
    }
    let mut profile = RustProfile::rebar_1_12_4();
    profile.options.unicode = benchmark.unicode;
    profile.options.case_insensitive = benchmark.case_insensitive;
    let mut rows = Vec::new();
    rows.try_reserve_exact(benchmark.patterns.len())
        .map_err(|_| "shared ordered-many row allocation failed".to_owned())?;
    for (ordinal, pattern) in benchmark.patterns.iter().enumerate() {
        let id = u32::try_from(ordinal)
            .map_err(|_| format!("shared ordered-many source ordinal {ordinal} overflowed"))?;
        rows.push(OrderedManyRow::new(
            OrderedManyPatternId::new(id),
            pattern.clone(),
        ));
    }
    let mut limits = OrderedManyAotCompileLimits::default();
    limits.max_rows = fre_aot_regex::ORDERED_MANY_AOT_MAX_ROWS;
    limits.max_pattern_bytes = benchmark
        .patterns
        .iter()
        .try_fold(0_usize, |total, pattern| total.checked_add(pattern.len()))
        .ok_or_else(|| "shared ordered-many source byte sum overflowed".to_owned())?;
    limits.compile = rebar_recovery_compile_limits();
    limits.compile.max_object_bytes = MAX_NATIVE_ROW_BRIDGE_OBJECT_BYTES;
    let disposition = compile_ordered_many_aot_reported(
        OrderedManyAotCompileRequest::new(rows, target)
            .profile(profile.clone())
            .mode(CompileMode::Optimizing)
            .limits(limits),
        benchmark.model.exports(),
        SlowAotLimits::default(),
    )
    .map_err(|error| format!("shared ordered-many AOT compilation failed: {error}"))?;
    let artifact = match disposition {
        OrderedManyAotCompileDisposition::Compiled(artifact) => artifact,
        OrderedManyAotCompileDisposition::Declined(decline) => {
            return Ok(SharedOrderedManyAggregateDisposition::Declined(decline));
        }
    };
    authenticate_shared_ordered_many_aggregate(benchmark, target, &profile, &artifact)?;
    Ok(SharedOrderedManyAggregateDisposition::Compiled(artifact))
}

fn authenticate_shared_ordered_many_aggregate(
    benchmark: &Benchmark,
    target: Target,
    profile: &RustProfile,
    artifact: &OrderedManyAotArtifact,
) -> Result<(), String> {
    let compiled = artifact.compiled();
    let module = compiled.module();
    let receipt = compiled.receipt();
    let shared_receipt = artifact.receipt();
    let strategy = module.prepared_aggregate_strategy();
    let reducer = match benchmark.model {
        Model::Count => module.prepared_count_symbol(),
        Model::SpanSum => module.prepared_span_sum_symbol(),
        _ => None,
    };
    let prepared_entry = module.prepared_entry_symbol();
    let span_fill = module.prepared_span_fill_symbol();
    let program = module.required_runtime_program();
    let symbol_surface_closed = match strategy {
        Some(PreparedAggregateStrategy::NativeFused) => {
            let bulk_shape_is_exact = match module.prepared_bulk_strategy() {
                None => prepared_entry.is_none() && span_fill.is_none(),
                Some(
                    PreparedBulkStrategy::NativePreparedLoop
                    | PreparedBulkStrategy::NativeFrozenLoop,
                ) => prepared_entry
                    .zip(span_fill)
                    .zip(program)
                    .is_some_and(|((prepared_entry, span_fill), (program, _))| {
                        prepared_row_symbol_identities_are_closed(
                            module.entry_symbol(),
                            prepared_entry,
                            span_fill,
                            program,
                        )
                    }),
                Some(_) => false,
            };
            receipt.required_prepare_capabilities == 0
                && module.required_prepare_capabilities() == 0
                && has_exact_runtime_symbol_closure(compiled, &[])
                && bulk_shape_is_exact
                && reducer.is_some_and(|symbol| {
                    has_defined_symbol(compiled, symbol, SymbolKind::Function, None)
                        && defined_function_has_no_unresolved_relocations(compiled, symbol)
                })
                && program.is_some_and(|(symbol, len)| {
                    len != 0
                        && has_defined_symbol(
                            compiled,
                            symbol,
                            SymbolKind::Object,
                            Some(len),
                        )
                })
                && reducer.zip(program).is_some_and(|(reducer, (program, _))| {
                    shared_ordered_many_native_fused_symbol_identities_are_closed(
                        benchmark.model,
                        module.entry_symbol(),
                        reducer,
                        program,
                    )
                })
                && has_defined_symbol(
                    compiled,
                    module.entry_symbol(),
                    SymbolKind::Function,
                    None,
                )
        }
        Some(PreparedAggregateStrategy::NativeOrderedNfaFused) => {
            let expected = match benchmark.model {
                Model::Count => &PREPARED_V15_SHARED_COUNT_RUNTIME_SYMBOLS[..],
                Model::SpanSum => &PREPARED_V15_SHARED_SPAN_SUM_RUNTIME_SYMBOLS[..],
                _ => &[][..],
            };
            receipt.engine == EngineKind::OrderedNfa
                && module.prepared_bulk_strategy()
                    == Some(PreparedBulkStrategy::NativeOrderedNfaLoop)
                && module.required_prepare_capabilities()
                    == PREPARED_CAPABILITY_ORDERED_NFA_V15
                && receipt.runtime_helper_required
                && has_exact_runtime_symbol_closure(compiled, expected)
                && prepared_entry.is_some_and(|symbol| {
                    has_defined_symbol(compiled, symbol, SymbolKind::Function, None)
                })
                && span_fill.is_some_and(|symbol| {
                    has_defined_symbol(compiled, symbol, SymbolKind::Function, None)
                })
                && reducer.is_some_and(|symbol| {
                    has_defined_symbol(compiled, symbol, SymbolKind::Function, None)
                })
                && program.is_some_and(|(symbol, len)| {
                    len != 0
                        && has_defined_symbol(
                            compiled,
                            symbol,
                            SymbolKind::Object,
                            Some(len),
                        )
                })
                && prepared_entry
                    .zip(span_fill)
                    .zip(reducer)
                    .zip(program)
                    .is_some_and(
                        |(((prepared_entry, span_fill), reducer), (program, _))| {
                            shared_ordered_many_v15_symbol_identities_are_closed(
                                benchmark.model,
                                module.entry_symbol(),
                                prepared_entry,
                                span_fill,
                                reducer,
                                program,
                            )
                        },
                    )
                && has_defined_symbol(
                    compiled,
                    module.entry_symbol(),
                    SymbolKind::Function,
                    None,
                )
        }
        _ => false,
    };
    if artifact.profile() != profile
        || receipt.target != target
        || receipt.mode != CompileMode::Optimizing
        || receipt.output != OutputContract::Span
        || receipt.prepared_aggregate_exports != benchmark.model.exports()
        || receipt.prepared_aggregate_strategy != strategy
        || module.prepared_aggregate_exports() != benchmark.model.exports()
        || program.is_none()
        || reducer.is_none()
        || !symbol_surface_closed
        || shared_receipt.rows != benchmark.patterns.len()
        || shared_receipt.pattern_bytes
            != benchmark.patterns.iter().map(String::len).sum::<usize>()
        || shared_receipt.program_sha256 != receipt.program_sha256
        || shared_receipt.object_sha256 != receipt.object_sha256
        || shared_receipt.exports != benchmark.model.exports()
        || Some(shared_receipt.aggregate_strategy) != strategy
        || compiled.object().is_empty()
        || compiled.object().len() > MAX_NATIVE_ROW_BRIDGE_OBJECT_BYTES
    {
        return Err(format!(
            "shared ordered-many AOT authentication failed: model={} rows={} strategy={strategy:?} bulk={:?} capabilities={:#x} unresolved={:?}",
            benchmark.model.name(),
            benchmark.patterns.len(),
            module.prepared_bulk_strategy(),
            module.required_prepare_capabilities(),
            unresolved_runtime_function_names(compiled),
        ));
    }
    Ok(())
}

/// One all-or-nothing uniform-participation proof per source row, paired with
/// the independently authenticated ordinary native selector table.
#[derive(Clone, Debug)]
pub struct UniformCaptureBridge {
    pub rows: NativeRowBridge,
    pub source_receipts: Vec<UniformCaptureCompileReceipt>,
}

/// One positive uniform-participation proof paired with the exact prepared
/// native `SpanFill` selected after the ordinary helper-free route declined
/// solely because its complete incumbent requires the compatibility runtime.
#[derive(Clone, Debug)]
pub struct PreparedUniformCaptureBridge {
    pub compiled: CompiledRegex,
    pub receipt: UniformCapturePreparedSpanFillCompileReceipt,
}

/// One exact-cardinality, helper-free native capture iterator.
#[derive(Debug)]
pub struct StrictCaptureBridge {
    pub artifact: RebarSingleCaptureAotArtifactV1,
}

/// One exact Rebar selector plus an authenticated helper-free exact-span
/// participation replay export.
#[derive(Debug)]
pub struct ParticipationCaptureBridge {
    pub artifact: RebarSingleCaptureParticipationAotArtifactV1,
}

/// Exact deterministic construction envelope exhausted by the optional
/// direct-DFA participation leaf. This is distinct from allocation, object,
/// authentication and every non-numeric compiler failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParticipationDfaEnvelopeExhaustion {
    pub resource: NativeParticipationAotResourceV1,
    pub required: usize,
    pub limit: usize,
}

/// One helper-free exact ordinary Span selector used as a negative
/// certificate before an explicitly declared stock positive capture route.
#[derive(Debug)]
pub struct SelectorCaptureFallbackBridge {
    pub rows: NativeRowBridge,
    pub direct_participation: ParticipationDfaEnvelopeExhaustion,
}

/// The participation compiler's sole nonterminal result is its authenticated
/// negative entry. All construction, resource, allocation, object and
/// authentication errors remain terminal.
#[derive(Debug)]
pub enum ParticipationCaptureBridgeDisposition {
    Selected(ParticipationCaptureBridge),
    Declined { reason: String },
}

/// A terminal participation compiler failure or the one typed construction
/// exhaustion that a separately authenticated selector-first adapter may
/// consume.
#[derive(Debug)]
pub enum ParticipationCaptureBridgeError {
    Terminal(String),
    DfaEnvelopeExhausted(ParticipationDfaEnvelopeExhaustion),
}

impl fmt::Display for ParticipationCaptureBridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Terminal(message) => formatter.write_str(message),
            Self::DfaEnvelopeExhausted(exhaustion) => write!(
                formatter,
                "direct participation DFA exhausted {:?}: required {}, limit {}",
                exhaustion.resource, exhaustion.required, exhaustion.limit,
            ),
        }
    }
}

impl std::error::Error for ParticipationCaptureBridgeError {}

fn participation_dfa_envelope_exhaustion(
    error: &RebarSingleCaptureParticipationAotErrorV1,
) -> Option<ParticipationDfaEnvelopeExhaustion> {
    let RebarSingleCaptureParticipationAotErrorV1::Participation(
        NativeParticipationAotErrorV1::Resource {
            resource,
            required,
            limit,
        },
    ) = error
    else {
        return None;
    };
    let exact_limit = match resource {
        NativeParticipationAotResourceV1::DfaStates => {
            *limit == REBAR_PARTICIPATION_RETRY_MAX_DFA_STATES
        }
        NativeParticipationAotResourceV1::BuildWork => {
            *limit == REBAR_PARTICIPATION_RETRY_MAX_BUILD_WORK
        }
        _ => false,
    };
    (exact_limit && *required == limit.saturating_add(1)).then_some(
        ParticipationDfaEnvelopeExhaustion {
            resource: *resource,
            required: *required,
            limit: *limit,
        },
    )
}

/// Compile the additive exact-span participation route after the uniform
/// theorem has semantically declined.
pub fn try_compile_participation_capture_bridge(
    benchmark: &Benchmark,
    target: Target,
) -> Result<ParticipationCaptureBridgeDisposition, ParticipationCaptureBridgeError> {
    if !benchmark.model.is_capture() {
        return Err(ParticipationCaptureBridgeError::Terminal(
            "participation capture compilation requires a capture model".to_owned(),
        ));
    }
    if benchmark.patterns.len() != 1 {
        return Ok(ParticipationCaptureBridgeDisposition::Declined {
            reason: format!(
                "exact-span participation V1 requires one source, got {}",
                benchmark.patterns.len()
            ),
        });
    }

    let mut native_limits = NativeParticipationAotLimitsV1::default();
    native_limits.max_object_bytes = MAX_NATIVE_ROW_BRIDGE_OBJECT_BYTES;
    let compile_with_limits = |compile_limits, native_limits| {
        let request = RebarSingleCaptureAotRequestV1::new([benchmark.patterns[0].clone()], target)
            .case_insensitive(benchmark.case_insensitive)
            .unicode(benchmark.unicode)
            .compile_limits(compile_limits);
        compile_rebar_single_capture_participation_aot_v1(request, native_limits)
    };
    let compile_with_native_state_retry =
        |compile_limits| match compile_with_limits(compile_limits, native_limits) {
            Err(error)
                if is_rebar_participation_dfa_state_limit(&error, native_limits.max_dfa_states) =>
            {
                let retry_limits = rebar_participation_native_retry_limits(native_limits);
                compile_with_limits(compile_limits, retry_limits)
            }
            result => result,
        };
    let artifact = match compile_with_native_state_retry(CaptureCompileLimits::default()) {
        Ok(artifact) => artifact,
        Err(error) if is_rebar_participation_lower_work_limit(&error) => {
            let mut compile_limits = CaptureCompileLimits::default();
            compile_limits.selector = rebar_recovery_compile_limits();
            compile_limits.selector_slow_aot = rebar_recovery_slow_aot_limits();
            match compile_with_native_state_retry(compile_limits) {
                Ok(artifact) => artifact,
                Err(error) => {
                    if let Some(exhaustion) = participation_dfa_envelope_exhaustion(&error) {
                        return Err(ParticipationCaptureBridgeError::DfaEnvelopeExhausted(
                            exhaustion,
                        ));
                    }
                    return Err(ParticipationCaptureBridgeError::Terminal(format!(
                        "Rebar participation recovery compilation failed: {error}"
                    )));
                }
            }
        }
        Err(error) => {
            if let Some(exhaustion) = participation_dfa_envelope_exhaustion(&error) {
                return Err(ParticipationCaptureBridgeError::DfaEnvelopeExhausted(
                    exhaustion,
                ));
            }
            return Err(ParticipationCaptureBridgeError::Terminal(format!(
                "Rebar participation compilation failed: {error}"
            )));
        }
    };
    if !artifact.authenticates_receipt()
        || artifact.object().is_empty()
        || artifact.object().len() > MAX_NATIVE_ROW_BRIDGE_OBJECT_BYTES
        || artifact.bundle().is_empty()
    {
        return Err(ParticipationCaptureBridgeError::Terminal(
            "participation artifact failed object/receipt authentication".to_owned(),
        ));
    }
    let receipt = artifact.native_receipt();
    if receipt.strategy == NativeParticipationAotStrategyV1::NegativeEntry {
        let decline = receipt.decline.ok_or_else(|| {
            ParticipationCaptureBridgeError::Terminal(
                "negative participation artifact omitted its semantic decline".to_owned(),
            )
        })?;
        return Ok(ParticipationCaptureBridgeDisposition::Declined {
            reason: format!("{decline:?}"),
        });
    }
    let expected_strategy = match target.architecture {
        Architecture::X86_64 => NativeParticipationAotStrategyV1::DfaX86_64,
        Architecture::Aarch64 => NativeParticipationAotStrategyV1::DfaAarch64,
    };
    let module = artifact.module();
    let selector = artifact.selector_entry_symbol();
    let bundle = artifact.bundle_symbol();
    let participation = artifact.participation_entry_symbol();
    let entry = module
        .symbols()
        .iter()
        .find(|symbol| symbol.name == selector)
        .ok_or_else(|| {
            ParticipationCaptureBridgeError::Terminal(
                "participation selector has no public symbol record".to_owned(),
            )
        })?;
    let unresolved = module.symbols().iter().enumerate().any(|(index, symbol)| {
        symbol.section.is_none()
            && module
                .relocations()
                .iter()
                .any(|relocation| relocation.symbol == index)
    });
    if receipt.strategy != expected_strategy
        || receipt.decline.is_some()
        || receipt.semantic_runtime_calls != 0
        || receipt.groups == 0
        || receipt.groups > MAX_STRICT_CAPTURE_GROUPS
        || receipt.assertion_signatures == 0
        || receipt.byte_classes == 0
        || receipt.dfa_states == 0
        || receipt.transition_cells == 0
        || receipt.build_work == 0
        || receipt.scratch_bytes != fre_aot_regex::NATIVE_PARTICIPATION_AOT_V1_SCRATCH_BYTES
        || receipt.plan_bytes != artifact.bundle().len()
        || selector.is_empty()
        || bundle.is_empty()
        || participation.is_empty()
        || selector == bundle
        || selector == participation
        || bundle == participation
        || module.entry_symbol() != selector
        || module.required_runtime_symbols().next().is_some()
        || module.required_runtime_program().is_some()
        || unresolved
        || module.prepared_entry_symbol().is_some()
        || !module.prepared_aggregate_exports().is_empty()
        || module.required_prepare_capabilities() != 0
        || entry.binding != SymbolBinding::Global
        || entry.kind != SymbolKind::Function
        || entry.section.is_none()
        || entry.size == 0
    {
        return Err(ParticipationCaptureBridgeError::Terminal(
            "participation artifact is not a helper-free native DFA selector/replay closure"
                .to_owned(),
        ));
    }
    Ok(ParticipationCaptureBridgeDisposition::Selected(
        ParticipationCaptureBridge { artifact },
    ))
}

/// Select the one-source grep-captures negative-certificate adapter after the
/// fixed direct-participation construction envelope has been exhausted.
///
/// The selector was produced by the same parsed-HIR uniform transaction and
/// is re-authenticated here. It is authoritative only for proving that an
/// LF-free line has no match. Positive lines are deliberately outside this
/// artifact and must enter the separately declared exact stock capture route.
pub fn compile_selector_capture_fallback_bridge(
    benchmark: &Benchmark,
    selector: NativeRowArtifact,
    direct_participation: ParticipationDfaEnvelopeExhaustion,
) -> Result<SelectorCaptureFallbackBridge, String> {
    if benchmark.model != Model::GrepCaptures || benchmark.patterns.len() != 1 {
        return Err("selector-first capture fallback requires one-source grep-captures".to_owned());
    }
    if selector.first_source_ordinal != 0 {
        return Err("selector-first capture fallback lost source ordinal zero".to_owned());
    }
    authenticate_native_row(&selector.compiled, 0)?;
    let total_object_bytes = selector.compiled.object().len();
    if total_object_bytes == 0 || total_object_bytes > MAX_NATIVE_ROW_BRIDGE_OBJECT_BYTES {
        return Err(format!(
            "selector-first capture object requires {total_object_bytes} bytes, limit is {MAX_NATIVE_ROW_BRIDGE_OBJECT_BYTES}"
        ));
    }
    let exact_limit = match direct_participation.resource {
        NativeParticipationAotResourceV1::DfaStates => {
            direct_participation.limit == REBAR_PARTICIPATION_RETRY_MAX_DFA_STATES
        }
        NativeParticipationAotResourceV1::BuildWork => {
            direct_participation.limit == REBAR_PARTICIPATION_RETRY_MAX_BUILD_WORK
        }
        _ => false,
    };
    if !exact_limit || direct_participation.required != direct_participation.limit.saturating_add(1)
    {
        return Err(
            "selector-first capture fallback received an inexact construction decline".to_owned(),
        );
    }
    Ok(SelectorCaptureFallbackBridge {
        rows: NativeRowBridge {
            artifacts: vec![selector],
            source_to_artifact: vec![0],
            total_object_bytes,
        },
        direct_participation,
    })
}

/// Compile the typed one-source Rebar capture route after a semantic decline
/// from a more specific static theorem. This function performs no fallback of
/// its own: every parse, construction, resource, allocator, emission, and
/// authentication error is terminal.
pub fn compile_strict_capture_bridge(
    benchmark: &Benchmark,
    target: Target,
) -> Result<StrictCaptureBridge, String> {
    if !benchmark.model.is_capture() {
        return Err("strict capture compilation requires a capture model".to_owned());
    }
    let mut request =
        RebarSingleCaptureAotRequestV1::try_from_patterns(benchmark.patterns.clone(), target)
            .map_err(|error| error.to_string())?;
    request = request
        .case_insensitive(benchmark.case_insensitive)
        .unicode(benchmark.unicode);
    let artifact = compile_rebar_single_capture_aot_v1(request)
        .map_err(|error| format!("strict capture compilation failed: {error}"))?;
    if !artifact.authenticates_receipt()
        || artifact.object().is_empty()
        || artifact.object().len() > MAX_NATIVE_ROW_BRIDGE_OBJECT_BYTES
        || artifact.receipt().group_count() == 0
        || artifact.receipt().group_count() > MAX_STRICT_CAPTURE_GROUPS
        || artifact
            .module()
            .required_runtime_symbols()
            .next()
            .is_some()
    {
        return Err("strict capture artifact failed helper-free route authentication".to_owned());
    }
    let capture_next = artifact.capture_next_symbol();
    let capture_materialize = artifact.capture_materialize_symbol();
    let selector = artifact.selector_entry_symbol();
    if capture_next.is_empty()
        || capture_materialize.is_empty()
        || selector.is_empty()
        || capture_next == capture_materialize
        || capture_next == selector
        || capture_materialize == selector
    {
        return Err("strict capture artifact has a malformed export closure".to_owned());
    }
    Ok(StrictCaptureBridge { artifact })
}

/// Compile one single-source capture operation into one native reducer call.
///
/// A conservative uniform-language decline is the only nonterminal outcome.
/// Parse, allocation, lowering, object, and authentication failures remain
/// terminal. The adapter-local recovery retry is restricted to the same exact
/// lowering-work exhaustion already admitted for public Rebar selectors.
pub fn try_compile_native_uniform_capture_reducer(
    benchmark: &Benchmark,
    target: Target,
) -> Result<UniformCaptureReducerCompileDisposition, String> {
    if benchmark.patterns.len() != 1 || !benchmark.model.is_capture() {
        return Err(
            "native uniform-capture reducer requires one CountCaptures/GrepCaptures source"
                .to_owned(),
        );
    }
    let mut profile = RustProfile::rebar_1_12_4();
    profile.options.unicode = benchmark.unicode;
    profile.options.case_insensitive = benchmark.case_insensitive;
    let pattern = benchmark.pattern();
    let parsed = parse(ParseRequest::rust(
        pattern,
        CompatibilityProfile::RustBytes(profile.clone()),
    ))
    .map_err(|error| format!("native uniform-capture reducer parse failed: {error}"))?;
    let CanonicalPattern::Rust(parsed) = parsed.pattern else {
        return Err("native uniform-capture reducer did not produce Rust HIR".to_owned());
    };
    let operation = match benchmark.model {
        Model::CountCaptures => UniformCaptureReducerOperation::CountCaptures,
        Model::GrepCaptures => UniformCaptureReducerOperation::GrepCaptures,
        _ => unreachable!("capture gate accepted a non-capture model"),
    };
    let compile_with_limits = |limits, slow_aot_limits| {
        compile_uniform_capture_reducer(
            &parsed,
            UniformCaptureCompileRequest::new(pattern.len(), target)
                .profile(profile.clone())
                .selector_limits(limits)
                .selector_slow_aot_limits(slow_aot_limits),
            operation,
        )
    };
    let disposition =
        match compile_with_limits(CompileLimitsV1::default(), SlowAotLimits::default()) {
            Ok(disposition) => disposition,
            Err(error) if is_uniform_reducer_lower_work_limit(&error) => compile_with_limits(
                rebar_recovery_compile_limits(),
                rebar_recovery_slow_aot_limits(),
            )
            .map_err(|error| format!("native uniform-capture reducer recovery failed: {error}"))?,
            Err(error) => {
                return Err(format!(
                    "native uniform-capture reducer compilation failed: {error}"
                ));
            }
        };
    if let Some(selected) = disposition.selected() {
        selected
            .authenticate()
            .map_err(|error| format!("native uniform-capture reducer seal failed: {error}"))?;
        if selected.compiled().object().is_empty()
            || selected.compiled().object().len() > MAX_NATIVE_ROW_BRIDGE_OBJECT_BYTES
        {
            return Err(format!(
                "native uniform-capture reducer object is empty or exceeds {MAX_NATIVE_ROW_BRIDGE_OBJECT_BYTES} bytes"
            ));
        }
    }
    Ok(disposition)
}

/// Build-time result that keeps a semantic theorem decline distinct from a
/// terminal parse, lowering, allocation, authentication, or object failure.
///
/// Capture adapters may try another independently authenticated native route
/// only for `Declined`. An `Err` remains terminal and must never be converted
/// into a fallback.
#[derive(Debug)]
pub enum UniformCaptureBridgeDisposition {
    Proven(UniformCaptureBridge),
    Prepared(PreparedUniformCaptureBridge),
    Declined {
        source_ordinal: usize,
        reason: String,
        /// The exact helper-free selector emitted from the same parsed HIR as
        /// an ordinary conservative proof decline. A prepared-selector
        /// decline has no independently usable ordinary artifact. A later
        /// adapter may consume `Some` only under independent authentication.
        selector: Option<NativeRowArtifact>,
    },
}

/// Compile one helper-free native selector per distinct row and prove that
/// every source has one positive, source-independent capture multiplier.
///
/// A semantic decline on any source rejects the whole operation. Distinct
/// capture spellings may erase to the same selector object; in that case the
/// retained row and multiplier are always those of the lowest source ordinal,
/// exactly matching Rust's leftmost-first multi-pattern priority.
pub fn compile_uniform_capture_bridge(
    benchmark: &Benchmark,
    target: Target,
) -> Result<UniformCaptureBridge, String> {
    match try_compile_uniform_capture_bridge(benchmark, target)? {
        UniformCaptureBridgeDisposition::Proven(bridge) => Ok(bridge),
        UniformCaptureBridgeDisposition::Prepared(_) => Err(
            "uniform-capture selected the prepared SpanFill bridge instead of an ordinary row"
                .to_owned(),
        ),
        UniformCaptureBridgeDisposition::Declined {
            source_ordinal,
            reason,
            ..
        } => Err(format!(
            "uniform-capture proof declined at source ordinal {source_ordinal}: {reason}"
        )),
    }
}

/// Compile the uniform route while preserving its sole nonterminal outcome.
pub fn try_compile_uniform_capture_bridge(
    benchmark: &Benchmark,
    target: Target,
) -> Result<UniformCaptureBridgeDisposition, String> {
    if !benchmark.uses_uniform_capture_bridge() || !benchmark.model.is_capture() {
        return Err(
            "uniform-capture bridge compilation requires count-captures or grep-captures"
                .to_owned(),
        );
    }
    if benchmark.patterns.is_empty() || benchmark.patterns.len() > MAX_NATIVE_ROW_BRIDGE_PATTERNS {
        return Err(format!(
            "general-AOT uniform-capture bridge pattern count {} is outside 1..={MAX_NATIVE_ROW_BRIDGE_PATTERNS}",
            benchmark.patterns.len()
        ));
    }

    let mut profile = RustProfile::rebar_1_12_4();
    profile.options.unicode = benchmark.unicode;
    profile.options.case_insensitive = benchmark.case_insensitive;
    let mut exact_sources = BTreeMap::<&str, (usize, UniformCaptureCompileReceipt)>::new();
    let mut link_artifacts = BTreeMap::<String, usize>::new();
    let mut defined_link_symbols = BTreeMap::<String, usize>::new();
    let mut artifacts = Vec::<NativeRowArtifact>::new();
    let mut source_to_artifact = Vec::new();
    let mut source_receipts = Vec::new();
    source_to_artifact
        .try_reserve_exact(benchmark.patterns.len())
        .map_err(|_| "uniform-capture source map allocation failed".to_owned())?;
    source_receipts
        .try_reserve_exact(benchmark.patterns.len())
        .map_err(|_| "uniform-capture receipt allocation failed".to_owned())?;
    let mut total_object_bytes = 0_usize;

    for (source_ordinal, pattern) in benchmark.patterns.iter().enumerate() {
        if let Some(&(artifact_index, receipt)) = exact_sources.get(pattern.as_str()) {
            source_to_artifact.push(artifact_index);
            source_receipts.push(receipt);
            continue;
        }

        let parsed = parse(ParseRequest::rust(
            pattern,
            CompatibilityProfile::RustBytes(profile.clone()),
        ))
        .map_err(|error| {
            format!("uniform-capture parse failed at source ordinal {source_ordinal}: {error}")
        })?;
        let CanonicalPattern::Rust(parsed) = parsed.pattern else {
            return Err(format!(
                "uniform-capture source ordinal {source_ordinal} did not produce Rust HIR"
            ));
        };
        let compile_with_limits = |limits, slow_aot_limits| {
            compile_uniform_capture_selector(
                &parsed,
                UniformCaptureCompileRequest::new(pattern.len(), target)
                    .profile(profile.clone())
                    .selector_limits(limits)
                    .selector_slow_aot_limits(slow_aot_limits),
            )
        };
        let (ordinary, recovered_from_work_limit) =
            match compile_with_limits(CompileLimitsV1::default(), SlowAotLimits::default()) {
                Ok(compiled) => (Ok(compiled), false),
                Err(error) if is_uniform_lower_work_limit(&error) => (
                    compile_with_limits(
                        rebar_recovery_compile_limits(),
                        rebar_recovery_slow_aot_limits(),
                    ),
                    true,
                ),
                Err(error) => (Err(error), false),
            };
        let compiled = match ordinary {
            Ok(compiled) => compiled,
            Err(UniformCaptureCompileError::Authentication(
                UniformCaptureAuthenticationError::RuntimeDependency,
            )) if benchmark.patterns.len() == 1 => {
                let compile_prepared_with_limits = |limits, slow_aot_limits| {
                    compile_uniform_capture_prepared_span_fill_selector(
                        &parsed,
                        UniformCaptureCompileRequest::new(pattern.len(), target)
                            .profile(profile.clone())
                            .selector_limits(limits)
                            .selector_slow_aot_limits(slow_aot_limits),
                    )
                };
                let disposition = match compile_prepared_with_limits(
                    CompileLimitsV1::default(),
                    SlowAotLimits::default(),
                ) {
                    Ok(disposition) => disposition,
                    Err(UniformCapturePreparedSpanFillCompileError::Lower(error))
                        if matches!(
                            error,
                            LowerError::ResourceLimit {
                                resource: LowerResource::Work,
                                ..
                            }
                        ) =>
                    {
                        compile_prepared_with_limits(
                            rebar_recovery_compile_limits(),
                            rebar_recovery_slow_aot_limits(),
                        )
                        .map_err(|error| {
                            format!(
                                "uniform-capture prepared SpanFill recovery failed at source ordinal {source_ordinal}: {error}"
                            )
                        })?
                    }
                    Err(error) => {
                        return Err(format!(
                            "uniform-capture prepared SpanFill compilation failed at source ordinal {source_ordinal}: {error}"
                        ));
                    }
                };
                match disposition {
                    UniformCapturePreparedSpanFillCompileDisposition::Selected(selected) => {
                        selected.authenticate().map_err(|error| {
                            format!(
                                "uniform-capture prepared SpanFill authentication failed at source ordinal {source_ordinal}: {error}"
                            )
                        })?;
                        let (compiled, receipt) = selected.into_parts();
                        if compiled.object().is_empty()
                            || compiled.object().len() > MAX_NATIVE_ROW_BRIDGE_OBJECT_BYTES
                        {
                            return Err(format!(
                                "uniform-capture prepared SpanFill object at source ordinal {source_ordinal} is empty or exceeds {MAX_NATIVE_ROW_BRIDGE_OBJECT_BYTES} bytes"
                            ));
                        }
                        return Ok(UniformCaptureBridgeDisposition::Prepared(
                            PreparedUniformCaptureBridge { compiled, receipt },
                        ));
                    }
                    UniformCapturePreparedSpanFillCompileDisposition::Declined(reason) => {
                        return Ok(UniformCaptureBridgeDisposition::Declined {
                            source_ordinal,
                            reason: format!("{reason:?}"),
                            selector: None,
                        });
                    }
                }
            }
            Err(error) => {
                let phase = if recovered_from_work_limit {
                    " recovery"
                } else {
                    ""
                };
                return Err(format!(
                    "uniform-capture selector{phase} compilation failed at source ordinal {source_ordinal}: {error}"
                ));
            }
        };
        compiled.authenticate().map_err(|error| {
            format!(
                "uniform-capture selector authentication failed at source ordinal {source_ordinal}: {error}"
            )
        })?;
        let (selector, disposition) = compiled.into_parts();
        let proof = match disposition {
            UniformCaptureCompileDisposition::Proven(receipt) => receipt,
            UniformCaptureCompileDisposition::Declined(reason) => {
                authenticate_native_row(&selector, source_ordinal)?;
                return Ok(UniformCaptureBridgeDisposition::Declined {
                    source_ordinal,
                    reason: format!("{reason:?}"),
                    selector: Some(NativeRowArtifact {
                        compiled: selector,
                        first_source_ordinal: source_ordinal,
                        route: NativeRowRoute::Ordinary,
                    }),
                });
            }
        };
        proof.authenticate(&selector).map_err(|error| {
            format!("uniform-capture proof seal failed at source ordinal {source_ordinal}: {error}")
        })?;
        authenticate_native_row(&selector, source_ordinal)?;

        let entry = selector.module().entry_symbol().to_owned();
        let artifact_index = if let Some(&existing) = link_artifacts.get(&entry) {
            let prior = &artifacts[existing].compiled;
            if prior.object() != selector.object()
                || prior.receipt().object_sha256 != selector.receipt().object_sha256
            {
                return Err(format!(
                    "uniform-capture entry symbol collision at source ordinal {source_ordinal}: {entry:?}"
                ));
            }
            proof.authenticate(prior).map_err(|error| {
                format!(
                    "uniform-capture source ordinal {source_ordinal} does not authenticate the retained selector: {error}"
                )
            })?;
            existing
        } else {
            let prospective = total_object_bytes
                .checked_add(selector.object().len())
                .ok_or_else(|| "uniform-capture object-byte total overflowed".to_owned())?;
            if prospective > MAX_NATIVE_ROW_BRIDGE_OBJECT_BYTES {
                return Err(format!(
                    "general-AOT uniform-capture objects require {prospective} bytes, limit is {MAX_NATIVE_ROW_BRIDGE_OBJECT_BYTES}"
                ));
            }
            let index = artifacts.len();
            for symbol in selector.module().symbols().iter().filter(|symbol| {
                symbol.binding == SymbolBinding::Global && symbol.section.is_some()
            }) {
                if let Some(&prior) = defined_link_symbols.get(&symbol.name) {
                    return Err(format!(
                        "uniform-capture source ordinal {source_ordinal} defines link symbol {:?} already owned by artifact {prior}",
                        symbol.name
                    ));
                }
            }
            artifacts
                .try_reserve(1)
                .map_err(|_| "uniform-capture artifact allocation failed".to_owned())?;
            artifacts.push(NativeRowArtifact {
                compiled: selector,
                first_source_ordinal: source_ordinal,
                route: NativeRowRoute::Ordinary,
            });
            for symbol in artifacts[index]
                .compiled
                .module()
                .symbols()
                .iter()
                .filter(|symbol| {
                    symbol.binding == SymbolBinding::Global && symbol.section.is_some()
                })
            {
                defined_link_symbols.insert(symbol.name.clone(), index);
            }
            link_artifacts.insert(entry, index);
            total_object_bytes = prospective;
            index
        };
        exact_sources.insert(pattern.as_str(), (artifact_index, proof));
        source_to_artifact.push(artifact_index);
        source_receipts.push(proof);
    }

    Ok(UniformCaptureBridgeDisposition::Proven(
        UniformCaptureBridge {
            rows: NativeRowBridge {
                artifacts,
                source_to_artifact,
                total_object_bytes,
            },
            source_receipts,
        },
    ))
}

/// Compile and authenticate one ordinary native `Span` object per distinct row.
///
/// Exact duplicate source rows are compiled once. If distinct source strings
/// nevertheless produce the same complete link artifact, that artifact is
/// retained once at its lowest source ordinal. Any row that exposes a
/// runtime-dependent ordinary route is replaced only by an explicitly
/// requested and capability-authenticated prepared Ordered-NFA V15 entry.
/// The ordinary transaction keeps the canonical semantic-DFA attempt, but the
/// adapter deliberately bounds the optional slow-DFA retry to zero. The
/// independent V15 replacement retains the selected transaction's exact
/// compile limits so its semantic identities can be compared without
/// normalization.
/// Compiler, allocation, object, and authentication failures remain terminal.
pub fn compile_native_row_bridge(
    benchmark: &Benchmark,
    target: Target,
) -> Result<NativeRowBridge, String> {
    if !benchmark.uses_native_row_bridge()
        || !matches!(
            benchmark.model,
            Model::Count | Model::SpanSum | Model::GrepCount
        )
    {
        return Err(
            "native-row bridge compilation requires a multi-pattern count, count-spans, or grep job"
                .to_owned(),
        );
    }
    if benchmark.patterns.len() > MAX_NATIVE_ROW_BRIDGE_PATTERNS {
        return Err(format!(
            "general-AOT native-row bridge pattern count {} exceeds limit {}",
            benchmark.patterns.len(),
            MAX_NATIVE_ROW_BRIDGE_PATTERNS
        ));
    }

    let mut profile = RustProfile::rebar_1_12_4();
    profile.options.unicode = benchmark.unicode;
    profile.options.case_insensitive = benchmark.case_insensitive;
    let mut source_artifacts = BTreeMap::<&str, usize>::new();
    let mut link_artifacts = BTreeMap::<String, usize>::new();
    let mut defined_link_symbols = BTreeMap::<String, usize>::new();
    let mut artifacts = Vec::<NativeRowArtifact>::new();
    let mut source_to_artifact = Vec::new();
    source_to_artifact
        .try_reserve_exact(benchmark.patterns.len())
        .map_err(|_| "native-row bridge source map allocation failed".to_owned())?;
    let mut total_object_bytes = 0_usize;

    for (source_ordinal, pattern) in benchmark.patterns.iter().enumerate() {
        if let Some(&artifact_index) = source_artifacts.get(pattern.as_str()) {
            source_to_artifact.push(artifact_index);
            continue;
        }

        let compile_with_limits = |limits, slow_aot_limits| {
            compile_with_slow_aot_limits(
                CompileRequest::new(pattern, target)
                    .profile(profile.clone())
                    .output(OutputContract::Span)
                    .mode(CompileMode::Optimizing)
                    .limits(limits),
                slow_aot_limits,
            )
        };
        let (compiled, selected_limits) = match compile_with_limits(
            CompileLimitsV1::default(),
            native_row_bridge_no_optional_dfa_limits(),
        ) {
            Ok(compiled) => (compiled, CompileLimitsV1::default()),
            Err(error) if is_lower_work_limit(&error) => {
                let limits = rebar_recovery_compile_limits();
                let compiled = compile_with_limits(limits, rebar_recovery_slow_aot_limits())
                    .map_err(|error| {
                        format!(
                            "general AOT native-row recovery compilation failed at source ordinal {source_ordinal}: {error}"
                        )
                    })?;
                (compiled, limits)
            }
            Err(error) => {
                return Err(format!(
                    "general AOT native-row compilation failed at source ordinal {source_ordinal}: {error}"
                ));
            }
        };
        let (compiled, route) = match authenticate_native_row(&compiled, source_ordinal) {
            Ok(()) => (compiled, NativeRowRoute::Ordinary),
            Err(_ordinary_error)
                if compiled.module().required_prepare_capabilities()
                    == PREPARED_CAPABILITY_ORDERED_NFA_V15 =>
            {
                authenticate_prepared_v15_row(&compiled, source_ordinal)?;
                (compiled, NativeRowRoute::PreparedOrderedNfaV15)
            }
            Err(ordinary_error)
                if ordinary_row_is_well_formed_runtime_dependency(&compiled, source_ordinal)? =>
            {
                let disposition = compile_with_prepared_ordered_nfa_v15_reported(
                    CompileRequest::new(pattern, target)
                        .profile(profile.clone())
                        .output(OutputContract::Span)
                        .mode(CompileMode::Optimizing)
                        .limits(selected_limits),
                    PreparedAggregateExports::NONE,
                )
                .map_err(|error| {
                    format!(
                        "general AOT prepared V15 row compilation failed at source ordinal {source_ordinal} after {ordinary_error}: {error}"
                    )
                })?;
                let prepared = match disposition {
                    PreparedOrderedNfaV15CompileDisposition::Compiled(prepared) => prepared,
                    PreparedOrderedNfaV15CompileDisposition::Declined(decline) => {
                        return Err(format!(
                            "general AOT prepared V15 row declined at source ordinal {source_ordinal} after {ordinary_error}: {decline:?}"
                        ));
                    }
                };
                if prepared.receipt().automaton_sha256
                    != compiled.receipt().automaton_sha256
                    || prepared.receipt().program_sha256 != compiled.receipt().program_sha256
                {
                    return Err(format!(
                        "general AOT prepared V15 row changed the semantic identity at source ordinal {source_ordinal}"
                    ));
                }
                authenticate_prepared_v15_row(&prepared, source_ordinal)?;
                (prepared, NativeRowRoute::PreparedOrderedNfaV15)
            }
            Err(error) => return Err(error),
        };

        let entry = match route {
            NativeRowRoute::Ordinary => compiled.module().entry_symbol(),
            NativeRowRoute::PreparedOrderedNfaV15 => compiled
                .module()
                .prepared_entry_symbol()
                .expect("authenticated prepared V15 row entry"),
        }
        .to_owned();
        let artifact_index = if let Some(&existing) = link_artifacts.get(&entry) {
            let prior = &artifacts[existing];
            if prior.route != route
                || prior.compiled.object() != compiled.object()
                || prior.compiled.receipt().object_sha256 != compiled.receipt().object_sha256
            {
                return Err(format!(
                    "native-row entry symbol collision at source ordinal {source_ordinal}: {entry:?}"
                ));
            }
            existing
        } else {
            let prospective = total_object_bytes
                .checked_add(compiled.object().len())
                .ok_or_else(|| "native-row bridge object-byte total overflowed".to_owned())?;
            if prospective > MAX_NATIVE_ROW_BRIDGE_OBJECT_BYTES {
                return Err(format!(
                    "general-AOT native-row bridge objects require {prospective} bytes, limit is {MAX_NATIVE_ROW_BRIDGE_OBJECT_BYTES}"
                ));
            }
            let index = artifacts.len();
            for symbol in compiled.module().symbols().iter().filter(|symbol| {
                symbol.binding == SymbolBinding::Global && symbol.section.is_some()
            }) {
                if let Some(&prior) = defined_link_symbols.get(&symbol.name) {
                    return Err(format!(
                        "native-row source ordinal {source_ordinal} defines link symbol {:?} already owned by artifact {prior}",
                        symbol.name
                    ));
                }
            }
            artifacts
                .try_reserve(1)
                .map_err(|_| "native-row bridge artifact allocation failed".to_owned())?;
            artifacts.push(NativeRowArtifact {
                compiled,
                first_source_ordinal: source_ordinal,
                route,
            });
            for symbol in artifacts[index]
                .compiled
                .module()
                .symbols()
                .iter()
                .filter(|symbol| {
                    symbol.binding == SymbolBinding::Global && symbol.section.is_some()
                })
            {
                defined_link_symbols.insert(symbol.name.clone(), index);
            }
            link_artifacts.insert(entry, index);
            total_object_bytes = prospective;
            index
        };
        source_artifacts.insert(pattern.as_str(), artifact_index);
        source_to_artifact.push(artifact_index);
    }

    Ok(NativeRowBridge {
        artifacts,
        source_to_artifact,
        total_object_bytes,
    })
}

fn authenticate_native_row(compiled: &CompiledRegex, source_ordinal: usize) -> Result<(), String> {
    let module = compiled.module();
    let receipt = compiled.receipt();
    let entry_name = module.entry_symbol();
    let entry = module
        .symbols()
        .iter()
        .find(|symbol| symbol.name == entry_name)
        .ok_or_else(|| {
            format!(
                "native-row source ordinal {source_ordinal} has no public entry record {entry_name:?}"
            )
        })?;
    let runtime_symbols = module.required_runtime_symbols().collect::<Vec<_>>();
    let unresolved_symbols = module
        .symbols()
        .iter()
        .enumerate()
        .filter(|(index, symbol)| {
            symbol.section.is_none()
                && module
                    .relocations()
                    .iter()
                    .any(|relocation| relocation.symbol == *index)
        })
        .map(|(_, symbol)| symbol.name.as_str())
        .collect::<Vec<_>>();
    if receipt.mode != CompileMode::Optimizing
        || receipt.output != OutputContract::Span
        || receipt.runtime_helper_required
        || !runtime_symbols.is_empty()
        || !unresolved_symbols.is_empty()
        || module.prepared_entry_symbol().is_some()
        || module.required_runtime_program().is_some()
        || !module.prepared_aggregate_exports().is_empty()
        || module.prepared_count_symbol().is_some()
        || module.prepared_span_sum_symbol().is_some()
        || module.prepared_grep_count_symbol().is_some()
        || module.required_prepare_capabilities() != 0
        || entry.binding != SymbolBinding::Global
        || entry.kind != SymbolKind::Function
        || entry.section.is_none()
        || entry.size == 0
    {
        return Err(format!(
            "native-row source ordinal {source_ordinal} is not a helper-free ordinary Span entry: engine={:?} runtime_helper={} runtime_symbols={runtime_symbols:?} unresolved_symbols={unresolved_symbols:?} prepared_entry={} runtime_program={} required_prepare_capabilities={:#x} prepared_bulk_strategy={:?} prepared_exports={:?} entry_defined={} entry_size={}",
            receipt.engine,
            receipt.runtime_helper_required,
            module.prepared_entry_symbol().is_some(),
            module.required_runtime_program().is_some(),
            module.required_prepare_capabilities(),
            module.prepared_bulk_strategy(),
            module.prepared_aggregate_exports(),
            entry.section.is_some(),
            entry.size,
        ));
    }
    Ok(())
}

/// Admit the sole additive fallback trigger: an otherwise well-formed
/// ordinary Span artifact whose selected execution surface requires the
/// semantic runtime. Every malformed receipt or symbol geometry remains a
/// terminal error; no compiler error reaches this predicate.
fn ordinary_row_is_well_formed_runtime_dependency(
    compiled: &CompiledRegex,
    _source_ordinal: usize,
) -> Result<bool, String> {
    let module = compiled.module();
    let receipt = compiled.receipt();
    let Some(prepared_entry) = module.prepared_entry_symbol() else {
        return Ok(false);
    };
    let Some(span_fill) = module.prepared_span_fill_symbol() else {
        return Ok(false);
    };
    let Some((program, program_len)) = module.required_runtime_program() else {
        return Ok(false);
    };
    let runtime_symbols_are_closed = match module.prepared_bulk_strategy() {
        Some(PreparedBulkStrategy::NativeTrustedPreflightRuntimeBulk) => {
            has_exact_runtime_symbol_closure(compiled, &PREPARED_V15_ROW_RUNTIME_SYMBOLS)
        }
        Some(PreparedBulkStrategy::NativePreparedLoop) => {
            native_prepared_loop_runtime_symbols_are_closed(compiled)
        }
        Some(PreparedBulkStrategy::NativeFrozenLoop) => {
            native_frozen_loop_runtime_symbols_are_closed(compiled)
        }
        _ => false,
    };
    Ok(receipt.mode == CompileMode::Optimizing
        && receipt.output == OutputContract::Span
        && receipt.engine == EngineKind::OrderedNfa
        && receipt.runtime_helper_required
        && receipt.prepared_aggregate_exports.is_empty()
        && receipt.prepared_aggregate_strategy.is_none()
        && receipt.required_prepare_capabilities == 0
        && module.prepared_aggregate_exports().is_empty()
        && module.prepared_aggregate_strategy().is_none()
        && runtime_symbols_are_closed
        && module.required_prepare_capabilities() == 0
        && module.prepared_count_symbol().is_none()
        && module.prepared_span_sum_symbol().is_none()
        && module.prepared_grep_count_symbol().is_none()
        && module.prepared_exists_batch_symbol().is_none()
        && program_len != 0
        && has_defined_symbol(compiled, module.entry_symbol(), SymbolKind::Function, None)
        && has_defined_symbol(compiled, prepared_entry, SymbolKind::Function, None)
        && has_defined_symbol(compiled, span_fill, SymbolKind::Function, None)
        && has_defined_symbol(compiled, program, SymbolKind::Object, Some(program_len))
        && prepared_row_symbol_identities_are_closed(
            module.entry_symbol(),
            prepared_entry,
            span_fill,
            program,
        )
        && [module.entry_symbol(), prepared_entry, span_fill, program]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == 4
        && !compiled.object().is_empty())
}

fn authenticate_prepared_v15_row(
    compiled: &CompiledRegex,
    source_ordinal: usize,
) -> Result<(), String> {
    let module = compiled.module();
    let receipt = compiled.receipt();
    let entry_name = module
        .prepared_entry_symbol()
        .ok_or_else(|| format!("prepared V15 row {source_ordinal} has no prepared entry"))?;
    let span_fill = module
        .prepared_span_fill_symbol()
        .ok_or_else(|| format!("prepared V15 row {source_ordinal} has no SpanFill entry"))?;
    let (program_name, program_len) = module
        .required_runtime_program()
        .ok_or_else(|| format!("prepared V15 row {source_ordinal} has no serialized program"))?;
    if receipt.mode != CompileMode::Optimizing
        || receipt.output != OutputContract::Span
        || receipt.engine != EngineKind::OrderedNfa
        || !receipt.runtime_helper_required
        || !receipt.prepared_aggregate_exports.is_empty()
        || receipt.prepared_aggregate_strategy.is_some()
        || receipt.required_prepare_capabilities != PREPARED_CAPABILITY_ORDERED_NFA_V15
        || module.required_prepare_capabilities() != PREPARED_CAPABILITY_ORDERED_NFA_V15
        || module.prepared_bulk_strategy() != Some(PreparedBulkStrategy::NativeOrderedNfaLoop)
        || !module.prepared_aggregate_exports().is_empty()
        || module.prepared_aggregate_strategy().is_some()
        || module.prepared_count_symbol().is_some()
        || module.prepared_span_sum_symbol().is_some()
        || module.prepared_grep_count_symbol().is_some()
        || module.prepared_exists_batch_symbol().is_some()
        || program_len == 0
        || !has_exact_runtime_symbol_closure(compiled, &PREPARED_V15_ROW_RUNTIME_SYMBOLS)
        || !has_defined_symbol(compiled, module.entry_symbol(), SymbolKind::Function, None)
        || !has_defined_symbol(compiled, entry_name, SymbolKind::Function, None)
        || !has_defined_symbol(compiled, span_fill, SymbolKind::Function, None)
        || !has_defined_symbol(
            compiled,
            program_name,
            SymbolKind::Object,
            Some(program_len),
        )
        || !prepared_row_symbol_identities_are_closed(
            module.entry_symbol(),
            entry_name,
            span_fill,
            program_name,
        )
        || [module.entry_symbol(), entry_name, span_fill, program_name]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != 4
        || compiled.object().is_empty()
    {
        return Err(format!(
            "prepared V15 row {source_ordinal} failed exact capability and symbol authentication"
        ));
    }
    Ok(())
}

/// Compile one fixed regex-redux stage as an ordinary Span artifact.
///
/// No aggregate or runtime composite is smuggled into this boundary. The
/// linked runner performs only Rebar's deterministic stage sequencing around
/// these independently receipted search entries.
pub fn compile_regex_redux_component(
    component: usize,
    target: Target,
) -> Result<CompiledRegex, String> {
    let pattern = regex_redux_pattern(component)
        .ok_or_else(|| format!("regex-redux component {component} is out of range"))?;
    let mut profile = RustProfile::rebar_1_12_4();
    profile.options.unicode = false;
    profile.options.case_insensitive = false;
    compile(
        CompileRequest::new(pattern, target)
            .profile(profile)
            .output(OutputContract::Span)
            .mode(CompileMode::Optimizing),
    )
    .map_err(|error| format!("regex-redux component {component} compilation failed: {error}"))
}

fn text<'a>(value: &'a [u8], key: &str) -> Result<&'a str, String> {
    std::str::from_utf8(value).map_err(|error| format!("{key} is not UTF-8: {error}"))
}

fn parse_bool(value: &[u8], key: &str) -> Result<bool, String> {
    match text(value, key)? {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(format!("{key} has invalid boolean value {other:?}")),
    }
}

fn parse_u64(value: &[u8], key: &str) -> Result<u64, String> {
    text(value, key)?
        .parse::<u64>()
        .map_err(|error| format!("{key} has invalid integer value: {error}"))
}

fn set_once<T>(slot: &mut Option<T>, value: T, key: &str) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("duplicate scalar KLV key {key:?}"));
    }
    Ok(())
}

fn required<T>(value: Option<T>, key: &str) -> Result<T, String> {
    value.ok_or_else(|| format!("missing required KLV key {key:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(output: &mut Vec<u8>, key: &str, value: &[u8]) {
        output.extend_from_slice(format!("{key}:{}:", value.len()).as_bytes());
        output.extend_from_slice(value);
        output.push(b'\n');
    }

    fn fixture(model: &str, pattern: &[u8], haystack: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        field(&mut output, "name", b"test/model/aot");
        field(&mut output, "model", model.as_bytes());
        field(&mut output, "case-insensitive", b"false");
        field(&mut output, "unicode", b"false");
        field(&mut output, "max-iters", b"2");
        field(&mut output, "max-warmup-iters", b"1");
        field(&mut output, "max-time", b"1000");
        field(&mut output, "max-warmup-time", b"100");
        field(&mut output, "pattern", pattern);
        field(&mut output, "haystack", haystack);
        output
    }

    fn zero_pattern_fixture(model: &str, haystack: &[u8]) -> Vec<u8> {
        let mut output = fixture(model, b"unused", haystack);
        let field = b"pattern:6:unused\n";
        let offset = output
            .windows(field.len())
            .position(|window| window == field)
            .expect("pattern field");
        let end = offset.checked_add(field.len()).expect("pattern field end");
        output.drain(offset..end);
        output
    }

    #[test]
    fn rebar_recovery_envelope_changes_only_work_and_determinization() {
        let ordinary = CompileLimitsV1::default();
        let rebar = rebar_recovery_compile_limits();
        let ordinary_slow = SlowAotLimits::default();
        let rebar_slow = rebar_recovery_slow_aot_limits();
        assert_eq!(rebar.lower.max_work, REBAR_MAX_LOWER_WORK);
        assert_eq!(rebar.lower.max_stack_items, ordinary.lower.max_stack_items);
        assert_eq!(rebar.lower.automata, ordinary.lower.automata);
        assert_eq!(
            rebar.determinize,
            DeterminizeLimits {
                max_states: REBAR_RECOVERY_MAX_DFA_STATES,
                max_transitions: REBAR_RECOVERY_MAX_DFA_TRANSITIONS,
                max_work: REBAR_RECOVERY_MAX_DFA_WORK,
            }
        );
        assert_eq!(rebar.max_program_bytes, ordinary.max_program_bytes);
        assert_eq!(rebar.max_object_bytes, ordinary.max_object_bytes);
        assert!(rebar.lower.max_work > ordinary.lower.max_work);
        assert!(rebar.determinize.max_states < ordinary.determinize.max_states);
        assert_eq!(rebar_slow.determinize, rebar.determinize);
        assert_eq!(
            rebar_slow.max_allocation_bytes,
            ordinary_slow.max_allocation_bytes
        );
        assert_eq!(
            rebar_slow.max_native_data_bytes,
            ordinary_slow.max_native_data_bytes
        );
    }

    #[test]
    fn rebar_construction_envelope_preserves_already_admitted_artifact_identity() {
        let benchmark = Benchmark::parse(&fixture("count", b"a+", b"baa")).expect("count fixture");
        let target = target_from_parts(
            std::env::consts::ARCH,
            std::env::consts::OS,
            FeatureSet::EMPTY.bits(),
        )
        .expect("host target");
        let compile_with_limits = |limits| {
            let mut profile = RustProfile::rebar_1_12_4();
            profile.options.unicode = benchmark.unicode;
            profile.options.case_insensitive = benchmark.case_insensitive;
            compile_with_prepared_aggregate_exports_and_slow_aot_limits(
                CompileRequest::new(benchmark.pattern(), target)
                    .profile(profile)
                    .output(benchmark.model.output())
                    .mode(CompileMode::Optimizing)
                    .limits(limits),
                benchmark.model.exports(),
                SlowAotLimits::default(),
            )
            .expect("already-admitted fixture")
        };
        let ordinary = compile_with_limits(CompileLimitsV1::default());
        let rebar = compile_benchmark(&benchmark, target).expect("Rebar default-first compile");
        assert_eq!(rebar.object(), ordinary.object());
        assert_eq!(
            rebar.receipt().program_sha256,
            ordinary.receipt().program_sha256
        );
        assert_eq!(
            rebar.receipt().object_sha256,
            ordinary.receipt().object_sha256
        );
        assert_eq!(
            rebar.module().entry_symbol(),
            ordinary.module().entry_symbol()
        );
        assert_eq!(
            authenticate_native_whole_scalar_reducer(benchmark.model, &rebar)
                .expect("whole scalar authentication"),
            is_native_whole_scalar_reducer(
                benchmark.model,
                rebar.receipt().prepared_aggregate_strategy,
            ),
        );
    }

    #[test]
    fn safe_v15_declines_return_the_recovered_incumbent_byte_for_byte() {
        use fre_aot_regex::PreparedOrderedNfaV15CompileDecline;

        let target = target_from_parts(
            std::env::consts::ARCH,
            std::env::consts::OS,
            FeatureSet::EMPTY.bits(),
        )
        .expect("host target");
        let recovered = compile(
            CompileRequest::new("ab", target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
        )
        .expect("recovered incumbent fixture");
        let expected_program = recovered.program().serialize().unwrap();
        let expected_object = recovered.object().to_vec();
        let expected_receipt = recovered.receipt().clone();
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
            let selected = select_prepared_ordered_nfa_v15_or_recovered(
                Model::Count,
                recovered.clone(),
                PreparedOrderedNfaV15CompileDisposition::Declined(decline),
            )
            .expect("safe V15 decline");
            assert_eq!(selected.program().serialize().unwrap(), expected_program);
            assert_eq!(selected.object(), expected_object);
            assert_eq!(selected.receipt(), &expected_receipt);
        }
    }

    #[test]
    fn safe_v15_grep_declines_return_the_incumbent_byte_for_byte() {
        use fre_aot_regex::PreparedOrderedNfaV15CompileDecline;

        let target = target_from_parts(
            std::env::consts::ARCH,
            std::env::consts::OS,
            FeatureSet::EMPTY.bits(),
        )
        .expect("host target");
        let incumbent = compile_with_prepared_aggregate_exports_and_slow_aot_limits(
            CompileRequest::new("ab", target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
            PreparedAggregateExports::GREP_COUNT,
            SlowAotLimits::default(),
        )
        .expect("grep incumbent fixture");
        let expected_program = incumbent.program().serialize().unwrap();
        let expected_object = incumbent.object().to_vec();
        let expected_receipt = incumbent.receipt().clone();
        for decline in [
            PreparedOrderedNfaV15CompileDecline::Unsupported,
            PreparedOrderedNfaV15CompileDecline::NativeDataBytes {
                limit: 7,
                required: 8,
            },
            PreparedOrderedNfaV15CompileDecline::ObjectBytes {
                limit: 11,
                required: 12,
            },
        ] {
            let selected = select_prepared_v15_grep_or_incumbent(
                incumbent.clone(),
                PreparedOrderedNfaV15CompileDisposition::Declined(decline),
            )
            .expect("safe grep V15 decline");
            assert_eq!(selected.program().serialize().unwrap(), expected_program);
            assert_eq!(selected.object(), expected_object);
            assert_eq!(selected.receipt(), &expected_receipt);
        }
    }

    #[test]
    fn ordinary_grep_runtime_bulk_requires_one_defined_runtime_helper_batch_entry() {
        let exists_batch = format!(
            "fre_aot_regex_is_match_batch_exclusive_v1_{}",
            "a".repeat(64)
        );
        assert!(ordinary_grep_runtime_bulk_is_authenticated(
            Some(PreparedBulkStrategy::RuntimeHelper),
            Some(&exists_batch),
            true,
        ));
        assert!(!ordinary_grep_runtime_bulk_is_authenticated(
            Some(PreparedBulkStrategy::NativeTrustedPreflightRuntimeBulk),
            Some(&exists_batch),
            true,
        ));
        assert!(!ordinary_grep_runtime_bulk_is_authenticated(
            Some(PreparedBulkStrategy::RuntimeHelper),
            None,
            false,
        ));
        assert!(!ordinary_grep_runtime_bulk_is_authenticated(
            Some(PreparedBulkStrategy::RuntimeHelper),
            Some(""),
            true,
        ));
        assert!(!ordinary_grep_runtime_bulk_is_authenticated(
            Some(PreparedBulkStrategy::RuntimeHelper),
            Some(&exists_batch),
            false,
        ));
    }

    #[test]
    fn ordinary_grep_symbol_identity_requires_exact_closed_suffixes() {
        let ordinary = format!("fre_aot_regex_search_v1_{}", "a".repeat(64));
        let prepared = format!("fre_aot_regex_search_exclusive_v1_{}", "a".repeat(64));
        let exists_batch = format!(
            "fre_aot_regex_is_match_batch_exclusive_v1_{}",
            "a".repeat(64)
        );
        let reducer = format!("fre_aot_regex_grep_count_exclusive_v1_{}", "b".repeat(64));
        let program = format!("fre_aot_regex_runtime_program_v1_{}", "a".repeat(64));
        assert!(ordinary_grep_symbol_identities_are_closed(
            &ordinary,
            &prepared,
            &exists_batch,
            &reducer,
            &program,
        ));

        let poisoned_batch = format!(
            "fre_aot_regex_is_match_batch_exclusive_v1_{}",
            "c".repeat(64)
        );
        assert!(!ordinary_grep_symbol_identities_are_closed(
            &ordinary,
            &prepared,
            &poisoned_batch,
            &reducer,
            &program,
        ));
        let aliased_reducer = format!("fre_aot_regex_grep_count_exclusive_v1_{}", "a".repeat(64));
        assert!(!ordinary_grep_symbol_identities_are_closed(
            &ordinary,
            &prepared,
            &exists_batch,
            &aliased_reducer,
            &program,
        ));
        assert!(!ordinary_grep_symbol_identities_are_closed(
            &ordinary, &prepared, "", &reducer, &program,
        ));
    }

    #[test]
    fn direct_native_grep_identity_requires_a_distinct_reducer() {
        let ordinary = format!("fre_aot_regex_search_v1_{}", "a".repeat(64));
        let reducer = format!("fre_aot_regex_grep_count_exclusive_v1_{}", "b".repeat(64));
        let program = format!("fre_aot_regex_runtime_program_v1_{}", "b".repeat(64));
        assert!(direct_native_grep_symbol_identities_are_closed(
            &ordinary, &reducer, &program,
        ));
        let aliased_reducer =
            format!("fre_aot_regex_grep_count_exclusive_v1_{}", "a".repeat(64));
        assert!(!direct_native_grep_symbol_identities_are_closed(
            &ordinary,
            &aliased_reducer,
            &program,
        ));
        let wrong_program =
            format!("fre_aot_regex_runtime_program_v1_{}", "c".repeat(64));
        assert!(!direct_native_grep_symbol_identities_are_closed(
            &ordinary,
            &reducer,
            &wrong_program,
        ));
    }

    #[test]
    fn prepared_row_symbol_identity_requires_one_exact_suffix() {
        let ordinary = format!("fre_aot_regex_search_v1_{}", "a".repeat(64));
        let prepared = format!("fre_aot_regex_search_exclusive_v1_{}", "a".repeat(64));
        let span_fill = format!(
            "fre_aot_regex_fill_spans_exclusive_v1_{}",
            "a".repeat(64)
        );
        let program = format!("fre_aot_regex_runtime_program_v1_{}", "a".repeat(64));
        assert!(prepared_row_symbol_identities_are_closed(
            &ordinary,
            &prepared,
            &span_fill,
            &program,
        ));

        let wrong_program = format!("fre_aot_regex_runtime_program_v1_{}", "b".repeat(64));
        assert!(!prepared_row_symbol_identities_are_closed(
            &ordinary,
            &prepared,
            &span_fill,
            &wrong_program,
        ));
        assert!(!prepared_row_symbol_identities_are_closed(
            &ordinary,
            &prepared,
            "fre_aot_regex_fill_spans_exclusive_v1_not-a-digest",
            &program,
        ));
    }

    #[test]
    fn ordinary_grep_runtime_symbol_closure_is_exact() {
        assert!(has_exact_symbol_name_closure(
            &ORDINARY_GREP_RUNTIME_SYMBOLS,
            &ORDINARY_GREP_RUNTIME_SYMBOLS,
        ));
        assert!(!has_exact_symbol_name_closure(
            &ORDINARY_GREP_RUNTIME_SYMBOLS[..3],
            &ORDINARY_GREP_RUNTIME_SYMBOLS,
        ));

        let mut poisoned = ORDINARY_GREP_RUNTIME_SYMBOLS;
        poisoned[2] = "fre_aot_regex_runtime_poisoned_is_match_batch_exclusive_v1";
        assert!(!has_exact_symbol_name_closure(
            &poisoned,
            &ORDINARY_GREP_RUNTIME_SYMBOLS,
        ));
        let duplicated = [
            ORDINARY_GREP_RUNTIME_SYMBOLS[0],
            ORDINARY_GREP_RUNTIME_SYMBOLS[1],
            ORDINARY_GREP_RUNTIME_SYMBOLS[2],
            ORDINARY_GREP_RUNTIME_SYMBOLS[3],
            ORDINARY_GREP_RUNTIME_SYMBOLS[3],
        ];
        assert!(!has_exact_symbol_name_closure(
            &duplicated,
            &ORDINARY_GREP_RUNTIME_SYMBOLS,
        ));

        let duplicated_expected = [
            ORDINARY_GREP_RUNTIME_SYMBOLS[0],
            ORDINARY_GREP_RUNTIME_SYMBOLS[1],
            ORDINARY_GREP_RUNTIME_SYMBOLS[2],
            ORDINARY_GREP_RUNTIME_SYMBOLS[2],
        ];
        assert!(!has_exact_symbol_name_closure(
            &ORDINARY_GREP_RUNTIME_SYMBOLS,
            &duplicated_expected,
        ));
    }

    #[test]
    fn optional_runtime_symbol_closure_is_exact() {
        let actual = ["runtime", "fallback", "preflight"];
        let expected = [
            Some("runtime"),
            None,
            Some("fallback"),
            Some("preflight"),
        ];
        assert!(has_exact_optional_symbol_name_closure(&actual, &expected));
        assert!(!has_exact_optional_symbol_name_closure(
            &actual[..2],
            &expected,
        ));

        let extra = ["runtime", "fallback", "preflight", "poisoned"];
        assert!(!has_exact_optional_symbol_name_closure(&extra, &expected));
        let poisoned = ["runtime", "fallback", "poisoned"];
        assert!(!has_exact_optional_symbol_name_closure(
            &poisoned,
            &expected,
        ));
        let duplicated_actual = ["runtime", "runtime", "preflight"];
        assert!(!has_exact_optional_symbol_name_closure(
            &duplicated_actual,
            &expected,
        ));
        let duplicated_expected = [
            Some("runtime"),
            Some("fallback"),
            Some("fallback"),
        ];
        assert!(!has_exact_optional_symbol_name_closure(
            &actual,
            &duplicated_expected,
        ));
    }

    #[test]
    fn ordinary_runtime_helper_grep_is_upgraded_to_authenticated_v15() {
        let mut benchmark = Benchmark::parse(&fixture(
            "grep",
            br"\b\w{25,}\b",
            b"one_very_long_identifier_name\nshort\n",
        ))
        .expect("Unicode grep fixture");
        benchmark.unicode = true;
        let target = target_from_parts(
            std::env::consts::ARCH,
            std::env::consts::OS,
            FeatureSet::EMPTY.bits(),
        )
        .expect("host target");
        let mut profile = RustProfile::rebar_1_12_4();
        profile.options.unicode = true;
        let ordinary = compile_with_prepared_aggregate_exports_and_slow_aot_limits(
            CompileRequest::new(benchmark.pattern(), target)
                .profile(profile)
                .output(OutputContract::Exists)
                .mode(CompileMode::Optimizing)
                .limits(rebar_recovery_compile_limits()),
            PreparedAggregateExports::GREP_COUNT,
            rebar_recovery_slow_aot_limits(),
        )
        .expect("ordinary RuntimeHelper grep incumbent");
        assert!(
            ordinary_grep_requires_prepared_v15(&ordinary),
            "fixture did not produce the exact ordinary grep incumbent: engine={:?} aggregate={:?} bulk={:?} capabilities={:#x} exists_batch={}",
            ordinary.receipt().engine,
            ordinary.module().prepared_aggregate_strategy(),
            ordinary.module().prepared_bulk_strategy(),
            ordinary.module().required_prepare_capabilities(),
            ordinary.module().prepared_exists_batch_symbol().is_some(),
        );

        let selected = compile_benchmark(&benchmark, target).expect("Rebar grep upgrade");
        assert_eq!(
            selected.module().required_prepare_capabilities(),
            PREPARED_CAPABILITY_ORDERED_NFA_V15
        );
        authenticate_prepared_v15_grep(&selected).expect("authenticated prepared V15 grep");
    }

    #[test]
    fn direct_grep_compiles_to_one_authenticated_native_reducer() {
        let benchmark =
            Benchmark::parse(&fixture("grep", b"ab", b"none\nab\r\nlast"))
                .expect("direct grep fixture");
        let target = target_from_parts(
            std::env::consts::ARCH,
            std::env::consts::OS,
            FeatureSet::EMPTY.bits(),
        )
        .expect("host target");
        let selected = compile_benchmark(&benchmark, target).expect("direct native grep compile");
        authenticate_direct_native_grep(&selected).expect("authenticated direct native grep");
        assert_eq!(
            selected.receipt().prepared_aggregate_strategy,
            Some(PreparedAggregateStrategy::NativeFused),
        );
        assert_eq!(selected.module().required_prepare_capabilities(), 0);
    }

    #[test]
    fn recovered_runtime_bulk_shape_has_one_authenticated_prepared_ordered_nfa_replacement() {
        let mut benchmark = Benchmark::parse(&fixture("count", br"\p{L}+", b" aa"))
            .expect("assertion-bearing count fixture");
        benchmark.unicode = true;
        let target = target_from_parts(
            std::env::consts::ARCH,
            std::env::consts::OS,
            FeatureSet::EMPTY.bits(),
        )
        .expect("host target");
        let mut profile = RustProfile::rebar_1_12_4();
        profile.options.unicode = benchmark.unicode;
        profile.options.case_insensitive = benchmark.case_insensitive;
        let recovered = compile_with_prepared_aggregate_exports_and_slow_aot_limits(
            CompileRequest::new(benchmark.pattern(), target)
                .profile(profile.clone())
                .output(benchmark.model.output())
                .mode(CompileMode::Optimizing)
                .limits(rebar_recovery_compile_limits()),
            benchmark.model.exports(),
            rebar_recovery_slow_aot_limits(),
        )
        .expect("runtime-bulk incumbent");
        assert!(
            !recovered_scalar_requires_prepared_ordered_nfa(benchmark.model, &recovered),
            "the small fixture is already native: engine={:?} aggregate={:?} bulk={:?} capabilities={:#x}",
            recovered.receipt().engine,
            recovered.module().prepared_aggregate_strategy(),
            recovered.module().prepared_bulk_strategy(),
            recovered.module().required_prepare_capabilities()
        );
        assert!(recovered_scalar_route_shape(
            Model::Count,
            EngineKind::OrderedNfa,
            Some(PreparedBulkStrategy::NativeTrustedPreflightRuntimeBulk),
            Some(PreparedAggregateStrategy::RuntimeHelper),
            0,
        ));
        assert!(recovered_scalar_route_shape(
            Model::SpanSum,
            EngineKind::OrderedNfa,
            Some(PreparedBulkStrategy::NativeTrustedPreflightRuntimeBulk),
            Some(PreparedAggregateStrategy::RuntimeHelper),
            0,
        ));
        assert!(!recovered_scalar_route_shape(
            Model::GrepCount,
            EngineKind::OrderedNfa,
            Some(PreparedBulkStrategy::NativeTrustedPreflightRuntimeBulk),
            Some(PreparedAggregateStrategy::RuntimeHelper),
            0,
        ));
        assert!(!recovered_scalar_route_shape(
            Model::CountCaptures,
            EngineKind::OrderedNfa,
            Some(PreparedBulkStrategy::NativeTrustedPreflightRuntimeBulk),
            Some(PreparedAggregateStrategy::RuntimeHelper),
            0,
        ));
        assert!(!recovered_scalar_route_shape(
            Model::Count,
            EngineKind::OrderedNfa,
            Some(PreparedBulkStrategy::NativeOrderedNfaLoop),
            Some(PreparedAggregateStrategy::NativeOrderedNfaFused),
            PREPARED_CAPABILITY_ORDERED_NFA_V15,
        ));

        let selected = compile_with_prepared_ordered_nfa_v15_reported(
            CompileRequest::new(benchmark.pattern(), target)
                .profile(profile)
                .output(OutputContract::Span)
                .mode(CompileMode::Optimizing)
                .limits(rebar_recovery_compile_limits()),
            benchmark.model.exports(),
        )
        .expect("explicit prepared Ordered-NFA route")
        .into_compiled()
        .expect("supported fixture must select V15");
        authenticate_prepared_ordered_nfa_scalar(benchmark.model, &selected)
            .expect("native scalar route receipt");
        assert!(
            authenticate_native_whole_scalar_reducer(benchmark.model, &selected)
                .expect("whole Ordered-NFA scalar authentication")
        );
    }

    #[test]
    fn rebar_construction_envelope_preserves_uniform_selector_identity() {
        let pattern = "(a+)";
        let profile = RustProfile::rebar_1_12_4();
        let parsed = parse(ParseRequest::rust(
            pattern,
            CompatibilityProfile::RustBytes(profile.clone()),
        ))
        .expect("capture fixture parse");
        let CanonicalPattern::Rust(parsed) = parsed.pattern else {
            panic!("capture fixture did not produce Rust HIR");
        };
        let target = target_from_parts(
            std::env::consts::ARCH,
            std::env::consts::OS,
            FeatureSet::EMPTY.bits(),
        )
        .expect("host target");
        let ordinary = compile_uniform_capture_selector(
            &parsed,
            UniformCaptureCompileRequest::new(pattern.len(), target).profile(profile),
        )
        .expect("already-admitted capture fixture");
        ordinary.authenticate().expect("ordinary transaction");
        let (ordinary_selector, ordinary_disposition) = ordinary.into_parts();
        let benchmark = Benchmark::parse(&fixture("count-captures", pattern.as_bytes(), b"aaa"))
            .expect("Rebar capture fixture");
        let rebar = compile_uniform_capture_bridge(&benchmark, target).expect("Rebar bridge");
        assert_eq!(rebar.rows.artifacts.len(), 1);
        let rebar_selector = &rebar.rows.artifacts[0].compiled;
        assert_eq!(
            ordinary_disposition.receipt(),
            Some(rebar.source_receipts[0])
        );
        assert_eq!(rebar_selector.object(), ordinary_selector.object());
        assert_eq!(
            rebar_selector.receipt().program_sha256,
            ordinary_selector.receipt().program_sha256
        );
        assert_eq!(
            rebar_selector.receipt().object_sha256,
            ordinary_selector.receipt().object_sha256
        );
    }

    #[test]
    fn rebar_recovery_never_retries_non_work_or_allocation_failures() {
        let states = CompileError::Lower(LowerError::ResourceLimit {
            resource: LowerResource::States,
            needed: 2,
            limit: 1,
        });
        let allocation = CompileError::Lower(LowerError::AllocationFailed {
            structure: "test",
            additional: 1,
        });
        assert!(!is_lower_work_limit(&states));
        assert!(!is_lower_work_limit(&allocation));
        assert!(!is_uniform_lower_work_limit(
            &UniformCaptureCompileError::Lower(LowerError::AllocationFailed {
                structure: "test",
                additional: 1,
            })
        ));
        assert!(is_lower_work_limit(&CompileError::Lower(
            LowerError::ResourceLimit {
                resource: LowerResource::Work,
                needed: 2,
                limit: 1,
            }
        )));
    }

    #[test]
    fn parses_binary_haystack_and_maps_typed_model() {
        let parsed =
            Benchmark::parse(&fixture("count-spans", b"a:b", b"a:b\n\xff")).expect("parse fixture");
        assert_eq!(parsed.model, Model::SpanSum);
        assert_eq!(
            parsed.model.adapter(),
            "general-aot-linked-complete-spans-prepared-v2"
        );
        assert_eq!(parsed.pattern(), "a:b");
        assert_eq!(parsed.haystack, b"a:b\n\xff");
        assert_eq!(parsed.max_iters, 2);
    }

    #[test]
    fn admits_typed_capture_models_and_multi_pattern_reducers() {
        let captures = Benchmark::parse(&fixture("count-captures", b"(a)", b"a"))
            .expect("count-captures fixture");
        assert_eq!(captures.model, Model::CountCaptures);
        assert!(captures.model.is_capture());
        assert!(captures.uses_uniform_capture_bridge());
        assert!(!captures.uses_native_row_bridge());
        let grep_captures = Benchmark::parse(&fixture("grep-captures", b"(a)", b"a"))
            .expect("grep-captures fixture");
        assert_eq!(grep_captures.model, Model::GrepCaptures);
        assert!(grep_captures.uses_uniform_capture_bridge());
        assert!(Benchmark::parse(&fixture("compile", b"a", b"a")).is_err());
        let mut multi = fixture("count", b"a", b"a");
        let insertion = b"pattern:1:b\n";
        let offset = multi
            .windows(b"haystack".len())
            .position(|window| window == b"haystack")
            .expect("haystack field");
        multi.splice(offset..offset, insertion.iter().copied());
        let parsed = Benchmark::parse(&multi).expect("multi-pattern Count");
        assert_eq!(parsed.patterns, ["a", "b"]);
        assert!(parsed.uses_native_row_bridge());

        let mut multi_captures = fixture("count-captures", b"(a)", b"a");
        let offset = multi_captures
            .windows(b"haystack".len())
            .position(|window| window == b"haystack")
            .expect("haystack field");
        multi_captures.splice(offset..offset, b"pattern:3:(b)\n".iter().copied());
        let parsed = Benchmark::parse(&multi_captures).expect("multi-pattern capture model");
        assert_eq!(parsed.patterns, ["(a)", "(b)"]);
        assert!(parsed.uses_uniform_capture_bridge());
        assert!(!parsed.uses_native_row_bridge());

        let mut multi_grep = fixture("grep", b"a", b"a\nno");
        let offset = multi_grep
            .windows(b"haystack".len())
            .position(|window| window == b"haystack")
            .expect("haystack field");
        multi_grep.splice(offset..offset, insertion.iter().copied());
        let parsed = Benchmark::parse(&multi_grep).expect("multi-pattern GrepCount");
        assert_eq!(parsed.patterns, ["a", "b"]);
        assert!(parsed.uses_native_row_bridge());
    }

    #[test]
    fn single_uniform_capture_jobs_select_one_authenticated_reducer() {
        let target = target_from_parts(
            std::env::consts::ARCH,
            std::env::consts::OS,
            FeatureSet::EMPTY.bits(),
        )
        .expect("host target");
        for (model, expected_operation, prefix) in [
            (
                "count-captures",
                UniformCaptureReducerOperation::CountCaptures,
                "fre_aot_regex_count_captures_exclusive_v1_",
            ),
            (
                "grep-captures",
                UniformCaptureReducerOperation::GrepCaptures,
                "fre_aot_regex_grep_captures_exclusive_v1_",
            ),
        ] {
            let benchmark = Benchmark::parse(&fixture(model, b"(a+)", b"aa\r\nb\na"))
                .expect("uniform capture fixture");
            let disposition = try_compile_native_uniform_capture_reducer(&benchmark, target)
                .expect("native uniform capture reducer");
            let selected = disposition
                .selected()
                .expect("uniform capture fixture proves one multiplier");
            selected.authenticate().expect("fresh reducer seal");
            assert_eq!(selected.receipt().operation(), expected_operation);
            assert!(selected.reducer_symbol().starts_with(prefix));
            assert_eq!(selected.receipt().multiplier().get(), 2);
        }
    }

    #[test]
    fn nonuniform_capture_job_declines_before_adapter_selection() {
        let benchmark = Benchmark::parse(&fixture("count-captures", b"(a)?b", b"ab b"))
            .expect("nonuniform capture fixture");
        let target = target_from_parts(
            std::env::consts::ARCH,
            std::env::consts::OS,
            FeatureSet::EMPTY.bits(),
        )
        .expect("host target");
        let disposition = try_compile_native_uniform_capture_reducer(&benchmark, target)
            .expect("conservative uniform capture disposition");
        assert!(disposition.decline().is_some());
    }

    #[test]
    fn native_row_bridge_deduplicates_source_rows_and_has_no_helper_surface() {
        let mut multi = fixture("count-spans", b"a+", b"abba");
        let insertion = b"pattern:2:a+\npattern:2:b+\n";
        let offset = multi
            .windows(b"haystack".len())
            .position(|window| window == b"haystack")
            .expect("haystack field");
        multi.splice(offset..offset, insertion.iter().copied());
        let benchmark = Benchmark::parse(&multi).expect("native-row fixture");
        let target = target_from_parts(
            std::env::consts::ARCH,
            std::env::consts::OS,
            FeatureSet::EMPTY.bits(),
        )
        .expect("host target");
        let bridge = compile_native_row_bridge(&benchmark, target).expect("native-row bridge");
        let mut profile = RustProfile::rebar_1_12_4();
        profile.options.unicode = benchmark.unicode;
        profile.options.case_insensitive = benchmark.case_insensitive;
        let ordinary = compile_with_slow_aot_limits(
            CompileRequest::new("a+", target)
                .profile(profile)
                .output(OutputContract::Span)
                .mode(CompileMode::Optimizing),
            SlowAotLimits::default(),
        )
        .expect("ordinary first-pass DFA winner");
        assert_eq!(bridge.source_to_artifact, [0, 0, 1]);
        assert_eq!(bridge.artifacts.len(), 2);
        assert_eq!(bridge.artifacts[0].first_source_ordinal, 0);
        assert_eq!(bridge.artifacts[1].first_source_ordinal, 2);
        assert_eq!(bridge.artifacts[0].compiled.object(), ordinary.object());
        assert_eq!(
            bridge.artifacts[0].compiled.receipt().object_sha256,
            ordinary.receipt().object_sha256
        );
        assert_eq!(
            bridge.total_object_bytes,
            bridge
                .artifacts
                .iter()
                .map(|artifact| artifact.compiled.object().len())
                .sum::<usize>()
        );
        for artifact in bridge.artifacts {
            assert!(!artifact.compiled.receipt().runtime_helper_required);
            assert!(artifact
                .compiled
                .module()
                .required_runtime_symbols()
                .next()
                .is_none());
            assert!(artifact.compiled.module().prepared_entry_symbol().is_none());
        }
    }

    #[test]
    fn shared_ordered_many_aggregate_is_one_native_semantic_program() {
        let mut multi = fixture("count", b"ab", b"abaabb");
        let offset = multi
            .windows(b"haystack".len())
            .position(|window| window == b"haystack")
            .expect("haystack field");
        multi.splice(
            offset..offset,
            b"pattern:1:a\npattern:2:b+\n".iter().copied(),
        );
        let benchmark = Benchmark::parse(&multi).expect("shared ordered-many fixture");
        let target = target_from_parts(
            std::env::consts::ARCH,
            std::env::consts::OS,
            FeatureSet::EMPTY.bits(),
        )
        .expect("host target");
        let artifact = compile_shared_ordered_many_aggregate(&benchmark, target)
            .expect("shared ordered-many aggregate");
        assert_eq!(artifact.receipt().rows, 3);
        assert_eq!(
            artifact.compiled().module().prepared_aggregate_exports(),
            PreparedAggregateExports::COUNT,
        );
        assert_eq!(
            artifact.receipt().aggregate_strategy,
            PreparedAggregateStrategy::NativeFused,
        );
        assert_eq!(artifact.compiled().module().required_prepare_capabilities(), 0);
        assert!(
            artifact
                .compiled()
                .module()
                .required_runtime_symbols()
                .next()
                .is_none(),
        );
        assert!(artifact.compiled().module().prepared_count_symbol().is_some());
        assert_ne!(artifact.receipt().ordered_sources_sha256, [0; 32]);
    }

    #[test]
    #[ignore = "requires FRE_TEST_NOSEY_KLV naming the public Nosey Parker multi KLV"]
    fn public_nosey_parker_multi_compiles_as_one_shared_native_reducer() {
        let path = std::env::var_os("FRE_TEST_NOSEY_KLV")
            .expect("FRE_TEST_NOSEY_KLV names the public KLV");
        let bytes = std::fs::read(path).expect("read public Nosey Parker KLV");
        let benchmark = Benchmark::parse(&bytes).expect("parse public Nosey Parker KLV");
        assert_eq!(benchmark.name, "curated/13-noseyparker/multi");
        assert_eq!(benchmark.model, Model::Count);
        assert_eq!(benchmark.patterns.len(), 96);
        let target = target_from_parts(
            std::env::consts::ARCH,
            std::env::consts::OS,
            FeatureSet::EMPTY.bits(),
        )
        .expect("host target");
        let artifact = compile_shared_ordered_many_aggregate(&benchmark, target)
            .expect("compile public Nosey Parker shared reducer");
        assert_eq!(artifact.receipt().rows, 96);
        assert_eq!(
            artifact.receipt().aggregate_strategy,
            PreparedAggregateStrategy::NativeFused,
        );
        assert_eq!(artifact.compiled().module().required_prepare_capabilities(), 0);
        assert!(artifact.compiled().module().prepared_count_symbol().is_some());
    }

    #[test]
    #[ignore = "requires FRE_TEST_REBAR_MULTI_DIR naming a public Rebar KLV directory"]
    fn public_scalar_multi_schedule_admits_shared_reducers() {
        let directory = std::env::var_os("FRE_TEST_REBAR_MULTI_DIR")
            .expect("FRE_TEST_REBAR_MULTI_DIR names the public KLV directory");
        let mut jobs = Vec::new();
        for entry in std::fs::read_dir(directory).expect("read public KLV directory") {
            let path = entry.expect("public KLV directory entry").path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("klv") {
                continue;
            }
            let bytes = std::fs::read(&path).expect("read public scalar-multi KLV");
            let benchmark = match Benchmark::parse(&bytes) {
                Ok(benchmark) => benchmark,
                Err(error)
                    if error
                        == "general AOT object emission is not a search-ready Rebar compile operation" =>
                {
                    continue;
                }
                Err(error) => panic!("parse public scalar-multi KLV {path:?}: {error}"),
            };
            if benchmark.patterns.len() > 1
                && matches!(benchmark.model, Model::Count | Model::SpanSum)
            {
                jobs.push((benchmark.name.clone(), benchmark, path));
            }
        }
        jobs.sort_by(|left, right| left.0.cmp(&right.0));
        let mut unique_jobs = Vec::new();
        for job in jobs {
            if unique_jobs.iter().any(|existing: &(String, Benchmark, _)| {
                job.1.same_compilation_identity(&existing.1)
            }) {
                continue;
            }
            unique_jobs.push(job);
        }
        let jobs = unique_jobs;
        let mut row_counts = jobs
            .iter()
            .map(|(_, benchmark, _)| benchmark.patterns.len())
            .collect::<Vec<_>>();
        row_counts.sort_unstable();
        assert_eq!(row_counts, [88, 88, 96, 2_663, 2_663]);

        let target = target_from_parts(
            std::env::consts::ARCH,
            std::env::consts::OS,
            FeatureSet::EMPTY.bits(),
        )
        .expect("host target");
        for (name, benchmark, _) in jobs {
            let artifact = compile_shared_ordered_many_aggregate(&benchmark, target)
                .unwrap_or_else(|error| panic!("public {name:?} shared reducer: {error}"));
            assert_eq!(artifact.receipt().rows, benchmark.patterns.len());
            assert_eq!(
                artifact.receipt().aggregate_strategy,
                PreparedAggregateStrategy::NativeFused,
            );
            eprintln!(
                "shared-admission name={name:?} model={} rows={} pattern_bytes={} object_bytes={} strategy={:?} bulk={:?} runtime_symbols={:?}",
                benchmark.model.name(),
                artifact.receipt().rows,
                artifact.receipt().pattern_bytes,
                artifact.compiled().object().len(),
                artifact.receipt().aggregate_strategy,
                artifact.compiled().module().prepared_bulk_strategy(),
                unresolved_runtime_function_names(artifact.compiled()),
            );
        }
    }

    #[test]
    fn native_dynamic_loop_is_only_a_trigger_for_authenticated_v15() {
        const TRIGGER: &str = r"(?i)(?:abc.?cdccefg|abc.?cdccefg.?hfidg|abc.?hfidg)[=:;=]?\s{0,30}(?:j|kl|k)\s{0,30}[=:;=]?([a-z0-9.!-]{16,200})[^a-z0-9.!-]";
        assert_eq!(TRIGGER.len(), 124);

        for (architecture, operating_system) in [("x86_64", "linux"), ("aarch64", "macos")] {
            let target =
                target_from_parts(architecture, operating_system, FeatureSet::EMPTY.bits())
                    .expect("supported target");
            let mut profile = RustProfile::rebar_1_12_4();
            profile.options.unicode = false;
            profile.options.case_insensitive = false;
            let ordinary = compile_with_slow_aot_limits(
                CompileRequest::new(TRIGGER, target)
                    .profile(profile)
                    .output(OutputContract::Span)
                    .mode(CompileMode::Optimizing),
                native_row_bridge_no_optional_dfa_limits(),
            )
            .expect("shape-equivalent native dynamic-loop incumbent");
            assert_eq!(ordinary.receipt().engine, EngineKind::OrderedNfa);
            assert!(ordinary.receipt().runtime_helper_required);
            assert!(ordinary.receipt().prepared_aggregate_exports.is_empty());
            assert!(ordinary.receipt().prepared_aggregate_strategy.is_none());
            assert_eq!(ordinary.receipt().required_prepare_capabilities, 0);
            let strategy = if architecture == "x86_64" {
                PreparedBulkStrategy::NativePreparedLoop
            } else {
                PreparedBulkStrategy::NativeFrozenLoop
            };
            assert_eq!(ordinary.module().prepared_bulk_strategy(), Some(strategy));
            assert_eq!(
                native_frozen_loop_runtime_symbols_are_closed(&ordinary),
                strategy == PreparedBulkStrategy::NativeFrozenLoop
            );
            assert_eq!(
                native_prepared_loop_runtime_symbols_are_closed(&ordinary),
                strategy == PreparedBulkStrategy::NativePreparedLoop
            );
            assert!(
                ordinary_row_is_well_formed_runtime_dependency(&ordinary, 1)
                    .expect("typed runtime-dependency check")
            );

            let benchmark = Benchmark {
                name: "test/model/native-prepared-loop-upgrade".to_owned(),
                model: Model::Count,
                patterns: vec!["a+".to_owned(), TRIGGER.to_owned()],
                case_insensitive: false,
                unicode: false,
                haystack: b"aa no synthetic token".to_vec(),
                max_iters: 1,
                max_warmup_iters: 0,
                max_time: Duration::from_secs(1),
                max_warmup_time: Duration::ZERO,
            };
            let bridge = compile_native_row_bridge(&benchmark, target)
                .expect("native prepared loop selects explicit V15");
            assert_eq!(bridge.source_to_artifact, [0, 1]);
            assert_eq!(bridge.artifacts.len(), 2);
            assert_eq!(bridge.artifacts[0].route, NativeRowRoute::Ordinary);
            assert_eq!(
                bridge.artifacts[1].route,
                NativeRowRoute::PreparedOrderedNfaV15
            );
            let selected = &bridge.artifacts[1].compiled;
            assert_eq!(
                selected.module().required_prepare_capabilities(),
                PREPARED_CAPABILITY_ORDERED_NFA_V15
            );
            assert_eq!(
                selected.module().prepared_bulk_strategy(),
                Some(PreparedBulkStrategy::NativeOrderedNfaLoop)
            );
            assert!(has_exact_runtime_symbol_closure(
                selected,
                &PREPARED_V15_ROW_RUNTIME_SYMBOLS,
            ));
            assert_eq!(
                selected.receipt().automaton_sha256,
                ordinary.receipt().automaton_sha256,
            );
            assert_eq!(
                selected.receipt().program_sha256,
                ordinary.receipt().program_sha256,
            );
        }
    }

    #[test]
    fn native_row_bridge_routes_one_runtime_dependent_row_through_explicit_v15() {
        let mut multi = fixture("count", b"a+", b"foo");
        let insertion = b"pattern:7:\\bfoo\\b\n";
        let offset = multi
            .windows(b"haystack".len())
            .position(|window| window == b"haystack")
            .expect("haystack field");
        multi.splice(offset..offset, insertion.iter().copied());
        let mut benchmark = Benchmark::parse(&multi).expect("helper trap fixture");
        benchmark.unicode = true;
        for (architecture, operating_system) in [("x86_64", "linux"), ("aarch64", "macos")] {
            let target =
                target_from_parts(architecture, operating_system, FeatureSet::EMPTY.bits())
                    .expect("supported target");
            let bridge = compile_native_row_bridge(&benchmark, target)
                .expect("runtime-dependent row selects explicit prepared V15");
            assert_eq!(bridge.source_to_artifact, [0, 1]);
            assert_eq!(bridge.artifacts.len(), 2);
            assert_eq!(bridge.artifacts[0].route, NativeRowRoute::Ordinary);
            assert_eq!(
                bridge.artifacts[1].route,
                NativeRowRoute::PreparedOrderedNfaV15
            );
            assert_eq!(
                bridge.artifacts[1]
                    .compiled
                    .module()
                    .required_prepare_capabilities(),
                PREPARED_CAPABILITY_ORDERED_NFA_V15
            );
            assert_eq!(
                bridge.artifacts[1]
                    .compiled
                    .module()
                    .prepared_bulk_strategy(),
                Some(PreparedBulkStrategy::NativeOrderedNfaLoop)
            );
            assert!(bridge.artifacts[1]
                .compiled
                .module()
                .prepared_span_fill_symbol()
                .is_some());
        }
    }

    #[test]
    fn uniform_capture_bridge_binds_winning_source_multiplier_after_selector_dedup() {
        let target = target_from_parts(
            std::env::consts::ARCH,
            std::env::consts::OS,
            FeatureSet::EMPTY.bits(),
        )
        .expect("host target");
        for (first, second, expected_first_groups) in [
            (b"(a+)".as_slice(), b"a+".as_slice(), 2),
            (b"a+", b"(a+)", 1),
        ] {
            let mut klv = fixture("count-captures", first, b"aa x aaa");
            let insertion = format!(
                "pattern:{}:{}\n",
                second.len(),
                std::str::from_utf8(second).expect("ASCII fixture")
            );
            let offset = klv
                .windows(b"haystack".len())
                .position(|window| window == b"haystack")
                .expect("haystack field");
            klv.splice(offset..offset, insertion.bytes());
            let benchmark = Benchmark::parse(&klv).expect("uniform-capture fixture");
            let bridge =
                compile_uniform_capture_bridge(&benchmark, target).expect("uniform-capture bridge");
            assert_eq!(bridge.rows.artifacts.len(), 1);
            assert_eq!(bridge.rows.source_to_artifact, [0, 0]);
            assert_eq!(bridge.rows.artifacts[0].first_source_ordinal, 0);
            let groups = bridge
                .source_receipts
                .iter()
                .map(|receipt| {
                    receipt
                        .participation()
                        .participating_groups_per_match()
                        .get()
                })
                .collect::<Vec<_>>();
            assert_eq!(groups[0], expected_first_groups);
            assert_eq!(groups.iter().sum::<usize>(), 3);
            for receipt in &bridge.source_receipts {
                receipt
                    .authenticate(&bridge.rows.artifacts[0].compiled)
                    .expect("each source proof binds the retained selector");
            }
        }
    }

    #[test]
    fn uniform_capture_bridge_declines_the_complete_job_on_one_unproved_source() {
        let target = target_from_parts(
            std::env::consts::ARCH,
            std::env::consts::OS,
            FeatureSet::EMPTY.bits(),
        )
        .expect("host target");
        for pattern in [b"(a)?b".as_slice(), b"(a)*".as_slice()] {
            let benchmark = Benchmark::parse(&fixture("count-captures", pattern, b"aa b"))
                .expect("decline fixture");
            assert!(matches!(
                try_compile_uniform_capture_bridge(&benchmark, target),
                Ok(UniformCaptureBridgeDisposition::Declined {
                    source_ordinal: 0,
                    ..
                })
            ));
            let error = compile_uniform_capture_bridge(&benchmark, target)
                .expect_err("a semantic decline rejects the complete job");
            assert!(error.contains("source ordinal 0"), "{error}");
            assert!(error.contains("proof declined"), "{error}");
        }
    }

    #[test]
    fn uniform_capture_runtime_dependency_selects_exact_prepared_span_fill() {
        let pattern = br"\b(?:([\w&&\p{Cyrillic}]{6})|([\w&&\p{Cyrillic}]{5}))\b";
        let mut benchmark = Benchmark::parse(&fixture("count-captures", pattern, b"words"))
            .expect("prepared uniform-capture fixture");
        benchmark.unicode = true;
        let target = target_from_parts(
            std::env::consts::ARCH,
            std::env::consts::OS,
            FeatureSet::EMPTY.bits(),
        )
        .expect("host target");
        let UniformCaptureBridgeDisposition::Prepared(bridge) =
            try_compile_uniform_capture_bridge(&benchmark, target)
                .expect("typed runtime dependency selects prepared route")
        else {
            panic!("uniform runtime dependency did not select prepared SpanFill");
        };
        bridge
            .receipt
            .authenticate(&bridge.compiled)
            .expect("prepared uniform-capture receipt");
        assert_eq!(
            bridge
                .receipt
                .participation()
                .participating_groups_per_match()
                .get(),
            2,
        );
        assert_eq!(
            bridge.compiled.module().prepared_bulk_strategy(),
            Some(fre_aot_regex::PreparedBulkStrategy::NativeOrderedNfaLoop),
        );
        assert_eq!(
            bridge.compiled.module().required_prepare_capabilities(),
            fre_aot_regex::PREPARED_CAPABILITY_ORDERED_NFA_V15,
        );
    }

    #[test]
    fn strict_capture_bridge_is_exactly_one_source_and_helper_free() {
        let target = target_from_parts(
            std::env::consts::ARCH,
            std::env::consts::OS,
            FeatureSet::EMPTY.bits(),
        )
        .expect("host target");
        let benchmark = Benchmark::parse(&fixture("count-captures", b"(a)?b", b"ab b"))
            .expect("strict capture fixture");
        assert!(matches!(
            try_compile_uniform_capture_bridge(&benchmark, target),
            Ok(UniformCaptureBridgeDisposition::Declined { .. })
        ));
        let strict = compile_strict_capture_bridge(&benchmark, target).expect("strict capture");
        assert!(strict.artifact.authenticates_receipt());
        assert!(strict
            .artifact
            .module()
            .required_runtime_symbols()
            .next()
            .is_none());
        assert_eq!(strict.artifact.receipt().source_cardinality(), 1);
        assert!(strict.artifact.receipt().includes_group_zero());
        assert!(strict.artifact.receipt().group_count() <= MAX_STRICT_CAPTURE_GROUPS);

        let mut many = fixture("count-captures", b"(a)", b"a");
        let offset = many
            .windows(b"haystack".len())
            .position(|window| window == b"haystack")
            .expect("haystack field");
        many.splice(offset..offset, b"pattern:3:(b)\n".iter().copied());
        let many = Benchmark::parse(&many).expect("multi-source capture fixture");
        assert!(compile_strict_capture_bridge(&many, target).is_err());
    }

    #[test]
    fn participation_capture_bridge_selects_after_uniform_semantic_decline() {
        let target = target_from_parts(
            std::env::consts::ARCH,
            std::env::consts::OS,
            FeatureSet::EMPTY.bits(),
        )
        .expect("host target");
        let benchmark = Benchmark::parse(&fixture("count-captures", b"(a)?b", b"ab b"))
            .expect("participation capture fixture");
        assert!(matches!(
            try_compile_uniform_capture_bridge(&benchmark, target),
            Ok(UniformCaptureBridgeDisposition::Declined { .. })
        ));
        let ParticipationCaptureBridgeDisposition::Selected(bridge) =
            try_compile_participation_capture_bridge(&benchmark, target)
                .expect("participation compiler")
        else {
            panic!("participation fixture unexpectedly declined");
        };
        let receipt = bridge.artifact.native_receipt();
        let expected = match target.architecture {
            Architecture::X86_64 => NativeParticipationAotStrategyV1::DfaX86_64,
            Architecture::Aarch64 => NativeParticipationAotStrategyV1::DfaAarch64,
        };
        assert!(bridge.artifact.authenticates_receipt());
        assert_eq!(receipt.strategy, expected);
        assert!(receipt.decline.is_none());
        assert_eq!(receipt.semantic_runtime_calls, 0);
        assert!(bridge
            .artifact
            .module()
            .required_runtime_symbols()
            .next()
            .is_none());
        assert!(bridge
            .artifact
            .module()
            .required_runtime_program()
            .is_none());
    }

    #[test]
    fn participation_state_retry_preserves_already_admitted_artifact_identity() {
        let target = target_from_parts(
            std::env::consts::ARCH,
            std::env::consts::OS,
            FeatureSet::EMPTY.bits(),
        )
        .expect("host target");
        let compile = |limits| {
            compile_rebar_single_capture_participation_aot_v1(
                RebarSingleCaptureAotRequestV1::new(["(a)?b".to_owned()], target),
                limits,
            )
            .expect("already-admitted participation artifact")
        };
        let mut ordinary_limits = NativeParticipationAotLimitsV1::default();
        ordinary_limits.max_object_bytes = MAX_NATIVE_ROW_BRIDGE_OBJECT_BYTES;
        let retry_limits = rebar_participation_native_retry_limits(ordinary_limits);
        let mut expected_retry_limits = ordinary_limits;
        expected_retry_limits.max_dfa_states = REBAR_PARTICIPATION_RETRY_MAX_DFA_STATES;
        expected_retry_limits.max_build_work = REBAR_PARTICIPATION_RETRY_MAX_BUILD_WORK;
        assert_eq!(retry_limits, expected_retry_limits);
        let ordinary = compile(ordinary_limits);
        let retry = compile(retry_limits);
        assert_eq!(retry.receipt(), ordinary.receipt());
        assert_eq!(retry.object(), ordinary.object());
        assert_eq!(retry.bundle(), ordinary.bundle());
        assert_eq!(retry.bundle_symbol(), ordinary.bundle_symbol());
        assert_eq!(
            retry.selector_entry_symbol(),
            ordinary.selector_entry_symbol()
        );
        assert_eq!(
            retry.participation_entry_symbol(),
            ordinary.participation_entry_symbol()
        );
    }

    #[test]
    fn participation_state_retry_classifier_is_narrow_and_fail_closed() {
        let default_limit = NativeParticipationAotLimitsV1::default().max_dfa_states;
        let exact_state_cap = RebarSingleCaptureParticipationAotErrorV1::Participation(
            NativeParticipationAotErrorV1::Resource {
                resource: NativeParticipationAotResourceV1::DfaStates,
                required: default_limit + 1,
                limit: default_limit,
            },
        );
        assert!(is_rebar_participation_dfa_state_limit(
            &exact_state_cap,
            default_limit
        ));

        let non_exact_state_cap = RebarSingleCaptureParticipationAotErrorV1::Participation(
            NativeParticipationAotErrorV1::Resource {
                resource: NativeParticipationAotResourceV1::DfaStates,
                required: default_limit + 2,
                limit: default_limit,
            },
        );
        assert!(!is_rebar_participation_dfa_state_limit(
            &non_exact_state_cap,
            default_limit
        ));
        let build_work = RebarSingleCaptureParticipationAotErrorV1::Participation(
            NativeParticipationAotErrorV1::Resource {
                resource: NativeParticipationAotResourceV1::BuildWork,
                required: 2,
                limit: 1,
            },
        );
        assert!(!is_rebar_participation_dfa_state_limit(
            &build_work,
            default_limit
        ));
        let allocation = RebarSingleCaptureParticipationAotErrorV1::Participation(
            NativeParticipationAotErrorV1::Allocation("injected allocation failure"),
        );
        assert!(!is_rebar_participation_dfa_state_limit(
            &allocation,
            default_limit
        ));

        let exhausted_states = RebarSingleCaptureParticipationAotErrorV1::Participation(
            NativeParticipationAotErrorV1::Resource {
                resource: NativeParticipationAotResourceV1::DfaStates,
                required: REBAR_PARTICIPATION_RETRY_MAX_DFA_STATES + 1,
                limit: REBAR_PARTICIPATION_RETRY_MAX_DFA_STATES,
            },
        );
        assert_eq!(
            participation_dfa_envelope_exhaustion(&exhausted_states),
            Some(ParticipationDfaEnvelopeExhaustion {
                resource: NativeParticipationAotResourceV1::DfaStates,
                required: REBAR_PARTICIPATION_RETRY_MAX_DFA_STATES + 1,
                limit: REBAR_PARTICIPATION_RETRY_MAX_DFA_STATES,
            })
        );
        let exhausted_work = RebarSingleCaptureParticipationAotErrorV1::Participation(
            NativeParticipationAotErrorV1::Resource {
                resource: NativeParticipationAotResourceV1::BuildWork,
                required: REBAR_PARTICIPATION_RETRY_MAX_BUILD_WORK + 1,
                limit: REBAR_PARTICIPATION_RETRY_MAX_BUILD_WORK,
            },
        );
        assert!(participation_dfa_envelope_exhaustion(&exhausted_work).is_some());
        assert!(participation_dfa_envelope_exhaustion(&exact_state_cap).is_none());
        assert!(participation_dfa_envelope_exhaustion(&allocation).is_none());
    }

    #[test]
    fn selector_capture_fallback_reuses_the_uniform_transaction_selector() {
        let target = target_from_parts(
            std::env::consts::ARCH,
            std::env::consts::OS,
            FeatureSet::EMPTY.bits(),
        )
        .expect("host target");
        let benchmark = Benchmark::parse(&fixture("grep-captures", b"(a)?b", b"no\nab"))
            .expect("selector fallback fixture");
        let UniformCaptureBridgeDisposition::Declined {
            source_ordinal,
            selector,
            ..
        } = try_compile_uniform_capture_bridge(&benchmark, target)
            .expect("uniform compiler publishes its semantic decline")
        else {
            panic!("fixture unexpectedly proved uniform participation");
        };
        assert_eq!(source_ordinal, 0);
        let exhaustion = ParticipationDfaEnvelopeExhaustion {
            resource: NativeParticipationAotResourceV1::DfaStates,
            required: REBAR_PARTICIPATION_RETRY_MAX_DFA_STATES + 1,
            limit: REBAR_PARTICIPATION_RETRY_MAX_DFA_STATES,
        };
        let bridge = compile_selector_capture_fallback_bridge(
            &benchmark,
            selector.expect("ordinary semantic decline retains its selector"),
            exhaustion,
        )
        .expect("authenticated selector-first bridge");
        assert_eq!(bridge.rows.artifacts.len(), 1);
        assert_eq!(bridge.rows.source_to_artifact, [0]);
        assert_eq!(bridge.direct_participation, exhaustion);
        authenticate_native_row(&bridge.rows.artifacts[0].compiled, 0)
            .expect("retained helper-free selector");

        let wrong_limit = ParticipationDfaEnvelopeExhaustion {
            resource: NativeParticipationAotResourceV1::DfaStates,
            required: REBAR_PARTICIPATION_RETRY_MAX_DFA_STATES,
            limit: REBAR_PARTICIPATION_RETRY_MAX_DFA_STATES - 1,
        };
        assert!(compile_selector_capture_fallback_bridge(
            &benchmark,
            bridge.rows.artifacts[0].clone(),
            wrong_limit,
        )
        .is_err());

        let count_benchmark = Benchmark::parse(&fixture("count-captures", b"(a)?b", b"ab"))
            .expect("count capture fixture");
        assert!(compile_selector_capture_fallback_bridge(
            &count_benchmark,
            bridge.rows.artifacts.into_iter().next().expect("one row"),
            exhaustion,
        )
        .is_err());
    }

    #[test]
    fn participation_capture_bridge_preserves_negative_and_cardinality_declines() {
        let target = target_from_parts(
            std::env::consts::ARCH,
            std::env::consts::OS,
            FeatureSet::EMPTY.bits(),
        )
        .expect("host target");
        let negative = Benchmark::parse(&fixture("count-captures", br"(?m)^((?:ab)+)$", b"ab"))
            .expect("negative fixture");
        assert!(matches!(
            try_compile_participation_capture_bridge(&negative, target),
            Ok(ParticipationCaptureBridgeDisposition::Declined { .. })
        ));

        let mut many = fixture("count-captures", b"(a)?b", b"ab");
        let offset = many
            .windows(b"haystack".len())
            .position(|window| window == b"haystack")
            .expect("haystack field");
        many.splice(offset..offset, b"pattern:3:(b)\n".iter().copied());
        let many = Benchmark::parse(&many).expect("multi-source fixture");
        assert!(matches!(
            try_compile_participation_capture_bridge(&many, target),
            Ok(ParticipationCaptureBridgeDisposition::Declined { .. })
        ));
    }

    #[test]
    fn native_row_bridge_pattern_cap_fails_before_compilation() {
        let mut too_many = fixture("count", b"a", b"a");
        let insertion = b"pattern:1:a\n".repeat(MAX_NATIVE_ROW_BRIDGE_PATTERNS);
        let offset = too_many
            .windows(b"haystack".len())
            .position(|window| window == b"haystack")
            .expect("haystack field");
        too_many.splice(offset..offset, insertion);
        let error = Benchmark::parse(&too_many).expect_err("pattern cap");
        assert!(
            error.contains("pattern count 4097 exceeds limit 4096"),
            "{error}"
        );
    }

    #[test]
    fn regex_redux_accepts_only_its_zero_pattern_fixed_suite() {
        let parsed = Benchmark::parse(&zero_pattern_fixture("regex-redux", b">x\nACGT\n"))
            .expect("parse fixed regex-redux model");
        assert_eq!(parsed.model, Model::RegexRedux);
        assert!(parsed.patterns.is_empty());
        assert_eq!(REGEX_REDUX_COMPONENTS, 15);
        assert_eq!(regex_redux_pattern(0), Some(REGEX_REDUX_FLATTEN_PATTERN));
        assert_eq!(
            regex_redux_pattern(
                REGEX_REDUX_COMPONENTS
                    .checked_sub(1)
                    .expect("fixed regex-redux suite is nonempty"),
            ),
            Some(REGEX_REDUX_SUBSTITUTIONS[4].0)
        );
        assert_eq!(regex_redux_pattern(REGEX_REDUX_COMPONENTS), None);
        assert!(Benchmark::parse(&fixture("regex-redux", b"a", b"a")).is_err());
    }

    #[test]
    fn models_bind_exact_prepare_abi_adapters_flags_and_capability_bit() {
        use fre_aot_regex_runtime::{
            PREPARE_CAPABILITY_ORDERED_NFA_V15, PREPARE_CONFIG_V2_VERSION,
            PREPARE_CONFIG_V3_VERSION, PREPARE_OPERATION_COUNT, PREPARE_OPERATION_GREP_COUNT,
            PREPARE_OPERATION_SPAN_SUM,
        };

        assert_eq!(PREPARE_CONFIG_V2_VERSION, 2);
        assert_eq!(PREPARE_CONFIG_V3_VERSION, 3);
        assert_eq!(
            fre_aot_regex::PREPARED_CAPABILITY_ORDERED_NFA_V15,
            PREPARE_CAPABILITY_ORDERED_NFA_V15,
        );

        for (model, adapter, operation_flags) in [
            (
                Model::Compile,
                "general-aot-optimizing-object-linked-count-verify-prepared-v2",
                PREPARE_OPERATION_COUNT,
            ),
            (
                Model::Count,
                "general-aot-identity-suffixed-exclusive-count-prepared-v2",
                PREPARE_OPERATION_COUNT,
            ),
            (
                Model::SpanSum,
                "general-aot-linked-complete-spans-prepared-v2",
                PREPARE_OPERATION_SPAN_SUM,
            ),
            (
                Model::CountCaptures,
                "general-aot-uniform-capture-native-row-count-adapter-loop-v1",
                0,
            ),
            (
                Model::GrepCount,
                "general-aot-linked-native-grep-count-reducer-prepared-v2",
                PREPARE_OPERATION_GREP_COUNT,
            ),
            (
                Model::GrepCaptures,
                "general-aot-uniform-capture-native-row-grep-adapter-loop-v1",
                0,
            ),
            (
                Model::RegexRedux,
                "general-aot-linked-fixed-regex-redux-span-entries-v1",
                0,
            ),
        ] {
            assert_eq!(model.adapter(), adapter);
            assert_eq!(model.prepare_operation_flags(), operation_flags);
        }
        assert_eq!(
            Model::Count.adapter_for_required_capabilities(PREPARE_CAPABILITY_ORDERED_NFA_V15,),
            "general-aot-identity-suffixed-exclusive-count-prepared-v3-required-ordered-nfa-v15",
        );
        assert_eq!(
            Model::SpanSum.adapter_for_required_capabilities(PREPARE_CAPABILITY_ORDERED_NFA_V15,),
            "general-aot-linked-complete-spans-prepared-v3-required-ordered-nfa-v15",
        );
        assert_eq!(
            Model::GrepCount
                .adapter_for_required_capabilities(PREPARE_CAPABILITY_ORDERED_NFA_V15,),
            "general-aot-linked-native-grep-count-reducer-prepared-v3-required-ordered-nfa-v15",
        );
        assert_eq!(
            Model::GrepCount.prepare_operation_flags_for_required_capabilities(
                PREPARE_CAPABILITY_ORDERED_NFA_V15,
            ),
            PREPARE_OPERATION_COUNT,
        );
    }

    #[test]
    fn whole_scalar_reducer_requires_an_exact_native_strategy() {
        for model in [Model::Count, Model::SpanSum] {
            assert!(is_native_whole_scalar_reducer(
                model,
                Some(PreparedAggregateStrategy::NativeFused),
            ));
            assert!(is_native_whole_scalar_reducer(
                model,
                Some(PreparedAggregateStrategy::NativeOrderedNfaFused),
            ));
            for strategy in [
                None,
                Some(PreparedAggregateStrategy::RuntimeHelper),
                Some(PreparedAggregateStrategy::NativeFusedWithRuntimeHelper),
                Some(PreparedAggregateStrategy::NativeOrderedNfaFusedWithRuntimeHelper),
            ] {
                assert!(!is_native_whole_scalar_reducer(model, strategy));
            }
        }
        for model in [
            Model::Compile,
            Model::CountCaptures,
            Model::GrepCount,
            Model::GrepCaptures,
            Model::RegexRedux,
        ] {
            assert!(!is_native_whole_scalar_reducer(
                model,
                Some(PreparedAggregateStrategy::NativeFused),
            ));
        }
    }

    #[test]
    fn compilation_requests_the_model_specific_export() {
        let benchmark =
            Benchmark::parse(&fixture("count", b"a+", b"baa")).expect("parse count fixture");
        let target = target_from_parts(
            std::env::consts::ARCH,
            std::env::consts::OS,
            FeatureSet::EMPTY.bits(),
        )
        .expect("host target");
        let compiled = compile_benchmark(&benchmark, target).expect("compile count fixture");
        assert_eq!(
            compiled.module().prepared_aggregate_exports(),
            PreparedAggregateExports::COUNT
        );
        assert!(compiled.module().prepared_count_symbol().is_some());
        assert!(compiled.module().required_runtime_program().is_some());

        let span_benchmark =
            Benchmark::parse(&fixture("count-spans", b"a+", b"baa")).expect("span fixture");
        let span_compiled =
            compile_benchmark(&span_benchmark, target).expect("compile span fixture");
        assert_eq!(
            span_compiled.module().prepared_aggregate_exports(),
            PreparedAggregateExports::SPAN_SUM
        );
        assert!(span_compiled.module().prepared_span_sum_symbol().is_some());
        assert!(!span_compiled.module().entry_symbol().is_empty());
        assert_eq!(
            span_compiled.module().prepared_span_fill_symbol().is_some(),
            span_compiled.module().prepared_bulk_strategy().is_some(),
            "count-spans must use either one authenticated prepared bulk route or its direct entry"
        );
    }
}
