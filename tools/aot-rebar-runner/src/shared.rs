use std::{collections::BTreeMap, time::Duration};

use fre_aot_regex::{
    Architecture, CompileMode, CompileRequest, CompiledRegex, FeatureSet, OperatingSystem,
    OutputContract, PreparedAggregateExports, RebarSingleCaptureAotArtifactV1,
    RebarSingleCaptureAotRequestV1, SymbolBinding, SymbolKind, Target,
    UniformCaptureCompileDisposition, UniformCaptureCompileReceipt, UniformCaptureCompileRequest,
    compile, compile_rebar_single_capture_aot_v1, compile_uniform_capture_selector,
    compile_with_prepared_aggregate_exports,
};
use fre_syntax::{CanonicalPattern, CompatibilityProfile, ParseRequest, RustProfile, parse};

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
            Self::GrepCount => "general-aot-linked-per-line-is-match-v1",
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
            Self::GrepCount => "general-aot-linked-per-line-is-match-v1",
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
                    Model::Count | Model::SpanSum | Model::CountCaptures | Model::GrepCaptures
                )
            {
                return Err(format!(
                    "current linked general-AOT multi-pattern bridge supports only count and count-spans, got model {:?} with {} patterns",
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
    let request = CompileRequest::new(benchmark.pattern(), target)
        .profile(profile)
        .output(benchmark.model.output())
        .mode(CompileMode::Optimizing);
    compile_with_prepared_aggregate_exports(request, benchmark.model.exports())
        .map_err(|error| format!("general AOT compilation failed: {error}"))
}

/// One distinct helper-free native `Span` object in source-priority order.
#[derive(Clone, Debug)]
pub struct NativeRowArtifact {
    pub compiled: CompiledRegex,
    pub first_source_ordinal: usize,
}

/// Build-time result for the independent native-row bridge.
#[derive(Clone, Debug)]
pub struct NativeRowBridge {
    pub artifacts: Vec<NativeRowArtifact>,
    pub source_to_artifact: Vec<usize>,
    pub total_object_bytes: usize,
}

/// One all-or-nothing uniform-participation proof per source row, paired with
/// the independently authenticated ordinary native selector table.
#[derive(Clone, Debug)]
pub struct UniformCaptureBridge {
    pub rows: NativeRowBridge,
    pub source_receipts: Vec<UniformCaptureCompileReceipt>,
}

/// One exact-cardinality, helper-free native capture iterator.
#[derive(Debug)]
pub struct StrictCaptureBridge {
    pub artifact: RebarSingleCaptureAotArtifactV1,
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

/// Build-time result that keeps a semantic theorem decline distinct from a
/// terminal parse, lowering, allocation, authentication, or object failure.
///
/// Capture adapters may try another independently authenticated native route
/// only for `Declined`. An `Err` remains terminal and must never be converted
/// into a fallback.
#[derive(Debug)]
pub enum UniformCaptureBridgeDisposition {
    Proven(UniformCaptureBridge),
    Declined {
        source_ordinal: usize,
        reason: String,
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
        UniformCaptureBridgeDisposition::Declined {
            source_ordinal,
            reason,
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
        let compiled = compile_uniform_capture_selector(
            &parsed,
            UniformCaptureCompileRequest::new(pattern.len(), target).profile(profile.clone()),
        )
        .map_err(|error| {
            format!(
                "uniform-capture selector compilation failed at source ordinal {source_ordinal}: {error}"
            )
        })?;
        compiled.authenticate().map_err(|error| {
            format!(
                "uniform-capture selector authentication failed at source ordinal {source_ordinal}: {error}"
            )
        })?;
        let (selector, disposition) = compiled.into_parts();
        let proof = match disposition {
            UniformCaptureCompileDisposition::Proven(receipt) => receipt,
            UniformCaptureCompileDisposition::Declined(reason) => {
                return Ok(UniformCaptureBridgeDisposition::Declined {
                    source_ordinal,
                    reason: format!("{reason:?}"),
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
/// prepared/runtime route rejects the entire bridge; the timed Rust selector
/// can therefore reach only generated native ordinary entries.
pub fn compile_native_row_bridge(
    benchmark: &Benchmark,
    target: Target,
) -> Result<NativeRowBridge, String> {
    if !benchmark.uses_native_row_bridge()
        || !matches!(benchmark.model, Model::Count | Model::SpanSum)
    {
        return Err(
            "native-row bridge compilation requires a multi-pattern count or count-spans job"
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

        let request = CompileRequest::new(pattern, target)
            .profile(profile.clone())
            .output(OutputContract::Span)
            .mode(CompileMode::Optimizing);
        let compiled = compile(request).map_err(|error| {
            format!(
                "general AOT native-row compilation failed at source ordinal {source_ordinal}: {error}"
            )
        })?;
        authenticate_native_row(&compiled, source_ordinal)?;

        let entry = compiled.module().entry_symbol().to_owned();
        let artifact_index = if let Some(&existing) = link_artifacts.get(&entry) {
            let prior = &artifacts[existing].compiled;
            if prior.object() != compiled.object()
                || prior.receipt().object_sha256 != compiled.receipt().object_sha256
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
            "native-row source ordinal {source_ordinal} is not a helper-free ordinary Span entry: engine={:?} runtime_helper={} runtime_symbols={runtime_symbols:?} unresolved_symbols={unresolved_symbols:?} prepared_entry={} runtime_program={} entry_defined={} entry_size={}",
            receipt.engine,
            receipt.runtime_helper_required,
            module.prepared_entry_symbol().is_some(),
            module.required_runtime_program().is_some(),
            entry.section.is_some(),
            entry.size,
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

        let mut multi_grep = fixture("grep", b"a", b"a");
        let offset = multi_grep
            .windows(b"haystack".len())
            .position(|window| window == b"haystack")
            .expect("haystack field");
        multi_grep.splice(offset..offset, insertion.iter().copied());
        assert!(Benchmark::parse(&multi_grep).is_err());
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
        assert_eq!(bridge.source_to_artifact, [0, 0, 1]);
        assert_eq!(bridge.artifacts.len(), 2);
        assert_eq!(bridge.artifacts[0].first_source_ordinal, 0);
        assert_eq!(bridge.artifacts[1].first_source_ordinal, 2);
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
            assert!(
                artifact
                    .compiled
                    .module()
                    .required_runtime_symbols()
                    .next()
                    .is_none()
            );
            assert!(artifact.compiled.module().prepared_entry_symbol().is_none());
        }
    }

    #[test]
    fn native_row_bridge_rejects_one_helper_backed_row_transactionally() {
        let mut multi = fixture("count", b"a+", b"foo");
        let insertion = b"pattern:7:\\bfoo\\b\n";
        let offset = multi
            .windows(b"haystack".len())
            .position(|window| window == b"haystack")
            .expect("haystack field");
        multi.splice(offset..offset, insertion.iter().copied());
        let mut benchmark = Benchmark::parse(&multi).expect("helper trap fixture");
        benchmark.unicode = true;
        let target = target_from_parts(
            std::env::consts::ARCH,
            std::env::consts::OS,
            FeatureSet::EMPTY.bits(),
        )
        .expect("host target");
        let error = compile_native_row_bridge(&benchmark, target)
            .expect_err("one semantic helper must reject the complete bridge");
        assert!(error.contains("source ordinal 1"), "{error}");
        assert!(
            error.contains("not a helper-free ordinary Span entry"),
            "{error}"
        );
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
        assert!(
            strict
                .artifact
                .module()
                .required_runtime_symbols()
                .next()
                .is_none()
        );
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
                "general-aot-linked-per-line-is-match-v1",
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
