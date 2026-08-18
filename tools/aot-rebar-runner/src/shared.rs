use std::time::Duration;

use fre_aot_regex::{
    Architecture, CompileMode, CompileRequest, CompiledRegex, FeatureSet, OperatingSystem,
    OutputContract, PreparedAggregateExports, Target, compile_with_prepared_aggregate_exports,
};
use fre_syntax::RustProfile;

pub const MAX_KLV_BYTES: u64 = 64 * 1_048_576;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Model {
    Compile,
    Count,
    SpanSum,
    GrepCount,
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
            "grep" => Ok(Self::GrepCount),
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
            Self::GrepCount => "grep",
        }
    }

    pub const fn adapter(self) -> &'static str {
        match self {
            Self::Compile => "general-aot-optimizing-object-linked-count-verify-prepared-v2",
            Self::Count => "general-aot-identity-suffixed-exclusive-count-prepared-v2",
            Self::SpanSum => "general-aot-linked-complete-spans-prepared-v2",
            Self::GrepCount => "general-aot-linked-per-line-is-match-v1",
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
            Self::GrepCount => "general-aot-linked-per-line-is-match-v1",
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
        }
    }

    pub const fn exports(self) -> PreparedAggregateExports {
        match self {
            Self::Compile | Self::Count => PreparedAggregateExports::COUNT,
            Self::SpanSum => PreparedAggregateExports::SPAN_SUM,
            Self::GrepCount => PreparedAggregateExports::GREP_COUNT,
        }
    }

    pub const fn output(self) -> OutputContract {
        match self {
            Self::GrepCount => OutputContract::Exists,
            Self::Compile | Self::Count | Self::SpanSum => OutputContract::Span,
        }
    }
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
        if benchmark.patterns.len() != 1 {
            return Err(format!(
                "current linked general-AOT operation requires exactly one pattern, got {}",
                benchmark.patterns.len()
            ));
        }
        if benchmark.max_iters == 0 {
            return Err("max-iters must be greater than zero".to_owned());
        }
        Ok(benchmark)
    }

    pub fn pattern(&self) -> &str {
        &self.patterns[0]
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
    fn rejects_unsupported_and_multi_pattern_models() {
        assert!(Benchmark::parse(&fixture("count-captures", b"(a)", b"a")).is_err());
        assert!(Benchmark::parse(&fixture("compile", b"a", b"a")).is_err());
        let mut multi = fixture("count", b"a", b"a");
        let insertion = b"pattern:1:b\n";
        let offset = multi
            .windows(b"haystack".len())
            .position(|window| window == b"haystack")
            .expect("haystack field");
        multi.splice(offset..offset, insertion.iter().copied());
        assert!(Benchmark::parse(&multi).is_err());
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
                Model::GrepCount,
                "general-aot-linked-per-line-is-match-v1",
                PREPARE_OPERATION_GREP_COUNT,
            ),
        ] {
            assert_eq!(model.adapter(), adapter);
            assert_eq!(model.prepare_operation_flags(), operation_flags);
        }
        assert_eq!(
            Model::Count.adapter_for_required_capabilities(
                PREPARE_CAPABILITY_ORDERED_NFA_V15,
            ),
            "general-aot-identity-suffixed-exclusive-count-prepared-v3-required-ordered-nfa-v15",
        );
        assert_eq!(
            Model::SpanSum.adapter_for_required_capabilities(
                PREPARE_CAPABILITY_ORDERED_NFA_V15,
            ),
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
