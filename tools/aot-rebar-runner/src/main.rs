//! Statically linked, job-specialized adapter for public Rebar operation models.

#![warn(unsafe_code)]

use std::{
    env,
    error::Error,
    hint::black_box,
    io::{self, Read, Write},
    time::{Duration, Instant},
};

use bstr::ByteSlice;
use fre_aot_rebar_runner::shared;
use fre_aot_regex::{
    CompiledRegex, DEFAULT_FROZEN_ORDERED_NFA_V1_MAX_HANDLE_BYTES,
    FROZEN_ORDERED_NFA_V1_MAX_SCRATCH_BYTES, FROZEN_ORDERED_NFA_V1_MAX_SETUP_WORK,
};
use fre_aot_regex_runtime::{
    DEFAULT_GREP_COUNT_WORKSPACE_BYTES, DEFAULT_START_FILTER_SETUP_WORK,
    FreAotRegexExclusiveHandleV1, FreAotRegexIterStateV1, FreAotRegexPrepareConfigV2,
    FreAotRegexPrepareConfigV3, FreAotRegexResultV1, PREPARE_CAPABILITY_KNOWN_FLAGS,
    PREPARE_CAPABILITY_ORDERED_NFA_V15,
    PREPARE_CONFIG_V2_VERSION, PREPARE_CONFIG_V3_VERSION, STATUS_MATCH, STATUS_NO_MATCH,
    STATUS_SUCCESS, fre_aot_regex_runtime_destroy_exclusive_v1,
    fre_aot_regex_runtime_prepare_exclusive_v2, fre_aot_regex_runtime_prepare_exclusive_v3,
};
use regex_automata::meta::Regex;

#[allow(
    unsafe_code,
    unreachable_pub,
    reason = "generated declarations are the exact statically linked AOT C ABI boundary"
)]
mod linked {
    include!(concat!(env!("OUT_DIR"), "/linked_artifact.rs"));
}

type DynError = Box<dyn Error + Send + Sync + 'static>;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Arguments {
    quiet: bool,
    version: bool,
    provenance: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Sample {
    duration: Duration,
    value: u64,
}

#[derive(Debug)]
struct ExclusiveSession {
    handle: FreAotRegexExclusiveHandleV1,
}

impl ExclusiveSession {
    #[allow(
        unsafe_code,
        reason = "preparation is the audited exclusive-handle C ABI boundary"
    )]
    fn prepare(model: shared::Model) -> Result<Self, String> {
        let mut handle = FreAotRegexExclusiveHandleV1::INVALID;
        let operation_flags = model.prepare_operation_flags();
        if operation_flags != linked::PREPARE_OPERATION_FLAGS {
            return Err("runtime model preparation differs from linked artifact".to_owned());
        }
        if linked::REQUIRED_PREPARE_CAPABILITIES & !PREPARE_CAPABILITY_KNOWN_FLAGS != 0 {
            return Err("linked artifact requires unknown prepare capabilities".to_owned());
        }
        // SAFETY: the linked immutable program has the exact generated extent;
        // each selected config is initialized and readable, while `handle` is
        // aligned, writable, and disjoint from both readable inputs.
        let status = if linked::REQUIRED_PREPARE_CAPABILITIES == 0 {
            if linked::PREPARE_CONFIG_VERSION != PREPARE_CONFIG_V2_VERSION {
                return Err("incumbent linked artifact does not select prepare V2".to_owned());
            }
            let config = FreAotRegexPrepareConfigV2::new(operation_flags);
            unsafe {
                fre_aot_regex_runtime_prepare_exclusive_v2(
                    linked::program_ptr(),
                    linked::PROGRAM_LEN,
                    &config,
                    &raw mut handle,
                )
            }
        } else {
            if linked::PREPARE_CONFIG_VERSION != PREPARE_CONFIG_V3_VERSION {
                return Err("capability-bearing linked artifact does not select prepare V3".to_owned());
            }
            let mut config = FreAotRegexPrepareConfigV3::new(operation_flags);
            config.required_capabilities = linked::REQUIRED_PREPARE_CAPABILITIES;
            unsafe {
                fre_aot_regex_runtime_prepare_exclusive_v3(
                    linked::program_ptr(),
                    linked::PROGRAM_LEN,
                    &config,
                    &raw mut handle,
                )
            }
        };
        if status != STATUS_SUCCESS || handle.is_invalid() {
            return Err(format!(
                "prepare exclusive AOT handle returned status {status}"
            ));
        }
        Ok(Self { handle })
    }

    #[allow(
        unsafe_code,
        reason = "the exact generated reducer call is the audited timed C ABI boundary"
    )]
    fn reduce(&mut self, haystack: &[u8]) -> Result<u64, String> {
        let mut value = u64::MAX;
        // SAFETY: this object uniquely owns the live exclusive handle; the
        // haystack and aligned scalar output remain disjoint and live for the
        // complete call.
        let status = unsafe {
            linked::reduce(
                self.handle,
                haystack.as_ptr(),
                haystack.len(),
                &raw mut value,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(format!(
                "identity-suffixed reducer {:?} returned status {status}",
                linked::REDUCER_SYMBOL
            ));
        }
        Ok(value)
    }

    #[allow(
        unsafe_code,
        reason = "the generated Span-fill declaration is the exact statically linked AOT C ABI boundary"
    )]
    fn strict_span_sum_with_fill(&mut self, haystack: &[u8]) -> Result<u64, String> {
        const SPAN_BUFFER_CAPACITY: usize = 64;

        let mut state = FreAotRegexIterStateV1::default();
        let mut spans = [FreAotRegexResultV1::default(); SPAN_BUFFER_CAPACITY];
        let mut accumulator = StrictSpanAccumulator::new(haystack.len());
        loop {
            let mut written = usize::MAX;
            // SAFETY: this session uniquely owns the live handle. The whole
            // haystack and the naturally aligned state/result/count outputs
            // are live, writable where required, and pairwise disjoint.
            let status = unsafe {
                linked::fill_spans(
                    self.handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    &raw mut state,
                    spans.as_mut_ptr(),
                    spans.len(),
                    &raw mut written,
                )
            };
            if written > spans.len() {
                return Err(format!(
                    "linked Span-fill published {written} records into capacity {}",
                    spans.len()
                ));
            }
            for &matched in &spans[..written] {
                accumulator.push(matched)?;
            }
            match status {
                STATUS_NO_MATCH => return Ok(accumulator.sum()),
                STATUS_MATCH if written == spans.len() => {}
                STATUS_MATCH => {
                    return Err(format!(
                        "linked Span-fill requested a refill after only {written} of {} records",
                        spans.len()
                    ));
                }
                other => {
                    return Err(format!(
                        "identity-suffixed Span-fill {:?} returned status {other}",
                        linked::SPAN_FILL_SYMBOL
                    ));
                }
            }
        }
    }

    fn strict_span_sum_with_direct_entry(&mut self, haystack: &[u8]) -> Result<u64, String> {
        strict_span_sum_with_direct_entry(haystack)
    }

    fn strict_grep_with_direct_entry(&mut self, haystack: &[u8]) -> Result<u64, String> {
        strict_grep_with_direct_entry(haystack)
    }

    #[allow(
        unsafe_code,
        reason = "explicit destruction is the audited exclusive-handle C ABI boundary"
    )]
    fn destroy(mut self) -> Result<(), String> {
        let handle = std::mem::replace(&mut self.handle, FreAotRegexExclusiveHandleV1::INVALID);
        // SAFETY: `handle` is the one live exclusively owned value and no call
        // overlaps this explicit terminal destruction.
        let status = unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) };
        if status != STATUS_SUCCESS {
            return Err(format!(
                "destroy exclusive AOT handle returned status {status}"
            ));
        }
        Ok(())
    }
}

impl Drop for ExclusiveSession {
    #[allow(
        unsafe_code,
        reason = "Drop is the terminal fallback for the uniquely owned exclusive handle"
    )]
    fn drop(&mut self) {
        if self.handle.is_invalid() {
            return;
        }
        let handle = std::mem::replace(&mut self.handle, FreAotRegexExclusiveHandleV1::INVALID);
        // SAFETY: Drop owns the only live handle and is the final fallback
        // when explicit checked destruction did not already consume it.
        let _ = unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) };
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StrictSpanAccumulator {
    haystack_len: usize,
    last: Option<FreAotRegexResultV1>,
    sum: u64,
}

impl StrictSpanAccumulator {
    const fn new(haystack_len: usize) -> Self {
        Self {
            haystack_len,
            last: None,
            sum: 0,
        }
    }

    fn push(&mut self, matched: FreAotRegexResultV1) -> Result<(), String> {
        validate_span(matched, self.haystack_len)?;
        if let Some(previous) = self.last {
            if matched.start < previous.end {
                return Err(format!(
                    "linked AOT spans overlap or move backward: previous={previous:?}, current={matched:?}"
                ));
            }
            if matched.start == matched.end && matched.end == previous.end {
                return Err(format!(
                    "linked AOT emitted the adjacent empty span suppressed by Rebar iteration: {matched:?}"
                ));
            }
            if previous.start == previous.end && matched.start <= previous.end {
                return Err(format!(
                    "linked AOT did not make byte progress after empty span {previous:?}: current={matched:?}"
                ));
            }
        }
        let width = matched
            .end
            .checked_sub(matched.start)
            .ok_or_else(|| "linked AOT span width underflowed".to_owned())?;
        let width =
            u64::try_from(width).map_err(|_| "linked AOT span width did not fit u64".to_owned())?;
        self.sum = self
            .sum
            .checked_add(width)
            .ok_or_else(|| "linked AOT complete-span sum overflowed u64".to_owned())?;
        self.last = Some(matched);
        Ok(())
    }

    const fn sum(self) -> u64 {
        self.sum
    }
}

fn validate_span(matched: FreAotRegexResultV1, haystack_len: usize) -> Result<(), String> {
    if matched.start <= matched.end && matched.end <= haystack_len {
        Ok(())
    } else {
        Err(format!(
            "linked AOT returned invalid span {matched:?} for haystack length {haystack_len}"
        ))
    }
}

#[allow(
    unsafe_code,
    reason = "the generated search declaration is the exact statically linked AOT C ABI boundary"
)]
fn strict_span_sum_with_direct_entry(haystack: &[u8]) -> Result<u64, String> {
    strict_span_sum_with_search(haystack.len(), |window_start| {
        let mut result = FreAotRegexResultV1::default();
        // SAFETY: the complete haystack and aligned result are live and
        // disjoint; the checked iterator start is always within its length.
        let status = unsafe {
            linked::search(
                haystack.as_ptr(),
                haystack.len(),
                window_start,
                haystack.len(),
                &raw mut result,
            )
        };
        match status {
            STATUS_NO_MATCH => Ok(None),
            STATUS_MATCH => Ok(Some(result)),
            other => Err(format!(
                "identity-suffixed direct entry {:?} returned status {other}",
                linked::ENTRY_SYMBOL
            )),
        }
    })
}

fn strict_span_sum_with_search(
    haystack_len: usize,
    mut search: impl FnMut(usize) -> Result<Option<FreAotRegexResultV1>, String>,
) -> Result<u64, String> {
    let mut accumulator = StrictSpanAccumulator::new(haystack_len);
    let mut next_start = 0_usize;
    let mut last_match_end = None;
    let mut pending_empty_progress = false;
    loop {
        if pending_empty_progress {
            pending_empty_progress = false;
            if next_start == haystack_len {
                return Ok(accumulator.sum());
            }
            next_start = next_start
                .checked_add(1)
                .ok_or_else(|| "linked AOT empty-match progress overflowed".to_owned())?;
        }

        let Some(matched) = search(next_start)? else {
            return Ok(accumulator.sum());
        };
        validate_span(matched, haystack_len)?;
        if matched.start < next_start {
            return Err(format!(
                "linked AOT returned span {matched:?} before requested start {next_start}"
            ));
        }

        if matched.start == matched.end && last_match_end == Some(matched.end) {
            if next_start == haystack_len {
                return Ok(accumulator.sum());
            }
            next_start = next_start
                .checked_add(1)
                .ok_or_else(|| "linked AOT adjacent-empty progress overflowed".to_owned())?;
            continue;
        }

        accumulator.push(matched)?;
        next_start = matched.end;
        last_match_end = Some(matched.end);
        pending_empty_progress = matched.start == matched.end;
    }
}

#[allow(
    unsafe_code,
    reason = "the generated search declaration is the exact statically linked AOT C ABI boundary"
)]
fn strict_grep_with_direct_entry(haystack: &[u8]) -> Result<u64, String> {
    strict_grep_with_search(haystack, |line| {
        let mut result = FreAotRegexResultV1::default();
        // SAFETY: `line` is one complete live Rebar line-domain haystack and
        // the naturally aligned result is writable and disjoint. The public
        // is-match operation always searches its complete 0..len window.
        let status =
            unsafe { linked::search(line.as_ptr(), line.len(), 0, line.len(), &raw mut result) };
        match status {
            STATUS_NO_MATCH => Ok(false),
            STATUS_MATCH => Ok(true),
            other => Err(format!(
                "identity-suffixed direct entry {:?} returned status {other} for one grep line",
                linked::ENTRY_SYMBOL
            )),
        }
    })
}

fn strict_grep_with_search(
    haystack: &[u8],
    mut is_match: impl FnMut(&[u8]) -> Result<bool, String>,
) -> Result<u64, String> {
    let mut count = 0_u64;
    for line in haystack.lines() {
        if is_match(line)? {
            count = count
                .checked_add(1)
                .ok_or_else(|| "linked AOT Rebar grep count overflowed".to_owned())?;
        }
    }
    Ok(count)
}

fn main() -> Result<(), DynError> {
    let arguments = parse_arguments()?;
    if arguments.version {
        if linked::CONFIGURED {
            println!("{}+{}", env!("CARGO_PKG_VERSION"), linked::ADAPTER);
        } else {
            println!("{}+general-aot-unconfigured", env!("CARGO_PKG_VERSION"));
        }
        return Ok(());
    }
    if arguments.provenance {
        print_provenance();
        return Ok(());
    }
    if !linked::CONFIGURED {
        return Err(format!(
            "runner is unconfigured; rebuild with FRE_AOT_REBAR_KLV=/absolute/public/job.klv"
        )
        .into());
    }

    let mut input = Vec::new();
    io::stdin()
        .take(shared::MAX_KLV_BYTES.saturating_add(1))
        .read_to_end(&mut input)?;
    if u64::try_from(input.len()).map_or(true, |length| length > shared::MAX_KLV_BYTES) {
        return Err(format!("KLV input exceeds {} bytes", shared::MAX_KLV_BYTES).into());
    }
    let benchmark = shared::Benchmark::parse(&input)?;
    authenticate_benchmark(&benchmark)?;
    authenticate_linked_route(&benchmark)?;
    let target =
        shared::target_from_parts(linked::TARGET_ARCH, linked::TARGET_OS, linked::FEATURE_BITS)?;
    let mut session = ExclusiveSession::prepare(benchmark.model)?;
    let samples = if benchmark.model == shared::Model::Compile {
        run_compile(&benchmark, target, &mut session)?
    } else {
        run_operation(&benchmark, &mut session)?
    };
    session.destroy()?;
    let expected = rust_oracle(&benchmark)?;
    for sample in &samples {
        require_expected(sample.value, expected)?;
    }

    if !arguments.quiet {
        let mut stdout = io::stdout().lock();
        for sample in samples {
            writeln!(stdout, "{},{}", sample.duration.as_nanos(), sample.value)?;
        }
    }
    Ok(())
}

fn parse_arguments() -> Result<Arguments, DynError> {
    let mut parsed = Arguments::default();
    for argument in env::args().skip(1) {
        match argument.as_str() {
            "--quiet" | "-q" => parsed.quiet = true,
            "--version" => parsed.version = true,
            "--provenance" => parsed.provenance = true,
            "--help" | "-h" => {
                return Err(
                    "usage: fre-aot-rebar-runner [--quiet | --version | --provenance]".into(),
                );
            }
            other => return Err(format!("unrecognized argument {other:?}").into()),
        }
    }
    if parsed.version && parsed.provenance {
        return Err("--version and --provenance are mutually exclusive".into());
    }
    Ok(parsed)
}

fn print_provenance() {
    let (max_handle_bytes, max_ordered_nfa_scratch_bytes, max_ordered_nfa_setup_work) =
        if linked::REQUIRED_PREPARE_CAPABILITIES == 0 {
            (0, 0, 0)
        } else {
            (
                u64::try_from(DEFAULT_FROZEN_ORDERED_NFA_V1_MAX_HANDLE_BYTES)
                    .expect("default Ordered-NFA handle cap fits u64"),
                u64::try_from(FROZEN_ORDERED_NFA_V1_MAX_SCRATCH_BYTES)
                    .expect("default Ordered-NFA scratch cap fits u64"),
                FROZEN_ORDERED_NFA_V1_MAX_SETUP_WORK,
            )
        };
    println!(
        "schema=fre.aot.rebar-runner.v2 disposition=executed configured={} adapter={} model={} benchmark={:?} source_commit={} source_tree={} target={}-{} feature_bits={:016x} compiler_version={} optimizer_version={} engine={} aggregate_strategy={} prepared_bulk_strategy={} span_iteration_strategy={} grep_iteration_strategy={} prepare_config_version={} prepare_operation_flags={:016x} required_prepare_capabilities={:016x} prepare_scope=runtime-handle-state object_descriptor_setup=authenticated-v3-when-required max_start_filter_setup_work={} max_grep_count_workspace_bytes={} max_handle_bytes={} max_ordered_nfa_scratch_bytes={} max_ordered_nfa_setup_work={} program_sha256={} object_sha256={} program_symbol={} entry_symbol={} reducer_symbol={} span_fill_symbol={} required_runtime_symbols={} boundary=runtime-klv-warmup-schedule required_comparators=rust-regex-1.12.4,fre-current-runtime",
        linked::CONFIGURED,
        linked::ADAPTER,
        linked::EXPECTED_MODEL,
        linked::EXPECTED_NAME,
        linked::SOURCE_COMMIT,
        linked::SOURCE_TREE,
        linked::TARGET_ARCH,
        linked::TARGET_OS,
        linked::FEATURE_BITS,
        linked::COMPILER_VERSION,
        linked::OPTIMIZER_VERSION,
        linked::ENGINE,
        linked::AGGREGATE_STRATEGY,
        linked::PREPARED_BULK_STRATEGY,
        linked::SPAN_ITERATION_STRATEGY,
        linked::GREP_ITERATION_STRATEGY,
        linked::PREPARE_CONFIG_VERSION,
        linked::PREPARE_OPERATION_FLAGS,
        linked::REQUIRED_PREPARE_CAPABILITIES,
        DEFAULT_START_FILTER_SETUP_WORK,
        DEFAULT_GREP_COUNT_WORKSPACE_BYTES,
        max_handle_bytes,
        max_ordered_nfa_scratch_bytes,
        max_ordered_nfa_setup_work,
        hex(&linked::PROGRAM_SHA256),
        hex(&linked::OBJECT_SHA256),
        linked::PROGRAM_SYMBOL,
        linked::ENTRY_SYMBOL,
        linked::REDUCER_SYMBOL,
        linked::SPAN_FILL_SYMBOL,
        linked::REQUIRED_RUNTIME_SYMBOLS,
    );
}

fn authenticate_benchmark(benchmark: &shared::Benchmark) -> Result<(), String> {
    let expected_model = shared::Model::parse(linked::EXPECTED_MODEL)?;
    let expected = shared::Benchmark {
        name: linked::EXPECTED_NAME.to_owned(),
        model: expected_model,
        patterns: vec![linked::EXPECTED_PATTERN.to_owned()],
        case_insensitive: linked::EXPECTED_CASE_INSENSITIVE,
        unicode: linked::EXPECTED_UNICODE,
        haystack: Vec::new(),
        max_iters: 1,
        max_warmup_iters: 0,
        max_time: Duration::ZERO,
        max_warmup_time: Duration::ZERO,
    };
    if benchmark.same_compilation_identity(&expected) {
        Ok(())
    } else {
        Err("runtime KLV compilation identity differs from linked AOT artifact".to_owned())
    }
}

fn authenticate_linked_route(benchmark: &shared::Benchmark) -> Result<(), String> {
    let has_named_span_fill = !linked::SPAN_FILL_SYMBOL.is_empty();
    if linked::HAS_SPAN_FILL != has_named_span_fill {
        return Err("linked Span-fill availability disagrees with its bound symbol".to_owned());
    }
    if benchmark.model == shared::Model::SpanSum {
        let bulk_route = linked::PREPARED_BULK_STRATEGY != "None";
        if linked::HAS_SPAN_FILL != bulk_route {
            return Err(format!(
                "linked count-spans route disagrees with prepared bulk strategy {:?}",
                linked::PREPARED_BULK_STRATEGY
            ));
        }
        if linked::AGGREGATE_STRATEGY == "None" {
            return Err("count-spans artifact has no aggregate strategy".to_owned());
        }
    } else if linked::SPAN_ITERATION_STRATEGY != "not-applicable" {
        return Err("non-count-spans artifact advertises a span iterator route".to_owned());
    }
    if benchmark.model == shared::Model::Count && linked::AGGREGATE_STRATEGY == "None" {
        return Err("count artifact has no aggregate strategy".to_owned());
    }
    if benchmark.model == shared::Model::GrepCount {
        if linked::GREP_ITERATION_STRATEGY != "linked-per-line-direct-entry"
            || linked::AGGREGATE_STRATEGY != linked::GREP_ITERATION_STRATEGY
        {
            return Err("grep artifact is not bound to the per-line direct-entry route".to_owned());
        }
    } else if linked::GREP_ITERATION_STRATEGY != "not-applicable" {
        return Err("non-grep artifact advertises a grep iterator route".to_owned());
    }
    let ordered_nfa_route =
        linked::PREPARED_BULK_STRATEGY == "Some(NativeOrderedNfaLoop)";
    let ordered_nfa_required = linked::REQUIRED_PREPARE_CAPABILITIES
        == PREPARE_CAPABILITY_ORDERED_NFA_V15;
    if linked::REQUIRED_PREPARE_CAPABILITIES & !PREPARE_CAPABILITY_KNOWN_FLAGS != 0
        || ordered_nfa_route != ordered_nfa_required
    {
        return Err(
            "linked Ordered-TNFA route disagrees with its required prepare capability".to_owned(),
        );
    }
    let expected_prepare_version = if ordered_nfa_required {
        PREPARE_CONFIG_V3_VERSION
    } else {
        PREPARE_CONFIG_V2_VERSION
    };
    if linked::PREPARE_CONFIG_VERSION != expected_prepare_version {
        return Err("linked prepare version disagrees with its capability receipt".to_owned());
    }
    if ordered_nfa_required
        && !matches!(benchmark.model, shared::Model::Count | shared::Model::SpanSum)
    {
        return Err("Ordered-TNFA capability is bound to an unsupported operation".to_owned());
    }
    if ordered_nfa_required
        && !matches!(
            linked::AGGREGATE_STRATEGY,
            "Some(NativeOrderedNfaFused)"
                | "Some(NativeOrderedNfaFusedWithRuntimeHelper)"
        )
    {
        return Err("Ordered-TNFA capability has no native aggregate strategy".to_owned());
    }
    Ok(())
}

fn run_operation(
    benchmark: &shared::Benchmark,
    session: &mut ExclusiveSession,
) -> Result<Vec<Sample>, String> {
    match benchmark.model {
        shared::Model::SpanSum if linked::HAS_SPAN_FILL => run_operation_route(
            benchmark,
            session,
            ExclusiveSession::strict_span_sum_with_fill,
        ),
        shared::Model::SpanSum => run_operation_route(
            benchmark,
            session,
            ExclusiveSession::strict_span_sum_with_direct_entry,
        ),
        shared::Model::GrepCount => run_operation_route(
            benchmark,
            session,
            ExclusiveSession::strict_grep_with_direct_entry,
        ),
        shared::Model::Count => run_operation_route(benchmark, session, ExclusiveSession::reduce),
        shared::Model::Compile => Err(
            "general AOT object emission is not a search-ready Rebar compile operation".to_owned(),
        ),
    }
}

fn run_operation_route(
    benchmark: &shared::Benchmark,
    session: &mut ExclusiveSession,
    mut operation: impl FnMut(&mut ExclusiveSession, &[u8]) -> Result<u64, String>,
) -> Result<Vec<Sample>, String> {
    let warmup_start = Instant::now();
    for _ in 0..benchmark.max_warmup_iters {
        let actual = operation(session, black_box(&benchmark.haystack))?;
        black_box(actual);
        if warmup_start.elapsed() >= benchmark.max_warmup_time {
            break;
        }
    }

    let capacity = usize::try_from(benchmark.max_iters)
        .unwrap_or(usize::MAX)
        .min(1_048_576);
    let mut samples = Vec::with_capacity(capacity);
    let run_start = Instant::now();
    for _ in 0..benchmark.max_iters {
        let sample_start = Instant::now();
        let actual = operation(session, black_box(&benchmark.haystack))?;
        let duration = sample_start.elapsed();
        samples.push(Sample {
            duration,
            value: actual,
        });
        if run_start.elapsed() >= benchmark.max_time {
            break;
        }
    }
    Ok(samples)
}

fn run_compile(
    benchmark: &shared::Benchmark,
    target: fre_aot_regex::Target,
    session: &mut ExclusiveSession,
) -> Result<Vec<Sample>, String> {
    let warmup_start = Instant::now();
    for _ in 0..benchmark.max_warmup_iters {
        let artifact = shared::compile_benchmark(benchmark, target)?;
        validate_compiled_artifact(&artifact)?;
        black_box(session.reduce(&benchmark.haystack)?);
        if warmup_start.elapsed() >= benchmark.max_warmup_time {
            break;
        }
    }

    let capacity = usize::try_from(benchmark.max_iters)
        .unwrap_or(usize::MAX)
        .min(1_048_576);
    let mut samples = Vec::with_capacity(capacity);
    let run_start = Instant::now();
    for _ in 0..benchmark.max_iters {
        let sample_start = Instant::now();
        let artifact = shared::compile_benchmark(black_box(benchmark), target)?;
        let duration = sample_start.elapsed();
        validate_compiled_artifact(&artifact)?;
        let actual = session.reduce(&benchmark.haystack)?;
        samples.push(Sample {
            duration,
            value: actual,
        });
        if run_start.elapsed() >= benchmark.max_time {
            break;
        }
    }
    Ok(samples)
}

fn validate_compiled_artifact(artifact: &CompiledRegex) -> Result<(), String> {
    if artifact.object() != linked::OBJECT_BYTES
        || artifact.receipt().program_sha256 != linked::PROGRAM_SHA256
        || artifact.receipt().object_sha256 != linked::OBJECT_SHA256
        || artifact.receipt().required_prepare_capabilities
            != linked::REQUIRED_PREPARE_CAPABILITIES
        || format!("{:?}", artifact.module().prepared_bulk_strategy())
            != linked::PREPARED_BULK_STRATEGY
        || (linked::EXPECTED_MODEL != "grep"
            && format!("{:?}", artifact.receipt().prepared_aggregate_strategy)
                != linked::AGGREGATE_STRATEGY)
    {
        return Err(
            "timed compilation differs from the exact statically linked verification artifact"
                .to_owned(),
        );
    }
    Ok(())
}

fn rust_oracle(benchmark: &shared::Benchmark) -> Result<u64, String> {
    let config = Regex::config()
        .utf8_empty(false)
        .nfa_size_limit(Some(104_857_600));
    let syntax = regex_automata::util::syntax::Config::new()
        .utf8(false)
        .unicode(benchmark.unicode)
        .case_insensitive(benchmark.case_insensitive);
    let regex = Regex::builder()
        .configure(config)
        .syntax(syntax)
        .build_many(&benchmark.patterns)
        .map_err(|error| format!("Rust Rebar oracle compilation failed: {error}"))?;
    match benchmark.model {
        shared::Model::Compile | shared::Model::Count => {
            u64::try_from(regex.find_iter(&benchmark.haystack).count())
                .map_err(|_| "Rust Rebar Count oracle overflow".to_owned())
        }
        shared::Model::SpanSum => {
            regex
                .find_iter(&benchmark.haystack)
                .try_fold(0_u64, |sum, matched| {
                    let width = u64::try_from(matched.end().saturating_sub(matched.start()))
                        .map_err(|_| "Rust Rebar span width overflow".to_owned())?;
                    sum.checked_add(width)
                        .ok_or_else(|| "Rust Rebar SpanSum oracle overflow".to_owned())
                })
        }
        shared::Model::GrepCount => benchmark.haystack.lines().try_fold(0_u64, |count, line| {
            if regex.is_match(line) {
                count
                    .checked_add(1)
                    .ok_or_else(|| "Rust Rebar GrepCount oracle overflow".to_owned())
            } else {
                Ok(count)
            }
        }),
    }
}

fn require_expected(actual: u64, expected: u64) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "linked AOT reducer returned {actual}, Rust Rebar oracle returned {expected}"
        ))
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn byte_regex(pattern: &str) -> Regex {
        Regex::builder()
            .configure(Regex::config().utf8_empty(false))
            .syntax(
                regex_automata::util::syntax::Config::new()
                    .utf8(false)
                    .unicode(false),
            )
            .build(pattern)
            .expect("test byte regex")
    }

    fn benchmark(model: shared::Model, haystack: &[u8]) -> shared::Benchmark {
        shared::Benchmark {
            name: "test/model/aot".to_owned(),
            model,
            patterns: vec!["a+".to_owned()],
            case_insensitive: false,
            unicode: false,
            haystack: haystack.to_vec(),
            max_iters: 1,
            max_warmup_iters: 0,
            max_time: Duration::from_secs(1),
            max_warmup_time: Duration::ZERO,
        }
    }

    #[test]
    fn independent_oracle_covers_all_current_scalar_models() {
        assert_eq!(
            rust_oracle(&benchmark(shared::Model::Compile, b"baa x aaa")).unwrap(),
            2
        );
        assert_eq!(
            rust_oracle(&benchmark(shared::Model::Count, b"baa x aaa")).unwrap(),
            2
        );
        assert_eq!(
            rust_oracle(&benchmark(shared::Model::SpanSum, b"baa x aaa")).unwrap(),
            5
        );
        assert_eq!(
            rust_oracle(&benchmark(shared::Model::GrepCount, b"aa\r\nno\na")).unwrap(),
            2
        );
    }

    #[test]
    fn direct_linked_iteration_matches_rebar_empty_progress_windows() {
        let cases: &[(&str, &[u8], u64, &[usize])] = &[
            ("", b"", 0, &[0]),
            ("", &[0xC3, 0xA9], 0, &[0, 1, 2]),
            ("a|", b"a", 1, &[0, 1]),
            ("a?", b"ba", 1, &[0, 1, 2]),
            ("(?:ab|)", b"xab", 2, &[0, 1, 3]),
        ];
        for &(pattern, haystack, expected_sum, expected_starts) in cases {
            let regex = byte_regex(pattern);
            let mut starts = Vec::new();
            let actual = strict_span_sum_with_search(haystack.len(), |start| {
                starts.push(start);
                Ok(regex
                    .find(regex_automata::Input::new(haystack).span(start..haystack.len()))
                    .map(|matched| FreAotRegexResultV1 {
                        start: matched.start(),
                        end: matched.end(),
                    }))
            })
            .expect("strict direct iteration");
            assert_eq!(actual, expected_sum, "pattern={pattern:?}");
            assert_eq!(starts, expected_starts, "pattern={pattern:?}");
        }
    }

    #[test]
    fn direct_linked_grep_matches_every_rebar_line_domain_once() {
        let regex = byte_regex("a+");
        let haystack = b"aa\r\nno\na\n\n";
        let mut observed = Vec::new();
        let actual = strict_grep_with_search(haystack, |line| {
            observed.push(line.to_vec());
            Ok(regex.is_match(line))
        })
        .expect("strict direct grep");
        assert_eq!(actual, 2);
        assert_eq!(
            observed,
            [
                b"aa".as_slice(),
                b"no".as_slice(),
                b"a".as_slice(),
                b"".as_slice()
            ]
        );
    }

    #[test]
    fn configured_parser_rejects_object_emission_as_rebar_compile() {
        let mut klv = Vec::new();
        for (key, value) in [
            ("name", b"test/compile".as_slice()),
            ("model", b"compile".as_slice()),
            ("pattern", b"a+".as_slice()),
            ("case-insensitive", b"false".as_slice()),
            ("unicode", b"false".as_slice()),
            ("haystack", b"aa".as_slice()),
            ("max-iters", b"1".as_slice()),
            ("max-warmup-iters", b"0".as_slice()),
            ("max-time", b"1".as_slice()),
            ("max-warmup-time", b"0".as_slice()),
        ] {
            klv.extend_from_slice(format!("{key}:{}:", value.len()).as_bytes());
            klv.extend_from_slice(value);
            klv.push(b'\n');
        }
        assert!(
            shared::Benchmark::parse(&klv)
                .expect_err("object emission is not Rebar compile")
                .contains("not a search-ready Rebar compile")
        );
    }

    #[test]
    fn strict_span_accumulator_rejects_non_rebar_sequences() {
        let mut overlap = StrictSpanAccumulator::new(8);
        overlap
            .push(FreAotRegexResultV1 { start: 1, end: 4 })
            .expect("first span");
        assert!(
            overlap
                .push(FreAotRegexResultV1 { start: 3, end: 5 })
                .is_err()
        );

        let mut adjacent_empty = StrictSpanAccumulator::new(8);
        adjacent_empty
            .push(FreAotRegexResultV1 { start: 1, end: 4 })
            .expect("first span");
        assert!(
            adjacent_empty
                .push(FreAotRegexResultV1 { start: 4, end: 4 })
                .is_err()
        );
    }

    #[test]
    fn provenance_hex_is_fixed_width() {
        assert_eq!(hex(&[0, 1, 0xfe, 0xff]), "0001feff");
    }
}
