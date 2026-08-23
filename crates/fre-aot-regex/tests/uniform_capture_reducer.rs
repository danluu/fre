use fre_aot_regex::{
    CompileError, CompileResource, EntryAbi, ObjectError, PREPARED_CAPABILITY_ORDERED_NFA_V15,
    PreparedAggregateExports, PreparedAggregateStrategy, PreparedBulkStrategy, SlowAotLimits,
    Target, UniformCaptureCompileRequest, UniformCapturePreparedSpanFillCompileError,
    UniformCaptureReducerCompileDisposition, UniformCaptureReducerCompileError,
    UniformCaptureReducerDomain, UniformCaptureReducerOperation,
    compile_uniform_capture_prepared_span_fill_selector, compile_uniform_capture_reducer,
};
use fre_lower::UniformCaptureParticipationDecline;
use fre_syntax::{
    CanonicalPattern, CompatibilityProfile, ParseRequest, RustParsed, RustProfile, parse,
};

const PUBLIC_PREPARED_FIXTURE: &str =
    r"\b(?:([\w&&\p{Cyrillic}]{6})|([\w&&\p{Cyrillic}]{5}))\b";

fn parse_rebar(pattern: &str) -> RustParsed {
    let parsed = parse(ParseRequest::rust(
        pattern,
        CompatibilityProfile::RustBytes(RustProfile::rebar_1_12_4()),
    ))
    .unwrap_or_else(|error| panic!("failed to parse public fixture: {error}"));
    match parsed.pattern {
        CanonicalPattern::Rust(parsed) => parsed,
        CanonicalPattern::Re2(_) | CanonicalPattern::Re2Literal(_) => {
            panic!("Rust request returned another syntax family")
        }
    }
}

fn request(source_bytes: usize, target: Target) -> UniformCaptureCompileRequest {
    UniformCaptureCompileRequest::new(source_bytes, target).profile(RustProfile::rebar_1_12_4())
}

#[test]
fn direct_uniform_capture_reducers_are_one_authenticated_native_operation_cross_target() {
    let pattern = r"(a+)";
    let parsed = parse_rebar(pattern);
    for target in [Target::x86_64_linux(), Target::aarch64_linux()] {
        for (operation, prefix, domain) in [
            (
                UniformCaptureReducerOperation::CountCaptures,
                "fre_aot_regex_count_captures_exclusive_v1_",
                UniformCaptureReducerDomain::WholeHaystack,
            ),
            (
                UniformCaptureReducerOperation::GrepCaptures,
                "fre_aot_regex_grep_captures_exclusive_v1_",
                UniformCaptureReducerDomain::ByteSliceLinesLfCrLf,
            ),
        ] {
            let disposition = compile_uniform_capture_reducer(
                &parsed,
                request(pattern.len(), target),
                operation,
            )
            .unwrap_or_else(|error| panic!("native capture compile failed for {target:?}: {error}"));
            let selected = disposition
                .selected()
                .unwrap_or_else(|| panic!("positive fixture declined for {target:?}"));
            selected
                .authenticate()
                .unwrap_or_else(|error| panic!("fresh capture receipt failed: {error}"));
            assert!(selected.reducer_symbol().starts_with(prefix));
            assert_eq!(selected.reducer_symbol().len(), prefix.len() + 64);
            assert_eq!(selected.receipt().operation(), operation);
            assert_eq!(selected.receipt().domain(), domain);
            assert_eq!(selected.receipt().multiplier().get(), 2);
            assert_eq!(
                selected.receipt().aggregate_strategy(),
                PreparedAggregateStrategy::NativeFused,
            );
            assert_eq!(selected.receipt().required_prepare_capabilities(), 0);
            assert_eq!(
                selected.compiled().module().prepared_aggregate_exports(),
                PreparedAggregateExports::COUNT,
            );
            let count = selected
                .compiled()
                .module()
                .prepared_count_symbol()
                .expect("direct uniform capture Count child");
            assert_ne!(count, selected.compiled().module().entry_symbol());
            assert_ne!(count, selected.reducer_symbol());
            assert_eq!(selected.compiled().receipt().entry_abi, EntryAbi::SpanSearchV1);
            assert_eq!(selected.compiled().module().prepared_span_sum_symbol(), None);
            assert_eq!(selected.compiled().module().prepared_grep_count_symbol(), None);
            assert_eq!(selected.compiled().module().prepared_bulk_strategy(), None);
        }
    }
}

#[test]
fn runtime_backed_ordinary_selector_upgrades_to_closed_operation_only_v15() {
    let parsed = parse_rebar(PUBLIC_PREPARED_FIXTURE);
    for target in [Target::x86_64_linux(), Target::aarch64_linux()] {
        let disposition = compile_uniform_capture_reducer(
            &parsed,
            request(PUBLIC_PREPARED_FIXTURE.len(), target),
            UniformCaptureReducerOperation::GrepCaptures,
        )
        .unwrap_or_else(|error| panic!("prepared capture compile failed for {target:?}: {error}"));
        let selected = disposition
            .selected()
            .unwrap_or_else(|| panic!("positive prepared fixture declined for {target:?}"));
        selected
            .authenticate()
            .unwrap_or_else(|error| panic!("prepared capture receipt failed: {error}"));
        assert_eq!(selected.receipt().multiplier().get(), 2);
        assert_eq!(
            selected.receipt().aggregate_strategy(),
            PreparedAggregateStrategy::NativeOrderedNfaFused,
        );
        assert_eq!(
            selected.receipt().required_prepare_capabilities(),
            PREPARED_CAPABILITY_ORDERED_NFA_V15,
        );
        assert_eq!(
            selected.compiled().module().prepared_bulk_strategy(),
            None,
        );
        let compiled = selected.compiled();
        let module = compiled.module();
        let count = module
            .prepared_count_symbol()
            .expect("operation-only uniform capture Count child");
        assert_eq!(compiled.receipt().entry_abi, EntryAbi::PreparedScalarReduceV1);
        assert_eq!(count, module.entry_symbol());
        assert_ne!(count, selected.reducer_symbol());
        assert_eq!(module.prepared_entry_symbol(), None);
        assert_eq!(module.prepared_span_fill_symbol(), None);
        assert!(module.required_runtime_symbols().next().is_none());
        assert!(module.required_runtime_program().is_some());
        assert!(!compiled.receipt().runtime_helper_required);
        let global_functions = module
            .symbols()
            .iter()
            .filter(|symbol| {
                symbol.binding == fre_aot_regex::SymbolBinding::Global
                    && symbol.kind == fre_aot_regex::SymbolKind::Function
                    && symbol.section.is_some()
            })
            .map(|symbol| symbol.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(global_functions, [count, selected.reducer_symbol()]);
    }
}

#[test]
fn typed_native_data_decline_resumes_the_legacy_span_fill_compiler() {
    let parsed = parse_rebar(PUBLIC_PREPARED_FIXTURE);
    let mut slow_limits = SlowAotLimits::default();
    slow_limits.max_native_data_bytes = 0;
    let error = compile_uniform_capture_reducer(
        &parsed,
        request(PUBLIC_PREPARED_FIXTURE.len(), Target::x86_64_linux())
            .selector_slow_aot_limits(slow_limits),
        UniformCaptureReducerOperation::CountCaptures,
    )
    .expect_err("zero native-data cap must refuse both V15 representations");
    assert!(matches!(
        error,
        UniformCaptureReducerCompileError::Prepared(
            UniformCapturePreparedSpanFillCompileError::Selector(CompileError::Object(
                ObjectError::Resource {
                    resource: CompileResource::ProgramBytes,
                    limit: 0,
                    required,
                }
            ))
        ) if required > 0
    ));
}

#[test]
fn legacy_uniform_capture_compatibility_compiler_remains_exact_span_fill_v15() {
    let parsed = parse_rebar(PUBLIC_PREPARED_FIXTURE);
    for target in [Target::x86_64_linux(), Target::aarch64_linux()] {
        let selected = compile_uniform_capture_prepared_span_fill_selector(
            &parsed,
            request(PUBLIC_PREPARED_FIXTURE.len(), target),
        )
        .unwrap_or_else(|error| panic!("legacy SpanFill compile failed for {target:?}: {error}"))
        .into_selected()
        .unwrap_or_else(|| panic!("positive legacy fixture declined for {target:?}"));
        selected
            .authenticate()
            .unwrap_or_else(|error| panic!("legacy SpanFill receipt failed: {error}"));
        let compiled = selected.selector();
        let module = compiled.module();
        assert_eq!(compiled.receipt().entry_abi, EntryAbi::SpanSearchV1);
        assert_eq!(
            module.prepared_bulk_strategy(),
            Some(PreparedBulkStrategy::NativeOrderedNfaLoop),
        );
        assert_eq!(
            module.required_prepare_capabilities(),
            PREPARED_CAPABILITY_ORDERED_NFA_V15,
        );
        assert!(module.prepared_entry_symbol().is_some());
        assert!(module.prepared_span_fill_symbol().is_some());
        assert_eq!(module.prepared_aggregate_exports(), PreparedAggregateExports::NONE);
        assert!(module.prepared_count_symbol().is_none());
        assert_eq!(
            module.required_runtime_symbols().collect::<Vec<_>>(),
            [
                "fre_aot_regex_runtime_search_v1",
                "fre_aot_regex_runtime_search_exclusive_v1",
                "fre_aot_regex_runtime_fill_spans_exclusive_v1",
            ],
        );
    }
}

#[test]
fn semantic_decline_is_published_before_selector_construction() {
    let pattern = r"(a)?b";
    let parsed = parse_rebar(pattern);
    let disposition = compile_uniform_capture_reducer(
        &parsed,
        request(pattern.len(), Target::x86_64_linux()),
        UniformCaptureReducerOperation::CountCaptures,
    )
    .expect("nonuniform language has a conservative disposition");
    assert!(matches!(
        disposition,
        UniformCaptureReducerCompileDisposition::Declined(
            UniformCaptureParticipationDecline::NonUniform
        )
    ));
}

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(target_os = "linux", target_os = "macos")
))]
#[test]
#[ignore = "requires `cargo build -p fre-aot-regex-runtime --lib`; links and executes generated capture reducers"]
#[allow(
    clippy::too_many_lines,
    reason = "the linked-host differential keeps both operation domains and their raw ABI transaction checks together"
)]
fn linked_host_uniform_capture_reducers_match_independent_expectations() {
    use std::{fs, process::Command, time::SystemTime};

    let target = if cfg!(target_arch = "x86_64") {
        if cfg!(target_os = "linux") {
            Target::x86_64_linux()
        } else {
            Target::x86_64_macos()
        }
    } else if cfg!(target_os = "linux") {
        Target::aarch64_linux()
    } else {
        Target::aarch64_macos()
    };
    let cases: [(&str, UniformCaptureReducerOperation, &[u8], u64); 2] = [
        (
            r"(a+)",
            UniformCaptureReducerOperation::CountCaptures,
            b"aa ba aaa",
            6,
        ),
        (
            r"^(a+)$",
            UniformCaptureReducerOperation::GrepCaptures,
            b"aa\r\nb\n\naaa\rx\na",
            4,
        ),
    ];
    let current_exe = std::env::current_exe().expect("current test executable");
    let profile_dir = current_exe
        .parent()
        .and_then(std::path::Path::parent)
        .expect("Cargo profile directory");
    let static_runtime = profile_dir.join("libfre_aot_regex_runtime.a");
    assert!(
        static_runtime.is_file(),
        "build the linked runtime first: cargo build -p fre-aot-regex-runtime --lib ({})",
        static_runtime.display(),
    );
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "fre-aot-uniform-capture-reducer-{}-{nonce}",
        std::process::id(),
    ));
    fs::create_dir_all(&directory).expect("create uniform capture linker directory");
    let compiler = if cfg!(target_os = "macos") {
        "clang"
    } else {
        "cc"
    };

    for (index, (pattern, operation, haystack, expected)) in cases.iter().enumerate() {
        let parsed = parse_rebar(pattern);
        let selected = compile_uniform_capture_reducer(
            &parsed,
            request(pattern.len(), target),
            *operation,
        )
        .expect("compile linked-host uniform capture reducer")
        .into_selected()
        .expect("linked-host fixture proves a uniform capture language");
        selected
            .authenticate()
            .expect("authenticate linked-host uniform capture reducer");
        assert!(
            selected
                .compiled()
                .module()
                .required_runtime_symbols()
                .next()
                .is_none(),
            "linked-host fixture must use a helper-free direct selector",
        );
        let (program_symbol, program_len) = selected
            .compiled()
            .module()
            .required_runtime_program()
            .expect("capture reducer preparation program");
        let initializer = haystack
            .iter()
            .map(|byte| format!("{byte}U"))
            .collect::<Vec<_>>()
            .join(",");
        let reducer_symbol = selected.reducer_symbol();
        let source = format!(
            r#"#include <stddef.h>
#include <stdint.h>
typedef void *handle_t;
typedef struct {{uint32_t size;uint32_t version;uint64_t operations;uint64_t start_work;uint64_t grep_bytes;uint64_t reserved[4];}} prepare_v2_t;
extern uint32_t fre_aot_regex_runtime_prepare_exclusive_v2(const unsigned char*,size_t,const prepare_v2_t*,handle_t*);
extern uint32_t fre_aot_regex_runtime_destroy_exclusive_v1(handle_t);
extern const unsigned char {program_symbol}[];
extern uint32_t {reducer_symbol}(handle_t,const unsigned char*,size_t,uint64_t*);
static const unsigned char haystack[]={{{initializer}}};
int main(void){{
  const prepare_v2_t config={{64U,2U,UINT64_C(15),UINT64_C(100000000),UINT64_C(67108864),{{0,0,0,0}}}};
  handle_t handle=0;uint64_t out=UINT64_C(0x1122334455667788);unsigned char raw[24]={{0}};
  if(fre_aot_regex_runtime_prepare_exclusive_v2({program_symbol},{program_len}U,&config,&handle)!=0U||handle==0)return 1;
  if({reducer_symbol}(handle,haystack,sizeof(haystack),&out)!=0U||out!=UINT64_C({expected}))return 2;
  out=UINT64_C(0x1122334455667788);
  if({reducer_symbol}(0,haystack,sizeof(haystack),&out)!=5U||out!=UINT64_C(0x1122334455667788))return 3;
  if({reducer_symbol}(handle,(const unsigned char*)(uintptr_t)1,(size_t)-1,&out)!=2U||out!=UINT64_C(0x1122334455667788))return 4;
  if({reducer_symbol}(handle,haystack,sizeof(haystack),(uint64_t*)(void*)(raw+1))!=2U)return 5;
  if(fre_aot_regex_runtime_destroy_exclusive_v1(handle)!=0U)return 6;
  return 0;
}}
"#,
        );
        let object = directory.join(format!("capture-{index}.o"));
        let c_path = directory.join(format!("capture-{index}.c"));
        let executable = directory.join(format!("capture-{index}"));
        fs::write(&object, selected.compiled().object()).expect("write capture reducer object");
        fs::write(&c_path, source).expect("write capture reducer C harness");
        let status = Command::new(compiler)
            .arg("-O0")
            .arg(&c_path)
            .arg(&object)
            .arg(&static_runtime)
            .arg("-o")
            .arg(&executable)
            .status()
            .expect("link capture reducer C harness");
        assert!(status.success(), "capture reducer harness failed to link");
        let output = Command::new(&executable)
            .output()
            .expect("execute capture reducer C harness");
        assert!(
            output.status.success(),
            "capture reducer {operation:?} status={:?}, stdout={}, stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    fs::remove_dir_all(directory).expect("remove uniform capture linker directory");
}
