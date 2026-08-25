use fre_aot_regex::{
    CompileError, CompileLimitsV1, CompileMode, CompileRequest, CompileResource, DeterminizeLimits,
    EngineKind, EntryAbi, ObjectError, OutputContract, PREPARED_CAPABILITY_ORDERED_NFA_V15,
    PreparedAggregateExports, PreparedAggregateStrategy, PreparedBulkStrategy,
    PreparedOrderedNfaV15CompileDecline, PreparedOrderedNfaV15CompileDisposition, SymbolBinding,
    SymbolKind, Target, compile,
    compile_with_prepared_ordered_nfa_v15,
    compile_with_prepared_ordered_nfa_v15_and_native_data_limit,
    compile_with_prepared_ordered_nfa_v15_and_native_data_limit_reported,
    compile_with_prepared_ordered_nfa_v15_reported,
    compile_with_prepared_ordered_nfa_v15_scalar_operation_and_native_data_limit_reported,
    compile_with_prepared_ordered_nfa_v15_scalar_operation_reported,
};

const PUBLIC_ORDERED_NFA_FIXTURE: &str = r"(?-u:[\x00-\xFF])\bfoo\b";

fn request(target: Target) -> CompileRequest {
    CompileRequest::new(PUBLIC_ORDERED_NFA_FIXTURE, target)
        .mode(CompileMode::Fast)
        .output(OutputContract::Span)
}

#[test]
fn explicit_route_publishes_exact_v15_span_fill_and_count_on_both_targets() {
    for target in [Target::x86_64_linux(), Target::aarch64_linux()] {
        let compiled =
            compile_with_prepared_ordered_nfa_v15(request(target), PreparedAggregateExports::COUNT)
                .unwrap_or_else(|error| {
                    panic!("explicit V15 compile failed for {target:?}: {error}")
                });
        assert_eq!(compiled.receipt().engine, EngineKind::OrderedNfa);
        assert_eq!(
            compiled.module().prepared_bulk_strategy(),
            Some(PreparedBulkStrategy::NativeOrderedNfaLoop),
        );
        assert_eq!(
            compiled.module().required_prepare_capabilities(),
            PREPARED_CAPABILITY_ORDERED_NFA_V15,
        );
        assert_eq!(
            compiled.receipt().required_prepare_capabilities,
            PREPARED_CAPABILITY_ORDERED_NFA_V15,
        );
        assert!(compiled.module().prepared_entry_symbol().is_some());
        assert!(compiled.module().prepared_span_fill_symbol().is_some());
        assert_eq!(
            compiled.module().prepared_aggregate_exports(),
            PreparedAggregateExports::COUNT,
        );
        assert_eq!(
            compiled.module().prepared_aggregate_strategy(),
            Some(PreparedAggregateStrategy::NativeOrderedNfaFused),
        );
    }
}

#[test]
fn explicit_route_resource_and_object_misses_are_terminal() {
    let target = Target::x86_64_linux();
    let reported_native_data =
        compile_with_prepared_ordered_nfa_v15_and_native_data_limit_reported(
            request(target),
            PreparedAggregateExports::NONE,
            0,
        )
        .expect("numeric admission is a reported disposition");
    let PreparedOrderedNfaV15CompileDisposition::Declined(
        PreparedOrderedNfaV15CompileDecline::NativeDataBytes {
            limit: 0,
            required: reported_required_native_data,
        },
    ) = reported_native_data
    else {
        panic!("zero native-data ceiling was not reported: {reported_native_data:?}");
    };
    let required_native_data =
        match compile_with_prepared_ordered_nfa_v15_and_native_data_limit(
            request(target),
            PreparedAggregateExports::NONE,
            0,
        ) {
            Err(CompileError::Object(ObjectError::Resource {
                resource: CompileResource::ProgramBytes,
                limit: 0,
                required,
            })) => required,
            other => panic!("zero native-data ceiling was not terminal: {other:?}"),
        };
    assert_eq!(reported_required_native_data, required_native_data);

    let unbounded = compile_with_prepared_ordered_nfa_v15_and_native_data_limit(
        request(target),
        PreparedAggregateExports::NONE,
        usize::MAX,
    )
    .expect("unbounded explicit V15 compile");
    let native_data_bytes = unbounded
        .receipt()
        .data_bytes
        .checked_sub(unbounded.receipt().program_bytes)
        .expect("native data follows the serialized program");
    assert_eq!(required_native_data, native_data_bytes);
    let object_limit = unbounded
        .object()
        .len()
        .checked_sub(1)
        .expect("object is nonempty");
    let limited = request(target).limits(CompileLimitsV1 {
        max_object_bytes: object_limit,
        ..CompileLimitsV1::default()
    });
    let reported_object =
        compile_with_prepared_ordered_nfa_v15_and_native_data_limit_reported(
            limited.clone(),
            PreparedAggregateExports::NONE,
            native_data_bytes,
        )
        .expect("object ceiling is a reported disposition");
    assert!(matches!(
        reported_object,
        PreparedOrderedNfaV15CompileDisposition::Declined(
            PreparedOrderedNfaV15CompileDecline::ObjectBytes { limit, required }
        ) if limit == object_limit && required > limit
    ));
    assert!(matches!(
        compile_with_prepared_ordered_nfa_v15_and_native_data_limit(
            limited,
            PreparedAggregateExports::NONE,
            native_data_bytes,
        ),
        Err(CompileError::Object(ObjectError::Resource {
            resource: CompileResource::ObjectBytes,
            limit,
            required,
        })) if limit == object_limit && required > limit
    ));
}

#[test]
fn explicit_route_failure_does_not_mutate_the_default_portfolio() {
    let request = CompileRequest::new("ab", Target::x86_64_linux())
        .mode(CompileMode::Optimizing)
        .output(OutputContract::Span);
    let before = compile(request.clone()).expect("default route before explicit attempt");
    assert_ne!(
        before.module().prepared_bulk_strategy(),
        Some(PreparedBulkStrategy::NativeOrderedNfaLoop),
    );
    assert!(matches!(
        compile_with_prepared_ordered_nfa_v15_reported(
            request.clone(),
            PreparedAggregateExports::NONE,
        ),
        Ok(PreparedOrderedNfaV15CompileDisposition::Declined(
            PreparedOrderedNfaV15CompileDecline::Unsupported,
        ))
    ));
    assert!(matches!(
        compile_with_prepared_ordered_nfa_v15(request.clone(), PreparedAggregateExports::NONE,),
        Err(CompileError::Object(ObjectError::InvalidModule(
            "prepared Ordered-NFA V15 route is unsupported"
        )))
    ));
    let after = compile(request).expect("default route after explicit attempt");
    assert_eq!(
        before.program().serialize().unwrap(),
        after.program().serialize().unwrap()
    );
    assert_eq!(before.object(), after.object());
    assert_eq!(before.receipt(), after.receipt());
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the cross-ISA closure and both reported byte ceilings share one exact fixture"
)]
fn grep_operation_only_is_one_closed_function_and_reports_numeric_declines() {
    const GREP_PATTERN: &str = r"(?-u:[\x00-\xFF])\bfoo\b\z";
    for target in [Target::x86_64_linux(), Target::aarch64_linux()] {
        let request = || {
            CompileRequest::new(GREP_PATTERN, target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span)
        };
        let compiled = compile_with_prepared_ordered_nfa_v15_scalar_operation_reported(
            request(),
            PreparedAggregateExports::GREP_COUNT,
        )
        .expect("operation-only GrepCount compilation")
        .into_compiled()
        .expect("Unicode GrepCount fixture remains V15 eligible");
        let module = compiled.module();
        assert_eq!(compiled.receipt().entry_abi, EntryAbi::PreparedScalarReduceV1);
        assert_eq!(compiled.receipt().engine, EngineKind::OrderedNfa);
        assert_eq!(
            compiled.receipt().prepared_aggregate_strategy,
            Some(PreparedAggregateStrategy::NativeOrderedNfaFused),
        );
        assert_eq!(
            compiled.receipt().required_prepare_capabilities,
            PREPARED_CAPABILITY_ORDERED_NFA_V15,
        );
        assert!(!compiled.receipt().runtime_helper_required);
        assert_eq!(module.prepared_bulk_strategy(), None);
        assert_eq!(module.prepared_entry_symbol(), None);
        assert_eq!(module.prepared_span_fill_symbol(), None);
        assert_eq!(module.prepared_count_symbol(), None);
        assert_eq!(module.prepared_span_sum_symbol(), None);
        assert_eq!(module.prepared_grep_count_symbol(), Some(module.entry_symbol()));
        assert!(module.required_runtime_program().is_some());
        assert!(module.required_runtime_symbols().next().is_none());
        let global_functions = module
            .symbols()
            .iter()
            .filter(|symbol| {
                symbol.binding == SymbolBinding::Global
                    && symbol.kind == SymbolKind::Function
                    && symbol.section.is_some()
            })
            .collect::<Vec<_>>();
        assert_eq!(global_functions.len(), 1);
        assert_eq!(global_functions[0].name, module.entry_symbol());
        assert!(module.relocations().iter().all(|relocation| {
            module
                .symbols()
                .get(relocation.symbol)
                .is_some_and(|symbol| symbol.section.is_some())
        }));
    }

    let request = || {
        CompileRequest::new(GREP_PATTERN, Target::x86_64_linux())
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span)
    };
    assert!(matches!(
        compile_with_prepared_ordered_nfa_v15_scalar_operation_and_native_data_limit_reported(
            request(),
            PreparedAggregateExports::GREP_COUNT,
            0,
        ),
        Ok(PreparedOrderedNfaV15CompileDisposition::Declined(
            PreparedOrderedNfaV15CompileDecline::NativeDataBytes {
                limit: 0,
                required,
            },
        )) if required > 0
    ));
    let unbounded = compile_with_prepared_ordered_nfa_v15_scalar_operation_reported(
        request(),
        PreparedAggregateExports::GREP_COUNT,
    )
    .expect("unbounded operation-only GrepCount compilation")
    .into_compiled()
    .expect("operation-only GrepCount fixture remains V15 eligible");
    let native_data_bytes = unbounded
        .receipt()
        .data_bytes
        .checked_sub(unbounded.receipt().program_bytes)
        .expect("native data follows the serialized program");
    let object_limit = unbounded
        .object()
        .len()
        .checked_sub(1)
        .expect("operation-only GrepCount object is nonempty");
    let limited = request().limits(CompileLimitsV1 {
        max_object_bytes: object_limit,
        ..CompileLimitsV1::default()
    });
    assert!(matches!(
        compile_with_prepared_ordered_nfa_v15_scalar_operation_and_native_data_limit_reported(
            limited,
            PreparedAggregateExports::GREP_COUNT,
            native_data_bytes,
        ),
        Ok(PreparedOrderedNfaV15CompileDisposition::Declined(
            PreparedOrderedNfaV15CompileDecline::ObjectBytes { limit, required },
        )) if limit == object_limit && required > limit
    ));
}

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(target_os = "linux", target_os = "macos")
))]
#[test]
#[ignore = "requires `cargo build -p fre-aot-regex-runtime --lib`; links operation-only and legacy GrepCount objects to the real runtime"]
#[allow(
    clippy::too_many_lines,
    reason = "the linked differential keeps both exact object routes, their byte cases, and raw ABI checks together"
)]
fn linked_host_grep_operation_only_matches_legacy_repeatedly_and_transactionally() {
    use std::{fmt::Write as _, fs, process::Command, time::SystemTime};

    const PATTERN: &str = r"(?-u:[\x00-\xFF])\bfoo\b\z";
    const FOREIGN_PATTERN: &str = r"(?-u:[\x00-\xFF])\bbar\b\z";
    const REPEATS: usize = 8;

    let target = match (std::env::consts::ARCH, std::env::consts::OS) {
        ("x86_64", "linux") => Target::x86_64_linux(),
        ("x86_64", "macos") => Target::x86_64_macos(),
        ("aarch64", "linux") => Target::aarch64_linux(),
        ("aarch64", "macos") => Target::aarch64_macos(),
        pair => panic!("unsupported linked-host pair {pair:?}"),
    };
    let compile = |pattern: &str| {
        compile_with_prepared_ordered_nfa_v15_scalar_operation_reported(
            CompileRequest::new(pattern, target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
            PreparedAggregateExports::GREP_COUNT,
        )
        .expect("operation-only GrepCount compile")
        .into_compiled()
        .expect("linked Unicode fixture remains V15 eligible")
    };
    let primary = compile(PATTERN);
    let foreign = compile(FOREIGN_PATTERN);
    let legacy = compile_with_prepared_ordered_nfa_v15(
        CompileRequest::new(PATTERN, target)
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span),
        PreparedAggregateExports::GREP_COUNT,
    )
    .expect("legacy NativeOrderedNfaLoop GrepCount compile");
    assert_eq!(legacy.receipt().entry_abi, EntryAbi::SpanSearchV1);
    assert_eq!(
        legacy.module().prepared_bulk_strategy(),
        Some(PreparedBulkStrategy::NativeOrderedNfaLoop),
    );
    assert!(legacy.module().prepared_entry_symbol().is_some());
    assert!(legacy.module().prepared_span_fill_symbol().is_some());
    assert!(legacy.module().required_runtime_symbols().next().is_some());
    assert_eq!(
        primary.receipt().program_sha256,
        legacy.receipt().program_sha256,
        "the paired reducers must own the exact same semantic program",
    );
    let (primary_program, primary_program_len) = primary
        .module()
        .required_runtime_program()
        .expect("primary preparation program");
    let (foreign_program, foreign_program_len) = foreign
        .module()
        .required_runtime_program()
        .expect("foreign preparation program");
    let primary_reducer = primary
        .module()
        .prepared_grep_count_symbol()
        .expect("primary GrepCount reducer");
    let (legacy_program, legacy_program_len) = legacy
        .module()
        .required_runtime_program()
        .expect("legacy preparation program");
    let legacy_reducer = legacy
        .module()
        .prepared_grep_count_symbol()
        .expect("legacy GrepCount reducer");

    let mut dense = Vec::new();
    for index in 0..96 {
        dense.extend_from_slice(if index % 2 == 0 {
            &b"!foo\n"[..]
        } else {
            &b"?foo\r\n"[..]
        });
    }
    let no_match = b"!fo\n?food\r\nplain\n".repeat(64);
    let cases = [
        (Vec::new(), 0_u64),
        (b"\r".to_vec(), 0),
        (b"\n".to_vec(), 0),
        (b"\r\n".to_vec(), 0),
        (b"!foo".to_vec(), 1),
        (b"!foo\n".to_vec(), 1),
        (b"!foo\r\n".to_vec(), 1),
        (b"!foo\r".to_vec(), 0),
        (b"\0foo\n".to_vec(), 1),
        (b"\xfffoo\n".to_vec(), 1),
        (b"!foo\n?foo\r\n#foo".to_vec(), 3),
        (b"foo\n!fo\n!!foo\n\xff\xfe".to_vec(), 1),
        (b"short\n!foo\r\n\xffbad\n\0foo\n".to_vec(), 2),
        (dense, 96),
        (no_match, 0),
    ];
    let mut arrays = String::new();
    for (index, (haystack, _)) in cases.iter().enumerate() {
        let initializer = if haystack.is_empty() {
            "0".to_owned()
        } else {
            haystack
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(",")
        };
        writeln!(
            arrays,
            "static const unsigned char h{index}[]={{{initializer}}};"
        )
        .unwrap();
    }

    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "fre-aot-v15-grep-operation-{}-{nonce}",
        std::process::id(),
    ));
    fs::create_dir_all(&directory).expect("create linked GrepCount directory");
    let current_exe = std::env::current_exe().expect("current test executable");
    let profile_dir = current_exe
        .parent()
        .and_then(std::path::Path::parent)
        .expect("Cargo profile directory");
    let static_runtime = profile_dir.join("libfre_aot_regex_runtime.a");
    assert!(
        static_runtime.is_file(),
        "build the runtime first: cargo build -p fre-aot-regex-runtime --lib ({})",
        static_runtime.display(),
    );
    let compiler = if cfg!(target_os = "macos") { "clang" } else { "cc" };

    let run = |label: &str,
               program: &str,
               program_len: usize,
               reducer: &str,
               object: &[u8],
               foreign: Option<(&str, usize, &[u8])>| {
        let mut checks = String::new();
        for (index, (haystack, expected)) in cases.iter().enumerate() {
            writeln!(
                checks,
                concat!(
                    "for(unsigned round=0;round<{repeats}U;round++){{",
                    "out=UINT64_C(0xaaaaaaaaaaaaaaaa)^round;",
                    "if({reducer}(right,h{index},{length}U,&out)!=0U||out!=UINT64_C({expected}))return {failure};",
                    "if(fwrite(&out,sizeof(out),1U,stdout)!=1U)return {write_failure};}}"
                ),
                repeats = REPEATS,
                reducer = reducer,
                index = index,
                length = haystack.len(),
                expected = expected,
                failure = 40 + index,
                write_failure = 80 + index,
            )
            .unwrap();
        }
        let (foreign_declaration, foreign_setup, route_check, extra_destroy) =
            if let Some((foreign_program, foreign_program_len, _)) = foreign {
                (
                    format!("extern const unsigned char {foreign_program}[];"),
                    format!(
                        concat!(
                            "handle_t wrong=0;",
                            "if(fre_aot_regex_runtime_prepare_exclusive_v3({foreign_program},{foreign_program_len}U,&v3,&wrong)!=0U)return 3;"
                        ),
                        foreign_program = foreign_program,
                        foreign_program_len = foreign_program_len,
                    ),
                    format!(
                        concat!(
                            "out=UINT64_C(0x1122334455667788);",
                            "if({reducer}(wrong,(const unsigned char*)(uintptr_t)1,8U,&out)!=3U||out!=UINT64_C(0x1122334455667788))return 14;",
                            "out=UINT64_C(0x1122334455667788);",
                            "if({reducer}(compat,(const unsigned char*)(uintptr_t)1,8U,&out)!=3U||out!=UINT64_C(0x1122334455667788))return 15;"
                        ),
                        reducer = reducer,
                    ),
                    "if(fre_aot_regex_runtime_destroy_exclusive_v1(wrong)!=0U)return 18;"
                        .to_owned(),
                )
            } else {
                (
                    String::new(),
                    String::new(),
                    format!(
                        concat!(
                            "out=UINT64_C(0x1122334455667788);",
                            "if({reducer}(compat,(const unsigned char*)(uintptr_t)1,8U,&out)!=3U||out!=UINT64_C(0x1122334455667788))return 15;"
                        ),
                        reducer = reducer,
                    ),
                    String::new(),
                )
            };
        let source = format!(
            r"#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef void *handle_t;
typedef struct {{uint32_t struct_size;uint32_t config_version;uint64_t operation_flags;uint64_t max_start_filter_setup_work;uint64_t max_grep_count_workspace_bytes;uint64_t v2_reserved[4];uint64_t max_handle_bytes;uint64_t max_ordered_nfa_scratch_bytes;uint64_t max_ordered_nfa_setup_work;uint64_t required_capabilities;uint64_t reserved[2];}} prepare_v3_t;
extern const unsigned char {program}[];
{foreign_declaration}
extern uint32_t {reducer}(handle_t,const unsigned char*,size_t,uint64_t*);
extern uint32_t fre_aot_regex_runtime_prepare_exclusive_v1(const unsigned char*,size_t,handle_t*);
extern uint32_t fre_aot_regex_runtime_prepare_exclusive_v3(const unsigned char*,size_t,const prepare_v3_t*,handle_t*);
extern uint32_t fre_aot_regex_runtime_destroy_exclusive_v1(handle_t);
{arrays}
int main(void){{
  const prepare_v3_t v3={{112U,3U,UINT64_C(2),UINT64_C(100000000),UINT64_C(67108864),{{0,0,0,0}},UINT64_C(8388608),UINT64_C(8388608),UINT64_C(2000000),UINT64_C(1),{{0,0}}}};
  handle_t right=0,compat=0;
  if(fre_aot_regex_runtime_prepare_exclusive_v3({program},{program_len}U,&v3,&right)!=0U)return 1;
  if(fre_aot_regex_runtime_prepare_exclusive_v1({program},{program_len}U,&compat)!=0U)return 2;
  {foreign_setup}
  uint64_t out=UINT64_C(0x1122334455667788);
  unsigned char bytes[17];memset(bytes,0xa5,sizeof(bytes));
  if({reducer}((handle_t)0,(const unsigned char*)(uintptr_t)1,8U,&out)!=5U||out!=UINT64_C(0x1122334455667788))return 4;
  if({reducer}(right,(const unsigned char*)0,1U,&out)!=2U||out!=UINT64_C(0x1122334455667788))return 5;
  if({reducer}(right,h0,0U,(uint64_t*)0)!=2U||out!=UINT64_C(0x1122334455667788))return 6;
  if({reducer}(right,h4,4U,(uint64_t*)(void*)(bytes+1))!=2U)return 7;
  for(size_t i=0;i<sizeof(bytes);i++)if(bytes[i]!=0xa5U)return 8;
  if({reducer}(right,(const unsigned char*)(uintptr_t)1,(size_t)-1,&out)!=2U||out!=UINT64_C(0x1122334455667788))return 9;
  {route_check}
  {checks}
  if(fre_aot_regex_runtime_destroy_exclusive_v1(right)!=0U)return 16;
  if(fre_aot_regex_runtime_destroy_exclusive_v1(compat)!=0U)return 17;
  {extra_destroy}
  return 0;
}}
",
        );
        let object_path = directory.join(format!("{label}.o"));
        let c_path = directory.join(format!("{label}.c"));
        let executable = directory.join(label);
        fs::write(&object_path, object).expect("write GrepCount object");
        fs::write(&c_path, source).expect("write GrepCount C harness");
        let mut command = Command::new(compiler);
        command.arg("-O2").arg(&c_path).arg(&object_path);
        if let Some((_, _, foreign_object)) = foreign {
            let foreign_path = directory.join(format!("{label}-foreign.o"));
            fs::write(&foreign_path, foreign_object).expect("write foreign GrepCount object");
            command.arg(foreign_path);
        }
        let linked = command
            .arg(&static_runtime)
            .arg("-o")
            .arg(&executable)
            .output()
            .expect("link GrepCount harness");
        assert!(
            linked.status.success(),
            "{label} link failed: {}",
            String::from_utf8_lossy(&linked.stderr),
        );
        let executed = Command::new(&executable)
            .output()
            .expect("run GrepCount harness");
        assert!(
            executed.status.success(),
            "{label} GrepCount harness status={:?}, stderr={}",
            executed.status.code(),
            String::from_utf8_lossy(&executed.stderr),
        );
        executed.stdout
    };

    let operation_transcript = run(
        "operation-only",
        primary_program,
        primary_program_len,
        primary_reducer,
        primary.object(),
        Some((foreign_program, foreign_program_len, foreign.object())),
    );
    let legacy_transcript = run(
        "legacy-loop",
        legacy_program,
        legacy_program_len,
        legacy_reducer,
        legacy.object(),
        None,
    );
    assert_eq!(
        operation_transcript.len(),
        cases.len() * REPEATS * std::mem::size_of::<u64>(),
    );
    assert_eq!(
        operation_transcript, legacy_transcript,
        "operation-only GrepCount diverged from the repeated legacy NativeOrderedNfaLoop transcript",
    );
    fs::remove_dir_all(&directory).expect("remove linked GrepCount directory");
}

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "macos")))]
#[test]
#[ignore = "requires `cargo build -p fre-aot-regex-runtime --lib`; links and executes sparse-prefix V15 Count+SpanSum"]
fn linked_aarch64_sparse_prefix_count_and_span_sum_match_stock() {
    use fre_aot_regex::{CpuFeature, FeatureSet};
    use std::{fmt::Write as _, fs, process::Command, time::SystemTime};

    const PATTERN: &str = r"Q?Q?Q?Q?Q?Q?Q?Q?Z";
    const REPEATS: usize = 8;

    let target = match (std::env::consts::ARCH, std::env::consts::OS) {
        ("aarch64", "linux") => Target::aarch64_linux(),
        ("aarch64", "macos") => Target::aarch64_macos(),
        pair => panic!("unsupported linked-host pair {pair:?}"),
    }
    .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
    .expect("linked host ASIMD target");
    let disposition = compile_with_prepared_ordered_nfa_v15_reported(
        CompileRequest::new(PATTERN, target)
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span)
            .limits(CompileLimitsV1 {
                determinize: DeterminizeLimits {
                    max_states: 0,
                    ..DeterminizeLimits::default()
                },
                ..CompileLimitsV1::default()
            }),
        PreparedAggregateExports::COUNT.union(PreparedAggregateExports::SPAN_SUM),
    )
    .expect("exact-prefix Count compilation");
    let decline = disposition.decline();
    let compiled = disposition
        .into_compiled()
        .unwrap_or_else(|| panic!("exact-prefix fixture remains V15 eligible: {decline:?}"));
    assert_eq!(compiled.receipt().engine, EngineKind::OrderedNfa);
    assert_eq!(
        compiled.module().prepared_bulk_strategy(),
        Some(PreparedBulkStrategy::NativeOrderedNfaLoop),
    );
    assert_eq!(
        compiled.receipt().prepared_aggregate_strategy,
        Some(PreparedAggregateStrategy::NativeOrderedNfaFused),
    );
    let (program, program_len) = compiled
        .module()
        .required_runtime_program()
        .expect("exact-prefix preparation program");
    let prepared_search = compiled
        .module()
        .prepared_entry_symbol()
        .expect("exact-prefix prepared Span search");
    let count_reducer = compiled
        .module()
        .prepared_count_symbol()
        .expect("exact-prefix Count reducer");
    let span_sum_reducer = compiled
        .module()
        .prepared_span_sum_symbol()
        .expect("exact-prefix SpanSum reducer");

    let mut late = b"_".repeat(16 * 1024 + 15);
    late.extend_from_slice(b"QQQQZ");
    let dense_decoy = b"Qy".repeat(4096);
    let dense_positive = b"Z_".repeat(1024);
    let mut lane15 = b"_".repeat(16);
    lane15.push(b'Z');
    let mut earliest_lane = b"_".repeat(32);
    earliest_lane.extend_from_slice(b"QZ__Z");
    let cases = [
        Vec::new(),
        b"_".repeat(15),
        b"_".repeat(16),
        lane15,
        b"_".repeat(16 * 1024),
        late,
        dense_decoy,
        dense_positive,
        earliest_lane,
    ];
    let stock = regex::bytes::Regex::new(PATTERN).expect("stock exact-prefix fixture");
    let expected = cases
        .iter()
        .map(|haystack| {
            let matches = stock.find_iter(haystack).collect::<Vec<_>>();
            let count = u64::try_from(matches.len()).expect("stock count fits u64");
            let span_sum = matches
                .iter()
                .try_fold(0_u64, |sum, matched| {
                    sum.checked_add(
                        u64::try_from(matched.end() - matched.start())
                            .expect("span width fits u64"),
                    )
                })
                .expect("stock span sum fits u64");
            let first = matches
                .first()
                .map(|matched| (matched.start(), matched.end()));
            (count, span_sum, first)
        })
        .collect::<Vec<_>>();
    let mut arrays = String::new();
    for (index, haystack) in cases.iter().enumerate() {
        let initializer = if haystack.is_empty() {
            "0".to_owned()
        } else {
            haystack
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(",")
        };
        writeln!(
            arrays,
            "static const unsigned char h{index}[]={{{initializer}}};"
        )
        .unwrap();
    }
    let mut checks = String::new();
    for (index, (haystack, (expected_count, expected_span_sum, expected_first))) in
        cases.iter().zip(&expected).enumerate()
    {
        let (expected_status, expected_start, expected_end) = expected_first
            .map_or((0_u32, 0_usize, 0_usize), |(start, end)| {
                (1_u32, start, end)
            });
        writeln!(
            checks,
            concat!(
                "for(unsigned round=0;round<{repeats}U;round++){{",
                "count=UINT64_C(0xaaaaaaaaaaaaaaaa)^round;",
                "span_sum=UINT64_C(0x5555555555555555)^round;",
                "if({count_reducer}(handle,h{index},{length}U,&count)!=0U||count!=UINT64_C({expected_count}))return {count_failure};",
                "if({span_sum_reducer}(handle,h{index},{length}U,&span_sum)!=0U||span_sum!=UINT64_C({expected_span_sum}))return {span_sum_failure};",
                "span_t one={{UINT64_C(0xaaaaaaaaaaaaaaaa),UINT64_C(0xbbbbbbbbbbbbbbbb)}};",
                "uint32_t status={prepared_search}(handle,h{index},{length}U,0U,{length}U,&one);",
                "if(status!={expected_status}U||one.start!={expected_start}U||one.end!={expected_end}U)return {span_failure};}}"
            ),
            repeats = REPEATS,
            count_reducer = count_reducer,
            span_sum_reducer = span_sum_reducer,
            prepared_search = prepared_search,
            index = index,
            length = haystack.len(),
            expected_count = expected_count,
            expected_span_sum = expected_span_sum,
            expected_status = expected_status,
            expected_start = expected_start,
            expected_end = expected_end,
            count_failure = 20 + index,
            span_sum_failure = 40 + index,
            span_failure = 60 + index,
        )
        .unwrap();
    }

    let source = format!(
        r"#include <stddef.h>
#include <stdint.h>
typedef void *handle_t;
typedef struct {{size_t start;size_t end;}} span_t;
typedef struct {{uint32_t struct_size;uint32_t config_version;uint64_t operation_flags;uint64_t max_start_filter_setup_work;uint64_t max_grep_count_workspace_bytes;uint64_t v2_reserved[4];uint64_t max_handle_bytes;uint64_t max_ordered_nfa_scratch_bytes;uint64_t max_ordered_nfa_setup_work;uint64_t required_capabilities;uint64_t reserved[2];}} prepare_v3_t;
extern const unsigned char {program}[];
extern uint32_t {prepared_search}(handle_t,const unsigned char*,size_t,size_t,size_t,span_t*);
extern uint32_t {count_reducer}(handle_t,const unsigned char*,size_t,uint64_t*);
extern uint32_t {span_sum_reducer}(handle_t,const unsigned char*,size_t,uint64_t*);
extern uint32_t fre_aot_regex_runtime_prepare_exclusive_v3(const unsigned char*,size_t,const prepare_v3_t*,handle_t*);
extern uint32_t fre_aot_regex_runtime_destroy_exclusive_v1(handle_t);
{arrays}
int main(void){{
  const prepare_v3_t config={{112U,3U,UINT64_C(2),UINT64_C(100000000),UINT64_C(67108864),{{0,0,0,0}},UINT64_C(8388608),UINT64_C(8388608),UINT64_C(2000000),UINT64_C(1),{{0,0}}}};
  handle_t handle=0;
  if(fre_aot_regex_runtime_prepare_exclusive_v3({program},{program_len}U,&config,&handle)!=0U)return 1;
  uint64_t count=UINT64_C(0x1122334455667788),span_sum=UINT64_C(0x8877665544332211);
  {checks}
  if(fre_aot_regex_runtime_destroy_exclusive_v1(handle)!=0U)return 2;
  return 0;
}}
",
    );

    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "fre-aot-v15-exact-prefix-count-{}-{nonce}",
        std::process::id(),
    ));
    fs::create_dir_all(&directory).expect("create exact-prefix Count directory");
    let current_exe = std::env::current_exe().expect("current test executable");
    let profile_dir = current_exe
        .parent()
        .and_then(std::path::Path::parent)
        .expect("Cargo profile directory");
    let static_runtime = profile_dir.join("libfre_aot_regex_runtime.a");
    assert!(
        static_runtime.is_file(),
        "build the runtime first: cargo build -p fre-aot-regex-runtime --lib ({})",
        static_runtime.display(),
    );
    let object_path = directory.join("exact-prefix-count.o");
    let c_path = directory.join("exact-prefix-count.c");
    let executable = directory.join("exact-prefix-count");
    fs::write(&object_path, compiled.object()).expect("write exact-prefix Count object");
    fs::write(&c_path, source).expect("write exact-prefix Count harness");
    let compiler = if cfg!(target_os = "macos") {
        "clang"
    } else {
        "cc"
    };
    let linked = Command::new(compiler)
        .arg("-O2")
        .arg(&c_path)
        .arg(&object_path)
        .arg(&static_runtime)
        .arg("-o")
        .arg(&executable)
        .output()
        .expect("link exact-prefix Count harness");
    assert!(
        linked.status.success(),
        "exact-prefix Count link failed: {}",
        String::from_utf8_lossy(&linked.stderr),
    );
    let executed = Command::new(&executable)
        .output()
        .expect("execute exact-prefix Count harness");
    assert!(
        executed.status.success(),
        "exact-prefix Count status={:?}, stderr={}",
        executed.status.code(),
        String::from_utf8_lossy(&executed.stderr),
    );
    fs::remove_dir_all(&directory).expect("remove exact-prefix Count directory");
}
