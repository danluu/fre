use fre_aot_regex::{
    Architecture, CompileMode, CompileRequest, OutputContract, RebarMultiGrepReducerRowV1,
    PreparedAggregateExports, PreparedOrderedNfaV15CompileDisposition,
    RebarMixedNativeRowScalarReducerRowV1, RebarMixedNativeRowScalarRouteV1,
    RebarNativeRowScalarOperationV1, RebarNativeRowScalarReducerAotArtifactV1,
    RebarNativeRowScalarReducerAotCompileDeclineV1,
    RebarNativeRowScalarReducerAotCompileDispositionV1, RelocationKind, SectionKind, SymbolBinding,
    SymbolKind, Target, compile, compile_rebar_mixed_native_row_scalar_reducer_aot_v1,
    compile_rebar_native_row_scalar_reducer_aot_v1,
    compile_with_prepared_ordered_nfa_v15_reported,
};
use fre_syntax::RustProfile;

const SOURCE_IDENTITY: [u8; 32] = [0x53; 32];
const MAX_OBJECT_BYTES: usize = 4 * 1024 * 1024;

fn compile_row(source: &str, target: Target) -> fre_aot_regex::CompiledRegex {
    let mut profile = RustProfile::rebar_1_12_4();
    profile.options.unicode = false;
    profile.options.case_insensitive = false;
    compile(
        CompileRequest::new(source, target)
            .profile(profile)
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span),
    )
    .expect("compile public scalar row")
}

fn compile_prepared_source(source: &str, target: Target) -> fre_aot_regex::CompiledRegex {
    let disposition = compile_with_prepared_ordered_nfa_v15_reported(
        CompileRequest::new(source, target)
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span),
        PreparedAggregateExports::NONE,
    )
    .expect("compile public prepared scalar row");
    let PreparedOrderedNfaV15CompileDisposition::Compiled(compiled) = disposition else {
        panic!("public prepared scalar row unexpectedly declined");
    };
    compiled
}

fn compile_prepared_row(target: Target) -> fre_aot_regex::CompiledRegex {
    compile_prepared_source(r"(?-u:[\x00-\xFF])\bfoo\b", target)
}

fn mixed_selected_for(
    target: Target,
    operation: RebarNativeRowScalarOperationV1,
) -> (
    [fre_aot_regex::CompiledRegex; 2],
    RebarNativeRowScalarReducerAotArtifactV1,
) {
    let compiled = [compile_row("a", target), compile_prepared_row(target)];
    let rows = [
        RebarMixedNativeRowScalarReducerRowV1::new(
            &compiled[0],
            0,
            RebarMixedNativeRowScalarRouteV1::Ordinary,
        ),
        RebarMixedNativeRowScalarReducerRowV1::new(
            &compiled[1],
            1,
            RebarMixedNativeRowScalarRouteV1::PreparedOrderedNfaV15,
        ),
    ];
    let disposition = compile_rebar_mixed_native_row_scalar_reducer_aot_v1(
        operation,
        [0x63; 32],
        2,
        32,
        &[0, 1],
        &rows,
        MAX_OBJECT_BYTES,
    )
    .expect("compile public mixed row-scalar reducer");
    let RebarNativeRowScalarReducerAotCompileDispositionV1::Selected(artifact) = disposition else {
        panic!("public mixed row-scalar reducer unexpectedly declined");
    };
    (compiled, artifact)
}

fn selected_for(
    target: Target,
    operation: RebarNativeRowScalarOperationV1,
) -> (
    Vec<fre_aot_regex::CompiledRegex>,
    RebarNativeRowScalarReducerAotArtifactV1,
) {
    let compiled = vec![compile_row("a", target), compile_row("ab", target)];
    let rows = [
        RebarMultiGrepReducerRowV1::new(&compiled[0], 0),
        RebarMultiGrepReducerRowV1::new(&compiled[1], 1),
    ];
    let disposition = compile_rebar_native_row_scalar_reducer_aot_v1(
        operation,
        SOURCE_IDENTITY,
        2,
        3,
        &[0, 1],
        &rows,
        MAX_OBJECT_BYTES,
    )
    .expect("compile public row-scalar reducer");
    let RebarNativeRowScalarReducerAotCompileDispositionV1::Selected(artifact) = disposition else {
        panic!("public row-scalar reducer unexpectedly declined");
    };
    (compiled, artifact)
}

fn assert_static_closure(target: Target) {
    for operation in [
        RebarNativeRowScalarOperationV1::Count,
        RebarNativeRowScalarOperationV1::SpanSum,
    ] {
        let (compiled, artifact) = selected_for(target, operation);
        let rows = [
            RebarMultiGrepReducerRowV1::new(&compiled[0], 0),
            RebarMultiGrepReducerRowV1::new(&compiled[1], 1),
        ];
        assert!(artifact.authenticates_rows(operation, SOURCE_IDENTITY, 2, 3, &[0, 1], &rows,));
        assert!(!artifact.authenticates_rows(operation, SOURCE_IDENTITY, 2, 3, &[1, 0], &rows,));
        assert!(!artifact.authenticates_rows(
            match operation {
                RebarNativeRowScalarOperationV1::Count => {
                    RebarNativeRowScalarOperationV1::SpanSum
                }
                RebarNativeRowScalarOperationV1::SpanSum => {
                    RebarNativeRowScalarOperationV1::Count
                }
            },
            SOURCE_IDENTITY,
            2,
            3,
            &[0, 1],
            &rows,
        ));
        let receipt = artifact.receipt();
        assert_eq!(receipt.target(), target);
        assert_eq!(receipt.operation(), operation);
        assert_eq!(receipt.semantic_runtime_calls(), 0);
        assert_eq!(receipt.reducer_relocations().len(), rows.len());
        assert_eq!(receipt.object_bytes(), artifact.object().len());
        assert_ne!(receipt.operation_identity_sha256(), [0; 32]);
        assert_ne!(receipt.artifact_identity_sha256(), [0; 32]);
        assert!(
            receipt
                .reducer_symbol()
                .starts_with("fre_aot_regex_rebar_row_scalar_v1_")
        );

        let module = artifact.module();
        assert_eq!(module.target(), target);
        assert_eq!(module.symbols().len(), rows.len() + 1);
        assert_eq!(module.relocations(), receipt.reducer_relocations());
        assert_eq!(
            module.required_runtime_symbols().collect::<Vec<_>>(),
            receipt.row_entry_symbols(),
        );
        assert!(module.required_runtime_program().is_none());
        assert!(module.prepared_entry_symbol().is_none());
        assert!(module.prepared_aggregate_exports().is_empty());
        assert_eq!(module.required_prepare_capabilities(), 0);
        assert_eq!(module.symbols()[0].binding, SymbolBinding::Global);
        assert_eq!(module.symbols()[0].kind, SymbolKind::Function);
        assert!(module.symbols()[0].section.is_some());
        assert_ne!(module.symbols()[0].size, 0);
        assert_eq!(
            module
                .sections()
                .iter()
                .filter(|section| section.kind == SectionKind::Text)
                .count(),
            1,
        );
        for (row, symbol) in module.symbols()[1..].iter().enumerate() {
            assert_eq!(symbol.name, receipt.row_entry_symbols()[row]);
            assert_eq!(symbol.binding, SymbolBinding::Global);
            assert_eq!(symbol.kind, SymbolKind::Function);
            assert!(symbol.section.is_none());
        }
        for (row, relocation) in module.relocations().iter().enumerate() {
            assert_eq!(relocation.symbol, row + 1);
            assert_eq!(
                relocation.kind,
                if target.architecture == Architecture::X86_64 {
                    RelocationKind::X86PltRelative32
                } else {
                    RelocationKind::Aarch64Branch26
                },
            );
            assert_eq!(
                relocation.addend,
                if target.architecture == Architecture::X86_64 {
                    -4
                } else {
                    0
                },
            );
        }

        let declined = compile_rebar_native_row_scalar_reducer_aot_v1(
            operation,
            SOURCE_IDENTITY,
            2,
            3,
            &[0, 1],
            &rows,
            1,
        )
        .expect("numeric object cap is a typed decline");
        assert!(matches!(
            declined,
            RebarNativeRowScalarReducerAotCompileDispositionV1::Declined(
                RebarNativeRowScalarReducerAotCompileDeclineV1::ObjectBytes {
                    limit: 1,
                    required,
                }
            ) if required > 1
        ));
    }
}

#[test]
fn x86_64_cross_format_scalar_closure_is_exact() {
    assert_static_closure(Target::x86_64_linux());
    assert_static_closure(Target::x86_64_macos());
}

#[test]
fn aarch64_cross_format_scalar_closure_is_exact() {
    assert_static_closure(Target::aarch64_linux());
    assert_static_closure(Target::aarch64_macos());
}

fn assert_static_mixed_closure(target: Target) {
    for operation in [
        RebarNativeRowScalarOperationV1::Count,
        RebarNativeRowScalarOperationV1::SpanSum,
    ] {
        let (compiled, artifact) = mixed_selected_for(target, operation);
        let rows = [
            RebarMixedNativeRowScalarReducerRowV1::new(
                &compiled[0],
                0,
                RebarMixedNativeRowScalarRouteV1::Ordinary,
            ),
            RebarMixedNativeRowScalarReducerRowV1::new(
                &compiled[1],
                1,
                RebarMixedNativeRowScalarRouteV1::PreparedOrderedNfaV15,
            ),
        ];
        assert!(artifact.authenticates_mixed_rows(
            operation,
            [0x63; 32],
            2,
            32,
            &[0, 1],
            &rows,
        ));
        let wrong_routes = [
            RebarMixedNativeRowScalarReducerRowV1::new(
                &compiled[0],
                0,
                RebarMixedNativeRowScalarRouteV1::PreparedOrderedNfaV15,
            ),
            RebarMixedNativeRowScalarReducerRowV1::new(
                &compiled[1],
                1,
                RebarMixedNativeRowScalarRouteV1::Ordinary,
            ),
        ];
        assert!(!artifact.authenticates_mixed_rows(
            operation,
            [0x63; 32],
            2,
            32,
            &[0, 1],
            &wrong_routes,
        ));
        assert!(!artifact.authenticates_rows(
            operation,
            [0x63; 32],
            2,
            32,
            &[0, 1],
            &[
                RebarMultiGrepReducerRowV1::new(&compiled[0], 0),
                RebarMultiGrepReducerRowV1::new(&compiled[1], 1),
            ],
        ));
        let receipt = artifact.receipt();
        assert!(receipt.uses_mixed_handle_table());
        assert_eq!(receipt.required_handle_count(), 2);
        assert_eq!(
            receipt.row_routes(),
            [
                RebarMixedNativeRowScalarRouteV1::Ordinary,
                RebarMixedNativeRowScalarRouteV1::PreparedOrderedNfaV15,
            ]
        );
        assert_eq!(receipt.semantic_runtime_calls(), 0);
        assert_eq!(receipt.reducer_relocations().len(), 2);
        assert!(
            receipt
                .reducer_symbol()
                .starts_with("fre_aot_regex_rebar_mixed_row_scalar_v1_")
        );
        assert_eq!(
            artifact
                .module()
                .required_runtime_symbols()
                .collect::<Vec<_>>(),
            receipt.row_entry_symbols(),
        );

        let declined = compile_rebar_mixed_native_row_scalar_reducer_aot_v1(
            operation,
            [0x63; 32],
            2,
            32,
            &[0, 1],
            &rows,
            1,
        )
        .expect("mixed numeric object cap is a typed decline");
        assert!(matches!(
            declined,
            RebarNativeRowScalarReducerAotCompileDispositionV1::Declined(
                RebarNativeRowScalarReducerAotCompileDeclineV1::ObjectBytes {
                    limit: 1,
                    required,
                }
            ) if required > 1
        ));
    }
}

#[test]
fn x86_64_cross_format_mixed_scalar_closure_is_exact() {
    assert_static_mixed_closure(Target::x86_64_linux());
    assert_static_mixed_closure(Target::x86_64_macos());
}

#[test]
fn aarch64_cross_format_mixed_scalar_closure_is_exact() {
    assert_static_mixed_closure(Target::aarch64_linux());
    assert_static_mixed_closure(Target::aarch64_macos());
}

#[test]
fn duplicates_are_sealed_and_malformed_priority_is_terminal() {
    let target = Target::x86_64_linux();
    let compiled = [compile_row("a", target), compile_row("b", target)];
    let duplicate = [RebarMultiGrepReducerRowV1::new(&compiled[0], 0)];
    let selected = compile_rebar_native_row_scalar_reducer_aot_v1(
        RebarNativeRowScalarOperationV1::Count,
        SOURCE_IDENTITY,
        2,
        2,
        &[0, 0],
        &duplicate,
        MAX_OBJECT_BYTES,
    )
    .expect("compile deduplicated row topology");
    let RebarNativeRowScalarReducerAotCompileDispositionV1::Selected(selected) = selected else {
        panic!("deduplicated row topology declined");
    };
    assert_eq!(selected.receipt().source_to_row(), [0, 0]);
    assert_eq!(selected.receipt().reducer_relocations().len(), 1);

    let reversed = [
        RebarMultiGrepReducerRowV1::new(&compiled[0], 1),
        RebarMultiGrepReducerRowV1::new(&compiled[1], 0),
    ];
    assert!(
        compile_rebar_native_row_scalar_reducer_aot_v1(
            RebarNativeRowScalarOperationV1::SpanSum,
            SOURCE_IDENTITY,
            2,
            2,
            &[1, 0],
            &reversed,
            MAX_OBJECT_BYTES,
        )
        .is_err()
    );
}

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(target_os = "linux", target_os = "macos")
))]
fn host_target() -> Target {
    if cfg!(all(target_arch = "x86_64", target_os = "linux")) {
        Target::x86_64_linux()
    } else if cfg!(all(target_arch = "x86_64", target_os = "macos")) {
        Target::x86_64_macos()
    } else if cfg!(target_os = "linux") {
        Target::aarch64_linux()
    } else {
        Target::aarch64_macos()
    }
}

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(target_os = "linux", target_os = "macos")
))]
fn host_cc_command(target: Target) -> std::process::Command {
    let mut command = std::process::Command::new("cc");
    #[cfg(target_os = "macos")]
    command.arg("-arch").arg(match target.architecture {
        Architecture::X86_64 => "x86_64",
        Architecture::Aarch64 => "arm64",
    });
    #[cfg(target_os = "linux")]
    assert_eq!(target, host_target(), "Linux link tests are host-ISA only");
    command
}

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(target_os = "linux", target_os = "macos")
))]
fn independent_scalar_oracle(patterns: &[&str], haystack: &[u8]) -> (u64, u64) {
    use regex_automata::meta::Regex;

    let oracle = Regex::builder()
        .configure(Regex::config().utf8_empty(false))
        .syntax(
            regex_automata::util::syntax::Config::new()
                .utf8(false)
                .unicode(false),
        )
        .build_many(patterns)
        .expect("build independent public build-many oracle");
    oracle
        .find_iter(haystack)
        .fold((0_u64, 0_u64), |(count, span_sum), matched| {
            (
                count.checked_add(1).expect("public oracle count fits u64"),
                span_sum
                    .checked_add(
                        u64::try_from(matched.end() - matched.start())
                            .expect("public oracle width fits u64"),
                    )
                    .expect("public oracle span sum fits u64"),
            )
        })
}

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(target_os = "linux", target_os = "macos")
))]
#[test]
#[ignore = "links and executes generated public row-scalar reducers"]
fn linked_host_scalar_reducers_match_priority_empty_progress_and_failure_seams() {
    use std::{fmt::Write as _, fs, process::Command, time::SystemTime};

    let target = host_target();
    let (compiled, count) = selected_for(target, RebarNativeRowScalarOperationV1::Count);
    let (_, span) = selected_for(target, RebarNativeRowScalarOperationV1::SpanSum);
    let reverse_rows = [
        RebarMultiGrepReducerRowV1::new(&compiled[1], 0),
        RebarMultiGrepReducerRowV1::new(&compiled[0], 1),
    ];
    let reverse = compile_rebar_native_row_scalar_reducer_aot_v1(
        RebarNativeRowScalarOperationV1::SpanSum,
        [0x54; 32],
        2,
        3,
        &[0, 1],
        &reverse_rows,
        MAX_OBJECT_BYTES,
    )
    .expect("compile reverse-priority reducer");
    let RebarNativeRowScalarReducerAotCompileDispositionV1::Selected(reverse) = reverse else {
        panic!("reverse-priority reducer declined");
    };
    let empty_compiled = [compile_row("", target)];
    let empty_rows = [RebarMultiGrepReducerRowV1::new(&empty_compiled[0], 0)];
    let empty_count = compile_rebar_native_row_scalar_reducer_aot_v1(
        RebarNativeRowScalarOperationV1::Count,
        [0x55; 32],
        2,
        0,
        &[0, 0],
        &empty_rows,
        MAX_OBJECT_BYTES,
    )
    .expect("compile empty Count reducer");
    let RebarNativeRowScalarReducerAotCompileDispositionV1::Selected(empty_count) = empty_count
    else {
        panic!("empty Count reducer declined");
    };
    let empty_span = compile_rebar_native_row_scalar_reducer_aot_v1(
        RebarNativeRowScalarOperationV1::SpanSum,
        [0x55; 32],
        2,
        0,
        &[0, 0],
        &empty_rows,
        MAX_OBJECT_BYTES,
    )
    .expect("compile empty SpanSum reducer");
    let RebarNativeRowScalarReducerAotCompileDispositionV1::Selected(empty_span) = empty_span
    else {
        panic!("empty SpanSum reducer declined");
    };

    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "fre-rebar-row-scalar-{}-{nonce}",
        std::process::id(),
    ));
    fs::create_dir_all(&directory).expect("create link fixture directory");
    let mut row_paths = Vec::new();
    for (row, component) in compiled.iter().chain(empty_compiled.iter()).enumerate() {
        let path = directory.join(format!("row-{row}.o"));
        fs::write(&path, component.object()).expect("write row object");
        row_paths.push(path);
    }
    let reducers = [&count, &span, &reverse, &empty_count, &empty_span];
    let mut reducer_paths = Vec::new();
    for (index, reducer) in reducers.iter().enumerate() {
        let path = directory.join(format!("reducer-{index}.o"));
        fs::write(&path, reducer.object()).expect("write reducer object");
        reducer_paths.push(path);
    }
    let correctness_c = directory.join("correctness.c");
    let correctness_exe = directory.join("correctness");
    let symbols = reducers
        .iter()
        .map(|artifact| artifact.receipt().reducer_symbol())
        .collect::<Vec<_>>();
    let c_array = |bytes: &[u8]| {
        if bytes.is_empty() {
            "0".to_owned()
        } else {
            bytes
                .iter()
                .map(|byte| format!("0x{byte:02x}"))
                .collect::<Vec<_>>()
                .join(",")
        }
    };
    let mut declarations = String::new();
    let mut calls = String::new();
    let fixed_cases: &[&[u8]] = &[
        b"",
        b"zzzzzzzzzzzzzzzz",
        b"abab",
        b"aaaaaaaaaaaaaaaa",
        b"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzabzzzza",
        &[0xff, b'a', 0, b'a'],
    ];
    for (case, &haystack) in fixed_cases.iter().enumerate() {
        let (count_expected, span_expected) = independent_scalar_oracle(&["a", "ab"], haystack);
        let (_, reverse_expected) = independent_scalar_oracle(&["ab", "a"], haystack);
        writeln!(
            &mut declarations,
            "static const unsigned char fixed_{case}[]={{{}}};",
            c_array(haystack),
        )
        .unwrap();
        writeln!(
            &mut calls,
            "if((r=run({count},fixed_{case},{length},UINT64_C({count_expected}))))return {base}+r;\
             if((r=run({span},fixed_{case},{length},UINT64_C({span_expected}))))return {span_base}+r;\
             if((r=run({reverse},fixed_{case},{length},UINT64_C({reverse_expected}))))return {reverse_base}+r;",
            count = symbols[0],
            span = symbols[1],
            reverse = symbols[2],
            length = haystack.len(),
            base = 100 + case * 100,
            span_base = 130 + case * 100,
            reverse_base = 160 + case * 100,
        )
        .unwrap();
    }
    let empty_cases: &[&[u8]] = &[b"", b"abc", &[0xf0, 0x9f, 0x92, 0xa9], &[0xff, 0, b'x']];
    for (case, &haystack) in empty_cases.iter().enumerate() {
        let (count_expected, span_expected) = independent_scalar_oracle(&["", ""], haystack);
        writeln!(
            &mut declarations,
            "static const unsigned char empty_{case}[]={{{}}};",
            c_array(haystack),
        )
        .unwrap();
        writeln!(
            &mut calls,
            "if((r=run({count},empty_{case},{length},UINT64_C({count_expected}))))return {base}+r;\
             if((r=run({span},empty_{case},{length},UINT64_C({span_expected}))))return {span_base}+r;",
            count = symbols[3],
            span = symbols[4],
            length = haystack.len(),
            base = 1000 + case * 100,
            span_base = 1030 + case * 100,
        )
        .unwrap();
    }
    let source = format!(
        r#"#include <stdint.h>
#include <stddef.h>
extern uint32_t {count}(const unsigned char*,size_t,uint64_t*);
extern uint32_t {span}(const unsigned char*,size_t,uint64_t*);
extern uint32_t {reverse}(const unsigned char*,size_t,uint64_t*);
extern uint32_t {empty_count}(const unsigned char*,size_t,uint64_t*);
extern uint32_t {empty_span}(const unsigned char*,size_t,uint64_t*);
static int run(uint32_t(*f)(const unsigned char*,size_t,uint64_t*),const unsigned char*h,size_t n,uint64_t expected){{uint64_t out=UINT64_C(0xa55ac33cf00f9669);uint32_t s=f(h,n,&out);return s?10+(int)s:(out==expected?0:20);}}
{declarations}
int main(void){{int r;{calls}return 0;}}
"#,
        count = symbols[0],
        span = symbols[1],
        reverse = symbols[2],
        empty_count = symbols[3],
        empty_span = symbols[4],
        declarations = declarations,
        calls = calls,
    );
    fs::write(&correctness_c, source).expect("write correctness harness");
    let output = host_cc_command(target)
        .arg("-O2")
        .arg(&correctness_c)
        .args(&row_paths)
        .args(&reducer_paths)
        .arg("-o")
        .arg(&correctness_exe)
        .output()
        .expect("link correctness harness");
    assert!(
        output.status.success(),
        "correctness link failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        Command::new(&correctness_exe)
            .status()
            .expect("run correctness harness")
            .success()
    );

    let stub_c = directory.join("failure-seams.c");
    let stub_exe = directory.join("failure-seams");
    let entries = count.receipt().row_entry_symbols();
    let mut stub = String::from("#include <stdint.h>\n#include <stddef.h>\n#include <limits.h>\n");
    writeln!(
        &mut stub,
        "extern uint32_t {}(const unsigned char*,size_t,uint64_t*);",
        symbols[0]
    )
    .unwrap();
    writeln!(
        &mut stub,
        "extern uint32_t {}(const unsigned char*,size_t,uint64_t*);",
        symbols[1]
    )
    .unwrap();
    writeln!(&mut stub, "static int mode;").unwrap();
    writeln!(&mut stub, "uint32_t {}(const unsigned char*h,size_t n,size_t s,size_t e,size_t*out){{(void)h;(void)e;if(mode==1){{out[0]=2;out[1]=1;return 1;}}if(mode==2)return 7;if(mode==3){{out[0]=s;out[1]=s;return 1;}}if(mode==4){{out[0]=s;out[1]=s==0?1:s;return 1;}}if(mode==5){{out[0]=s;out[1]=n+1;return 1;}}if(mode==6){{out[0]=0;out[1]=1;return 1;}}if(s==0){{out[0]=0;out[1]=1;return 1;}}return 0;}}", entries[0]).unwrap();
    writeln!(&mut stub, "uint32_t {}(const unsigned char*h,size_t n,size_t s,size_t e,size_t*out){{(void)h;(void)n;(void)e;if(mode==0&&s==0){{out[0]=0;out[1]=2;return 1;}}return 0;}}", entries[1]).unwrap();
    writeln!(
        &mut stub,
        r#"int main(void){{static const unsigned char h[]={{0xf0,0x9f,0x92,0xa9}};uint64_t out;unsigned char bytes[24];mode=0;out=99;if({symbol}(h,4,&out)||out!=1)return 1;out=99;if({span_symbol}(h,4,&out)||out!=1)return 11;mode=1;out=99;if({symbol}(h,4,&out)!=3||out!=99)return 2;out=99;if({span_symbol}(h,4,&out)!=3||out!=99)return 12;mode=2;out=99;if({symbol}(h,4,&out)!=3||out!=99)return 3;out=99;if({span_symbol}(h,4,&out)!=3||out!=99)return 13;mode=3;out=99;if({symbol}(h,4,&out)||out!=5)return 4;out=99;if({span_symbol}(h,4,&out)||out!=0)return 14;mode=4;out=99;if({symbol}(h,4,&out)||out!=4)return 5;out=99;if({span_symbol}(h,4,&out)||out!=1)return 15;mode=5;out=99;if({symbol}(h,4,&out)!=3||out!=99)return 16;out=99;if({span_symbol}(h,4,&out)!=3||out!=99)return 17;mode=6;out=99;if({symbol}(h,4,&out)!=3||out!=99)return 18;out=99;if({span_symbol}(h,4,&out)!=3||out!=99)return 19;out=99;if({symbol}(h,(size_t)-1,&out)!=2||out!=99)return 6;out=99;if({symbol}((const unsigned char*)(uintptr_t)(UINTPTR_MAX-1),4,&out)!=2||out!=99)return 7;for(size_t i=0;i<sizeof(bytes);i++)bytes[i]=0x5a;if({symbol}(h,4,(uint64_t*)(void*)(bytes+1))!=2)return 8;for(size_t i=0;i<sizeof(bytes);i++)if(bytes[i]!=0x5a)return 9;if({symbol}(0,0,&out)!=2||out!=99)return 10;return 0;}}"#,
        symbol = symbols[0],
        span_symbol = symbols[1],
    )
    .unwrap();
    fs::write(&stub_c, stub).expect("write failure-seam harness");
    let output = host_cc_command(target)
        .arg("-O2")
        .arg(&stub_c)
        .arg(&reducer_paths[0])
        .arg(&reducer_paths[1])
        .arg("-o")
        .arg(&stub_exe)
        .output()
        .expect("link failure-seam harness");
    assert!(
        output.status.success(),
        "failure-seam link failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        Command::new(&stub_exe)
            .status()
            .expect("run failure-seam harness")
            .success()
    );
    fs::remove_dir_all(&directory).expect("remove link fixture directory");
}

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(target_os = "linux", target_os = "macos")
))]
#[test]
#[ignore = "links and executes generated public mixed row-scalar reducers"]
fn linked_mixed_scalar_reducers_validate_handles_priority_and_transactions() {
    use std::{fmt::Write as _, fs, process::Command, time::SystemTime};

    let mut targets = vec![host_target()];
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    targets.push(Target::x86_64_macos());

    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "fre-rebar-mixed-row-scalar-{}-{nonce}",
        std::process::id(),
    ));
    fs::create_dir_all(&directory).expect("create mixed link fixture directory");

    for (target_index, target) in targets.into_iter().enumerate() {
        let (compiled, count) =
            mixed_selected_for(target, RebarNativeRowScalarOperationV1::Count);
        let (_, span) = mixed_selected_for(target, RebarNativeRowScalarOperationV1::SpanSum);
        let count_symbol = count.receipt().reducer_symbol();
        let span_symbol = span.receipt().reducer_symbol();
        let entries = count.receipt().row_entry_symbols();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries, span.receipt().row_entry_symbols());

        let count_path = directory.join(format!("mixed-count-{target_index}.o"));
        let span_path = directory.join(format!("mixed-span-{target_index}.o"));
        fs::write(&count_path, count.object()).expect("write mixed Count reducer");
        fs::write(&span_path, span.object()).expect("write mixed SpanSum reducer");
        let source_path = directory.join(format!("mixed-{target_index}.c"));
        let executable = directory.join(format!("mixed-{target_index}"));
        let mut source = String::from(
            "#include <stdint.h>\n#include <stddef.h>\n#include <limits.h>\n#include <string.h>\n",
        );
        writeln!(
            &mut source,
            "extern uint32_t {count_symbol}(void *const*,size_t,const unsigned char*,size_t,uint64_t*);"
        )
        .unwrap();
        writeln!(
            &mut source,
            "extern uint32_t {span_symbol}(void *const*,size_t,const unsigned char*,size_t,uint64_t*);"
        )
        .unwrap();
        source.push_str(
            "static int mode;\nstatic void *const expected_handle=(void*)(uintptr_t)0x1230;\n",
        );
        writeln!(
            &mut source,
            concat!(
                "uint32_t {}(const unsigned char*h,size_t n,size_t s,size_t e,size_t*out){{",
                "(void)h;(void)e;",
                "if(mode==5){{out[0]=s;out[1]=n+1;return 1;}}",
                "if(mode==0&&s==0){{out[0]=0;out[1]=2;return 1;}}",
                "if(mode==2){{out[0]=s;out[1]=s;return 1;}}",
                "return 0;}}"
            ),
            entries[0],
        )
        .unwrap();
        writeln!(
            &mut source,
            concat!(
                "uint32_t {}(void*handle,const unsigned char*h,size_t n,size_t s,size_t e,size_t*out){{",
                "(void)h;(void)e;if(handle!=expected_handle)return 9;",
                "if(mode==3)return 7;",
                "if(mode==4){{out[0]=s;out[1]=n+1;return 1;}}",
                "if((mode==0||mode==1)&&s==0){{out[0]=0;out[1]=3;return 1;}}",
                "return 0;}}"
            ),
            entries[1],
        )
        .unwrap();
        writeln!(
            &mut source,
            r#"
typedef uint32_t (*mixed_fn)(void *const*,size_t,const unsigned char*,size_t,uint64_t*);
static int run(mixed_fn f,void *const*handles,size_t count,const unsigned char*h,size_t n,uint32_t status,uint64_t expected){{
  uint64_t out=UINT64_C(0xa55ac33cf00f9669);uint32_t got=f(handles,count,h,n,&out);
  return got!=status||(status==0?out!=expected:out!=UINT64_C(0xa55ac33cf00f9669));
}}
int main(void){{
  static const unsigned char h[]={{'x','x','x','x'}};
  void *valid[2]={{0,(void*)expected_handle}};void *nonnull_ordinary[2]={{(void*)1,(void*)expected_handle}};void *null_prepared[2]={{0,0}};
  unsigned char unaligned[32];memset(unaligned,0,sizeof(unaligned));
  mode=0;if(run({count_symbol},valid,2,h,4,0,1))return 1;if(run({span_symbol},valid,2,h,4,0,2))return 2;
  mode=1;if(run({count_symbol},valid,2,h,4,0,1))return 3;if(run({span_symbol},valid,2,h,4,0,3))return 4;
  mode=2;if(run({count_symbol},valid,2,h,4,0,5))return 5;if(run({span_symbol},valid,2,h,4,0,0))return 6;
  mode=3;if(run({count_symbol},valid,2,h,4,3,0))return 7;if(run({span_symbol},valid,2,h,4,3,0))return 8;
  mode=4;if(run({count_symbol},valid,2,h,4,3,0))return 9;
  mode=5;if(run({span_symbol},valid,2,h,4,3,0))return 10;
  mode=0;
  if(run({count_symbol},0,2,h,4,2,0))return 11;
  if(run({count_symbol},valid,1,h,4,2,0)||run({count_symbol},valid,3,h,4,2,0))return 12;
  if(run({count_symbol},(void *const*)(void*)(unaligned+1),2,h,4,2,0))return 13;
  if(run({count_symbol},(void *const*)(uintptr_t)(UINTPTR_MAX-7),2,h,4,2,0))return 14;
  if(run({count_symbol},nonnull_ordinary,2,h,4,2,0))return 15;
  if(run({count_symbol},null_prepared,2,h,4,2,0))return 16;
  if(run({count_symbol},valid,2,0,1,2,0))return 17;
  if(run({count_symbol},valid,2,(const unsigned char*)(uintptr_t)(UINTPTR_MAX-1),4,2,0))return 18;
  uint64_t out=9;if({count_symbol}(valid,2,h,4,0)!=2||out!=9)return 19;
  if(run({count_symbol},valid,2,h,(size_t)-1,2,0))return 20;
  if(run({count_symbol},valid,2,h,4,0,1))return 21;
  return 0;
}}
"#,
        )
        .unwrap();
        fs::write(&source_path, source).expect("write mixed C harness");
        let output = host_cc_command(target)
            .arg("-O2")
            .arg(&source_path)
            .arg(&count_path)
            .arg(&span_path)
            .arg("-o")
            .arg(&executable)
            .output()
            .expect("link mixed harness");
        assert!(
            output.status.success(),
            "mixed {target:?} link failed: {}",
            String::from_utf8_lossy(&output.stderr),
        );
        let output = Command::new(&executable)
            .output()
            .expect("run mixed harness");
        assert!(
            output.status.success(),
            "mixed {target:?} harness failed: status={:?} stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        drop(compiled);
    }
    fs::remove_dir_all(directory).expect("remove mixed link fixture directory");
}

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(target_os = "linux", target_os = "macos")
))]
#[test]
#[ignore = "requires `cargo build -p fre-aot-regex-runtime --lib`; links a real prepared V15 handle"]
fn linked_host_mixed_scalar_reducer_uses_one_prepared_handle_table() {
    use std::{fs, process::Command, time::SystemTime};

    let target = host_target();
    let (compiled, count) = mixed_selected_for(target, RebarNativeRowScalarOperationV1::Count);
    let (_, span) = mixed_selected_for(target, RebarNativeRowScalarOperationV1::SpanSum);
    let foreign = compile_prepared_source(r"(?-u:[\x00-\xFF])\bbar\b", target);
    let (program, program_len) = compiled[1]
        .module()
        .required_runtime_program()
        .expect("prepared row runtime program");
    let (foreign_program, foreign_program_len) = foreign
        .module()
        .required_runtime_program()
        .expect("foreign prepared row runtime program");

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

    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "fre-rebar-mixed-row-real-runtime-{}-{nonce}",
        std::process::id(),
    ));
    fs::create_dir_all(&directory).expect("create real-runtime fixture directory");
    let objects = [
        ("ordinary.o", compiled[0].object()),
        ("prepared.o", compiled[1].object()),
        ("foreign.o", foreign.object()),
        ("count.o", count.object()),
        ("span.o", span.object()),
    ];
    let mut paths = Vec::new();
    for (name, object) in objects {
        let path = directory.join(name);
        fs::write(&path, object).expect("write real-runtime object");
        paths.push(path);
    }
    let source = format!(
        r#"#include <stddef.h>
#include <stdint.h>
typedef void *handle_t;
typedef struct {{uint32_t struct_size;uint32_t config_version;uint64_t operation_flags;uint64_t max_start_filter_setup_work;uint64_t max_grep_count_workspace_bytes;uint64_t v2_reserved[4];uint64_t max_handle_bytes;uint64_t max_ordered_nfa_scratch_bytes;uint64_t max_ordered_nfa_setup_work;uint64_t required_capabilities;uint64_t reserved[2];}} prepare_v3_t;
extern const unsigned char {program}[];
extern const unsigned char {foreign_program}[];
extern uint32_t {count}(handle_t const*,size_t,const unsigned char*,size_t,uint64_t*);
extern uint32_t {span}(handle_t const*,size_t,const unsigned char*,size_t,uint64_t*);
extern uint32_t fre_aot_regex_runtime_prepare_exclusive_v3(const unsigned char*,size_t,const prepare_v3_t*,handle_t*);
extern uint32_t fre_aot_regex_runtime_destroy_exclusive_v1(handle_t);
static int run(uint32_t(*f)(handle_t const*,size_t,const unsigned char*,size_t,uint64_t*),handle_t const*t,const unsigned char*h,size_t n,uint64_t expected){{uint64_t out=UINT64_C(0xa55ac33cf00f9669);uint32_t s=f(t,2,h,n,&out);return s||out!=expected;}}
int main(void){{
  const prepare_v3_t config={{112U,3U,UINT64_C(2),UINT64_C(100000000),UINT64_C(67108864),{{0,0,0,0}},UINT64_C(8388608),UINT64_C(8388608),UINT64_C(2000000),UINT64_C(1),{{0,0}}}};
  handle_t right=0,wrong=0;if(fre_aot_regex_runtime_prepare_exclusive_v3({program},{program_len}U,&config,&right)!=0U||!right)return 1;if(fre_aot_regex_runtime_prepare_exclusive_v3({foreign_program},{foreign_program_len}U,&config,&wrong)!=0U||!wrong)return 2;
  handle_t table[2]={{0,right}},wrong_table[2]={{0,wrong}};
  static const unsigned char empty[]={{0}},a[]={{'a'}},foo[]={{'!','f','o','o'}},many[]={{'a',' ','!','f','o','o',' ','a','a'}},negative[]={{'!','f','o','o','d'}};
  for(unsigned round=0;round<8U;round++){{if(run({count},table,empty,0,0)||run({span},table,empty,0,0))return 3;if(run({count},table,a,sizeof(a),1)||run({span},table,a,sizeof(a),1))return 4;if(run({count},table,foo,sizeof(foo),1)||run({span},table,foo,sizeof(foo),4))return 5;if(run({count},table,many,sizeof(many),4)||run({span},table,many,sizeof(many),7))return 6;if(run({count},table,negative,sizeof(negative),0)||run({span},table,negative,sizeof(negative),0))return 7;}}
  uint64_t out=UINT64_C(0x1122334455667788);if({count}(wrong_table,2,foo,sizeof(foo),&out)!=3U||out!=UINT64_C(0x1122334455667788))return 8;
  if(fre_aot_regex_runtime_destroy_exclusive_v1(right)!=0U)return 9;if(fre_aot_regex_runtime_destroy_exclusive_v1(wrong)!=0U)return 10;return 0;
}}
"#,
        count = count.receipt().reducer_symbol(),
        span = span.receipt().reducer_symbol(),
    );
    let source_path = directory.join("real-runtime.c");
    let executable = directory.join("real-runtime");
    fs::write(&source_path, source).expect("write real-runtime C harness");
    let output = host_cc_command(target)
        .arg("-O2")
        .arg(&source_path)
        .args(&paths)
        .arg(&static_runtime)
        .arg("-o")
        .arg(&executable)
        .output()
        .expect("link real-runtime mixed harness");
    assert!(
        output.status.success(),
        "real-runtime mixed link failed: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let output = Command::new(&executable)
        .output()
        .expect("run real-runtime mixed harness");
    assert!(
        output.status.success(),
        "real-runtime mixed harness failed: status={:?} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
    );
    fs::remove_dir_all(directory).expect("remove real-runtime fixture directory");
}

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
#[test]
#[ignore = "cross-links and executes the affected macOS x86-64 reducer under Rosetta"]
fn linked_x86_64_macos_span_sum_preserves_late_cursor_and_empty_progress() {
    use std::{fmt::Write as _, fs, process::Command, time::SystemTime};

    let target = Target::x86_64_macos();
    let (compiled, count) = selected_for(target, RebarNativeRowScalarOperationV1::Count);
    let (_, span) = selected_for(target, RebarNativeRowScalarOperationV1::SpanSum);
    let empty_compiled = [compile_row("", target)];
    let empty_rows = [RebarMultiGrepReducerRowV1::new(&empty_compiled[0], 0)];
    let compile_empty = |operation| {
        let disposition = compile_rebar_native_row_scalar_reducer_aot_v1(
            operation,
            [0x55; 32],
            2,
            0,
            &[0, 0],
            &empty_rows,
            MAX_OBJECT_BYTES,
        )
        .expect("compile x86-64 empty reducer");
        let RebarNativeRowScalarReducerAotCompileDispositionV1::Selected(selected) = disposition
        else {
            panic!("x86-64 empty reducer declined");
        };
        selected
    };
    let empty_count = compile_empty(RebarNativeRowScalarOperationV1::Count);
    let empty_span = compile_empty(RebarNativeRowScalarOperationV1::SpanSum);
    let reducers = [&count, &span, &empty_count, &empty_span];
    let symbols = reducers
        .iter()
        .map(|artifact| artifact.receipt().reducer_symbol())
        .collect::<Vec<_>>();

    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "fre-rebar-row-scalar-x86-{}-{nonce}",
        std::process::id(),
    ));
    fs::create_dir_all(&directory).expect("create x86-64 link fixture directory");
    let mut objects = Vec::new();
    for (index, component) in compiled.iter().chain(empty_compiled.iter()).enumerate() {
        let path = directory.join(format!("row-{index}.o"));
        fs::write(&path, component.object()).expect("write x86-64 row object");
        objects.push(path);
    }
    for (index, reducer) in reducers.iter().enumerate() {
        let path = directory.join(format!("reducer-{index}.o"));
        fs::write(&path, reducer.object()).expect("write x86-64 reducer object");
        objects.push(path);
    }

    let late = b"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzabzzzza";
    let binary = [0xf0, 0x9f, 0x92, 0xa9];
    let (late_count, late_span) = independent_scalar_oracle(&["a", "ab"], late);
    let (empty_expected, empty_span_expected) = independent_scalar_oracle(&["", ""], &binary);
    let c_array = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("0x{byte:02x}"))
            .collect::<Vec<_>>()
            .join(",")
    };
    let mut source =
        String::from("#include <stdint.h>\n#include <stddef.h>\n#include <unistd.h>\n");
    for symbol in &symbols {
        writeln!(
            &mut source,
            "extern uint32_t {symbol}(const unsigned char*,size_t,uint64_t*);"
        )
        .unwrap();
    }
    writeln!(
        &mut source,
        "static const unsigned char late[]={{{}}};\nstatic const unsigned char binary[]={{{}}};",
        c_array(late),
        c_array(&binary),
    )
    .unwrap();
    writeln!(
        &mut source,
        "static int run(uint32_t(*f)(const unsigned char*,size_t,uint64_t*),const unsigned char*h,size_t n,uint64_t expected){{uint64_t out=99;uint32_t status=f(h,n,&out);return status||out!=expected;}}\nint main(void){{alarm(10);if(run({},late,sizeof(late),UINT64_C({late_count})))return 1;if(run({},late,sizeof(late),UINT64_C({late_span})))return 2;if(run({},binary,sizeof(binary),UINT64_C({empty_expected})))return 3;if(run({},binary,sizeof(binary),UINT64_C({empty_span_expected})))return 4;return 0;}}",
        symbols[0], symbols[1], symbols[2], symbols[3],
    )
    .unwrap();
    let source_path = directory.join("correctness.c");
    let executable = directory.join("correctness");
    fs::write(&source_path, source).expect("write x86-64 correctness harness");
    let output = host_cc_command(target)
        .arg("-O2")
        .arg(&source_path)
        .args(&objects)
        .arg("-o")
        .arg(&executable)
        .output()
        .expect("link x86-64 correctness harness");
    assert!(
        output.status.success(),
        "x86-64 correctness link failed: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let output = Command::new(&executable)
        .output()
        .expect("execute x86-64 correctness harness");
    assert!(
        output.status.success(),
        "x86-64 reducer failed or timed out: status={:?} stdout={} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    fs::remove_dir_all(directory).expect("remove x86-64 link fixture directory");
}
