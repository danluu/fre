use fre_aot_regex::{
    Architecture, CompileMode, CompileRequest, OutputContract, PreparedAggregateExports,
    PreparedOrderedNfaV15CompileDisposition,
    RebarMultiGrepReducerAotCompileDeclineV1, RebarMultiGrepReducerAotCompileDispositionV1,
    RebarMixedMultiGrepReducerRowV1, RebarMixedNativeRowScalarRouteV1,
    RebarMultiGrepReducerRowV1, RelocationKind, SectionKind, SymbolBinding, SymbolKind, Target,
    compile, compile_rebar_mixed_multi_grep_reducer_aot_v1,
    compile_rebar_multi_grep_reducer_aot_v1, compile_with_prepared_ordered_nfa_v15_reported,
};
use fre_syntax::RustProfile;

const SOURCE_IDENTITY: [u8; 32] = [0x71; 32];
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
    .expect("compile public generated grep row")
}

fn compile_prepared_source(source: &str, target: Target) -> fre_aot_regex::CompiledRegex {
    let disposition = compile_with_prepared_ordered_nfa_v15_reported(
        CompileRequest::new(source, target)
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span),
        PreparedAggregateExports::NONE,
    )
    .expect("compile public prepared grep row");
    let PreparedOrderedNfaV15CompileDisposition::Compiled(compiled) = disposition else {
        panic!("public prepared grep row unexpectedly declined");
    };
    compiled
}

fn mixed_selected_for(
    target: Target,
) -> (
    [fre_aot_regex::CompiledRegex; 2],
    fre_aot_regex::RebarMultiGrepReducerAotArtifactV1,
) {
    let compiled = [
        compile_row("^ordinary$", target),
        compile_prepared_source(r"(?-u:[\x00-\xFF])\bfoo\b", target),
    ];
    let rows = [
        RebarMixedMultiGrepReducerRowV1::new(
            &compiled[0],
            0,
            RebarMixedNativeRowScalarRouteV1::Ordinary,
        ),
        RebarMixedMultiGrepReducerRowV1::new(
            &compiled[1],
            1,
            RebarMixedNativeRowScalarRouteV1::PreparedOrderedNfaV15,
        ),
    ];
    let disposition = compile_rebar_mixed_multi_grep_reducer_aot_v1(
        [0x72; 32],
        2,
        40,
        &[0, 1],
        &rows,
        MAX_OBJECT_BYTES,
    )
    .expect("compile public mixed multi-grep reducer");
    let RebarMultiGrepReducerAotCompileDispositionV1::Selected(artifact) = disposition else {
        panic!("public mixed multi-grep reducer unexpectedly declined");
    };
    (compiled, artifact)
}

fn selected_for(
    target: Target,
) -> (
    Vec<fre_aot_regex::CompiledRegex>,
    fre_aot_regex::RebarMultiGrepReducerAotArtifactV1,
) {
    let compiled = vec![compile_row("^foo$", target), compile_row("^bar$", target)];
    let rows = [
        RebarMultiGrepReducerRowV1::new(&compiled[0], 0),
        RebarMultiGrepReducerRowV1::new(&compiled[1], 1),
    ];
    let disposition = compile_rebar_multi_grep_reducer_aot_v1(
        SOURCE_IDENTITY,
        2,
        10,
        &[0, 1],
        &rows,
        4 * 1024 * 1024,
    )
    .expect("compile public multi-grep reducer");
    let RebarMultiGrepReducerAotCompileDispositionV1::Selected(artifact) = disposition else {
        panic!("public reducer unexpectedly declined");
    };
    (compiled, artifact)
}

fn assert_static_closure(target: Target) {
    let (compiled, artifact) = selected_for(target);
    let rows = [
        RebarMultiGrepReducerRowV1::new(&compiled[0], 0),
        RebarMultiGrepReducerRowV1::new(&compiled[1], 1),
    ];
    assert!(artifact.authenticates_rows(SOURCE_IDENTITY, 2, 10, &[0, 1], &rows));
    assert!(!artifact.authenticates_rows(SOURCE_IDENTITY, 2, 10, &[1, 0], &rows));
    let receipt = artifact.receipt();
    assert_eq!(receipt.semantic_runtime_calls(), 0);
    assert_eq!(receipt.reducer_relocation_count(), rows.len());
    assert_eq!(receipt.object_bytes(), artifact.object().len());
    assert_ne!(receipt.operation_identity_sha256(), [0; 32]);
    assert_ne!(receipt.artifact_identity_sha256(), [0; 32]);
    assert!(
        receipt
            .reducer_symbol()
            .starts_with("fre_aot_regex_rebar_multi_grep_v1_")
    );

    let module = artifact.module();
    assert_eq!(module.target(), target);
    assert_eq!(module.symbols().len(), rows.len() + 1);
    assert_eq!(module.relocations().len(), rows.len());
    assert_eq!(
        module.required_runtime_symbols().collect::<Vec<_>>(),
        receipt.row_entry_symbols()
    );
    assert!(module.required_runtime_program().is_none());
    assert!(module.prepared_entry_symbol().is_none());
    assert!(module.prepared_aggregate_exports().is_empty());
    assert_eq!(module.required_prepare_capabilities(), 0);
    assert_eq!(module.symbols()[0].binding, SymbolBinding::Global);
    assert_eq!(module.symbols()[0].kind, SymbolKind::Function);
    assert!(module.symbols()[0].section.is_some());
    assert!(module.symbols()[0].size != 0);
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

    let declined =
        compile_rebar_multi_grep_reducer_aot_v1(SOURCE_IDENTITY, 2, 10, &[0, 1], &rows, 1)
            .expect("numeric object cap is a typed decline");
    assert!(matches!(
        declined,
        RebarMultiGrepReducerAotCompileDispositionV1::Declined(
            RebarMultiGrepReducerAotCompileDeclineV1::ObjectBytes {
                limit: 1,
                required
            }
        ) if required > 1
    ));

    let duplicate_row = [RebarMultiGrepReducerRowV1::new(&compiled[0], 0)];
    let duplicate_sources = compile_rebar_multi_grep_reducer_aot_v1(
        SOURCE_IDENTITY,
        2,
        10,
        &[0, 0],
        &duplicate_row,
        4 * 1024 * 1024,
    )
    .expect("compile deduplicated single-row reducer");
    let RebarMultiGrepReducerAotCompileDispositionV1::Selected(duplicate_sources) =
        duplicate_sources
    else {
        panic!("deduplicated single-row reducer unexpectedly declined");
    };
    assert_eq!(duplicate_sources.module().relocations().len(), 1);
    assert!(duplicate_sources.authenticates_rows(SOURCE_IDENTITY, 2, 10, &[0, 0], &duplicate_row,));

    let empty = compile_row("", target);
    let empty_row = [RebarMultiGrepReducerRowV1::new(&empty, 0)];
    let empty_sources = compile_rebar_multi_grep_reducer_aot_v1(
        SOURCE_IDENTITY,
        2,
        0,
        &[0, 0],
        &empty_row,
        4 * 1024 * 1024,
    )
    .expect("zero total source bytes are a valid authenticated regex shape");
    let RebarMultiGrepReducerAotCompileDispositionV1::Selected(empty_sources) = empty_sources
    else {
        panic!("empty source reducer unexpectedly declined");
    };
    assert!(empty_sources.authenticates_rows(SOURCE_IDENTITY, 2, 0, &[0, 0], &empty_row));
}

#[test]
fn x86_64_cross_format_reducer_closure_is_exact() {
    assert_static_closure(Target::x86_64_linux());
    assert_static_closure(Target::x86_64_macos());
}

#[test]
fn aarch64_cross_format_reducer_closure_is_exact() {
    assert_static_closure(Target::aarch64_linux());
    assert_static_closure(Target::aarch64_macos());
}

fn assert_static_mixed_closure(target: Target) {
    let (compiled, artifact) = mixed_selected_for(target);
    let rows = [
        RebarMixedMultiGrepReducerRowV1::new(
            &compiled[0],
            0,
            RebarMixedNativeRowScalarRouteV1::Ordinary,
        ),
        RebarMixedMultiGrepReducerRowV1::new(
            &compiled[1],
            1,
            RebarMixedNativeRowScalarRouteV1::PreparedOrderedNfaV15,
        ),
    ];
    assert!(artifact.authenticates_mixed_rows([0x72; 32], 2, 40, &[0, 1], &rows));
    assert!(!artifact.authenticates_mixed_rows([0x72; 32], 2, 40, &[1, 0], &rows));
    let wrong_routes = [
        RebarMixedMultiGrepReducerRowV1::new(
            &compiled[0],
            0,
            RebarMixedNativeRowScalarRouteV1::PreparedOrderedNfaV15,
        ),
        RebarMixedMultiGrepReducerRowV1::new(
            &compiled[1],
            1,
            RebarMixedNativeRowScalarRouteV1::Ordinary,
        ),
    ];
    assert!(!artifact.authenticates_mixed_rows(
        [0x72; 32],
        2,
        40,
        &[0, 1],
        &wrong_routes,
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
    assert_eq!(receipt.reducer_relocation_count(), 2);
    assert_eq!(receipt.semantic_runtime_calls(), 0);
    assert!(
        receipt
            .reducer_symbol()
            .starts_with("fre_aot_regex_rebar_mixed_multi_grep_v1_")
    );
    assert_eq!(
        artifact
            .module()
            .required_runtime_symbols()
            .collect::<Vec<_>>(),
        receipt.row_entry_symbols(),
    );
    let declined = compile_rebar_mixed_multi_grep_reducer_aot_v1(
        [0x72; 32],
        2,
        40,
        &[0, 1],
        &rows,
        1,
    )
    .expect("mixed numeric object cap is a typed decline");
    assert!(matches!(
        declined,
        RebarMultiGrepReducerAotCompileDispositionV1::Declined(
            RebarMultiGrepReducerAotCompileDeclineV1::ObjectBytes {
                limit: 1,
                required,
            }
        ) if required > 1
    ));
}

#[test]
fn x86_64_cross_format_mixed_reducer_closure_is_exact() {
    assert_static_mixed_closure(Target::x86_64_linux());
    assert_static_mixed_closure(Target::x86_64_macos());
}

#[test]
fn aarch64_cross_format_mixed_reducer_closure_is_exact() {
    assert_static_mixed_closure(Target::aarch64_linux());
    assert_static_mixed_closure(Target::aarch64_macos());
}

#[test]
fn malformed_source_priority_topology_is_terminal() {
    let compiled = [
        compile_row("foo", Target::x86_64_linux()),
        compile_row("bar", Target::x86_64_linux()),
    ];
    let rows = [
        RebarMultiGrepReducerRowV1::new(&compiled[0], 1),
        RebarMultiGrepReducerRowV1::new(&compiled[1], 0),
    ];
    assert!(
        compile_rebar_multi_grep_reducer_aot_v1(
            SOURCE_IDENTITY,
            2,
            6,
            &[1, 0],
            &rows,
            4 * 1024 * 1024,
        )
        .is_err()
    );
}

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(target_os = "linux", target_os = "macos")
))]
fn host_cc_command() -> std::process::Command {
    let mut command = std::process::Command::new("cc");
    #[cfg(target_os = "macos")]
    command.arg("-arch").arg(if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else {
        "arm64"
    });
    command
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
fn target_cc_command(target: Target) -> std::process::Command {
    let mut command = std::process::Command::new("cc");
    #[cfg(target_os = "macos")]
    command.arg("-arch").arg(if target.architecture == Architecture::X86_64 {
        "x86_64"
    } else {
        "arm64"
    });
    command
}

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(target_os = "linux", target_os = "macos")
))]
#[test]
#[ignore = "links and executes generated public mixed multi-grep reducers"]
fn linked_mixed_reducer_validates_lines_every_row_handles_and_transactions() {
    use std::{fmt::Write as _, fs, process::Command, time::SystemTime};

    let mut targets = vec![host_target()];
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    targets.push(Target::x86_64_macos());
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "fre-rebar-mixed-multi-grep-{}-{nonce}",
        std::process::id(),
    ));
    fs::create_dir_all(&directory).expect("create mixed Grep fixture directory");

    for (target_index, target) in targets.into_iter().enumerate() {
        let (_, artifact) = mixed_selected_for(target);
        let symbol = artifact.receipt().reducer_symbol();
        let entries = artifact.receipt().row_entry_symbols();
        let reducer_path = directory.join(format!("reducer-{target_index}.o"));
        fs::write(&reducer_path, artifact.object()).expect("write mixed Grep reducer");
        let source_path = directory.join(format!("mixed-{target_index}.c"));
        let executable = directory.join(format!("mixed-{target_index}"));
        let mut source = String::from(
            "#include <stdint.h>\n#include <stddef.h>\n#include <limits.h>\n#include <string.h>\n",
        );
        writeln!(
            &mut source,
            "extern uint32_t {symbol}(void *const*,size_t,const unsigned char*,size_t,uint64_t*);"
        )
        .unwrap();
        source.push_str(
            "static unsigned ordinary_calls,prepared_calls;static int mode;static void *const expected_handle=(void*)(uintptr_t)0x1230;\n",
        );
        writeln!(
            &mut source,
            concat!(
                "uint32_t {}(const unsigned char*h,size_t n,size_t s,size_t e,size_t*out){{",
                "(void)s;(void)e;ordinary_calls++;",
                "if(mode==2){{out[0]=0;out[1]=n+1;return 1;}}",
                "if(n==1&&h[0]=='o'){{out[0]=0;out[1]=1;return 1;}}return 0;}}"
            ),
            entries[0],
        )
        .unwrap();
        writeln!(
            &mut source,
            concat!(
                "uint32_t {}(void*handle,const unsigned char*h,size_t n,size_t s,size_t e,size_t*out){{",
                "(void)s;(void)e;prepared_calls++;if(handle!=expected_handle)return 9;",
                "if(mode==1)return 7;if(mode==3){{out[0]=0;out[1]=n+1;return 1;}}",
                "if(n==1&&h[0]=='p'){{out[0]=0;out[1]=1;return 1;}}return 0;}}"
            ),
            entries[1],
        )
        .unwrap();
        writeln!(
            &mut source,
            r#"
static int run(void *const*table,size_t count,const unsigned char*h,size_t n,uint32_t status,uint64_t expected){{
  uint64_t out=UINT64_C(0xa55ac33cf00f9669);uint32_t got={symbol}(table,count,h,n,&out);
  return got!=status||(status==0?out!=expected:out!=UINT64_C(0xa55ac33cf00f9669));
}}
int main(void){{
  static const unsigned char lines[]={{'o','\r','\n','p','\n','x','\n'}};
  static const unsigned char final_cr[]={{'o','\r'}};static const unsigned char one_lf[]={{'\n'}};
  void *valid[2]={{0,(void*)expected_handle}},*wrong[2]={{0,(void*)(uintptr_t)0x4560}};
  void *nonnull_ordinary[2]={{(void*)1,(void*)expected_handle}},*null_prepared[2]={{0,0}};
  unsigned char unaligned[32];memset(unaligned,0,sizeof(unaligned));
  mode=0;ordinary_calls=prepared_calls=0;if(run(valid,2,lines,sizeof(lines),0,2))return 1;if(ordinary_calls!=3||prepared_calls!=3)return 2;
  ordinary_calls=prepared_calls=0;if(run(valid,2,(const unsigned char*)"",0,0,0))return 3;if(ordinary_calls||prepared_calls)return 4;
  ordinary_calls=prepared_calls=0;if(run(valid,2,one_lf,sizeof(one_lf),0,0))return 5;if(ordinary_calls!=1||prepared_calls!=1)return 6;
  if(run(valid,2,final_cr,sizeof(final_cr),0,0))return 7;
  mode=1;ordinary_calls=prepared_calls=0;if(run(valid,2,lines,sizeof(lines),3,0))return 8;if(!ordinary_calls||!prepared_calls)return 9;
  mode=2;if(run(valid,2,lines,sizeof(lines),3,0))return 10;
  mode=3;if(run(valid,2,lines,sizeof(lines),3,0))return 11;
  mode=0;if(run(wrong,2,lines,sizeof(lines),3,0))return 12;
  if(run(0,2,lines,sizeof(lines),2,0))return 13;
  if(run(valid,1,lines,sizeof(lines),2,0)||run(valid,3,lines,sizeof(lines),2,0))return 14;
  if(run((void *const*)(void*)(unaligned+1),2,lines,sizeof(lines),2,0))return 15;
  if(run((void *const*)(uintptr_t)(UINTPTR_MAX-7),2,lines,sizeof(lines),2,0))return 16;
  if(run(nonnull_ordinary,2,lines,sizeof(lines),2,0)||run(null_prepared,2,lines,sizeof(lines),2,0))return 17;
  if(run(valid,2,0,1,2,0))return 18;
  if(run(valid,2,(const unsigned char*)(uintptr_t)(UINTPTR_MAX-1),4,2,0))return 19;
  if(run(valid,2,lines,(size_t)-1,2,0))return 20;
  uint64_t out=9;if({symbol}(valid,2,lines,sizeof(lines),0)!=2||out!=9)return 21;
  if({symbol}(valid,2,lines,sizeof(lines),(uint64_t*)(void*)(unaligned+1))!=2)return 22;
  for(size_t i=0;i<sizeof(unaligned);i++)if(unaligned[i]!=0)return 23;
  return 0;
}}
"#,
        )
        .unwrap();
        fs::write(&source_path, source).expect("write mixed Grep C harness");
        let output = target_cc_command(target)
            .arg("-O2")
            .arg(&source_path)
            .arg(&reducer_path)
            .arg("-o")
            .arg(&executable)
            .output()
            .expect("link mixed Grep harness");
        assert!(
            output.status.success(),
            "mixed Grep {target:?} link failed: {}",
            String::from_utf8_lossy(&output.stderr),
        );
        let output = Command::new(&executable)
            .output()
            .expect("run mixed Grep harness");
        assert!(
            output.status.success(),
            "mixed Grep {target:?} harness failed: status={:?} stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    fs::remove_dir_all(directory).expect("remove mixed Grep fixture directory");
}

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(target_os = "linux", target_os = "macos")
))]
#[test]
#[ignore = "requires the runtime static library; links a real prepared V15 handle"]
fn linked_host_mixed_reducer_matches_the_prior_adapter_with_real_prepared_handles() {
    use std::{fs, process::Command, time::SystemTime};

    let target = host_target();
    let (compiled, artifact) = mixed_selected_for(target);
    let foreign = compile_prepared_source(r"(?-u:[\x00-\xFF])\bbar\b", target);
    let (program, program_len) = compiled[1]
        .module()
        .required_runtime_program()
        .expect("prepared Grep row runtime program");
    let (foreign_program, foreign_program_len) = foreign
        .module()
        .required_runtime_program()
        .expect("foreign prepared Grep row runtime program");
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
        "fre-rebar-mixed-grep-real-runtime-{}-{nonce}",
        std::process::id(),
    ));
    fs::create_dir_all(&directory).expect("create real-runtime Grep fixture directory");
    let objects = [
        ("ordinary.o", compiled[0].object()),
        ("prepared.o", compiled[1].object()),
        ("foreign.o", foreign.object()),
        ("reducer.o", artifact.object()),
    ];
    let mut paths = Vec::new();
    for (name, object) in objects {
        let path = directory.join(name);
        fs::write(&path, object).expect("write real-runtime Grep object");
        paths.push(path);
    }
    let entries = artifact.receipt().row_entry_symbols();
    let source = format!(
        r#"#include <stddef.h>
#include <stdint.h>
typedef void *handle_t;
typedef struct {{uint32_t struct_size;uint32_t config_version;uint64_t operation_flags;uint64_t max_start_filter_setup_work;uint64_t max_grep_count_workspace_bytes;uint64_t v2_reserved[4];uint64_t max_handle_bytes;uint64_t max_ordered_nfa_scratch_bytes;uint64_t max_ordered_nfa_setup_work;uint64_t required_capabilities;uint64_t reserved[2];}} prepare_v3_t;
extern const unsigned char {program}[];
extern const unsigned char {foreign_program}[];
extern uint32_t {ordinary}(const unsigned char*,size_t,size_t,size_t,size_t*);
extern uint32_t {prepared}(handle_t,const unsigned char*,size_t,size_t,size_t,size_t*);
extern uint32_t {reducer}(handle_t const*,size_t,const unsigned char*,size_t,uint64_t*);
extern uint32_t fre_aot_regex_runtime_prepare_exclusive_v3(const unsigned char*,size_t,const prepare_v3_t*,handle_t*);
extern uint32_t fre_aot_regex_runtime_destroy_exclusive_v1(handle_t);
static uint32_t adapter(handle_t handle,const unsigned char*h,size_t n,uint64_t*out){{
  uint64_t total=0;if(!n){{*out=0;return 0;}}size_t cursor=0;
  for(;;){{size_t start=cursor,end=cursor;while(end<n&&h[end]!=10)end++;int lf=end<n;if(lf)cursor=end+1;else cursor=end;size_t line_end=end;if(lf&&line_end>start&&h[line_end-1]==13)line_end--;size_t len=line_end-start;size_t result[2];int matched=0;
    result[0]=result[1]=(size_t)-1;uint32_t s={ordinary}(h+start,len,0,len,result);if(s>1)return 3;if(s==1){{if(result[0]>result[1]||result[1]>len)return 3;matched=1;}}
    result[0]=result[1]=(size_t)-1;s={prepared}(handle,h+start,len,0,len,result);if(s>1)return 3;if(s==1){{if(result[0]>result[1]||result[1]>len)return 3;matched=1;}}
    if(matched){{if(total==UINT64_MAX)return 3;total++;}}if(cursor==n)break;
  }}*out=total;return 0;
}}
static int compare(handle_t const*table,const unsigned char*h,size_t n){{uint64_t a=UINT64_C(0x1111),b=UINT64_C(0x2222);uint32_t sa=adapter(table[1],h,n,&a),sb={reducer}(table,2,h,n,&b);return sa!=sb||a!=b;}}
int main(void){{
  const prepare_v3_t config={{112U,3U,UINT64_C(2),UINT64_C(100000000),UINT64_C(67108864),{{0,0,0,0}},UINT64_C(8388608),UINT64_C(8388608),UINT64_C(2000000),UINT64_C(1),{{0,0}}}};
  handle_t right=0,wrong=0;if(fre_aot_regex_runtime_prepare_exclusive_v3({program},{program_len}U,&config,&right)!=0U||!right)return 1;if(fre_aot_regex_runtime_prepare_exclusive_v3({foreign_program},{foreign_program_len}U,&config,&wrong)!=0U||!wrong)return 2;
  handle_t table[2]={{0,right}},wrong_table[2]={{0,wrong}};
  static const unsigned char empty[]={{0}},one[]="ordinary",lines[]="ordinary\r\n!foo!\nno\n",crlf[]="ordinary\r\n!foo!\r\nfood\r\nfoo",final_cr[]="ordinary\r",binary[]={{0,'f','o','o',0,'\n','o','r','d','i','n','a','r','y'}};
  for(unsigned round=0;round<16U;round++){{if(compare(table,empty,0))return 3;if(compare(table,one,sizeof(one)-1))return 4;if(compare(table,lines,sizeof(lines)-1))return 5;if(compare(table,crlf,sizeof(crlf)-1))return 6;if(compare(table,final_cr,sizeof(final_cr)-1))return 7;if(compare(table,binary,sizeof(binary)))return 8;}}
  uint64_t out=UINT64_C(0x1122334455667788);if({reducer}(wrong_table,2,lines,sizeof(lines)-1,&out)!=3U||out!=UINT64_C(0x1122334455667788))return 9;
  if(fre_aot_regex_runtime_destroy_exclusive_v1(right)!=0U)return 10;if(fre_aot_regex_runtime_destroy_exclusive_v1(wrong)!=0U)return 11;return 0;
}}
"#,
        ordinary = entries[0],
        prepared = entries[1],
        reducer = artifact.receipt().reducer_symbol(),
    );
    let source_path = directory.join("real-runtime.c");
    let executable = directory.join("real-runtime");
    fs::write(&source_path, source).expect("write real-runtime Grep C harness");
    let output = target_cc_command(target)
        .arg("-O2")
        .arg(&source_path)
        .args(&paths)
        .arg(&static_runtime)
        .arg("-o")
        .arg(&executable)
        .output()
        .expect("link real-runtime mixed Grep harness");
    assert!(
        output.status.success(),
        "real-runtime mixed Grep link failed: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let output = Command::new(&executable)
        .output()
        .expect("run real-runtime mixed Grep harness");
    assert!(
        output.status.success(),
        "real-runtime mixed Grep harness failed: status={:?} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
    );

    let timing_source = format!(
        r#"use std::{{ffi::c_void, hint::black_box, time::Instant}};
type Handle = *mut c_void;
#[repr(C)]
struct PrepareV3 {{ struct_size:u32, config_version:u32, operation_flags:u64, max_start_filter_setup_work:u64, max_grep_count_workspace_bytes:u64, v2_reserved:[u64;4], max_handle_bytes:u64, max_ordered_nfa_scratch_bytes:u64, max_ordered_nfa_setup_work:u64, required_capabilities:u64, reserved:[u64;2] }}
unsafe extern "C" {{
  #[link_name="{program}"] static PROGRAM:u8;
  #[link_name="{ordinary}"] fn ordinary(h:*const u8,n:usize,s:usize,e:usize,out:*mut usize)->u32;
  #[link_name="{prepared}"] fn prepared(handle:Handle,h:*const u8,n:usize,s:usize,e:usize,out:*mut usize)->u32;
  #[link_name="{reducer}"] fn reducer(table:*const Handle,count:usize,h:*const u8,n:usize,out:*mut u64)->u32;
  fn fre_aot_regex_runtime_prepare_exclusive_v3(program:*const u8,n:usize,config:*const PrepareV3,out:*mut Handle)->u32;
  fn fre_aot_regex_runtime_destroy_exclusive_v1(handle:Handle)->u32;
}}
fn adapter(handle:Handle,h:&[u8],out:&mut u64)->u32 {{
  if h.is_empty() {{ *out=0; return 0; }}
  let mut total=0u64; let mut cursor=0usize;
  loop {{
    let start=cursor; let mut end=cursor; while end<h.len() && h[end]!=b'\n' {{ end+=1; }}
    let lf=end<h.len(); cursor=if lf {{ end+1 }} else {{ end }};
    let line_end=if lf && end>start && h[end-1]==b'\r' {{ end-1 }} else {{ end }};
    let line=&h[start..line_end]; let mut span=[usize::MAX;2]; let mut matched=false;
    let status=unsafe {{ ordinary(line.as_ptr(),line.len(),0,line.len(),span.as_mut_ptr()) }};
    if status>1 || (status==1 && (span[0]>span[1] || span[1]>line.len())) {{ return 3; }}
    matched |= status==1; span=[usize::MAX;2];
    let status=unsafe {{ prepared(handle,line.as_ptr(),line.len(),0,line.len(),span.as_mut_ptr()) }};
    if status>1 || (status==1 && (span[0]>span[1] || span[1]>line.len())) {{ return 3; }}
    matched |= status==1; if matched {{ let Some(next)=total.checked_add(1) else {{ return 3 }}; total=next; }}
    if cursor==h.len() {{ break; }}
  }}
  *out=total; 0
}}
fn invoke_adapter(table:&[Handle;2],h:&[u8])->(u32,u64) {{ let mut out=u64::MAX; let s=adapter(table[1],h,&mut out); (s,out) }}
fn invoke_reducer(table:&[Handle;2],h:&[u8])->(u32,u64) {{ let mut out=u64::MAX; let s=unsafe {{ reducer(table.as_ptr(),2,h.as_ptr(),h.len(),&mut out) }}; (s,out) }}
fn elapsed<F:FnOnce()->(u32,u64)>(f:F)->(u128,(u32,u64)) {{ let start=Instant::now(); let value=black_box(f()); (start.elapsed().as_nanos(),value) }}
fn time_shape(name:&str,table:&[Handle;2],h:&[u8]) {{
  assert_eq!(invoke_adapter(table,h),invoke_reducer(table,h));
  black_box(invoke_adapter(table,h)); black_box(invoke_reducer(table,h));
  for round in 0..7 {{
    let (adapter_ns,reducer_ns,a,b)=if round%2==0 {{ let (a,av)=elapsed(||invoke_adapter(table,h)); let (b,bv)=elapsed(||invoke_reducer(table,h)); (a,b,av,bv) }} else {{ let (b,bv)=elapsed(||invoke_reducer(table,h)); let (a,av)=elapsed(||invoke_adapter(table,h)); (a,b,av,bv) }};
    assert_eq!(a,b); println!("mixed_grep_timing shape={{name}} round={{round}} adapter_ns={{adapter_ns}} reducer_ns={{reducer_ns}}");
  }}
}}
fn fixed_lines()->Vec<u8> {{ let mut h=vec![b'x';1024*1024]; for line in h.chunks_mut(64) {{ line[63]=b'\n'; }} h }}
fn main() {{
  let config=PrepareV3{{struct_size:112,config_version:3,operation_flags:2,max_start_filter_setup_work:100000000,max_grep_count_workspace_bytes:67108864,v2_reserved:[0;4],max_handle_bytes:8388608,max_ordered_nfa_scratch_bytes:8388608,max_ordered_nfa_setup_work:2000000,required_capabilities:1,reserved:[0;2]}};
  let mut handle:Handle=std::ptr::null_mut(); let status=unsafe {{ fre_aot_regex_runtime_prepare_exclusive_v3(std::ptr::addr_of!(PROGRAM),{program_len},&config,&mut handle) }}; assert_eq!(status,0); assert!(!handle.is_null()); let table=[std::ptr::null_mut(),handle];
  let negative=fixed_lines(); time_shape("negative",&table,&negative);
  let mut late=negative.clone(); let start=late.len()-64; late[start..start+4].copy_from_slice(b"foo "); time_shape("late-positive",&table,&late);
  let mut dense=negative.clone(); for line in dense.chunks_mut(64) {{ line[..4].copy_from_slice(b"foo "); }} time_shape("dense-prepared",&table,&dense);
  let mut ordinary=Vec::with_capacity(1024*1024); while ordinary.len()+9<=1024*1024 {{ ordinary.extend_from_slice(b"ordinary\n"); }} time_shape("dense-ordinary-control",&table,&ordinary);
  assert_eq!(unsafe {{ fre_aot_regex_runtime_destroy_exclusive_v1(handle) }},0);
}}
"#,
        ordinary = entries[0],
        prepared = entries[1],
        reducer = artifact.receipt().reducer_symbol(),
    );
    let timing_source_path = directory.join("timing.rs");
    let timing_executable = directory.join("timing");
    fs::write(&timing_source_path, timing_source).expect("write Rust adapter timing harness");
    let mut rustc = Command::new("rustc");
    rustc.arg("-O").arg("--edition=2021").arg(&timing_source_path);
    for path in &paths {
        rustc.arg("-C").arg(format!("link-arg={}", path.display()));
    }
    rustc
        .arg("-C")
        .arg(format!("link-arg={}", static_runtime.display()))
        .arg("-o")
        .arg(&timing_executable);
    let output = rustc.output().expect("compile Rust adapter timing harness");
    assert!(
        output.status.success(),
        "Rust adapter timing link failed: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let output = Command::new(&timing_executable)
        .output()
        .expect("run Rust adapter timing harness");
    assert!(
        output.status.success(),
        "Rust adapter timing failed: status={:?} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
    );
    eprint!("{}", String::from_utf8_lossy(&output.stdout));
    fs::remove_dir_all(directory).expect("remove real-runtime Grep fixture directory");
}

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(target_os = "linux", target_os = "macos")
))]
#[test]
#[ignore = "links generated public row/reducer objects and executes ABI differential cases"]
fn linked_host_reducer_matches_lf_crlf_line_semantics_and_is_transactional() {
    use std::{fmt::Write as _, fs, process::Command, time::SystemTime};

    let target = if cfg!(all(target_arch = "x86_64", target_os = "linux")) {
        Target::x86_64_linux()
    } else if cfg!(all(target_arch = "x86_64", target_os = "macos")) {
        Target::x86_64_macos()
    } else if cfg!(target_os = "linux") {
        Target::aarch64_linux()
    } else {
        Target::aarch64_macos()
    };
    let (compiled, artifact) = selected_for(target);
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "fre-rebar-multi-grep-{}-{nonce}",
        std::process::id(),
    ));
    fs::create_dir_all(&directory).expect("create link fixture directory");
    let reducer_path = directory.join("reducer.o");
    fs::write(&reducer_path, artifact.object()).expect("write reducer object");
    let mut component_paths = Vec::new();
    for (row, component) in compiled.iter().enumerate() {
        let path = directory.join(format!("row-{row}.o"));
        fs::write(&path, component.object()).expect("write row object");
        component_paths.push(path);
    }
    let symbol = artifact.receipt().reducer_symbol();
    let correctness_c = directory.join("correctness.c");
    let correctness_exe = directory.join("correctness");
    let source = format!(
        r#"#include <stdint.h>
#include <stddef.h>
#include <string.h>
extern uint32_t {symbol}(const unsigned char*,size_t,uint64_t*);
static int run(const unsigned char*h,size_t n,uint64_t expected){{uint64_t out=UINT64_C(0xa55ac33cf00f9669);uint32_t s={symbol}(h,n,&out);return s?10+(int)s:(out==expected?0:20);}}
int main(void){{static const unsigned char a[]="foo\r\nbar\nno\n";static const unsigned char b[]="foo\r";static const unsigned char c[]="\r\nfoo\nbar\r\nbar";int r;if((r=run((const unsigned char*)"",0,0)))return r;if((r=run(a,sizeof(a)-1,2)))return r;if((r=run(b,sizeof(b)-1,0)))return r;if((r=run(c,sizeof(c)-1,3)))return r;return 0;}}
"#
    );
    fs::write(&correctness_c, source).expect("write correctness harness");
    let output = host_cc_command()
        .arg("-O2")
        .arg(&correctness_c)
        .args(&component_paths)
        .arg(&reducer_path)
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

    let stub_c = directory.join("transaction.c");
    let stub_exe = directory.join("transaction");
    let entries = artifact.receipt().row_entry_symbols();
    let mut stub = String::from("#include <stdint.h>\n#include <stddef.h>\n");
    writeln!(
        &mut stub,
        "extern uint32_t {symbol}(const unsigned char*,size_t,uint64_t*);"
    )
    .unwrap();
    writeln!(&mut stub, "static int mode;").unwrap();
    writeln!(&mut stub, "uint32_t {}(const unsigned char*h,size_t n,size_t s,size_t e,size_t*out){{(void)h;(void)s;(void)e;if(mode==0){{out[0]=0;out[1]=0;return 1;}}out[0]=0;out[1]=n+1;return 1;}}", entries[0]).unwrap();
    writeln!(&mut stub, "uint32_t {}(const unsigned char*h,size_t n,size_t s,size_t e,size_t*out){{(void)h;(void)n;(void)s;(void)e;(void)out;return mode==0?7:0;}}", entries[1]).unwrap();
    writeln!(
        &mut stub,
        r#"int main(void){{static const unsigned char h[]="foo\n";uint64_t out=UINT64_C(0x123456789abcdef0);unsigned char misaligned[16];mode=0;if({symbol}(h,sizeof(h)-1,&out)!=3||out!=UINT64_C(0x123456789abcdef0))return 1;mode=1;if({symbol}(h,sizeof(h)-1,&out)!=3||out!=UINT64_C(0x123456789abcdef0))return 2;if({symbol}(0,0,&out)!=2||out!=UINT64_C(0x123456789abcdef0))return 3;if({symbol}(h,(size_t)-1,&out)!=2||out!=UINT64_C(0x123456789abcdef0))return 4;for(size_t i=0;i<sizeof(misaligned);i++)misaligned[i]=0x5a;if({symbol}(h,sizeof(h)-1,(uint64_t*)(void*)(misaligned+1))!=2)return 5;for(size_t i=0;i<sizeof(misaligned);i++)if(misaligned[i]!=0x5a)return 6;return 0;}}"#,
    )
    .unwrap();
    fs::write(&stub_c, stub).expect("write transaction harness");
    let output = host_cc_command()
        .arg("-O2")
        .arg(&stub_c)
        .arg(&reducer_path)
        .arg("-o")
        .arg(&stub_exe)
        .output()
        .expect("link transaction harness");
    assert!(
        output.status.success(),
        "transaction link failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        Command::new(&stub_exe)
            .status()
            .expect("run transaction harness")
            .success()
    );

    #[cfg(target_arch = "x86_64")]
    {
        // Seed every SysV callee-saved GPR and make both sides of the native
        // wrapper call boundary assert the mandated stack alignment. This is
        // deliberately assembly, so a C compiler cannot save or normalize a
        // clobbered rbp/rbx/r12-r15 on the probe's behalf.
        let abi_asm = directory.join("abi-probe.S");
        let abi_c = directory.join("abi-probe.c");
        let abi_exe = directory.join("abi-probe");
        let prefix = if cfg!(target_os = "macos") { "_" } else { "" };
        let probe_symbol = format!("{prefix}fre_multi_grep_abi_probe");
        let reducer_symbol = format!("{prefix}{symbol}");
        let row0 = format!("{prefix}{}", entries[0]);
        let row1 = format!("{prefix}{}", entries[1]);
        let assembly = format!(
            r#".text
.p2align 4
.globl {probe_symbol}
{probe_symbol}:
    pushq %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    subq $40, %rsp
    movabsq $0x1122334455667788, %rbp
    movabsq $0x8877665544332211, %rbx
    movabsq $0x13579bdf2468ace0, %r12
    movabsq $0x0fedcba987654321, %r13
    movabsq $0x55aa33cc77ee11ff, %r14
    movabsq $0xa55ac33cf00f9669, %r15
    movq %rsp, %rax
    andq $15, %rax
    jne .Lprobe_bad_alignment
    call {reducer_symbol}
    movl %eax, 24(%rsp)
    movabsq $0x1122334455667788, %rax
    cmpq %rax, %rbp
    jne .Lprobe_bad_register
    movabsq $0x8877665544332211, %rax
    cmpq %rax, %rbx
    jne .Lprobe_bad_register
    movabsq $0x13579bdf2468ace0, %rax
    cmpq %rax, %r12
    jne .Lprobe_bad_register
    movabsq $0x0fedcba987654321, %rax
    cmpq %rax, %r13
    jne .Lprobe_bad_register
    movabsq $0x55aa33cc77ee11ff, %rax
    cmpq %rax, %r14
    jne .Lprobe_bad_register
    movabsq $0xa55ac33cf00f9669, %rax
    cmpq %rax, %r15
    jne .Lprobe_bad_register
    movl 24(%rsp), %eax
    jmp .Lprobe_done
.Lprobe_bad_alignment:
    movl $91, %eax
    jmp .Lprobe_done
.Lprobe_bad_register:
    movl $92, %eax
.Lprobe_done:
    addq $40, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    ret

.p2align 4
.globl {row0}
{row0}:
    movq %rsp, %rax
    andq $15, %rax
    cmpq $8, %rax
    jne .Lrow_bad_alignment
    movq $0, 0(%r8)
    movq $0, 8(%r8)
    movl $1, %eax
    ret

.p2align 4
.globl {row1}
{row1}:
    movq %rsp, %rax
    andq $15, %rax
    cmpq $8, %rax
    jne .Lrow_bad_alignment
    xorl %eax, %eax
    ret
.Lrow_bad_alignment:
    movl $7, %eax
    ret
"#,
        );
        fs::write(&abi_asm, assembly).expect("write x86-64 ABI assembly probe");
        fs::write(
            &abi_c,
            r#"#include <stdint.h>
#include <stddef.h>
extern uint32_t fre_multi_grep_abi_probe(const unsigned char*,size_t,uint64_t*);
int main(void){static const unsigned char h[]="x\n";uint64_t out=UINT64_C(0x123456789abcdef0);uint32_t status=fre_multi_grep_abi_probe(h,sizeof(h)-1,&out);return status==0&&out==1?0:(int)(100+status);}
"#,
        )
        .expect("write x86-64 ABI C probe");
        let output = host_cc_command()
            .arg("-O2")
            .arg(&abi_c)
            .arg(&abi_asm)
            .arg(&reducer_path)
            .arg("-o")
            .arg(&abi_exe)
            .output()
            .expect("link x86-64 ABI probe");
        assert!(
            output.status.success(),
            "x86-64 ABI probe link failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            Command::new(&abi_exe)
                .status()
                .expect("run x86-64 ABI probe")
                .success(),
            "x86-64 reducer clobbered a callee-saved GPR or misaligned a call",
        );
    }
    fs::remove_dir_all(&directory).expect("remove link fixture directory");
}
