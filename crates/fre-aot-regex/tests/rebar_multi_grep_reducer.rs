use fre_aot_regex::{
    Architecture, CompileMode, CompileRequest, OutputContract,
    RebarMultiGrepReducerAotCompileDeclineV1, RebarMultiGrepReducerAotCompileDispositionV1,
    RebarMultiGrepReducerRowV1, RelocationKind, SectionKind, SymbolBinding, SymbolKind, Target,
    compile, compile_rebar_multi_grep_reducer_aot_v1,
};
use fre_syntax::RustProfile;

const SOURCE_IDENTITY: [u8; 32] = [0x71; 32];

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
