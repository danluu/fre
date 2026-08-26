use fre_aot_regex::{
    CompiledRegex, RebarWeightedCaptureReducerAotCompileDispositionV1,
    RebarWeightedCaptureReducerAotRequestV1, RelocationKind, Target,
    UniformCaptureCompileDisposition, UniformCaptureCompileReceipt, UniformCaptureCompileRequest,
    UniformCaptureReducerOperation, compile_rebar_weighted_capture_reducer_aot_v1,
    compile_uniform_capture_selector,
};
use fre_syntax::{CanonicalPattern, CompatibilityProfile, ParseRequest, RustProfile, parse};
use sha2::{Digest, Sha256};

const SOURCES: [&str; 3] = [r"(a+)", r"a+", r"((b+))"];
const SOURCE_TO_COMPONENT: [usize; 3] = [0, 0, 1];
const FIRST_ORDINALS: [usize; 2] = [0, 2];

fn ordered_sources_sha256() -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"fre-aot-regex/test-weighted-capture-sources-v1\0");
    for (ordinal, source) in SOURCES.iter().enumerate() {
        digest.update(u64::try_from(ordinal).unwrap().to_le_bytes());
        digest.update(u64::try_from(source.len()).unwrap().to_le_bytes());
        digest.update(source.as_bytes());
    }
    digest.finalize().into()
}

fn components_and_proofs(
    target: Target,
) -> (Vec<CompiledRegex>, Vec<UniformCaptureCompileReceipt>) {
    let profile = RustProfile::rebar_1_12_4();
    let mut components = Vec::new();
    let mut proofs = Vec::new();
    for (source, pattern) in SOURCES.iter().enumerate() {
        let parsed = parse(ParseRequest::rust(
            *pattern,
            CompatibilityProfile::RustBytes(profile.clone()),
        ))
        .expect("parse public weighted fixture");
        let CanonicalPattern::Rust(parsed) = parsed.pattern else {
            panic!("Rust request returned another syntax family")
        };
        let paired = compile_uniform_capture_selector(
            &parsed,
            UniformCaptureCompileRequest::new(pattern.len(), target).profile(profile.clone()),
        )
        .expect("compile public weighted component");
        paired.authenticate().expect("fresh paired selector");
        let (selector, disposition) = paired.into_parts();
        let UniformCaptureCompileDisposition::Proven(proof) = disposition else {
            panic!("positive-width public fixture must prove uniform participation")
        };
        if source == 0 || source == 2 {
            components.push(selector);
        } else {
            assert_eq!(selector.object(), components[0].object());
            proof
                .authenticate(&components[0])
                .expect("capture-erased duplicate authenticates first component");
        }
        proofs.push(proof);
    }
    (components, proofs)
}

fn compile_fixture(
    target: Target,
    operation: UniformCaptureReducerOperation,
    max_object_bytes: usize,
) -> RebarWeightedCaptureReducerAotCompileDispositionV1 {
    let (components, proofs) = components_and_proofs(target);
    let component_refs = components.iter().collect::<Vec<_>>();
    compile_rebar_weighted_capture_reducer_aot_v1(RebarWeightedCaptureReducerAotRequestV1::new(
        operation,
        target,
        SOURCES.iter().map(|source| source.len()).sum(),
        ordered_sources_sha256(),
        &component_refs,
        &SOURCE_TO_COMPONENT,
        &FIRST_ORDINALS,
        &proofs,
        max_object_bytes,
    ))
    .expect("compile weighted reducer")
}

#[test]
fn receipt_closes_priority_weights_and_exact_external_calls_cross_target() {
    for target in [
        Target::x86_64_linux(),
        Target::x86_64_macos(),
        Target::aarch64_linux(),
        Target::aarch64_macos(),
    ] {
        for operation in [
            UniformCaptureReducerOperation::CountCaptures,
            UniformCaptureReducerOperation::GrepCaptures,
        ] {
            let (components, proofs) = components_and_proofs(target);
            let component_refs = components.iter().collect::<Vec<_>>();
            let disposition = compile_rebar_weighted_capture_reducer_aot_v1(
                RebarWeightedCaptureReducerAotRequestV1::new(
                    operation,
                    target,
                    SOURCES.iter().map(|source| source.len()).sum(),
                    ordered_sources_sha256(),
                    &component_refs,
                    &SOURCE_TO_COMPONENT,
                    &FIRST_ORDINALS,
                    &proofs,
                    16 * 1_048_576,
                ),
            )
            .expect("compile cross-target weighted reducer");
            let RebarWeightedCaptureReducerAotCompileDispositionV1::Compiled(artifact) =
                disposition
            else {
                panic!("small wrapper must fit its explicit cap")
            };
            artifact
                .authenticate(&component_refs)
                .expect("fresh weighted artifact authenticates");
            let receipt = artifact.receipt();
            assert_eq!(receipt.operation(), operation);
            assert_eq!(receipt.domain(), operation.domain());
            assert_eq!(receipt.source_to_component(), SOURCE_TO_COMPONENT);
            assert_eq!(receipt.component_first_source_ordinals(), FIRST_ORDINALS);
            assert_eq!(receipt.component_weights(), [2, 3]);
            assert_eq!(receipt.component_entry_symbols().len(), 2);
            assert_eq!(receipt.component_program_sha256().len(), 2);
            assert_eq!(receipt.component_object_sha256().len(), 2);
            assert_eq!(receipt.relocations().len(), 2);
            let (kind, addend) = if target.architecture == fre_aot_regex::Architecture::X86_64 {
                (RelocationKind::X86PltRelative32, -4)
            } else {
                (RelocationKind::Aarch64Branch26, 0)
            };
            for (component, relocation) in receipt.relocations().iter().enumerate() {
                assert_eq!(relocation.component, component);
                assert_eq!(relocation.kind, kind);
                assert_eq!(relocation.addend, addend);
            }
            assert!(receipt.relocations()[0].offset < receipt.relocations()[1].offset);
            assert!(artifact.module().required_runtime_program().is_none());
            assert_eq!(
                artifact
                    .module()
                    .required_runtime_symbols()
                    .collect::<Vec<_>>(),
                receipt.component_entry_symbols()
            );
        }
    }
}

#[test]
fn only_the_exact_serialized_object_cap_is_a_decline() {
    let target = Target::x86_64_linux();
    let operation = UniformCaptureReducerOperation::CountCaptures;
    let RebarWeightedCaptureReducerAotCompileDispositionV1::Compiled(selected) =
        compile_fixture(target, operation, usize::MAX)
    else {
        panic!("unlimited object cap selected a decline")
    };
    let required = selected.object().len();
    assert!(required > 0);
    let RebarWeightedCaptureReducerAotCompileDispositionV1::Declined(decline) =
        compile_fixture(target, operation, required - 1)
    else {
        panic!("one-byte-small object cap must be the typed decline")
    };
    assert_eq!(decline.limit, required - 1);
    assert_eq!(decline.required, required);
}

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(target_os = "linux", target_os = "macos")
))]
#[test]
#[ignore = "links the reducer objects to adversarial fake Span children on the host ISA"]
fn linked_fake_children_close_priority_crlf_and_failure_transactions() {
    use std::{fmt::Write as _, fs, process::Command, time::SystemTime};

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
    let RebarWeightedCaptureReducerAotCompileDispositionV1::Compiled(count) = compile_fixture(
        target,
        UniformCaptureReducerOperation::CountCaptures,
        16 * 1_048_576,
    ) else {
        panic!("small count wrapper must fit its cap")
    };
    let RebarWeightedCaptureReducerAotCompileDispositionV1::Compiled(grep) = compile_fixture(
        target,
        UniformCaptureReducerOperation::GrepCaptures,
        16 * 1_048_576,
    ) else {
        panic!("small grep wrapper must fit its cap")
    };
    assert_eq!(
        count.receipt().component_entry_symbols(),
        grep.receipt().component_entry_symbols()
    );
    let entries = count.receipt().component_entry_symbols();
    assert_eq!(entries.len(), 2);
    let grep_abi_wrapper = "fre_aot_weighted_grep_abi_wrap_v1";

    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "fre-aot-weighted-capture-fake-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("create fake-child linker directory");
    let count_object = directory.join("count.o");
    let grep_object = directory.join("grep.o");
    fs::write(&count_object, count.object()).expect("write count reducer object");
    fs::write(&grep_object, grep.object()).expect("write grep reducer object");

    let mut source =
        String::from("#include <stdint.h>\n#include <stddef.h>\n#include <limits.h>\n");
    writeln!(
        source,
        "extern uint32_t {}(const unsigned char*,size_t,uint64_t*);",
        count.reducer_symbol()
    )
    .unwrap();
    writeln!(
        source,
        "extern uint32_t {}(const unsigned char*,size_t,uint64_t*);",
        grep.reducer_symbol()
    )
    .unwrap();
    writeln!(
        source,
        "extern uint32_t {grep_abi_wrapper}(const unsigned char*,size_t,uint64_t*,uint32_t*);"
    )
    .unwrap();
    if !cfg!(target_arch = "x86_64") {
        writeln!(
            source,
            "uint32_t {grep_abi_wrapper}(const unsigned char*h,size_t n,uint64_t*v,uint32_t*p){{*p=1;return {}(h,n,v);}}",
            grep.reducer_symbol()
        )
        .unwrap();
    }
    writeln!(
        source,
        "uint32_t {}(const unsigned char*h,size_t n,size_t s,size_t e,size_t*r){{\
         if(s>e||e>n)return 77;if(n&&h[0]=='S')return 9;\
         if(n&&h[0]=='Z'){{r[0]=s;r[1]=s;return 1;}}\
         if(n&&h[0]=='E'){{r[0]=s;r[1]=n+1;return 1;}}\
         if(n&&h[0]=='W'){{if(s==0)return 0;r[0]=0;r[1]=1;return 1;}}\
         if(n&&h[0]=='P'){{if(s<=2){{r[0]=2;r[1]=4;return 1;}}if(s<=6){{r[0]=6;r[1]=7;return 1;}}return 0;}}\
         if(n&&h[n-1]=='\\r')return 9;if(s==0&&n){{r[0]=0;r[1]=n;return 1;}}return 0;}}",
        entries[0]
    )
    .unwrap();
    writeln!(
        source,
        "uint32_t {}(const unsigned char*h,size_t n,size_t s,size_t e,size_t*r){{\
         if(s>e||e>n)return 78;if(n&&h[0]=='W'){{if(s==0){{r[0]=0;r[1]=1;return 1;}}return 0;}}\
         if(n&&h[0]=='P'){{if(s<=2){{r[0]=2;r[1]=3;return 1;}}if(s<=5){{r[0]=5;r[1]=6;return 1;}}if(s<=6){{r[0]=6;r[1]=8;return 1;}}return 0;}}\
         return 0;}}",
        entries[1]
    )
    .unwrap();
    writeln!(
        source,
        "int main(void){{uint64_t v;uint32_t s,abi;\
         static const unsigned char p[8]={{'P',0,0,0,0,0,0,0}};\
         static const unsigned char bad_status[1]={{'S'}};\
         static const unsigned char zero_width[1]={{'Z'}};\
         static const unsigned char beyond_end[1]={{'E'}};\
         static const unsigned char late_invalid[2]={{'W',0}};\
         static const unsigned char lines[11]={{'a','a','\\r','\\n','b','\\n','\\r','\\n','c','\\r','\\n'}};\
         v=91;s={}(p,8,&v);if(s!=0||v!=7)return 10;\
         v=92;s={}(bad_status,1,&v);if(s!=3||v!=92)return 11;\
         v=93;s={}(zero_width,1,&v);if(s!=3||v!=93)return 12;\
         v=94;s={}(beyond_end,1,&v);if(s!=3||v!=94)return 13;\
         v=95;s={}(late_invalid,2,&v);if(s!=3||v!=95)return 14;\
         v=96;abi=0;s={}(lines,11,&v,&abi);if(s!=0||v!=6||abi!=1)return 15;\
         v=97;s={}(p,(size_t)-1,&v);if(s!=2||v!=97)return 16;\
         return 0;}}",
        count.reducer_symbol(),
        count.reducer_symbol(),
        count.reducer_symbol(),
        count.reducer_symbol(),
        count.reducer_symbol(),
        grep_abi_wrapper,
        count.reducer_symbol(),
    )
    .unwrap();
    let c_path = directory.join("fake_children.c");
    let executable = directory.join("fake_children");
    fs::write(&c_path, source).expect("write fake-child C harness");
    let compiler = if cfg!(target_os = "macos") {
        "clang"
    } else {
        "cc"
    };
    let mut command = Command::new(compiler);
    command
        .arg("-O0")
        .arg(&c_path)
        .arg(&count_object)
        .arg(&grep_object);
    if cfg!(target_arch = "x86_64") {
        let prefix = if cfg!(target_os = "macos") { "_" } else { "" };
        let type_directive = if cfg!(target_os = "linux") {
            format!(".type {prefix}{grep_abi_wrapper},@function\n")
        } else {
            String::new()
        };
        let size_directive = if cfg!(target_os = "linux") {
            format!(
                ".size {prefix}{grep_abi_wrapper},.-{prefix}{grep_abi_wrapper}\n"
            )
        } else {
            String::new()
        };
        let assembly = format!(
            ".text\n.p2align 4\n.globl {prefix}{grep_abi_wrapper}\n{type_directive}\
             {prefix}{grep_abi_wrapper}:\n\
             pushq %rbp\n\
             pushq %rbx\n\
             subq $8,%rsp\n\
             movq %rcx,%rbx\n\
             movabsq $0x6a09e667f3bcc909,%rbp\n\
             call {prefix}{grep_reducer}\n\
             movabsq $0x6a09e667f3bcc909,%r10\n\
             cmpq %r10,%rbp\n\
             sete %r11b\n\
             movzbl %r11b,%r11d\n\
             movl %r11d,(%rbx)\n\
             addq $8,%rsp\n\
             popq %rbx\n\
             popq %rbp\n\
             ret\n\
             {size_directive}",
            grep_reducer = grep.reducer_symbol(),
        );
        let assembly_path = directory.join("grep_abi.S");
        fs::write(&assembly_path, assembly).expect("write x86 grep ABI wrapper");
        command.arg(assembly_path);
    }
    let output = command
        .arg("-o")
        .arg(&executable)
        .output()
        .expect("link fake-child reducer harness");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new(&executable)
        .output()
        .expect("execute fake-child reducer harness");
    assert!(
        output.status.success(),
        "status={:?} stdout={} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    fs::remove_dir_all(directory).expect("remove fake-child linker directory");
}
