use fre_aot_regex::{
    CompileResource, NativeParticipationAotDeclineV1, NativeParticipationAotLimitsV1,
    NativeParticipationAotStrategyV1, ObjectError, RebarSingleCaptureAotRequestV1,
    RebarSingleCaptureReducerAotErrorV1, RebarSingleCaptureReducerDomainV1,
    RebarSingleCaptureReducerOperationV1, RebarSingleCaptureReducerSourceArtifactV1,
    RebarSingleCaptureReducerSourceRouteV1, Target, compile_rebar_single_capture_aot_v1,
    compile_rebar_single_capture_participation_aot_v1, compile_rebar_single_capture_reducer_aot_v1,
};

const MAX_OBJECT_BYTES: usize = 512 * 1_024 * 1_024;

fn request(pattern: &str, target: Target) -> RebarSingleCaptureAotRequestV1 {
    RebarSingleCaptureAotRequestV1::new([pattern.to_owned()], target)
}

fn participation_source(
    pattern: &str,
    target: Target,
) -> RebarSingleCaptureReducerSourceArtifactV1 {
    compile_rebar_single_capture_participation_aot_v1(
        request(pattern, target),
        NativeParticipationAotLimitsV1::default(),
    )
    .expect("compile exact-span participation source")
    .into()
}

fn capture_next_source(pattern: &str, target: Target) -> RebarSingleCaptureReducerSourceArtifactV1 {
    compile_rebar_single_capture_aot_v1(request(pattern, target))
        .expect("compile strict capture-next source")
        .into()
}

fn ordered_participation_source(
    pattern: &str,
    target: Target,
) -> RebarSingleCaptureReducerSourceArtifactV1 {
    let mut limits = NativeParticipationAotLimitsV1::default();
    limits.max_dfa_states = 1;
    let artifact =
        compile_rebar_single_capture_participation_aot_v1(request(pattern, target), limits)
            .expect("compile ordered-NFA exact-span participation source");
    assert!(matches!(
        artifact.native_receipt().strategy,
        NativeParticipationAotStrategyV1::OrderedNfaX86_64
            | NativeParticipationAotStrategyV1::OrderedNfaAarch64
    ));
    artifact.into()
}

#[test]
fn both_nonuniform_routes_publish_distinct_authenticated_one_call_receipts_cross_target() {
    for target in [Target::x86_64_linux(), Target::aarch64_linux()] {
        for route in [
            RebarSingleCaptureReducerSourceRouteV1::ExactSpanParticipationV1,
            RebarSingleCaptureReducerSourceRouteV1::CaptureNextV1,
        ] {
            for operation in [
                RebarSingleCaptureReducerOperationV1::CountCaptures,
                RebarSingleCaptureReducerOperationV1::GrepCaptures,
            ] {
                // Recompile the route because the additive finalizer owns its
                // retained source artifact and never clones across routes.
                let source = match route {
                    RebarSingleCaptureReducerSourceRouteV1::ExactSpanParticipationV1 => {
                        participation_source(r"(?:(a)|(ab))(b)?", target)
                    }
                    RebarSingleCaptureReducerSourceRouteV1::CaptureNextV1 => {
                        capture_next_source(r"((ab)+)", target)
                    }
                };
                let artifact = compile_rebar_single_capture_reducer_aot_v1(
                    source,
                    operation,
                    MAX_OBJECT_BYTES,
                )
                .expect("compile whole-operation capture reducer");
                let receipt = artifact.receipt();
                assert!(artifact.authenticates_receipt());
                assert_eq!(receipt.operation(), operation);
                assert_eq!(receipt.domain(), operation.domain());
                assert_eq!(receipt.source_route(), route);
                assert_eq!(receipt.semantic_runtime_calls(), 0);
                assert_eq!(receipt.source_cardinality(), 1);
                assert!(receipt.group_count() > 1);
                assert!(
                    artifact
                        .module()
                        .required_runtime_symbols()
                        .next()
                        .is_none()
                );
                assert!(artifact.module().required_runtime_program().is_none());
                match route {
                    RebarSingleCaptureReducerSourceRouteV1::ExactSpanParticipationV1 => {
                        assert_eq!(receipt.caller_scratch_bytes(), 0);
                        assert_eq!(receipt.private_participation_scratch_bytes(), 16);
                        assert_eq!(receipt.private_iterator_state_bytes(), 0);
                        assert_eq!(receipt.private_result_slot_count(), 0);
                        assert_eq!(receipt.private_result_slot_bytes(), 0);
                    }
                    RebarSingleCaptureReducerSourceRouteV1::CaptureNextV1 => {
                        assert_eq!(receipt.caller_scratch_bytes(), 0);
                        assert_eq!(receipt.private_participation_scratch_bytes(), 0);
                        assert_eq!(receipt.private_iterator_state_bytes(), 24);
                        assert_eq!(receipt.private_result_slot_count(), receipt.group_count(),);
                        assert_eq!(
                            receipt.private_result_slot_bytes(),
                            receipt.group_count() * 16,
                        );
                    }
                }
                match operation {
                    RebarSingleCaptureReducerOperationV1::CountCaptures => {
                        assert_eq!(
                            receipt.domain(),
                            RebarSingleCaptureReducerDomainV1::WholeHaystack,
                        );
                        assert!(
                            artifact
                                .reducer_symbol()
                                .starts_with("fre_aot_regex_count_captures_v1_")
                        );
                    }
                    RebarSingleCaptureReducerOperationV1::GrepCaptures => {
                        assert_eq!(
                            receipt.domain(),
                            RebarSingleCaptureReducerDomainV1::ByteSliceLinesLfCrLf,
                        );
                        assert!(
                            artifact
                                .reducer_symbol()
                                .starts_with("fre_aot_regex_grep_captures_v1_")
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn ordered_participation_reducer_uses_additive_exact_caller_scratch_abi_cross_target() {
    for target in [Target::x86_64_linux(), Target::aarch64_linux()] {
        for operation in [
            RebarSingleCaptureReducerOperationV1::CountCaptures,
            RebarSingleCaptureReducerOperationV1::GrepCaptures,
        ] {
            let artifact = compile_rebar_single_capture_reducer_aot_v1(
                ordered_participation_source(r"(?:(a)|(ab))(b)?", target),
                operation,
                MAX_OBJECT_BYTES,
            )
            .expect("compile ordered-NFA whole-operation capture reducer");
            let receipt = artifact.receipt();
            assert!(artifact.authenticates_receipt());
            assert!(receipt.caller_scratch_bytes() > 16);
            assert!(receipt.caller_scratch_bytes().is_multiple_of(8));
            assert_eq!(receipt.private_participation_scratch_bytes(), 0);
            assert_eq!(receipt.private_iterator_state_bytes(), 0);
            assert_eq!(receipt.private_result_slot_count(), 0);
            assert_eq!(receipt.private_result_slot_bytes(), 0);
            let prefix = match operation {
                RebarSingleCaptureReducerOperationV1::CountCaptures => {
                    "fre_aot_regex_count_captures_scratch_v1_"
                }
                RebarSingleCaptureReducerOperationV1::GrepCaptures => {
                    "fre_aot_regex_grep_captures_scratch_v1_"
                }
            };
            assert!(artifact.reducer_symbol().starts_with(prefix));
        }
    }
}

#[test]
fn negative_participation_and_final_object_cap_are_terminal_without_route_fallback() {
    let target = Target::x86_64_linux();
    let negative = participation_source(r"(?m)^((?:ab)+)$", target);
    let error = compile_rebar_single_capture_reducer_aot_v1(
        negative,
        RebarSingleCaptureReducerOperationV1::CountCaptures,
        MAX_OBJECT_BYTES,
    )
    .expect_err("negative participation cannot publish a reducer");
    assert!(matches!(
        error,
        RebarSingleCaptureReducerAotErrorV1::ParticipationUnavailable(
            NativeParticipationAotDeclineV1::UnsupportedAssertion
        )
    ));

    let selected = capture_next_source(r"((ab)+)", target);
    let error = compile_rebar_single_capture_reducer_aot_v1(
        selected,
        RebarSingleCaptureReducerOperationV1::GrepCaptures,
        0,
    )
    .expect_err("final object cap is terminal");
    assert!(matches!(
        error,
        RebarSingleCaptureReducerAotErrorV1::Object(ObjectError::Resource {
            resource: CompileResource::ObjectBytes,
            limit: 0,
            ..
        })
    ));
}

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(target_os = "linux", target_os = "macos")
))]
#[test]
#[ignore = "links and executes generated helper-free capture reducers"]
fn linked_host_nonuniform_reducers_match_count_and_exact_lf_crlf_line_semantics() {
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
    let cases: [(
        fn(&str, Target) -> RebarSingleCaptureReducerSourceArtifactV1,
        RebarSingleCaptureReducerOperationV1,
        &str,
        &[u8],
        u64,
    ); 8] = [
        (
            participation_source,
            RebarSingleCaptureReducerOperationV1::CountCaptures,
            r"(a)?b",
            b"b ab aab",
            5,
        ),
        (
            capture_next_source,
            RebarSingleCaptureReducerOperationV1::CountCaptures,
            r"(a)?b",
            b"b ab aab",
            5,
        ),
        (
            participation_source,
            RebarSingleCaptureReducerOperationV1::GrepCaptures,
            r"((ab)+)(c)?(\r)?",
            b"ab\r\nabc\n\nabab\r\nab\r",
            14,
        ),
        (
            capture_next_source,
            RebarSingleCaptureReducerOperationV1::GrepCaptures,
            r"((ab)+)(c)?(\r)?",
            b"ab\r\nabc\n\nabab\r\nab\r",
            14,
        ),
        (
            participation_source,
            RebarSingleCaptureReducerOperationV1::GrepCaptures,
            r"(a*)",
            b"\n\r\n",
            4,
        ),
        (
            capture_next_source,
            RebarSingleCaptureReducerOperationV1::GrepCaptures,
            r"(a*)",
            b"\n\r\n",
            4,
        ),
        (
            ordered_participation_source,
            RebarSingleCaptureReducerOperationV1::CountCaptures,
            r"((((((((((((((((a))))))))))))))))",
            b"a a",
            34,
        ),
        (
            ordered_participation_source,
            RebarSingleCaptureReducerOperationV1::GrepCaptures,
            r"((((((((((((((((a))))))))))))))))",
            b"a\nx\na",
            34,
        ),
    ];
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "fre-aot-rebar-capture-reducer-{}-{nonce}",
        std::process::id(),
    ));
    fs::create_dir_all(&directory).expect("create reducer linker directory");
    let compiler = if cfg!(target_os = "macos") {
        "clang"
    } else {
        "cc"
    };

    for (index, (build_source, operation, pattern, haystack, expected)) in
        cases.into_iter().enumerate()
    {
        let artifact = compile_rebar_single_capture_reducer_aot_v1(
            build_source(pattern, target),
            operation,
            MAX_OBJECT_BYTES,
        )
        .expect("compile linked reducer");
        assert!(artifact.authenticates_receipt());
        let bytes = haystack
            .iter()
            .map(|byte| format!("{byte}U"))
            .collect::<Vec<_>>()
            .join(",");
        let symbol = artifact.reducer_symbol();
        let caller_scratch_bytes = artifact.receipt().caller_scratch_bytes();
        let c_source = if caller_scratch_bytes == 0 {
            format!(
                r#"#include <stddef.h>
#include <stdint.h>
extern uint32_t {symbol}(const unsigned char*,size_t,uint64_t*);
static const unsigned char haystack[]={{{bytes}}};
int main(void){{
  uint64_t out=UINT64_C(0x1122334455667788);unsigned char raw[24]={{0}};
  if({symbol}(haystack,sizeof(haystack),&out)!=0U||out!=UINT64_C({expected}))return 1;
  out=UINT64_C(0x1122334455667788);
  if({symbol}(haystack,0,&out)!=0U||out!=UINT64_C(0))return 2;
  out=UINT64_C(0x1122334455667788);
  if({symbol}(0,sizeof(haystack),&out)!=2U||out!=UINT64_C(0x1122334455667788))return 3;
  if({symbol}((const unsigned char*)(uintptr_t)1,(size_t)-1,&out)!=2U||out!=UINT64_C(0x1122334455667788))return 4;
  if({symbol}(haystack,sizeof(haystack),(uint64_t*)(void*)(raw+1))!=2U)return 5;
  return 0;
}}
"#,
            )
        } else {
            format!(
                r#"#include <stddef.h>
#include <stdint.h>
extern uint32_t {symbol}(const unsigned char*,size_t,unsigned char*,size_t,uint64_t*);
static const unsigned char haystack[]={{{bytes}}};
_Alignas(8) static unsigned char scratch[{caller_scratch_bytes}];
int main(void){{
  uint64_t out=UINT64_C(0x1122334455667788);unsigned char raw[24]={{0}};
  if({symbol}(haystack,sizeof(haystack),scratch,sizeof(scratch),&out)!=0U||out!=UINT64_C({expected}))return 1;
  out=UINT64_C(0x1122334455667788);
  if({symbol}(haystack,0,scratch,sizeof(scratch),&out)!=0U||out!=UINT64_C(0))return 2;
  out=UINT64_C(0x1122334455667788);
  if({symbol}(0,sizeof(haystack),scratch,sizeof(scratch),&out)!=2U||out!=UINT64_C(0x1122334455667788))return 3;
  if({symbol}((const unsigned char*)(uintptr_t)1,(size_t)-1,scratch,sizeof(scratch),&out)!=2U||out!=UINT64_C(0x1122334455667788))return 4;
  if({symbol}(haystack,sizeof(haystack),scratch,sizeof(scratch),(uint64_t*)(void*)(raw+1))!=2U)return 5;
  out=UINT64_C(0x1122334455667788);
  if({symbol}(haystack,sizeof(haystack),0,sizeof(scratch),&out)!=2U||out!=UINT64_C(0x1122334455667788))return 6;
  if({symbol}(haystack,sizeof(haystack),scratch,sizeof(scratch)-1U,&out)!=2U||out!=UINT64_C(0x1122334455667788))return 7;
  if({symbol}(haystack,sizeof(haystack),scratch+1,sizeof(scratch),&out)!=2U||out!=UINT64_C(0x1122334455667788))return 8;
  return 0;
}}
"#,
            )
        };
        let object_path = directory.join(format!("reducer-{index}.o"));
        let source_path = directory.join(format!("reducer-{index}.c"));
        let executable_path = directory.join(format!("reducer-{index}"));
        fs::write(&object_path, artifact.object()).expect("write reducer object");
        fs::write(&source_path, c_source).expect("write reducer harness");
        let status = Command::new(compiler)
            .arg("-O0")
            .arg(&source_path)
            .arg(&object_path)
            .arg("-o")
            .arg(&executable_path)
            .status()
            .expect("link reducer harness");
        assert!(status.success(), "failed to link {operation:?}/{index}");
        let output = Command::new(&executable_path)
            .output()
            .expect("execute reducer harness");
        assert!(
            output.status.success(),
            "{operation:?}/{index}: status={:?}, stdout={}, stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    fs::remove_dir_all(directory).expect("remove reducer linker directory");
}
