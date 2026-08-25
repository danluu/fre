use fre_aot_regex::{
    RegexSetCompileRequest, RegexSetExact64AotCompileDispositionV1, RegexSetExact64AotLimitsV1,
    RegexSetExact64CompileDisposition, RegexSetExact64Limits, Target,
    compile_regex_set_exact64_aot_v1, compile_regex_set_exact64_reported,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn exact64_v1_outputs_match_e7d6_cross_revision_goldens() {
    // These values were generated independently from the exact parent
    // revision e7d6b591d3827ea153903456f2e019ee7326aa0e before compiling this
    // candidate. They cover the incumbent regex-set identity, the Exact64 V1
    // source mapping and graph, and every digest of its AArch64 object.
    let request = RegexSetCompileRequest::new(
        ["he", "she", "hers", "he", r"(?-u:\xFFx)"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
    );
    let program = match compile_regex_set_exact64_reported(
        request,
        RegexSetExact64Limits::default(),
    )
    .unwrap()
    {
        RegexSetExact64CompileDisposition::Selected(program) => program,
        RegexSetExact64CompileDisposition::Declined { reason, .. } => {
            panic!("cross-revision Exact64 fixture declined: {reason}")
        }
    };
    assert_eq!(
        "79a44ca1d9270c3c5d98c80027e2cd618f99c71088e6fad20160c5ab1136ef46",
        hex(program.receipt().source_artifact().as_bytes())
    );
    assert_eq!(
        "264596248747623c07d3ab151233d08bc53730c13cba675f4bbff4d4e5865712",
        hex(&program.receipt().source_mapping_digest())
    );
    assert_eq!(
        "90f8397fcf4b528b6d8d636756c82201379e82dc8c3ba7b02a7d249170874273",
        hex(program.receipt().artifact_identity().as_bytes())
    );

    let artifact = match compile_regex_set_exact64_aot_v1(
        program,
        Target::aarch64_linux(),
        RegexSetExact64AotLimitsV1::default(),
    )
    .unwrap()
    {
        RegexSetExact64AotCompileDispositionV1::Selected(artifact) => artifact,
        RegexSetExact64AotCompileDispositionV1::Declined { reason, .. } => {
            panic!("cross-revision Exact64 AOT fixture declined: {reason}")
        }
    };
    assert_eq!(
        "8f417bc4cebe3611ff1830768658c4fb8c6d3000403870ea9a95fa69a794315c",
        hex(&artifact.receipt().operation_identity_sha256())
    );
    assert_eq!(
        "c9454a060bd1a7458e7232d9b42d8a111868a84b5713000043bcb480467a76c1",
        hex(&artifact.receipt().dense_data_sha256())
    );
    assert_eq!(
        "55efeddfe8c81da3a7972d9d75065a15547546b0e29e6d0c8143f2b50454b01c",
        hex(&artifact.receipt().code_sha256())
    );
    assert_eq!(
        "5551d96b3698aca19dc4f6f4c6f960e57c265a723a7e89fa725501e469a10f88",
        hex(&artifact.receipt().object_sha256())
    );
    assert_eq!(
        "13a0e38917b3e1ef3fc0b1420873eb56fb69cd2692074ff4e796678c9135bef0",
        hex(&artifact.receipt().artifact_identity_sha256())
    );
    assert!(artifact.authenticates_receipt());
}
