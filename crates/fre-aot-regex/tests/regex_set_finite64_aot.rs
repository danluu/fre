use fre_aot_regex::{
    CompileMode, RegexSetCompileRequest, RegexSetFinite64AotCompileDispositionV1,
    RegexSetFinite64AotLimitsV1, RegexSetFinite64CompileDisposition, RegexSetFinite64Limits,
    SearchWindow, Target, compile_regex_set_finite64_aot_v1, compile_regex_set_finite64_reported,
};

#[test]
fn public_generic_graph_api_selects_non_singleton_rows_and_retains_the_portable_owner() {
    let request = RegexSetCompileRequest::new(vec![
        "(?:a|ab)".to_owned(),
        "(?:bc|c)".to_owned(),
        "a".to_owned(),
    ])
    .mode(CompileMode::Optimizing);
    let program =
        match compile_regex_set_finite64_reported(request, RegexSetFinite64Limits::default())
            .expect("target-neutral Finite64 compile")
        {
            RegexSetFinite64CompileDisposition::Selected(program) => program,
            RegexSetFinite64CompileDisposition::Declined { reason, .. } => {
                panic!("finite-language public fixture declined: {reason}")
            }
        };
    let source = program.receipt();
    let artifact = match compile_regex_set_finite64_aot_v1(
        program,
        Target::aarch64_linux(),
        RegexSetFinite64AotLimitsV1::default(),
    )
    .expect("generic graph AOT compile")
    {
        RegexSetFinite64AotCompileDispositionV1::Selected(artifact) => artifact,
        RegexSetFinite64AotCompileDispositionV1::Declined { reason, .. } => {
            panic!("generic graph public fixture declined: {reason}")
        }
    };

    assert!(artifact.authenticates_receipt());
    assert_eq!(source, artifact.program().receipt());
    assert_eq!(0, artifact.receipt().semantic_runtime_calls());
    assert!(
        artifact
            .module()
            .required_runtime_symbols()
            .next()
            .is_none()
    );
    assert!(artifact.module().required_runtime_program().is_none());

    let mut output = u64::MAX;
    artifact
        .program()
        .fill_matches(b"zabc", SearchWindow::new(1, 4), &mut output)
        .expect("portable owner scan");
    assert_eq!(0b111, output);
}
