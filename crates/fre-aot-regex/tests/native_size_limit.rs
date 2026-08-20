#![forbid(unsafe_code)]

use fre_aot_regex::{
    CaptureCompileRequest, CompileError, CompileMode, CompileRequest, CompileResource, Target,
    compile, compile_captures,
};

#[test]
fn compile_request_size_limit_is_the_exact_stable_program_boundary() {
    let target = Target::x86_64_linux();
    let measured = compile(
        CompileRequest::new("a", target)
            .mode(CompileMode::Fast)
            .size_limit(usize::MAX),
    )
    .expect("measure one native semantic program");
    let needed = measured.program().serialized_len().expect("program length");
    assert!(needed > 0);

    let exact = compile(
        CompileRequest::new("a", target)
            .mode(CompileMode::Fast)
            .size_limit(needed),
    )
    .expect("the exact stable-program boundary is inclusive");
    assert_eq!(needed, exact.program().serialized_len().unwrap());

    assert!(matches!(
        compile(
            CompileRequest::new("a", target)
                .mode(CompileMode::Fast)
                .size_limit(needed - 1)
        ),
        Err(CompileError::Resource {
            resource: CompileResource::ProgramBytes,
            required,
            limit,
        }) if required == needed && limit == needed - 1
    ));
}

#[test]
fn capture_size_limit_charges_the_selector_not_capture_schema() {
    let target = Target::x86_64_linux();
    let pattern = concat!(
        "(?P<c00>)(?P<c01>)(?P<c02>)(?P<c03>)",
        "(?P<c04>)(?P<c05>)(?P<c06>)(?P<c07>)",
        "(?P<c08>)(?P<c09>)(?P<c10>)(?P<c11>)",
        "(?P<c12>)(?P<c13>)(?P<c14>)(?P<c15>)",
    );
    let measured = compile_captures(
        CaptureCompileRequest::new(pattern, target)
            .mode(CompileMode::Fast)
            .size_limit(usize::MAX),
    )
    .expect("measure selector and capture artifacts");
    let selector_bytes = measured
        .selector()
        .program()
        .serialized_len()
        .expect("selector length");
    let capture_bytes = measured.capture_program().usage().serialized_bytes;
    assert!(
        capture_bytes > selector_bytes,
        "fixture must retain a capture artifact larger than its selector"
    );

    let exact = compile_captures(
        CaptureCompileRequest::new(pattern, target)
            .mode(CompileMode::Fast)
            .size_limit(selector_bytes),
    )
    .expect("capture schema uses its separate typed limits");
    assert_eq!(
        selector_bytes,
        exact.selector().program().serialized_len().unwrap()
    );
    assert_eq!(
        capture_bytes,
        exact.capture_program().usage().serialized_bytes
    );
}
