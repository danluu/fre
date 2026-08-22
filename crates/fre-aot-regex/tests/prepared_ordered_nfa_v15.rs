use fre_aot_regex::{
    CompileError, CompileLimitsV1, CompileMode, CompileRequest, CompileResource, EngineKind,
    ObjectError, OutputContract, PREPARED_CAPABILITY_ORDERED_NFA_V15, PreparedAggregateExports,
    PreparedAggregateStrategy, PreparedBulkStrategy, PreparedOrderedNfaV15CompileDecline,
    PreparedOrderedNfaV15CompileDisposition, Target, compile,
    compile_with_prepared_ordered_nfa_v15,
    compile_with_prepared_ordered_nfa_v15_and_native_data_limit,
    compile_with_prepared_ordered_nfa_v15_and_native_data_limit_reported,
    compile_with_prepared_ordered_nfa_v15_reported,
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
