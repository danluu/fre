use fre_aot_regex::{
    Architecture, CompileMode, EngineKind, EntryAbi, OrderedManyAotCompileLimits,
    OrderedManyAotCompileRequest, OrderedManyPatternId, OrderedManyRow, PreparedAggregateStrategy,
    SHARED_UNIFORM_CAPTURE_REDUCER_AOT_RECEIPT_VERSION,
    SharedUniformCaptureReducerAotCompileDecline, SharedUniformCaptureReducerAotCompileDisposition,
    SharedUniformCaptureReducerAotCompileError, SlowAotLimits, Target,
    UniformCaptureReducerOperation, compile_shared_uniform_capture_reducer_aot_reported,
};
use fre_lower::{UniformCaptureParticipationLimits, UniformCaptureParticipationResource};
use fre_syntax::RustProfile;

fn targets() -> [Target; 2] {
    [Target::x86_64_linux(), Target::aarch64_linux()]
}

fn rows(patterns: &[&str]) -> Vec<OrderedManyRow> {
    patterns
        .iter()
        .enumerate()
        .map(|(row, pattern)| {
            OrderedManyRow::new(
                OrderedManyPatternId::new(u32::try_from(row).unwrap()),
                *pattern,
            )
        })
        .collect()
}

fn compile(
    patterns: &[&str],
    target: Target,
    operation: UniformCaptureReducerOperation,
) -> Result<
    SharedUniformCaptureReducerAotCompileDisposition,
    SharedUniformCaptureReducerAotCompileError,
> {
    compile_shared_uniform_capture_reducer_aot_reported(
        OrderedManyAotCompileRequest::new(rows(patterns), target)
            .profile(RustProfile::rebar_1_12_4())
            .mode(CompileMode::Optimizing),
        operation,
        UniformCaptureParticipationLimits::default(),
        SlowAotLimits::default(),
    )
}

#[test]
fn equal_multipliers_publish_one_authenticated_helper_free_object_cross_isa() {
    for target in targets() {
        for operation in [
            UniformCaptureReducerOperation::CountCaptures,
            UniformCaptureReducerOperation::GrepCaptures,
        ] {
            let artifact = compile(&[r"(ab)+", r"(cd)+", r"([ef])+"], target, operation)
                .unwrap()
                .into_compiled()
                .expect("equal uniform sources compile");
            artifact
                .authenticate()
                .expect("authenticated shared reducer");
            let receipt = artifact.receipt();
            assert_eq!(
                receipt.schema_version(),
                SHARED_UNIFORM_CAPTURE_REDUCER_AOT_RECEIPT_VERSION
            );
            assert_eq!(receipt.rows(), 3);
            assert_eq!(receipt.source_proofs().len(), 3);
            assert_eq!(receipt.source_proof_bindings_sha256().len(), 3);
            assert_eq!(receipt.multiplier().get(), 2);
            assert_ne!(receipt.proof_identity_sha256(), [0; 32]);
            assert_ne!(receipt.aggregate_object_sha256(), [0; 32]);
            assert_ne!(receipt.count_symbol_sha256(), [0; 32]);
            assert_ne!(receipt.reducer_symbol_sha256(), [0; 32]);
            assert_eq!(
                artifact
                    .compiled()
                    .module()
                    .required_runtime_symbols()
                    .next(),
                None
            );
            assert!(matches!(
                receipt.aggregate_strategy(),
                PreparedAggregateStrategy::NativeFused
                    | PreparedAggregateStrategy::NativeOrderedNfaFused
            ));
            assert_eq!(artifact.compiled().module().prepared_bulk_strategy(), None);
            assert!(
                artifact
                    .compiled()
                    .module()
                    .required_runtime_program()
                    .is_some()
            );
            let object = artifact.compiled().object();
            assert_eq!(receipt.target(), target);
            assert_eq!(&object[..4], b"\x7fELF");
            let machine = u16::from_le_bytes([object[18], object[19]]);
            assert_eq!(
                machine,
                match target.architecture {
                    Architecture::X86_64 => 62,
                    Architecture::Aarch64 => 183,
                }
            );
        }
    }
}

#[test]
fn ordered_v15_equal_multiplier_reducer_is_operation_only_cross_isa() {
    let patterns = [r"((?-u:[\x00-\xFF])\bfoo\b)", r"((?-u:[\x00-\xFF])\bbar\b)"];
    for target in targets() {
        let artifact = compile_shared_uniform_capture_reducer_aot_reported(
            OrderedManyAotCompileRequest::new(rows(&patterns), target)
                .profile(RustProfile::rebar_1_12_4())
                .mode(CompileMode::Fast),
            UniformCaptureReducerOperation::CountCaptures,
            UniformCaptureParticipationLimits::default(),
            SlowAotLimits::default(),
        )
        .expect("shared V15 capture compilation")
        .into_compiled()
        .expect("shared V15 capture route is eligible");
        artifact.authenticate().expect("shared V15 capture seal");
        let compiled = artifact.compiled();
        assert_eq!(compiled.receipt().engine, EngineKind::OrderedNfa);
        assert_eq!(
            compiled.receipt().entry_abi,
            EntryAbi::PreparedScalarReduceV1
        );
        assert_eq!(
            artifact.receipt().aggregate_strategy(),
            PreparedAggregateStrategy::NativeOrderedNfaFused,
        );
        assert_eq!(compiled.module().prepared_bulk_strategy(), None);
        assert_eq!(compiled.module().prepared_entry_symbol(), None);
        assert_eq!(compiled.module().prepared_span_fill_symbol(), None);
        assert_eq!(
            compiled.module().prepared_count_symbol(),
            Some(compiled.module().entry_symbol()),
        );
        assert_ne!(artifact.reducer_symbol(), compiled.module().entry_symbol());
        assert!(
            compiled
                .module()
                .required_runtime_symbols()
                .next()
                .is_none()
        );
        assert!(compiled.module().required_runtime_program().is_some());
    }
}

#[test]
fn source_order_and_exact_source_bytes_change_the_composite_proof_identity() {
    let target = targets()[0];
    let first = compile(
        &[r"(ab)+", r"(cd)+"],
        target,
        UniformCaptureReducerOperation::CountCaptures,
    )
    .unwrap()
    .into_compiled()
    .unwrap();
    let reversed = compile(
        &[r"(cd)+", r"(ab)+"],
        target,
        UniformCaptureReducerOperation::CountCaptures,
    )
    .unwrap()
    .into_compiled()
    .unwrap();
    let changed = compile(
        &[r"(ab)+", r"(ce)+"],
        target,
        UniformCaptureReducerOperation::CountCaptures,
    )
    .unwrap()
    .into_compiled()
    .unwrap();
    assert_ne!(
        first.receipt().ordered_sources_sha256(),
        reversed.receipt().ordered_sources_sha256()
    );
    assert_ne!(
        first.receipt().proof_identity_sha256(),
        reversed.receipt().proof_identity_sha256()
    );
    assert_ne!(
        first.receipt().proof_identity_sha256(),
        changed.receipt().proof_identity_sha256()
    );
}

#[test]
fn semantic_and_unequal_multiplier_refusals_are_typed_before_aggregate_selection() {
    let target = targets()[0];
    let semantic = compile(
        &[r"(ab)+", r"(?:cd)+"],
        target,
        UniformCaptureReducerOperation::CountCaptures,
    )
    .unwrap();
    assert!(matches!(
        semantic,
        SharedUniformCaptureReducerAotCompileDisposition::Declined(
            SharedUniformCaptureReducerAotCompileDecline::UnequalMultiplier { row: 1, .. }
        )
    ));
    let unproved = compile(
        &[r"(ab)+", r"(cd)?"],
        target,
        UniformCaptureReducerOperation::CountCaptures,
    )
    .unwrap();
    assert!(matches!(
        unproved,
        SharedUniformCaptureReducerAotCompileDisposition::Declined(
            SharedUniformCaptureReducerAotCompileDecline::Participation { row: 1, .. }
        )
    ));
}

#[test]
fn parse_and_proof_resource_failures_are_terminal() {
    let target = targets()[0];
    let parse = compile(
        &[r"(ab)+", r"("],
        target,
        UniformCaptureReducerOperation::CountCaptures,
    )
    .unwrap_err();
    assert!(matches!(
        parse,
        SharedUniformCaptureReducerAotCompileError::Parse { row: 1, .. }
    ));

    let error = compile_shared_uniform_capture_reducer_aot_reported(
        OrderedManyAotCompileRequest::new(rows(&[r"(ab)+", r"(cd)+"]), target)
            .profile(RustProfile::rebar_1_12_4()),
        UniformCaptureReducerOperation::CountCaptures,
        UniformCaptureParticipationLimits {
            max_work: 0,
            ..UniformCaptureParticipationLimits::default()
        },
        SlowAotLimits::default(),
    )
    .unwrap_err();
    assert!(
        matches!(
            &error,
            SharedUniformCaptureReducerAotCompileError::Participation {
                source: fre_lower::UniformCaptureParticipationError::ResourceLimit {
                    resource: UniformCaptureParticipationResource::Work,
                    ..
                },
                ..
            }
        ),
        "unexpected proof-resource result: {error:?}"
    );
}

#[test]
fn ordered_many_native_data_and_object_refusals_remain_typed() {
    let target = targets()[0];
    let patterns = [r"((?-u:[\x00-\xFF])\bfoo\b)", r"((?-u:[\x00-\xFF])\bbar\b)"];
    let make_request = |object_bytes, native_data_bytes| {
        let mut limits = OrderedManyAotCompileLimits::default();
        limits.compile.max_object_bytes = object_bytes;
        let mut slow = SlowAotLimits::default();
        slow.max_native_data_bytes = native_data_bytes;
        (
            OrderedManyAotCompileRequest::new(rows(&patterns), target)
                .profile(RustProfile::rebar_1_12_4())
                .mode(CompileMode::Fast)
                .limits(limits),
            slow,
        )
    };
    let (request, slow) = make_request(
        OrderedManyAotCompileLimits::default()
            .compile
            .max_object_bytes,
        0,
    );
    let native_data = compile_shared_uniform_capture_reducer_aot_reported(
        request,
        UniformCaptureReducerOperation::CountCaptures,
        UniformCaptureParticipationLimits::default(),
        slow,
    )
    .unwrap();
    assert!(matches!(
        native_data,
        SharedUniformCaptureReducerAotCompileDisposition::Declined(
            SharedUniformCaptureReducerAotCompileDecline::NativeDataBytes { limit: 0, .. }
        )
    ));

    let (request, slow) = make_request(
        OrderedManyAotCompileLimits::default()
            .compile
            .max_object_bytes,
        SlowAotLimits::default().max_native_data_bytes,
    );
    let unbounded = compile_shared_uniform_capture_reducer_aot_reported(
        request,
        UniformCaptureReducerOperation::CountCaptures,
        UniformCaptureParticipationLimits::default(),
        slow,
    )
    .unwrap()
    .into_compiled()
    .expect("uncapped V15 resource fixture compiles");
    assert_eq!(
        unbounded.receipt().aggregate_strategy(),
        PreparedAggregateStrategy::NativeOrderedNfaFused
    );
    let object_limit = unbounded.compiled().receipt().data_bytes;
    assert!(object_limit < unbounded.compiled().object().len());

    let (request, slow) =
        make_request(object_limit, SlowAotLimits::default().max_native_data_bytes);
    let object = compile_shared_uniform_capture_reducer_aot_reported(
        request,
        UniformCaptureReducerOperation::CountCaptures,
        UniformCaptureParticipationLimits::default(),
        slow,
    );
    assert!(
        matches!(
            &object,
            Ok(SharedUniformCaptureReducerAotCompileDisposition::Declined(
                SharedUniformCaptureReducerAotCompileDecline::ObjectBytes { limit, .. }
            )) if *limit == object_limit
        ),
        "unexpected object-resource result: {object:?}"
    );
}
