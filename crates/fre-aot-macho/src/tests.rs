use fre_aot_aarch64::{
    AOT_COUNT_BACKEND_ALGORITHM_VERSION_V2, AOT_COUNT_BACKEND_VERSION_V2, CountEmitLimitsV2,
    emit_count_v2,
};
use fre_jit_aarch64::{
    BackendVersion, EmitLimits, NativeAggregateImage, NativeImage, SearchBackendPolicy,
    emit_exact_aggregate, emit_with_backend,
};
use fre_kernel_ir::{
    AnchorFlags, Count, Span, ValidateLimits, build_exact_aggregate, build_exact_literal,
};
use sha2::{Digest, Sha256};

use super::*;
use crate::macho::{
    CONTENT_OFFSET, MetadataMutationForTest, ObjectLayout,
    rewrite_metadata_with_recomputed_compile_identity_for_test,
};

fn aggregate_image(literal: &[u8]) -> NativeAggregateImage {
    let program = build_exact_aggregate::<Count>(literal, ValidateLimits::default())
        .expect("bounded exact aggregate");
    emit_exact_aggregate(&program, EmitLimits::default()).expect("audited aggregate image")
}

fn search_image(literal: &[u8]) -> NativeImage {
    search_image_with_backend(literal, SearchBackendPolicy::AsimdV8)
}

fn search_image_with_backend(literal: &[u8], backend: SearchBackendPolicy) -> NativeImage {
    let program =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("bounded exact search");
    emit_with_backend(&program, backend, EmitLimits::default()).expect("audited Search image")
}

#[test]
fn aggregate_object_is_deterministic_contiguous_and_fully_bound() {
    let image = aggregate_image(b"aba");
    let binding = BindingIdentity::new([0x5a; 32]).unwrap();
    let first = emit_aggregate_object(&image, binding, ObjectLimits::default()).unwrap();
    let second = emit_aggregate_object(&image, binding, ObjectLimits::default()).unwrap();
    assert_eq!(first.as_bytes(), second.as_bytes());
    assert_eq!(first.object_identity(), second.object_identity());

    let inspected = inspect_object(first.as_bytes(), ObjectLimits::default()).unwrap();
    let metadata = inspected.metadata();
    assert_eq!(
        metadata.backend_version(),
        BackendVersion::AGGREGATE_CURRENT.0
    );
    assert_eq!(metadata.abi_kind(), AbiKind::Aggregate);
    assert_eq!(metadata.output_kind(), 1);
    assert_eq!(metadata.literal_bytes(), 3);
    assert_eq!(metadata.status_bits(), 64);
    assert_eq!(metadata.abi_schema(), 1);
    assert!(binding.matches_claim(metadata.claimed_binding_identity()));
    assert!(
        first
            .compile_identity()
            .matches_claim(metadata.claimed_compile_identity())
    );
    assert!(
        first
            .object_identity()
            .matches_claim(inspected.claimed_object_identity())
    );
    let symbols = first.exported_symbols();
    let suffix = first.compile_identity().to_string();
    assert!(symbols.entry().as_str().ends_with(&suffix));
    assert!(symbols.payload().as_str().ends_with(&suffix));
    assert!(symbols.metadata().as_str().ends_with(&suffix));
    assert_eq!(
        symbols.entry().as_str().len(),
        AGGREGATE_ENTRY_SYMBOL_PREFIX_V1.len() + EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V1
    );

    let rodata_start = usize::try_from(image.layout().rodata_from_code_start).unwrap();
    assert_eq!(&inspected.payload()[..image.code().len()], image.code());
    assert!(
        inspected.payload()[image.code().len()..rodata_start]
            .iter()
            .all(|&byte| byte == 0)
    );
    assert_eq!(&inspected.payload()[rodata_start..], image.rodata());
    validate_aggregate_object(&image, binding, first.as_bytes(), ObjectLimits::default()).unwrap();
}

#[test]
fn count_v2_object_is_deterministic_audited_and_fully_bound() {
    let program = build_exact_aggregate::<Count>(b"abab", ValidateLimits::default())
        .expect("bounded exact aggregate");
    let image =
        emit_count_v2(&program, CountEmitLimitsV2::default()).expect("audited Count v2 image");
    let binding = BindingIdentity::new([0x6d; 32]).unwrap();
    let first = emit_count_v2_object(&program, &image, binding, ObjectLimits::default())
        .expect("Count v2 object");
    let second = emit_count_v2_object(&program, &image, binding, ObjectLimits::default())
        .expect("deterministic Count v2 object");
    assert_eq!(first.as_bytes(), second.as_bytes());
    assert_eq!(first.object_identity(), second.object_identity());
    let build_report = first.report();
    assert_eq!(
        build_report.image_audit_work_upper_bound,
        image.build_receipt().audit.work_upper_bound
    );
    assert_eq!(
        build_report.image_audit_scratch_upper_bound,
        image.build_receipt().audit.scratch_bytes_upper_bound
    );
    let exact_limits = ObjectLimits {
        max_object_bytes: u64::try_from(build_report.object_bytes).unwrap(),
        max_persistent_bytes: u64::try_from(build_report.persistent_capacity_bytes).unwrap(),
        max_payload_bytes: u64::try_from(build_report.payload_bytes).unwrap(),
        max_work: build_report.total_work,
        max_scratch_bytes: build_report.scratch_bytes,
        max_sections: u64::from(build_report.sections),
        max_symbols: u64::from(build_report.symbols),
    };
    emit_count_v2_object(&program, &image, binding, exact_limits)
        .expect("sealed Count v2 report admits exact object limits");
    for (resource, limits) in [
        (
            ObjectResource::Work,
            ObjectLimits {
                max_work: exact_limits.max_work.checked_sub(1).unwrap(),
                ..exact_limits
            },
        ),
        (
            ObjectResource::ScratchBytes,
            ObjectLimits {
                max_scratch_bytes: exact_limits.max_scratch_bytes.checked_sub(1).unwrap(),
                ..exact_limits
            },
        ),
    ] {
        assert!(matches!(
            emit_count_v2_object(&program, &image, binding, limits),
            Err(ObjectError::ResourceLimit {
                resource: actual,
                ..
            }) if actual == resource
        ));
    }

    let validated = validate_count_v2_object(
        &program,
        &image,
        binding,
        first.as_bytes(),
        ObjectLimits::default(),
    )
    .expect("strict Count v2 validation");
    let metadata = validated.inspection.metadata();
    assert_eq!(metadata.backend_version(), AOT_COUNT_BACKEND_VERSION_V2.0);
    assert_eq!(metadata.backend_version(), image.backend_version().0);
    assert_eq!(metadata.abi_kind(), AbiKind::Aggregate);
    assert_eq!(metadata.output_kind(), 1);
    assert_eq!(metadata.literal_bytes(), 4);
    assert_eq!(
        validated.image_audit.instructions,
        image.build_receipt().audit.instructions
    );
    assert_eq!(
        validated.image_audit.vector_instructions,
        image.build_receipt().audit.vector_instructions
    );
    assert_eq!(
        validated.image_audit.direct_branches,
        image.build_receipt().audit.direct_branches
    );
    assert_eq!(validated.image_audit.decode_passes, 1);
    assert_eq!(validated.image_audit.source_identity_rebuilds, 0);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one receipt test compares the complete V2 metadata and accounting contract"
)]
fn aggregate_only_metadata_v2_is_deterministic_exact_and_fully_bound() {
    let program = build_exact_aggregate::<Count>(b"metadata-v2", ValidateLimits::default())
        .expect("bounded exact aggregate");
    let image =
        emit_count_v2(&program, CountEmitLimitsV2::default()).expect("audited direct Count image");
    let binding = BindingIdentity::new([0x2d; 32]).unwrap();
    let first = emit_count_object_v2(&program, &image, binding, ObjectLimits::default())
        .expect("aggregate-only MetadataV2 object");
    let second = emit_count_object_v2(&program, &image, binding, ObjectLimits::default())
        .expect("deterministic aggregate-only MetadataV2 object");
    assert_eq!(first.as_bytes(), second.as_bytes());
    assert_eq!(first.metadata(), second.metadata());
    assert_eq!(first.report(), second.report());
    assert_eq!(first.object_identity(), second.object_identity());

    let report = first.report();
    let metadata = first.metadata();
    let inspection = inspect_count_object_v2(first.as_bytes(), ObjectLimits::default())
        .expect("strict aggregate-only MetadataV2 inspection");
    assert_eq!(metadata.format_version(), METADATA_VERSION_V2);
    assert_eq!(usize::from(metadata.record_bytes()), METADATA_BYTES_V2);
    assert_eq!(metadata.backend_version(), 0xa002);
    assert_eq!(
        metadata.algorithm_version(),
        AOT_COUNT_BACKEND_ALGORITHM_VERSION_V2
    );
    assert_eq!(
        metadata.kir_semantics_version(),
        image.support().kir_semantics_version
    );
    assert_eq!(metadata.kir_abi_version(), image.support().kir_abi_version);
    assert_eq!(metadata.abi_schema(), CALL_ABI_SCHEMA_V2);
    assert_eq!(metadata.abi_kind(), AbiKind::Aggregate);
    assert_eq!(metadata.output_kind(), image.output_kind());
    assert_eq!(metadata.actual_features(), image.target().features.bits());
    assert_eq!(
        metadata.allowed_features(),
        image.support().allowed_features.bits()
    );
    assert_eq!(metadata.payload_bytes(), image.layout().total_mapped_bytes);
    assert_eq!(
        metadata.code_bytes(),
        u32::try_from(image.code().len()).unwrap()
    );
    assert_eq!(
        metadata.rodata_offset(),
        image.layout().rodata_from_code_start
    );
    assert_eq!(metadata.rodata_bytes(), 0);
    assert_eq!(metadata.literal_bytes(), image.literal_bytes());
    assert_eq!(
        metadata.source_identity(),
        image.source_identity().as_bytes()
    );
    assert_eq!(
        metadata.artifact_identity(),
        image.artifact_identity().as_bytes()
    );
    assert!(binding.matches_claim(metadata.claimed_binding_identity()));
    assert!(
        first
            .compile_identity()
            .matches_claim(metadata.claimed_compile_identity())
    );
    assert!(
        first
            .object_identity()
            .matches_claim(inspection.claimed_object_identity())
    );
    assert_eq!(
        metadata.payload_sha256(),
        &*Sha256::digest(inspection.payload())
    );
    assert_eq!(
        first.object_identity().as_bytes(),
        &*Sha256::digest(first.as_bytes())
    );
    assert_eq!(inspection.metadata(), metadata);
    assert_eq!(inspection.metadata_bytes().len(), METADATA_BYTES_V2);
    assert_eq!(inspection.object_bytes(), report.object_bytes);
    assert_eq!(inspection.payload().len(), report.payload_bytes);
    assert_eq!(report.persistent_capacity_bytes, report.object_bytes);
    assert_eq!(
        report.image_audit_work_upper_bound,
        image.build_receipt().audit.work_upper_bound
    );
    assert_eq!(
        report.image_audit_scratch_upper_bound,
        image.build_receipt().scratch_bytes_upper_bound
    );
    assert_eq!(report.image_audit, image.build_receipt().audit);
    assert_eq!(report.image_audit.decode_passes, 1);
    assert_eq!(report.image_audit.source_identity_rebuilds, 0);
    assert_eq!(report.compile_identity, first.compile_identity());
    assert_eq!(report.object_identity, first.object_identity());
    let second_bytes = second.into_bytes();
    assert_eq!(second_bytes.len(), second_bytes.capacity());
    let mut canonical_metadata = [0_u8; METADATA_BYTES_V2];
    metadata
        .write_canonical_into(&mut canonical_metadata)
        .expect("borrowed canonical metadata writer");
    assert_eq!(canonical_metadata, metadata.canonical_bytes().unwrap());
    assert_ne!(METADATA_V2_WRITER_SCRATCH_BYTES, 0);

    let symbols = first.exported_symbols();
    let suffix = first.compile_identity().to_string();
    for (symbol, prefix) in [
        (symbols.entry().as_str(), COUNT_ENTRY_SYMBOL_PREFIX_V2),
        (symbols.payload().as_str(), COUNT_PAYLOAD_SYMBOL_PREFIX_V2),
        (symbols.metadata().as_str(), COUNT_METADATA_SYMBOL_PREFIX_V2),
    ] {
        assert!(symbol.starts_with(prefix));
        assert!(symbol.ends_with(&suffix));
        assert!(!symbol.contains("_v1_"));
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one exact-limit matrix covers construction, inspection, and external validation"
)]
fn aggregate_only_metadata_v2_build_inspect_and_validate_limits_are_exact() {
    let program = build_exact_aggregate::<Count>(b"bounded-v2", ValidateLimits::default()).unwrap();
    let image = emit_count_v2(&program, CountEmitLimitsV2::default()).unwrap();
    let binding = BindingIdentity::new([0x3e; 32]).unwrap();
    let built = emit_count_object_v2(&program, &image, binding, ObjectLimits::default()).unwrap();
    let report = built.report();
    let exact_build = ObjectLimits {
        max_object_bytes: u64::try_from(report.object_bytes).unwrap(),
        max_persistent_bytes: u64::try_from(report.persistent_capacity_bytes).unwrap(),
        max_payload_bytes: u64::try_from(report.payload_bytes).unwrap(),
        max_work: report.total_work_upper_bound,
        max_scratch_bytes: report.scratch_bytes_upper_bound,
        max_sections: u64::from(report.sections),
        max_symbols: u64::from(report.symbols),
    };
    emit_count_object_v2(&program, &image, binding, exact_build).expect("exact build limits");
    for (resource, one_below) in [
        (
            ObjectResource::ObjectBytes,
            ObjectLimits {
                max_object_bytes: exact_build.max_object_bytes - 1,
                ..exact_build
            },
        ),
        (
            ObjectResource::PersistentBytes,
            ObjectLimits {
                max_persistent_bytes: exact_build.max_persistent_bytes - 1,
                ..exact_build
            },
        ),
        (
            ObjectResource::PayloadBytes,
            ObjectLimits {
                max_payload_bytes: exact_build.max_payload_bytes - 1,
                ..exact_build
            },
        ),
        (
            ObjectResource::Work,
            ObjectLimits {
                max_work: exact_build.max_work - 1,
                ..exact_build
            },
        ),
        (
            ObjectResource::ScratchBytes,
            ObjectLimits {
                max_scratch_bytes: exact_build.max_scratch_bytes - 1,
                ..exact_build
            },
        ),
        (
            ObjectResource::Sections,
            ObjectLimits {
                max_sections: exact_build.max_sections - 1,
                ..exact_build
            },
        ),
        (
            ObjectResource::Symbols,
            ObjectLimits {
                max_symbols: exact_build.max_symbols - 1,
                ..exact_build
            },
        ),
    ] {
        assert!(matches!(
            emit_count_object_v2(&program, &image, binding, one_below),
            Err(ObjectError::ResourceLimit {
                resource: actual,
                ..
            }) if actual == resource
        ));
    }

    let inspection = inspect_count_object_v2(built.as_bytes(), ObjectLimits::default()).unwrap();
    let exact_inspection = ObjectLimits {
        max_object_bytes: u64::try_from(inspection.object_bytes()).unwrap(),
        max_payload_bytes: u64::try_from(inspection.payload().len()).unwrap(),
        max_work: inspection.work_upper_bound(),
        max_scratch_bytes: inspection.scratch_bytes_upper_bound(),
        max_sections: u64::from(report.sections),
        max_symbols: u64::from(report.symbols),
        ..ObjectLimits::default()
    };
    inspect_count_object_v2(built.as_bytes(), exact_inspection).expect("exact inspection limits");
    for (resource, one_below) in [
        (
            ObjectResource::ObjectBytes,
            ObjectLimits {
                max_object_bytes: exact_inspection.max_object_bytes - 1,
                ..exact_inspection
            },
        ),
        (
            ObjectResource::PayloadBytes,
            ObjectLimits {
                max_payload_bytes: exact_inspection.max_payload_bytes - 1,
                ..exact_inspection
            },
        ),
        (
            ObjectResource::Work,
            ObjectLimits {
                max_work: exact_inspection.max_work - 1,
                ..exact_inspection
            },
        ),
        (
            ObjectResource::ScratchBytes,
            ObjectLimits {
                max_scratch_bytes: exact_inspection.max_scratch_bytes - 1,
                ..exact_inspection
            },
        ),
        (
            ObjectResource::Sections,
            ObjectLimits {
                max_sections: exact_inspection.max_sections - 1,
                ..exact_inspection
            },
        ),
        (
            ObjectResource::Symbols,
            ObjectLimits {
                max_symbols: exact_inspection.max_symbols - 1,
                ..exact_inspection
            },
        ),
    ] {
        assert!(matches!(
            inspect_count_object_v2(built.as_bytes(), one_below),
            Err(ObjectError::ResourceLimit {
                resource: actual,
                ..
            }) if actual == resource
        ));
    }

    let validation_work = inspection
        .work_upper_bound()
        .checked_add(report.image_audit_work_upper_bound)
        .and_then(|work| work.checked_add(report.image_binding_work_upper_bound))
        .unwrap();
    let exact_validation = ObjectLimits {
        max_work: validation_work,
        max_scratch_bytes: report.scratch_bytes_upper_bound,
        ..exact_inspection
    };
    let validation = validate_count_object_v2(
        &program,
        &image,
        binding,
        built.as_bytes(),
        exact_validation,
    )
    .expect("exact validation limits");
    assert_eq!(
        validation.object_scratch_bytes_upper_bound,
        report.object_scratch_bytes_upper_bound
    );
    assert_eq!(
        validation.image_audit_scratch_upper_bound,
        report.image_audit_scratch_upper_bound
    );
    assert_eq!(
        validation.scratch_bytes_upper_bound,
        report.scratch_bytes_upper_bound
    );
    for (resource, one_below) in [
        (
            ObjectResource::Work,
            ObjectLimits {
                max_work: exact_validation.max_work - 1,
                ..exact_validation
            },
        ),
        (
            ObjectResource::ScratchBytes,
            ObjectLimits {
                max_scratch_bytes: exact_validation.max_scratch_bytes - 1,
                ..exact_validation
            },
        ),
    ] {
        assert!(matches!(
            validate_count_object_v2(
                &program,
                &image,
                binding,
                built.as_bytes(),
                one_below,
            ),
            Err(ObjectError::ResourceLimit {
                resource: actual,
                ..
            }) if actual == resource
        ));
    }
}

#[test]
fn v1_and_aggregate_only_v2_objects_are_rejected_both_ways() {
    let v1 = emit_aggregate_object(
        &aggregate_image(b"wire-separation"),
        BindingIdentity::new([0x4f; 32]).unwrap(),
        ObjectLimits::default(),
    )
    .unwrap();
    let program =
        build_exact_aggregate::<Count>(b"wire-separation", ValidateLimits::default()).unwrap();
    let image = emit_count_v2(&program, CountEmitLimitsV2::default()).unwrap();
    let v2 = emit_count_object_v2(
        &program,
        &image,
        BindingIdentity::new([0x50; 32]).unwrap(),
        ObjectLimits::default(),
    )
    .unwrap();

    assert!(inspect_object(v2.as_bytes(), ObjectLimits::default()).is_err());
    assert!(inspect_count_object_v2(v1.as_bytes(), ObjectLimits::default()).is_err());
    assert_eq!(
        &v2.metadata().canonical_bytes().unwrap()[..8],
        b"FREOM64\x02"
    );
    let v1_inspection = inspect_object(v1.as_bytes(), ObjectLimits::default()).unwrap();
    assert_eq!(&v1_inspection.metadata_bytes()[..8], b"FREOM64\x01");
}

#[test]
fn count_v2_metadata_rejects_cross_backend_tuples_even_with_recomputed_identity() {
    let program =
        build_exact_aggregate::<Count>(b"staged-filter", ValidateLimits::default()).unwrap();
    let image = emit_count_v2(&program, CountEmitLimitsV2::default()).unwrap();
    let built = emit_count_v2_object(
        &program,
        &image,
        BindingIdentity::new([0x7d; 32]).unwrap(),
        ObjectLimits::default(),
    )
    .unwrap();

    for (name, hostile) in [
        (
            "ABI",
            rewrite_metadata_with_recomputed_compile_identity_for_test(
                &built,
                MetadataMutationForTest::AbiSearch,
            ),
        ),
        (
            "output",
            rewrite_metadata_with_recomputed_compile_identity_for_test(
                &built,
                MetadataMutationForTest::OutputSpanSum,
            ),
        ),
        (
            "features",
            rewrite_metadata_with_recomputed_compile_identity_for_test(
                &built,
                MetadataMutationForTest::FeaturesNone,
            ),
        ),
        (
            "literal",
            rewrite_metadata_with_recomputed_compile_identity_for_test(
                &built,
                MetadataMutationForTest::LiteralTooWide,
            ),
        ),
        (
            "backend",
            rewrite_metadata_with_recomputed_compile_identity_for_test(
                &built,
                MetadataMutationForTest::UnknownBackend,
            ),
        ),
        (
            "rodata",
            rewrite_metadata_with_recomputed_compile_identity_for_test(
                &built,
                MetadataMutationForTest::RodataPresent,
            ),
        ),
    ] {
        let result = inspect_object(&hostile, ObjectLimits::default());
        assert!(
            matches!(
                result,
                Err(ObjectError::InvalidObject {
                    at: "metadata backend contract"
                })
            ),
            "{name} hostile tuple returned {result:?}"
        );
    }
}

#[test]
fn search_object_has_the_distinct_five_argument_contract() {
    let image = search_image(b"needle");
    let built = emit_search_object(
        &image,
        BindingIdentity::LOW_LEVEL_V1,
        ObjectLimits::default(),
    )
    .unwrap();
    let validated = validate_search_object(
        &image,
        BindingIdentity::LOW_LEVEL_V1,
        built.as_bytes(),
        ObjectLimits::default(),
    )
    .unwrap();
    let metadata = validated.inspection.metadata();
    assert_eq!(metadata.backend_version(), BackendVersion::SEARCH_V8.0);
    assert_eq!(metadata.abi_kind(), AbiKind::Search);
    assert_eq!(metadata.output_kind(), 3);
    assert_eq!(metadata.literal_bytes(), 0);
    assert_eq!(validated.image_audit.decode_passes, 1);
    assert_eq!(validated.image_audit.source_identity_rebuilds, 1);
}

#[test]
fn search_v12_v13_v15_v16_v17_v24_v25_objects_are_deterministic_inspectable_and_inert() {
    for (literal, policy, version) in [
        (
            b"needle".as_slice(),
            SearchBackendPolicy::AsimdV12,
            BackendVersion::SEARCH_V12.0,
        ),
        (
            b"needle".as_slice(),
            SearchBackendPolicy::AsimdV13,
            BackendVersion::SEARCH_V13.0,
        ),
        (
            b"phase-unique-15!".as_slice(),
            SearchBackendPolicy::AsimdV15,
            BackendVersion::SEARCH_V15.0,
        ),
        (
            b"phase-unique-16!".as_slice(),
            SearchBackendPolicy::AsimdV16,
            BackendVersion::SEARCH_V16.0,
        ),
        (
            b"phase-unique-17!".as_slice(),
            SearchBackendPolicy::AsimdV17,
            BackendVersion::SEARCH_V17.0,
        ),
        (
            b"phase-unique-24!".as_slice(),
            SearchBackendPolicy::AsimdV24,
            BackendVersion::SEARCH_V24.0,
        ),
        (
            b"sixth-promote-25!".as_slice(),
            SearchBackendPolicy::AsimdV25,
            BackendVersion::SEARCH_V25.0,
        ),
    ] {
        let image = search_image_with_backend(literal, policy);
        let binding = BindingIdentity::new([0x6b; 32]).expect("nonzero test binding");
        let first = emit_search_object(&image, binding, ObjectLimits::default())
            .expect("first candidate Mach-O object");
        let second = emit_search_object(&image, binding, ObjectLimits::default())
            .expect("second candidate Mach-O object");
        assert_eq!(first.as_bytes(), second.as_bytes());
        assert_eq!(first.object_identity(), second.object_identity());
        let inspection = inspect_object(first.as_bytes(), ObjectLimits::default())
            .expect("strict candidate Mach-O inspection");
        assert_eq!(inspection.metadata().backend_version(), version);
        validate_search_object(&image, binding, first.as_bytes(), ObjectLimits::default())
            .expect("expected-image candidate validation");
    }
}

#[test]
fn metadata_backend_domains_reject_cross_abi_retagging_with_recomputed_identity() {
    let search = emit_search_object(
        &search_image(b"search-domain"),
        BindingIdentity::LOW_LEVEL_V1,
        ObjectLimits::default(),
    )
    .unwrap();
    let aggregate = emit_aggregate_object(
        &aggregate_image(b"aggregate-domain"),
        BindingIdentity::LOW_LEVEL_V1,
        ObjectLimits::default(),
    )
    .unwrap();
    let count_program =
        build_exact_aggregate::<Count>(b"count-domain", ValidateLimits::default()).unwrap();
    let count_image = emit_count_v2(&count_program, CountEmitLimitsV2::default()).unwrap();
    let count = emit_count_v2_object(
        &count_program,
        &count_image,
        BindingIdentity::LOW_LEVEL_V1,
        ObjectLimits::default(),
    )
    .unwrap();

    for (name, built, mutation) in [
        (
            "search as aggregate ABI",
            &search,
            MetadataMutationForTest::AbiAggregate,
        ),
        (
            "search as aggregate backend",
            &search,
            MetadataMutationForTest::BackendAggregateCurrent,
        ),
        (
            "search as Count backend",
            &search,
            MetadataMutationForTest::BackendCountV2,
        ),
        (
            "aggregate as search backend",
            &aggregate,
            MetadataMutationForTest::BackendSearchV8,
        ),
        (
            "aggregate as Count backend",
            &aggregate,
            MetadataMutationForTest::BackendCountV2,
        ),
        (
            "Count as search ABI",
            &count,
            MetadataMutationForTest::AbiSearch,
        ),
        (
            "Count as search backend",
            &count,
            MetadataMutationForTest::BackendSearchV8,
        ),
        (
            "Count as aggregate backend",
            &count,
            MetadataMutationForTest::BackendAggregateCurrent,
        ),
    ] {
        let hostile = rewrite_metadata_with_recomputed_compile_identity_for_test(built, mutation);
        let result = inspect_object(&hostile, ObjectLimits::default());
        assert!(
            matches!(
                result,
                Err(ObjectError::InvalidObject {
                    at: "metadata backend contract"
                })
            ),
            "{name} hostile tuple returned {result:?}"
        );
    }
}

#[test]
fn every_object_resource_limit_is_exact() {
    let image = aggregate_image(b"bounded");
    let binding = BindingIdentity::new([0x33; 32]).unwrap();
    let baseline =
        emit_aggregate_object(&image, binding, ObjectLimits::default()).expect("baseline");
    let report = baseline.report();
    assert!(report.scratch_bytes <= HARD_MAX_SCRATCH_BYTES);
    let exact = ObjectLimits {
        max_object_bytes: u64::try_from(report.object_bytes).unwrap(),
        max_persistent_bytes: u64::try_from(report.persistent_capacity_bytes).unwrap(),
        max_payload_bytes: u64::try_from(report.payload_bytes).unwrap(),
        max_work: report.total_work,
        max_scratch_bytes: report.scratch_bytes,
        max_sections: u64::from(report.sections),
        max_symbols: u64::from(report.symbols),
    };
    emit_aggregate_object(&image, binding, exact).expect("exact limits");

    let cases = [
        (
            ObjectResource::ObjectBytes,
            ObjectLimits {
                max_object_bytes: exact.max_object_bytes - 1,
                ..exact
            },
        ),
        (
            ObjectResource::PersistentBytes,
            ObjectLimits {
                max_persistent_bytes: exact.max_persistent_bytes - 1,
                ..exact
            },
        ),
        (
            ObjectResource::PayloadBytes,
            ObjectLimits {
                max_payload_bytes: exact.max_payload_bytes - 1,
                ..exact
            },
        ),
        (
            ObjectResource::Work,
            ObjectLimits {
                max_work: exact.max_work - 1,
                ..exact
            },
        ),
        (
            ObjectResource::ScratchBytes,
            ObjectLimits {
                max_scratch_bytes: exact.max_scratch_bytes - 1,
                ..exact
            },
        ),
        (
            ObjectResource::Sections,
            ObjectLimits {
                max_sections: exact.max_sections - 1,
                ..exact
            },
        ),
        (
            ObjectResource::Symbols,
            ObjectLimits {
                max_symbols: exact.max_symbols - 1,
                ..exact
            },
        ),
    ];
    for (resource, one_below) in cases {
        assert!(matches!(
            emit_aggregate_object(&image, binding, one_below),
            Err(ObjectError::ResourceLimit {
                resource: actual,
                ..
            }) if actual == resource
        ));
    }
}

#[test]
fn strict_inspector_rejects_structural_and_content_mutations() {
    let image = aggregate_image(b"mutation");
    let built = emit_aggregate_object(
        &image,
        BindingIdentity::LOW_LEVEL_V1,
        ObjectLimits::default(),
    )
    .unwrap();
    let canonical = built.as_bytes();
    let object_layout = ObjectLayout::new(
        usize::try_from(image.layout().total_mapped_bytes).unwrap(),
        AbiKind::Aggregate,
    )
    .unwrap();

    let mut bad_magic = canonical.to_vec();
    bad_magic[0] ^= 1;
    assert!(matches!(
        inspect_object(&bad_magic, ObjectLimits::default()),
        Err(ObjectError::InvalidObject { .. })
    ));
    assert_ne!(
        &*Sha256::digest(&bad_magic),
        built.object_identity().as_bytes()
    );

    let mut bad_payload = canonical.to_vec();
    bad_payload[CONTENT_OFFSET] ^= 1;
    assert_eq!(
        inspect_object(&bad_payload, ObjectLimits::default()),
        Err(ObjectError::PayloadDigestMismatch)
    );

    let mut bad_compile_identity = canonical.to_vec();
    bad_compile_identity[object_layout.metadata_file_offset + 184] ^= 1;
    assert_eq!(
        inspect_object(&bad_compile_identity, ObjectLimits::default()),
        Err(ObjectError::CompileIdentityMismatch)
    );

    let mut bad_symbol = canonical.to_vec();
    bad_symbol[object_layout.symbol_file_offset + 4] = 0;
    assert!(matches!(
        inspect_object(&bad_symbol, ObjectLimits::default()),
        Err(ObjectError::InvalidObject { .. })
    ));

    for (name, offset, value) in [
        ("CPU type", 4, 0_u32),
        ("load-command count", 16, 5),
        ("header flags", 24, 1),
        ("segment command", 32, 0x0c),
        ("section count", 96, 3),
        ("payload offset", 152, 399),
        ("relocation offset", 160, 400),
        ("relocation count", 164, 1),
        ("payload flags", 168, 0),
        ("metadata offset", 232, 400),
        ("metadata relocation count", 244, 1),
        ("build-version command", 264, 0x0c),
        ("minimum OS", 276, 0x000c_0000),
        ("symbol count", 300, 4),
        ("undefined symbol count", 340, 1),
    ] {
        let mut mutated = canonical.to_vec();
        mutated[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        assert!(
            inspect_object(&mutated, ObjectLimits::default()).is_err(),
            "accepted hostile {name} mutation"
        );
    }

    assert!(matches!(
        inspect_object(&canonical[..canonical.len() - 1], ObjectLimits::default()),
        Err(ObjectError::InvalidObject { .. } | ObjectError::Truncated { .. })
    ));
}

#[test]
fn independent_inspection_limits_are_exact_and_precede_content_parsing() {
    let image = aggregate_image(b"inspect");
    let built = emit_aggregate_object(
        &image,
        BindingIdentity::LOW_LEVEL_V1,
        ObjectLimits::default(),
    )
    .unwrap();
    let baseline = inspect_object(built.as_bytes(), ObjectLimits::default()).unwrap();
    let exact = ObjectLimits {
        max_object_bytes: u64::try_from(baseline.object_bytes()).unwrap(),
        max_payload_bytes: u64::try_from(baseline.payload().len()).unwrap(),
        max_work: baseline.work(),
        max_scratch_bytes: baseline.scratch_bytes(),
        max_sections: HARD_MAX_SECTIONS,
        max_symbols: HARD_MAX_SYMBOLS,
        ..ObjectLimits::default()
    };
    inspect_object(built.as_bytes(), exact).expect("exact inspection limits");
    for (resource, one_below) in [
        (
            ObjectResource::ObjectBytes,
            ObjectLimits {
                max_object_bytes: exact.max_object_bytes - 1,
                ..exact
            },
        ),
        (
            ObjectResource::PayloadBytes,
            ObjectLimits {
                max_payload_bytes: exact.max_payload_bytes - 1,
                ..exact
            },
        ),
        (
            ObjectResource::Work,
            ObjectLimits {
                max_work: exact.max_work - 1,
                ..exact
            },
        ),
        (
            ObjectResource::ScratchBytes,
            ObjectLimits {
                max_scratch_bytes: exact.max_scratch_bytes - 1,
                ..exact
            },
        ),
        (
            ObjectResource::Sections,
            ObjectLimits {
                max_sections: exact.max_sections - 1,
                ..exact
            },
        ),
        (
            ObjectResource::Symbols,
            ObjectLimits {
                max_symbols: exact.max_symbols - 1,
                ..exact
            },
        ),
    ] {
        assert!(matches!(
            inspect_object(built.as_bytes(), one_below),
            Err(ObjectError::ResourceLimit {
                resource: actual,
                ..
            }) if actual == resource
        ));
    }

    let invalid = [0_u8; 32];
    assert!(matches!(
        inspect_object(
            &invalid,
            ObjectLimits {
                max_object_bytes: 31,
                ..ObjectLimits::default()
            }
        ),
        Err(ObjectError::ResourceLimit {
            resource: ObjectResource::ObjectBytes,
            ..
        })
    ));
}

#[test]
fn combined_validation_work_and_scratch_refuse_before_object_parsing() {
    let image = aggregate_image(b"validation-envelope");
    let binding = BindingIdentity::new([0x71; 32]).unwrap();
    let built =
        emit_aggregate_object(&image, binding, ObjectLimits::default()).expect("baseline object");
    let inspection =
        inspect_object(built.as_bytes(), ObjectLimits::default()).expect("baseline inspection");
    let report = built.report();
    let inspection_work = inspection.work();
    let total_work = inspection_work
        .checked_add(report.image_audit_work_upper_bound)
        .and_then(|work| work.checked_add(report.image_binding_work_upper_bound))
        .unwrap();
    let total_scratch = report
        .object_scratch_bytes
        .checked_add(report.image_audit_scratch_upper_bound)
        .unwrap();

    validate_aggregate_object(
        &image,
        binding,
        built.as_bytes(),
        ObjectLimits {
            max_work: total_work,
            max_scratch_bytes: total_scratch,
            ..ObjectLimits::default()
        },
    )
    .expect("exact combined validation envelope");

    let mut invalid = built.as_bytes().to_vec();
    invalid[0] ^= 0xff;
    for (resource, limits) in [
        (
            ObjectResource::Work,
            ObjectLimits {
                max_work: total_work - 1,
                max_scratch_bytes: total_scratch,
                ..ObjectLimits::default()
            },
        ),
        (
            ObjectResource::ScratchBytes,
            ObjectLimits {
                max_work: total_work,
                max_scratch_bytes: total_scratch - 1,
                ..ObjectLimits::default()
            },
        ),
    ] {
        assert!(matches!(
            validate_aggregate_object(&image, binding, &invalid, limits),
            Err(ObjectError::ResourceLimit {
                resource: actual,
                ..
            }) if actual == resource
        ));
    }
}

#[test]
fn binding_and_image_expectations_are_not_taken_from_object_metadata() {
    let image = aggregate_image(b"identity");
    let binding = BindingIdentity::new([0x11; 32]).unwrap();
    let built =
        emit_aggregate_object(&image, binding, ObjectLimits::default()).expect("bound object");
    let wrong_binding = BindingIdentity::new([0x12; 32]).unwrap();
    assert!(matches!(
        validate_aggregate_object(
            &image,
            wrong_binding,
            built.as_bytes(),
            ObjectLimits::default()
        ),
        Err(ObjectError::ImageBindingMismatch {
            field: "planner binding identity"
        })
    ));

    let other = aggregate_image(b"identitx");
    let other_built =
        emit_aggregate_object(&other, binding, ObjectLimits::default()).expect("object B");
    assert_ne!(built.object_identity(), other_built.object_identity());
    let other_claim =
        inspect_object(other_built.as_bytes(), ObjectLimits::default()).expect("inspect B");
    assert!(
        !built
            .object_identity()
            .matches_claim(other_claim.claimed_object_identity())
    );
    assert!(matches!(
        validate_aggregate_object(&other, binding, built.as_bytes(), ObjectLimits::default()),
        Err(ObjectError::ImageBindingMismatch { .. })
    ));

    let trusted_symbols = built.exported_symbols();
    let hostile_symbols = other_built.exported_symbols();
    let trusted_entry = trusted_symbols.entry().as_bytes();
    let hostile_entry = hostile_symbols.entry().as_bytes();
    assert_eq!(trusted_entry.len(), hostile_entry.len());
    let mut symbol_splice = built.as_bytes().to_vec();
    let entry_offset = symbol_splice
        .windows(trusted_entry.len())
        .position(|window| window == trusted_entry)
        .expect("canonical entry symbol");
    symbol_splice[entry_offset..entry_offset + hostile_entry.len()].copy_from_slice(hostile_entry);
    assert!(matches!(
        inspect_object(&symbol_splice, ObjectLimits::default()),
        Err(ObjectError::InvalidObject { .. })
    ));
}

#[test]
fn compile_receipt_changes_with_binding_and_low_level_identity_is_domain_separated() {
    let expected = Sha256::digest(b"fre-aot-macho:low-level-direct-binding:v1");
    assert_eq!(BindingIdentity::LOW_LEVEL_V1.as_bytes(), &*expected);
    assert!(BindingIdentity::new([0; 32]).is_err());

    let image = aggregate_image(b"receipt");
    let first = emit_aggregate_object(
        &image,
        BindingIdentity::new([1; 32]).unwrap(),
        ObjectLimits::default(),
    )
    .unwrap();
    let second = emit_aggregate_object(
        &image,
        BindingIdentity::new([2; 32]).unwrap(),
        ObjectLimits::default(),
    )
    .unwrap();
    assert_ne!(first.compile_identity(), second.compile_identity());
    assert_ne!(first.as_bytes(), second.as_bytes());
    assert_ne!(
        first.exported_symbols().entry(),
        second.exported_symbols().entry()
    );
    assert_ne!(
        first.exported_symbols().payload(),
        second.exported_symbols().payload()
    );
    assert_ne!(
        first.exported_symbols().metadata(),
        second.exported_symbols().metadata()
    );
}

#[test]
fn c_header_pins_metadata_offsets_and_64_bit_status_contract() {
    assert!(C_HEADER.contains("requires Apple macOS"));
    assert!(C_HEADER.contains("requires AArch64"));
    assert!(C_HEADER.contains("__ORDER_LITTLE_ENDIAN__"));
    assert!(C_HEADER.contains("UINTPTR_MAX != UINT64_MAX"));
    assert!(C_HEADER.contains("SIZE_MAX != UINT64_MAX"));
    assert!(C_HEADER.contains("sizeof(void *) == 8u"));
    assert!(C_HEADER.contains("sizeof(size_t) == 8u"));
    assert!(C_HEADER.contains("fre_aot_search_entry_fn_v1"));
    assert!(C_HEADER.contains("fre_aot_aggregate_entry_fn_v1"));
    assert!(C_HEADER.contains("must be nonnull"));
    assert!(C_HEADER.contains("must not overlap haystack"));
    assert!(C_HEADER.contains("Concurrent calls are"));
    assert!(C_HEADER.contains("leave the slot bitwise unchanged"));
    assert!(!C_HEADER.contains("extern uint64_t fre_aot_search_entry_v1("));
    assert!(!C_HEADER.contains("extern uint64_t fre_aot_aggregate_entry_v1("));
    assert!(C_HEADER.contains("uint8_t status_bits;"));
    assert!(C_HEADER.contains("uint16_t abi_schema;"));
    assert!(C_HEADER.contains("compile_identity) == 184u"));
    assert!(C_HEADER.contains("fre_aot_search_result_v1, end) == sizeof(size_t)"));
    assert!(C_HEADER.contains("fre_aot_aggregate_result_v1) == 8u"));

    let object = emit_aggregate_object(
        &aggregate_image(b"header"),
        BindingIdentity::new([0x44; 32]).unwrap(),
        ObjectLimits::default(),
    )
    .unwrap();
    let symbols = object.exported_symbols();
    let mut declarations = String::new();
    symbols
        .write_c_declarations(&mut declarations)
        .expect("render declarations");
    assert!(declarations.contains(symbols.entry().as_str()));
    assert!(declarations.contains(symbols.payload().as_str()));
    assert!(declarations.contains(symbols.metadata().as_str()));
}

#[test]
fn count_v2_c_header_pins_the_hidden_internal_call_contract() {
    for required in [
        "#define FRE_AOT_METADATA_BYTES_V2 232u",
        "#define FRE_AOT_EXPORTED_SYMBOL_SCHEMA_V2 3u",
        "#define FRE_AOT_COUNT_STATUS_OK_V2 UINT64_C(0)",
        "#define FRE_AOT_COUNT_STATUS_OVERFLOW_V2 UINT64_C(1)",
        "private-external implementation symbols",
        "final export trie or dynamic export table",
        "For length zero glue supplies a nonnull sentinel",
        "uniquely writable",
        "must replace poison",
        "leaves the complete slot bitwise unchanged",
        "every refusal leaves application-visible output unpublished",
        "never unwinds across the C ABI",
        "The entry is reentrant",
        "unsynchronized mutation through shared state",
        "offsetof(struct fre_aot_metadata_v2, actual_features) == 32u",
        "offsetof(struct fre_aot_metadata_v2, compile_identity) == 200u",
    ] {
        assert!(
            C_HEADER.contains(required),
            "missing V2 C contract: {required}"
        );
    }
}
