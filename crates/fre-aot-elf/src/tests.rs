use fre_jit_aarch64::{BackendVersion, EmitLimits, SearchBackendPolicy, emit_with_backend};
use fre_kernel_ir::{AnchorFlags, Span, ValidateLimits, build_exact_literal};

use crate::{
    BindingIdentity, ObjectLimitsV1, PLATFORM_LINUX_V1, emit_search_object_v1,
    inspect_search_object_v1, validate_search_object_v1,
};

const TEST_BINDING: [u8; 32] = [0x5a; 32];

fn image(literal: &[u8], backend: SearchBackendPolicy) -> fre_jit_aarch64::NativeImage {
    let program =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("exact-literal test KIR");
    emit_with_backend(&program, backend, EmitLimits::default()).expect("test native image")
}

#[test]
fn v8_v12_and_explicit_tag21_emit_deterministic_strict_elf_objects() {
    for (literal, backend, version) in [
        (
            b"needle".as_slice(),
            SearchBackendPolicy::AsimdV8,
            BackendVersion::SEARCH_V8,
        ),
        (
            b"0123456789abcdef".as_slice(),
            SearchBackendPolicy::Sve2Fixed16V2,
            BackendVersion::SEARCH_SVE2_FIXED16_V2,
        ),
        (
            b"needle".as_slice(),
            SearchBackendPolicy::AsimdV12,
            BackendVersion::SEARCH_V12,
        ),
    ] {
        let image = image(literal, backend);
        let binding = BindingIdentity::new(TEST_BINDING).expect("nonzero test binding");
        let first =
            emit_search_object_v1(&image, binding, ObjectLimitsV1::default()).expect("first ELF");
        let second =
            emit_search_object_v1(&image, binding, ObjectLimitsV1::default()).expect("second ELF");
        assert_eq!(first.as_bytes(), second.as_bytes());
        assert_eq!(first.object_identity(), second.object_identity());
        assert_eq!(first.compile_identity(), second.compile_identity());
        assert_eq!(&first.as_bytes()[..4], b"\x7fELF");

        let inspection = inspect_search_object_v1(first.as_bytes(), ObjectLimitsV1::default())
            .expect("strict ELF inspection");
        assert_eq!(inspection.metadata().backend_version(), version.0);
        assert_eq!(inspection.metadata().platform(), PLATFORM_LINUX_V1);
        assert_eq!(
            inspection.metadata().artifact_identity(),
            image.artifact_identity().as_bytes()
        );
        validate_search_object_v1(&image, binding, first.as_bytes(), ObjectLimitsV1::default())
            .expect("expected-image validation");
    }
}

#[test]
fn every_single_byte_mutation_is_rejected() {
    let image = image(b"0123456789abcdef", SearchBackendPolicy::Sve2Fixed16V2);
    let binding = BindingIdentity::new(TEST_BINDING).expect("nonzero test binding");
    let object =
        emit_search_object_v1(&image, binding, ObjectLimitsV1::default()).expect("canonical ELF");
    for index in 0..object.as_bytes().len() {
        let mut changed = object.as_bytes().to_vec();
        changed[index] ^= 1;
        assert!(
            inspect_search_object_v1(&changed, ObjectLimitsV1::default()).is_err(),
            "single-byte mutation {index} survived strict inspection"
        );
    }
}
