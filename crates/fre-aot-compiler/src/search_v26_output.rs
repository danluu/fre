//! Inert output-specific Search V26/tag39 source-to-object builders.
//!
//! These helpers expose the existing generic non-LLVM compiler for
//! [`Exists`] and [`SelectedEnd`] without pretending either output implements
//! Span's two-word C publication contract. They accept only decoded exact
//! literals in the prospective V26 production envelope, 9..=32 bytes, and
//! return deterministic Mach-O or ELF implementation objects.
//!
//! No helper in this module creates an expectation, glue object, linked
//! image, runtime family row, or callable. Every successful result retains
//! [`SearchAotRuntimeAuthorityV1::Absent`].

use core::fmt;

use fre::RustProfile;
use fre_aot_search_contract::search_v26_production_literal_width_is_valid_v1;
use fre_kernel_ir::{Exists, Operation, SelectedEnd};

use crate::{
    LinuxAarch64ExactSearchManifestV1, LinuxAarch64SearchCompilePolicyV1,
    LinuxSearchCompileErrorV1, LinuxSearchCompiledObjectV1, LinuxSearchManifestErrorV1,
    MacosAarch64ExactSearchManifestV1, SearchAotRuntimeAuthorityV1, SearchCompileErrorV1,
    SearchCompilePolicyV1, SearchCompiledObjectV1, SearchManifestErrorV1,
    plan_and_compile_linux_aarch64_exact_search_v1, plan_and_compile_macos_aarch64_exact_search_v1,
};

/// Failure while compiling one inert output-specific V26/tag39 object.
#[derive(Debug)]
#[non_exhaustive]
pub enum SearchV26OutputObjectErrorV1 {
    /// The decoded, compiler-sealed live literal is outside the prospective
    /// production envelope. The compiled candidate is discarded and no
    /// output object is returned.
    LiteralWidthOutsideProductionEnvelope {
        bytes: u32,
    },
    MacosManifest(SearchManifestErrorV1),
    MacosCompile(SearchCompileErrorV1),
    LinuxManifest(LinuxSearchManifestErrorV1),
    LinuxCompile(LinuxSearchCompileErrorV1),
}

impl fmt::Display for SearchV26OutputObjectErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FRE tag39 inert output-object compilation failed: {self:?}"
        )
    }
}

impl std::error::Error for SearchV26OutputObjectErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::LiteralWidthOutsideProductionEnvelope { .. } => None,
            Self::MacosManifest(error) => Some(error),
            Self::MacosCompile(error) => Some(error),
            Self::LinuxManifest(error) => Some(error),
            Self::LinuxCompile(error) => Some(error),
        }
    }
}

fn build_macos_aarch64_search_v26_output_object_v1<O: Operation>(
    source: Vec<u8>,
    profile: RustProfile,
    compile_policy: &SearchCompilePolicyV1,
) -> Result<SearchCompiledObjectV1<O>, SearchV26OutputObjectErrorV1> {
    let manifest = MacosAarch64ExactSearchManifestV1::<O>::v26_candidate(*compile_policy)
        .map_err(SearchV26OutputObjectErrorV1::MacosManifest)?;
    let implementation = plan_and_compile_macos_aarch64_exact_search_v1(manifest, source, profile)
        .map_err(SearchV26OutputObjectErrorV1::MacosCompile)?;
    let live_literal_bytes = implementation.receipt().literal_bytes();
    if !search_v26_production_literal_width_is_valid_v1(live_literal_bytes) {
        return Err(
            SearchV26OutputObjectErrorV1::LiteralWidthOutsideProductionEnvelope {
                bytes: live_literal_bytes,
            },
        );
    }
    debug_assert_eq!(
        implementation.runtime_authority(),
        SearchAotRuntimeAuthorityV1::Absent
    );
    Ok(implementation)
}

fn build_linux_aarch64_search_v26_output_object_v1<O: Operation>(
    source: Vec<u8>,
    profile: RustProfile,
    compile_policy: LinuxAarch64SearchCompilePolicyV1,
) -> Result<LinuxSearchCompiledObjectV1<O>, SearchV26OutputObjectErrorV1> {
    let manifest = LinuxAarch64ExactSearchManifestV1::<O>::v26_candidate(compile_policy)
        .map_err(SearchV26OutputObjectErrorV1::LinuxManifest)?;
    let implementation = plan_and_compile_linux_aarch64_exact_search_v1(manifest, source, profile)
        .map_err(SearchV26OutputObjectErrorV1::LinuxCompile)?;
    let live_literal_bytes = implementation.receipt().literal_bytes();
    if !search_v26_production_literal_width_is_valid_v1(live_literal_bytes) {
        return Err(
            SearchV26OutputObjectErrorV1::LiteralWidthOutsideProductionEnvelope {
                bytes: live_literal_bytes,
            },
        );
    }
    debug_assert_eq!(
        implementation.runtime_authority(),
        SearchAotRuntimeAuthorityV1::Absent
    );
    Ok(implementation)
}

/// Compile one exact-literal `Exists` source into an inert macOS/AArch64
/// V26/tag39 Mach-O object.
///
/// The decoded literal must contain 9..=32 bytes. This function neither uses
/// LLVM for regex code generation nor creates Span expectation/glue state.
pub fn build_macos_aarch64_search_v26_exists_object_v1(
    source: Vec<u8>,
    profile: RustProfile,
    compile_policy: SearchCompilePolicyV1,
) -> Result<SearchCompiledObjectV1<Exists>, SearchV26OutputObjectErrorV1> {
    build_macos_aarch64_search_v26_output_object_v1(source, profile, &compile_policy)
}

/// Compile one exact-literal `SelectedEnd` source into an inert
/// macOS/AArch64 V26/tag39 Mach-O object.
///
/// The decoded literal must contain 9..=32 bytes. This function neither uses
/// LLVM for regex code generation nor creates Span expectation/glue state.
pub fn build_macos_aarch64_search_v26_selected_end_object_v1(
    source: Vec<u8>,
    profile: RustProfile,
    compile_policy: SearchCompilePolicyV1,
) -> Result<SearchCompiledObjectV1<SelectedEnd>, SearchV26OutputObjectErrorV1> {
    build_macos_aarch64_search_v26_output_object_v1(source, profile, &compile_policy)
}

/// Compile one exact-literal `Exists` source into an inert Linux/AArch64
/// V26/tag39 ELF object.
///
/// The decoded literal must contain 9..=32 bytes. This function neither uses
/// LLVM for regex code generation nor creates Span expectation/glue state.
pub fn build_linux_aarch64_search_v26_exists_object_v1(
    source: Vec<u8>,
    profile: RustProfile,
    compile_policy: LinuxAarch64SearchCompilePolicyV1,
) -> Result<LinuxSearchCompiledObjectV1<Exists>, SearchV26OutputObjectErrorV1> {
    build_linux_aarch64_search_v26_output_object_v1(source, profile, compile_policy)
}

/// Compile one exact-literal `SelectedEnd` source into an inert Linux/AArch64
/// V26/tag39 ELF object.
///
/// The decoded literal must contain 9..=32 bytes. This function neither uses
/// LLVM for regex code generation nor creates Span expectation/glue state.
pub fn build_linux_aarch64_search_v26_selected_end_object_v1(
    source: Vec<u8>,
    profile: RustProfile,
    compile_policy: LinuxAarch64SearchCompilePolicyV1,
) -> Result<LinuxSearchCompiledObjectV1<SelectedEnd>, SearchV26OutputObjectErrorV1> {
    build_linux_aarch64_search_v26_output_object_v1(source, profile, compile_policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fre_aot_elf::ObjectLimitsV1;
    use fre_aot_macho::ObjectLimits;
    use fre_aot_search_contract::SEARCH_BACKEND_ASIMD_TAG39_V1;
    use fre_jit_aarch64::{
        AotLimits, BackendVersion, CpuFeatures, EmitLimits, SearchBackendPolicy, emit_with_backend,
    };
    use fre_kernel_ir::{AnchorFlags, OutputKind, ValidateLimits, build_exact_literal};

    const ESCAPED_WIDTH_8: &[u8] = br"\x61\x62\x63\x64\x65\x66\x67\x68";
    const WIDTH_9: &[u8] = b"abcdefghi";
    const WIDTH_32: &[u8] = b"abcdefghijklmnopqrstuvwxyz012345";

    fn assert_width_error(error: &SearchV26OutputObjectErrorV1) {
        assert!(matches!(
            error,
            SearchV26OutputObjectErrorV1::LiteralWidthOutsideProductionEnvelope { bytes: 8 }
        ));
    }

    #[test]
    fn decoded_width_eight_is_refused_for_both_outputs_and_targets() {
        assert_width_error(
            &build_macos_aarch64_search_v26_exists_object_v1(
                ESCAPED_WIDTH_8.to_vec(),
                RustProfile::default(),
                SearchCompilePolicyV1::default(),
            )
            .unwrap_err(),
        );
        assert_width_error(
            &build_macos_aarch64_search_v26_selected_end_object_v1(
                ESCAPED_WIDTH_8.to_vec(),
                RustProfile::default(),
                SearchCompilePolicyV1::default(),
            )
            .unwrap_err(),
        );
        assert_width_error(
            &build_linux_aarch64_search_v26_exists_object_v1(
                ESCAPED_WIDTH_8.to_vec(),
                RustProfile::default(),
                LinuxAarch64SearchCompilePolicyV1::default(),
            )
            .unwrap_err(),
        );
        assert_width_error(
            &build_linux_aarch64_search_v26_selected_end_object_v1(
                ESCAPED_WIDTH_8.to_vec(),
                RustProfile::default(),
                LinuxAarch64SearchCompilePolicyV1::default(),
            )
            .unwrap_err(),
        );
    }

    fn assert_macos_contract<O: Operation>(
        compiled: &SearchCompiledObjectV1<O>,
        expected_width: u32,
    ) {
        let receipt = compiled.receipt();
        assert_eq!(receipt.literal_bytes(), expected_width);
        assert_eq!(receipt.output(), O::KIND);
        assert_eq!(
            receipt.metadata().backend_version(),
            SEARCH_BACKEND_ASIMD_TAG39_V1
        );
        assert_eq!(receipt.metadata().features(), CpuFeatures::ASIMD.bits());
        assert_eq!(
            compiled.runtime_authority(),
            SearchAotRuntimeAuthorityV1::Absent
        );
        assert_eq!(
            receipt.runtime_authority(),
            SearchAotRuntimeAuthorityV1::Absent
        );
    }

    fn assert_linux_contract<O: Operation>(
        compiled: &LinuxSearchCompiledObjectV1<O>,
        expected_width: u32,
    ) {
        let receipt = compiled.receipt();
        assert_eq!(receipt.literal_bytes(), expected_width);
        assert_eq!(receipt.output(), O::KIND);
        assert_eq!(
            receipt.backend(),
            crate::LinuxAarch64SearchBackendV1::AsimdV26
        );
        assert_eq!(
            receipt.metadata().backend_version(),
            SEARCH_BACKEND_ASIMD_TAG39_V1
        );
        assert_eq!(receipt.metadata().features(), CpuFeatures::ASIMD.bits());
        assert_eq!(receipt.backend().required_features(), CpuFeatures::ASIMD);
        assert_eq!(receipt.backend().fixed_active_vector_bytes(), 0);
        assert_eq!(
            compiled.runtime_authority(),
            SearchAotRuntimeAuthorityV1::Absent
        );
        assert_eq!(
            receipt.runtime_authority(),
            SearchAotRuntimeAuthorityV1::Absent
        );
    }

    #[test]
    fn inclusive_width_boundaries_bind_output_backend_isa_and_absent_authority() {
        for (source, expected_width) in [(WIDTH_9, 9), (WIDTH_32, 32)] {
            let macos_exists = build_macos_aarch64_search_v26_exists_object_v1(
                source.to_vec(),
                RustProfile::default(),
                SearchCompilePolicyV1::default(),
            )
            .unwrap();
            assert_macos_contract(&macos_exists, expected_width);
            assert_eq!(macos_exists.receipt().output(), OutputKind::Exists);

            let macos_selected_end = build_macos_aarch64_search_v26_selected_end_object_v1(
                source.to_vec(),
                RustProfile::default(),
                SearchCompilePolicyV1::default(),
            )
            .unwrap();
            assert_macos_contract(&macos_selected_end, expected_width);
            assert_eq!(
                macos_selected_end.receipt().output(),
                OutputKind::SelectedEnd
            );

            let linux_exists = build_linux_aarch64_search_v26_exists_object_v1(
                source.to_vec(),
                RustProfile::default(),
                LinuxAarch64SearchCompilePolicyV1::default(),
            )
            .unwrap();
            assert_linux_contract(&linux_exists, expected_width);
            assert_eq!(linux_exists.receipt().output(), OutputKind::Exists);

            let linux_selected_end = build_linux_aarch64_search_v26_selected_end_object_v1(
                source.to_vec(),
                RustProfile::default(),
                LinuxAarch64SearchCompilePolicyV1::default(),
            )
            .unwrap();
            assert_linux_contract(&linux_selected_end, expected_width);
            assert_eq!(
                linux_selected_end.receipt().output(),
                OutputKind::SelectedEnd
            );
        }
    }

    fn assert_macos_roundtrip_and_v25_parity<O: Operation>(source: &[u8]) {
        let first = build_macos_aarch64_search_v26_output_object_v1::<O>(
            source.to_vec(),
            RustProfile::default(),
            &SearchCompilePolicyV1::default(),
        )
        .unwrap();
        let second = build_macos_aarch64_search_v26_output_object_v1::<O>(
            source.to_vec(),
            RustProfile::default(),
            &SearchCompilePolicyV1::default(),
        )
        .unwrap();
        assert_eq!(first.object().as_bytes(), second.object().as_bytes());
        assert_eq!(first.receipt(), second.receipt());

        let v26_inspection = first
            .receipt()
            .validate_object(first.object().as_bytes(), ObjectLimits::default())
            .expect("V26 receipt must reopen its Mach-O object");
        let canonical_receipt = first
            .receipt()
            .canonical_bytes()
            .expect("V26 Mach-O receipt must encode deterministically");

        let program =
            build_exact_literal::<O>(source, AnchorFlags::default(), ValidateLimits::default())
                .expect("typed V26 KIR");
        let image = emit_with_backend(
            &program,
            SearchBackendPolicy::AsimdV26,
            EmitLimits::default(),
        )
        .expect("typed V26 image");
        let aot = image
            .to_aot(AotLimits::default())
            .expect("typed V26 AOT container");
        assert_eq!(aot.identity(), image.artifact_identity());
        assert_eq!(
            image.artifact_identity(),
            first.receipt().native_artifact_identity()
        );
        assert_eq!(&aot.as_bytes()[..8], b"FREA64\0\x27");
        assert_eq!(&aot.as_bytes()[8..10], &39_u16.to_le_bytes());

        let v25 = plan_and_compile_macos_aarch64_exact_search_v1(
            MacosAarch64ExactSearchManifestV1::<O>::v25_candidate(SearchCompilePolicyV1::default())
                .expect("typed V25 manifest"),
            source.to_vec(),
            RustProfile::default(),
        )
        .expect("typed V25 object");
        let v25_inspection = v25
            .receipt()
            .validate_object(v25.object().as_bytes(), ObjectLimits::default())
            .expect("V25 receipt must reopen its Mach-O object");
        assert_eq!(v26_inspection.payload(), v25_inspection.payload());
        assert_ne!(first.object().as_bytes(), v25.object().as_bytes());
        assert_ne!(
            first.receipt().native_artifact_identity(),
            v25.receipt().native_artifact_identity()
        );
        assert_eq!(
            canonical_receipt,
            first.receipt().canonical_bytes().unwrap()
        );
    }

    fn assert_linux_roundtrip_and_v25_parity<O: Operation>(source: &[u8]) {
        let first = build_linux_aarch64_search_v26_output_object_v1::<O>(
            source.to_vec(),
            RustProfile::default(),
            LinuxAarch64SearchCompilePolicyV1::default(),
        )
        .unwrap();
        let second = build_linux_aarch64_search_v26_output_object_v1::<O>(
            source.to_vec(),
            RustProfile::default(),
            LinuxAarch64SearchCompilePolicyV1::default(),
        )
        .unwrap();
        assert_eq!(first.object().as_bytes(), second.object().as_bytes());
        assert_eq!(first.receipt(), second.receipt());

        let receipt_bytes = first
            .receipt()
            .canonical_receipt_bytes()
            .expect("V26 ELF receipt must encode deterministically");
        let reopened = first
            .receipt()
            .validate_canonical_receipt_bytes(&receipt_bytes)
            .expect("V26 ELF receipt must round-trip");
        let v26_inspection = reopened
            .validate_object(first.object().as_bytes(), ObjectLimitsV1::default())
            .expect("reopened V26 receipt must bind its ELF object");

        let program =
            build_exact_literal::<O>(source, AnchorFlags::default(), ValidateLimits::default())
                .expect("typed V26 KIR");
        let image = emit_with_backend(
            &program,
            SearchBackendPolicy::AsimdV26,
            EmitLimits::default(),
        )
        .expect("typed V26 image");
        reopened
            .validate_reconstructed_image_object(
                &image,
                first.object().as_bytes(),
                ObjectLimitsV1::default(),
            )
            .expect("V26 ELF object must bind the reconstructed image");
        let aot = image
            .to_aot(AotLimits::default())
            .expect("typed V26 AOT container");
        assert_eq!(aot.identity(), image.artifact_identity());
        assert_eq!(
            image.artifact_identity(),
            first.receipt().artifact_identity()
        );
        assert_eq!(&aot.as_bytes()[..8], b"FREA64\0\x27");
        assert_eq!(&aot.as_bytes()[8..10], &39_u16.to_le_bytes());

        let v25 = plan_and_compile_linux_aarch64_exact_search_v1(
            LinuxAarch64ExactSearchManifestV1::<O>::v25_candidate(
                LinuxAarch64SearchCompilePolicyV1::default(),
            )
            .expect("typed V25 manifest"),
            source.to_vec(),
            RustProfile::default(),
        )
        .expect("typed V25 object");
        let v25_inspection = v25
            .receipt()
            .validate_object(v25.object().as_bytes(), ObjectLimitsV1::default())
            .expect("V25 receipt must reopen its ELF object");
        assert_eq!(v26_inspection.payload(), v25_inspection.payload());
        assert_ne!(first.object().as_bytes(), v25.object().as_bytes());
        assert_ne!(
            first.receipt().artifact_identity(),
            v25.receipt().artifact_identity()
        );
        assert_eq!(
            receipt_bytes,
            first.receipt().canonical_receipt_bytes().unwrap()
        );
    }

    #[test]
    fn output_objects_are_deterministic_roundtrip_and_retain_wide_v25_payloads() {
        for source in [WIDTH_9, WIDTH_32] {
            assert_macos_roundtrip_and_v25_parity::<Exists>(source);
            assert_macos_roundtrip_and_v25_parity::<SelectedEnd>(source);
            assert_linux_roundtrip_and_v25_parity::<Exists>(source);
            assert_linux_roundtrip_and_v25_parity::<SelectedEnd>(source);
        }
    }

    #[test]
    fn output_builders_do_not_change_defaults_or_create_span_abi_authority() {
        assert_eq!(SearchBackendPolicy::CURRENT, SearchBackendPolicy::AsimdV8);
        assert_eq!(BackendVersion::CURRENT, BackendVersion::SEARCH_V8);
        assert_eq!(
            MacosAarch64ExactSearchManifestV1::<Exists>::default().backend(),
            crate::MacosAarch64SearchBackendV1::AsimdV8
        );
        assert_eq!(
            LinuxAarch64ExactSearchManifestV1::<SelectedEnd>::default().backend(),
            crate::LinuxAarch64SearchBackendV1::AsimdV8
        );

        let macos = build_macos_aarch64_search_v26_selected_end_object_v1(
            WIDTH_9.to_vec(),
            RustProfile::default(),
            SearchCompilePolicyV1::default(),
        )
        .unwrap();
        let linux = build_linux_aarch64_search_v26_exists_object_v1(
            WIDTH_9.to_vec(),
            RustProfile::default(),
            LinuxAarch64SearchCompilePolicyV1::default(),
        )
        .unwrap();
        assert_eq!(
            macos.runtime_authority(),
            SearchAotRuntimeAuthorityV1::Absent
        );
        assert_eq!(
            linux.runtime_authority(),
            SearchAotRuntimeAuthorityV1::Absent
        );
    }
}
