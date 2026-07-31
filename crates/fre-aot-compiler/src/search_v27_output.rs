//! Inert output-specific Search V27/tag40 source-to-object builders.
//!
//! These helpers expose the topology-total non-LLVM compiler for [`Exists`]
//! and [`SelectedEnd`] over every nonempty 1..=32-byte exact literal. They
//! return deterministic implementation objects only: no helper creates a
//! static binding, expectation, adopter, qualification row, or callable.

use core::fmt;

use fre::RustProfile;
use fre_aot_search_contract::{
    SEARCH_BACKEND_ASIMD_TAG40_MAX_LITERAL_BYTES_V1,
    SEARCH_BACKEND_ASIMD_TAG40_MIN_LITERAL_BYTES_V1,
};
use fre_kernel_ir::{Exists, Operation, SelectedEnd};

use crate::{
    LinuxAarch64ExactSearchManifestV1, LinuxAarch64SearchCompilePolicyV1,
    LinuxSearchCompileErrorV1, LinuxSearchCompiledObjectV1, LinuxSearchManifestErrorV1,
    MacosAarch64ExactSearchManifestV1, SearchAotRuntimeAuthorityV1, SearchCompileErrorV1,
    SearchCompilePolicyV1, SearchCompiledObjectV1, SearchManifestErrorV1,
    plan_and_compile_linux_aarch64_exact_search_v1, plan_and_compile_macos_aarch64_exact_search_v1,
};

/// Failure while compiling one inert output-specific V27/tag40 object.
#[derive(Debug)]
#[non_exhaustive]
pub enum SearchV27OutputObjectErrorV1 {
    LiteralWidthOutsideV27Envelope { bytes: u32 },
    MacosManifest(SearchManifestErrorV1),
    MacosCompile(SearchCompileErrorV1),
    LinuxManifest(LinuxSearchManifestErrorV1),
    LinuxCompile(LinuxSearchCompileErrorV1),
}

impl fmt::Display for SearchV27OutputObjectErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FRE tag40 inert output-object compilation failed: {self:?}"
        )
    }
}

impl std::error::Error for SearchV27OutputObjectErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::LiteralWidthOutsideV27Envelope { .. } => None,
            Self::MacosManifest(error) => Some(error),
            Self::MacosCompile(error) => Some(error),
            Self::LinuxManifest(error) => Some(error),
            Self::LinuxCompile(error) => Some(error),
        }
    }
}

fn width_is_valid(bytes: u32) -> bool {
    (SEARCH_BACKEND_ASIMD_TAG40_MIN_LITERAL_BYTES_V1
        ..=SEARCH_BACKEND_ASIMD_TAG40_MAX_LITERAL_BYTES_V1)
        .contains(&bytes)
}

fn build_macos_aarch64_search_v27_output_object_v1<O: Operation>(
    source: Vec<u8>,
    profile: RustProfile,
    compile_policy: &SearchCompilePolicyV1,
) -> Result<SearchCompiledObjectV1<O>, SearchV27OutputObjectErrorV1> {
    let manifest = MacosAarch64ExactSearchManifestV1::<O>::v27_candidate(*compile_policy)
        .map_err(SearchV27OutputObjectErrorV1::MacosManifest)?;
    let implementation = plan_and_compile_macos_aarch64_exact_search_v1(manifest, source, profile)
        .map_err(SearchV27OutputObjectErrorV1::MacosCompile)?;
    let literal_bytes = implementation.receipt().literal_bytes();
    if !width_is_valid(literal_bytes) {
        return Err(
            SearchV27OutputObjectErrorV1::LiteralWidthOutsideV27Envelope {
                bytes: literal_bytes,
            },
        );
    }
    debug_assert_eq!(
        implementation.runtime_authority(),
        SearchAotRuntimeAuthorityV1::Absent
    );
    Ok(implementation)
}

fn build_linux_aarch64_search_v27_output_object_v1<O: Operation>(
    source: Vec<u8>,
    profile: RustProfile,
    compile_policy: LinuxAarch64SearchCompilePolicyV1,
) -> Result<LinuxSearchCompiledObjectV1<O>, SearchV27OutputObjectErrorV1> {
    let manifest = LinuxAarch64ExactSearchManifestV1::<O>::v27_candidate(compile_policy)
        .map_err(SearchV27OutputObjectErrorV1::LinuxManifest)?;
    let implementation = plan_and_compile_linux_aarch64_exact_search_v1(manifest, source, profile)
        .map_err(SearchV27OutputObjectErrorV1::LinuxCompile)?;
    let literal_bytes = implementation.receipt().literal_bytes();
    if !width_is_valid(literal_bytes) {
        return Err(
            SearchV27OutputObjectErrorV1::LiteralWidthOutsideV27Envelope {
                bytes: literal_bytes,
            },
        );
    }
    debug_assert_eq!(
        implementation.runtime_authority(),
        SearchAotRuntimeAuthorityV1::Absent
    );
    Ok(implementation)
}

/// Compile a nonempty 1..=32-byte exact literal into an inert tag40
/// macOS/AArch64 `Exists` implementation object.
pub fn build_macos_aarch64_search_v27_exists_object_v1(
    source: Vec<u8>,
    profile: RustProfile,
    compile_policy: SearchCompilePolicyV1,
) -> Result<SearchCompiledObjectV1<Exists>, SearchV27OutputObjectErrorV1> {
    build_macos_aarch64_search_v27_output_object_v1(source, profile, &compile_policy)
}

/// Compile a nonempty 1..=32-byte exact literal into an inert tag40
/// macOS/AArch64 `SelectedEnd` implementation object.
pub fn build_macos_aarch64_search_v27_selected_end_object_v1(
    source: Vec<u8>,
    profile: RustProfile,
    compile_policy: SearchCompilePolicyV1,
) -> Result<SearchCompiledObjectV1<SelectedEnd>, SearchV27OutputObjectErrorV1> {
    build_macos_aarch64_search_v27_output_object_v1(source, profile, &compile_policy)
}

/// Compile a nonempty 1..=32-byte exact literal into an inert tag40
/// Linux/AArch64 `Exists` implementation object.
pub fn build_linux_aarch64_search_v27_exists_object_v1(
    source: Vec<u8>,
    profile: RustProfile,
    compile_policy: LinuxAarch64SearchCompilePolicyV1,
) -> Result<LinuxSearchCompiledObjectV1<Exists>, SearchV27OutputObjectErrorV1> {
    build_linux_aarch64_search_v27_output_object_v1(source, profile, compile_policy)
}

/// Compile a nonempty 1..=32-byte exact literal into an inert tag40
/// Linux/AArch64 `SelectedEnd` implementation object.
pub fn build_linux_aarch64_search_v27_selected_end_object_v1(
    source: Vec<u8>,
    profile: RustProfile,
    compile_policy: LinuxAarch64SearchCompilePolicyV1,
) -> Result<LinuxSearchCompiledObjectV1<SelectedEnd>, SearchV27OutputObjectErrorV1> {
    build_linux_aarch64_search_v27_output_object_v1(source, profile, compile_policy)
}

#[cfg(test)]
mod tests {
    use fre_aot_search_contract::SEARCH_BACKEND_ASIMD_TAG40_V1;
    use fre_kernel_ir::OutputKind;

    use super::*;

    const TOPOLOGIES: [&[u8]; 5] = [
        b"a",
        b"aaaaaaaaa",
        b"abcabcabc",
        b"abcdefghi",
        b"abcdefghijklmnopqrstuvwxyz012345",
    ];

    #[test]
    fn every_requested_topology_builds_for_both_outputs_and_formats() {
        for source in TOPOLOGIES {
            let mac_exists = build_macos_aarch64_search_v27_exists_object_v1(
                source.to_vec(),
                RustProfile::default(),
                SearchCompilePolicyV1::default(),
            )
            .unwrap();
            let mac_end = build_macos_aarch64_search_v27_selected_end_object_v1(
                source.to_vec(),
                RustProfile::default(),
                SearchCompilePolicyV1::default(),
            )
            .unwrap();
            let linux_exists = build_linux_aarch64_search_v27_exists_object_v1(
                source.to_vec(),
                RustProfile::default(),
                LinuxAarch64SearchCompilePolicyV1::default(),
            )
            .unwrap();
            let linux_end = build_linux_aarch64_search_v27_selected_end_object_v1(
                source.to_vec(),
                RustProfile::default(),
                LinuxAarch64SearchCompilePolicyV1::default(),
            )
            .unwrap();
            assert_eq!(mac_exists.receipt().output(), OutputKind::Exists);
            assert_eq!(mac_end.receipt().output(), OutputKind::SelectedEnd);
            assert_eq!(linux_exists.receipt().output(), OutputKind::Exists);
            assert_eq!(linux_end.receipt().output(), OutputKind::SelectedEnd);
            for backend in [
                mac_exists.receipt().metadata().backend_version(),
                mac_end.receipt().metadata().backend_version(),
                linux_exists.receipt().metadata().backend_version(),
                linux_end.receipt().metadata().backend_version(),
            ] {
                assert_eq!(backend, SEARCH_BACKEND_ASIMD_TAG40_V1);
            }
        }
    }

    #[test]
    fn empty_and_width_33_sources_fail_closed() {
        for source in [
            b"".as_slice(),
            b"abcdefghijklmnopqrstuvwxyz0123456".as_slice(),
        ] {
            assert!(
                build_macos_aarch64_search_v27_exists_object_v1(
                    source.to_vec(),
                    RustProfile::default(),
                    SearchCompilePolicyV1::default(),
                )
                .is_err()
            );
            assert!(
                build_linux_aarch64_search_v27_selected_end_object_v1(
                    source.to_vec(),
                    RustProfile::default(),
                    LinuxAarch64SearchCompilePolicyV1::default(),
                )
                .is_err()
            );
        }
    }
}
