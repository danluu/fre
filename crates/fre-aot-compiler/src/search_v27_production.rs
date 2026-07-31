//! Deterministic per-source tag40 implementation/production-glue bundles.
//!
//! These helpers close only the build-time object pair for one exact source:
//! an implementation object, neutral expectation, and identity-suffixed
//! production-adopter glue object. They do not link either object, populate a
//! runtime family table, inspect a final image, or grant runtime authority.
//!
//! The topology-total tag40 compiler accepts decoded exact byte literals of
//! width 1..=32. This production seam deliberately publishes glue only for
//! the independently benchmarked 17..=32-byte class. The check uses the
//! compiler-sealed decoded width, not regex source spelling.

use core::fmt;

use fre::RustProfile;
use fre_aot_search_contract::search_v27_production_literal_width_is_valid_v1;
use fre_kernel_ir::Span;

use crate::{
    LinuxAarch64ExactSearchManifestV1, LinuxAarch64SearchCompilePolicyV1,
    LinuxSearchCompileErrorV1, LinuxSearchCompiledObjectV1, LinuxSearchManifestErrorV1,
    LinuxSearchSpanFinalImageGlueErrorV1, LinuxSearchSpanFinalImageGlueLimitsV1,
    LinuxStaticSearchSpanExpectationBuildErrorV1, LinuxStaticSearchSpanExpectationV1,
    MacosAarch64ExactSearchManifestV1, PublishedLinuxSearchSpanFinalImageGlueV1,
    PublishedSearchSpanFinalImageGlueV1, SearchAotRuntimeAuthorityV1, SearchCompileErrorV1,
    SearchCompilePolicyV1, SearchCompiledObjectV1, SearchManifestErrorV1,
    SearchSpanFinalImageGlueErrorV1, SearchSpanFinalImageGlueLimitsV1,
    StaticSearchSpanExpectationBuildErrorV1, StaticSearchSpanExpectationV1,
    build_linux_static_search_span_expectation_v1, build_static_search_span_expectation_v1,
    plan_and_compile_linux_aarch64_exact_search_v1, plan_and_compile_macos_aarch64_exact_search_v1,
    publish_linux_search_span_final_image_glue_v1, publish_search_span_final_image_glue_v1,
};

/// Failure while materializing one inert per-source tag40 object pair.
#[derive(Debug)]
#[non_exhaustive]
pub enum SearchV27ProductionSourceErrorV1 {
    ZeroSelector,
    /// The decoded, compiler-sealed live literal is outside the production
    /// 17..=32-byte envelope. No expectation or glue object was published.
    LiteralWidthOutsideProductionEnvelope {
        bytes: u32,
    },
    MacosManifest(SearchManifestErrorV1),
    MacosCompile(SearchCompileErrorV1),
    MacosExpectation(StaticSearchSpanExpectationBuildErrorV1),
    MacosGlue(SearchSpanFinalImageGlueErrorV1),
    LinuxManifest(LinuxSearchManifestErrorV1),
    LinuxCompile(LinuxSearchCompileErrorV1),
    LinuxExpectation(LinuxStaticSearchSpanExpectationBuildErrorV1),
    LinuxGlue(LinuxSearchSpanFinalImageGlueErrorV1),
}

impl fmt::Display for SearchV27ProductionSourceErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FRE tag40 per-source production scaffold failed: {self:?}"
        )
    }
}

impl std::error::Error for SearchV27ProductionSourceErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ZeroSelector | Self::LiteralWidthOutsideProductionEnvelope { .. } => None,
            Self::MacosManifest(error) => Some(error),
            Self::MacosCompile(error) => Some(error),
            Self::MacosExpectation(error) => Some(error),
            Self::MacosGlue(error) => Some(error),
            Self::LinuxManifest(error) => Some(error),
            Self::LinuxCompile(error) => Some(error),
            Self::LinuxExpectation(error) => Some(error),
            Self::LinuxGlue(error) => Some(error),
        }
    }
}

/// Inert deterministic Mach-O implementation/production-glue pair for one
/// exact source in the V27 production width envelope.
#[derive(Debug)]
pub struct MacosAarch64SearchV27ProductionSourceV1 {
    implementation: SearchCompiledObjectV1<Span>,
    expectation: StaticSearchSpanExpectationV1,
    glue: PublishedSearchSpanFinalImageGlueV1,
}

impl MacosAarch64SearchV27ProductionSourceV1 {
    #[must_use]
    pub const fn implementation(&self) -> &SearchCompiledObjectV1<Span> {
        &self.implementation
    }

    #[must_use]
    pub const fn expectation(&self) -> &StaticSearchSpanExpectationV1 {
        &self.expectation
    }

    #[must_use]
    pub const fn glue(&self) -> &PublishedSearchSpanFinalImageGlueV1 {
        &self.glue
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> SearchAotRuntimeAuthorityV1 {
        SearchAotRuntimeAuthorityV1::Absent
    }
}

/// Inert deterministic ELF implementation/production-glue pair for one exact
/// source in the V27 production width envelope.
#[derive(Debug)]
pub struct LinuxAarch64SearchV27ProductionSourceV1 {
    implementation: LinuxSearchCompiledObjectV1<Span>,
    expectation: LinuxStaticSearchSpanExpectationV1,
    glue: PublishedLinuxSearchSpanFinalImageGlueV1,
}

impl LinuxAarch64SearchV27ProductionSourceV1 {
    #[must_use]
    pub const fn implementation(&self) -> &LinuxSearchCompiledObjectV1<Span> {
        &self.implementation
    }

    #[must_use]
    pub const fn expectation(&self) -> &LinuxStaticSearchSpanExpectationV1 {
        &self.expectation
    }

    #[must_use]
    pub const fn glue(&self) -> &PublishedLinuxSearchSpanFinalImageGlueV1 {
        &self.glue
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> SearchAotRuntimeAuthorityV1 {
        SearchAotRuntimeAuthorityV1::Absent
    }
}

/// Materialize one deterministic Mach-O tag40 implementation and production
/// glue object from exact regex source bytes.
///
/// Compilation precedes the production-width decision so escaped source
/// spelling cannot substitute for decoded literal width. Widths outside
/// 17..=32 return an error before expectation or glue publication. A
/// successful return remains inert until a separately reviewed source family
/// grants runtime authority.
pub fn build_macos_aarch64_search_v27_production_source_v1(
    source: Vec<u8>,
    profile: RustProfile,
    selector: u16,
    compile_policy: SearchCompilePolicyV1,
    glue_limits: SearchSpanFinalImageGlueLimitsV1,
) -> Result<MacosAarch64SearchV27ProductionSourceV1, SearchV27ProductionSourceErrorV1> {
    if selector == 0 {
        return Err(SearchV27ProductionSourceErrorV1::ZeroSelector);
    }
    let manifest = MacosAarch64ExactSearchManifestV1::<Span>::v27_candidate(compile_policy)
        .map_err(SearchV27ProductionSourceErrorV1::MacosManifest)?;
    let implementation = plan_and_compile_macos_aarch64_exact_search_v1(manifest, source, profile)
        .map_err(SearchV27ProductionSourceErrorV1::MacosCompile)?;
    let live_literal_bytes = implementation.receipt().literal_bytes();
    if !search_v27_production_literal_width_is_valid_v1(live_literal_bytes) {
        return Err(
            SearchV27ProductionSourceErrorV1::LiteralWidthOutsideProductionEnvelope {
                bytes: live_literal_bytes,
            },
        );
    }
    let expectation = build_static_search_span_expectation_v1(&implementation)
        .map_err(SearchV27ProductionSourceErrorV1::MacosExpectation)?;
    let glue = publish_search_span_final_image_glue_v1(
        &implementation,
        &expectation,
        selector,
        glue_limits,
    )
    .map_err(SearchV27ProductionSourceErrorV1::MacosGlue)?;
    Ok(MacosAarch64SearchV27ProductionSourceV1 {
        implementation,
        expectation,
        glue,
    })
}

/// Materialize one deterministic ELF tag40 implementation and production glue
/// object from exact regex source bytes.
///
/// As on macOS, the production-width check uses the decoded live literal
/// sealed in the compiler receipt and occurs before expectation or glue
/// publication. This performs no link, final-image inspection, family
/// promotion, or runtime publication.
pub fn build_linux_aarch64_search_v27_production_source_v1(
    source: Vec<u8>,
    profile: RustProfile,
    selector: u16,
    compile_policy: LinuxAarch64SearchCompilePolicyV1,
    glue_limits: LinuxSearchSpanFinalImageGlueLimitsV1,
) -> Result<LinuxAarch64SearchV27ProductionSourceV1, SearchV27ProductionSourceErrorV1> {
    if selector == 0 {
        return Err(SearchV27ProductionSourceErrorV1::ZeroSelector);
    }
    let manifest = LinuxAarch64ExactSearchManifestV1::<Span>::v27_candidate(compile_policy)
        .map_err(SearchV27ProductionSourceErrorV1::LinuxManifest)?;
    let implementation = plan_and_compile_linux_aarch64_exact_search_v1(manifest, source, profile)
        .map_err(SearchV27ProductionSourceErrorV1::LinuxCompile)?;
    let live_literal_bytes = implementation.receipt().literal_bytes();
    if !search_v27_production_literal_width_is_valid_v1(live_literal_bytes) {
        return Err(
            SearchV27ProductionSourceErrorV1::LiteralWidthOutsideProductionEnvelope {
                bytes: live_literal_bytes,
            },
        );
    }
    let expectation = build_linux_static_search_span_expectation_v1(&implementation)
        .map_err(SearchV27ProductionSourceErrorV1::LinuxExpectation)?;
    let glue = publish_linux_search_span_final_image_glue_v1(
        &implementation,
        &expectation,
        selector,
        glue_limits,
    )
    .map_err(SearchV27ProductionSourceErrorV1::LinuxGlue)?;
    Ok(LinuxAarch64SearchV27ProductionSourceV1 {
        implementation,
        expectation,
        glue,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LinuxAarch64SearchBackendV1, MacosAarch64SearchBackendV1};
    use fre_aot_search_contract::SEARCH_BACKEND_ASIMD_TAG40_V1;
    use fre_jit_aarch64::{BackendVersion, SearchBackendPolicy};

    const SELECTOR: u16 = 41;
    const ESCAPED_WIDTH_16: &[u8] =
        br"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70";
    const ESCAPED_WIDTH_17: &[u8] =
        br"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71";
    const PERIODIC_WIDTH_18: &[u8] = b"abcabcabcabcabcabc";
    const UNIFORM_WIDTH_17: &[u8] = b"aaaaaaaaaaaaaaaaa";
    const WIDTH_32: &[u8] = b"abcdefghijklmnopqrstuvwxyz012345";

    #[test]
    fn decoded_width_sixteen_is_refused_before_glue_publication_on_both_targets() {
        let macos = build_macos_aarch64_search_v27_production_source_v1(
            ESCAPED_WIDTH_16.to_vec(),
            RustProfile::default(),
            SELECTOR,
            SearchCompilePolicyV1::default(),
            SearchSpanFinalImageGlueLimitsV1::default(),
        )
        .unwrap_err();
        assert!(matches!(
            macos,
            SearchV27ProductionSourceErrorV1::LiteralWidthOutsideProductionEnvelope { bytes: 16 }
        ));

        let linux = build_linux_aarch64_search_v27_production_source_v1(
            ESCAPED_WIDTH_16.to_vec(),
            RustProfile::default(),
            SELECTOR,
            LinuxAarch64SearchCompilePolicyV1::default(),
            LinuxSearchSpanFinalImageGlueLimitsV1::default(),
        )
        .unwrap_err();
        assert!(matches!(
            linux,
            SearchV27ProductionSourceErrorV1::LiteralWidthOutsideProductionEnvelope { bytes: 16 }
        ));
    }

    #[test]
    fn inclusive_widths_and_non_unique_topologies_build_inert_tag40_pairs() {
        for (source, expected_width) in [
            (ESCAPED_WIDTH_17, 17),
            (UNIFORM_WIDTH_17, 17),
            (PERIODIC_WIDTH_18, 18),
            (WIDTH_32, 32),
        ] {
            let macos = build_macos_aarch64_search_v27_production_source_v1(
                source.to_vec(),
                RustProfile::default(),
                SELECTOR,
                SearchCompilePolicyV1::default(),
                SearchSpanFinalImageGlueLimitsV1::default(),
            )
            .unwrap();
            assert_eq!(
                macos.implementation().receipt().literal_bytes(),
                expected_width
            );
            assert_eq!(
                macos
                    .implementation()
                    .receipt()
                    .metadata()
                    .backend_version(),
                SEARCH_BACKEND_ASIMD_TAG40_V1
            );
            assert_eq!(
                macos.runtime_authority(),
                SearchAotRuntimeAuthorityV1::Absent
            );

            let linux = build_linux_aarch64_search_v27_production_source_v1(
                source.to_vec(),
                RustProfile::default(),
                SELECTOR,
                LinuxAarch64SearchCompilePolicyV1::default(),
                LinuxSearchSpanFinalImageGlueLimitsV1::default(),
            )
            .unwrap();
            assert_eq!(
                linux.implementation().receipt().literal_bytes(),
                expected_width
            );
            assert_eq!(
                linux
                    .implementation()
                    .receipt()
                    .metadata()
                    .backend_version(),
                SEARCH_BACKEND_ASIMD_TAG40_V1
            );
            assert_eq!(
                linux.runtime_authority(),
                SearchAotRuntimeAuthorityV1::Absent
            );
        }
    }

    #[test]
    fn production_builder_does_not_change_existing_backend_defaults() {
        assert_eq!(SearchBackendPolicy::CURRENT, SearchBackendPolicy::AsimdV8);
        assert_eq!(BackendVersion::CURRENT, BackendVersion::SEARCH_V8);
        assert_eq!(
            MacosAarch64ExactSearchManifestV1::<Span>::default().backend(),
            MacosAarch64SearchBackendV1::AsimdV8
        );
        assert_eq!(
            LinuxAarch64ExactSearchManifestV1::<Span>::default().backend(),
            LinuxAarch64SearchBackendV1::AsimdV8
        );
    }
}
