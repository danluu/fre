//! Deterministic per-source tag38 implementation/production-glue bundles.
//!
//! These helpers close only the build-time object pair for one exact source:
//! an implementation object, neutral expectation, and identity-suffixed
//! production-adopter glue object. They do not link either object, populate a
//! runtime family table, inspect a final image, or grant runtime authority.
//! The static runtime still refuses tag38 unless the separate V25
//! authorization atom and target family row are source-promoted.
//!
//! Tag38 accepts only exact byte literals of width 6..=32 whose authenticated
//! five-column selector is cyclic-phase unique. That shape check remains in
//! the shared V25 emitter: these helpers return a compile error and emit no
//! glue when it refuses the source. Production adoption independently
//! regenerates the same V25 payload from mapped literal bytes before a
//! callable can exist.

use core::fmt;

use fre::RustProfile;
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

/// Failure while materializing one inert per-source tag38 object pair.
#[derive(Debug)]
#[non_exhaustive]
pub enum SearchV25ProductionSourceErrorV1 {
    ZeroSelector,
    MacosManifest(SearchManifestErrorV1),
    MacosCompile(SearchCompileErrorV1),
    MacosExpectation(StaticSearchSpanExpectationBuildErrorV1),
    MacosGlue(SearchSpanFinalImageGlueErrorV1),
    LinuxManifest(LinuxSearchManifestErrorV1),
    LinuxCompile(LinuxSearchCompileErrorV1),
    LinuxExpectation(LinuxStaticSearchSpanExpectationBuildErrorV1),
    LinuxGlue(LinuxSearchSpanFinalImageGlueErrorV1),
}

impl fmt::Display for SearchV25ProductionSourceErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FRE tag38 per-source production scaffold failed: {self:?}"
        )
    }
}

impl std::error::Error for SearchV25ProductionSourceErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ZeroSelector => None,
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
/// exact source.
#[derive(Debug)]
pub struct MacosAarch64SearchV25ProductionSourceV1 {
    implementation: SearchCompiledObjectV1<Span>,
    expectation: StaticSearchSpanExpectationV1,
    glue: PublishedSearchSpanFinalImageGlueV1,
}

impl MacosAarch64SearchV25ProductionSourceV1 {
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
/// source.
#[derive(Debug)]
pub struct LinuxAarch64SearchV25ProductionSourceV1 {
    implementation: LinuxSearchCompiledObjectV1<Span>,
    expectation: LinuxStaticSearchSpanExpectationV1,
    glue: PublishedLinuxSearchSpanFinalImageGlueV1,
}

impl LinuxAarch64SearchV25ProductionSourceV1 {
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

/// Materialize one deterministic Mach-O tag38 implementation and production
/// glue object from the exact source bytes.
///
/// The returned object pair remains inert even when linked. Its glue selector
/// is looked up only in the separate production authority table, which this
/// function cannot modify. Sources outside tag38's width or cyclic-phase
/// envelope fail during compilation before glue publication.
pub fn build_macos_aarch64_search_v25_production_source_v1(
    source: Vec<u8>,
    profile: RustProfile,
    selector: u16,
    compile_policy: SearchCompilePolicyV1,
    glue_limits: SearchSpanFinalImageGlueLimitsV1,
) -> Result<MacosAarch64SearchV25ProductionSourceV1, SearchV25ProductionSourceErrorV1> {
    if selector == 0 {
        return Err(SearchV25ProductionSourceErrorV1::ZeroSelector);
    }
    let manifest = MacosAarch64ExactSearchManifestV1::<Span>::v25_candidate(compile_policy)
        .map_err(SearchV25ProductionSourceErrorV1::MacosManifest)?;
    let implementation = plan_and_compile_macos_aarch64_exact_search_v1(manifest, source, profile)
        .map_err(SearchV25ProductionSourceErrorV1::MacosCompile)?;
    let expectation = build_static_search_span_expectation_v1(&implementation)
        .map_err(SearchV25ProductionSourceErrorV1::MacosExpectation)?;
    let glue = publish_search_span_final_image_glue_v1(
        &implementation,
        &expectation,
        selector,
        glue_limits,
    )
    .map_err(SearchV25ProductionSourceErrorV1::MacosGlue)?;
    Ok(MacosAarch64SearchV25ProductionSourceV1 {
        implementation,
        expectation,
        glue,
    })
}

/// Materialize one deterministic ELF tag38 implementation and production
/// glue object from the exact source bytes.
///
/// As on macOS, this performs no link, final-image inspection, family
/// promotion, or runtime publication. Sources outside tag38's width or
/// cyclic-phase envelope fail during compilation before glue publication.
pub fn build_linux_aarch64_search_v25_production_source_v1(
    source: Vec<u8>,
    profile: RustProfile,
    selector: u16,
    compile_policy: LinuxAarch64SearchCompilePolicyV1,
    glue_limits: LinuxSearchSpanFinalImageGlueLimitsV1,
) -> Result<LinuxAarch64SearchV25ProductionSourceV1, SearchV25ProductionSourceErrorV1> {
    if selector == 0 {
        return Err(SearchV25ProductionSourceErrorV1::ZeroSelector);
    }
    let manifest = LinuxAarch64ExactSearchManifestV1::<Span>::v25_candidate(compile_policy)
        .map_err(SearchV25ProductionSourceErrorV1::LinuxManifest)?;
    let implementation = plan_and_compile_linux_aarch64_exact_search_v1(manifest, source, profile)
        .map_err(SearchV25ProductionSourceErrorV1::LinuxCompile)?;
    let expectation = build_linux_static_search_span_expectation_v1(&implementation)
        .map_err(SearchV25ProductionSourceErrorV1::LinuxExpectation)?;
    let glue = publish_linux_search_span_final_image_glue_v1(
        &implementation,
        &expectation,
        selector,
        glue_limits,
    )
    .map_err(SearchV25ProductionSourceErrorV1::LinuxGlue)?;
    Ok(LinuxAarch64SearchV25ProductionSourceV1 {
        implementation,
        expectation,
        glue,
    })
}
