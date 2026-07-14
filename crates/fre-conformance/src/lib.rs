//! Bounded differential conformance infrastructure for FRE.
//!
//! The implementation is being built incrementally; unsupported comparisons
//! must remain explicit outcomes rather than being counted as passes.

#![forbid(unsafe_code)]

mod canonical;
mod case;
mod engine;
mod generate;

pub use canonical::{
    Agreement, CanonicalSpan, ComparatorIdentity, EngineRecord, GlobalMode, Outcome, RefusalKind,
    SearchRecord, UnsupportedFeature,
};
pub use case::{ByteRange, CaseAst, CaseLimits, Greed};
pub use engine::{ConformanceCase, Harness, HarnessLimits};
pub use generate::{GeneratedCorpus, GeneratorLimits, generate_small_exhaustive};

/// Identity of the independent, direct-AST semantic oracle.
pub const SEMANTIC_ORACLE: ComparatorIdentity = ComparatorIdentity {
    name: "fre-reference",
    version: env!("CARGO_PKG_VERSION"),
    role: "semantic oracle",
};

/// The separately pinned secondary comparator used only in tests.
///
/// Agreement with this implementation is useful compatibility evidence, but
/// is never used to override the direct semantic oracle.
pub const UPSTREAM_RUST_REGEX_BASELINE: ComparatorIdentity = ComparatorIdentity {
    name: "regex",
    version: "1.12.4",
    role: "secondary upstream comparator",
};
