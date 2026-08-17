//! Planner-disabled qualification manifest for staged forced compilers.
//!
//! This registry describes explicit compiler contracts only. It has no
//! executable callbacks, accepts no pattern or haystack, and is not visible
//! to the default Rebar adapter. A completed leaf may be wired here only after
//! its exact source identity and operation surface are authenticated.

use crate::CompareError;

/// Schema for the staged compiler-contract manifest.
pub const P128_FORCED_COMPILER_MANIFEST_SCHEMA: &str = "fre.rebar.p128-forced-compiler-manifest.v1";

/// The only public exposure admitted before forced qualification completes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum P128ForcedExposure {
    /// Explicit qualification callers may request a compiler by exact ID.
    QualificationOnly,
}

/// Structural compiler families in the planner-disabled composition.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum P128ForcedCompiler {
    /// Finite literal candidates with bounded start and endpoint recovery.
    LiteralAnchor,
    /// Priority-preserving whole-operation automata.
    WholeAutomata,
    /// One shared priority automaton for an ordered pattern collection.
    BuildMany,
    /// Tagged capture participation, history, and line execution.
    CaptureStream,
    /// Fixed-width byte programs with retained ASCII-class SIMD classifiers.
    HotBytePrograms,
}

impl P128ForcedCompiler {
    /// Stable explicit compiler identifier used only by qualification callers.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::LiteralAnchor => "fre.forced.literal-anchor.v1",
            Self::WholeAutomata => "fre.forced.whole-automata.v1",
            Self::BuildMany => "fre.forced.build-many.v1",
            Self::CaptureStream => "fre.forced.capture-stream.v1",
            Self::HotBytePrograms => "fre.forced.hot-byte-programs.v1",
        }
    }
}

/// Rebar operation models admitted by the forced-only composition.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum P128ForcedModel {
    /// Count complete non-overlapping matches.
    Count,
    /// Sum complete non-overlapping match lengths.
    SpanSum,
    /// Count capture participation over selected matches.
    CountCaptures,
    /// Emit the selected capture projection.
    GrepCaptures,
}

impl P128ForcedModel {
    /// Parse one exact Rebar operation model.
    ///
    /// # Errors
    ///
    /// Returns an error for compile timing and every model outside the
    /// planner-disabled forced-operation scope.
    pub fn parse(model: &str) -> Result<Self, CompareError> {
        match model {
            "count" => Ok(Self::Count),
            "count-spans" => Ok(Self::SpanSum),
            "count-captures" => Ok(Self::CountCaptures),
            "grep-captures" => Ok(Self::GrepCaptures),
            "compile" => Err(CompareError::new(
                "forced compiler registry has no compile-timing lifecycle",
            )),
            _ => Err(CompareError::new(
                "forced compiler registry received an unsupported operation model",
            )),
        }
    }

    /// Exact Rebar model spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Count => "count",
            Self::SpanSum => "count-spans",
            Self::CountCaptures => "count-captures",
            Self::GrepCaptures => "grep-captures",
        }
    }
}

/// One immutable compiler/model contract in the staged manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P128ForcedCompilerContract {
    compiler: P128ForcedCompiler,
    model: P128ForcedModel,
    exposure: P128ForcedExposure,
}

impl P128ForcedCompilerContract {
    const fn new(compiler: P128ForcedCompiler, model: P128ForcedModel) -> Self {
        Self {
            compiler,
            model,
            exposure: P128ForcedExposure::QualificationOnly,
        }
    }

    /// Explicit compiler family.
    #[must_use]
    pub const fn compiler(self) -> P128ForcedCompiler {
        self.compiler
    }

    /// Stable compiler identifier.
    #[must_use]
    pub const fn compiler_id(self) -> &'static str {
        self.compiler.id()
    }

    /// Supported operation model.
    #[must_use]
    pub const fn model(self) -> P128ForcedModel {
        self.model
    }

    /// Qualification-only exposure.
    #[must_use]
    pub const fn exposure(self) -> P128ForcedExposure {
        self.exposure
    }
}

const CONTRACTS: [P128ForcedCompilerContract; 8] = [
    P128ForcedCompilerContract::new(P128ForcedCompiler::LiteralAnchor, P128ForcedModel::Count),
    P128ForcedCompilerContract::new(P128ForcedCompiler::LiteralAnchor, P128ForcedModel::SpanSum),
    P128ForcedCompilerContract::new(P128ForcedCompiler::WholeAutomata, P128ForcedModel::Count),
    P128ForcedCompilerContract::new(P128ForcedCompiler::WholeAutomata, P128ForcedModel::SpanSum),
    P128ForcedCompilerContract::new(P128ForcedCompiler::BuildMany, P128ForcedModel::SpanSum),
    P128ForcedCompilerContract::new(
        P128ForcedCompiler::CaptureStream,
        P128ForcedModel::CountCaptures,
    ),
    P128ForcedCompilerContract::new(
        P128ForcedCompiler::CaptureStream,
        P128ForcedModel::GrepCaptures,
    ),
    P128ForcedCompilerContract::new(P128ForcedCompiler::HotBytePrograms, P128ForcedModel::Count),
];

/// Static planner-disabled compiler-contract manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P128ForcedCompilerManifest {
    schema: &'static str,
    contracts: &'static [P128ForcedCompilerContract],
}

impl P128ForcedCompilerManifest {
    /// Load the staged qualification manifest.
    #[must_use]
    pub const fn load() -> Self {
        Self {
            schema: P128_FORCED_COMPILER_MANIFEST_SCHEMA,
            contracts: &CONTRACTS,
        }
    }

    /// Versioned manifest schema.
    #[must_use]
    pub const fn schema(self) -> &'static str {
        self.schema
    }

    /// Complete ordered compiler/model contract list.
    #[must_use]
    pub const fn contracts(self) -> &'static [P128ForcedCompilerContract] {
        self.contracts
    }

    /// Resolve an explicitly requested compiler and operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the stable compiler ID is unknown or if that
    /// compiler does not support the requested operation.
    pub fn resolve(
        self,
        compiler_id: &str,
        model: P128ForcedModel,
    ) -> Result<P128ForcedCompilerContract, CompareError> {
        let mut saw_compiler = false;
        for contract in self.contracts {
            if contract.compiler_id() == compiler_id {
                saw_compiler = true;
                if contract.model == model {
                    return Ok(*contract);
                }
            }
        }
        if saw_compiler {
            Err(CompareError::new(
                "forced compiler does not support the requested operation",
            ))
        } else {
            Err(CompareError::new(
                "forced compiler registry received an unknown compiler ID",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn manifest_is_unique_explicit_and_qualification_only() {
        let manifest = P128ForcedCompilerManifest::load();
        assert_eq!(manifest.schema(), P128_FORCED_COMPILER_MANIFEST_SCHEMA);
        let mut keys = BTreeSet::new();
        for contract in manifest.contracts() {
            assert_eq!(contract.exposure(), P128ForcedExposure::QualificationOnly);
            assert!(keys.insert((contract.compiler_id(), contract.model())));
            assert_eq!(
                manifest
                    .resolve(contract.compiler_id(), contract.model())
                    .unwrap(),
                *contract
            );
        }
        assert_eq!(keys.len(), manifest.contracts().len());
    }

    #[test]
    fn operation_matrix_is_exact_and_has_no_automatic_entry() {
        let manifest = P128ForcedCompilerManifest::load();
        let expected = [
            (
                P128ForcedCompiler::LiteralAnchor,
                [Some(P128ForcedModel::Count), Some(P128ForcedModel::SpanSum)],
            ),
            (
                P128ForcedCompiler::WholeAutomata,
                [Some(P128ForcedModel::Count), Some(P128ForcedModel::SpanSum)],
            ),
            (
                P128ForcedCompiler::BuildMany,
                [Some(P128ForcedModel::SpanSum), None],
            ),
            (
                P128ForcedCompiler::CaptureStream,
                [
                    Some(P128ForcedModel::CountCaptures),
                    Some(P128ForcedModel::GrepCaptures),
                ],
            ),
            (
                P128ForcedCompiler::HotBytePrograms,
                [Some(P128ForcedModel::Count), None],
            ),
        ];
        for (compiler, models) in expected {
            for model in models.into_iter().flatten() {
                assert!(
                    manifest.resolve(compiler.id(), model).is_ok(),
                    "{} / {}",
                    compiler.id(),
                    model.as_str()
                );
            }
        }
        assert_eq!(manifest.contracts().len(), 8);
        assert!(
            manifest
                .resolve(
                    P128ForcedCompiler::HotBytePrograms.id(),
                    P128ForcedModel::SpanSum,
                )
                .is_err(),
            "the hot-byte value reducer cannot materialize Rebar match bounds"
        );
    }

    #[test]
    fn unknown_compiler_unsupported_operation_and_compile_fail_closed() {
        let manifest = P128ForcedCompilerManifest::load();
        assert!(
            manifest
                .resolve("fre.forced.unknown.v1", P128ForcedModel::Count)
                .unwrap_err()
                .to_string()
                .contains("unknown compiler ID")
        );
        assert!(
            manifest
                .resolve(P128ForcedCompiler::BuildMany.id(), P128ForcedModel::Count)
                .unwrap_err()
                .to_string()
                .contains("does not support")
        );
        assert!(P128ForcedModel::parse("compile").is_err());
        assert!(P128ForcedModel::parse("search").is_err());
    }

    #[test]
    fn every_admitted_model_round_trips_exact_rebar_spelling() {
        for model in [
            P128ForcedModel::Count,
            P128ForcedModel::SpanSum,
            P128ForcedModel::CountCaptures,
            P128ForcedModel::GrepCaptures,
        ] {
            assert_eq!(P128ForcedModel::parse(model.as_str()).unwrap(), model);
        }
    }
}
