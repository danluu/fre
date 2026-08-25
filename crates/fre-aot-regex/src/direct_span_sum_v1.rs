//! Direct exact-singleton `SpanSum` receipt.
//!
//! The selected implementation keeps the public `SpanSum` entry and its
//! artifact-authentication prefix. Its private leaf calls one independently
//! audited Count-v3 core, checks `count * literal_width` (with multiplication
//! by one discharged arithmetically), and publishes the completed byte sum
//! transactionally. No source bytes are retained here.

use crate::PreparedAggregateStrategy;
use fre_aot_optimizer::CountV3Strategy;

/// Receipt schema for the direct exact-singleton `SpanSum` composition.
pub const DIRECT_EXACT_SINGLETON_SPAN_SUM_AOT_SCHEMA_VERSION: u16 = 3;

/// Required section-relative alignment of the embedded Count-v3 core.
///
/// This aliases the producer contract so the wrapper and the independently
/// audited Count image cannot drift to different alignment requirements.
pub const DIRECT_EXACT_SINGLETON_SPAN_SUM_COUNT_CORE_ALIGNMENT_BYTES: usize =
    fre_aot_aarch64::AOT_COUNT_CODE_ALIGNMENT_V3;

/// Successor rule shared by the exact Count core and `SpanSum` operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectExactSingletonSpanSumSuccessorMode {
    /// A successful literal consumes its complete, non-empty width.
    NonOverlapping,
}

/// Source-independent reason the composition beats the materialized iterator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectExactSingletonSpanSumSelectionBasis {
    /// One exhaustive Count scan replaces one ordinary search call and one
    /// internal span publication for each accepted match.
    ExactWidthCountComposition,
    /// The direct arm has the same structural dominance, while a source-only
    /// cold-long gate leaves the incumbent short path in place.
    ExactWidthCountCompositionWithShortIncumbent,
}

/// Comparable whole-operation shape. Smaller is better in each runtime field;
/// code bytes break an otherwise exact tie only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectExactSingletonSpanSumCostShape {
    pub scan_passes: u8,
    /// The first native scan entry needed even when no match is present.
    pub native_scan_entries_per_operation: u8,
    /// Continuation search calls after accepted matches.
    pub native_calls_per_match: u8,
    pub internal_span_publications_per_match: u8,
    pub unresolved_runtime_helpers: u8,
    /// Operation code only; the ordinary entry shared by both choices is
    /// excluded.
    pub code_bytes: u32,
}

impl DirectExactSingletonSpanSumCostShape {
    pub(crate) const fn runtime_components(self) -> [u8; 5] {
        [
            self.unresolved_runtime_helpers,
            self.scan_passes,
            self.native_scan_entries_per_operation,
            self.native_calls_per_match,
            self.internal_span_publications_per_match,
        ]
    }
}

/// Authenticated receipt for the selected `SpanSum` wrapper/Count-core
/// transaction. No literal bytes are retained or exposed here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectExactSingletonSpanSumAotReport {
    pub schema_version: u16,
    pub literal_bytes: u8,
    pub successor_mode: DirectExactSingletonSpanSumSuccessorMode,
    pub selection_basis: DirectExactSingletonSpanSumSelectionBasis,
    /// Independently authenticated Count-v3 recipe family.
    pub count_recipe_strategy: CountV3Strategy,
    pub incumbent_strategy: PreparedAggregateStrategy,
    pub incumbent_cost: DirectExactSingletonSpanSumCostShape,
    /// Cost of the selected direct arm. When `short_fallback_max_bytes` is
    /// present, shorter sources use the exact incumbent arm instead.
    pub selected_cost: DirectExactSingletonSpanSumCostShape,
    /// First instruction after the unchanged public validation and artifact
    /// authentication prefix.
    pub authenticated_wrapper_body_offset: usize,
    /// Inclusive source-length ceiling for the incumbent arm. `None` means
    /// the checked composition owns every authenticated source length.
    pub short_fallback_max_bytes: Option<u32>,
    /// Appended cold path that rechecks invalid-length precedence, validates
    /// the result pointer, reauthenticates the handle, and enters the checked
    /// composition. Both fields are absent for an ungated direct selection.
    pub cold_long_offset: Option<usize>,
    pub cold_long_bytes: Option<usize>,
    /// Compiler-generated checked Count-to-SpanSum composition leaf.
    pub wrapper_offset: usize,
    pub wrapper_bytes: usize,
    pub wrapper_sha256: [u8; 32],
    /// Exact AArch64 NOP padding between the checked wrapper and Count-v3 core.
    pub wrapper_to_core_padding_bytes: usize,
    /// Independently compiled and audited Count-v3 core.
    pub core_offset: usize,
    /// Declared text-section alignment used to realize the section-relative
    /// Count-v3 core alignment in the final object.
    pub text_section_alignment_bytes: usize,
    pub core_alignment_bytes: usize,
    pub core_bytes: usize,
    pub core_sha256: [u8; 32],
    pub compile_identity: [u8; 32],
    pub object_identity: [u8; 32],
    pub recipe_identity: [u8; 32],
    /// Identity of the selected merged wrapper/core transaction.
    pub module_identity: [u8; 32],
}
