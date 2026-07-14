//! Stable, engine-neutral differential result records.

/// One half-open byte span in the original haystack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalSpan {
    /// Inclusive start offset.
    pub start: usize,
    /// Exclusive end offset.
    pub end: usize,
}

impl CanonicalSpan {
    /// Construct a span without silently normalizing invalid offsets.
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    /// Whether this match consumed no input.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }
}

/// Why an adapter cannot represent a requested semantic feature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum UnsupportedFeature {
    /// The capture-free K0 path cannot return capture histories.
    Captures,
    /// The direct automata adapter was given a node outside its declared AST.
    PatternNode,
    /// A bounded end before the original haystack end is not available in the
    /// independent oracle API.
    TruncatedReferenceWindow,
    /// Nullable unbounded repetition whose loop priority is not faithfully
    /// representable by simple Thompson epsilon-cycle deduplication.
    NullableUnboundedRepeat,
}

/// Which hard cap refused a comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RefusalKind {
    AstNodes,
    AstDepth,
    PlanStates,
    PlanEdges,
    HaystackBytes,
    SearchWork,
    ScratchBytes,
    Results,
    Cases,
    Arithmetic,
    Allocation,
}

/// A canonical adapter result. Unsupported and refused cases are not passes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Outcome<T> {
    /// A complete result.
    Value(T),
    /// Semantics unavailable on this adapter.
    Unsupported(UnsupportedFeature),
    /// A declared resource cap rejected the operation.
    Refused(RefusalKind),
    /// A structural or execution failure, kept distinct from no-match.
    Fault(String),
}

/// Exact search outputs for all capture-free operation contracts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchRecord {
    pub exists: Outcome<bool>,
    pub selected_end: Outcome<Option<usize>>,
    pub span: Outcome<Option<CanonicalSpan>>,
    pub global: Outcome<Vec<CanonicalSpan>>,
}

/// How the global sequence was obtained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GlobalMode {
    /// The intentionally quadratic direct-AST reference iterator.
    ReferenceRepeatedSearch,
    /// A compatibility adapter around repeated production single searches;
    /// this is not evidence for an aggregate linear-time implementation.
    ProductionRepeatedSearchAdapter,
}

/// Comparison verdict; only `Equal` counts as a conformance pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Agreement {
    Equal,
    Mismatch,
    NotComparable,
}

/// All engine-neutral evidence for one differential case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineRecord {
    pub case_id: String,
    pub seed: u64,
    pub ordinal: u64,
    pub haystack: Vec<u8>,
    pub window_start: usize,
    pub window_end: usize,
    pub oracle: SearchRecord,
    pub production: SearchRecord,
    pub agreement: Agreement,
}

/// Auditable identity and role of one comparator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComparatorIdentity {
    pub name: &'static str,
    pub version: &'static str,
    pub role: &'static str,
}
