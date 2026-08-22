//! Bounded, output-aware facts derived from canonical Rust-regex HIR.
//!
//! This module deliberately analyzes the HIR that `fre-syntax` already
//! canonicalized. It does not infer which parser flag produced a Unicode
//! class, and it never treats an unavailable proof as a positive fact.
//! Positive certificates are conservative and carry the output contract under
//! which they may be consumed.

use core::{fmt, mem::size_of};

use regex_syntax::{
    hir::{Class, Hir, HirKind, Look},
    utf8::Utf8Sequences,
};

use fre_syntax::RustParsed;

/// Semantic algorithm identity for canonical-HIR fact analysis.
///
/// Version 9 combines output-aware capture erasure, the conservative
/// reverse-suffix certificate used for capture-observing operations, and
/// explicitly requested route-proof envelopes including the isolated finite-
/// language surface.
pub const HIR_FACT_ALGORITHM_VERSION: u32 = 9;

/// Exact construction-accounting identity for canonical-HIR fact analysis.
///
/// Version 9 accounts for erased capture traversal, the reverse-suffix
/// internal-pivot guard, and explicitly requested route-proof envelopes under
/// one authenticated construction envelope, including isolated finite-
/// language construction.
pub const HIR_FACT_ACCOUNTING_VERSION: u32 = 9;

/// Stable semantic and exact-accounting identity carried by every report.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FactIdentity {
    algorithm_version: u32,
    accounting_version: u32,
}

impl FactIdentity {
    /// Current identity for reports constructed by this crate.
    #[must_use]
    pub const fn current() -> Self {
        Self {
            algorithm_version: HIR_FACT_ALGORITHM_VERSION,
            accounting_version: HIR_FACT_ACCOUNTING_VERSION,
        }
    }

    #[must_use]
    pub const fn algorithm_version(self) -> u32 {
        self.algorithm_version
    }

    #[must_use]
    pub const fn accounting_version(self) -> u32 {
        self.accounting_version
    }

    /// Whether this is the exact identity implemented by this build.
    #[must_use]
    pub const fn authenticates_current(self) -> bool {
        self.algorithm_version == HIR_FACT_ALGORITHM_VERSION
            && self.accounting_version == HIR_FACT_ACCOUNTING_VERSION
    }
}

/// Public output semantics for one HIR-fact analysis.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum FactOutput {
    /// Whether any match exists.
    Exists,
    /// Number of non-overlapping matches.
    Count,
    /// Sum of complete-match span lengths.
    SpanSum,
    /// Complete ordered sequence of match spans.
    SpanSequence,
    /// Complete capture participation and capture spans.
    Captures,
}

/// Treatment of capture annotations during operation-aware fact analysis.
///
/// Whole-match value reducers may erase capture annotations before deriving
/// execution facts. Capture-observing operations must retain them.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum FactCaptureSemantics {
    /// Retain and classify every canonical capture annotation.
    Preserve,
    /// Erase capture annotations while retaining their HIR traversal charge.
    EraseForValue,
}

/// Optional positive facts requested by an authenticated analysis consumer.
///
/// Core HIR facts (including width, structural state bounds, and capture
/// erasure) are always derived. These variants control only separately
/// bounded proofs whose construction is not required by every consumer.
/// `Complete` preserves the default [`analyze_facts`] contract.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum FactOptionalProofs {
    /// Retain the complete historical optional-fact surface.
    Complete,
    /// Retain no optional positive facts beyond the core HIR facts.
    CoreOnly,
    /// Retain only the complete finite language and the assertion facts needed
    /// to authenticate that every member is context independent.
    FiniteLanguage,
    /// Retain assertion context and the finite-decision-horizon derivation.
    AssertionContext,
    /// Retain assertion context and an ordered-subset determinism proof.
    AssertionContextAndDeterminism,
}

impl FactOptionalProofs {
    const fn requests_finite_language(self) -> bool {
        matches!(self, Self::Complete | Self::FiniteLanguage)
    }

    const fn requests_required_substrings(self) -> bool {
        matches!(self, Self::Complete)
    }

    const fn requests_assertion_context(self) -> bool {
        matches!(
            self,
            Self::Complete
                | Self::FiniteLanguage
                | Self::AssertionContext
                | Self::AssertionContextAndDeterminism
        )
    }

    const fn requests_determinism(self) -> bool {
        matches!(self, Self::Complete | Self::AssertionContextAndDeterminism)
    }

    const fn requests_reductions(self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// Operation contract under which facts and reductions are certified.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FactOperation {
    output: FactOutput,
    capture_semantics: FactCaptureSemantics,
    optional_proofs: FactOptionalProofs,
}

impl FactOperation {
    #[must_use]
    pub const fn new(output: FactOutput) -> Self {
        Self {
            output,
            capture_semantics: FactCaptureSemantics::Preserve,
            optional_proofs: FactOptionalProofs::Complete,
        }
    }

    /// Construct a whole-match value operation whose canonical capture
    /// annotations are erased before any capture-priority analysis.
    #[must_use]
    pub const fn capture_erased(output: FactOutput) -> Self {
        Self {
            output,
            capture_semantics: FactCaptureSemantics::EraseForValue,
            optional_proofs: FactOptionalProofs::Complete,
        }
    }

    /// Replace the independently bounded optional proof envelope while
    /// retaining this operation's output and capture semantics.
    #[must_use]
    pub const fn with_optional_proofs(mut self, optional_proofs: FactOptionalProofs) -> Self {
        self.optional_proofs = optional_proofs;
        self
    }

    #[must_use]
    pub const fn output(self) -> FactOutput {
        self.output
    }

    #[must_use]
    pub const fn capture_semantics(self) -> FactCaptureSemantics {
        self.capture_semantics
    }

    /// Optional positive facts explicitly requested by this consumer.
    #[must_use]
    pub const fn optional_proofs(self) -> FactOptionalProofs {
        self.optional_proofs
    }

    const fn requests_finite_language(self) -> bool {
        self.optional_proofs.requests_finite_language()
    }

    const fn requests_required_substrings(self) -> bool {
        self.optional_proofs.requests_required_substrings()
    }

    const fn requests_assertion_context(self) -> bool {
        self.optional_proofs.requests_assertion_context()
    }

    const fn requests_determinism(self) -> bool {
        self.optional_proofs.requests_determinism()
    }

    const fn requests_reductions(self) -> bool {
        self.optional_proofs.requests_reductions()
    }

    const fn requests_unicode_scalar_alternatives(self) -> bool {
        matches!(self.optional_proofs, FactOptionalProofs::Complete)
    }

    const fn uses_complete_proof_envelope(self) -> bool {
        matches!(self.optional_proofs, FactOptionalProofs::Complete)
    }

    #[must_use]
    pub const fn erases_captures(self) -> bool {
        matches!(self.capture_semantics, FactCaptureSemantics::EraseForValue)
    }

    #[must_use]
    pub const fn observes_captures(self) -> bool {
        matches!(self.output, FactOutput::Captures)
    }

    #[must_use]
    pub const fn observes_complete_spans(self) -> bool {
        matches!(self.output, FactOutput::SpanSequence | FactOutput::Captures)
    }
}

/// Hard construction limits and independently bounded optional-proof limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FactLimits {
    /// Exact logical analysis work units.
    pub max_work: u64,
    /// Combined explicit task and result-stack items.
    pub max_stack_items: usize,
    /// HIR nodes visited.
    pub max_hir_nodes: usize,
    /// Logical bytes retained by the published facts.
    pub max_retained_bytes: usize,
    /// Peak logical bytes in explicit construction storage.
    pub max_temporary_bytes: usize,
    /// Peak combined retained and temporary logical bytes.
    pub max_peak_bytes: usize,
    /// Fallible allocation requests made by fact construction.
    pub max_allocation_attempts: usize,
    /// Maximum strings in one complete finite-language proof.
    pub max_finite_strings: usize,
    /// Maximum total payload bytes in one finite-language proof.
    pub max_finite_string_bytes: usize,
    /// Maximum independently required substring groups.
    pub max_required_groups: usize,
    /// Maximum alternatives across one required-substring group.
    pub max_required_alternatives: usize,
    /// Maximum payload bytes across one required-substring group.
    pub max_required_bytes: usize,
    /// Maximum positioned assertion facts retained.
    pub max_assertions: usize,
    /// Maximum admitted deterministic subset states.
    pub max_deterministic_states: usize,
}

impl Default for FactLimits {
    fn default() -> Self {
        Self {
            max_work: 8_000_000,
            max_stack_items: 1_000_000,
            max_hir_nodes: 1_000_000,
            max_retained_bytes: 16 * 1024 * 1024,
            max_temporary_bytes: 64 * 1024 * 1024,
            max_peak_bytes: 80 * 1024 * 1024,
            max_allocation_attempts: 8_000_000,
            max_finite_strings: 4_096,
            max_finite_string_bytes: 1 << 20,
            max_required_groups: 64,
            max_required_alternatives: 4_096,
            max_required_bytes: 1 << 20,
            max_assertions: 4_096,
            max_deterministic_states: 1 << 20,
        }
    }
}

/// A separately identified analysis or optional-proof resource.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum FactResource {
    Work,
    StackItems,
    HirNodes,
    RetainedBytes,
    TemporaryBytes,
    PeakBytes,
    AllocationAttempts,
    FiniteStrings,
    FiniteStringBytes,
    RequiredGroups,
    RequiredAlternatives,
    RequiredBytes,
    Assertions,
    DeterministicStates,
}

impl fmt::Display for FactResource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Work => "HIR-fact work",
            Self::StackItems => "HIR-fact explicit stack items",
            Self::HirNodes => "HIR nodes",
            Self::RetainedBytes => "retained HIR-fact bytes",
            Self::TemporaryBytes => "temporary HIR-fact bytes",
            Self::PeakBytes => "peak HIR-fact bytes",
            Self::AllocationAttempts => "HIR-fact allocation attempts",
            Self::FiniteStrings => "finite-language strings",
            Self::FiniteStringBytes => "finite-language bytes",
            Self::RequiredGroups => "required-substring groups",
            Self::RequiredAlternatives => "required-substring alternatives",
            Self::RequiredBytes => "required-substring bytes",
            Self::Assertions => "positioned assertions",
            Self::DeterministicStates => "deterministic states",
        })
    }
}

/// A hard construction failure.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FactError {
    CaptureErasureForCaptureOutput,
    ResourceLimit {
        resource: FactResource,
        needed: u64,
        limit: u64,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    AllocationFailed {
        structure: &'static str,
        additional: usize,
    },
    InternalInvariant {
        detail: &'static str,
    },
}

impl fmt::Display for FactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CaptureErasureForCaptureOutput => {
                f.write_str("capture-erased HIR facts cannot certify a capture-observing output")
            }
            Self::ResourceLimit {
                resource,
                needed,
                limit,
            } => write!(
                f,
                "HIR-fact analysis needs {needed} {resource}, exceeding limit {limit}"
            ),
            Self::ArithmeticOverflow { computation } => {
                write!(f, "arithmetic overflow while computing {computation}")
            }
            Self::AllocationFailed {
                structure,
                additional,
            } => write!(
                f,
                "failed to reserve {additional} additional items for {structure}"
            ),
            Self::InternalInvariant { detail } => {
                write!(f, "HIR-fact invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for FactError {}

/// Exact reason why an optional positive proof was not published.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum FactRefusal {
    /// The authenticated consumer did not request this optional proof.
    NotRequested,
    /// The source language is not finite under the checked width proof.
    InfiniteLanguage,
    /// The canonical HIR does not expose the requested syntax-origin fact.
    OriginUnavailable,
    /// A positive proof exceeded its independent cap.
    Limit {
        resource: FactResource,
        needed: u64,
        limit: u64,
    },
    /// A checked proof dimension cannot be represented.
    ArithmeticOverflow { computation: &'static str },
    /// Capture preservation has not been proved for the proposed reduction.
    CapturesObservable,
    /// Ordered priority or greediness prevents a deterministic certificate.
    OrderedAmbiguity,
    /// Assertions require context not represented by the certificate.
    AssertionContext,
}

/// A proof lattice. Only `Proven` may be consumed positively.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FactProof<T> {
    Proven(T),
    Unknown,
    Refused(FactRefusal),
}

impl<T> FactProof<T> {
    #[must_use]
    pub const fn as_proven(&self) -> Option<&T> {
        match self {
            Self::Proven(value) => Some(value),
            Self::Unknown | Self::Refused(_) => None,
        }
    }

    #[must_use]
    pub const fn refusal(&self) -> Option<FactRefusal> {
        match self {
            Self::Refused(refusal) => Some(*refusal),
            Self::Proven(_) | Self::Unknown => None,
        }
    }
}

/// Exact byte width of a canonical HIR language.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CheckedWidth {
    /// The HIR has no matching string. This is distinct from a nullable
    /// language, which has `minimum == 0`.
    EmptyLanguage,
    /// At least one match exists.
    NonEmpty {
        minimum: usize,
        /// `None` means a checked unbounded maximum.
        maximum: Option<usize>,
    },
}

impl CheckedWidth {
    #[must_use]
    pub const fn minimum(self) -> Option<usize> {
        match self {
            Self::EmptyLanguage => None,
            Self::NonEmpty { minimum, .. } => Some(minimum),
        }
    }

    #[must_use]
    pub const fn maximum(self) -> Option<usize> {
        match self {
            Self::EmptyLanguage => None,
            Self::NonEmpty { maximum, .. } => maximum,
        }
    }

    #[must_use]
    pub const fn is_empty_language(self) -> bool {
        matches!(self, Self::EmptyLanguage)
    }

    #[must_use]
    pub const fn is_nullable(self) -> bool {
        matches!(self, Self::NonEmpty { minimum: 0, .. })
    }

    #[must_use]
    const fn exact(self) -> Option<usize> {
        match self {
            Self::NonEmpty {
                minimum,
                maximum: Some(maximum),
            } if minimum == maximum => Some(minimum),
            Self::EmptyLanguage | Self::NonEmpty { .. } => None,
        }
    }
}

/// Inclusive checked range of bytes before or after a positioned fact.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct WidthRange {
    minimum: usize,
    maximum: Option<usize>,
}

impl WidthRange {
    #[must_use]
    pub const fn new(minimum: usize, maximum: Option<usize>) -> Self {
        Self { minimum, maximum }
    }

    #[must_use]
    pub const fn exact(width: usize) -> Self {
        Self {
            minimum: width,
            maximum: Some(width),
        }
    }

    #[must_use]
    pub const fn minimum(self) -> usize {
        self.minimum
    }

    #[must_use]
    pub const fn maximum(self) -> Option<usize> {
        self.maximum
    }

    #[must_use]
    pub const fn is_exact(self) -> bool {
        matches!(self.maximum, Some(maximum) if maximum == self.minimum)
    }
}

/// Checked match-relative context for a string, assertion, or capture.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BoundedContext {
    before: WidthRange,
    after: WidthRange,
}

impl BoundedContext {
    #[must_use]
    pub const fn new(before: WidthRange, after: WidthRange) -> Self {
        Self { before, after }
    }

    #[must_use]
    pub const fn at_match() -> Self {
        Self::new(WidthRange::exact(0), WidthRange::exact(0))
    }

    #[must_use]
    pub const fn before(self) -> WidthRange {
        self.before
    }

    #[must_use]
    pub const fn after(self) -> WidthRange {
        self.after
    }

    #[must_use]
    pub const fn has_bounded_prefix(self) -> bool {
        self.before.maximum.is_some()
    }

    #[must_use]
    pub const fn has_bounded_suffix(self) -> bool {
        self.after.maximum.is_some()
    }
}

/// Proven origin of the bytes in a required alternative.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum StringEncoding {
    /// Opaque bytes from a byte literal or byte class.
    Bytes,
    /// One canonical UTF-8 encoding of one Unicode scalar from the HIR.
    UnicodeScalar,
}

/// One alternative in a group of required substrings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequiredString {
    bytes: Vec<u8>,
    context: BoundedContext,
    encoding: StringEncoding,
}

impl RequiredString {
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn context(&self) -> BoundedContext {
        self.context
    }

    #[must_use]
    pub const fn encoding(&self) -> StringEncoding {
        self.encoding
    }
}

/// Every semantic match contains at least one alternative in this group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequiredAlternatives {
    alternatives: Vec<RequiredString>,
}

impl RequiredAlternatives {
    #[must_use]
    pub fn alternatives(&self) -> &[RequiredString] {
        &self.alternatives
    }
}

/// Complete finite set of possible consumed byte strings.
///
/// Assertions remain separate facts. Thus every semantic match consumes one
/// listed string, while contextual assertions can make a listed string
/// impossible at a particular haystack position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FiniteLanguage {
    strings: Vec<Vec<u8>>,
    total_bytes: usize,
}

impl FiniteLanguage {
    #[must_use]
    pub fn strings(&self) -> impl ExactSizeIterator<Item = &[u8]> {
        self.strings.iter().map(Vec::as_slice)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.strings.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.strings.is_empty()
    }

    #[must_use]
    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Consume this proof payload and return its source-priority-ordered
    /// strings without copying their bytes.
    #[must_use]
    pub fn into_strings(self) -> Vec<Vec<u8>> {
        self.strings
    }
}

/// One assertion and its possible match-relative context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PositionedAssertion {
    look: Look,
    context: BoundedContext,
}

impl PositionedAssertion {
    #[must_use]
    pub const fn look(self) -> Look {
        self.look
    }

    #[must_use]
    pub const fn context(self) -> BoundedContext {
        self.context
    }
}

/// Possible and independently required assertions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssertionFacts {
    possible: FactProof<Vec<PositionedAssertion>>,
    required: FactProof<Vec<PositionedAssertion>>,
    maximum_look_behind_bytes: usize,
    maximum_look_ahead_bytes: usize,
    requires_stream_end: bool,
}

impl AssertionFacts {
    #[must_use]
    pub const fn possible(&self) -> &FactProof<Vec<PositionedAssertion>> {
        &self.possible
    }

    #[must_use]
    pub const fn required(&self) -> &FactProof<Vec<PositionedAssertion>> {
        &self.required
    }

    #[must_use]
    pub const fn maximum_look_behind_bytes(&self) -> usize {
        self.maximum_look_behind_bytes
    }

    #[must_use]
    pub const fn maximum_look_ahead_bytes(&self) -> usize {
        self.maximum_look_ahead_bytes
    }

    /// Whether any possible path contains an absolute stream-end assertion.
    ///
    /// This is preserved independently from the optional positioned-
    /// assertion proof, so an assertion-cap refusal cannot manufacture an
    /// end-of-stream dependency.
    #[must_use]
    pub const fn requires_stream_end(&self) -> bool {
        self.requires_stream_end
    }
}

/// Canonical Unicode facts visible in already-expanded HIR.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnicodeFacts {
    class_count: usize,
    scalar_range_count: usize,
    scalar_count: usize,
    utf8_width_mask: u8,
    contains_non_ascii: bool,
    width_changing_alternatives: bool,
    scalar_alternatives: FactProof<FiniteLanguage>,
    simple_fold_origin: FactProof<()>,
    full_fold_equivalence: FactProof<()>,
}

impl UnicodeFacts {
    #[must_use]
    pub const fn class_count(&self) -> usize {
        self.class_count
    }

    #[must_use]
    pub const fn scalar_range_count(&self) -> usize {
        self.scalar_range_count
    }

    #[must_use]
    pub const fn scalar_count(&self) -> usize {
        self.scalar_count
    }

    #[must_use]
    pub const fn utf8_width_mask(&self) -> u8 {
        self.utf8_width_mask
    }

    #[must_use]
    pub const fn contains_non_ascii(&self) -> bool {
        self.contains_non_ascii
    }

    #[must_use]
    pub const fn width_changing_alternatives(&self) -> bool {
        self.width_changing_alternatives
    }

    #[must_use]
    pub const fn scalar_alternatives(&self) -> &FactProof<FiniteLanguage> {
        &self.scalar_alternatives
    }

    /// Canonical HIR does not retain whether a class originated in `(?i)`.
    #[must_use]
    pub const fn simple_fold_origin(&self) -> &FactProof<()> {
        &self.simple_fold_origin
    }

    /// Simple-fold HIR is not a proof of Unicode full-fold equivalence.
    #[must_use]
    pub const fn full_fold_equivalence(&self) -> &FactProof<()> {
        &self.full_fold_equivalence
    }
}

/// One capture annotation retained in source order.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CaptureParticipation {
    /// No semantic match can enter this capture.
    Never,
    /// Some semantic matches enter this capture and some do not.
    Maybe,
    /// Every semantic match enters this capture.
    Always,
    /// Canonical HIR facts cannot decide exact participation safely.
    Unknown,
}

/// One capture annotation retained in source order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PositionedCapture {
    index: u32,
    name: Option<String>,
    context: BoundedContext,
    participation: CaptureParticipation,
}

impl PositionedCapture {
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }

    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    #[must_use]
    pub const fn context(&self) -> BoundedContext {
        self.context
    }

    #[must_use]
    pub const fn participation(&self) -> CaptureParticipation {
        self.participation
    }
}

/// Capture structure and operation-specific observability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureFacts {
    captures: Vec<PositionedCapture>,
    observable: bool,
    source_schema_complete: FactProof<()>,
}

impl CaptureFacts {
    #[must_use]
    pub fn captures(&self) -> &[PositionedCapture] {
        &self.captures
    }

    #[must_use]
    pub const fn observable(&self) -> bool {
        self.observable
    }

    #[must_use]
    pub const fn erasure_permitted(&self) -> bool {
        !self.observable
    }

    /// Canonical HIR can omit captures erased by upstream smart constructors
    /// such as an outer `{0}` repetition. Source-schema completeness therefore
    /// requires a separately authenticated syntax side channel.
    #[must_use]
    pub const fn source_schema_complete(&self) -> &FactProof<()> {
        &self.source_schema_complete
    }
}

/// Semantic preconditions carried by a positive execution certificate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each boolean is an independent semantic preservation obligation"
)]
pub struct CertificatePreconditions {
    output: FactOutput,
    preserves_priority: bool,
    preserves_greediness: bool,
    preserves_empty_progress: bool,
    preserves_assertion_context: bool,
    preserves_captures: bool,
}

impl CertificatePreconditions {
    #[must_use]
    pub const fn output(self) -> FactOutput {
        self.output
    }

    #[must_use]
    pub const fn preserves_priority(self) -> bool {
        self.preserves_priority
    }

    #[must_use]
    pub const fn preserves_greediness(self) -> bool {
        self.preserves_greediness
    }

    #[must_use]
    pub const fn preserves_empty_progress(self) -> bool {
        self.preserves_empty_progress
    }

    #[must_use]
    pub const fn preserves_assertion_context(self) -> bool {
        self.preserves_assertion_context
    }

    #[must_use]
    pub const fn preserves_captures(self) -> bool {
        self.preserves_captures
    }
}

/// Checked priority-ordered deterministic-state certificate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DeterministicCertificate {
    thompson_states_upper_bound: usize,
    subset_states_upper_bound: usize,
    preconditions: CertificatePreconditions,
}

impl DeterministicCertificate {
    #[must_use]
    pub const fn thompson_states_upper_bound(self) -> usize {
        self.thompson_states_upper_bound
    }

    #[must_use]
    pub const fn subset_states_upper_bound(self) -> usize {
        self.subset_states_upper_bound
    }

    #[must_use]
    pub const fn preconditions(self) -> CertificatePreconditions {
        self.preconditions
    }
}

/// Conservative one-pass certificate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OnePassCertificate {
    thompson_states_upper_bound: usize,
    preconditions: CertificatePreconditions,
}

impl OnePassCertificate {
    #[must_use]
    pub const fn thompson_states_upper_bound(self) -> usize {
        self.thompson_states_upper_bound
    }

    #[must_use]
    pub const fn preconditions(self) -> CertificatePreconditions {
        self.preconditions
    }
}

/// Deterministic eligibility and checked state bounds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeterminismFacts {
    thompson_states_upper_bound: usize,
    subset: FactProof<DeterministicCertificate>,
    one_pass: FactProof<OnePassCertificate>,
}

impl DeterminismFacts {
    #[must_use]
    pub const fn thompson_states_upper_bound(&self) -> usize {
        self.thompson_states_upper_bound
    }

    #[must_use]
    pub const fn subset(&self) -> &FactProof<DeterministicCertificate> {
        &self.subset
    }

    #[must_use]
    pub const fn one_pass(&self) -> &FactProof<OnePassCertificate> {
        &self.one_pass
    }
}

/// Safe common-affix reduction certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AffixCertificate {
    bytes: Vec<u8>,
    preconditions: CertificatePreconditions,
}

impl AffixCertificate {
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn preconditions(&self) -> CertificatePreconditions {
        self.preconditions
    }
}

/// Operation-aware reductions proved from a complete finite language.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReductionFacts {
    common_prefix: FactProof<AffixCertificate>,
    common_suffix: FactProof<AffixCertificate>,
    duplicate_consuming_alternatives: FactProof<usize>,
}

impl ReductionFacts {
    #[must_use]
    pub const fn common_prefix(&self) -> &FactProof<AffixCertificate> {
        &self.common_prefix
    }

    #[must_use]
    pub const fn common_suffix(&self) -> &FactProof<AffixCertificate> {
        &self.common_suffix
    }

    #[must_use]
    pub const fn duplicate_consuming_alternatives(&self) -> &FactProof<usize> {
        &self.duplicate_consuming_alternatives
    }
}

/// Source-independent upper bounds admitted before facts are returned.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FactProspective {
    work: u64,
    peak_stack_items: usize,
    hir_nodes: usize,
    retained_bytes: usize,
    temporary_bytes: usize,
    peak_bytes: usize,
    allocation_attempts: usize,
    finite_strings: usize,
    finite_string_bytes: usize,
    required_groups: usize,
    required_alternatives: usize,
    required_bytes: usize,
    assertions: usize,
    deterministic_states: usize,
}

macro_rules! accounting_getters {
    () => {
        #[must_use]
        pub const fn work(self) -> u64 {
            self.work
        }
        #[must_use]
        pub const fn peak_stack_items(self) -> usize {
            self.peak_stack_items
        }
        #[must_use]
        pub const fn hir_nodes(self) -> usize {
            self.hir_nodes
        }
        #[must_use]
        pub const fn retained_bytes(self) -> usize {
            self.retained_bytes
        }
        #[must_use]
        pub const fn temporary_bytes(self) -> usize {
            self.temporary_bytes
        }
        #[must_use]
        pub const fn peak_bytes(self) -> usize {
            self.peak_bytes
        }
        #[must_use]
        pub const fn allocation_attempts(self) -> usize {
            self.allocation_attempts
        }
    };
}

impl FactProspective {
    accounting_getters!();

    #[must_use]
    pub const fn finite_strings(self) -> usize {
        self.finite_strings
    }

    #[must_use]
    pub const fn finite_string_bytes(self) -> usize {
        self.finite_string_bytes
    }

    #[must_use]
    pub const fn required_groups(self) -> usize {
        self.required_groups
    }

    #[must_use]
    pub const fn required_alternatives(self) -> usize {
        self.required_alternatives
    }

    #[must_use]
    pub const fn required_bytes(self) -> usize {
        self.required_bytes
    }

    #[must_use]
    pub const fn assertions(self) -> usize {
        self.assertions
    }

    #[must_use]
    pub const fn deterministic_states(self) -> usize {
        self.deterministic_states
    }
}

/// Exact actual construction accounting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FactStats {
    work: u64,
    peak_stack_items: usize,
    hir_nodes: usize,
    retained_bytes: usize,
    temporary_bytes: usize,
    peak_bytes: usize,
    allocation_attempts: usize,
    required_groups: usize,
    required_alternatives: usize,
    required_bytes: usize,
    finite_strings: usize,
    finite_string_bytes: usize,
}

impl FactStats {
    accounting_getters!();

    #[must_use]
    pub const fn required_groups(self) -> usize {
        self.required_groups
    }

    #[must_use]
    pub const fn required_alternatives(self) -> usize {
        self.required_alternatives
    }

    #[must_use]
    pub const fn required_bytes(self) -> usize {
        self.required_bytes
    }

    #[must_use]
    pub const fn finite_strings(self) -> usize {
        self.finite_strings
    }

    #[must_use]
    pub const fn finite_string_bytes(self) -> usize {
        self.finite_string_bytes
    }
}

/// Complete operation-aware canonical HIR report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HirFacts {
    identity: FactIdentity,
    operation: FactOperation,
    width: CheckedWidth,
    finite_language: FactProof<FiniteLanguage>,
    required: FactProof<Vec<RequiredAlternatives>>,
    assertions: AssertionFacts,
    unicode: UnicodeFacts,
    captures: CaptureFacts,
    determinism: DeterminismFacts,
    reductions: ReductionFacts,
    finite_decision_horizon_bytes: FactProof<usize>,
    prospective: FactProspective,
    stats: FactStats,
}

impl HirFacts {
    #[must_use]
    pub const fn identity(&self) -> FactIdentity {
        self.identity
    }

    #[must_use]
    pub const fn operation(&self) -> FactOperation {
        self.operation
    }

    #[must_use]
    pub const fn width(&self) -> CheckedWidth {
        self.width
    }

    #[must_use]
    pub const fn finite_language(&self) -> &FactProof<FiniteLanguage> {
        &self.finite_language
    }

    /// Consume this authenticated report and return its finite-language proof.
    ///
    /// This avoids a second potentially failing allocation when a downstream
    /// compiler uses the proof as a bounded resource fallback.
    #[must_use]
    pub fn into_finite_language(self) -> FactProof<FiniteLanguage> {
        self.finite_language
    }

    #[must_use]
    pub const fn required(&self) -> &FactProof<Vec<RequiredAlternatives>> {
        &self.required
    }

    #[must_use]
    pub const fn assertions(&self) -> &AssertionFacts {
        &self.assertions
    }

    #[must_use]
    pub const fn unicode(&self) -> &UnicodeFacts {
        &self.unicode
    }

    #[must_use]
    pub const fn captures(&self) -> &CaptureFacts {
        &self.captures
    }

    #[must_use]
    pub const fn determinism(&self) -> &DeterminismFacts {
        &self.determinism
    }

    #[must_use]
    pub const fn reductions(&self) -> &ReductionFacts {
        &self.reductions
    }

    #[must_use]
    pub const fn finite_decision_horizon_bytes(&self) -> &FactProof<usize> {
        &self.finite_decision_horizon_bytes
    }

    #[must_use]
    pub const fn prospective(&self) -> FactProspective {
        self.prospective
    }

    #[must_use]
    pub const fn stats(&self) -> FactStats {
        self.stats
    }
}

/// Analyze a canonical parsed Rust expression.
///
/// # Errors
///
/// Returns a typed hard construction failure. Optional positive proofs report
/// independent refusals inside the returned facts.
pub fn analyze_facts(
    parsed: &RustParsed,
    operation: FactOperation,
    limits: FactLimits,
) -> Result<HirFacts, FactError> {
    analyze_hir_facts(&parsed.hir, operation, limits)
}

/// Analyze canonical Rust-regex HIR directly.
///
/// # Errors
///
/// Returns a typed hard construction failure. Capture-observing operations are
/// valid analysis inputs; only lowering to the capture-free K0 engine rejects
/// them.
pub fn analyze_hir_facts(
    hir: &Hir,
    operation: FactOperation,
    limits: FactLimits,
) -> Result<HirFacts, FactError> {
    if operation.erases_captures() && operation.observes_captures() {
        return Err(FactError::CaptureErasureForCaptureOutput);
    }
    let census = Census::new(operation, limits).run(hir)?;
    Analyzer::new(operation, limits, census).run(hir)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContinuationContext {
    Terminal,
    MayReject,
}

#[derive(Clone, Copy)]
enum Task<'h> {
    Visit {
        hir: &'h Hir,
        continuation: ContinuationContext,
    },
    FinishCapture {
        index: u32,
        name: Option<&'h str>,
    },
    FinishConcat(usize),
    FinishAlternation {
        count: usize,
        continuation: ContinuationContext,
    },
    FinishRepetition {
        min: u32,
        max: Option<u32>,
        greedy: bool,
        continuation: ContinuationContext,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FirstBytes {
    words: [u64; 4],
    complete: bool,
}

impl FirstBytes {
    const fn empty(complete: bool) -> Self {
        Self {
            words: [0; 4],
            complete,
        }
    }

    fn insert(&mut self, byte: u8) {
        let index = usize::from(byte);
        self.words[index / 64] |= 1_u64 << (index % 64);
    }

    fn union(&mut self, other: Self) {
        for (left, right) in self.words.iter_mut().zip(other.words) {
            *left |= right;
        }
        self.complete &= other.complete;
    }

    fn disjoint(self, other: Self) -> bool {
        self.words
            .into_iter()
            .zip(other.words)
            .all(|(left, right)| left & right == 0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BranchReachability {
    ProvenReachable,
    ProvenUnreachable,
    Unknown,
}

/// Private capture entry over the node's ordered finite derivations.
///
/// `Bits` is aligned with `NodeFacts::finite.strings`, including duplicate
/// derivations. The trace is construction-only and is discarded when public
/// root facts are published.
#[derive(Debug)]
enum CaptureTrace {
    All,
    None,
    Bits(Vec<u64>),
    Unavailable,
}

#[derive(Debug)]
struct NodeFacts {
    width: CheckedWidth,
    finite: FactProof<FiniteLanguage>,
    required: FactProof<Vec<RequiredAlternatives>>,
    possible_assertions: FactProof<Vec<PositionedAssertion>>,
    required_assertions: FactProof<Vec<PositionedAssertion>>,
    captures: Vec<PositionedCapture>,
    capture_traces: Vec<CaptureTrace>,
    capture_trace_ordered: bool,
    unicode: UnicodeAccumulator,
    first: FirstBytes,
    one_pass_shape: bool,
    thompson_states: usize,
    duplicate_consuming_alternatives: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct UnicodeAccumulator {
    class_count: usize,
    scalar_range_count: usize,
    scalar_count: usize,
    utf8_width_mask: u8,
    contains_non_ascii: bool,
    width_changing_alternatives: bool,
    scalar_strings: Option<Vec<Vec<u8>>>,
    scalar_refusal: Option<FactRefusal>,
}

#[derive(Clone, Copy, Debug)]
struct LanguageMeasure {
    count: usize,
    bytes: usize,
}

#[derive(Clone, Copy, Debug, Default)]
struct RequiredMeasure {
    proven: bool,
    groups: usize,
    alternatives: usize,
    bytes: usize,
    selected_alternatives: usize,
    selected_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default)]
struct AssertionMeasure {
    proven: bool,
    count: usize,
    // Unlike the optional positioned-assertion proof, this structural bit is
    // retained even when the proof hits its independent cap. Consumers use it
    // to distinguish a genuine absolute-end dependency from an unavailable
    // assertion certificate.
    contains_stream_end: bool,
}

#[derive(Clone, Copy, Debug)]
struct CaptureTraceMeasure {
    all: usize,
    none: usize,
    bits: usize,
    unavailable: usize,
    ordered: bool,
}

impl CaptureTraceMeasure {
    const fn empty() -> Self {
        Self {
            all: 0,
            none: 0,
            bits: 0,
            unavailable: 0,
            ordered: true,
        }
    }

    fn combine(self, other: Self) -> Result<Self, FactError> {
        Ok(Self {
            all: add_usize(self.all, other.all, "capture trace All census")?,
            none: add_usize(self.none, other.none, "capture trace None census")?,
            bits: add_usize(self.bits, other.bits, "capture trace Bits census")?,
            unavailable: add_usize(
                self.unavailable,
                other.unavailable,
                "capture trace unavailable census",
            )?,
            ordered: self.ordered && other.ordered,
        })
    }

    fn refuse_bits(mut self) -> Result<Self, FactError> {
        self.unavailable = add_usize(
            self.unavailable,
            self.bits,
            "refused capture trace Bits census",
        )?;
        self.bits = 0;
        Ok(self)
    }

    fn validate(self, captures: usize) -> Result<(), FactError> {
        let total = add_usize(
            add_usize(self.all, self.none, "capture trace census schema")?,
            add_usize(self.bits, self.unavailable, "capture trace census schema")?,
            "capture trace census schema",
        )?;
        if total != captures {
            return Err(FactError::InternalInvariant {
                detail: "capture trace census schema diverged",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct MeasureNode {
    width: CheckedWidth,
    finite: Option<LanguageMeasure>,
    required: RequiredMeasure,
    possible_assertions: AssertionMeasure,
    required_assertions: AssertionMeasure,
    captures: usize,
    capture_name_bytes: usize,
    capture_traces: CaptureTraceMeasure,
    unicode_classes: usize,
    unicode_ranges: usize,
    unicode_scalars: usize,
    unicode_bytes: usize,
    thompson_states: usize,
    logical_bytes_upper: usize,
    build_bytes_upper: usize,
    own_build_work_upper: usize,
    own_allocation_upper: usize,
}

#[derive(Clone, Copy)]
struct CensusOutcome {
    prospective: FactProspective,
    census_work: u64,
    hir_nodes: usize,
    census_peak_stack_items: usize,
    census_temporary_bytes: usize,
    census_peak_bytes: usize,
    census_allocation_attempts: usize,
    capture_trace_precision_enabled: bool,
    possible_contains_stream_end: bool,
}

struct Census<'h> {
    operation: FactOperation,
    limits: FactLimits,
    capture_trace_precision_enabled: bool,
    tasks: Vec<Task<'h>>,
    results: Vec<MeasureNode>,
    work: u64,
    hir_nodes: usize,
    peak_stack_items: usize,
    temporary_bytes: usize,
    peak_bytes: usize,
    allocation_attempts: usize,
    live_build_bytes: usize,
    peak_build_bytes: usize,
    sum_node_bytes: usize,
    max_finite_strings: usize,
    max_finite_bytes: usize,
    max_required_groups: usize,
    max_required_alternatives: usize,
    max_required_bytes: usize,
    max_assertions: usize,
    max_deterministic_states: usize,
    construction_work_upper: usize,
    construction_allocation_upper: usize,
}

impl<'h> Census<'h> {
    const fn new(operation: FactOperation, limits: FactLimits) -> Self {
        Self {
            operation,
            limits,
            capture_trace_precision_enabled: operation.observes_captures(),
            tasks: Vec::new(),
            results: Vec::new(),
            work: 0,
            hir_nodes: 0,
            peak_stack_items: 0,
            temporary_bytes: 0,
            peak_bytes: 0,
            allocation_attempts: 0,
            live_build_bytes: 0,
            peak_build_bytes: 0,
            sum_node_bytes: 0,
            max_finite_strings: 0,
            max_finite_bytes: 0,
            max_required_groups: 0,
            max_required_alternatives: 0,
            max_required_bytes: 0,
            max_assertions: 0,
            max_deterministic_states: 0,
            construction_work_upper: 0,
            construction_allocation_upper: 0,
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the task interpreter keeps cumulative accounting transitions in one auditable loop"
    )]
    fn run(mut self, hir: &'h Hir) -> Result<CensusOutcome, FactError> {
        self.push_task(Task::Visit {
            hir,
            continuation: ContinuationContext::Terminal,
        })?;
        while let Some(task) = self.tasks.pop() {
            self.charge(1)?;
            match task {
                Task::Visit { hir, continuation } => self.visit(hir, continuation)?,
                Task::FinishCapture { name, .. } => {
                    let (mut children, child_bytes) = self.take_children(1)?;
                    let mut child = children.pop().ok_or(FactError::InternalInvariant {
                        detail: "capture census lacked its child",
                    })?;
                    if !self.operation.erases_captures() {
                        child.captures = add_usize(child.captures, 1, "capture census")?;
                        if child.width.is_empty_language() {
                            child.capture_traces.none = add_usize(
                                child.capture_traces.none,
                                1,
                                "capture trace None census",
                            )?;
                        } else {
                            child.capture_traces.all =
                                add_usize(child.capture_traces.all, 1, "capture trace All census")?;
                        }
                        if let Some(language) = child.finite {
                            if !self.capture_trace_storage_allowed(child.captures, language) {
                                child.capture_traces = child.capture_traces.refuse_bits()?;
                            }
                        }
                        child.capture_name_bytes = add_usize(
                            child.capture_name_bytes,
                            name.map_or(0, str::len),
                            "capture name census",
                        )?;
                        child.thompson_states =
                            add_usize(child.thompson_states, 1, "capture state census")?;
                    }
                    self.finish_measure_node(&mut child)?;
                    self.publish_combined(child, child_bytes, 1)?;
                }
                Task::FinishConcat(count) => {
                    let (children, child_bytes) = self.take_children(count)?;
                    let mut node = self.concat(children)?;
                    self.finish_measure_node(&mut node)?;
                    self.publish_combined(node, child_bytes, count)?;
                }
                Task::FinishAlternation {
                    count,
                    continuation,
                } => {
                    let (children, child_bytes) = self.take_children(count)?;
                    let mut node = self.alternation(children, continuation)?;
                    self.finish_measure_node(&mut node)?;
                    self.publish_combined(node, child_bytes, count)?;
                }
                Task::FinishRepetition { min, max, .. } => {
                    let (mut children, child_bytes) = self.take_children(1)?;
                    let child = children.pop().ok_or(FactError::InternalInvariant {
                        detail: "repetition census lacked its child",
                    })?;
                    let mut node = self.repetition(child, min, max)?;
                    self.finish_measure_node(&mut node)?;
                    self.publish_combined(node, child_bytes, 1)?;
                }
            }
        }
        if self.results.len() != 1 {
            return Err(FactError::InternalInvariant {
                detail: "HIR-fact census did not produce one root",
            });
        }
        let root = self.results[0];
        let root_capture_trace_work =
            root_capture_trace_work_bound(root).ok_or(FactError::InternalInvariant {
                detail: "admitted root capture trace work was not representable",
            })?;
        if self.operation.requests_determinism() {
            let complete_thompson_states =
                add_usize(root.thompson_states, 1, "final accept state census")?;
            if let Some(bound) = ordered_subset_bound(complete_thompson_states) {
                self.max_deterministic_states = self.max_deterministic_states.max(bound);
            } else {
                self.max_deterministic_states = usize::MAX;
            }
        }
        let construction_allocations = self.construction_allocation_upper;
        let allocation_attempts = add_usize(
            self.allocation_attempts,
            construction_allocations,
            "prospective allocation attempts",
        )?;
        let mut construction_work = add_usize(
            self.construction_work_upper,
            root.possible_assertions.count,
            "root assertion context work",
        )?;
        construction_work = add_usize(
            construction_work,
            root_capture_trace_work,
            "root capture trace work",
        )?;
        if self.operation.requests_reductions()
            && let Some(language) = root.finite
        {
            if let Some(reduction_work) = duplicate_reduction_work_bound(language) {
                construction_work = add_usize(
                    construction_work,
                    reduction_work,
                    "prospective reduction work",
                )?;
            }
        }
        let work = self
            .work
            .checked_add(to_u64(construction_work, "prospective work conversion")?)
            .ok_or(FactError::ArithmeticOverflow {
                computation: "prospective work",
            })?;
        let construction_peak_upper = add_usize(
            self.peak_build_bytes,
            construction_work,
            "prospective construction peak bytes",
        )?;
        let temporary_bytes = self.temporary_bytes.max(construction_peak_upper);
        let retained_bytes = root.logical_bytes_upper;
        let peak_bytes = self.peak_bytes.max(temporary_bytes).max(retained_bytes);
        let prospective = FactProspective {
            work,
            peak_stack_items: self.peak_stack_items,
            hir_nodes: self.hir_nodes,
            retained_bytes,
            temporary_bytes,
            peak_bytes,
            allocation_attempts,
            finite_strings: self.max_finite_strings,
            finite_string_bytes: self.max_finite_bytes,
            required_groups: self.max_required_groups,
            required_alternatives: self.max_required_alternatives,
            required_bytes: self.max_required_bytes,
            assertions: self.max_assertions,
            deterministic_states: self.max_deterministic_states,
        };
        preflight_prospective(prospective, self.limits)?;
        Ok(CensusOutcome {
            prospective,
            census_work: self.work,
            hir_nodes: self.hir_nodes,
            census_peak_stack_items: self.peak_stack_items,
            census_temporary_bytes: self.temporary_bytes,
            census_peak_bytes: self.peak_bytes,
            census_allocation_attempts: self.allocation_attempts,
            capture_trace_precision_enabled: self.capture_trace_precision_enabled,
            possible_contains_stream_end: root.possible_assertions.contains_stream_end,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "all HIR leaf census rules remain adjacent for accounting auditability"
    )]
    fn visit(&mut self, hir: &'h Hir, continuation: ContinuationContext) -> Result<(), FactError> {
        self.charge(1)?;
        let needed = add_usize(self.hir_nodes, 1, "HIR census node count")?;
        Self::check(FactResource::HirNodes, needed, self.limits.max_hir_nodes)?;
        self.hir_nodes = needed;
        match hir.kind() {
            HirKind::Empty => {
                let finite = self.finite_measure(1, 0);
                self.publish_leaf(MeasureNode {
                    width: CheckedWidth::NonEmpty {
                        minimum: 0,
                        maximum: Some(0),
                    },
                    finite,
                    required: RequiredMeasure {
                        proven: true,
                        ..RequiredMeasure::default()
                    },
                    possible_assertions: AssertionMeasure {
                        proven: true,
                        count: 0,
                        contains_stream_end: false,
                    },
                    required_assertions: AssertionMeasure {
                        proven: true,
                        count: 0,
                        contains_stream_end: false,
                    },
                    captures: 0,
                    capture_name_bytes: 0,
                    capture_traces: CaptureTraceMeasure::empty(),
                    unicode_classes: 0,
                    unicode_ranges: 0,
                    unicode_scalars: 0,
                    unicode_bytes: 0,
                    thompson_states: 1,
                    logical_bytes_upper: 0,
                    build_bytes_upper: 0,
                    own_build_work_upper: 0,
                    own_allocation_upper: 0,
                })
            }
            HirKind::Literal(literal) => {
                let required = if literal.0.is_empty() {
                    RequiredMeasure {
                        proven: true,
                        ..RequiredMeasure::default()
                    }
                } else {
                    self.required_measure(1, 1, literal.0.len(), 1, literal.0.len())
                };
                let finite = self.finite_measure(1, literal.0.len());
                self.publish_leaf(MeasureNode {
                    width: CheckedWidth::NonEmpty {
                        minimum: literal.0.len(),
                        maximum: Some(literal.0.len()),
                    },
                    finite,
                    required,
                    possible_assertions: AssertionMeasure {
                        proven: true,
                        count: 0,
                        contains_stream_end: false,
                    },
                    required_assertions: AssertionMeasure {
                        proven: true,
                        count: 0,
                        contains_stream_end: false,
                    },
                    captures: 0,
                    capture_name_bytes: 0,
                    capture_traces: CaptureTraceMeasure::empty(),
                    unicode_classes: 0,
                    unicode_ranges: 0,
                    unicode_scalars: 0,
                    unicode_bytes: 0,
                    thompson_states: literal.0.len().max(1),
                    logical_bytes_upper: 0,
                    build_bytes_upper: 0,
                    own_build_work_upper: 0,
                    own_allocation_upper: 0,
                })
            }
            HirKind::Class(Class::Bytes(class)) => {
                self.charge(to_u64(class.ranges().len(), "byte-class census work")?)?;
                let count = class.ranges().iter().try_fold(0_usize, |total, range| {
                    let width = usize::from(range.end())
                        .checked_sub(usize::from(range.start()))
                        .and_then(|value| value.checked_add(1))
                        .ok_or(FactError::ArithmeticOverflow {
                            computation: "byte-class census",
                        })?;
                    add_usize(total, width, "byte-class census")
                })?;
                let width = if count == 0 {
                    CheckedWidth::EmptyLanguage
                } else {
                    CheckedWidth::NonEmpty {
                        minimum: 1,
                        maximum: Some(1),
                    }
                };
                let required = if count == 0 {
                    RequiredMeasure {
                        proven: true,
                        ..RequiredMeasure::default()
                    }
                } else {
                    self.required_measure(1, count, count, count, count)
                };
                let finite = self.finite_measure(count, count);
                self.publish_leaf(MeasureNode {
                    width,
                    finite,
                    required,
                    possible_assertions: AssertionMeasure {
                        proven: true,
                        count: 0,
                        contains_stream_end: false,
                    },
                    required_assertions: AssertionMeasure {
                        proven: true,
                        count: 0,
                        contains_stream_end: false,
                    },
                    captures: 0,
                    capture_name_bytes: 0,
                    capture_traces: CaptureTraceMeasure::empty(),
                    unicode_classes: 0,
                    unicode_ranges: 0,
                    unicode_scalars: 0,
                    unicode_bytes: 0,
                    thompson_states: 1,
                    logical_bytes_upper: 0,
                    build_bytes_upper: 0,
                    own_build_work_upper: 0,
                    own_allocation_upper: 0,
                })
            }
            HirKind::Class(Class::Unicode(class)) => {
                // The metric helper performs one cardinality operation and
                // four fixed UTF-8-width intersections per range. The width
                // helper then examines every range once. Charge that complete
                // traversal before either helper is allowed to scan.
                let metric_work = mul_usize(class.ranges().len(), 6, "Unicode census metric work")?;
                self.charge(to_u64(metric_work, "Unicode census metric work")?)?;
                let (count, bytes) = unicode_class_metrics(class)?;
                let width = unicode_class_width(class);
                let required = if count == 0 {
                    RequiredMeasure {
                        proven: true,
                        ..RequiredMeasure::default()
                    }
                } else {
                    self.required_measure(1, count, bytes, count, bytes)
                };
                // Without a deterministic certificate, preserve a cheap
                // structural upper bound without constructing the UTF-8
                // sequence partition. A scalar expands to at most four byte
                // states plus one branch state, so treating every scalar as
                // a separate branch is conservative.
                let mut thompson_states = if self.operation.requests_determinism() {
                    1
                } else {
                    add_usize(
                        mul_usize(count, 5, "coarse Unicode census states")?,
                        1,
                        "coarse Unicode census states",
                    )?
                };
                let mut sequence_count = 0_usize;
                if self.operation.requests_determinism() {
                    for range in class.ranges() {
                        self.charge(1)?;
                        for sequence in Utf8Sequences::new(range.start(), range.end()) {
                            self.charge(1)?;
                            sequence_count =
                                add_usize(sequence_count, 1, "Unicode sequence census")?;
                            thompson_states = add_usize(
                                thompson_states,
                                add_usize(sequence.len(), 1, "Unicode census states")?,
                                "Unicode census states",
                            )?;
                        }
                    }
                }
                let finite = self.finite_measure(count, bytes);
                self.publish_leaf(MeasureNode {
                    width,
                    finite,
                    required,
                    possible_assertions: AssertionMeasure {
                        proven: true,
                        count: 0,
                        contains_stream_end: false,
                    },
                    required_assertions: AssertionMeasure {
                        proven: true,
                        count: 0,
                        contains_stream_end: false,
                    },
                    captures: 0,
                    capture_name_bytes: 0,
                    capture_traces: CaptureTraceMeasure::empty(),
                    unicode_classes: 1,
                    unicode_ranges: class.ranges().len(),
                    unicode_scalars: count,
                    unicode_bytes: bytes,
                    thompson_states,
                    logical_bytes_upper: 0,
                    build_bytes_upper: 0,
                    own_build_work_upper: if self.operation.requests_finite_language() {
                        mul_usize(
                            add_usize(
                                class.ranges().len(),
                                sequence_count,
                                "Unicode construction traversal",
                            )?,
                            8,
                            "Unicode construction traversal",
                        )?
                    } else {
                        // The route-scoped analyzer repeats the five-operation
                        // scalar metric pass and one width/range visit after
                        // the census. Determinism additionally visits each
                        // UTF-8 sequence. The compact per-node envelope below
                        // cannot infer this input-sized work from retained
                        // bytes, so publish it explicitly.
                        add_usize(
                            mul_usize(
                                class.ranges().len(),
                                6,
                                "route-scoped Unicode construction traversal",
                            )?,
                            sequence_count,
                            "route-scoped Unicode construction traversal",
                        )?
                    },
                    own_allocation_upper: 0,
                })
            }
            HirKind::Look(look) => {
                let assertion = self.assertion_measure(1, *look == Look::End);
                let finite = self.finite_measure(1, 0);
                self.publish_leaf(MeasureNode {
                    width: CheckedWidth::NonEmpty {
                        minimum: 0,
                        maximum: Some(0),
                    },
                    finite,
                    required: RequiredMeasure {
                        proven: true,
                        ..RequiredMeasure::default()
                    },
                    possible_assertions: assertion,
                    required_assertions: assertion,
                    captures: 0,
                    capture_name_bytes: 0,
                    capture_traces: CaptureTraceMeasure::empty(),
                    unicode_classes: 0,
                    unicode_ranges: 0,
                    unicode_scalars: 0,
                    unicode_bytes: 0,
                    thompson_states: 1,
                    logical_bytes_upper: 0,
                    build_bytes_upper: 0,
                    own_build_work_upper: 0,
                    own_allocation_upper: 0,
                })
            }
            HirKind::Capture(capture) => {
                self.push_task(Task::FinishCapture {
                    index: capture.index,
                    name: capture.name.as_deref(),
                })?;
                self.push_task(Task::Visit {
                    hir: &capture.sub,
                    continuation,
                })
            }
            HirKind::Concat(parts) => {
                self.push_task(Task::FinishConcat(parts.len()))?;
                for (index, part) in parts.iter().enumerate().rev() {
                    self.push_task(Task::Visit {
                        hir: part,
                        continuation: if index == parts.len().saturating_sub(1) {
                            continuation
                        } else {
                            ContinuationContext::MayReject
                        },
                    })?;
                }
                Ok(())
            }
            HirKind::Alternation(branches) => {
                self.push_task(Task::FinishAlternation {
                    count: branches.len(),
                    continuation,
                })?;
                for branch in branches.iter().rev() {
                    self.push_task(Task::Visit {
                        hir: branch,
                        continuation,
                    })?;
                }
                Ok(())
            }
            HirKind::Repetition(repetition) => {
                self.push_task(Task::FinishRepetition {
                    min: repetition.min,
                    max: repetition.max,
                    greedy: repetition.greedy,
                    continuation,
                })?;
                self.push_task(Task::Visit {
                    hir: &repetition.sub,
                    continuation: if repetition.min == 1 && repetition.max == Some(1) {
                        continuation
                    } else {
                        ContinuationContext::MayReject
                    },
                })
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the concatenation proof and its cumulative ledger must be updated atomically"
    )]
    fn concat(&mut self, children: Vec<MeasureNode>) -> Result<MeasureNode, FactError> {
        if children.iter().any(|child| child.width.is_empty_language()) {
            return self.empty_measure(children);
        }
        let mut width = WidthRange::exact(0);
        let mut finite = self
            .operation
            .requests_finite_language()
            .then_some(LanguageMeasure { count: 1, bytes: 0 });
        let mut finite_intermediate_work = 0_usize;
        let mut finite_intermediate_allocations =
            usize::from(self.operation.requests_finite_language());
        let mut required = RequiredMeasure {
            proven: true,
            ..RequiredMeasure::default()
        };
        let mut possible_assertions = AssertionMeasure {
            proven: true,
            count: 0,
            contains_stream_end: false,
        };
        let mut required_assertions = possible_assertions;
        let mut captures = 0_usize;
        let mut capture_name_bytes = 0_usize;
        let mut unicode_classes = 0_usize;
        let mut unicode_ranges = 0_usize;
        let mut unicode_scalars = 0_usize;
        let mut unicode_bytes = 0_usize;
        let mut thompson_states = add_usize(children.len(), 1, "concat census states")?;
        for child in &children {
            width = add_width_range(width, width_range(child.width)?)?;
            finite = measure_concat_language(finite, child.finite);
            if let Some(language) = finite {
                // Optional finite-language materialization is quota bounded.
                // Drop the proof at the first over-limit intermediate instead
                // of allowing later prospective-work arithmetic to overflow.
                finite = self.finite_measure(language.count, language.bytes);
            }
            if let Some(language) = finite {
                finite_intermediate_work = add_usize(
                    finite_intermediate_work,
                    language.bytes,
                    "finite concatenation intermediate work",
                )?;
                finite_intermediate_allocations = add_usize(
                    finite_intermediate_allocations,
                    add_usize(
                        language.count,
                        1,
                        "finite concatenation intermediate allocations",
                    )?,
                    "finite concatenation intermediate allocations",
                )?;
            }
            if child.required.proven {
                required.groups = add_usize(
                    required.groups,
                    child.required.groups,
                    "concat required groups",
                )?;
                required.alternatives = add_usize(
                    required.alternatives,
                    child.required.alternatives,
                    "concat required alternatives",
                )?;
                required.bytes = add_usize(
                    required.bytes,
                    child.required.bytes,
                    "concat required bytes",
                )?;
                // The analyzer selects one strongest group from the union of
                // concatenated child groups. The census intentionally does
                // not retain every candidate, so carry component-wise maxima
                // instead of incorrectly binding the first non-empty group.
                required.selected_alternatives = required
                    .selected_alternatives
                    .max(child.required.selected_alternatives);
                required.selected_bytes =
                    required.selected_bytes.max(child.required.selected_bytes);
            }
            possible_assertions =
                measure_concat_assertions(possible_assertions, child.possible_assertions)?;
            required_assertions =
                measure_concat_assertions(required_assertions, child.required_assertions)?;
            captures = add_usize(captures, child.captures, "concat captures")?;
            capture_name_bytes = add_usize(
                capture_name_bytes,
                child.capture_name_bytes,
                "concat capture names",
            )?;
            unicode_classes = add_usize(
                unicode_classes,
                child.unicode_classes,
                "concat Unicode classes",
            )?;
            unicode_ranges = add_usize(
                unicode_ranges,
                child.unicode_ranges,
                "concat Unicode ranges",
            )?;
            unicode_scalars = add_usize(
                unicode_scalars,
                child.unicode_scalars,
                "concat Unicode scalars",
            )?;
            unicode_bytes = add_usize(unicode_bytes, child.unicode_bytes, "concat Unicode bytes")?;
            thompson_states = add_usize(
                thompson_states,
                child.thompson_states,
                "concat census states",
            )?;
        }
        self.normalize_measures(&mut finite, &mut required, &mut possible_assertions);
        self.normalize_assertion_measure(&mut required_assertions);
        let capture_traces = self.concat_capture_trace_measure(&children, captures, finite)?;
        let assertion_work = children.iter().try_fold(0_usize, |work, child| {
            add_usize(
                work,
                add_usize(
                    child.possible_assertions.count,
                    child.required_assertions.count,
                    "concat assertion publication work",
                )?,
                "concat assertion publication work",
            )
        })?;
        Ok(MeasureNode {
            width: CheckedWidth::NonEmpty {
                minimum: width.minimum,
                maximum: width.maximum,
            },
            finite,
            required,
            possible_assertions,
            required_assertions,
            captures,
            capture_name_bytes,
            capture_traces,
            unicode_classes,
            unicode_ranges,
            unicode_scalars,
            unicode_bytes,
            thompson_states,
            logical_bytes_upper: 0,
            build_bytes_upper: 0,
            own_build_work_upper: add_usize(
                mul_usize(
                    finite_intermediate_work,
                    4,
                    "finite concatenation work upper bound",
                )?,
                assertion_work,
                "concat construction work upper bound",
            )?,
            own_allocation_upper: finite_intermediate_allocations,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the alternation proof and its cumulative ledger must be updated atomically"
    )]
    fn alternation(
        &mut self,
        children: Vec<MeasureNode>,
        continuation: ContinuationContext,
    ) -> Result<MeasureNode, FactError> {
        let possible_count = children
            .iter()
            .filter(|child| !child.width.is_empty_language())
            .count();
        if possible_count == 0 {
            return self.empty_measure(children);
        }
        let mut minimum = usize::MAX;
        let mut maximum = Some(0_usize);
        let mut finite = self
            .operation
            .requests_finite_language()
            .then_some(LanguageMeasure { count: 0, bytes: 0 });
        let mut required = RequiredMeasure {
            proven: true,
            groups: 1,
            ..RequiredMeasure::default()
        };
        let mut possible_assertions = AssertionMeasure {
            proven: true,
            count: 0,
            contains_stream_end: false,
        };
        let mut required_assertions = AssertionMeasure {
            proven: true,
            count: usize::MAX,
            contains_stream_end: true,
        };
        let mut captures = 0_usize;
        let mut capture_name_bytes = 0_usize;
        let mut unicode_classes = 0_usize;
        let mut unicode_ranges = 0_usize;
        let mut unicode_scalars = 0_usize;
        let mut unicode_bytes = 0_usize;
        let mut thompson_states = add_usize(
            mul_usize(children.len(), 2, "alternation census states")?,
            1,
            "alternation census states",
        )?;
        for child in &children {
            captures = add_usize(captures, child.captures, "alternation captures")?;
            capture_name_bytes = add_usize(
                capture_name_bytes,
                child.capture_name_bytes,
                "alternation capture names",
            )?;
        }
        for child in children
            .iter()
            .filter(|child| !child.width.is_empty_language())
        {
            let CheckedWidth::NonEmpty {
                minimum: child_minimum,
                maximum: child_maximum,
            } = child.width
            else {
                continue;
            };
            minimum = minimum.min(child_minimum);
            maximum = match (maximum, child_maximum) {
                (Some(left), Some(right)) => Some(left.max(right)),
                _ => None,
            };
            finite = measure_alternation_language(finite, child.finite);
            if !child.required.proven || child.required.selected_alternatives == 0 {
                required = RequiredMeasure {
                    proven: true,
                    ..RequiredMeasure::default()
                };
            } else if required.groups != 0 {
                required.alternatives = add_usize(
                    required.alternatives,
                    child.required.selected_alternatives,
                    "alternation required alternatives",
                )?;
                required.bytes = add_usize(
                    required.bytes,
                    child.required.selected_bytes,
                    "alternation required bytes",
                )?;
                required.selected_alternatives = required.alternatives;
                required.selected_bytes = required.bytes;
            }
            possible_assertions =
                measure_concat_assertions(possible_assertions, child.possible_assertions)?;
            if child.required_assertions.proven {
                required_assertions.count = required_assertions
                    .count
                    .min(child.required_assertions.count);
                required_assertions.contains_stream_end &=
                    child.required_assertions.contains_stream_end;
            } else {
                required_assertions.proven = false;
                required_assertions.count = 0;
                required_assertions.contains_stream_end = false;
            }
            unicode_classes = add_usize(
                unicode_classes,
                child.unicode_classes,
                "alternation Unicode classes",
            )?;
            unicode_ranges = add_usize(
                unicode_ranges,
                child.unicode_ranges,
                "alternation Unicode ranges",
            )?;
            unicode_scalars = add_usize(
                unicode_scalars,
                child.unicode_scalars,
                "alternation Unicode scalars",
            )?;
            unicode_bytes = add_usize(
                unicode_bytes,
                child.unicode_bytes,
                "alternation Unicode bytes",
            )?;
            thompson_states = add_usize(
                thompson_states,
                child.thompson_states,
                "alternation census states",
            )?;
        }
        if required_assertions.count == usize::MAX {
            required_assertions.count = 0;
        }
        self.normalize_measures(&mut finite, &mut required, &mut possible_assertions);
        self.normalize_assertion_measure(&mut required_assertions);
        let capture_traces =
            self.alternation_capture_trace_measure(&children, captures, possible_count, finite)?;
        let finite_work = finite.map_or(0, |language| language.bytes);
        let finite_allocations = finite.map_or(0, |language| language.count.saturating_add(1));
        let capture_priority_work = capture_priority_work_bound(&children, continuation)?;
        let assertion_work = alternation_assertion_work_bound(&children)?;
        Ok(MeasureNode {
            width: CheckedWidth::NonEmpty { minimum, maximum },
            finite,
            required,
            possible_assertions,
            required_assertions,
            captures,
            capture_name_bytes,
            capture_traces,
            unicode_classes,
            unicode_ranges,
            unicode_scalars,
            unicode_bytes,
            thompson_states,
            logical_bytes_upper: 0,
            build_bytes_upper: 0,
            own_build_work_upper: add_usize(
                mul_usize(finite_work, 4, "finite alternation work upper bound")?,
                add_usize(
                    capture_priority_work,
                    assertion_work,
                    "alternation proof work upper bound",
                )?,
                "alternation construction work upper bound",
            )?,
            own_allocation_upper: finite_allocations,
        })
    }

    fn repetition(
        &mut self,
        child: MeasureNode,
        min: u32,
        max: Option<u32>,
    ) -> Result<MeasureNode, FactError> {
        let width = repeat_width(child.width, min, max)?;
        if width.is_empty_language() {
            let mut children = self.measure_vector(1, "empty repetition census")?;
            children.push(child);
            return self.empty_measure(children);
        }
        let (mut finite, repetition_work, repetition_allocations) = match (child.finite, max) {
            (Some(language), Some(maximum)) => {
                match repeat_language_census(language, min, maximum)? {
                    Some((language, work, allocations)) => (Some(language), work, allocations),
                    None => (None, 0, 0),
                }
            }
            (Some(language), None) if language.bytes == 0 => {
                (Some(LanguageMeasure { count: 1, bytes: 0 }), 1, 1)
            }
            _ => (None, 0, 0),
        };
        let mut required = if min == 0 {
            RequiredMeasure {
                proven: true,
                ..RequiredMeasure::default()
            }
        } else {
            child.required
        };
        let mut possible_assertions = if max == Some(0) {
            AssertionMeasure {
                proven: true,
                count: 0,
                contains_stream_end: false,
            }
        } else {
            child.possible_assertions
        };
        let mut required_assertions = if min == 0 {
            AssertionMeasure {
                proven: true,
                count: 0,
                contains_stream_end: false,
            }
        } else {
            child.required_assertions
        };
        self.normalize_measures(&mut finite, &mut required, &mut possible_assertions);
        self.normalize_assertion_measure(&mut required_assertions);
        let assertion_work = if max == Some(0) {
            0
        } else {
            add_usize(
                child.possible_assertions.count,
                if min == 0 {
                    0
                } else {
                    child.required_assertions.count
                },
                "repetition shifted assertion work",
            )?
        };
        let copies = usize::try_from(match max {
            Some(maximum) => maximum,
            None => min.saturating_add(1),
        })
        .map_err(|_| FactError::ArithmeticOverflow {
            computation: "repetition census copies",
        })?;
        let thompson_states = add_usize(
            mul_usize(
                copies,
                add_usize(child.thompson_states, 2, "repetition census states")?,
                "repetition census states",
            )?,
            1,
            "repetition census states",
        )?;
        let capture_traces = self.repetition_capture_trace_measure(child, finite, min, max)?;
        Ok(MeasureNode {
            width,
            finite,
            required,
            possible_assertions,
            required_assertions,
            captures: child.captures,
            capture_name_bytes: child.capture_name_bytes,
            capture_traces,
            unicode_classes: child.unicode_classes,
            unicode_ranges: child.unicode_ranges,
            unicode_scalars: child.unicode_scalars,
            unicode_bytes: child.unicode_bytes,
            thompson_states,
            logical_bytes_upper: 0,
            build_bytes_upper: 0,
            own_build_work_upper: add_usize(
                repetition_work,
                assertion_work,
                "repetition construction work upper bound",
            )?,
            own_allocation_upper: repetition_allocations,
        })
    }

    fn empty_measure(&mut self, children: Vec<MeasureNode>) -> Result<MeasureNode, FactError> {
        let mut captures = 0_usize;
        let mut capture_name_bytes = 0_usize;
        let mut unicode_classes = 0_usize;
        let mut unicode_ranges = 0_usize;
        let mut unicode_scalars = 0_usize;
        let mut unicode_bytes = 0_usize;
        let mut thompson_states = 1_usize;
        for child in children {
            captures = add_usize(captures, child.captures, "empty census captures")?;
            capture_name_bytes = add_usize(
                capture_name_bytes,
                child.capture_name_bytes,
                "empty census capture names",
            )?;
            unicode_classes = add_usize(
                unicode_classes,
                child.unicode_classes,
                "empty census Unicode classes",
            )?;
            unicode_ranges = add_usize(
                unicode_ranges,
                child.unicode_ranges,
                "empty census Unicode ranges",
            )?;
            unicode_scalars = add_usize(
                unicode_scalars,
                child.unicode_scalars,
                "empty census Unicode scalars",
            )?;
            unicode_bytes = add_usize(
                unicode_bytes,
                child.unicode_bytes,
                "empty census Unicode bytes",
            )?;
            thompson_states = add_usize(
                thompson_states,
                child.thompson_states,
                "empty census states",
            )?;
        }
        Ok(MeasureNode {
            width: CheckedWidth::EmptyLanguage,
            finite: self.finite_measure(0, 0),
            required: RequiredMeasure {
                proven: true,
                ..RequiredMeasure::default()
            },
            possible_assertions: AssertionMeasure {
                proven: true,
                count: 0,
                contains_stream_end: false,
            },
            required_assertions: AssertionMeasure {
                proven: true,
                count: 0,
                contains_stream_end: false,
            },
            captures,
            capture_name_bytes,
            capture_traces: CaptureTraceMeasure {
                all: 0,
                none: captures,
                bits: 0,
                unavailable: 0,
                ordered: true,
            },
            unicode_classes,
            unicode_ranges,
            unicode_scalars,
            unicode_bytes,
            thompson_states,
            logical_bytes_upper: 0,
            build_bytes_upper: 0,
            own_build_work_upper: 0,
            own_allocation_upper: 0,
        })
    }

    fn finite_measure(&mut self, count: usize, bytes: usize) -> Option<LanguageMeasure> {
        if !self.operation.requests_finite_language() {
            return None;
        }
        self.max_finite_strings = self.max_finite_strings.max(count);
        self.max_finite_bytes = self.max_finite_bytes.max(bytes);
        if count > self.limits.max_finite_strings || bytes > self.limits.max_finite_string_bytes {
            None
        } else {
            Some(LanguageMeasure { count, bytes })
        }
    }

    fn capture_trace_storage_allowed(&self, captures: usize, language: LanguageMeasure) -> bool {
        self.capture_trace_precision_enabled
            && capture_trace_precision_fits(
                captures,
                language.count,
                language.bytes,
                self.limits.max_finite_string_bytes,
            )
    }

    fn required_measure(
        &mut self,
        groups: usize,
        alternatives: usize,
        bytes: usize,
        selected_alternatives: usize,
        selected_bytes: usize,
    ) -> RequiredMeasure {
        if !self.operation.requests_required_substrings() {
            return RequiredMeasure {
                proven: false,
                ..RequiredMeasure::default()
            };
        }
        self.max_required_groups = self.max_required_groups.max(groups);
        self.max_required_alternatives = self.max_required_alternatives.max(alternatives);
        self.max_required_bytes = self.max_required_bytes.max(bytes);
        RequiredMeasure {
            proven: groups <= self.limits.max_required_groups
                && alternatives <= self.limits.max_required_alternatives
                && bytes <= self.limits.max_required_bytes,
            groups: if groups <= self.limits.max_required_groups
                && alternatives <= self.limits.max_required_alternatives
                && bytes <= self.limits.max_required_bytes
            {
                groups
            } else {
                0
            },
            alternatives: if groups <= self.limits.max_required_groups
                && alternatives <= self.limits.max_required_alternatives
                && bytes <= self.limits.max_required_bytes
            {
                alternatives
            } else {
                0
            },
            bytes: if groups <= self.limits.max_required_groups
                && alternatives <= self.limits.max_required_alternatives
                && bytes <= self.limits.max_required_bytes
            {
                bytes
            } else {
                0
            },
            selected_alternatives: if groups <= self.limits.max_required_groups
                && alternatives <= self.limits.max_required_alternatives
                && bytes <= self.limits.max_required_bytes
            {
                selected_alternatives
            } else {
                0
            },
            selected_bytes: if groups <= self.limits.max_required_groups
                && alternatives <= self.limits.max_required_alternatives
                && bytes <= self.limits.max_required_bytes
            {
                selected_bytes
            } else {
                0
            },
        }
    }

    fn assertion_measure(&mut self, count: usize, contains_stream_end: bool) -> AssertionMeasure {
        if !self.operation.requests_assertion_context() {
            return AssertionMeasure {
                proven: false,
                count: 0,
                contains_stream_end,
            };
        }
        self.max_assertions = self.max_assertions.max(count);
        AssertionMeasure {
            proven: count <= self.limits.max_assertions,
            count: if count <= self.limits.max_assertions {
                count
            } else {
                0
            },
            contains_stream_end,
        }
    }

    fn normalize_measures(
        &mut self,
        finite: &mut Option<LanguageMeasure>,
        required: &mut RequiredMeasure,
        assertions: &mut AssertionMeasure,
    ) {
        if let Some(language) = *finite {
            *finite = self.finite_measure(language.count, language.bytes);
        }
        if required.groups <= 1 {
            *required = self.required_measure(
                required.groups,
                required.alternatives,
                required.bytes,
                required.selected_alternatives,
                required.selected_bytes,
            );
        } else {
            self.max_required_groups = self.max_required_groups.max(required.groups);
            self.max_required_alternatives =
                self.max_required_alternatives.max(required.alternatives);
            self.max_required_bytes = self.max_required_bytes.max(required.bytes);
            if required.groups > self.limits.max_required_groups {
                required.proven = false;
                required.groups = 0;
                required.alternatives = 0;
                required.bytes = 0;
                required.selected_alternatives = 0;
                required.selected_bytes = 0;
            }
        }
        self.normalize_assertion_measure(assertions);
    }

    fn normalize_assertion_measure(&mut self, assertions: &mut AssertionMeasure) {
        if assertions.proven {
            *assertions = self.assertion_measure(assertions.count, assertions.contains_stream_end);
        }
    }

    fn concat_capture_trace_measure(
        &self,
        children: &[MeasureNode],
        captures: usize,
        finite: Option<LanguageMeasure>,
    ) -> Result<CaptureTraceMeasure, FactError> {
        let mut traces = CaptureTraceMeasure::empty();
        for child in children {
            traces = traces.combine(child.capture_traces)?;
        }
        let admitted = self.capture_trace_precision_enabled
            && traces.ordered
            && finite
                .is_some_and(|language| self.capture_trace_storage_allowed(captures, language));
        if !admitted {
            traces = traces.refuse_bits()?;
        }
        traces.validate(captures)?;
        Ok(traces)
    }

    fn alternation_capture_trace_measure(
        &self,
        children: &[MeasureNode],
        captures: usize,
        possible_count: usize,
        finite: Option<LanguageMeasure>,
    ) -> Result<CaptureTraceMeasure, FactError> {
        let ordered = children.iter().all(|child| child.capture_traces.ordered);
        let admitted = self.capture_trace_precision_enabled
            && ordered
            && finite
                .is_some_and(|language| self.capture_trace_storage_allowed(captures, language));
        let mut traces = CaptureTraceMeasure {
            ordered,
            ..CaptureTraceMeasure::empty()
        };
        for child in children {
            if child.width.is_empty_language() {
                traces.none = add_usize(
                    traces.none,
                    add_usize(
                        child.capture_traces.all,
                        child.capture_traces.none,
                        "empty alternation capture traces",
                    )?,
                    "empty alternation capture traces",
                )?;
                traces.unavailable = add_usize(
                    traces.unavailable,
                    add_usize(
                        child.capture_traces.bits,
                        child.capture_traces.unavailable,
                        "empty alternation unavailable traces",
                    )?,
                    "empty alternation unavailable traces",
                )?;
                continue;
            }
            traces.none = add_usize(
                traces.none,
                child.capture_traces.none,
                "alternation capture trace None census",
            )?;
            traces.unavailable = add_usize(
                traces.unavailable,
                child.capture_traces.unavailable,
                "alternation unavailable trace census",
            )?;
            if possible_count == 1 {
                traces.all = add_usize(
                    traces.all,
                    child.capture_traces.all,
                    "alternation capture trace All census",
                )?;
            } else if admitted {
                traces.bits = add_usize(
                    traces.bits,
                    child.capture_traces.all,
                    "alternation capture trace All conversion",
                )?;
            } else {
                traces.unavailable = add_usize(
                    traces.unavailable,
                    child.capture_traces.all,
                    "alternation refused All traces",
                )?;
            }
            if admitted {
                traces.bits = add_usize(
                    traces.bits,
                    child.capture_traces.bits,
                    "alternation capture trace Bits census",
                )?;
            } else {
                traces.unavailable = add_usize(
                    traces.unavailable,
                    child.capture_traces.bits,
                    "alternation refused Bits traces",
                )?;
            }
        }
        traces.validate(captures)?;
        Ok(traces)
    }

    fn repetition_capture_trace_measure(
        &self,
        child: MeasureNode,
        finite: Option<LanguageMeasure>,
        min: u32,
        max: Option<u32>,
    ) -> Result<CaptureTraceMeasure, FactError> {
        let captures = child.captures;
        let traces = if max == Some(0) {
            CaptureTraceMeasure {
                all: 0,
                none: captures,
                bits: 0,
                unavailable: 0,
                ordered: true,
            }
        } else if min == 1 && max == Some(1) {
            let admitted = self.capture_trace_precision_enabled
                && finite
                    .is_some_and(|language| self.capture_trace_storage_allowed(captures, language));
            if admitted {
                child.capture_traces
            } else {
                child.capture_traces.refuse_bits()?
            }
        } else {
            let retained_all = if min >= 1 {
                child.capture_traces.all
            } else {
                0
            };
            let refused_all = if min == 0 {
                child.capture_traces.all
            } else {
                0
            };
            CaptureTraceMeasure {
                all: retained_all,
                none: child.capture_traces.none,
                bits: 0,
                unavailable: add_usize(
                    add_usize(
                        child.capture_traces.unavailable,
                        child.capture_traces.bits,
                        "repetition unavailable capture traces",
                    )?,
                    refused_all,
                    "repetition unavailable capture traces",
                )?,
                ordered: false,
            }
        };
        traces.validate(captures)?;
        Ok(traces)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one transaction derives every route-aware node envelope and its exact construction ledger"
    )]
    fn finish_measure_node(&mut self, node: &mut MeasureNode) -> Result<(), FactError> {
        node.capture_traces.validate(node.captures)?;
        if self.operation.requests_determinism() {
            if let Some(bound) = ordered_subset_bound(node.thompson_states) {
                self.max_deterministic_states = self.max_deterministic_states.max(bound);
            } else {
                self.max_deterministic_states = usize::MAX;
            }
        }
        node.logical_bytes_upper = measure_node_logical_upper(node, self.limits, self.operation)?;
        let trace_slots = mul_usize(
            node.captures,
            size_of::<CaptureTrace>(),
            "capture trace build slots",
        )?;
        let trace_words = capture_trace_build_words(*node)?;
        node.build_bytes_upper = add_usize(
            node.logical_bytes_upper,
            add_usize(
                trace_slots,
                mul_usize(trace_words, size_of::<u64>(), "capture trace build bytes")?,
                "capture trace build storage",
            )?,
            "node build bytes",
        )?;
        // The complete envelope materializes every independently bounded
        // proof and retains its historical, deliberately generous
        // per-node construction charge. Route-specific envelopes publish a
        // smaller fact surface; account for their actual node construction
        // rather than charging every node as a complete `HirFacts` value.
        // The root's `logical_bytes_upper` remains the full public value, so
        // retained-byte preflight stays exact for every envelope.
        let (build_work_multiplier, fixed_build_work) =
            if self.operation.uses_complete_proof_envelope() {
                (16, 512)
            } else {
                (1, 64)
            };
        node.own_build_work_upper = add_usize(
            node.own_build_work_upper,
            add_usize(
                mul_usize(
                    node.build_bytes_upper,
                    build_work_multiplier,
                    "per-node construction work upper bound",
                )?,
                add_usize(
                    fixed_build_work,
                    match node.finite {
                        Some(language) => mul_usize(
                            node.capture_traces.bits,
                            language.count,
                            "capture trace construction work",
                        )?,
                        None => 0,
                    },
                    "per-node construction work upper bound",
                )?,
                "per-node construction work upper bound",
            )?,
            "per-node construction work upper bound",
        )?;
        let retained_unicode_scalars = if self.operation.requests_unicode_scalar_alternatives()
            && node.unicode_scalars <= self.limits.max_finite_strings
            && node.unicode_bytes <= self.limits.max_finite_string_bytes
        {
            node.unicode_scalars
        } else {
            0
        };
        let finite_items = if self.operation.requests_finite_language() {
            node.finite.map_or(0, |language| language.count)
        } else {
            0
        };
        let required_items = if self.operation.requests_required_substrings() {
            add_usize(
                node.required.alternatives,
                node.required.groups,
                "per-node required fact items",
            )?
        } else {
            0
        };
        let assertion_items = if self.operation.requests_assertion_context() {
            add_usize(
                node.possible_assertions.count,
                node.required_assertions.count,
                "per-node assertion fact items",
            )?
        } else {
            0
        };
        let retained_items = finite_items
            .checked_add(required_items)
            .and_then(|value| value.checked_add(assertion_items))
            .and_then(|value| value.checked_add(node.captures))
            .and_then(|value| value.checked_add(retained_unicode_scalars))
            .ok_or(FactError::ArithmeticOverflow {
                computation: "per-node retained fact items",
            })?;
        let fixed_allocations = if self.operation.uses_complete_proof_envelope() {
            64
        } else {
            8
        };
        node.own_allocation_upper = add_usize(
            node.own_allocation_upper,
            add_usize(
                mul_usize(retained_items, 8, "per-node allocation upper bound")?,
                fixed_allocations,
                "per-node allocation upper bound",
            )?,
            "per-node allocation upper bound",
        )?;
        self.sum_node_bytes = add_usize(
            self.sum_node_bytes,
            node.build_bytes_upper,
            "sum of node fact bytes",
        )?;
        self.construction_work_upper = add_usize(
            self.construction_work_upper,
            node.own_build_work_upper,
            "total construction work upper bound",
        )?;
        self.construction_allocation_upper = add_usize(
            self.construction_allocation_upper,
            node.own_allocation_upper,
            "total construction allocation upper bound",
        )?;
        Ok(())
    }

    fn publish_leaf(&mut self, mut node: MeasureNode) -> Result<(), FactError> {
        self.finish_measure_node(&mut node)?;
        self.push_result(node)
    }

    fn push_task(&mut self, task: Task<'h>) -> Result<(), FactError> {
        let stack = self
            .tasks
            .len()
            .checked_add(self.results.len())
            .and_then(|value| value.checked_add(1))
            .ok_or(FactError::ArithmeticOverflow {
                computation: "census stack occupancy",
            })?;
        Self::check(FactResource::StackItems, stack, self.limits.max_stack_items)?;
        self.observe_census_storage(1, 0, 0)?;
        self.allocate("census task stack", 1)?;
        self.tasks
            .try_reserve_exact(1)
            .map_err(|_| FactError::AllocationFailed {
                structure: "census task stack",
                additional: 1,
            })?;
        self.tasks.push(task);
        self.peak_stack_items = self.peak_stack_items.max(stack);
        Ok(())
    }

    fn push_result(&mut self, node: MeasureNode) -> Result<(), FactError> {
        let stack = self
            .tasks
            .len()
            .checked_add(self.results.len())
            .and_then(|value| value.checked_add(1))
            .ok_or(FactError::ArithmeticOverflow {
                computation: "census result stack occupancy",
            })?;
        Self::check(FactResource::StackItems, stack, self.limits.max_stack_items)?;
        self.observe_census_storage(0, 1, 0)?;
        self.allocate("census result stack", 1)?;
        self.results
            .try_reserve_exact(1)
            .map_err(|_| FactError::AllocationFailed {
                structure: "census result stack",
                additional: 1,
            })?;
        self.results.push(node);
        self.live_build_bytes = add_usize(
            self.live_build_bytes,
            node.build_bytes_upper,
            "live prospective build bytes",
        )?;
        self.peak_build_bytes = self.peak_build_bytes.max(self.live_build_bytes);
        self.peak_stack_items = self.peak_stack_items.max(stack);
        Ok(())
    }

    fn take_children(&mut self, count: usize) -> Result<(Vec<MeasureNode>, usize), FactError> {
        if self.results.len() < count {
            return Err(FactError::InternalInvariant {
                detail: "census result stack underflow",
            });
        }
        let local_bytes = mul_usize(count, size_of::<MeasureNode>(), "census child bytes")?;
        self.observe_census_storage(0, 0, local_bytes)?;
        let mut children = self.measure_vector(count, "census child transfer")?;
        let mut build_bytes = 0_usize;
        for _ in 0..count {
            let child = self.results.pop().ok_or(FactError::InternalInvariant {
                detail: "census child disappeared",
            })?;
            build_bytes = add_usize(
                build_bytes,
                child.build_bytes_upper,
                "child prospective bytes",
            )?;
            children.push(child);
        }
        children.reverse();
        Ok((children, build_bytes))
    }

    fn publish_combined(
        &mut self,
        node: MeasureNode,
        child_bytes: usize,
        child_count: usize,
    ) -> Result<(), FactError> {
        let stack = self
            .tasks
            .len()
            .checked_add(self.results.len())
            .and_then(|value| value.checked_add(child_count))
            .and_then(|value| value.checked_add(1))
            .ok_or(FactError::ArithmeticOverflow {
                computation: "combined census stack occupancy",
            })?;
        Self::check(FactResource::StackItems, stack, self.limits.max_stack_items)?;
        self.peak_stack_items = self.peak_stack_items.max(stack);
        let scratch = mul_usize(node.build_bytes_upper, 2, "combined construction scratch")?;
        let child_slots = mul_usize(child_count, size_of::<NodeFacts>(), "combined child slots")?;
        let peak = self
            .live_build_bytes
            .checked_add(scratch)
            .and_then(|value| value.checked_add(child_slots))
            .ok_or(FactError::ArithmeticOverflow {
                computation: "combined prospective build bytes",
            })?;
        self.peak_build_bytes = self.peak_build_bytes.max(peak);
        self.push_result(node)?;
        self.live_build_bytes =
            self.live_build_bytes
                .checked_sub(child_bytes)
                .ok_or(FactError::InternalInvariant {
                    detail: "prospective child byte accounting underflowed",
                })?;
        Ok(())
    }

    fn measure_vector<T>(
        &mut self,
        count: usize,
        structure: &'static str,
    ) -> Result<Vec<T>, FactError> {
        let bytes = mul_usize(count, size_of::<T>(), "census local vector bytes")?;
        self.observe_census_storage(0, 0, bytes)?;
        let mut output = Vec::new();
        if count != 0 {
            self.allocate(structure, count)?;
            output
                .try_reserve_exact(count)
                .map_err(|_| FactError::AllocationFailed {
                    structure,
                    additional: count,
                })?;
        }
        Ok(output)
    }

    fn observe_census_storage(
        &mut self,
        extra_tasks: usize,
        extra_results: usize,
        local_bytes: usize,
    ) -> Result<(), FactError> {
        let task_bytes = mul_usize(
            add_usize(self.tasks.len(), extra_tasks, "census task slots")?,
            size_of::<Task<'h>>(),
            "census task bytes",
        )?;
        let result_bytes = mul_usize(
            add_usize(self.results.len(), extra_results, "census result slots")?,
            size_of::<MeasureNode>(),
            "census result bytes",
        )?;
        let temporary = task_bytes
            .checked_add(result_bytes)
            .and_then(|value| value.checked_add(local_bytes))
            .ok_or(FactError::ArithmeticOverflow {
                computation: "census temporary bytes",
            })?;
        Self::check(
            FactResource::TemporaryBytes,
            temporary,
            self.limits.max_temporary_bytes,
        )?;
        Self::check(
            FactResource::PeakBytes,
            temporary,
            self.limits.max_peak_bytes,
        )?;
        self.temporary_bytes = self.temporary_bytes.max(temporary);
        self.peak_bytes = self.peak_bytes.max(temporary);
        Ok(())
    }

    fn allocate(&mut self, _structure: &'static str, additional: usize) -> Result<(), FactError> {
        if additional == 0 {
            return Ok(());
        }
        let needed = add_usize(self.allocation_attempts, 1, "census allocation attempts")?;
        Self::check(
            FactResource::AllocationAttempts,
            needed,
            self.limits.max_allocation_attempts,
        )?;
        self.allocation_attempts = needed;
        self.charge(1)
    }

    fn charge(&mut self, amount: u64) -> Result<(), FactError> {
        let needed = self
            .work
            .checked_add(amount)
            .ok_or(FactError::ArithmeticOverflow {
                computation: "census work",
            })?;
        if needed > self.limits.max_work {
            return Err(FactError::ResourceLimit {
                resource: FactResource::Work,
                needed,
                limit: self.limits.max_work,
            });
        }
        self.work = needed;
        Ok(())
    }

    fn check(resource: FactResource, needed: usize, limit: usize) -> Result<(), FactError> {
        if needed > limit {
            return Err(FactError::ResourceLimit {
                resource,
                needed: to_u64(needed, "census resource need")?,
                limit: to_u64(limit, "census resource limit")?,
            });
        }
        Ok(())
    }
}

struct Analyzer<'h> {
    operation: FactOperation,
    limits: FactLimits,
    capture_trace_precision_enabled: bool,
    possible_contains_stream_end: bool,
    tasks: Vec<Task<'h>>,
    results: Vec<NodeFacts>,
    work: u64,
    hir_nodes: usize,
    peak_stack_items: usize,
    peak_temporary_bytes: usize,
    peak_bytes: usize,
    allocation_attempts: usize,
    live_result_bytes: usize,
    live_local_bytes: usize,
    prospective: FactProspective,
}

impl<'h> Analyzer<'h> {
    const fn new(operation: FactOperation, limits: FactLimits, census: CensusOutcome) -> Self {
        Self {
            operation,
            limits,
            capture_trace_precision_enabled: census.capture_trace_precision_enabled,
            possible_contains_stream_end: census.possible_contains_stream_end,
            tasks: Vec::new(),
            results: Vec::new(),
            work: census.census_work,
            hir_nodes: census.hir_nodes,
            peak_stack_items: census.census_peak_stack_items,
            peak_temporary_bytes: census.census_temporary_bytes,
            peak_bytes: census.census_peak_bytes,
            allocation_attempts: census.census_allocation_attempts,
            live_result_bytes: 0,
            live_local_bytes: 0,
            prospective: census.prospective,
        }
    }

    fn run(mut self, hir: &'h Hir) -> Result<HirFacts, FactError> {
        self.push_task(Task::Visit {
            hir,
            continuation: ContinuationContext::Terminal,
        })?;
        while let Some(task) = self.tasks.pop() {
            self.charge(1, "task dispatch")?;
            match task {
                Task::Visit { hir, continuation } => self.visit(hir, continuation)?,
                Task::FinishCapture { index, name } => {
                    let (mut children, child_bytes, transfer_bytes) = self.take_children(1)?;
                    let child = children.pop().ok_or(FactError::InternalInvariant {
                        detail: "capture finish lacked its child",
                    })?;
                    drop(children);
                    self.release_local_bytes(transfer_bytes)?;
                    let facts = if self.operation.erases_captures() {
                        child
                    } else {
                        self.finish_capture(child, index, name)?
                    };
                    self.publish_combined(facts, 1, child_bytes)?;
                }
                Task::FinishConcat(count) => {
                    let (children, child_bytes, transfer_bytes) = self.take_children(count)?;
                    let facts = self.finish_concat(children)?;
                    self.release_local_bytes(transfer_bytes)?;
                    self.publish_combined(facts, count, child_bytes)?;
                }
                Task::FinishAlternation {
                    count,
                    continuation,
                } => {
                    let (children, child_bytes, transfer_bytes) = self.take_children(count)?;
                    let facts = self.finish_alternation(children, continuation)?;
                    self.release_local_bytes(transfer_bytes)?;
                    self.publish_combined(facts, count, child_bytes)?;
                }
                Task::FinishRepetition {
                    min,
                    max,
                    greedy,
                    continuation,
                } => {
                    let (mut children, child_bytes, transfer_bytes) = self.take_children(1)?;
                    let child = children.pop().ok_or(FactError::InternalInvariant {
                        detail: "repetition finish lacked its child",
                    })?;
                    drop(children);
                    self.release_local_bytes(transfer_bytes)?;
                    let facts = self.finish_repetition(child, min, max, greedy, continuation)?;
                    self.publish_combined(facts, 1, child_bytes)?;
                }
            }
        }
        if self.results.len() != 1 {
            return Err(FactError::InternalInvariant {
                detail: "postorder HIR analysis did not produce one root",
            });
        }
        let root = self.results.pop().ok_or(FactError::InternalInvariant {
            detail: "root HIR facts disappeared",
        })?;
        self.finish_root(root)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "all HIR leaf publication rules remain adjacent for semantic and ledger auditability"
    )]
    fn visit(&mut self, hir: &'h Hir, continuation: ContinuationContext) -> Result<(), FactError> {
        self.charge(1, "HIR node visit")?;
        match hir.kind() {
            HirKind::Empty => {
                let finite = self.singleton_finite(&[], "empty finite language")?;
                self.push_result(NodeFacts {
                    width: CheckedWidth::NonEmpty {
                        minimum: 0,
                        maximum: Some(0),
                    },
                    finite,
                    required: self.empty_required(),
                    possible_assertions: self.empty_assertions(),
                    required_assertions: self.empty_assertions(),
                    captures: Vec::new(),
                    capture_traces: Vec::new(),
                    capture_trace_ordered: true,
                    unicode: UnicodeAccumulator::default(),
                    first: FirstBytes::empty(true),
                    one_pass_shape: true,
                    thompson_states: 1,
                    duplicate_consuming_alternatives: 0,
                })
            }
            HirKind::Literal(literal) => {
                let finite = self.singleton_finite(&literal.0, "finite literal bytes")?;
                let required = if literal.0.is_empty() {
                    self.empty_required()
                } else if self.operation.requests_required_substrings() {
                    let bytes = self.copy_bytes(&literal.0, "literal fact bytes")?;
                    self.singleton_required(bytes, StringEncoding::Bytes)?
                } else {
                    Self::not_requested()
                };
                let mut first = FirstBytes::empty(true);
                if let Some(&byte) = literal.0.first() {
                    first.insert(byte);
                }
                self.push_result(NodeFacts {
                    width: CheckedWidth::NonEmpty {
                        minimum: literal.0.len(),
                        maximum: Some(literal.0.len()),
                    },
                    finite,
                    required,
                    possible_assertions: self.empty_assertions(),
                    required_assertions: self.empty_assertions(),
                    captures: Vec::new(),
                    capture_traces: Vec::new(),
                    capture_trace_ordered: true,
                    unicode: UnicodeAccumulator::default(),
                    first,
                    one_pass_shape: true,
                    thompson_states: literal.0.len().max(1),
                    duplicate_consuming_alternatives: 0,
                })
            }
            HirKind::Class(Class::Bytes(class)) => self.visit_byte_class(class),
            HirKind::Class(Class::Unicode(class)) => self.visit_unicode_class(class),
            HirKind::Look(look) => {
                let positioned = PositionedAssertion {
                    look: *look,
                    context: BoundedContext::at_match(),
                };
                let possible = self.singleton_assertion(positioned)?;
                let required = self.singleton_assertion(positioned)?;
                let finite = self.singleton_finite(&[], "look finite language")?;
                self.push_result(NodeFacts {
                    width: CheckedWidth::NonEmpty {
                        minimum: 0,
                        maximum: Some(0),
                    },
                    finite,
                    required: self.empty_required(),
                    possible_assertions: possible,
                    required_assertions: required,
                    captures: Vec::new(),
                    capture_traces: Vec::new(),
                    capture_trace_ordered: true,
                    unicode: UnicodeAccumulator::default(),
                    first: FirstBytes::empty(true),
                    one_pass_shape: true,
                    thompson_states: 1,
                    duplicate_consuming_alternatives: 0,
                })
            }
            HirKind::Capture(capture) => {
                self.push_task(Task::FinishCapture {
                    index: capture.index,
                    name: capture.name.as_deref(),
                })?;
                self.push_task(Task::Visit {
                    hir: &capture.sub,
                    continuation,
                })
            }
            HirKind::Concat(parts) => {
                self.push_task(Task::FinishConcat(parts.len()))?;
                for (index, part) in parts.iter().enumerate().rev() {
                    self.push_task(Task::Visit {
                        hir: part,
                        continuation: if index == parts.len().saturating_sub(1) {
                            continuation
                        } else {
                            ContinuationContext::MayReject
                        },
                    })?;
                }
                Ok(())
            }
            HirKind::Alternation(branches) => {
                self.push_task(Task::FinishAlternation {
                    count: branches.len(),
                    continuation,
                })?;
                for branch in branches.iter().rev() {
                    self.push_task(Task::Visit {
                        hir: branch,
                        continuation,
                    })?;
                }
                Ok(())
            }
            HirKind::Repetition(repetition) => {
                self.push_task(Task::FinishRepetition {
                    min: repetition.min,
                    max: repetition.max,
                    greedy: repetition.greedy,
                    continuation,
                })?;
                self.push_task(Task::Visit {
                    hir: &repetition.sub,
                    continuation: if repetition.min == 1 && repetition.max == Some(1) {
                        continuation
                    } else {
                        ContinuationContext::MayReject
                    },
                })
            }
        }
    }

    fn push_task(&mut self, task: Task<'h>) -> Result<(), FactError> {
        let stack = add_usize(
            add_usize(self.tasks.len(), self.results.len(), "stack occupancy")?,
            1,
            "stack occupancy",
        )?;
        Self::check_hard(FactResource::StackItems, stack, self.limits.max_stack_items)?;
        self.observe_storage(0, 1, 0)?;
        self.allocation_request("HIR-fact task stack", 1)?;
        self.tasks
            .try_reserve_exact(1)
            .map_err(|_| FactError::AllocationFailed {
                structure: "HIR-fact task stack",
                additional: 1,
            })?;
        self.tasks.push(task);
        Ok(())
    }

    fn push_result(&mut self, facts: NodeFacts) -> Result<(), FactError> {
        let bytes = node_dynamic_bytes(&facts)?;
        let stack = add_usize(
            add_usize(self.tasks.len(), self.results.len(), "stack occupancy")?,
            1,
            "stack occupancy",
        )?;
        Self::check_hard(FactResource::StackItems, stack, self.limits.max_stack_items)?;
        self.live_local_bytes = 0;
        self.live_result_bytes = add_usize(self.live_result_bytes, bytes, "live fact bytes")?;
        self.observe_storage(0, 0, 1)?;
        self.allocation_request("HIR-fact result stack", 1)?;
        self.results
            .try_reserve_exact(1)
            .map_err(|_| FactError::AllocationFailed {
                structure: "HIR-fact result stack",
                additional: 1,
            })?;
        self.results.push(facts);
        self.peak_stack_items = self.peak_stack_items.max(stack);
        Ok(())
    }

    fn take_children(&mut self, count: usize) -> Result<(Vec<NodeFacts>, usize, usize), FactError> {
        if self.results.len() < count {
            return Err(FactError::InternalInvariant {
                detail: "finish task requested absent child facts",
            });
        }
        let transfer_bytes = mul_usize(
            count,
            size_of::<NodeFacts>(),
            "HIR-fact child transfer bytes",
        )?;
        self.acquire_local_bytes(transfer_bytes)?;
        self.allocation_request("HIR-fact child transfer", count)?;
        let mut children = Vec::new();
        children
            .try_reserve_exact(count)
            .map_err(|_| FactError::AllocationFailed {
                structure: "HIR-fact child transfer",
                additional: count,
            })?;
        let mut bytes = 0_usize;
        for _ in 0..count {
            let child = self.results.pop().ok_or(FactError::InternalInvariant {
                detail: "child fact stack underflow",
            })?;
            bytes = add_usize(bytes, node_dynamic_bytes(&child)?, "child fact bytes")?;
            children.push(child);
        }
        children.reverse();
        Ok((children, bytes, transfer_bytes))
    }

    fn publish_combined(
        &mut self,
        facts: NodeFacts,
        child_count: usize,
        child_bytes: usize,
    ) -> Result<(), FactError> {
        let bytes = node_dynamic_bytes(&facts)?;
        let stack = self
            .tasks
            .len()
            .checked_add(self.results.len())
            .and_then(|value| value.checked_add(child_count))
            .and_then(|value| value.checked_add(1))
            .ok_or(FactError::ArithmeticOverflow {
                computation: "combined stack occupancy",
            })?;
        Self::check_hard(FactResource::StackItems, stack, self.limits.max_stack_items)?;
        self.peak_stack_items = self.peak_stack_items.max(stack);
        self.live_local_bytes = 0;
        self.live_result_bytes = self
            .live_result_bytes
            .checked_add(bytes)
            .and_then(|value| value.checked_sub(child_bytes))
            .ok_or(FactError::InternalInvariant {
                detail: "combined live fact byte accounting underflowed",
            })?;
        self.observe_storage(0, 0, 1)?;
        self.allocation_request("HIR-fact result stack", 1)?;
        self.results
            .try_reserve_exact(1)
            .map_err(|_| FactError::AllocationFailed {
                structure: "HIR-fact result stack",
                additional: 1,
            })?;
        self.results.push(facts);
        Ok(())
    }

    fn observe_storage(
        &mut self,
        additional_fact_bytes: usize,
        additional_tasks: usize,
        additional_results: usize,
    ) -> Result<(), FactError> {
        let task_bytes = mul_usize(
            add_usize(self.tasks.len(), additional_tasks, "temporary task slots")?,
            size_of::<Task<'h>>(),
            "temporary task bytes",
        )?;
        let result_slot_bytes = mul_usize(
            add_usize(
                self.results.len(),
                additional_results,
                "temporary result slots",
            )?,
            size_of::<NodeFacts>(),
            "temporary result-slot bytes",
        )?;
        let result_bytes = self
            .live_result_bytes
            .checked_add(additional_fact_bytes)
            .and_then(|value| value.checked_add(result_slot_bytes))
            .ok_or(FactError::ArithmeticOverflow {
                computation: "temporary result bytes",
            })?;
        let temporary = task_bytes
            .checked_add(result_bytes)
            .and_then(|value| value.checked_add(self.live_local_bytes))
            .ok_or(FactError::ArithmeticOverflow {
                computation: "temporary analysis bytes",
            })?;
        Self::check_hard(
            FactResource::TemporaryBytes,
            temporary,
            self.limits.max_temporary_bytes,
        )?;
        self.peak_temporary_bytes = self.peak_temporary_bytes.max(temporary);
        self.peak_bytes = self.peak_bytes.max(temporary);
        Self::check_hard(
            FactResource::PeakBytes,
            self.peak_bytes,
            self.limits.max_peak_bytes,
        )
    }

    fn acquire_local_bytes(&mut self, bytes: usize) -> Result<(), FactError> {
        if bytes == 0 {
            return Ok(());
        }
        let previous = self.live_local_bytes;
        self.live_local_bytes = add_usize(previous, bytes, "live local construction bytes")?;
        if let Err(error) = self.observe_storage(0, 0, 0) {
            self.live_local_bytes = previous;
            return Err(error);
        }
        Ok(())
    }

    fn release_local_bytes(&mut self, bytes: usize) -> Result<(), FactError> {
        self.live_local_bytes =
            self.live_local_bytes
                .checked_sub(bytes)
                .ok_or(FactError::InternalInvariant {
                    detail: "live local construction byte accounting underflowed",
                })?;
        Ok(())
    }

    fn charge(&mut self, amount: u64, _phase: &'static str) -> Result<(), FactError> {
        let needed = self
            .work
            .checked_add(amount)
            .ok_or(FactError::ArithmeticOverflow {
                computation: "HIR-fact work",
            })?;
        if needed > self.limits.max_work {
            return Err(FactError::ResourceLimit {
                resource: FactResource::Work,
                needed,
                limit: self.limits.max_work,
            });
        }
        self.work = needed;
        Ok(())
    }

    fn charge_usize(&mut self, amount: usize, phase: &'static str) -> Result<(), FactError> {
        self.charge(to_u64(amount, "work conversion")?, phase)
    }

    fn allocation_request(
        &mut self,
        _structure: &'static str,
        additional: usize,
    ) -> Result<(), FactError> {
        if additional == 0 {
            return Ok(());
        }
        let needed = add_usize(self.allocation_attempts, 1, "allocation request count")?;
        Self::check_hard(
            FactResource::AllocationAttempts,
            needed,
            self.limits.max_allocation_attempts,
        )?;
        self.allocation_attempts = needed;
        self.charge(1, "fallible allocation request")
    }

    fn check_hard(resource: FactResource, needed: usize, limit: usize) -> Result<(), FactError> {
        if needed > limit {
            return Err(FactError::ResourceLimit {
                resource,
                needed: to_u64(needed, "resource need conversion")?,
                limit: to_u64(limit, "resource limit conversion")?,
            });
        }
        Ok(())
    }

    fn refusal(
        resource: FactResource,
        needed: usize,
        limit: usize,
    ) -> Result<FactRefusal, FactError> {
        Ok(FactRefusal::Limit {
            resource,
            needed: to_u64(needed, "proof resource need conversion")?,
            limit: to_u64(limit, "proof resource limit conversion")?,
        })
    }
}

impl Analyzer<'_> {
    fn visit_byte_class(&mut self, class: &regex_syntax::hir::ClassBytes) -> Result<(), FactError> {
        let mut count = 0_usize;
        let mut first = FirstBytes::empty(true);
        for range in class.ranges() {
            let width = usize::from(range.end())
                .checked_sub(usize::from(range.start()))
                .and_then(|value| value.checked_add(1))
                .ok_or(FactError::ArithmeticOverflow {
                    computation: "byte-class cardinality",
                })?;
            count = add_usize(count, width, "byte-class cardinality")?;
            self.charge_usize(add_usize(width, 1, "byte-class work")?, "byte-class census")?;
            for byte in range.start()..=range.end() {
                first.insert(byte);
            }
        }
        if count == 0 {
            let finite = self.empty_finite()?;
            return self.push_result(NodeFacts {
                width: CheckedWidth::EmptyLanguage,
                finite,
                required: self.empty_required(),
                possible_assertions: self.empty_assertions(),
                required_assertions: self.empty_assertions(),
                captures: Vec::new(),
                capture_traces: Vec::new(),
                capture_trace_ordered: true,
                unicode: UnicodeAccumulator::default(),
                first,
                one_pass_shape: true,
                thompson_states: 1,
                duplicate_consuming_alternatives: 0,
            });
        }
        let finite = self.byte_class_language(class, count)?;
        let required = self.byte_class_required(class, count)?;
        self.push_result(NodeFacts {
            width: CheckedWidth::NonEmpty {
                minimum: 1,
                maximum: Some(1),
            },
            finite,
            required,
            possible_assertions: self.empty_assertions(),
            required_assertions: self.empty_assertions(),
            captures: Vec::new(),
            capture_traces: Vec::new(),
            capture_trace_ordered: true,
            unicode: UnicodeAccumulator::default(),
            first,
            one_pass_shape: true,
            thompson_states: 1,
            duplicate_consuming_alternatives: 0,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "Unicode scalar facts and their metered UTF-8 expansion share one bounded traversal"
    )]
    fn visit_unicode_class(
        &mut self,
        class: &regex_syntax::hir::ClassUnicode,
    ) -> Result<(), FactError> {
        // `unicode_class_metrics` performs five fixed logical operations per
        // range. Precharge the complete helper traversal before it scans.
        let metric_work = mul_usize(class.ranges().len(), 5, "Unicode analysis metric work")?;
        self.charge_usize(metric_work, "Unicode analysis metric precharge")?;
        let (scalar_count, total_bytes) = unicode_class_metrics(class)?;
        let mut minimum = usize::MAX;
        let mut maximum = 0_usize;
        let mut utf8_width_mask = 0_u8;
        let mut contains_non_ascii = false;
        let mut first = FirstBytes::empty(self.operation.requests_determinism());
        let mut seen_sequence_first = FirstBytes::empty(self.operation.requests_determinism());
        let mut one_pass_shape = self.operation.requests_determinism();
        // See the matching census rule: when no determinism proof is
        // requested, retain a coarse structural bound without constructing
        // the scalar-to-UTF-8 sequence partition.
        let mut thompson_states = if self.operation.requests_determinism() {
            1
        } else {
            add_usize(
                mul_usize(scalar_count, 5, "coarse Unicode analysis states")?,
                1,
                "coarse Unicode analysis states",
            )?
        };
        for range in class.ranges() {
            self.charge(1, "Unicode scalar range census")?;
            let start_width = range.start().len_utf8();
            let end_width = range.end().len_utf8();
            minimum = minimum.min(start_width);
            maximum = maximum.max(end_width);
            for width in start_width..=end_width {
                let width_bit = match width {
                    1 => 0b0001,
                    2 => 0b0010,
                    3 => 0b0100,
                    4 => 0b1000,
                    _ => {
                        return Err(FactError::InternalInvariant {
                            detail: "Unicode scalar had an invalid UTF-8 width",
                        });
                    }
                };
                utf8_width_mask |= width_bit;
            }
            contains_non_ascii |= !range.end().is_ascii();
            if self.operation.requests_determinism() {
                for sequence in Utf8Sequences::new(range.start(), range.end()) {
                    self.charge(1, "UTF-8 sequence census")?;
                    let mut sequence_first = FirstBytes::empty(true);
                    if let Some(range) = sequence.as_slice().first() {
                        for byte in range.start..=range.end {
                            first.insert(byte);
                            sequence_first.insert(byte);
                        }
                    } else {
                        one_pass_shape = false;
                    }
                    one_pass_shape &=
                        seen_sequence_first.disjoint(sequence_first) && sequence_first.complete;
                    seen_sequence_first.union(sequence_first);
                    let branch = add_usize(sequence.len(), 1, "Unicode branch states")?;
                    thompson_states =
                        add_usize(thompson_states, branch, "Unicode Thompson states")?;
                }
            }
        }
        if scalar_count == 0 {
            let finite = self.empty_finite()?;
            return self.push_result(NodeFacts {
                width: CheckedWidth::EmptyLanguage,
                finite,
                required: self.empty_required(),
                possible_assertions: self.empty_assertions(),
                required_assertions: self.empty_assertions(),
                captures: Vec::new(),
                capture_traces: Vec::new(),
                capture_trace_ordered: true,
                unicode: UnicodeAccumulator {
                    class_count: 1,
                    scalar_range_count: class.ranges().len(),
                    scalar_count: 0,
                    utf8_width_mask: 0,
                    contains_non_ascii: false,
                    width_changing_alternatives: false,
                    scalar_strings: self
                        .operation
                        .requests_unicode_scalar_alternatives()
                        .then(Vec::new),
                    scalar_refusal: if self.operation.requests_unicode_scalar_alternatives() {
                        None
                    } else {
                        Some(FactRefusal::NotRequested)
                    },
                },
                first,
                one_pass_shape,
                thompson_states,
                duplicate_consuming_alternatives: 0,
            });
        }
        let finite = self.unicode_class_language(class, scalar_count, total_bytes)?;
        let required = self.unicode_class_required(class, scalar_count, total_bytes)?;
        let (scalar_strings, scalar_refusal) = if self
            .operation
            .requests_unicode_scalar_alternatives()
        {
            match &finite {
                FactProof::Proven(language) => (
                    Some(
                        self.copy_string_list(
                            &language.strings,
                            "Unicode scalar fact alternatives",
                        )?,
                    ),
                    None,
                ),
                FactProof::Refused(refusal) => (None, Some(*refusal)),
                FactProof::Unknown => (None, None),
            }
        } else {
            (None, Some(FactRefusal::NotRequested))
        };
        self.push_result(NodeFacts {
            width: CheckedWidth::NonEmpty {
                minimum,
                maximum: Some(maximum),
            },
            finite,
            required,
            possible_assertions: self.empty_assertions(),
            required_assertions: self.empty_assertions(),
            captures: Vec::new(),
            capture_traces: Vec::new(),
            capture_trace_ordered: true,
            unicode: UnicodeAccumulator {
                class_count: 1,
                scalar_range_count: class.ranges().len(),
                scalar_count,
                utf8_width_mask,
                contains_non_ascii,
                width_changing_alternatives: minimum != maximum,
                scalar_strings,
                scalar_refusal,
            },
            first,
            one_pass_shape,
            thompson_states,
            duplicate_consuming_alternatives: 0,
        })
    }

    fn finish_capture(
        &mut self,
        mut child: NodeFacts,
        index: u32,
        name: Option<&str>,
    ) -> Result<NodeFacts, FactError> {
        let name = match name {
            Some(name) => Some(self.copy_string(name, "capture name")?),
            None => None,
        };
        self.acquire_local_bytes(size_of::<PositionedCapture>())?;
        self.allocation_request("capture fact list", 1)?;
        child
            .captures
            .try_reserve_exact(1)
            .map_err(|_| FactError::AllocationFailed {
                structure: "capture fact list",
                additional: 1,
            })?;
        self.charge_usize(child.captures.len(), "nested capture order insertion")?;
        child.captures.insert(
            0,
            PositionedCapture {
                index,
                name,
                context: BoundedContext::at_match(),
                participation: if child.width.is_empty_language() {
                    CaptureParticipation::Never
                } else {
                    CaptureParticipation::Always
                },
            },
        );
        self.acquire_local_bytes(size_of::<CaptureTrace>())?;
        self.allocation_request("capture trace list", 1)?;
        child
            .capture_traces
            .try_reserve_exact(1)
            .map_err(|_| FactError::AllocationFailed {
                structure: "capture trace list",
                additional: 1,
            })?;
        child.capture_traces.insert(
            0,
            if child.width.is_empty_language() {
                CaptureTrace::None
            } else {
                CaptureTrace::All
            },
        );
        if let FactProof::Proven(language) = &child.finite {
            if !self.capture_trace_storage_allowed(child.capture_traces.len(), language) {
                for trace in &mut child.capture_traces {
                    if matches!(trace, CaptureTrace::Bits(_)) {
                        *trace = CaptureTrace::Unavailable;
                    }
                }
            }
        }
        child.thompson_states = add_usize(child.thompson_states, 1, "capture Thompson states")?;
        Ok(child)
    }

    fn finish_concat(&mut self, children: Vec<NodeFacts>) -> Result<NodeFacts, FactError> {
        if children.iter().any(|child| child.width.is_empty_language()) {
            return self.empty_composite(children, true);
        }
        let count = children.len();
        let mut prefixes = self.width_vector(count, "concatenation prefix widths")?;
        let mut suffixes = self.width_vector(count, "concatenation suffix widths")?;
        let mut prefix = WidthRange::exact(0);
        for (index, child) in children.iter().enumerate() {
            prefixes[index] = prefix;
            prefix = add_width_range(prefix, width_range(child.width)?)?;
        }
        let width = CheckedWidth::NonEmpty {
            minimum: prefix.minimum,
            maximum: prefix.maximum,
        };
        let mut suffix = WidthRange::exact(0);
        for (index, child) in children.iter().enumerate().rev() {
            suffixes[index] = suffix;
            suffix = add_width_range(suffix, width_range(child.width)?)?;
        }
        let finite = self.concat_finite(&children)?;
        let capture_trace_ordered = children.iter().all(|child| child.capture_trace_ordered);
        let capture_traces = self.concat_capture_traces(&children, &finite)?;
        let required = self.concat_required(&children, &prefixes, &suffixes)?;
        let possible_assertions = self.concat_assertions(&children, &prefixes, &suffixes, false)?;
        let required_assertions = self.concat_assertions(&children, &prefixes, &suffixes, true)?;
        let captures = self.concat_captures(&children, &prefixes, &suffixes)?;
        let unicode = self.merge_unicode(children.iter().map(|child| &child.unicode))?;
        let first = concat_first(&children);
        let one_pass_shape = children.iter().all(|child| child.one_pass_shape)
            && children.iter().all(|child| child.width.exact().is_some());
        let mut thompson_states = add_usize(count, 1, "concat structural states")?;
        let mut duplicates = 0_usize;
        for child in &children {
            thompson_states = add_usize(
                thompson_states,
                child.thompson_states,
                "concat Thompson states",
            )?;
            duplicates = add_usize(
                duplicates,
                child.duplicate_consuming_alternatives,
                "concat duplicate alternatives",
            )?;
        }
        let facts = NodeFacts {
            width,
            finite,
            required,
            possible_assertions,
            required_assertions,
            captures,
            capture_traces,
            capture_trace_ordered,
            unicode,
            first,
            one_pass_shape,
            thompson_states,
            duplicate_consuming_alternatives: duplicates,
        };
        self.release_local_bytes(mul_usize(
            mul_usize(count, 2, "concatenation width scratch items")?,
            size_of::<WidthRange>(),
            "concatenation width scratch bytes",
        )?)?;
        Ok(facts)
    }

    fn finish_alternation(
        &mut self,
        children: Vec<NodeFacts>,
        continuation: ContinuationContext,
    ) -> Result<NodeFacts, FactError> {
        let possible_count = children
            .iter()
            .filter(|child| !child.width.is_empty_language())
            .count();
        let mut possible = self.vector(possible_count, "possible alternation branches")?;
        for child in &children {
            if !child.width.is_empty_language() {
                possible.push(child);
            }
        }
        if possible.is_empty() {
            return self.empty_composite(children, false);
        }
        let mut minimum = usize::MAX;
        let mut maximum = Some(0_usize);
        for child in &possible {
            let CheckedWidth::NonEmpty {
                minimum: child_minimum,
                maximum: child_maximum,
            } = child.width
            else {
                continue;
            };
            minimum = minimum.min(child_minimum);
            maximum = match (maximum, child_maximum) {
                (Some(left), Some(right)) => Some(left.max(right)),
                _ => None,
            };
        }
        let finite = self.alternation_finite(&possible)?;
        let capture_trace_ordered = children.iter().all(|child| child.capture_trace_ordered);
        let capture_traces = self.alternation_capture_traces(&children, &finite)?;
        let required = self.alternation_required(&possible)?;
        let possible_assertions = self.alternation_possible_assertions(&possible)?;
        let required_assertions = self.alternation_required_assertions(&possible)?;
        let captures = self.alternation_captures(&children, continuation)?;
        let unicode = self.merge_unicode(possible.iter().map(|child| &child.unicode))?;
        let mut first = FirstBytes::empty(true);
        let mut disjoint = true;
        let mut seen = FirstBytes::empty(true);
        for child in &possible {
            disjoint &= child.first.complete && seen.disjoint(child.first);
            seen.union(child.first);
            first.union(child.first);
        }
        let one_pass_shape = disjoint
            && possible.iter().all(|child| {
                child.one_pass_shape && !child.width.is_nullable() && child.first.complete
            });
        let mut thompson_states = add_usize(
            mul_usize(children.len(), 2, "alternation states")?,
            1,
            "alternation states",
        )?;
        let mut duplicates = 0_usize;
        for child in &children {
            thompson_states = add_usize(
                thompson_states,
                child.thompson_states,
                "alternation Thompson states",
            )?;
            duplicates = add_usize(
                duplicates,
                child.duplicate_consuming_alternatives,
                "alternation duplicates",
            )?;
        }
        let facts = NodeFacts {
            width: CheckedWidth::NonEmpty { minimum, maximum },
            finite,
            required,
            possible_assertions,
            required_assertions,
            captures,
            capture_traces,
            capture_trace_ordered,
            unicode,
            first,
            one_pass_shape,
            thompson_states,
            duplicate_consuming_alternatives: duplicates,
        };
        self.release_local_bytes(mul_usize(
            possible_count,
            size_of::<&NodeFacts>(),
            "possible alternation scratch bytes",
        )?)?;
        Ok(facts)
    }

    fn finish_repetition(
        &mut self,
        child: NodeFacts,
        min: u32,
        max: Option<u32>,
        greedy: bool,
        continuation: ContinuationContext,
    ) -> Result<NodeFacts, FactError> {
        let width = repeat_width(child.width, min, max)?;
        if width.is_empty_language() {
            let mut children = self.vector(1, "empty repeated child")?;
            children.push(child);
            let facts = self.empty_composite(children, false)?;
            self.release_local_bytes(size_of::<NodeFacts>())?;
            return Ok(facts);
        }
        let finite = self.repeat_finite(&child.finite, min, max, greedy)?;
        let remaining_min = min.saturating_sub(1);
        let remaining_max = max.map(|value| value.saturating_sub(1));
        let tail = repeat_width(child.width, remaining_min, remaining_max)?;
        let tail = if tail.is_empty_language() {
            WidthRange::exact(0)
        } else {
            width_range(tail)?
        };
        let required = if min == 0 {
            self.empty_required()
        } else {
            self.shift_required(&child.required, WidthRange::exact(0), tail)?
        };
        let possible_assertions =
            self.repeat_assertions(&child.possible_assertions, child.width, max, false)?;
        let required_assertions = if min == 0 {
            self.empty_assertions()
        } else {
            self.shift_assertions(&child.required_assertions, WidthRange::exact(0), tail)?
        };
        let captures =
            self.repeat_captures(&child.captures, child.width, min, max, continuation)?;
        let capture_traces =
            self.repeat_capture_traces(&child.capture_traces, &finite, min, max)?;
        let capture_trace_ordered =
            max == Some(0) || (min == 1 && max == Some(1) && child.capture_trace_ordered);
        let first = if max == Some(0) {
            FirstBytes::empty(true)
        } else {
            child.first
        };
        let fixed_count = max == Some(min);
        let one_pass_shape = child.one_pass_shape && child.width.exact().is_some() && fixed_count;
        let copies = usize::try_from(match max {
            Some(maximum) => maximum,
            None => min.saturating_add(1),
        })
        .map_err(|_| FactError::ArithmeticOverflow {
            computation: "repeat Thompson copy count",
        })?;
        let thompson_states = add_usize(
            mul_usize(
                copies,
                add_usize(child.thompson_states, 2, "repeat per-copy states")?,
                "repeat Thompson states",
            )?,
            1,
            "repeat Thompson states",
        )?;
        Ok(NodeFacts {
            width,
            finite,
            required,
            possible_assertions,
            required_assertions,
            captures,
            capture_traces,
            capture_trace_ordered,
            unicode: child.unicode,
            first,
            one_pass_shape,
            thompson_states,
            duplicate_consuming_alternatives: child.duplicate_consuming_alternatives,
        })
    }
}

fn to_u64(value: usize, computation: &'static str) -> Result<u64, FactError> {
    u64::try_from(value).map_err(|_| FactError::ArithmeticOverflow { computation })
}

fn add_usize(left: usize, right: usize, computation: &'static str) -> Result<usize, FactError> {
    left.checked_add(right)
        .ok_or(FactError::ArithmeticOverflow { computation })
}

fn mul_usize(left: usize, right: usize, computation: &'static str) -> Result<usize, FactError> {
    left.checked_mul(right)
        .ok_or(FactError::ArithmeticOverflow { computation })
}

fn scalar_range_count(start: u32, end: u32) -> Option<u32> {
    let raw = end.checked_sub(start)?.checked_add(1)?;
    let surrogate_start = start.max(0xD800);
    let surrogate_end = end.min(0xDFFF);
    let surrogates = if surrogate_start <= surrogate_end {
        surrogate_end.checked_sub(surrogate_start)?.checked_add(1)?
    } else {
        0
    };
    raw.checked_sub(surrogates)
}

fn unicode_class_metrics(
    class: &regex_syntax::hir::ClassUnicode,
) -> Result<(usize, usize), FactError> {
    let mut count = 0_usize;
    let mut bytes = 0_usize;
    for range in class.ranges() {
        let start = u32::from(range.start());
        let end = u32::from(range.end());
        let range_count = scalar_range_count(start, end).ok_or(FactError::ArithmeticOverflow {
            computation: "Unicode scalar range count",
        })?;
        count = add_usize(
            count,
            usize::try_from(range_count).map_err(|_| FactError::ArithmeticOverflow {
                computation: "Unicode scalar count conversion",
            })?,
            "Unicode scalar count",
        )?;
        for (width_start, width_end, width) in [
            (0_u32, 0x7F_u32, 1_usize),
            (0x80, 0x7FF, 2),
            (0x800, 0xFFFF, 3),
            (0x1_0000, 0x10_FFFF, 4),
        ] {
            let intersection_start = start.max(width_start);
            let intersection_end = end.min(width_end);
            if intersection_start > intersection_end {
                continue;
            }
            let scalars = scalar_range_count(intersection_start, intersection_end).ok_or(
                FactError::ArithmeticOverflow {
                    computation: "Unicode width partition count",
                },
            )?;
            let partition_bytes = mul_usize(
                usize::try_from(scalars).map_err(|_| FactError::ArithmeticOverflow {
                    computation: "Unicode width count conversion",
                })?,
                width,
                "Unicode width partition bytes",
            )?;
            bytes = add_usize(bytes, partition_bytes, "Unicode class bytes")?;
        }
    }
    Ok((count, bytes))
}

fn unicode_class_width(class: &regex_syntax::hir::ClassUnicode) -> CheckedWidth {
    let Some(first) = class.ranges().first() else {
        return CheckedWidth::EmptyLanguage;
    };
    let mut minimum = first.start().len_utf8();
    let mut maximum = first.end().len_utf8();
    for range in class.ranges().iter().skip(1) {
        minimum = minimum.min(range.start().len_utf8());
        maximum = maximum.max(range.end().len_utf8());
    }
    CheckedWidth::NonEmpty {
        minimum,
        maximum: Some(maximum),
    }
}

fn width_range(width: CheckedWidth) -> Result<WidthRange, FactError> {
    match width {
        CheckedWidth::EmptyLanguage => Err(FactError::InternalInvariant {
            detail: "empty language has no match-relative width range",
        }),
        CheckedWidth::NonEmpty { minimum, maximum } => Ok(WidthRange { minimum, maximum }),
    }
}

fn add_width_range(left: WidthRange, right: WidthRange) -> Result<WidthRange, FactError> {
    Ok(WidthRange {
        minimum: add_usize(left.minimum, right.minimum, "minimum width sum")?,
        maximum: match (left.maximum, right.maximum) {
            (Some(left), Some(right)) => Some(add_usize(left, right, "maximum width sum")?),
            _ => None,
        },
    })
}

fn repeat_width(
    child: CheckedWidth,
    min: u32,
    max: Option<u32>,
) -> Result<CheckedWidth, FactError> {
    match child {
        CheckedWidth::EmptyLanguage if min == 0 => Ok(CheckedWidth::NonEmpty {
            minimum: 0,
            maximum: Some(0),
        }),
        CheckedWidth::EmptyLanguage => Ok(CheckedWidth::EmptyLanguage),
        CheckedWidth::NonEmpty { minimum, maximum } => {
            let minimum = mul_usize(
                minimum,
                usize::try_from(min).map_err(|_| FactError::ArithmeticOverflow {
                    computation: "minimum repeat conversion",
                })?,
                "minimum repeat width",
            )?;
            let maximum = match max {
                Some(maximum_count) => {
                    let count = usize::try_from(maximum_count).map_err(|_| {
                        FactError::ArithmeticOverflow {
                            computation: "maximum repeat conversion",
                        }
                    })?;
                    match maximum {
                        Some(maximum) => Some(mul_usize(maximum, count, "maximum repeat width")?),
                        None if count == 0 => Some(0),
                        None => None,
                    }
                }
                None => {
                    if maximum == Some(0) {
                        Some(0)
                    } else {
                        None
                    }
                }
            };
            Ok(CheckedWidth::NonEmpty { minimum, maximum })
        }
    }
}

fn repetition_displacement(child: CheckedWidth, max: Option<u32>) -> Result<WidthRange, FactError> {
    if child.is_empty_language() {
        return Ok(WidthRange::exact(0));
    }
    let child = width_range(child)?;
    let maximum_copies = max.map(|value| value.saturating_sub(1));
    Ok(WidthRange {
        minimum: 0,
        maximum: match (child.maximum, maximum_copies) {
            (_, Some(0)) => Some(0),
            (Some(width), Some(copies)) => Some(mul_usize(
                width,
                usize::try_from(copies).map_err(|_| FactError::ArithmeticOverflow {
                    computation: "repetition displacement conversion",
                })?,
                "repetition displacement",
            )?),
            _ => None,
        },
    })
}

fn shift_context(
    context: BoundedContext,
    prefix: WidthRange,
    suffix: WidthRange,
) -> Result<BoundedContext, FactError> {
    Ok(BoundedContext {
        before: add_width_range(prefix, context.before)?,
        after: add_width_range(context.after, suffix)?,
    })
}

fn concat_first(children: &[NodeFacts]) -> FirstBytes {
    let mut first = FirstBytes::empty(true);
    for child in children {
        first.union(child.first);
        if !child.width.is_nullable() {
            break;
        }
    }
    first
}

fn select_required_group(groups: &[RequiredAlternatives]) -> Option<&RequiredAlternatives> {
    groups.iter().max_by_key(|group| {
        group
            .alternatives
            .iter()
            .map(|alternative| alternative.bytes.len())
            .min()
            .unwrap_or(0)
    })
}

fn measure_concat_language(
    left: Option<LanguageMeasure>,
    right: Option<LanguageMeasure>,
) -> Option<LanguageMeasure> {
    let (left, right) = (left?, right?);
    let count = left.count.checked_mul(right.count)?;
    let bytes = left
        .bytes
        .checked_mul(right.count)?
        .checked_add(right.bytes.checked_mul(left.count)?)?;
    Some(LanguageMeasure { count, bytes })
}

fn measure_alternation_language(
    left: Option<LanguageMeasure>,
    right: Option<LanguageMeasure>,
) -> Option<LanguageMeasure> {
    let (left, right) = (left?, right?);
    Some(LanguageMeasure {
        count: left.count.checked_add(right.count)?,
        bytes: left.bytes.checked_add(right.bytes)?,
    })
}

fn capture_priority_work_bound(
    children: &[MeasureNode],
    continuation: ContinuationContext,
) -> Result<usize, FactError> {
    if children.iter().all(|child| child.captures == 0) {
        return Ok(0);
    }
    if continuation == ContinuationContext::MayReject {
        return Ok(children.len());
    }
    let mut work = 0_usize;
    let mut finite_predecessor_count = 0_usize;
    let mut finite_predecessor_bytes = 0_usize;
    for (index, child) in children.iter().enumerate() {
        if let Some(candidate) = child.finite {
            // Construction visits every candidate once and every earlier
            // branch once per candidate, even when that predecessor lacks a
            // finite proof. Finite predecessors can additionally cause one
            // length probe and at most every predecessor byte to be read.
            let candidate_visits = candidate.count;
            let predecessor_visits = mul_usize(
                candidate.count,
                index,
                "capture-priority predecessor visits",
            )?;
            let prefix_lengths = mul_usize(
                candidate.count,
                finite_predecessor_count,
                "capture-priority prefix lengths",
            )?;
            let prefix_bytes = mul_usize(
                candidate.count,
                finite_predecessor_bytes,
                "capture-priority prefix bytes",
            )?;
            work = add_usize(
                work,
                add_usize(
                    add_usize(
                        candidate_visits,
                        predecessor_visits,
                        "capture-priority traversal work",
                    )?,
                    add_usize(
                        prefix_lengths,
                        prefix_bytes,
                        "capture-priority comparison work",
                    )?,
                    "capture-priority candidate work",
                )?,
                "capture-priority work",
            )?;
            finite_predecessor_count = add_usize(
                finite_predecessor_count,
                candidate.count,
                "capture-priority finite predecessor strings",
            )?;
            finite_predecessor_bytes = add_usize(
                finite_predecessor_bytes,
                candidate.bytes,
                "capture-priority finite predecessor bytes",
            )?;
        }
    }
    Ok(work)
}

fn root_capture_trace_work_bound(root: MeasureNode) -> Option<usize> {
    let Some(language) = root.finite else {
        return Some(0);
    };
    if root.captures == 0
        || !root.capture_traces.ordered
        || root.capture_traces.bits == 0
        || !root.possible_assertions.proven
        || root.possible_assertions.count != 0
    {
        return Some(0);
    }
    capture_trace_priority_work_bound(root.captures, language)
}

/// Upper-bound the root selector before admitting private capture traces.
///
/// This intentionally models the more expensive substring selector used by
/// meta-style root searches as well as the ordinary source-priority selector.
/// Every intermediate is checked: inability to represent this optional work
/// means precision is unavailable, never that fact construction has failed.
fn capture_trace_priority_work_bound(captures: usize, language: LanguageMeasure) -> Option<usize> {
    if captures == 0 {
        return Some(0);
    }
    let predecessors = language.count.saturating_sub(1);
    // Divide the even operand before multiplying so a representable
    // triangular count is not rejected because of an intermediate product.
    let triangular_pairs = if language.count % 2 == 0 {
        language.count.checked_div(2)?.checked_mul(predecessors)?
    } else {
        language.count.checked_mul(predecessors.checked_div(2)?)?
    };
    // The ordinary source-priority selector can inspect every ordered pair,
    // while the reverse-suffix selector can inspect every row at every byte
    // boundary. Keep both envelopes in the shared admission bound.
    let ordered_pairs = triangular_pairs
        .checked_mul(2)?
        .checked_add(language.count)?;
    let relation_probes = ordered_pairs.checked_mul(2)?;
    let offset_probes = language.count.checked_mul(language.bytes)?;
    let byte_probes = language.bytes.checked_mul(language.bytes)?.checked_mul(2)?;
    let classification = language.count.checked_mul(captures)?;
    // The certificate compares each trace slot once and can read a `Bits`
    // slot twice (pivot and candidate), so reserve three visits per row and
    // capture in addition to the structural byte checks below.
    let certificate_per_capture = language
        .count
        .checked_mul(3)?
        .checked_add(language.bytes)?
        .checked_add(language.bytes.checked_mul(language.bytes)?)?;
    let certificate = captures.checked_mul(certificate_per_capture)?;
    // A distinct-signature long row can inspect every candidate as a
    // potential longer internal reverse endpoint. Reserve a row visit and
    // endpoint probe per pair, plus all candidate bytes per long row.
    let internal_endpoint_guard = language
        .count
        .checked_mul(language.count.checked_mul(2)?.checked_add(language.bytes)?)?;
    captures
        .checked_add(language.count)?
        .checked_add(relation_probes)?
        .checked_add(offset_probes)?
        .checked_add(byte_probes)?
        .checked_add(classification)?
        .checked_add(certificate)?
        .checked_add(internal_endpoint_guard)
}

fn capture_trace_build_words(node: MeasureNode) -> Result<usize, FactError> {
    match (node.capture_traces.bits, node.finite) {
        (0, _) => Ok(0),
        (bits, Some(language)) => mul_usize(
            bits,
            capture_trace_word_count(language.count)?,
            "capture trace build words",
        ),
        (_, None) => Err(FactError::InternalInvariant {
            detail: "capture trace Bits census lacked a finite language",
        }),
    }
}

fn alternation_assertion_work_bound(children: &[MeasureNode]) -> Result<usize, FactError> {
    let possible_publication = children.iter().try_fold(0_usize, |work, child| {
        add_usize(
            work,
            child.possible_assertions.count,
            "alternation possible assertion work",
        )
    })?;
    let Some(first) = children.first() else {
        return Ok(possible_publication);
    };
    if !first.required_assertions.proven
        || children
            .iter()
            .skip(1)
            .any(|child| !child.required_assertions.proven)
    {
        return Ok(possible_publication);
    }
    let other_assertions = children.iter().skip(1).try_fold(0_usize, |work, child| {
        add_usize(
            work,
            child.required_assertions.count,
            "alternation required assertion work",
        )
    })?;
    let comparisons = mul_usize(
        mul_usize(
            first.required_assertions.count,
            other_assertions,
            "alternation required assertion comparisons",
        )?,
        2,
        "alternation repeated assertion comparisons",
    )?;
    let candidates_and_publication = mul_usize(
        first.required_assertions.count,
        3,
        "alternation required assertion publication",
    )?;
    add_usize(
        possible_publication,
        add_usize(
            comparisons,
            candidates_and_publication,
            "alternation required assertion work",
        )?,
        "alternation assertion work",
    )
}

fn measure_concat_assertions(
    left: AssertionMeasure,
    right: AssertionMeasure,
) -> Result<AssertionMeasure, FactError> {
    let contains_stream_end = left.contains_stream_end || right.contains_stream_end;
    if !left.proven || !right.proven {
        return Ok(AssertionMeasure {
            proven: false,
            count: 0,
            contains_stream_end,
        });
    }
    Ok(AssertionMeasure {
        proven: true,
        count: add_usize(left.count, right.count, "assertion census")?,
        contains_stream_end,
    })
}

fn repeat_language_metrics_measure(
    language: LanguageMeasure,
    min: u32,
    max: u32,
) -> Option<LanguageMeasure> {
    if min > max {
        return Some(LanguageMeasure { count: 0, bytes: 0 });
    }
    let mut count = 0_usize;
    let mut bytes = 0_usize;
    if language.count == 0 {
        if min == 0 {
            count = 1;
        }
        return Some(LanguageMeasure { count, bytes });
    }
    if language.count == 1 {
        let alternatives = usize::try_from(max.checked_sub(min)?.checked_add(1)?).ok()?;
        let sum = sum_u32_range(min, max)?;
        return Some(LanguageMeasure {
            count: alternatives,
            bytes: language.bytes.checked_mul(sum)?,
        });
    }
    if max > usize::BITS {
        return None;
    }
    let mut power = 1_usize;
    for copies in 0..=max {
        if copies >= min {
            count = count.checked_add(power)?;
            if copies != 0 {
                let copies = usize::try_from(copies).ok()?;
                let previous = power.checked_div(language.count)?;
                bytes = bytes
                    .checked_add(copies.checked_mul(language.bytes)?.checked_mul(previous)?)?;
            }
        }
        if copies != max {
            power = power.checked_mul(language.count)?;
        }
    }
    Some(LanguageMeasure { count, bytes })
}

fn repeat_language_census(
    language: LanguageMeasure,
    min: u32,
    max: u32,
) -> Result<Option<(LanguageMeasure, usize, usize)>, FactError> {
    let Some(final_language) = repeat_language_metrics_measure(language, min, max) else {
        return Ok(None);
    };
    let loop_iterations = sum_u32_range(min, max).ok_or(FactError::ArithmeticOverflow {
        computation: "finite repetition loop iterations",
    })?;
    let mut work = loop_iterations;
    let mut allocations =
        usize::try_from(max.saturating_sub(min).saturating_add(1)).map_err(|_| {
            FactError::ArithmeticOverflow {
                computation: "finite repetition outer allocations",
            }
        })?;
    if language.count == 0 {
        allocations = add_usize(
            allocations,
            loop_iterations,
            "finite repetition empty allocations",
        )?;
    } else if language.count == 1 {
        let sum_squares = sum_squares_u32_range(min, max).ok_or(FactError::ArithmeticOverflow {
            computation: "finite repetition copy work",
        })?;
        work = add_usize(
            work,
            mul_usize(language.bytes, sum_squares, "finite repetition copy work")?,
            "finite repetition work",
        )?;
        allocations = add_usize(
            allocations,
            mul_usize(loop_iterations, 2, "finite repetition allocations")?,
            "finite repetition allocations",
        )?;
    } else {
        if max > usize::BITS {
            return Ok(None);
        }
        for copies in min..=max {
            let mut frontier = LanguageMeasure { count: 1, bytes: 0 };
            for _ in 0..copies {
                frontier = measure_concat_language(Some(frontier), Some(language)).ok_or(
                    FactError::ArithmeticOverflow {
                        computation: "finite repetition frontier",
                    },
                )?;
                work = add_usize(work, frontier.bytes, "finite repetition work")?;
                allocations = add_usize(
                    allocations,
                    add_usize(frontier.count, 1, "finite repetition allocations")?,
                    "finite repetition allocations",
                )?;
            }
        }
    }
    Ok(Some((
        final_language,
        mul_usize(work, 4, "finite repetition work upper bound")?,
        allocations,
    )))
}

fn sum_u32_range(min: u32, max: u32) -> Option<usize> {
    if min > max {
        return Some(0);
    }
    let max = u128::from(max);
    let before = u128::from(min.saturating_sub(1));
    let sum_max = max.checked_mul(max.checked_add(1)?)?.checked_div(2)?;
    let sum_before = before.checked_mul(before.checked_add(1)?)?.checked_div(2)?;
    usize::try_from(sum_max.checked_sub(sum_before)?).ok()
}

fn sum_squares_u32_range(min: u32, max: u32) -> Option<usize> {
    fn prefix(value: u128) -> Option<u128> {
        value
            .checked_mul(value.checked_add(1)?)?
            .checked_mul(value.checked_mul(2)?.checked_add(1)?)?
            .checked_div(6)
    }
    if min > max {
        return Some(0);
    }
    let before = u128::from(min.saturating_sub(1));
    usize::try_from(prefix(u128::from(max))?.checked_sub(prefix(before)?)?).ok()
}

fn repeat_language_metrics(
    language: &FiniteLanguage,
    min: u32,
    max: u32,
) -> Option<(usize, usize)> {
    repeat_language_metrics_measure(
        LanguageMeasure {
            count: language.len(),
            bytes: language.total_bytes(),
        },
        min,
        max,
    )
    .map(|metrics| (metrics.count, metrics.bytes))
}

fn ordered_subset_bound(states: usize) -> Option<usize> {
    // Every ordered subset is a partial permutation. Priority-preserving
    // determinization can distinguish two states with identical members in a
    // different order, so an unordered 2^N bound is insufficient.
    let mut total = 1_usize;
    let mut permutations = 1_usize;
    for selected in 1..=states {
        permutations = permutations.checked_mul(states.checked_sub(selected)?.checked_add(1)?)?;
        total = total.checked_add(permutations)?;
    }
    Some(total)
}

fn duplicate_reduction_work_bound(language: LanguageMeasure) -> Option<usize> {
    if language.count < 2 {
        return Some(1);
    }
    let previous = language.count.checked_sub(1)?;
    let significant_bits = usize::BITS.checked_sub(previous.leading_zeros())?;
    let logarithm = usize::try_from(significant_bits).ok()?;
    language
        .count
        .checked_mul(logarithm.checked_add(1)?)?
        .checked_mul(language.bytes.checked_add(1)?)?
        .checked_mul(8)
}

fn measure_node_logical_upper(
    node: &MeasureNode,
    limits: FactLimits,
    operation: FactOperation,
) -> Result<usize, FactError> {
    let mut bytes = size_of::<HirFacts>();
    if operation.requests_finite_language() {
        if let Some(language) = node.finite {
            bytes = add_usize(
                bytes,
                mul_usize(
                    language.count,
                    size_of::<Vec<u8>>(),
                    "finite language slots",
                )?,
                "logical fact bytes",
            )?;
            bytes = add_usize(bytes, language.bytes, "logical fact bytes")?;
            if operation.requests_reductions() {
                // Common-prefix and suffix certificates can each retain at
                // most one complete finite alternative.
                bytes = add_usize(
                    bytes,
                    mul_usize(language.bytes, 2, "finite affix certificates")?,
                    "logical fact bytes",
                )?;
            }
        }
    }
    if operation.requests_required_substrings() {
        bytes = add_usize(
            bytes,
            mul_usize(
                node.required.groups,
                size_of::<RequiredAlternatives>(),
                "required group slots",
            )?,
            "logical fact bytes",
        )?;
        bytes = add_usize(
            bytes,
            mul_usize(
                node.required.alternatives,
                size_of::<RequiredString>(),
                "required alternative slots",
            )?,
            "logical fact bytes",
        )?;
        bytes = add_usize(bytes, node.required.bytes, "logical fact bytes")?;
    }
    if operation.requests_assertion_context() {
        let assertion_count = add_usize(
            node.possible_assertions.count,
            node.required_assertions.count,
            "assertion logical count",
        )?;
        bytes = add_usize(
            bytes,
            mul_usize(
                assertion_count,
                size_of::<PositionedAssertion>(),
                "assertion fact slots",
            )?,
            "logical fact bytes",
        )?;
    }
    bytes = add_usize(
        bytes,
        mul_usize(
            node.captures,
            size_of::<PositionedCapture>(),
            "capture fact slots",
        )?,
        "logical fact bytes",
    )?;
    bytes = add_usize(bytes, node.capture_name_bytes, "logical fact bytes")?;
    if operation.requests_unicode_scalar_alternatives()
        && node.unicode_scalars != 0
        && node.unicode_scalars <= limits.max_finite_strings
        && node.unicode_bytes <= limits.max_finite_string_bytes
    {
        bytes = add_usize(
            bytes,
            mul_usize(
                node.unicode_scalars,
                size_of::<Vec<u8>>(),
                "Unicode scalar fact slots",
            )?,
            "logical fact bytes",
        )?;
        bytes = add_usize(bytes, node.unicode_bytes, "logical fact bytes")?;
    }
    Ok(bytes)
}

fn proof_language_logical_bytes(proof: &FactProof<FiniteLanguage>) -> Result<usize, FactError> {
    let FactProof::Proven(language) = proof else {
        return Ok(0);
    };
    add_usize(
        mul_usize(language.len(), size_of::<Vec<u8>>(), "finite proof slots")?,
        language.total_bytes(),
        "finite proof bytes",
    )
}

fn string_list_logical_bytes(strings: &[Vec<u8>]) -> Result<usize, FactError> {
    let mut bytes = mul_usize(
        strings.len(),
        size_of::<Vec<u8>>(),
        "string-list logical slots",
    )?;
    for string in strings {
        bytes = add_usize(bytes, string.len(), "string-list logical bytes")?;
    }
    Ok(bytes)
}

fn proof_required_logical_bytes(
    proof: &FactProof<Vec<RequiredAlternatives>>,
) -> Result<usize, FactError> {
    let FactProof::Proven(groups) = proof else {
        return Ok(0);
    };
    let mut bytes = mul_usize(
        groups.len(),
        size_of::<RequiredAlternatives>(),
        "required proof group slots",
    )?;
    for group in groups {
        bytes = add_usize(
            bytes,
            mul_usize(
                group.alternatives.len(),
                size_of::<RequiredString>(),
                "required proof alternative slots",
            )?,
            "required proof bytes",
        )?;
        for alternative in &group.alternatives {
            bytes = add_usize(bytes, alternative.bytes.len(), "required proof bytes")?;
        }
    }
    Ok(bytes)
}

fn proof_assertion_logical_bytes(
    proof: &FactProof<Vec<PositionedAssertion>>,
) -> Result<usize, FactError> {
    let FactProof::Proven(assertions) = proof else {
        return Ok(0);
    };
    mul_usize(
        assertions.len(),
        size_of::<PositionedAssertion>(),
        "assertion proof bytes",
    )
}

fn node_logical_bytes(node: &NodeFacts) -> Result<usize, FactError> {
    let mut bytes = size_of::<NodeFacts>();
    bytes = add_usize(
        bytes,
        proof_language_logical_bytes(&node.finite)?,
        "node logical bytes",
    )?;
    bytes = add_usize(
        bytes,
        proof_required_logical_bytes(&node.required)?,
        "node logical bytes",
    )?;
    bytes = add_usize(
        bytes,
        proof_assertion_logical_bytes(&node.possible_assertions)?,
        "node logical bytes",
    )?;
    bytes = add_usize(
        bytes,
        proof_assertion_logical_bytes(&node.required_assertions)?,
        "node logical bytes",
    )?;
    bytes = add_usize(
        bytes,
        mul_usize(
            node.captures.len(),
            size_of::<PositionedCapture>(),
            "capture node slots",
        )?,
        "node logical bytes",
    )?;
    for capture in &node.captures {
        bytes = add_usize(
            bytes,
            capture.name.as_ref().map_or(0, String::len),
            "node logical bytes",
        )?;
    }
    bytes = add_usize(
        bytes,
        mul_usize(
            node.capture_traces.len(),
            size_of::<CaptureTrace>(),
            "capture trace node slots",
        )?,
        "node logical bytes",
    )?;
    for trace in &node.capture_traces {
        if let CaptureTrace::Bits(words) = trace {
            bytes = add_usize(
                bytes,
                mul_usize(words.len(), size_of::<u64>(), "capture trace node words")?,
                "node logical bytes",
            )?;
        }
    }
    if let Some(strings) = &node.unicode.scalar_strings {
        bytes = add_usize(
            bytes,
            mul_usize(strings.len(), size_of::<Vec<u8>>(), "Unicode node slots")?,
            "node logical bytes",
        )?;
        for string in strings {
            bytes = add_usize(bytes, string.len(), "node logical bytes")?;
        }
    }
    Ok(bytes)
}

fn node_dynamic_bytes(node: &NodeFacts) -> Result<usize, FactError> {
    node_logical_bytes(node)?
        .checked_sub(size_of::<NodeFacts>())
        .ok_or(FactError::InternalInvariant {
            detail: "node logical bytes omitted its inline slot",
        })
}

fn published_logical_bytes(
    finite: &FactProof<FiniteLanguage>,
    required: &FactProof<Vec<RequiredAlternatives>>,
    assertions: &AssertionFacts,
    unicode: &UnicodeFacts,
    captures: &[PositionedCapture],
    reductions: &ReductionFacts,
) -> Result<usize, FactError> {
    let mut bytes = size_of::<HirFacts>();
    bytes = add_usize(
        bytes,
        proof_language_logical_bytes(finite)?,
        "published fact bytes",
    )?;
    bytes = add_usize(
        bytes,
        proof_required_logical_bytes(required)?,
        "published fact bytes",
    )?;
    bytes = add_usize(
        bytes,
        proof_assertion_logical_bytes(&assertions.possible)?,
        "published fact bytes",
    )?;
    bytes = add_usize(
        bytes,
        proof_assertion_logical_bytes(&assertions.required)?,
        "published fact bytes",
    )?;
    bytes = add_usize(
        bytes,
        mul_usize(
            captures.len(),
            size_of::<PositionedCapture>(),
            "published capture slots",
        )?,
        "published fact bytes",
    )?;
    for capture in captures {
        bytes = add_usize(
            bytes,
            capture.name.as_ref().map_or(0, String::len),
            "published fact bytes",
        )?;
    }
    bytes = add_usize(
        bytes,
        proof_language_logical_bytes(&unicode.scalar_alternatives)?,
        "published fact bytes",
    )?;
    for proof in [&reductions.common_prefix, &reductions.common_suffix] {
        if let FactProof::Proven(affix) = proof {
            bytes = add_usize(bytes, affix.bytes.len(), "published fact bytes")?;
        }
    }
    Ok(bytes)
}

fn required_metrics(
    proof: &FactProof<Vec<RequiredAlternatives>>,
) -> Result<(usize, usize, usize), FactError> {
    let FactProof::Proven(groups) = proof else {
        return Ok((0, 0, 0));
    };
    let mut alternatives = 0_usize;
    let mut bytes = 0_usize;
    for group in groups {
        alternatives = add_usize(
            alternatives,
            group.alternatives.len(),
            "required metric alternatives",
        )?;
        for alternative in &group.alternatives {
            bytes = add_usize(bytes, alternative.bytes.len(), "required metric bytes")?;
        }
    }
    Ok((groups.len(), alternatives, bytes))
}

fn preflight_prospective(
    prospective: FactProspective,
    limits: FactLimits,
) -> Result<(), FactError> {
    for (resource, needed, limit) in [
        (FactResource::Work, prospective.work, limits.max_work),
        (
            FactResource::StackItems,
            to_u64(prospective.peak_stack_items, "prospective stack")?,
            to_u64(limits.max_stack_items, "prospective stack limit")?,
        ),
        (
            FactResource::HirNodes,
            to_u64(prospective.hir_nodes, "prospective HIR nodes")?,
            to_u64(limits.max_hir_nodes, "prospective HIR node limit")?,
        ),
        (
            FactResource::RetainedBytes,
            to_u64(prospective.retained_bytes, "prospective retained bytes")?,
            to_u64(limits.max_retained_bytes, "prospective retained limit")?,
        ),
        (
            FactResource::TemporaryBytes,
            to_u64(prospective.temporary_bytes, "prospective temporary bytes")?,
            to_u64(limits.max_temporary_bytes, "prospective temporary limit")?,
        ),
        (
            FactResource::PeakBytes,
            to_u64(prospective.peak_bytes, "prospective peak bytes")?,
            to_u64(limits.max_peak_bytes, "prospective peak limit")?,
        ),
        (
            FactResource::AllocationAttempts,
            to_u64(
                prospective.allocation_attempts,
                "prospective allocation attempts",
            )?,
            to_u64(
                limits.max_allocation_attempts,
                "prospective allocation limit",
            )?,
        ),
    ] {
        if needed > limit {
            return Err(FactError::ResourceLimit {
                resource,
                needed,
                limit,
            });
        }
    }
    Ok(())
}

fn validate_actual_within_prospective(
    actual: FactStats,
    prospective: FactProspective,
) -> Result<(), FactError> {
    macro_rules! require_at_most {
        ($actual:expr, $prospective:expr, $detail:literal) => {
            if $actual > $prospective {
                return Err(FactError::InternalInvariant { detail: $detail });
            }
        };
    }
    require_at_most!(
        actual.work,
        prospective.work,
        "actual HIR-fact work exceeded prospective work"
    );
    require_at_most!(
        actual.peak_stack_items,
        prospective.peak_stack_items,
        "actual HIR-fact stack exceeded prospective stack"
    );
    if actual.hir_nodes != prospective.hir_nodes {
        return Err(FactError::InternalInvariant {
            detail: "actual HIR-fact node count differed from prospective nodes",
        });
    }
    require_at_most!(
        actual.retained_bytes,
        prospective.retained_bytes,
        "actual HIR-fact retained bytes exceeded prospective retained bytes"
    );
    require_at_most!(
        actual.temporary_bytes,
        prospective.temporary_bytes,
        "actual HIR-fact temporary bytes exceeded prospective temporary bytes"
    );
    require_at_most!(
        actual.peak_bytes,
        prospective.peak_bytes,
        "actual HIR-fact peak bytes exceeded prospective peak bytes"
    );
    require_at_most!(
        actual.allocation_attempts,
        prospective.allocation_attempts,
        "actual HIR-fact allocations exceeded prospective allocations"
    );
    require_at_most!(
        actual.finite_strings,
        prospective.finite_strings,
        "actual finite strings exceeded prospective finite strings"
    );
    require_at_most!(
        actual.finite_string_bytes,
        prospective.finite_string_bytes,
        "actual finite-string bytes exceeded prospective finite-string bytes"
    );
    require_at_most!(
        actual.required_groups,
        prospective.required_groups,
        "actual required groups exceeded prospective required groups"
    );
    require_at_most!(
        actual.required_alternatives,
        prospective.required_alternatives,
        "actual required alternatives exceeded prospective required alternatives"
    );
    require_at_most!(
        actual.required_bytes,
        prospective.required_bytes,
        "actual required bytes exceeded prospective required bytes"
    );
    Ok(())
}

fn assertion_context_requirements(proof: &FactProof<Vec<PositionedAssertion>>) -> (usize, usize) {
    let FactProof::Proven(assertions) = proof else {
        // Keep the finite local-context envelope conservative, but do not
        // infer an absolute stream-end dependency from unavailable proof
        // material. That fact is carried separately by the structural census.
        return (4, 4);
    };
    let mut behind = 0_usize;
    let mut ahead = 0_usize;
    for assertion in assertions {
        match assertion.look {
            Look::Start | Look::End => {}
            Look::StartLF => behind = behind.max(1),
            Look::EndLF => ahead = ahead.max(1),
            Look::StartCRLF => behind = behind.max(2),
            Look::EndCRLF => ahead = ahead.max(2),
            Look::WordAscii
            | Look::WordAsciiNegate
            | Look::WordStartAscii
            | Look::WordEndAscii
            | Look::WordStartHalfAscii
            | Look::WordEndHalfAscii => {
                behind = behind.max(1);
                ahead = ahead.max(1);
            }
            Look::WordUnicode
            | Look::WordUnicodeNegate
            | Look::WordStartUnicode
            | Look::WordEndUnicode
            | Look::WordStartHalfUnicode
            | Look::WordEndHalfUnicode => {
                behind = behind.max(4);
                ahead = ahead.max(4);
            }
        }
    }
    (behind, ahead)
}

fn common_prefix(strings: &[Vec<u8>]) -> &[u8] {
    let Some(first) = strings.first() else {
        return &[];
    };
    let mut length = first.len();
    for string in strings.iter().skip(1) {
        length = first[..length]
            .iter()
            .zip(string)
            .take_while(|(left, right)| left == right)
            .count();
    }
    &first[..length]
}

fn common_suffix(strings: &[Vec<u8>]) -> &[u8] {
    let Some(first) = strings.first() else {
        return &[];
    };
    let mut length = first.len();
    for string in strings.iter().skip(1) {
        length = first[first.len().saturating_sub(length)..]
            .iter()
            .rev()
            .zip(string.iter().rev())
            .take_while(|(left, right)| left == right)
            .count();
    }
    &first[first.len().saturating_sub(length)..]
}

fn mixed_radix_index(ordinal: usize, stride: usize, radix: usize) -> Result<usize, FactError> {
    ordinal
        .checked_div(stride)
        .and_then(|quotient| quotient.checked_rem(radix))
        .ok_or(FactError::InternalInvariant {
            detail: "finite concatenation had a zero mixed-radix component",
        })
}

fn capture_trace_word_count(rows: usize) -> Result<usize, FactError> {
    rows.checked_add(63)
        .and_then(|rounded| rounded.checked_div(64))
        .ok_or(FactError::ArithmeticOverflow {
            computation: "capture trace word count",
        })
}

fn capture_trace_storage_fits(captures: usize, rows: usize, limit: usize) -> bool {
    rows.checked_add(63)
        .map(|rounded| rounded / 64)
        .and_then(|words| captures.checked_mul(words))
        .and_then(|words| words.checked_mul(size_of::<u64>()))
        .is_some_and(|bytes| bytes <= limit)
}

fn capture_trace_precision_fits(captures: usize, rows: usize, bytes: usize, limit: usize) -> bool {
    capture_trace_storage_fits(captures, rows, limit)
        && capture_trace_priority_work_bound(captures, LanguageMeasure { count: rows, bytes })
            .is_some()
}

fn capture_trace_location(row: usize) -> Result<(usize, u64), FactError> {
    let index = row.checked_div(64).ok_or(FactError::ArithmeticOverflow {
        computation: "capture trace word index",
    })?;
    let offset = row.checked_rem(64).ok_or(FactError::ArithmeticOverflow {
        computation: "capture trace bit offset",
    })?;
    let shift = u32::try_from(offset).map_err(|_| FactError::ArithmeticOverflow {
        computation: "capture trace bit shift",
    })?;
    let mask = 1_u64
        .checked_shl(shift)
        .ok_or(FactError::ArithmeticOverflow {
            computation: "capture trace bit mask",
        })?;
    Ok((index, mask))
}

fn capture_trace_bit(words: &[u64], row: usize) -> Result<bool, FactError> {
    let (index, mask) = capture_trace_location(row)?;
    let word = words.get(index).ok_or(FactError::InternalInvariant {
        detail: "capture trace row exceeded its word storage",
    })?;
    Ok(word & mask != 0)
}

fn set_capture_trace_bit(words: &mut [u64], row: usize) -> Result<(), FactError> {
    let (index, mask) = capture_trace_location(row)?;
    let word = words.get_mut(index).ok_or(FactError::InternalInvariant {
        detail: "capture trace row exceeded its mutable word storage",
    })?;
    *word |= mask;
    Ok(())
}

impl Analyzer<'_> {
    fn vector<T>(&mut self, capacity: usize, structure: &'static str) -> Result<Vec<T>, FactError> {
        let mut values = Vec::new();
        if capacity == 0 {
            return Ok(values);
        }
        self.acquire_local_bytes(mul_usize(capacity, size_of::<T>(), "local vector bytes")?)?;
        self.allocation_request(structure, capacity)?;
        values
            .try_reserve_exact(capacity)
            .map_err(|_| FactError::AllocationFailed {
                structure,
                additional: capacity,
            })?;
        Ok(values)
    }

    fn copy_bytes(&mut self, source: &[u8], structure: &'static str) -> Result<Vec<u8>, FactError> {
        let mut bytes = self.vector(source.len(), structure)?;
        self.charge_usize(source.len(), "byte proof copy")?;
        bytes.extend_from_slice(source);
        Ok(bytes)
    }

    fn copy_string(&mut self, source: &str, structure: &'static str) -> Result<String, FactError> {
        let mut output = String::new();
        if !source.is_empty() {
            self.acquire_local_bytes(source.len())?;
            self.allocation_request(structure, source.len())?;
            output
                .try_reserve_exact(source.len())
                .map_err(|_| FactError::AllocationFailed {
                    structure,
                    additional: source.len(),
                })?;
            self.charge_usize(source.len(), "string proof copy")?;
            output.push_str(source);
        }
        Ok(output)
    }

    fn copy_string_list(
        &mut self,
        source: &[Vec<u8>],
        structure: &'static str,
    ) -> Result<Vec<Vec<u8>>, FactError> {
        let mut output = self.vector(source.len(), structure)?;
        for value in source {
            output.push(self.copy_bytes(value, structure)?);
        }
        Ok(output)
    }

    fn not_requested<T>() -> FactProof<T> {
        FactProof::Refused(FactRefusal::NotRequested)
    }

    fn empty_finite(&mut self) -> Result<FactProof<FiniteLanguage>, FactError> {
        if self.operation.requests_finite_language() {
            self.empty_language().map(FactProof::Proven)
        } else {
            Ok(Self::not_requested())
        }
    }

    fn singleton_finite(
        &mut self,
        source: &[u8],
        structure: &'static str,
    ) -> Result<FactProof<FiniteLanguage>, FactError> {
        if self.operation.requests_finite_language() {
            self.copy_bytes(source, structure)
                .and_then(|bytes| self.singleton_language(bytes))
                .map(FactProof::Proven)
        } else {
            Ok(Self::not_requested())
        }
    }

    fn empty_required(&self) -> FactProof<Vec<RequiredAlternatives>> {
        if self.operation.requests_required_substrings() {
            FactProof::Proven(Vec::new())
        } else {
            Self::not_requested()
        }
    }

    fn empty_assertions(&self) -> FactProof<Vec<PositionedAssertion>> {
        if self.operation.requests_assertion_context() {
            FactProof::Proven(Vec::new())
        } else {
            Self::not_requested()
        }
    }

    fn empty_language(&mut self) -> Result<FiniteLanguage, FactError> {
        self.charge(1, "empty finite language publication")?;
        Ok(FiniteLanguage {
            strings: Vec::new(),
            total_bytes: 0,
        })
    }

    fn singleton_language(&mut self, bytes: Vec<u8>) -> Result<FiniteLanguage, FactError> {
        let total_bytes = bytes.len();
        let mut strings = self.vector(1, "singleton finite language")?;
        self.charge(1, "singleton finite language publication")?;
        strings.push(bytes);
        Ok(FiniteLanguage {
            strings,
            total_bytes,
        })
    }

    fn singleton_required(
        &mut self,
        bytes: Vec<u8>,
        encoding: StringEncoding,
    ) -> Result<FactProof<Vec<RequiredAlternatives>>, FactError> {
        if !self.operation.requests_required_substrings() {
            return Ok(Self::not_requested());
        }
        if self.limits.max_required_groups < 1 {
            return Ok(FactProof::Refused(Self::refusal(
                FactResource::RequiredGroups,
                1,
                self.limits.max_required_groups,
            )?));
        }
        if self.limits.max_required_alternatives < 1 {
            return Ok(FactProof::Refused(Self::refusal(
                FactResource::RequiredAlternatives,
                1,
                self.limits.max_required_alternatives,
            )?));
        }
        if bytes.len() > self.limits.max_required_bytes {
            return Ok(FactProof::Refused(Self::refusal(
                FactResource::RequiredBytes,
                bytes.len(),
                self.limits.max_required_bytes,
            )?));
        }
        let mut alternatives = self.vector(1, "required-string alternatives")?;
        alternatives.push(RequiredString {
            bytes,
            context: BoundedContext::at_match(),
            encoding,
        });
        let mut groups = self.vector(1, "required-string groups")?;
        groups.push(RequiredAlternatives { alternatives });
        Ok(FactProof::Proven(groups))
    }

    fn singleton_assertion(
        &mut self,
        assertion: PositionedAssertion,
    ) -> Result<FactProof<Vec<PositionedAssertion>>, FactError> {
        if !self.operation.requests_assertion_context() {
            return Ok(Self::not_requested());
        }
        if self.limits.max_assertions < 1 {
            return Ok(FactProof::Refused(Self::refusal(
                FactResource::Assertions,
                1,
                self.limits.max_assertions,
            )?));
        }
        let mut assertions = self.vector(1, "positioned assertions")?;
        assertions.push(assertion);
        self.charge(1, "singleton assertion publication")?;
        Ok(FactProof::Proven(assertions))
    }

    fn byte_class_language(
        &mut self,
        class: &regex_syntax::hir::ClassBytes,
        count: usize,
    ) -> Result<FactProof<FiniteLanguage>, FactError> {
        if !self.operation.requests_finite_language() {
            return Ok(Self::not_requested());
        }
        if count > self.limits.max_finite_strings {
            return Ok(FactProof::Refused(Self::refusal(
                FactResource::FiniteStrings,
                count,
                self.limits.max_finite_strings,
            )?));
        }
        if count > self.limits.max_finite_string_bytes {
            return Ok(FactProof::Refused(Self::refusal(
                FactResource::FiniteStringBytes,
                count,
                self.limits.max_finite_string_bytes,
            )?));
        }
        let mut strings = self.vector(count, "byte-class finite language")?;
        for range in class.ranges() {
            for byte in range.start()..=range.end() {
                let mut value = self.vector(1, "byte-class finite string")?;
                value.push(byte);
                strings.push(value);
                self.charge(1, "byte-class finite publication")?;
            }
        }
        Ok(FactProof::Proven(FiniteLanguage {
            strings,
            total_bytes: count,
        }))
    }

    fn byte_class_required(
        &mut self,
        class: &regex_syntax::hir::ClassBytes,
        count: usize,
    ) -> Result<FactProof<Vec<RequiredAlternatives>>, FactError> {
        if !self.operation.requests_required_substrings() {
            return Ok(Self::not_requested());
        }
        if self.limits.max_required_groups < 1 {
            return Ok(FactProof::Refused(Self::refusal(
                FactResource::RequiredGroups,
                1,
                self.limits.max_required_groups,
            )?));
        }
        if count > self.limits.max_required_alternatives {
            return Ok(FactProof::Refused(Self::refusal(
                FactResource::RequiredAlternatives,
                count,
                self.limits.max_required_alternatives,
            )?));
        }
        if count > self.limits.max_required_bytes {
            return Ok(FactProof::Refused(Self::refusal(
                FactResource::RequiredBytes,
                count,
                self.limits.max_required_bytes,
            )?));
        }
        let mut alternatives = self.vector(count, "byte-class required alternatives")?;
        for range in class.ranges() {
            for byte in range.start()..=range.end() {
                let mut bytes = self.vector(1, "byte-class required byte")?;
                bytes.push(byte);
                alternatives.push(RequiredString {
                    bytes,
                    context: BoundedContext::at_match(),
                    encoding: StringEncoding::Bytes,
                });
                self.charge(1, "byte-class required publication")?;
            }
        }
        let mut groups = self.vector(1, "byte-class required groups")?;
        groups.push(RequiredAlternatives { alternatives });
        Ok(FactProof::Proven(groups))
    }

    fn unicode_class_language(
        &mut self,
        class: &regex_syntax::hir::ClassUnicode,
        count: usize,
        total_bytes: usize,
    ) -> Result<FactProof<FiniteLanguage>, FactError> {
        if !self.operation.requests_finite_language() {
            return Ok(Self::not_requested());
        }
        if count > self.limits.max_finite_strings {
            return Ok(FactProof::Refused(Self::refusal(
                FactResource::FiniteStrings,
                count,
                self.limits.max_finite_strings,
            )?));
        }
        if total_bytes > self.limits.max_finite_string_bytes {
            return Ok(FactProof::Refused(Self::refusal(
                FactResource::FiniteStringBytes,
                total_bytes,
                self.limits.max_finite_string_bytes,
            )?));
        }
        let strings = self.unicode_scalar_strings(class, count, "Unicode finite language")?;
        Ok(FactProof::Proven(FiniteLanguage {
            strings,
            total_bytes,
        }))
    }

    fn unicode_class_required(
        &mut self,
        class: &regex_syntax::hir::ClassUnicode,
        count: usize,
        total_bytes: usize,
    ) -> Result<FactProof<Vec<RequiredAlternatives>>, FactError> {
        if !self.operation.requests_required_substrings() {
            return Ok(Self::not_requested());
        }
        if self.limits.max_required_groups < 1 {
            return Ok(FactProof::Refused(Self::refusal(
                FactResource::RequiredGroups,
                1,
                self.limits.max_required_groups,
            )?));
        }
        if count > self.limits.max_required_alternatives {
            return Ok(FactProof::Refused(Self::refusal(
                FactResource::RequiredAlternatives,
                count,
                self.limits.max_required_alternatives,
            )?));
        }
        if total_bytes > self.limits.max_required_bytes {
            return Ok(FactProof::Refused(Self::refusal(
                FactResource::RequiredBytes,
                total_bytes,
                self.limits.max_required_bytes,
            )?));
        }
        let strings = self.unicode_scalar_strings(class, count, "Unicode required alternatives")?;
        let mut alternatives = self.vector(count, "Unicode required-string facts")?;
        for bytes in strings {
            alternatives.push(RequiredString {
                bytes,
                context: BoundedContext::at_match(),
                encoding: StringEncoding::UnicodeScalar,
            });
        }
        self.release_local_bytes(mul_usize(
            count,
            size_of::<Vec<u8>>(),
            "Unicode required temporary string slots",
        )?)?;
        let mut groups = self.vector(1, "Unicode required groups")?;
        groups.push(RequiredAlternatives { alternatives });
        Ok(FactProof::Proven(groups))
    }

    fn unicode_scalar_strings(
        &mut self,
        class: &regex_syntax::hir::ClassUnicode,
        count: usize,
        structure: &'static str,
    ) -> Result<Vec<Vec<u8>>, FactError> {
        let mut strings = self.vector(count, structure)?;
        for range in class.ranges() {
            for character in range.start()..=range.end() {
                let mut buffer = [0_u8; 4];
                let encoded = character.encode_utf8(&mut buffer).as_bytes();
                strings.push(self.copy_bytes(encoded, structure)?);
                self.charge(1, "Unicode scalar publication")?;
            }
        }
        if strings.len() != count {
            return Err(FactError::InternalInvariant {
                detail: "Unicode scalar census differed from publication",
            });
        }
        Ok(strings)
    }

    fn width_vector(
        &mut self,
        count: usize,
        structure: &'static str,
    ) -> Result<Vec<WidthRange>, FactError> {
        let mut widths = self.vector(count, structure)?;
        widths.resize(count, WidthRange::exact(0));
        self.charge_usize(count, "width vector initialization")?;
        Ok(widths)
    }
}

impl Analyzer<'_> {
    fn concat_finite(
        &mut self,
        children: &[NodeFacts],
    ) -> Result<FactProof<FiniteLanguage>, FactError> {
        if !self.operation.requests_finite_language() {
            return Ok(Self::not_requested());
        }
        let mut count = 1_usize;
        let mut bytes = 0_usize;
        for child in children {
            let language = match &child.finite {
                FactProof::Proven(language) => language,
                FactProof::Unknown => return Ok(FactProof::Unknown),
                FactProof::Refused(refusal) => return Ok(FactProof::Refused(*refusal)),
            };
            let Some(next_count) = count.checked_mul(language.len()) else {
                return Ok(FactProof::Refused(FactRefusal::ArithmeticOverflow {
                    computation: "finite concatenation count",
                }));
            };
            let Some(next_bytes) = bytes.checked_mul(language.len()).and_then(|left| {
                language
                    .total_bytes()
                    .checked_mul(count)
                    .and_then(|right| left.checked_add(right))
            }) else {
                return Ok(FactProof::Refused(FactRefusal::ArithmeticOverflow {
                    computation: "finite concatenation bytes",
                }));
            };
            count = next_count;
            bytes = next_bytes;
        }
        if count > self.limits.max_finite_strings {
            return Ok(FactProof::Refused(Self::refusal(
                FactResource::FiniteStrings,
                count,
                self.limits.max_finite_strings,
            )?));
        }
        if bytes > self.limits.max_finite_string_bytes {
            return Ok(FactProof::Refused(Self::refusal(
                FactResource::FiniteStringBytes,
                bytes,
                self.limits.max_finite_string_bytes,
            )?));
        }
        let mut strides = self.vector(children.len(), "finite concatenation strides")?;
        strides.resize(children.len(), 1);
        let mut stride = 1_usize;
        for (index, child) in children.iter().enumerate().rev() {
            strides[index] = stride;
            let FactProof::Proven(language) = &child.finite else {
                return Err(FactError::InternalInvariant {
                    detail: "finite concatenation proof changed during publication",
                });
            };
            stride = mul_usize(stride, language.len(), "finite concatenation stride")?;
        }
        let mut strings = self.vector(count, "finite concatenation alternatives")?;
        for ordinal in 0..count {
            let mut length = 0_usize;
            for (child, stride) in children.iter().zip(&strides) {
                let FactProof::Proven(language) = &child.finite else {
                    return Err(FactError::InternalInvariant {
                        detail: "finite concatenation proof changed during sizing",
                    });
                };
                let index = mixed_radix_index(ordinal, *stride, language.len())?;
                length = add_usize(
                    length,
                    language.strings[index].len(),
                    "finite concatenated string",
                )?;
                self.charge(1, "finite concatenation selection")?;
            }
            let mut value = self.vector(length, "finite concatenated string")?;
            for (child, stride) in children.iter().zip(&strides) {
                let FactProof::Proven(language) = &child.finite else {
                    return Err(FactError::InternalInvariant {
                        detail: "finite concatenation proof changed during copy",
                    });
                };
                let index = mixed_radix_index(ordinal, *stride, language.len())?;
                value.extend_from_slice(&language.strings[index]);
            }
            self.charge_usize(length, "finite concatenation copy")?;
            strings.push(value);
        }
        let language = FiniteLanguage {
            strings,
            total_bytes: bytes,
        };
        self.release_local_bytes(mul_usize(
            children.len(),
            size_of::<usize>(),
            "finite concatenation stride bytes",
        )?)?;
        Ok(FactProof::Proven(language))
    }

    fn alternation_finite(
        &mut self,
        children: &[&NodeFacts],
    ) -> Result<FactProof<FiniteLanguage>, FactError> {
        if !self.operation.requests_finite_language() {
            return Ok(Self::not_requested());
        }
        let mut count = 0_usize;
        let mut bytes = 0_usize;
        for child in children {
            let language = match &child.finite {
                FactProof::Proven(language) => language,
                FactProof::Unknown => return Ok(FactProof::Unknown),
                FactProof::Refused(refusal) => return Ok(FactProof::Refused(*refusal)),
            };
            count = add_usize(count, language.len(), "finite alternation count")?;
            bytes = add_usize(bytes, language.total_bytes(), "finite alternation bytes")?;
        }
        if count > self.limits.max_finite_strings {
            return Ok(FactProof::Refused(Self::refusal(
                FactResource::FiniteStrings,
                count,
                self.limits.max_finite_strings,
            )?));
        }
        if bytes > self.limits.max_finite_string_bytes {
            return Ok(FactProof::Refused(Self::refusal(
                FactResource::FiniteStringBytes,
                bytes,
                self.limits.max_finite_string_bytes,
            )?));
        }
        let mut strings = self.vector(count, "finite alternation")?;
        for child in children {
            let FactProof::Proven(language) = &child.finite else {
                return Err(FactError::InternalInvariant {
                    detail: "finite alternation proof changed during publication",
                });
            };
            for value in &language.strings {
                strings.push(self.copy_bytes(value, "finite alternation string")?);
            }
        }
        Ok(FactProof::Proven(FiniteLanguage {
            strings,
            total_bytes: bytes,
        }))
    }

    fn repeat_finite(
        &mut self,
        child: &FactProof<FiniteLanguage>,
        min: u32,
        max: Option<u32>,
        greedy: bool,
    ) -> Result<FactProof<FiniteLanguage>, FactError> {
        if !self.operation.requests_finite_language() {
            return Ok(Self::not_requested());
        }
        let child = match child {
            FactProof::Proven(language) => language,
            FactProof::Unknown => return Ok(FactProof::Unknown),
            FactProof::Refused(refusal) => return Ok(FactProof::Refused(*refusal)),
        };
        let Some(max) = max else {
            if child.strings.iter().all(Vec::is_empty) {
                return Ok(FactProof::Proven(self.singleton_language(Vec::new())?));
            }
            return Ok(FactProof::Refused(FactRefusal::InfiniteLanguage));
        };
        let Some((count, bytes)) = repeat_language_metrics(child, min, max) else {
            return Ok(FactProof::Refused(FactRefusal::ArithmeticOverflow {
                computation: "finite repetition language",
            }));
        };
        if count > self.limits.max_finite_strings {
            return Ok(FactProof::Refused(Self::refusal(
                FactResource::FiniteStrings,
                count,
                self.limits.max_finite_strings,
            )?));
        }
        if bytes > self.limits.max_finite_string_bytes {
            return Ok(FactProof::Refused(Self::refusal(
                FactResource::FiniteStringBytes,
                bytes,
                self.limits.max_finite_string_bytes,
            )?));
        }
        let mut strings = self.vector(count, "finite repetition language")?;
        if greedy {
            for copies in (min..=max).rev() {
                self.publish_repeated_strings(child, copies, &mut strings)?;
            }
        } else {
            for copies in min..=max {
                self.publish_repeated_strings(child, copies, &mut strings)?;
            }
        }
        if strings.len() != count {
            return Err(FactError::InternalInvariant {
                detail: "finite repetition census differed from publication",
            });
        }
        Ok(FactProof::Proven(FiniteLanguage {
            strings,
            total_bytes: bytes,
        }))
    }

    fn publish_repeated_strings(
        &mut self,
        child: &FiniteLanguage,
        copies: u32,
        output: &mut Vec<Vec<u8>>,
    ) -> Result<(), FactError> {
        self.charge(1, "finite repetition alternative")?;
        let mut frontier = self.vector(1, "finite repetition frontier")?;
        frontier.push(Vec::new());
        for _ in 0..copies {
            self.charge(1, "finite repetition frontier step")?;
            let count = mul_usize(
                frontier.len(),
                child.len(),
                "finite repetition frontier count",
            )?;
            let mut next = self.vector(count, "finite repetition frontier")?;
            for prefix in &frontier {
                for suffix in &child.strings {
                    let length = add_usize(prefix.len(), suffix.len(), "finite repeated string")?;
                    let mut value = self.vector(length, "finite repeated string")?;
                    value.extend_from_slice(prefix);
                    value.extend_from_slice(suffix);
                    self.charge_usize(length, "finite repetition copy")?;
                    next.push(value);
                }
            }
            let released = string_list_logical_bytes(&frontier)?;
            frontier = next;
            self.release_local_bytes(released)?;
        }
        let frontier_slots = mul_usize(
            frontier.len(),
            size_of::<Vec<u8>>(),
            "finite repetition frontier slots",
        )?;
        output.append(&mut frontier);
        self.release_local_bytes(frontier_slots)?;
        Ok(())
    }

    fn concat_required(
        &mut self,
        children: &[NodeFacts],
        prefixes: &[WidthRange],
        suffixes: &[WidthRange],
    ) -> Result<FactProof<Vec<RequiredAlternatives>>, FactError> {
        if !self.operation.requests_required_substrings() {
            return Ok(Self::not_requested());
        }
        let mut count = 0_usize;
        for child in children {
            match &child.required {
                FactProof::Proven(groups) => {
                    count = add_usize(count, groups.len(), "required group count")?;
                }
                FactProof::Unknown | FactProof::Refused(_) => {}
            }
        }
        if count > self.limits.max_required_groups {
            return Ok(FactProof::Refused(Self::refusal(
                FactResource::RequiredGroups,
                count,
                self.limits.max_required_groups,
            )?));
        }
        let mut groups = self.vector(count, "concatenated required groups")?;
        for ((child, prefix), suffix) in children.iter().zip(prefixes).zip(suffixes) {
            let FactProof::Proven(child_groups) = &child.required else {
                continue;
            };
            for group in child_groups {
                groups.push(self.copy_shifted_group(group, *prefix, *suffix)?);
            }
        }
        Ok(FactProof::Proven(groups))
    }

    fn alternation_required(
        &mut self,
        children: &[&NodeFacts],
    ) -> Result<FactProof<Vec<RequiredAlternatives>>, FactError> {
        if !self.operation.requests_required_substrings() {
            return Ok(Self::not_requested());
        }
        if children.is_empty() {
            return Ok(FactProof::Proven(Vec::new()));
        }
        let mut alternatives = 0_usize;
        let mut bytes = 0_usize;
        for child in children {
            let groups = match &child.required {
                FactProof::Proven(groups) => groups,
                FactProof::Unknown => return Ok(FactProof::Unknown),
                FactProof::Refused(refusal) => return Ok(FactProof::Refused(*refusal)),
            };
            let Some(group) = select_required_group(groups) else {
                return Ok(FactProof::Proven(Vec::new()));
            };
            alternatives = add_usize(
                alternatives,
                group.alternatives.len(),
                "alternation required alternatives",
            )?;
            for alternative in &group.alternatives {
                bytes = add_usize(bytes, alternative.bytes.len(), "alternation required bytes")?;
            }
        }
        if self.limits.max_required_groups < 1 {
            return Ok(FactProof::Refused(Self::refusal(
                FactResource::RequiredGroups,
                1,
                self.limits.max_required_groups,
            )?));
        }
        if alternatives > self.limits.max_required_alternatives {
            return Ok(FactProof::Refused(Self::refusal(
                FactResource::RequiredAlternatives,
                alternatives,
                self.limits.max_required_alternatives,
            )?));
        }
        if bytes > self.limits.max_required_bytes {
            return Ok(FactProof::Refused(Self::refusal(
                FactResource::RequiredBytes,
                bytes,
                self.limits.max_required_bytes,
            )?));
        }
        let mut combined = self.vector(alternatives, "alternation required alternatives")?;
        for child in children {
            let FactProof::Proven(groups) = &child.required else {
                return Err(FactError::InternalInvariant {
                    detail: "required alternation proof changed during publication",
                });
            };
            let group = select_required_group(groups).ok_or(FactError::InternalInvariant {
                detail: "required alternation group disappeared",
            })?;
            for alternative in &group.alternatives {
                combined.push(self.copy_required(alternative)?);
            }
        }
        let mut groups = self.vector(1, "alternation required group")?;
        groups.push(RequiredAlternatives {
            alternatives: combined,
        });
        Ok(FactProof::Proven(groups))
    }

    fn shift_required(
        &mut self,
        proof: &FactProof<Vec<RequiredAlternatives>>,
        prefix: WidthRange,
        suffix: WidthRange,
    ) -> Result<FactProof<Vec<RequiredAlternatives>>, FactError> {
        if !self.operation.requests_required_substrings() {
            return Ok(Self::not_requested());
        }
        match proof {
            FactProof::Proven(groups) => {
                let mut shifted = self.vector(groups.len(), "shifted required groups")?;
                for group in groups {
                    shifted.push(self.copy_shifted_group(group, prefix, suffix)?);
                }
                Ok(FactProof::Proven(shifted))
            }
            FactProof::Unknown => Ok(FactProof::Unknown),
            FactProof::Refused(refusal) => Ok(FactProof::Refused(*refusal)),
        }
    }

    fn copy_shifted_group(
        &mut self,
        group: &RequiredAlternatives,
        prefix: WidthRange,
        suffix: WidthRange,
    ) -> Result<RequiredAlternatives, FactError> {
        let mut alternatives =
            self.vector(group.alternatives.len(), "shifted required alternatives")?;
        for alternative in &group.alternatives {
            let mut copied = self.copy_required(alternative)?;
            copied.context = shift_context(copied.context, prefix, suffix)?;
            alternatives.push(copied);
        }
        Ok(RequiredAlternatives { alternatives })
    }

    fn copy_required(&mut self, source: &RequiredString) -> Result<RequiredString, FactError> {
        Ok(RequiredString {
            bytes: self.copy_bytes(&source.bytes, "required string copy")?,
            context: source.context,
            encoding: source.encoding,
        })
    }
}

impl Analyzer<'_> {
    fn concat_assertions(
        &mut self,
        children: &[NodeFacts],
        prefixes: &[WidthRange],
        suffixes: &[WidthRange],
        required: bool,
    ) -> Result<FactProof<Vec<PositionedAssertion>>, FactError> {
        if !self.operation.requests_assertion_context() {
            return Ok(Self::not_requested());
        }
        let mut count = 0_usize;
        for child in children {
            let proof = if required {
                &child.required_assertions
            } else {
                &child.possible_assertions
            };
            match proof {
                FactProof::Proven(assertions) => {
                    count = add_usize(count, assertions.len(), "concatenated assertions")?;
                }
                FactProof::Unknown => return Ok(FactProof::Unknown),
                FactProof::Refused(refusal) => return Ok(FactProof::Refused(*refusal)),
            }
        }
        if count > self.limits.max_assertions {
            return Ok(FactProof::Refused(Self::refusal(
                FactResource::Assertions,
                count,
                self.limits.max_assertions,
            )?));
        }
        let mut output = self.vector(count, "concatenated assertions")?;
        for ((child, prefix), suffix) in children.iter().zip(prefixes).zip(suffixes) {
            let proof = if required {
                &child.required_assertions
            } else {
                &child.possible_assertions
            };
            let FactProof::Proven(assertions) = proof else {
                return Err(FactError::InternalInvariant {
                    detail: "assertion concatenation proof changed during publication",
                });
            };
            for assertion in assertions {
                output.push(PositionedAssertion {
                    look: assertion.look,
                    context: shift_context(assertion.context, *prefix, *suffix)?,
                });
                self.charge(1, "positioned assertion publication")?;
            }
        }
        Ok(FactProof::Proven(output))
    }

    fn alternation_possible_assertions(
        &mut self,
        children: &[&NodeFacts],
    ) -> Result<FactProof<Vec<PositionedAssertion>>, FactError> {
        if !self.operation.requests_assertion_context() {
            return Ok(Self::not_requested());
        }
        let mut count = 0_usize;
        for child in children {
            match &child.possible_assertions {
                FactProof::Proven(assertions) => {
                    count = add_usize(count, assertions.len(), "possible assertions")?;
                }
                FactProof::Unknown => return Ok(FactProof::Unknown),
                FactProof::Refused(refusal) => return Ok(FactProof::Refused(*refusal)),
            }
        }
        if count > self.limits.max_assertions {
            return Ok(FactProof::Refused(Self::refusal(
                FactResource::Assertions,
                count,
                self.limits.max_assertions,
            )?));
        }
        let mut output = self.vector(count, "alternation possible assertions")?;
        for child in children {
            let FactProof::Proven(assertions) = &child.possible_assertions else {
                return Err(FactError::InternalInvariant {
                    detail: "possible assertion proof changed during publication",
                });
            };
            output.extend_from_slice(assertions);
            self.charge_usize(assertions.len(), "possible assertion publication")?;
        }
        Ok(FactProof::Proven(output))
    }

    fn alternation_required_assertions(
        &mut self,
        children: &[&NodeFacts],
    ) -> Result<FactProof<Vec<PositionedAssertion>>, FactError> {
        if !self.operation.requests_assertion_context() {
            return Ok(Self::not_requested());
        }
        let Some(first) = children.first() else {
            return Ok(FactProof::Proven(Vec::new()));
        };
        let first = match &first.required_assertions {
            FactProof::Proven(assertions) => assertions,
            FactProof::Unknown => return Ok(FactProof::Unknown),
            FactProof::Refused(refusal) => return Ok(FactProof::Refused(*refusal)),
        };
        for child in children.iter().skip(1) {
            match &child.required_assertions {
                FactProof::Proven(_) => {}
                FactProof::Unknown => return Ok(FactProof::Unknown),
                FactProof::Refused(refusal) => return Ok(FactProof::Refused(*refusal)),
            }
        }
        let mut count = 0_usize;
        for assertion in first {
            self.charge(1, "required assertion intersection candidate")?;
            let mut retained = true;
            for child in children.iter().skip(1) {
                let FactProof::Proven(assertions) = &child.required_assertions else {
                    return Err(FactError::InternalInvariant {
                        detail: "required assertion proof changed during intersection",
                    });
                };
                retained &= self.assertion_contains_metered(assertions, assertion)?;
            }
            count = add_usize(count, usize::from(retained), "required assertion count")?;
        }
        if count > self.limits.max_assertions {
            return Ok(FactProof::Refused(Self::refusal(
                FactResource::Assertions,
                count,
                self.limits.max_assertions,
            )?));
        }
        let mut output = self.vector(count, "required assertion intersection")?;
        for assertion in first {
            self.charge(1, "required assertion publication candidate")?;
            let mut retained = true;
            for child in children.iter().skip(1) {
                let FactProof::Proven(assertions) = &child.required_assertions else {
                    return Err(FactError::InternalInvariant {
                        detail: "required assertion proof changed during publication",
                    });
                };
                retained &= self.assertion_contains_metered(assertions, assertion)?;
            }
            if retained {
                output.push(*assertion);
                self.charge(1, "required assertion publication")?;
            }
        }
        Ok(FactProof::Proven(output))
    }

    fn assertion_contains_metered(
        &mut self,
        assertions: &[PositionedAssertion],
        needle: &PositionedAssertion,
    ) -> Result<bool, FactError> {
        for assertion in assertions {
            self.charge(1, "required assertion comparison")?;
            if assertion == needle {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn shift_assertions(
        &mut self,
        proof: &FactProof<Vec<PositionedAssertion>>,
        prefix: WidthRange,
        suffix: WidthRange,
    ) -> Result<FactProof<Vec<PositionedAssertion>>, FactError> {
        if !self.operation.requests_assertion_context() {
            return Ok(Self::not_requested());
        }
        match proof {
            FactProof::Proven(assertions) => {
                let mut output = self.vector(assertions.len(), "shifted assertions")?;
                for assertion in assertions {
                    output.push(PositionedAssertion {
                        look: assertion.look,
                        context: shift_context(assertion.context, prefix, suffix)?,
                    });
                    self.charge(1, "shifted assertion publication")?;
                }
                Ok(FactProof::Proven(output))
            }
            FactProof::Unknown => Ok(FactProof::Unknown),
            FactProof::Refused(refusal) => Ok(FactProof::Refused(*refusal)),
        }
    }

    fn repeat_assertions(
        &mut self,
        proof: &FactProof<Vec<PositionedAssertion>>,
        child_width: CheckedWidth,
        max: Option<u32>,
        _required: bool,
    ) -> Result<FactProof<Vec<PositionedAssertion>>, FactError> {
        if !self.operation.requests_assertion_context() {
            return Ok(Self::not_requested());
        }
        if max == Some(0) {
            return Ok(FactProof::Proven(Vec::new()));
        }
        let displacement = repetition_displacement(child_width, max)?;
        self.shift_assertions(proof, displacement, displacement)
    }

    fn capture_trace_storage_allowed(&self, captures: usize, language: &FiniteLanguage) -> bool {
        // Capture provenance is an optional finite proof. Sharing the finite
        // byte cap makes lost precision a typed `Unavailable` trace instead
        // of turning an otherwise valid analysis into a new hard failure.
        self.capture_trace_precision_enabled
            && capture_trace_precision_fits(
                captures,
                language.len(),
                language.total_bytes(),
                self.limits.max_finite_string_bytes,
            )
    }

    fn empty_capture_trace_bits(
        &mut self,
        rows: usize,
        structure: &'static str,
    ) -> Result<Vec<u64>, FactError> {
        let words = capture_trace_word_count(rows)?;
        let mut bits = self.vector(words, structure)?;
        bits.resize(words, 0);
        self.charge_usize(words, "capture trace word initialization")?;
        Ok(bits)
    }

    fn concat_capture_traces(
        &mut self,
        children: &[NodeFacts],
        output_finite: &FactProof<FiniteLanguage>,
    ) -> Result<Vec<CaptureTrace>, FactError> {
        let captures = children.iter().try_fold(0_usize, |total, child| {
            if child.captures.len() != child.capture_traces.len() {
                return Err(FactError::InternalInvariant {
                    detail: "concatenation capture trace schema diverged",
                });
            }
            add_usize(total, child.captures.len(), "concatenated capture traces")
        })?;
        let mut output = self.vector(captures, "concatenated capture traces")?;
        let rows = match output_finite {
            FactProof::Proven(language) => Some(language.len()),
            FactProof::Unknown | FactProof::Refused(_) => None,
        };
        let bits_allowed = children.iter().all(|child| child.capture_trace_ordered)
            && match output_finite {
                FactProof::Proven(language) => {
                    self.capture_trace_storage_allowed(captures, language)
                }
                FactProof::Unknown | FactProof::Refused(_) => false,
            };
        for (child_index, child) in children.iter().enumerate() {
            let child_rows = match &child.finite {
                FactProof::Proven(language) => Some(language.len()),
                FactProof::Unknown | FactProof::Refused(_) => None,
            };
            let stride = if bits_allowed {
                let suffix_start =
                    child_index
                        .checked_add(1)
                        .ok_or(FactError::ArithmeticOverflow {
                            computation: "capture trace suffix start",
                        })?;
                children
                    .get(suffix_start..)
                    .ok_or(FactError::InternalInvariant {
                        detail: "capture trace suffix start exceeded children",
                    })?
                    .iter()
                    .try_fold(1_usize, |stride, suffix| {
                        let FactProof::Proven(language) = &suffix.finite else {
                            return Err(FactError::InternalInvariant {
                                detail: "proven concatenation trace lost a finite suffix",
                            });
                        };
                        mul_usize(stride, language.len(), "capture trace concatenation stride")
                    })?
            } else {
                1
            };
            for trace in &child.capture_traces {
                output.push(match trace {
                    CaptureTrace::All => CaptureTrace::All,
                    CaptureTrace::None => CaptureTrace::None,
                    CaptureTrace::Bits(source)
                        if bits_allowed && rows.is_some() && child_rows.is_some() =>
                    {
                        let output_rows = rows.ok_or(FactError::InternalInvariant {
                            detail: "capture trace output rows disappeared",
                        })?;
                        let radix = child_rows.ok_or(FactError::InternalInvariant {
                            detail: "capture trace child rows disappeared",
                        })?;
                        let mut bits = self.empty_capture_trace_bits(
                            output_rows,
                            "concatenated capture trace bits",
                        )?;
                        for ordinal in 0..output_rows {
                            let index = mixed_radix_index(ordinal, stride, radix)?;
                            self.charge(1, "concatenated capture trace remap")?;
                            if capture_trace_bit(source, index)? {
                                set_capture_trace_bit(&mut bits, ordinal)?;
                            }
                        }
                        CaptureTrace::Bits(bits)
                    }
                    CaptureTrace::Bits(_) | CaptureTrace::Unavailable => CaptureTrace::Unavailable,
                });
            }
        }
        Ok(output)
    }

    fn alternation_capture_traces(
        &mut self,
        children: &[NodeFacts],
        output_finite: &FactProof<FiniteLanguage>,
    ) -> Result<Vec<CaptureTrace>, FactError> {
        let captures = children.iter().try_fold(0_usize, |total, child| {
            if child.captures.len() != child.capture_traces.len() {
                return Err(FactError::InternalInvariant {
                    detail: "alternation capture trace schema diverged",
                });
            }
            add_usize(total, child.captures.len(), "alternation capture traces")
        })?;
        let possible_count = children
            .iter()
            .filter(|child| !child.width.is_empty_language())
            .count();
        let rows = match output_finite {
            FactProof::Proven(language) => Some(language.len()),
            FactProof::Unknown | FactProof::Refused(_) => None,
        };
        let bits_allowed = children.iter().all(|child| child.capture_trace_ordered)
            && match output_finite {
                FactProof::Proven(language) => {
                    self.capture_trace_storage_allowed(captures, language)
                }
                FactProof::Unknown | FactProof::Refused(_) => false,
            };
        let mut output = self.vector(captures, "alternation capture traces")?;
        let mut offset = 0_usize;
        for child in children {
            let child_rows = if child.width.is_empty_language() {
                0
            } else {
                match &child.finite {
                    FactProof::Proven(language) => language.len(),
                    FactProof::Unknown | FactProof::Refused(_) => 0,
                }
            };
            for trace in &child.capture_traces {
                output.push(match trace {
                    CaptureTrace::None => CaptureTrace::None,
                    CaptureTrace::All if child.width.is_empty_language() => CaptureTrace::None,
                    CaptureTrace::All if possible_count == 1 => CaptureTrace::All,
                    CaptureTrace::All if bits_allowed => {
                        let output_rows = rows.ok_or(FactError::InternalInvariant {
                            detail: "capture trace alternation rows disappeared",
                        })?;
                        let mut bits = self.empty_capture_trace_bits(
                            output_rows,
                            "alternation capture trace bits",
                        )?;
                        for row in offset
                            ..add_usize(offset, child_rows, "alternation capture trace range")?
                        {
                            self.charge(1, "alternation capture trace fill")?;
                            set_capture_trace_bit(&mut bits, row)?;
                        }
                        CaptureTrace::Bits(bits)
                    }
                    CaptureTrace::Bits(source)
                        if bits_allowed && !child.width.is_empty_language() =>
                    {
                        let output_rows = rows.ok_or(FactError::InternalInvariant {
                            detail: "capture trace alternation rows disappeared",
                        })?;
                        let mut bits = self.empty_capture_trace_bits(
                            output_rows,
                            "alternation capture trace bits",
                        )?;
                        for child_row in 0..child_rows {
                            self.charge(1, "alternation capture trace copy")?;
                            if capture_trace_bit(source, child_row)? {
                                set_capture_trace_bit(
                                    &mut bits,
                                    add_usize(offset, child_row, "alternation capture trace row")?,
                                )?;
                            }
                        }
                        CaptureTrace::Bits(bits)
                    }
                    CaptureTrace::All | CaptureTrace::Bits(_) | CaptureTrace::Unavailable => {
                        CaptureTrace::Unavailable
                    }
                });
            }
            offset = add_usize(offset, child_rows, "alternation capture trace offset")?;
        }
        if let Some(rows) = rows {
            if bits_allowed && offset != rows {
                return Err(FactError::InternalInvariant {
                    detail: "alternation capture traces differed from finite rows",
                });
            }
        }
        Ok(output)
    }

    fn repeat_capture_traces(
        &mut self,
        source: &[CaptureTrace],
        finite: &FactProof<FiniteLanguage>,
        min: u32,
        max: Option<u32>,
    ) -> Result<Vec<CaptureTrace>, FactError> {
        let bits_allowed = match finite {
            FactProof::Proven(language) => {
                self.capture_trace_storage_allowed(source.len(), language)
            }
            FactProof::Unknown | FactProof::Refused(_) => false,
        };
        let mut output = self.vector(source.len(), "repeated capture traces")?;
        for trace in source {
            output.push(match (min, max, trace) {
                (_, Some(0), _) | (_, _, CaptureTrace::None) => CaptureTrace::None,
                (1, Some(1), CaptureTrace::Bits(bits)) if bits_allowed => {
                    let mut copied =
                        self.vector(bits.len(), "single-copy repeated capture trace bits")?;
                    self.charge_usize(bits.len(), "single-copy capture trace word copy")?;
                    copied.extend_from_slice(bits);
                    CaptureTrace::Bits(copied)
                }
                (1.., _, CaptureTrace::All) => CaptureTrace::All,
                (_, _, CaptureTrace::All | CaptureTrace::Bits(_) | CaptureTrace::Unavailable) => {
                    CaptureTrace::Unavailable
                }
            });
        }
        Ok(output)
    }

    fn concat_captures(
        &mut self,
        children: &[NodeFacts],
        prefixes: &[WidthRange],
        suffixes: &[WidthRange],
    ) -> Result<Vec<PositionedCapture>, FactError> {
        let count = children.iter().try_fold(0_usize, |total, child| {
            add_usize(total, child.captures.len(), "capture fact count")
        })?;
        let mut captures = self.vector(count, "concatenated capture facts")?;
        for ((child, prefix), suffix) in children.iter().zip(prefixes).zip(suffixes) {
            for capture in &child.captures {
                captures.push(PositionedCapture {
                    index: capture.index,
                    name: match &capture.name {
                        Some(name) => Some(self.copy_string(name, "capture name copy")?),
                        None => None,
                    },
                    context: shift_context(capture.context, *prefix, *suffix)?,
                    participation: capture.participation,
                });
            }
        }
        Ok(captures)
    }

    fn alternation_captures(
        &mut self,
        children: &[NodeFacts],
        continuation: ContinuationContext,
    ) -> Result<Vec<PositionedCapture>, FactError> {
        let count = children.iter().try_fold(0_usize, |total, child| {
            add_usize(total, child.captures.len(), "alternation capture facts")
        })?;
        if count == 0 {
            return Ok(Vec::new());
        }
        let reachability = self.alternation_branch_reachability(children, continuation)?;
        let possibly_reachable = reachability
            .iter()
            .filter(|state| **state != BranchReachability::ProvenUnreachable)
            .count();
        let proved_reachable = reachability
            .iter()
            .filter(|state| **state == BranchReachability::ProvenReachable)
            .count();
        let mut captures = self.vector(count, "alternation capture facts")?;
        for (child, branch) in children.iter().zip(&reachability) {
            for capture in &child.captures {
                let participation = if *branch == BranchReachability::ProvenUnreachable {
                    CaptureParticipation::Never
                } else if possibly_reachable == 1 {
                    capture.participation
                } else {
                    match capture.participation {
                        CaptureParticipation::Never => CaptureParticipation::Never,
                        // Branch reachability is only a proof about the
                        // branch's complete language. An inherited `Maybe`
                        // also needs outcome-sensitive reachability: an outer
                        // predecessor can shadow every capture-present string
                        // while leaving a capture-absent string reachable.
                        // Until both outcomes are proved separately, retaining
                        // `Maybe` would claim semantic matches for outcomes
                        // that may not exist.
                        CaptureParticipation::Maybe => CaptureParticipation::Unknown,
                        CaptureParticipation::Always
                            if *branch == BranchReachability::ProvenReachable
                                && proved_reachable >= 2 =>
                        {
                            CaptureParticipation::Maybe
                        }
                        CaptureParticipation::Unknown | CaptureParticipation::Always => {
                            CaptureParticipation::Unknown
                        }
                    }
                };
                captures.push(PositionedCapture {
                    index: capture.index,
                    name: match &capture.name {
                        Some(name) => Some(self.copy_string(name, "capture name copy")?),
                        None => None,
                    },
                    context: capture.context,
                    participation: if continuation == ContinuationContext::MayReject
                        && participation == CaptureParticipation::Maybe
                    {
                        CaptureParticipation::Unknown
                    } else {
                        participation
                    },
                });
            }
        }
        self.release_local_bytes(mul_usize(
            reachability.len(),
            size_of::<BranchReachability>(),
            "alternation reachability scratch bytes",
        )?)?;
        Ok(captures)
    }

    fn alternation_branch_reachability(
        &mut self,
        children: &[NodeFacts],
        continuation: ContinuationContext,
    ) -> Result<Vec<BranchReachability>, FactError> {
        let mut states = self.vector(children.len(), "alternation branch reachability")?;
        if continuation == ContinuationContext::MayReject {
            for child in children {
                self.charge(1, "continuation-aware alternation branch")?;
                states.push(
                    if child.width.is_empty_language()
                        || matches!(
                            &child.finite,
                            FactProof::Proven(language) if language.is_empty()
                        )
                    {
                        BranchReachability::ProvenUnreachable
                    } else {
                        // A following expression can reject an earlier local
                        // prefix and expose a later branch. Without an exact
                        // continuation language, neither local reachability
                        // nor local prefix shadowing is a whole-match proof.
                        BranchReachability::Unknown
                    },
                );
            }
            return Ok(states);
        }
        for (index, child) in children.iter().enumerate() {
            if child.width.is_empty_language() {
                states.push(BranchReachability::ProvenUnreachable);
                continue;
            }
            let FactProof::Proven(language) = &child.finite else {
                states.push(BranchReachability::Unknown);
                continue;
            };
            if language.is_empty() {
                states.push(BranchReachability::ProvenUnreachable);
                continue;
            }
            let assertions_absent = matches!(
                &child.possible_assertions,
                FactProof::Proven(assertions) if assertions.is_empty()
            );
            let mut every_string_shadowed = true;
            let mut one_string_proved_reachable = false;
            for candidate in &language.strings {
                self.charge(1, "priority-shadow candidate")?;
                let mut shadowed = false;
                let mut all_predecessors_modeled = assertions_absent;
                for (predecessor, predecessor_state) in children[..index].iter().zip(&states) {
                    self.charge(1, "priority-shadow predecessor")?;
                    if *predecessor_state == BranchReachability::ProvenUnreachable {
                        continue;
                    }
                    let predecessor_assertions_absent = matches!(
                        &predecessor.possible_assertions,
                        FactProof::Proven(assertions) if assertions.is_empty()
                    );
                    let FactProof::Proven(predecessor_language) = &predecessor.finite else {
                        all_predecessors_modeled = false;
                        continue;
                    };
                    if !predecessor_assertions_absent {
                        all_predecessors_modeled = false;
                        continue;
                    }
                    if *predecessor_state != BranchReachability::ProvenReachable {
                        all_predecessors_modeled = false;
                        continue;
                    }
                    for prefix in &predecessor_language.strings {
                        if self.is_prefix_metered(prefix, candidate)? {
                            shadowed = true;
                            break;
                        }
                    }
                    if shadowed {
                        break;
                    }
                }
                every_string_shadowed &= shadowed;
                one_string_proved_reachable |= !shadowed && all_predecessors_modeled;
            }
            states.push(if every_string_shadowed {
                BranchReachability::ProvenUnreachable
            } else if one_string_proved_reachable {
                BranchReachability::ProvenReachable
            } else {
                BranchReachability::Unknown
            });
        }
        Ok(states)
    }

    fn is_prefix_metered(&mut self, prefix: &[u8], value: &[u8]) -> Result<bool, FactError> {
        self.charge(1, "priority-shadow prefix length")?;
        if prefix.len() > value.len() {
            return Ok(false);
        }
        for (left, right) in prefix.iter().zip(value) {
            self.charge(1, "priority-shadow prefix byte")?;
            if left != right {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn repeat_captures(
        &mut self,
        source: &[PositionedCapture],
        child_width: CheckedWidth,
        min: u32,
        max: Option<u32>,
        continuation: ContinuationContext,
    ) -> Result<Vec<PositionedCapture>, FactError> {
        let displacement = repetition_displacement(child_width, max)?;
        let mut captures = self.vector(source.len(), "repeated capture facts")?;
        for capture in source {
            let participation = match (min, max, capture.participation) {
                (_, Some(0), _) | (_, _, CaptureParticipation::Never) => {
                    CaptureParticipation::Never
                }
                (0, _, CaptureParticipation::Always) => CaptureParticipation::Maybe,
                (_, _, CaptureParticipation::Unknown) => CaptureParticipation::Unknown,
                _ => capture.participation,
            };
            captures.push(PositionedCapture {
                index: capture.index,
                name: match &capture.name {
                    Some(name) => Some(self.copy_string(name, "capture name copy")?),
                    None => None,
                },
                context: shift_context(capture.context, displacement, displacement)?,
                participation: if continuation == ContinuationContext::MayReject
                    && participation == CaptureParticipation::Maybe
                {
                    CaptureParticipation::Unknown
                } else {
                    participation
                },
            });
        }
        Ok(captures)
    }

    fn merge_unicode<'a>(
        &mut self,
        inputs: impl Iterator<Item = &'a UnicodeAccumulator>,
    ) -> Result<UnicodeAccumulator, FactError> {
        let mut retained_inputs = Vec::new();
        let mut retained_input_bytes = 0_usize;
        for input in inputs {
            let reference_bytes = size_of::<&UnicodeAccumulator>();
            self.acquire_local_bytes(reference_bytes)?;
            retained_input_bytes = add_usize(
                retained_input_bytes,
                reference_bytes,
                "Unicode merge input bytes",
            )?;
            self.allocation_request("Unicode merge inputs", 1)?;
            retained_inputs
                .try_reserve_exact(1)
                .map_err(|_| FactError::AllocationFailed {
                    structure: "Unicode merge inputs",
                    additional: 1,
                })?;
            retained_inputs.push(input);
        }
        let mut output = UnicodeAccumulator::default();
        let mut scalar_strings = 0_usize;
        let mut scalar_bytes = 0_usize;
        for input in &retained_inputs {
            output.class_count =
                add_usize(output.class_count, input.class_count, "Unicode class count")?;
            output.scalar_range_count = add_usize(
                output.scalar_range_count,
                input.scalar_range_count,
                "Unicode scalar range count",
            )?;
            output.scalar_count = add_usize(
                output.scalar_count,
                input.scalar_count,
                "Unicode scalar count",
            )?;
            output.utf8_width_mask |= input.utf8_width_mask;
            output.contains_non_ascii |= input.contains_non_ascii;
            output.width_changing_alternatives |= input.width_changing_alternatives;
            if output.scalar_refusal.is_none() {
                output.scalar_refusal = input.scalar_refusal;
            }
            if let Some(strings) = &input.scalar_strings {
                scalar_strings =
                    add_usize(scalar_strings, strings.len(), "Unicode scalar alternatives")?;
                for string in strings {
                    scalar_bytes = add_usize(scalar_bytes, string.len(), "Unicode scalar bytes")?;
                }
            }
        }
        if output.scalar_refusal.is_none()
            && scalar_strings <= self.limits.max_finite_strings
            && scalar_bytes <= self.limits.max_finite_string_bytes
        {
            let mut strings = self.vector(scalar_strings, "merged Unicode scalar facts")?;
            for input in &retained_inputs {
                if let Some(input_strings) = &input.scalar_strings {
                    for string in input_strings {
                        strings.push(self.copy_bytes(string, "Unicode scalar fact copy")?);
                    }
                }
            }
            output.scalar_strings = Some(strings);
        } else {
            output.scalar_strings = None;
            if output.scalar_refusal.is_none() {
                output.scalar_refusal = if scalar_strings > self.limits.max_finite_strings {
                    Some(Self::refusal(
                        FactResource::FiniteStrings,
                        scalar_strings,
                        self.limits.max_finite_strings,
                    )?)
                } else {
                    Some(Self::refusal(
                        FactResource::FiniteStringBytes,
                        scalar_bytes,
                        self.limits.max_finite_string_bytes,
                    )?)
                };
            }
        }
        self.release_local_bytes(retained_input_bytes)?;
        Ok(output)
    }
}

impl Analyzer<'_> {
    fn refine_root_capture_participation(&mut self, root: &mut NodeFacts) -> Result<(), FactError> {
        if !self.capture_trace_precision_enabled || !self.operation.observes_captures() {
            return Ok(());
        }
        if root.captures.len() != root.capture_traces.len() {
            return Err(FactError::InternalInvariant {
                detail: "root capture trace schema diverged",
            });
        }
        if !root.capture_trace_ordered
            || !matches!(
                &root.possible_assertions,
                FactProof::Proven(assertions) if assertions.is_empty()
            )
            || !root
                .capture_traces
                .iter()
                .any(|trace| matches!(trace, CaptureTrace::Bits(_)))
        {
            return Ok(());
        }
        let FactProof::Proven(language) = &root.finite else {
            return Ok(());
        };
        let mut outcomes = self.vector(root.captures.len(), "root capture outcomes")?;
        outcomes.resize(root.captures.len(), 0_u8);
        self.charge_usize(root.captures.len(), "root capture outcome initialization")?;
        // The public Rust-bytes engine can use its reverse-suffix strategy,
        // but it may retry or fall back after an arbitrary external prefix.
        // Use that selector only for a structural no-retry certificate;
        // otherwise the ordinary source-priority proof is the safe result.
        let suffix = self.certified_reverse_suffix(language, &root.capture_traces)?;
        for (witness_index, witness) in language.strings.iter().enumerate() {
            let selected_index = match suffix {
                Some(suffix) => {
                    self.root_reverse_suffix_selected_row(&language.strings, suffix, witness)?
                }
                None => self.root_source_priority_selected_row(&language.strings, witness_index)?,
            };
            let Some(selected_index) = selected_index else {
                continue;
            };
            for (trace, outcome) in root.capture_traces.iter().zip(&mut outcomes) {
                match trace {
                    CaptureTrace::All => *outcome |= 0b01,
                    CaptureTrace::None => *outcome |= 0b10,
                    CaptureTrace::Bits(words) => {
                        self.charge(1, "root capture trace classification")?;
                        if capture_trace_bit(words, selected_index)? {
                            *outcome |= 0b01;
                        } else {
                            *outcome |= 0b10;
                        }
                    }
                    CaptureTrace::Unavailable => *outcome |= 0b100,
                }
            }
        }
        for (capture, outcome) in root.captures.iter_mut().zip(outcomes.iter().copied()) {
            capture.participation = match outcome {
                0b01 => CaptureParticipation::Always,
                0b10 => CaptureParticipation::Never,
                0b11 => CaptureParticipation::Maybe,
                _ => capture.participation,
            };
        }
        self.release_local_bytes(root.captures.len())?;
        Ok(())
    }

    fn root_source_priority_selected_row(
        &mut self,
        rows: &[Vec<u8>],
        candidate_index: usize,
    ) -> Result<Option<usize>, FactError> {
        let candidate = rows
            .get(candidate_index)
            .ok_or(FactError::InternalInvariant {
                detail: "root capture candidate row disappeared",
            })?;
        self.charge(1, "root capture-priority candidate")?;
        for predecessor in &rows[..candidate_index] {
            self.charge(1, "root capture-priority predecessor")?;
            // It is safe to compare every earlier derivation, including one
            // that is itself shadowed: its earlier shadower is also a prefix
            // of this candidate by prefix transitivity.
            if self.is_prefix_metered(predecessor, candidate)? {
                return Ok(None);
            }
        }
        Ok(Some(candidate_index))
    }

    fn certified_reverse_suffix<'a>(
        &mut self,
        language: &'a FiniteLanguage,
        traces: &[CaptureTrace],
    ) -> Result<Option<&'a [u8]>, FactError> {
        self.charge_usize(
            mul_usize(
                language.total_bytes(),
                2,
                "root reverse-suffix common-affix work",
            )?,
            "root reverse-suffix common-affix work",
        )?;
        let suffix = common_suffix(&language.strings);
        if suffix.len() != 1 {
            return Ok(None);
        }
        let mut has_bits = false;
        for trace in traces {
            self.charge(1, "root reverse-suffix certificate trace availability")?;
            if matches!(trace, CaptureTrace::Bits(_)) {
                has_bits = true;
                break;
            }
        }
        if !has_bits {
            return Ok(None);
        }
        let mut short = None;
        for (index, row) in language.strings.iter().enumerate() {
            self.charge(1, "root reverse-suffix certificate pivot")?;
            if row.as_slice() == suffix {
                short = Some(index);
                break;
            }
        }
        let Some(short) = short else {
            return Ok(None);
        };
        let mut saw_distinct_signature = false;
        for (index, row) in language.strings.iter().enumerate() {
            let Some(same_signature) = self.root_trace_signatures_equal(traces, short, index)?
            else {
                return Ok(None);
            };
            if row.as_slice() == suffix {
                if !same_signature {
                    return Ok(None);
                }
                continue;
            }
            if same_signature {
                continue;
            }
            saw_distinct_signature = true;
            if !self.is_certified_reverse_suffix_long(row, suffix)? {
                return Ok(None);
            }
            if !self.reverse_suffix_pivot_is_unambiguous(&language.strings, row, suffix)? {
                return Ok(None);
            }
        }
        Ok(saw_distinct_signature.then_some(suffix))
    }

    fn root_trace_signatures_equal(
        &mut self,
        traces: &[CaptureTrace],
        left: usize,
        right: usize,
    ) -> Result<Option<bool>, FactError> {
        for trace in traces {
            self.charge(1, "root reverse-suffix certificate signature slot")?;
            let Some(left_value) = self.root_trace_value(trace, left)? else {
                return Ok(None);
            };
            let Some(right_value) = self.root_trace_value(trace, right)? else {
                return Ok(None);
            };
            if left_value != right_value {
                return Ok(Some(false));
            }
        }
        Ok(Some(true))
    }

    fn root_trace_value(
        &mut self,
        trace: &CaptureTrace,
        row: usize,
    ) -> Result<Option<bool>, FactError> {
        match trace {
            CaptureTrace::All => Ok(Some(true)),
            CaptureTrace::None => Ok(Some(false)),
            CaptureTrace::Bits(words) => {
                self.charge(1, "root reverse-suffix certificate trace")?;
                capture_trace_bit(words, row).map(Some)
            }
            CaptureTrace::Unavailable => Ok(None),
        }
    }

    fn is_certified_reverse_suffix_long(
        &mut self,
        row: &[u8],
        suffix: &[u8],
    ) -> Result<bool, FactError> {
        let Some(prefix) = row.strip_suffix(suffix) else {
            return Ok(false);
        };
        if prefix.len() < 3 {
            return Ok(false);
        }
        self.charge(1, "root reverse-suffix long shape")?;
        if prefix.last() != suffix.first() {
            return Ok(false);
        }
        let earlier =
            prefix
                .get(..prefix.len().saturating_sub(1))
                .ok_or(FactError::InternalInvariant {
                    detail: "root reverse-suffix prefix disappeared",
                })?;
        for byte in earlier {
            self.charge(1, "root reverse-suffix earlier pivot")?;
            if Some(byte) == suffix.first() {
                return Ok(false);
            }
        }
        self.is_unbordered_root_suffix(prefix)
    }

    fn reverse_suffix_pivot_is_unambiguous(
        &mut self,
        rows: &[Vec<u8>],
        long: &[u8],
        suffix: &[u8],
    ) -> Result<bool, FactError> {
        let pivot_prefix = long
            .strip_suffix(suffix)
            .ok_or(FactError::InternalInvariant {
                detail: "root reverse-suffix long row lost its suffix",
            })?;
        for candidate in rows {
            self.charge(1, "root reverse-suffix pivot competitor")?;
            if candidate.len() <= suffix.len() {
                continue;
            }
            if self.root_row_ends_at(candidate, pivot_prefix)? {
                // The reverse selector would stop at this internal endpoint
                // and reapply source priority only to the suffix. That can
                // hide this full `long` derivation, so use the ordinary
                // whole-match selector instead.
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn is_unbordered_root_suffix(&mut self, bytes: &[u8]) -> Result<bool, FactError> {
        for border in 1..bytes.len() {
            self.charge(1, "root reverse-suffix border")?;
            let suffix_start =
                bytes
                    .len()
                    .checked_sub(border)
                    .ok_or(FactError::InternalInvariant {
                        detail: "root reverse-suffix border exceeded its prefix",
                    })?;
            let mut equal = true;
            for (left, right) in bytes[..border].iter().zip(&bytes[suffix_start..]) {
                self.charge(1, "root reverse-suffix border byte")?;
                if left != right {
                    equal = false;
                    break;
                }
            }
            if equal {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn root_reverse_suffix_selected_row(
        &mut self,
        rows: &[Vec<u8>],
        suffix: &[u8],
        witness: &[u8],
    ) -> Result<Option<usize>, FactError> {
        if suffix.is_empty() || suffix.len() > witness.len() {
            return Ok(None);
        }
        let last_offset =
            witness
                .len()
                .checked_sub(suffix.len())
                .ok_or(FactError::InternalInvariant {
                    detail: "root capture suffix exceeded its witness",
                })?;
        for offset in 0..=last_offset {
            if !self.root_suffix_matches_at(witness, suffix, offset)? {
                continue;
            }
            let end = offset
                .checked_add(suffix.len())
                .ok_or(FactError::ArithmeticOverflow {
                    computation: "root capture suffix end",
                })?;
            let mut selected: Option<usize> = None;
            for (index, row) in rows.iter().enumerate() {
                if !self.root_row_ends_at(row, &witness[..end])? {
                    continue;
                }
                if selected.is_none_or(|current| row.len() > rows[current].len()) {
                    selected = Some(index);
                }
            }
            if let Some(reverse_row) = selected {
                let start = end.checked_sub(rows[reverse_row].len()).ok_or(
                    FactError::InternalInvariant {
                        detail: "root reverse-suffix row exceeded its end",
                    },
                )?;
                return self.root_anchored_source_priority_selected_row(rows, &witness[start..]);
            }
        }
        Ok(None)
    }

    fn root_anchored_source_priority_selected_row(
        &mut self,
        rows: &[Vec<u8>],
        haystack: &[u8],
    ) -> Result<Option<usize>, FactError> {
        for (index, row) in rows.iter().enumerate() {
            self.charge(1, "root capture-forward row")?;
            if self.is_prefix_metered(row, haystack)? {
                return Ok(Some(index));
            }
        }
        Ok(None)
    }

    fn root_suffix_matches_at(
        &mut self,
        witness: &[u8],
        suffix: &[u8],
        offset: usize,
    ) -> Result<bool, FactError> {
        self.charge(1, "root capture-suffix offset")?;
        let end = offset
            .checked_add(suffix.len())
            .ok_or(FactError::ArithmeticOverflow {
                computation: "root capture suffix comparison end",
            })?;
        let candidate = witness
            .get(offset..end)
            .ok_or(FactError::InternalInvariant {
                detail: "root capture suffix comparison exceeded its witness",
            })?;
        for (left, right) in suffix.iter().zip(candidate) {
            self.charge(1, "root capture-suffix byte")?;
            if left != right {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn root_row_ends_at(&mut self, row: &[u8], prefix: &[u8]) -> Result<bool, FactError> {
        self.charge(1, "root capture-suffix row")?;
        let Some(start) = prefix.len().checked_sub(row.len()) else {
            return Ok(false);
        };
        for (left, right) in row.iter().zip(&prefix[start..]) {
            self.charge(1, "root capture-suffix row byte")?;
            if left != right {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn empty_composite(
        &mut self,
        children: Vec<NodeFacts>,
        _concatenation: bool,
    ) -> Result<NodeFacts, FactError> {
        let unicode = self.merge_unicode(children.iter().map(|child| &child.unicode))?;
        let capture_count = children.iter().try_fold(0_usize, |total, child| {
            add_usize(total, child.captures.len(), "empty-language capture facts")
        })?;
        let mut captures = self.vector(capture_count, "empty-language capture facts")?;
        let mut capture_traces = self.vector(capture_count, "empty-language capture traces")?;
        let mut thompson_states = 1_usize;
        let mut duplicates = 0_usize;
        for child in children {
            for mut capture in child.captures {
                capture.participation = CaptureParticipation::Never;
                captures.push(capture);
                capture_traces.push(CaptureTrace::None);
            }
            thompson_states = add_usize(
                thompson_states,
                child.thompson_states,
                "empty-language Thompson states",
            )?;
            duplicates = add_usize(
                duplicates,
                child.duplicate_consuming_alternatives,
                "empty-language duplicate alternatives",
            )?;
        }
        Ok(NodeFacts {
            width: CheckedWidth::EmptyLanguage,
            finite: self.empty_finite()?,
            required: self.empty_required(),
            possible_assertions: self.empty_assertions(),
            required_assertions: self.empty_assertions(),
            captures,
            capture_traces,
            capture_trace_ordered: true,
            unicode,
            first: FirstBytes::empty(true),
            one_pass_shape: true,
            thompson_states,
            duplicate_consuming_alternatives: duplicates,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "root publication validates every prospective and actual ledger field together"
    )]
    fn finish_root(mut self, mut root: NodeFacts) -> Result<HirFacts, FactError> {
        self.refine_root_capture_participation(&mut root)?;
        if let FactProof::Proven(assertions) = &root.possible_assertions {
            self.charge_usize(assertions.len(), "assertion context publication")?;
        }
        let (maximum_look_behind_bytes, maximum_look_ahead_bytes) =
            assertion_context_requirements(&root.possible_assertions);
        // This is a structural possible-path fact, not a deduction from the
        // optional positioned-assertion proof. In particular, a refused proof
        // must not turn every assertion-bearing pattern into a stream-end one.
        let requires_stream_end = self.possible_contains_stream_end;
        let assertions = AssertionFacts {
            possible: root.possible_assertions,
            required: root.required_assertions,
            maximum_look_behind_bytes,
            maximum_look_ahead_bytes,
            requires_stream_end,
        };
        let scalar_alternatives = match (root.unicode.scalar_strings, root.unicode.scalar_refusal) {
            (Some(strings), _) => {
                let total_bytes = strings.iter().try_fold(0_usize, |total, string| {
                    add_usize(total, string.len(), "Unicode scalar fact bytes")
                })?;
                FactProof::Proven(FiniteLanguage {
                    strings,
                    total_bytes,
                })
            }
            (None, Some(refusal)) => FactProof::Refused(refusal),
            (None, None) => FactProof::Unknown,
        };
        let unicode = UnicodeFacts {
            class_count: root.unicode.class_count,
            scalar_range_count: root.unicode.scalar_range_count,
            scalar_count: root.unicode.scalar_count,
            utf8_width_mask: root.unicode.utf8_width_mask,
            contains_non_ascii: root.unicode.contains_non_ascii,
            width_changing_alternatives: root.unicode.width_changing_alternatives,
            scalar_alternatives,
            simple_fold_origin: FactProof::Refused(FactRefusal::OriginUnavailable),
            full_fold_equivalence: FactProof::Refused(FactRefusal::OriginUnavailable),
        };
        let preconditions = CertificatePreconditions {
            output: self.operation.output,
            preserves_priority: true,
            preserves_greediness: true,
            preserves_empty_progress: true,
            preserves_assertion_context: matches!(
                assertions.possible,
                FactProof::Proven(ref facts) if facts.is_empty()
            ),
            preserves_captures: !self.operation.observes_captures(),
        };
        let complete_thompson_states =
            add_usize(root.thompson_states, 1, "final accept state bound")?;
        let subset = self.subset_certificate(
            complete_thompson_states,
            preconditions,
            &assertions.possible,
        )?;
        let one_pass = if !self.operation.requests_determinism() {
            FactProof::Refused(FactRefusal::NotRequested)
        } else if self.operation.observes_captures() {
            FactProof::Refused(FactRefusal::CapturesObservable)
        } else if !matches!(
            assertions.possible,
            FactProof::Proven(ref facts) if facts.is_empty()
        ) {
            FactProof::Refused(FactRefusal::AssertionContext)
        } else if root.one_pass_shape {
            FactProof::Proven(OnePassCertificate {
                thompson_states_upper_bound: complete_thompson_states,
                preconditions,
            })
        } else {
            FactProof::Refused(FactRefusal::OrderedAmbiguity)
        };
        let determinism = DeterminismFacts {
            thompson_states_upper_bound: complete_thompson_states,
            subset,
            one_pass,
        };
        let reductions = self.reduction_facts(
            &root.finite,
            root.duplicate_consuming_alternatives,
            &assertions.possible,
            preconditions,
        )?;
        let finite_decision_horizon_bytes = if self.operation.requests_assertion_context() {
            match (root.width, &assertions.possible) {
                // Absolute stream end is an intrinsic whole-input dependency,
                // independent of whether the optional positioned-assertion
                // context was published. The facade separately projects
                // unavailable context as AssertionContext rather than
                // mistaking it for a finite decision horizon.
                (CheckedWidth::NonEmpty { .. }, _) if requires_stream_end => FactProof::Unknown,
                (_, FactProof::Refused(refusal)) => FactProof::Refused(*refusal),
                (_, FactProof::Unknown) => FactProof::Unknown,
                (CheckedWidth::EmptyLanguage, FactProof::Proven(_)) => FactProof::Proven(0),
                (
                    CheckedWidth::NonEmpty {
                        maximum: Some(maximum),
                        ..
                    },
                    FactProof::Proven(_),
                ) => match maximum.checked_add(maximum_look_ahead_bytes) {
                    Some(horizon) => FactProof::Proven(horizon),
                    None => FactProof::Refused(FactRefusal::ArithmeticOverflow {
                        computation: "finite decision horizon",
                    }),
                },
                (CheckedWidth::NonEmpty { maximum: None, .. }, FactProof::Proven(_)) => {
                    FactProof::Unknown
                }
            }
        } else {
            FactProof::Refused(FactRefusal::NotRequested)
        };
        let (required_groups, required_alternatives, required_bytes) =
            required_metrics(&root.required)?;
        let (finite_strings, finite_string_bytes) = match &root.finite {
            FactProof::Proven(language) => (language.len(), language.total_bytes()),
            FactProof::Unknown | FactProof::Refused(_) => (0, 0),
        };
        let retained_bytes = published_logical_bytes(
            &root.finite,
            &root.required,
            &assertions,
            &unicode,
            &root.captures,
            &reductions,
        )?;
        self.live_result_bytes = 0;
        self.live_local_bytes = 0;
        Self::check_hard(
            FactResource::RetainedBytes,
            retained_bytes,
            self.limits.max_retained_bytes,
        )?;
        self.peak_bytes = self.peak_bytes.max(retained_bytes);
        Self::check_hard(
            FactResource::PeakBytes,
            self.peak_bytes,
            self.limits.max_peak_bytes,
        )?;
        let prospective = self.prospective;
        let stats = FactStats {
            work: self.work,
            peak_stack_items: self.peak_stack_items,
            hir_nodes: self.hir_nodes,
            retained_bytes,
            temporary_bytes: self.peak_temporary_bytes,
            peak_bytes: self.peak_bytes,
            allocation_attempts: self.allocation_attempts,
            required_groups,
            required_alternatives,
            required_bytes,
            finite_strings,
            finite_string_bytes,
        };
        validate_actual_within_prospective(stats, prospective)?;
        Ok(HirFacts {
            identity: FactIdentity::current(),
            operation: self.operation,
            width: root.width,
            finite_language: root.finite,
            required: root.required,
            assertions,
            unicode,
            captures: CaptureFacts {
                captures: root.captures,
                observable: self.operation.observes_captures(),
                source_schema_complete: FactProof::Refused(FactRefusal::OriginUnavailable),
            },
            determinism,
            reductions,
            finite_decision_horizon_bytes,
            prospective,
            stats,
        })
    }

    fn subset_certificate(
        &mut self,
        thompson_states: usize,
        preconditions: CertificatePreconditions,
        assertions: &FactProof<Vec<PositionedAssertion>>,
    ) -> Result<FactProof<DeterministicCertificate>, FactError> {
        if !self.operation.requests_determinism() {
            return Ok(FactProof::Refused(FactRefusal::NotRequested));
        }
        if self.operation.observes_captures() {
            return Ok(FactProof::Refused(FactRefusal::CapturesObservable));
        }
        if !matches!(assertions, FactProof::Proven(facts) if facts.is_empty()) {
            return Ok(FactProof::Refused(FactRefusal::AssertionContext));
        }
        let Some(subset_states) = ordered_subset_bound(thompson_states) else {
            return Ok(FactProof::Refused(FactRefusal::ArithmeticOverflow {
                computation: "priority-ordered deterministic state bound",
            }));
        };
        if subset_states > self.limits.max_deterministic_states {
            return Ok(FactProof::Refused(Self::refusal(
                FactResource::DeterministicStates,
                subset_states,
                self.limits.max_deterministic_states,
            )?));
        }
        Ok(FactProof::Proven(DeterministicCertificate {
            thompson_states_upper_bound: thompson_states,
            subset_states_upper_bound: subset_states,
            preconditions,
        }))
    }

    fn reduction_facts(
        &mut self,
        finite: &FactProof<FiniteLanguage>,
        _syntactic_duplicates: usize,
        assertions: &FactProof<Vec<PositionedAssertion>>,
        preconditions: CertificatePreconditions,
    ) -> Result<ReductionFacts, FactError> {
        if !self.operation.requests_reductions() {
            return Ok(ReductionFacts {
                common_prefix: FactProof::Refused(FactRefusal::NotRequested),
                common_suffix: FactProof::Refused(FactRefusal::NotRequested),
                duplicate_consuming_alternatives: FactProof::Refused(FactRefusal::NotRequested),
            });
        }
        if self.operation.observes_captures() {
            return Ok(ReductionFacts {
                common_prefix: FactProof::Refused(FactRefusal::CapturesObservable),
                common_suffix: FactProof::Refused(FactRefusal::CapturesObservable),
                duplicate_consuming_alternatives: FactProof::Refused(
                    FactRefusal::CapturesObservable,
                ),
            });
        }
        if !matches!(assertions, FactProof::Proven(facts) if facts.is_empty()) {
            return Ok(ReductionFacts {
                common_prefix: FactProof::Refused(FactRefusal::AssertionContext),
                common_suffix: FactProof::Refused(FactRefusal::AssertionContext),
                duplicate_consuming_alternatives: FactProof::Refused(FactRefusal::AssertionContext),
            });
        }
        let language = match finite {
            FactProof::Proven(language) => language,
            FactProof::Unknown => {
                return Ok(ReductionFacts {
                    common_prefix: FactProof::Unknown,
                    common_suffix: FactProof::Unknown,
                    duplicate_consuming_alternatives: FactProof::Unknown,
                });
            }
            FactProof::Refused(refusal) => {
                return Ok(ReductionFacts {
                    common_prefix: FactProof::Refused(*refusal),
                    common_suffix: FactProof::Refused(*refusal),
                    duplicate_consuming_alternatives: FactProof::Refused(*refusal),
                });
            }
        };
        self.charge_usize(
            mul_usize(language.total_bytes(), 2, "common-affix comparison work")?,
            "common-affix comparison work",
        )?;
        let prefix = common_prefix(&language.strings);
        let suffix = common_suffix(&language.strings);
        let duplicate_consuming_alternatives = self.duplicate_reduction(language)?;
        Ok(ReductionFacts {
            common_prefix: if prefix.is_empty() {
                FactProof::Unknown
            } else {
                FactProof::Proven(AffixCertificate {
                    bytes: self.copy_bytes(prefix, "common-prefix certificate")?,
                    preconditions,
                })
            },
            common_suffix: if suffix.is_empty() {
                FactProof::Unknown
            } else {
                FactProof::Proven(AffixCertificate {
                    bytes: self.copy_bytes(suffix, "common-suffix certificate")?,
                    preconditions,
                })
            },
            duplicate_consuming_alternatives,
        })
    }

    fn duplicate_reduction(
        &mut self,
        language: &FiniteLanguage,
    ) -> Result<FactProof<usize>, FactError> {
        let Some(work) = duplicate_reduction_work_bound(LanguageMeasure {
            count: language.len(),
            bytes: language.total_bytes(),
        }) else {
            return Ok(FactProof::Refused(FactRefusal::ArithmeticOverflow {
                computation: "duplicate-reduction work",
            }));
        };
        let needed = self
            .work
            .checked_add(to_u64(work, "duplicate-reduction work conversion")?)
            .ok_or(FactError::ArithmeticOverflow {
                computation: "duplicate-reduction work",
            })?;
        if needed > self.prospective.work {
            return Ok(FactProof::Refused(FactRefusal::Limit {
                resource: FactResource::Work,
                needed,
                limit: self.prospective.work,
            }));
        }
        self.charge_usize(work, "duplicate-reduction proof")?;
        let mut order = self.vector(language.len(), "duplicate-reduction order")?;
        order.extend(0..language.len());
        order
            .sort_unstable_by(|&left, &right| language.strings[left].cmp(&language.strings[right]));
        let duplicates = order
            .windows(2)
            .filter(|pair| language.strings[pair[0]] == language.strings[pair[1]])
            .count();
        self.release_local_bytes(mul_usize(
            order.len(),
            size_of::<usize>(),
            "duplicate-reduction order bytes",
        )?)?;
        Ok(FactProof::Proven(duplicates))
    }
}
