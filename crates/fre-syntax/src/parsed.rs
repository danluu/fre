use regex_syntax::{
    ast::{Ast, Comment},
    hir::Hir,
};
use std::sync::Arc;

use crate::{
    AdmissionPolicy, CompatibilityProfile, ParseError, ResourceKind, RustAstOptions, SafetyEnvelope,
};

pub const SCHEMA_VERSION: u32 = 3;
/// Version of the receipt-bearing Rust parse-attempt algorithm.
pub const PARSE_ATTEMPT_ALGORITHM_VERSION: u32 = 1;
/// Version of the parse-attempt prospective/actual accounting schema.
pub const PARSE_ATTEMPT_ACCOUNTING_VERSION: u32 = 2;

/// Pattern source is bytes because RE2's Latin-1 surface is not a Rust `str`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PatternBytes(Vec<u8>);

impl PatternBytes {
    #[must_use]
    pub fn from_utf8(pattern: impl Into<String>) -> Self {
        Self(pattern.into().into_bytes())
    }

    #[must_use]
    pub fn from_bytes(pattern: impl Into<Vec<u8>>) -> Self {
        Self(pattern.into())
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume this source identity without copying its retained bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Exact retained byte capacity of this owned source identity.
    #[must_use]
    pub fn capacity_bytes(&self) -> usize {
        self.0.capacity()
    }

    pub(crate) fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.0).ok()
    }
}

/// Immutable parse input. Profile, admission and hard-safety identities all
/// become part of the output cache key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ParseRequest {
    pattern: PatternBytes,
    profile: CompatibilityProfile,
    admission: AdmissionPolicy,
    safety: SafetyEnvelope,
    attempt_source_owner: ParseAttemptSourceOwnerEvidence,
}

impl ParseRequest {
    #[must_use]
    pub fn rust(pattern: impl Into<String>, profile: CompatibilityProfile) -> Self {
        Self {
            pattern: PatternBytes::from_utf8(pattern),
            profile,
            admission: AdmissionPolicy::default(),
            safety: SafetyEnvelope::default(),
            attempt_source_owner: ParseAttemptSourceOwnerEvidence::default(),
        }
    }

    #[must_use]
    pub fn re2(pattern: impl Into<Vec<u8>>, profile: CompatibilityProfile) -> Self {
        Self {
            pattern: PatternBytes::from_bytes(pattern),
            profile,
            admission: AdmissionPolicy::default(),
            safety: SafetyEnvelope::default(),
            attempt_source_owner: ParseAttemptSourceOwnerEvidence::default(),
        }
    }

    #[must_use]
    pub fn with_admission(mut self, admission: AdmissionPolicy) -> Self {
        self.admission = admission;
        self
    }

    #[must_use]
    pub fn with_safety_envelope(mut self, safety: SafetyEnvelope) -> Self {
        self.safety = safety;
        self
    }

    #[must_use]
    pub const fn profile(&self) -> &CompatibilityProfile {
        &self.profile
    }

    #[must_use]
    pub const fn admission(&self) -> AdmissionPolicy {
        self.admission
    }

    #[must_use]
    pub const fn safety_envelope(&self) -> SafetyEnvelope {
        self.safety
    }

    #[must_use]
    pub const fn pattern(&self) -> &PatternBytes {
        &self.pattern
    }

    /// Exact allocation-bound identity used by receipt-bearing construction
    /// owners before this request moves into either a cache key or terminal
    /// error.
    #[must_use]
    pub fn attempt_identity(&self) -> ParseAttemptIdentity {
        ParseAttemptIdentity::for_request(self)
    }

    /// Complete input-derived syntax envelope used by a parent construction
    /// transaction before parsing begins.
    #[must_use]
    pub fn attempt_prospective(&self) -> ParseAttemptProspective {
        ParseAttemptProspective::for_request(self)
    }

    /// Bind one stable allocation-backed owner before a receipt-bearing
    /// parent construction begins source access.
    ///
    /// Returns the exact logical owner-allocation bytes, or `None` when this
    /// request was already bound.
    #[must_use]
    pub fn bind_attempt_source_owner(&mut self) -> Option<usize> {
        self.attempt_source_owner
            .bind()
            .then_some(Self::attempt_source_owner_allocation_bytes())
    }

    /// Exact logical bytes in the stable source-owner allocation: the two
    /// `Arc` ownership words plus the zero-sized opaque token.
    #[must_use]
    pub const fn attempt_source_owner_allocation_bytes() -> usize {
        core::mem::size_of::<[usize; 2]>()
    }

    /// Exact inline bytes in one strong handle to the stable source owner.
    ///
    /// Parent transactions use this separately from
    /// [`Self::attempt_source_owner_allocation_bytes`] when a request,
    /// receipt, or cache identity clones the allocation-backed provenance.
    #[must_use]
    pub const fn attempt_source_owner_handle_bytes() -> usize {
        core::mem::size_of::<ParseAttemptSourceOwnerEvidence>()
    }

    pub(crate) fn validate_and_charge_source(&self) -> Result<(), ParseError> {
        self.admission
            .check_source(&self.profile, &self.pattern, self.safety)
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        PatternBytes,
        CompatibilityProfile,
        AdmissionPolicy,
        SafetyEnvelope,
        ParseAttemptSourceOwnerEvidence,
    ) {
        (
            self.pattern,
            self.profile,
            self.admission,
            self.safety,
            self.attempt_source_owner,
        )
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CacheKey {
    pub schema_version: u32,
    pub pattern: PatternBytes,
    pub profile: CompatibilityProfile,
    pub admission: AdmissionPolicy,
    pub safety: SafetyEnvelope,
    pub(crate) attempt_source_owner: ParseAttemptSourceOwnerEvidence,
}

#[derive(Debug)]
struct ParseAttemptSourceOwnerToken;

/// Provenance is deliberately excluded from semantic request/cache equality;
/// receipt authentication compares its allocation identity explicitly.
#[derive(Clone, Default)]
pub(crate) struct ParseAttemptSourceOwnerEvidence(Option<Arc<ParseAttemptSourceOwnerToken>>);

impl ParseAttemptSourceOwnerEvidence {
    fn bind(&mut self) -> bool {
        if self.0.is_some() {
            return false;
        }
        self.0 = Some(Arc::new(ParseAttemptSourceOwnerToken));
        true
    }

    fn ptr_eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (Some(left), Some(right)) => Arc::ptr_eq(left, right),
            (None, None) => true,
            _ => false,
        }
    }

    const fn is_bound(&self) -> bool {
        self.0.is_some()
    }
}

impl core::fmt::Debug for ParseAttemptSourceOwnerEvidence {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("ParseAttemptSourceOwnerEvidence")
            .field(&if self.is_bound() { "bound" } else { "unbound" })
            .finish()
    }
}

impl PartialEq for ParseAttemptSourceOwnerEvidence {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for ParseAttemptSourceOwnerEvidence {}

impl core::hash::Hash for ParseAttemptSourceOwnerEvidence {
    fn hash<H: core::hash::Hasher>(&self, _state: &mut H) {}
}

impl PartialOrd for ParseAttemptSourceOwnerEvidence {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ParseAttemptSourceOwnerEvidence {
    fn cmp(&self, _other: &Self) -> core::cmp::Ordering {
        core::cmp::Ordering::Equal
    }
}

/// The only post-attempt action permitted by the syntax layer.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ParseAttemptDeclaredFallback {
    /// A syntax failure is terminal for this exact request.
    None,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ParseAttemptSourceOrigin(usize);

impl ParseAttemptSourceOrigin {
    fn for_pattern(pattern: &PatternBytes) -> Self {
        Self(pattern.as_bytes().as_ptr().addr())
    }

    const fn is_bound(self) -> bool {
        self.0 != 0
    }
}

impl core::fmt::Debug for ParseAttemptSourceOrigin {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("ParseAttemptSourceOrigin")
            .field(&if self.is_bound() { "bound" } else { "unbound" })
            .finish()
    }
}

/// Immutable identity of one receipt-bearing Rust syntax attempt.
///
/// The exact source bytes live once in either the successful [`CacheKey`] or
/// the terminal [`ParseRequest`][crate::ParseAttemptError::request]. The
/// identity deliberately does not duplicate them or replace them with a
/// probabilistic digest. Unbound identities remain available for legacy parse
/// compatibility, but a parent transaction that needs ABA-resistant closure
/// must bind first and require [`Self::has_stable_source_owner`].
#[derive(Clone, Debug)]
pub struct ParseAttemptIdentity {
    pub schema_version: u32,
    pub profile: CompatibilityProfile,
    pub admission: AdmissionPolicy,
    pub safety: SafetyEnvelope,
    pub source_bytes: u64,
    source_capacity_bytes: usize,
    source_origin: ParseAttemptSourceOrigin,
    attempt_source_owner: ParseAttemptSourceOwnerEvidence,
    pub algorithm_version: u32,
    pub accounting_version: u32,
    pub declared_fallback: ParseAttemptDeclaredFallback,
}

impl ParseAttemptIdentity {
    pub(crate) fn for_request(request: &ParseRequest) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            profile: request.profile.clone(),
            admission: request.admission,
            safety: request.safety,
            source_bytes: u64::try_from(request.pattern.as_bytes().len()).unwrap_or(u64::MAX),
            source_capacity_bytes: request.pattern.capacity_bytes(),
            source_origin: ParseAttemptSourceOrigin::for_pattern(&request.pattern),
            attempt_source_owner: request.attempt_source_owner.clone(),
            algorithm_version: PARSE_ATTEMPT_ALGORITHM_VERSION,
            accounting_version: PARSE_ATTEMPT_ACCOUNTING_VERSION,
            declared_fallback: ParseAttemptDeclaredFallback::None,
        }
    }

    /// Check every immutable request field without copying its source bytes.
    #[must_use]
    pub fn authenticates_request(&self, request: &ParseRequest) -> bool {
        self.schema_version == SCHEMA_VERSION
            && self.profile == request.profile
            && self.admission == request.admission
            && self.safety == request.safety
            && u64::try_from(request.pattern.as_bytes().len()) == Ok(self.source_bytes)
            && self.source_capacity_bytes == request.pattern.capacity_bytes()
            && self.source_origin == ParseAttemptSourceOrigin::for_pattern(&request.pattern)
            && self.source_origin.is_bound()
            && self
                .attempt_source_owner
                .ptr_eq(&request.attempt_source_owner)
            && self.algorithm_version == PARSE_ATTEMPT_ALGORITHM_VERSION
            && self.accounting_version == PARSE_ATTEMPT_ACCOUNTING_VERSION
            && self.declared_fallback == ParseAttemptDeclaredFallback::None
    }

    /// Check the exact successful cache-key owner after the request's source
    /// allocation moves into it.
    #[must_use]
    pub fn authenticates_key(&self, key: &CacheKey) -> bool {
        self.schema_version == SCHEMA_VERSION
            && self.schema_version == key.schema_version
            && self.profile == key.profile
            && self.admission == key.admission
            && self.safety == key.safety
            && u64::try_from(key.pattern.as_bytes().len()) == Ok(self.source_bytes)
            && self.source_capacity_bytes == key.pattern.capacity_bytes()
            && self.source_origin == ParseAttemptSourceOrigin::for_pattern(&key.pattern)
            && self.source_origin.is_bound()
            && self.attempt_source_owner.ptr_eq(&key.attempt_source_owner)
            && self.algorithm_version == PARSE_ATTEMPT_ALGORITHM_VERSION
            && self.accounting_version == PARSE_ATTEMPT_ACCOUNTING_VERSION
            && self.declared_fallback == ParseAttemptDeclaredFallback::None
    }

    /// Exact capacity of the sole retained source allocation.
    #[must_use]
    pub const fn source_capacity_bytes(&self) -> usize {
        self.source_capacity_bytes
    }

    /// Whether this identity carries an opaque live source provenance.
    #[must_use]
    pub const fn has_bound_source_origin(&self) -> bool {
        self.source_origin.is_bound()
    }

    /// Whether the receipt keeps a stable allocation-backed source owner that
    /// prevents address-reuse authentication.
    #[must_use]
    pub const fn has_stable_source_owner(&self) -> bool {
        self.attempt_source_owner.is_bound()
    }
}

impl PartialEq for ParseAttemptIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.schema_version == other.schema_version
            && self.profile == other.profile
            && self.admission == other.admission
            && self.safety == other.safety
            && self.source_bytes == other.source_bytes
            && self.source_capacity_bytes == other.source_capacity_bytes
            && self.source_origin == other.source_origin
            && self
                .attempt_source_owner
                .ptr_eq(&other.attempt_source_owner)
            && self.algorithm_version == other.algorithm_version
            && self.accounting_version == other.accounting_version
            && self.declared_fallback == other.declared_fallback
    }
}

impl Eq for ParseAttemptIdentity {}

/// Complete input-only reservation published before syntax effects begin.
///
/// `source_bytes` is an admission reservation, not observed parser progress.
/// `max_observed_work` is the remaining explicit visitor/summarizer work
/// allowed after that reservation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ParseAttemptProspective {
    pub source_bytes: u64,
    pub max_observed_work: u64,
    pub max_hir_nodes: u64,
    pub max_nesting: u64,
    pub max_traversal_stack_items: u64,
    pub max_source_admission_checks: u8,
    pub max_configuration_checks: u8,
    pub max_opaque_parser_invocations: u8,
}

impl ParseAttemptProspective {
    pub(crate) fn for_request(request: &ParseRequest) -> Self {
        let source_bytes = u64::try_from(request.pattern.as_bytes().len()).unwrap_or(u64::MAX);
        let parse_work_limit = request
            .admission
            .limit_for(ResourceKind::ParseWork, request.safety);
        let traversal_limit = request
            .admission
            .limit_for(ResourceKind::TraversalStack, request.safety);
        Self {
            source_bytes,
            max_observed_work: parse_work_limit.saturating_sub(source_bytes),
            max_hir_nodes: request
                .admission
                .limit_for(ResourceKind::HirNodes, request.safety),
            max_nesting: request
                .admission
                .limit_for(ResourceKind::Nesting, request.safety),
            // The root is placed in the iterative stack before child-stack
            // quota checks begin.
            max_traversal_stack_items: traversal_limit.max(1),
            max_source_admission_checks: 1,
            max_configuration_checks: 1,
            // Full-feature parsing invokes one opaque parser. Restricted
            // Unicode profiles invoke the AST parser and HIR translator.
            max_opaque_parser_invocations: 2,
        }
    }

    /// Check every observed counter against this pre-effect reservation.
    #[must_use]
    pub fn contains(&self, actual: ParseAttemptActual) -> bool {
        let observed_work = actual
            .availability_work
            .checked_add(actual.hir_summary_work);
        observed_work == Some(actual.observed_work)
            && actual.observed_work <= self.max_observed_work
            && actual.hir_nodes <= self.max_hir_nodes
            && actual.max_depth <= self.max_nesting
            && actual.traversal_stack_peak <= self.max_traversal_stack_items
            && actual.source_admission_checks <= self.max_source_admission_checks
            && actual.configuration_checks <= self.max_configuration_checks
            && actual.opaque_parser_invocations <= self.max_opaque_parser_invocations
            && actual.literal_bytes <= actual.hir_summary_work
            && actual.class_ranges <= actual.hir_summary_work
            && actual.captures <= actual.hir_nodes
            && actual.repetitions <= actual.hir_nodes
    }
}

/// Exact syntax effects observed through the last admitted step.
///
/// Opaque parser internals are represented only by invocation counts. Source
/// length is never copied into an actual-work field.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ParseAttemptActual {
    pub source_admission_checks: u8,
    pub configuration_checks: u8,
    pub opaque_parser_invocations: u8,
    pub availability_work: u64,
    pub hir_summary_work: u64,
    pub observed_work: u64,
    pub hir_nodes: u64,
    pub literal_bytes: u64,
    pub class_ranges: u64,
    pub captures: u64,
    pub repetitions: u64,
    pub max_depth: u64,
    pub traversal_stack_peak: u64,
    authentication: ParseAttemptActualAuthentication,
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct ParseAttemptActualAuthentication {
    source_admission_checks: u8,
    configuration_checks: u8,
    opaque_parser_invocations: u8,
    availability_work: u64,
    hir_summary_work: u64,
    observed_work: u64,
    hir_nodes: u64,
    literal_bytes: u64,
    class_ranges: u64,
    captures: u64,
    repetitions: u64,
    max_depth: u64,
    traversal_stack_peak: u64,
}

impl ParseAttemptActual {
    pub(crate) fn authenticate_exact(&mut self) {
        self.authentication = ParseAttemptActualAuthentication {
            source_admission_checks: self.source_admission_checks,
            configuration_checks: self.configuration_checks,
            opaque_parser_invocations: self.opaque_parser_invocations,
            availability_work: self.availability_work,
            hir_summary_work: self.hir_summary_work,
            observed_work: self.observed_work,
            hir_nodes: self.hir_nodes,
            literal_bytes: self.literal_bytes,
            class_ranges: self.class_ranges,
            captures: self.captures,
            repetitions: self.repetitions,
            max_depth: self.max_depth,
            traversal_stack_peak: self.traversal_stack_peak,
        };
    }

    const fn authenticates_exact(self) -> bool {
        self.source_admission_checks == self.authentication.source_admission_checks
            && self.configuration_checks == self.authentication.configuration_checks
            && self.opaque_parser_invocations == self.authentication.opaque_parser_invocations
            && self.availability_work == self.authentication.availability_work
            && self.hir_summary_work == self.authentication.hir_summary_work
            && self.observed_work == self.authentication.observed_work
            && self.hir_nodes == self.authentication.hir_nodes
            && self.literal_bytes == self.authentication.literal_bytes
            && self.class_ranges == self.authentication.class_ranges
            && self.captures == self.authentication.captures
            && self.repetitions == self.authentication.repetitions
            && self.max_depth == self.authentication.max_depth
            && self.traversal_stack_peak == self.authentication.traversal_stack_peak
    }
}

/// Terminal state of one parse-attempt receipt.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ParseAttemptTerminal {
    Success,
    Failure,
}

/// Identity, P, cumulative A, and terminal state for one syntax attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseAttemptReceipt {
    pub identity: ParseAttemptIdentity,
    pub prospective: Option<ParseAttemptProspective>,
    pub actual: ParseAttemptActual,
    pub terminal: ParseAttemptTerminal,
    authenticated_prospective: Option<ParseAttemptProspective>,
    authenticated_terminal: ParseAttemptTerminal,
}

impl ParseAttemptReceipt {
    pub(crate) fn rust(request: &ParseRequest) -> Self {
        Self {
            identity: ParseAttemptIdentity::for_request(request),
            prospective: Some(ParseAttemptProspective::for_request(request)),
            actual: ParseAttemptActual::default(),
            terminal: ParseAttemptTerminal::Failure,
            authenticated_prospective: Some(ParseAttemptProspective::for_request(request)),
            authenticated_terminal: ParseAttemptTerminal::Failure,
        }
    }

    pub(crate) fn unsupported_profile(request: &ParseRequest) -> Self {
        Self {
            identity: ParseAttemptIdentity::for_request(request),
            prospective: None,
            actual: ParseAttemptActual::default(),
            terminal: ParseAttemptTerminal::Failure,
            authenticated_prospective: None,
            authenticated_terminal: ParseAttemptTerminal::Failure,
        }
    }

    /// Check the exact request owner and canonical P/A protocol.
    #[must_use]
    pub fn authenticates_request(&self, request: &ParseRequest) -> bool {
        self.identity.authenticates_request(request) && self.authenticates_canonical()
    }

    /// Check numeric versions, the no-fallback policy, and P=None=>A=0/A<=P.
    #[must_use]
    pub fn authenticates_canonical(&self) -> bool {
        self.identity.schema_version == SCHEMA_VERSION
            && self.identity.algorithm_version == PARSE_ATTEMPT_ALGORITHM_VERSION
            && self.identity.accounting_version == PARSE_ATTEMPT_ACCOUNTING_VERSION
            && self.identity.declared_fallback == ParseAttemptDeclaredFallback::None
            && self.prospective == self.authenticated_prospective
            && self.actual.authenticates_exact()
            && self.terminal == self.authenticated_terminal
            && self.prospective.map_or_else(
                || self.actual == ParseAttemptActual::default(),
                |prospective| {
                    prospective.source_bytes == self.identity.source_bytes
                        && prospective.contains(self.actual)
                },
            )
    }
}

/// What syntax parsing has established about local admission.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AdmissionStatus {
    /// Every strict FRE syntax and hard-safety check passed.
    StrictChecked,
    /// All caller-selected FRE syntax quotas were checked. This is not exact
    /// upstream resource compatibility.
    QuotaChecked,
}

impl AdmissionStatus {
    /// Compatibility spelling for the former pending-oracle state.
    ///
    /// No upstream oracle is pending under the native-size contract; the
    /// value is therefore an alias for [`Self::StrictChecked`].
    #[allow(non_upper_case_globals)]
    #[deprecated(
        since = "0.1.0",
        note = "native-size admission is complete after StrictChecked"
    )]
    pub const UpstreamOraclePending: Self = Self::StrictChecked;

    pub(crate) const fn from_policy(policy: AdmissionPolicy) -> Self {
        match policy {
            AdmissionPolicy::Strict(_) => Self::StrictChecked,
            AdmissionPolicy::Quota(_) => Self::QuotaChecked,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ParseSummary {
    pub hir_nodes: u64,
    pub max_depth: u64,
    pub parse_work: u64,
    pub literal_bytes: u64,
    pub class_ranges: u64,
    pub captures: u64,
    pub repetitions: u64,
    pub largest_finite_repeat: Option<u32>,
    pub guarantees_valid_utf8_nonempty: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RustParsed {
    pub hir: Hir,
}

/// Exact pinned `regex-syntax` AST plus the prospective resource reservation
/// that authorized its construction.
///
/// This record exists for source-addressable conformance work. Normal FRE
/// compilation consumes [`ParseRecord`] instead.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RustAstRecord {
    pub key: CacheKey,
    /// AST-only parser options completing this record's semantic identity.
    pub ast_options: RustAstOptions,
    pub admission_status: AdmissionStatus,
    pub reserved_ast_nodes: u64,
    pub reserved_max_nesting: u64,
    pub reserved_parser_stack: u64,
    pub reserved_parse_work: u64,
    pub ast: Ast,
    /// Source comments retained by the pinned parser, in source order.
    ///
    /// The aggregate comment text and span count are bounded by the already
    /// admitted source. The pinned parser constructs this side channel even
    /// for callers that subsequently discard it, so retaining it does not add
    /// unreserved parser work or peak parser allocation.
    pub comments: Vec<Comment>,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Re2Literal {
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Re2Parsed {
    pub ast: fre_re2_syntax::Ast,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalPattern {
    Rust(RustParsed),
    Re2Literal(Re2Literal),
    Re2(Re2Parsed),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseRecord {
    pub key: CacheKey,
    pub admission_status: AdmissionStatus,
    pub summary: ParseSummary,
    pub pattern: CanonicalPattern,
}

/// Successful Rust parse plus the same receipt schema exposed by terminal
/// attempts.
#[derive(Debug)]
pub struct ParseAttempt {
    record: ParseRecord,
    receipt: ParseAttemptReceipt,
}

impl ParseAttempt {
    pub(crate) fn new(record: ParseRecord, mut receipt: ParseAttemptReceipt) -> Self {
        receipt.terminal = ParseAttemptTerminal::Success;
        receipt.authenticated_terminal = ParseAttemptTerminal::Success;
        Self { record, receipt }
    }

    /// Parsed cache key, summary, and canonical HIR.
    #[must_use]
    pub const fn record(&self) -> &ParseRecord {
        &self.record
    }

    /// Complete identity/P/A/terminal receipt for this success.
    #[must_use]
    pub const fn receipt(&self) -> &ParseAttemptReceipt {
        &self.receipt
    }

    /// Consume the attempt without cloning the original source bytes.
    #[must_use]
    pub fn into_parts(self) -> (ParseRecord, ParseAttemptReceipt) {
        (self.record, self.receipt)
    }

    /// Consume the receipt wrapper while preserving the existing parse API's
    /// exact owned record.
    #[must_use]
    pub fn into_record(self) -> ParseRecord {
        self.record
    }

    /// Authenticate the successful cache owner and every observed syntax
    /// counter against the published reservation.
    #[must_use]
    pub fn closes(&self) -> bool {
        let receipt = &self.receipt;
        let actual = receipt.actual;
        let summary = &self.record.summary;
        let summary_work = receipt
            .prospective
            .and_then(|prospective| prospective.source_bytes.checked_add(actual.observed_work));
        receipt.terminal == ParseAttemptTerminal::Success
            && receipt.identity.authenticates_key(&self.record.key)
            && receipt.authenticates_canonical()
            && receipt.prospective.is_some()
            && actual.source_admission_checks == 1
            && actual.configuration_checks == 1
            && actual.opaque_parser_invocations >= 1
            && actual.hir_nodes == summary.hir_nodes
            && actual.literal_bytes == summary.literal_bytes
            && actual.class_ranges == summary.class_ranges
            && actual.captures == summary.captures
            && actual.repetitions == summary.repetitions
            && actual.max_depth == summary.max_depth
            && summary_work == Some(summary.parse_work)
    }
}
