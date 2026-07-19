use regex_syntax::{
    ast::{Ast, Comment},
    hir::Hir,
};

use crate::{AdmissionPolicy, CompatibilityProfile, ParseError, RustAstOptions, SafetyEnvelope};

pub const SCHEMA_VERSION: u32 = 2;

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
}

impl ParseRequest {
    #[must_use]
    pub fn rust(pattern: impl Into<String>, profile: CompatibilityProfile) -> Self {
        Self {
            pattern: PatternBytes::from_utf8(pattern),
            profile,
            admission: AdmissionPolicy::default(),
            safety: SafetyEnvelope::default(),
        }
    }

    #[must_use]
    pub fn re2(pattern: impl Into<Vec<u8>>, profile: CompatibilityProfile) -> Self {
        Self {
            pattern: PatternBytes::from_bytes(pattern),
            profile,
            admission: AdmissionPolicy::default(),
            safety: SafetyEnvelope::default(),
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
    ) {
        (self.pattern, self.profile, self.admission, self.safety)
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CacheKey {
    pub schema_version: u32,
    pub pattern: PatternBytes,
    pub profile: CompatibilityProfile,
    pub admission: AdmissionPolicy,
    pub safety: SafetyEnvelope,
}

/// What syntax parsing has established about constructor admission.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AdmissionStatus {
    /// Local syntax checks passed, but exact upstream constructor admission has
    /// not. The pinned upstream oracle must still run before compatibility is
    /// claimed.
    UpstreamOraclePending,
    /// All caller-selected FRE syntax quotas were checked. This is not exact
    /// upstream resource compatibility.
    QuotaChecked,
}

impl AdmissionStatus {
    pub(crate) const fn from_policy(policy: AdmissionPolicy) -> Self {
        match policy {
            AdmissionPolicy::Strict(_) => Self::UpstreamOraclePending,
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
