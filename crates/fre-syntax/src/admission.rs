use crate::{CompatibilityProfile, ErrorCategory, ParseError, PatternBytes};

/// Resource dimensions whose failure is reported without semantic relabeling.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ResourceKind {
    PatternBytes,
    Nesting,
    ParseWork,
    HirNodes,
    TraversalStack,
}

/// Selects FRE's strict, locally checked syntax-admission policy.
///
/// This applies the audited hard safety envelope without substituting
/// another regex engine's constructor or resource model.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StrictAdmission;

/// Caller-visible syntax quotas for the explicitly non-compatible service API.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SyntaxQuotas {
    pub max_pattern_bytes: u64,
    pub max_nesting: u64,
    pub max_hir_nodes: u64,
    pub max_parse_work: u64,
    pub max_traversal_stack: u64,
}

impl Default for SyntaxQuotas {
    fn default() -> Self {
        Self {
            max_pattern_bytes: 8 * (1 << 20),
            max_nesting: 250,
            max_hir_nodes: 1_000_000,
            max_parse_work: 16_000_000,
            max_traversal_stack: 262_144,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct QuotaBounded {
    pub syntax: SyntaxQuotas,
}

/// Admission mode is part of the cache key and error contract.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AdmissionPolicy {
    Strict(StrictAdmission),
    Quota(QuotaBounded),
}

impl Default for AdmissionPolicy {
    fn default() -> Self {
        Self::Strict(StrictAdmission)
    }
}

/// Non-configurable implementation safety envelope.
///
/// Crossing this boundary in strict mode is a qualification failure.
/// Production values can only be raised after auditing allocation and integer
/// bounds.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SafetyEnvelope {
    pub max_pattern_bytes: u64,
    pub max_nesting: u64,
    pub max_hir_nodes: u64,
    pub max_parse_work: u64,
    pub max_traversal_stack: u64,
}

impl Default for SafetyEnvelope {
    fn default() -> Self {
        Self {
            max_pattern_bytes: 32 * (1 << 20),
            max_nesting: 1_000_000,
            max_hir_nodes: 4_000_000,
            max_parse_work: 64_000_000,
            max_traversal_stack: 1_000_000,
        }
    }
}

impl AdmissionPolicy {
    pub(crate) fn check_source(
        self,
        profile: &CompatibilityProfile,
        pattern: &PatternBytes,
        safety: SafetyEnvelope,
    ) -> Result<(), ParseError> {
        let bytes = u64::try_from(pattern.as_bytes().len()).unwrap_or(u64::MAX);
        if bytes > safety.max_pattern_bytes {
            return Err(ParseError::new(
                profile.clone(),
                ErrorCategory::StrictQualificationFailure {
                    resource: ResourceKind::PatternBytes,
                    limit: safety.max_pattern_bytes,
                    observed: bytes,
                },
                "pattern exceeds FRE's audited hard safety envelope",
            ));
        }
        if let Self::Quota(quota) = self
            && bytes > quota.syntax.max_pattern_bytes
        {
            return Err(ParseError::new(
                profile.clone(),
                ErrorCategory::FreResourceLimit {
                    resource: ResourceKind::PatternBytes,
                    limit: quota.syntax.max_pattern_bytes,
                    observed: bytes,
                },
                "pattern exceeds the caller-selected FRE source quota",
            ));
        }
        let work_limit = self.limit_for(ResourceKind::ParseWork, safety);
        if bytes > work_limit {
            return Err(self.limit_error(profile.clone(), ResourceKind::ParseWork, safety, bytes));
        }
        Ok(())
    }

    pub(crate) const fn limit_for(self, resource: ResourceKind, safety: SafetyEnvelope) -> u64 {
        let hard = match resource {
            ResourceKind::PatternBytes => safety.max_pattern_bytes,
            ResourceKind::Nesting => safety.max_nesting,
            ResourceKind::TraversalStack => safety.max_traversal_stack,
            ResourceKind::ParseWork => safety.max_parse_work,
            ResourceKind::HirNodes => safety.max_hir_nodes,
        };
        match self {
            Self::Strict(_) => hard,
            Self::Quota(quota) => {
                let selected = match resource {
                    ResourceKind::PatternBytes => quota.syntax.max_pattern_bytes,
                    ResourceKind::Nesting => quota.syntax.max_nesting,
                    ResourceKind::TraversalStack => quota.syntax.max_traversal_stack,
                    ResourceKind::ParseWork => quota.syntax.max_parse_work,
                    ResourceKind::HirNodes => quota.syntax.max_hir_nodes,
                };
                if selected < hard { selected } else { hard }
            }
        }
    }

    pub(crate) fn limit_error(
        self,
        profile: CompatibilityProfile,
        resource: ResourceKind,
        safety: SafetyEnvelope,
        observed: u64,
    ) -> ParseError {
        let limit = self.limit_for(resource, safety);
        let hard = match resource {
            ResourceKind::PatternBytes => safety.max_pattern_bytes,
            ResourceKind::Nesting => safety.max_nesting,
            ResourceKind::ParseWork => safety.max_parse_work,
            ResourceKind::HirNodes => safety.max_hir_nodes,
            ResourceKind::TraversalStack => safety.max_traversal_stack,
        };
        let quota_is_binding = match self {
            Self::Strict(_) => false,
            Self::Quota(quota) => {
                let selected = match resource {
                    ResourceKind::PatternBytes => quota.syntax.max_pattern_bytes,
                    ResourceKind::Nesting => quota.syntax.max_nesting,
                    ResourceKind::ParseWork => quota.syntax.max_parse_work,
                    ResourceKind::HirNodes => quota.syntax.max_hir_nodes,
                    ResourceKind::TraversalStack => quota.syntax.max_traversal_stack,
                };
                selected <= hard
            }
        };
        let category = if quota_is_binding {
            ErrorCategory::FreResourceLimit {
                resource,
                limit,
                observed,
            }
        } else {
            ErrorCategory::StrictQualificationFailure {
                resource,
                limit,
                observed,
            }
        };
        ParseError::new(
            profile,
            category,
            "bounded syntax accounting limit exceeded",
        )
    }
}
