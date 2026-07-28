use super::QualifiedExactSearchQualification;

/// Qualification atom scoped only to `SearchBackendPolicy::AsimdV8` / tag 8.
pub const QUALIFIED_EXACT_SEARCH_ASIMD_V8_QUALIFICATION: QualifiedExactSearchQualification =
    QualifiedExactSearchQualification::Candidate;

/// Qualification atom scoped only to `SearchBackendPolicy::Sve16V6` / tag 19.
pub const QUALIFIED_EXACT_SEARCH_SVE16_V6_QUALIFICATION: QualifiedExactSearchQualification =
    QualifiedExactSearchQualification::Candidate;

/// Qualification atom scoped only to `SearchBackendPolicy::Sve2Fixed16` / tag 10.
pub const QUALIFIED_EXACT_SEARCH_SVE2_FIXED16_QUALIFICATION: QualifiedExactSearchQualification =
    QualifiedExactSearchQualification::Candidate;

/// Qualification atom scoped only to `SearchBackendPolicy::Sve2Fixed16V2` /
/// tag 21.
pub const QUALIFIED_EXACT_SEARCH_SVE2_FIXED16_V2_QUALIFICATION: QualifiedExactSearchQualification =
    QualifiedExactSearchQualification::Candidate;
