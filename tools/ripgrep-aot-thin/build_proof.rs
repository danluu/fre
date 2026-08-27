//! Independent source proof for the opt-in ripgrep `GrepCount` endpoint.

use fre_lower::{
    CheckedWidth, FactLimits, FactOperation, FactOptionalProofs, FactOutput, FactProof,
    analyze_facts,
};
use fre_syntax::{CanonicalPattern, CompatibilityProfile, ParseRequest, RustProfile};
use sha2::{Digest, Sha256};

const MATCHING_LF_LINE_WITNESS_LANGUAGE_IDENTITY_DOMAIN: &[u8] =
    b"FRE-RIPGREP-AOT-THIN-MATCHING-LF-LINE-WITNESS-LANGUAGE\0\x01";

/// Raw-free summary of an independently proved exact finite byte language.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MatchingLfLineWitnessSourceProof {
    pub(crate) source_count: usize,
    pub(crate) source_bytes: usize,
    pub(crate) minimum_width: usize,
    pub(crate) maximum_width: usize,
    pub(crate) language_sha256: [u8; 32],
    /// Canonical count/length/member identity used independently by the
    /// exact-finite Teddy compiler. Unlike `language_sha256`, this deliberately
    /// has no adapter domain so it can be compared byte-for-byte with the
    /// compiler's authenticated literal census.
    pub(crate) compiler_literal_sha256: [u8; 32],
}

/// The ordinary byte-regex profile used by ripgrep's LF-delimited line
/// matcher. Multiline controls `^`/`$`; dot still does not consume LF.
pub(crate) fn ripgrep_grep_count_profile(case_insensitive: bool) -> RustProfile {
    let mut profile = RustProfile::default();
    profile.options.case_insensitive = case_insensitive;
    profile.options.multi_line = true;
    profile
}

/// The sole regex-set profile admitted by the opt-in exact64 registry.
///
/// The registry consumes already delineated LF-byte domains. It does not
/// reproduce fixed-string, PCRE2, word/line wrapping, inversion, decoding, or
/// cross-line transformations performed by a higher-level ripgrep adapter.
pub(crate) fn ripgrep_exact64_set_profile(case_insensitive: bool) -> RustProfile {
    let mut profile = RustProfile::regex_set_1_12_4();
    profile.options.case_insensitive = case_insensitive;
    profile
}

/// Independently prove that one Rust-regex source denotes exactly one
/// nonempty, assertion-free byte string and that string contains no LF.
///
/// The exact64 compiler repeats this proof under its own authenticated witness
/// transaction. This adapter-side pass prevents a registry entry from being
/// requested solely on the strength of the optional compiler optimization.
pub(crate) fn exact_nonempty_lf_free_singleton_literal(
    pattern: &str,
    profile: &RustProfile,
) -> Option<Vec<u8>> {
    let operation = FactOperation::capture_erased(FactOutput::Exists)
        .with_optional_proofs(FactOptionalProofs::FiniteLanguage);
    let Ok(parsed) = fre_syntax::parse(ParseRequest::rust(
        pattern,
        CompatibilityProfile::RustBytes(profile.clone()),
    )) else {
        return None;
    };
    let CanonicalPattern::Rust(parsed) = parsed.pattern else {
        return None;
    };
    let Ok(facts) = analyze_facts(&parsed, operation, FactLimits::default()) else {
        return None;
    };
    if !facts.identity().authenticates_current()
        || facts.operation() != operation
        || !matches!(
            facts.width(),
            CheckedWidth::NonEmpty { minimum, .. } if minimum != 0
        )
        || !facts
            .assertions()
            .possible()
            .as_proven()
            .is_some_and(Vec::is_empty)
    {
        return None;
    }
    let FactProof::Proven(language) = facts.finite_language() else {
        return None;
    };
    if language.len() != 1 {
        return None;
    }
    language
        .strings()
        .next()
        .filter(|literal| !literal.is_empty() && !literal.contains(&b'\n'))
        .map(<[u8]>::to_vec)
}

/// Boolean wrapper used by registries that need only independent admission.
pub(crate) fn exact_nonempty_lf_free_singleton(pattern: &str, profile: &RustProfile) -> bool {
    exact_nonempty_lf_free_singleton_literal(pattern, profile).is_some()
}

/// Independently prove the complete source condition required by the
/// matching-LF-line witness endpoint.
///
/// The proof is intentionally independent of the optional compiler report:
/// it authenticates this facts pass, requires an assertion-free exact finite
/// byte language, and checks every member rather than relying on width alone.
/// The returned digest binds the deterministic finite-language enumeration
/// without retaining any raw source or member bytes in the generated registry.
pub(crate) fn exact_nonempty_lf_free_finite_language_proof(
    pattern: &str,
    profile: &RustProfile,
) -> Option<MatchingLfLineWitnessSourceProof> {
    let operation = FactOperation::capture_erased(FactOutput::Exists)
        .with_optional_proofs(FactOptionalProofs::FiniteLanguage);
    let parsed = fre_syntax::parse(ParseRequest::rust(
        pattern,
        CompatibilityProfile::RustBytes(profile.clone()),
    ))
    .ok()?;
    let CanonicalPattern::Rust(parsed) = parsed.pattern else {
        return None;
    };
    let facts = analyze_facts(&parsed, operation, FactLimits::default()).ok()?;
    if !facts.identity().authenticates_current()
        || facts.operation() != operation
        || !matches!(
            facts.width(),
            CheckedWidth::NonEmpty { minimum, .. } if minimum != 0
        )
        || !facts
            .assertions()
            .possible()
            .as_proven()
            .is_some_and(Vec::is_empty)
    {
        return None;
    }
    let FactProof::Proven(language) = facts.finite_language() else {
        return None;
    };
    if language.is_empty() {
        return None;
    }

    let mut source_bytes = 0_usize;
    let mut minimum_width = usize::MAX;
    let mut maximum_width = 0_usize;
    let mut digest = Sha256::new();
    digest.update(MATCHING_LF_LINE_WITNESS_LANGUAGE_IDENTITY_DOMAIN);
    digest.update(u64::try_from(language.len()).ok()?.to_le_bytes());
    let mut compiler_literal_digest = Sha256::new();
    compiler_literal_digest.update(u64::try_from(language.len()).ok()?.to_le_bytes());
    for literal in language.strings() {
        if literal.is_empty() || literal.contains(&b'\n') {
            return None;
        }
        source_bytes = source_bytes.checked_add(literal.len())?;
        minimum_width = minimum_width.min(literal.len());
        maximum_width = maximum_width.max(literal.len());
        digest.update(u64::try_from(literal.len()).ok()?.to_le_bytes());
        digest.update(literal);
        compiler_literal_digest.update(u64::try_from(literal.len()).ok()?.to_le_bytes());
        compiler_literal_digest.update(literal);
    }
    Some(MatchingLfLineWitnessSourceProof {
        source_count: language.len(),
        source_bytes,
        minimum_width,
        maximum_width,
        language_sha256: digest.finalize().into(),
        compiler_literal_sha256: compiler_literal_digest.finalize().into(),
    })
}

/// Independently prove the source language required by the native line-jump
/// `GrepCount` compiler. Any parse, construction, identity, or proof refusal is
/// a closed structural decline.
pub(crate) fn exact_crlf_free_finite_language(pattern: &str, profile: &RustProfile) -> bool {
    let operation = FactOperation::capture_erased(FactOutput::SpanSequence)
        .with_optional_proofs(FactOptionalProofs::FiniteLanguage);
    let Ok(parsed) = fre_syntax::parse(ParseRequest::rust(
        pattern,
        CompatibilityProfile::RustBytes(profile.clone()),
    )) else {
        return false;
    };
    let CanonicalPattern::Rust(parsed) = parsed.pattern else {
        return false;
    };
    let Ok(facts) = analyze_facts(&parsed, operation, FactLimits::default()) else {
        return false;
    };
    if !facts.identity().authenticates_current()
        || facts.operation() != operation
        || !matches!(
            facts.width(),
            CheckedWidth::NonEmpty { minimum, .. } if minimum != 0
        )
        || !facts
            .assertions()
            .possible()
            .as_proven()
            .is_some_and(Vec::is_empty)
    {
        return false;
    }
    let FactProof::Proven(language) = facts.finite_language() else {
        return false;
    };
    !language.is_empty()
        && language.strings().all(|literal| {
            !literal.is_empty() && !literal.iter().any(|byte| matches!(byte, b'\r' | b'\n'))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ripgrep_profile_is_lf_delimited_without_cross_line_dot() {
        let sensitive = ripgrep_grep_count_profile(false);
        assert!(!sensitive.options.case_insensitive);
        assert!(sensitive.options.multi_line);
        assert!(!sensitive.options.dot_matches_new_line);
        assert!(!sensitive.options.crlf);
        assert_eq!(sensitive.options.line_terminator, b'\n');

        let insensitive = ripgrep_grep_count_profile(true);
        assert!(insensitive.options.case_insensitive);
        assert_eq!(
            insensitive.options.multi_line,
            sensitive.options.multi_line
        );
        assert_eq!(
            insensitive.options.line_terminator,
            sensitive.options.line_terminator
        );
    }

    #[test]
    fn exact_language_proof_accepts_only_nonempty_assertion_free_crlf_free_sets() {
        let profile = ripgrep_grep_count_profile(false);
        for pattern in ["alpha", "alpha|alphabet|beta", "(?:ab){2}"] {
            assert!(
                exact_crlf_free_finite_language(pattern, &profile),
                "eligible public fixture declined: {pattern:?}"
            );
        }
        for pattern in [
            "",
            "(?:alpha)?",
            "alpha+",
            "^alpha",
            r"alpha\nbeta",
            r"alpha\rbeta",
            r"alpha(?:\r)?beta",
        ] {
            assert!(
                !exact_crlf_free_finite_language(pattern, &profile),
                "ineligible public fixture admitted: {pattern:?}"
            );
        }
    }

    #[test]
    fn exact64_profile_is_one_pinned_lf_byte_regex_set_profile() {
        let sensitive = ripgrep_exact64_set_profile(false);
        assert!(!sensitive.options.case_insensitive);
        assert!(!sensitive.options.multi_line);
        assert!(!sensitive.options.dot_matches_new_line);
        assert!(!sensitive.options.crlf);
        assert!(sensitive.options.unicode);
        assert_eq!(sensitive.options.line_terminator, b'\n');

        let insensitive = ripgrep_exact64_set_profile(true);
        assert!(insensitive.options.case_insensitive);
        assert_eq!(insensitive.options.multi_line, sensitive.options.multi_line);
        assert_eq!(insensitive.options.unicode, sensitive.options.unicode);
    }

    #[test]
    fn exact64_independent_proof_accepts_only_exact_nonempty_lf_free_rows() {
        let profile = ripgrep_exact64_set_profile(false);
        for pattern in ["alpha", r"\x61", "123", r"a\tb"] {
            assert!(
                exact_nonempty_lf_free_singleton(pattern, &profile),
                "eligible public fixture declined: {pattern:?}"
            );
        }
        for pattern in ["", "a|b", "a+", "^a", r"a\nb", r"(?:a)?"] {
            assert!(
                !exact_nonempty_lf_free_singleton(pattern, &profile),
                "ineligible public fixture admitted: {pattern:?}"
            );
        }
        assert!(exact_nonempty_lf_free_singleton(
            "123",
            &ripgrep_exact64_set_profile(true)
        ));
        assert!(!exact_nonempty_lf_free_singleton(
            "Alpha",
            &ripgrep_exact64_set_profile(true)
        ));
    }

    #[test]
    fn singleton_proof_returns_the_exact_bytes_without_source_heuristics() {
        let profile = RustProfile::default();
        assert_eq!(
            exact_nonempty_lf_free_singleton_literal(r"a\x62\t", &profile),
            Some(b"ab\t".to_vec())
        );
        assert_eq!(
            exact_nonempty_lf_free_singleton_literal("(?:ab){2}", &profile),
            Some(b"abab".to_vec())
        );
        assert_eq!(
            exact_nonempty_lf_free_singleton_literal(r"a\nb", &profile),
            None
        );
        assert_eq!(
            exact_nonempty_lf_free_singleton_literal("a|b", &profile),
            None
        );
    }

    #[test]
    fn matching_lf_line_proof_accepts_exact_finite_lf_free_languages() {
        let profile = RustProfile::default();
        let singleton = exact_nonempty_lf_free_finite_language_proof("a", &profile)
            .expect("width-one language is independently eligible");
        assert_eq!(singleton.source_count, 1);
        assert_eq!(singleton.source_bytes, 1);
        assert_eq!(singleton.minimum_width, 1);
        assert_eq!(singleton.maximum_width, 1);
        assert_ne!(singleton.language_sha256, [0; 32]);
        assert_ne!(singleton.compiler_literal_sha256, [0; 32]);
        assert_ne!(singleton.compiler_literal_sha256, singleton.language_sha256);

        let finite =
            exact_nonempty_lf_free_finite_language_proof(r"(?:alpha|beta\r|(?:xy){2})", &profile)
                .expect("finite LF-free language");
        assert_eq!(finite.source_count, 3);
        assert_eq!(finite.source_bytes, 14);
        assert_eq!(finite.minimum_width, 4);
        assert_eq!(finite.maximum_width, 5);
        assert_ne!(finite.language_sha256, singleton.language_sha256);
        assert_ne!(
            finite.compiler_literal_sha256,
            singleton.compiler_literal_sha256
        );
    }

    #[test]
    fn matching_lf_line_proof_fails_closed_for_nonexact_or_unsafe_sources() {
        let profile = RustProfile::default();
        for pattern in ["", "(?:a)?", "a+", "^a", r"a\nb", r"(?:safe|line\nbreak)"] {
            assert!(
                exact_nonempty_lf_free_finite_language_proof(pattern, &profile).is_none(),
                "ineligible source admitted: {pattern:?}"
            );
        }
    }
}
