//! Independent source proof for the opt-in ripgrep `GrepCount` endpoint.

use fre_lower::{
    CheckedWidth, FactLimits, FactOperation, FactOptionalProofs, FactOutput, FactProof,
    analyze_facts,
};
use fre_syntax::{CanonicalPattern, CompatibilityProfile, ParseRequest, RustProfile};

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
pub(crate) fn exact_nonempty_lf_free_singleton(
    pattern: &str,
    profile: &RustProfile,
) -> bool {
    let operation = FactOperation::capture_erased(FactOutput::Exists)
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
    language.len() == 1
        && language
            .strings()
            .next()
            .is_some_and(|literal| !literal.is_empty() && !literal.contains(&b'\n'))
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
}
