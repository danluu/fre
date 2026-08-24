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
}
