use regex_automata::{MatchKind, meta, nfa::thompson::WhichCaptures, util::syntax};
use regex_syntax::{
    ParserBuilder,
    hir::{Class, Hir, HirKind},
};

use crate::{
    AdmissionPolicy, AdmissionStatus, CacheKey, CanonicalPattern, CompatibilityProfile,
    ErrorCategory, ParseError, ParseRecord, ParseRequest, ParseSummary, ResourceKind,
    RustConstructor, RustOptions, RustParsed, RustProfile, SCHEMA_VERSION, SafetyEnvelope,
    UnicodeVersion,
};

pub(crate) fn parse_rust(request: ParseRequest) -> Result<ParseRecord, ParseError> {
    let (pattern, profile, admission, safety) = request.into_parts();
    let Some(source) = pattern.as_str() else {
        return Err(ParseError::new(
            profile,
            ErrorCategory::InvalidPatternEncoding,
            "Rust regex patterns must be valid UTF-8 strings",
        ));
    };
    let (options, utf8) = match &profile {
        CompatibilityProfile::RustText(rust) => (&rust.options, true),
        CompatibilityProfile::RustBytes(rust) => (&rust.options, false),
        CompatibilityProfile::Re2(_) => unreachable!("dispatch validated profile"),
    };
    validate_rust_configuration(&profile, options)?;

    let mut builder = ParserBuilder::new();
    builder
        .nest_limit(options.nest_limit)
        .octal(options.octal)
        .utf8(utf8)
        .ignore_whitespace(options.ignore_whitespace)
        .case_insensitive(options.case_insensitive)
        .multi_line(options.multi_line)
        .dot_matches_new_line(options.dot_matches_new_line)
        .crlf(options.crlf)
        .line_terminator(options.line_terminator)
        .swap_greed(options.swap_greed)
        .unicode(options.unicode);
    let hir = builder.build().parse(source).map_err(|error| {
        let span = match &error {
            regex_syntax::Error::Parse(error) => Some(error.span()),
            regex_syntax::Error::Translate(error) => Some(error.span()),
            _ => None,
        };
        let record = ParseError::new(
            profile.clone(),
            ErrorCategory::UpstreamRustSyntax,
            error.to_string(),
        );
        if let Some(span) = span {
            record.with_span(crate::SourceSpan {
                start: u64::try_from(span.start.offset).unwrap_or(u64::MAX),
                end: u64::try_from(span.end.offset).unwrap_or(u64::MAX),
            })
        } else {
            record
        }
    })?;
    enforce_high_level_size_limit(&hir, &profile, options)?;
    let source_bytes = u64::try_from(source.len()).unwrap_or(u64::MAX);
    let summary = summarize_hir(&hir, source_bytes, &profile, admission, safety)?;
    Ok(ParseRecord {
        key: CacheKey {
            schema_version: SCHEMA_VERSION,
            pattern,
            profile,
            admission,
            safety,
        },
        admission_status: AdmissionStatus::from_policy(admission),
        summary,
        pattern: CanonicalPattern::Rust(RustParsed { hir }),
    })
}

fn enforce_high_level_size_limit(
    hir: &Hir,
    profile: &CompatibilityProfile,
    options: &RustOptions,
) -> Result<(), ParseError> {
    let rust = match profile {
        CompatibilityProfile::RustText(rust) | CompatibilityProfile::RustBytes(rust) => rust,
        CompatibilityProfile::Re2(_) => unreachable!("dispatch validated profile"),
    };
    let (size_limit, dfa_size_limit) = match rust.constructor {
        RustConstructor::RegexBuilder {
            size_limit,
            dfa_size_limit,
            ..
        } => (size_limit, dfa_size_limit),
        // A set builder applies this limit once to its combined capture-free
        // NFA in `validate_rust_bytes_set`, never to a constituent pattern.
        RustConstructor::RegexSetBuilder { .. } | RustConstructor::RebarMeta { .. } => {
            return Ok(());
        }
    };
    let limit = usize::try_from(size_limit).map_err(|_| {
        ParseError::new(
            profile.clone(),
            ErrorCategory::InvalidConfiguration,
            "the high-level Rust regex size limit does not fit this target",
        )
    })?;
    let dfa_size_limit = usize::try_from(dfa_size_limit).map_err(|_| {
        ParseError::new(
            profile.clone(),
            ErrorCategory::InvalidConfiguration,
            "the high-level Rust regex DFA size limit does not fit this target",
        )
    })?;
    let utf8_empty = matches!(profile, CompatibilityProfile::RustText(_));
    let config = meta::Config::new()
        .nfa_size_limit(Some(limit))
        .hybrid_cache_capacity(dfa_size_limit)
        .match_kind(MatchKind::LeftmostFirst)
        .utf8_empty(utf8_empty)
        .line_terminator(options.line_terminator);
    meta::Builder::new()
        .configure(config)
        .build_from_hir(hir)
        .map(|_| ())
        .map_err(|error| {
            if let Some(limit) = error.size_limit() {
                ParseError::new(
                    profile.clone(),
                    ErrorCategory::UpstreamRustCompiledTooBig {
                        limit: u64::try_from(limit).unwrap_or(u64::MAX),
                    },
                    format!("Compiled regex exceeds size limit of {limit} bytes."),
                )
            } else {
                ParseError::new(
                    profile.clone(),
                    ErrorCategory::UpstreamRustSyntax,
                    error.to_string(),
                )
            }
        })
}

/// Validate the pinned high-level Rust bytes set constructor as one combined
/// capture-free program.
///
/// Callers must first parse every constituent pattern through [`crate::parse`]
/// so FRE's syntax safety envelope and indexed diagnostics remain the first
/// boundary. This function then reproduces the pinned `regex` 1.12.4
/// `bytes::RegexSetBuilder` meta construction, including its combined NFA
/// size limit and capture erasure.
///
/// Non-high-level profiles have no corresponding set-constructor contract and
/// are left unchanged.
///
/// # Errors
///
/// Returns the pinned compiled-too-big category for a combined NFA limit, or
/// an upstream syntax category if the already-parsed inputs unexpectedly fail
/// during the independent combined construction.
pub fn validate_rust_bytes_set(
    patterns: &[String],
    profile: &RustProfile,
) -> Result<(), ParseError> {
    let compatibility = CompatibilityProfile::RustBytes(profile.clone());
    validate_rust_configuration(&compatibility, &profile.options)?;
    let RustConstructor::RegexSetBuilder {
        size_limit,
        dfa_size_limit,
        ..
    } = profile.constructor
    else {
        return Ok(());
    };
    let size_limit = usize::try_from(size_limit).map_err(|_| {
        ParseError::new(
            compatibility.clone(),
            ErrorCategory::InvalidConfiguration,
            "the high-level Rust regex set size limit does not fit this target",
        )
    })?;
    let dfa_size_limit = usize::try_from(dfa_size_limit).map_err(|_| {
        ParseError::new(
            compatibility.clone(),
            ErrorCategory::InvalidConfiguration,
            "the high-level Rust regex set DFA size limit does not fit this target",
        )
    })?;
    let options = &profile.options;
    let meta_config = meta::Config::new()
        .nfa_size_limit(Some(size_limit))
        .hybrid_cache_capacity(dfa_size_limit)
        .match_kind(MatchKind::All)
        .utf8_empty(false)
        .which_captures(WhichCaptures::None)
        .line_terminator(options.line_terminator);
    let syntax_config = syntax::Config::new()
        .case_insensitive(options.case_insensitive)
        .multi_line(options.multi_line)
        .dot_matches_new_line(options.dot_matches_new_line)
        .crlf(options.crlf)
        .line_terminator(options.line_terminator)
        .swap_greed(options.swap_greed)
        .ignore_whitespace(options.ignore_whitespace)
        .unicode(options.unicode)
        .utf8(false)
        .nest_limit(options.nest_limit)
        .octal(options.octal);
    meta::Builder::new()
        .configure(meta_config)
        .syntax(syntax_config)
        .build_many(patterns)
        .map(|_| ())
        .map_err(|error| {
            if let Some(limit) = error.size_limit() {
                ParseError::new(
                    compatibility,
                    ErrorCategory::UpstreamRustCompiledTooBig {
                        limit: u64::try_from(limit).unwrap_or(u64::MAX),
                    },
                    format!("Compiled regex exceeds size limit of {limit} bytes."),
                )
            } else {
                ParseError::new(
                    compatibility,
                    ErrorCategory::UpstreamRustSyntax,
                    error.to_string(),
                )
            }
        })
}

fn rebar_options_match_runner_surface(options: &RustOptions) -> bool {
    let exposed = RustOptions {
        unicode: options.unicode,
        case_insensitive: options.case_insensitive,
        ..RustOptions::default()
    };
    options == &exposed
}

fn validate_rust_configuration(
    profile: &CompatibilityProfile,
    options: &RustOptions,
) -> Result<(), ParseError> {
    let rust = match profile {
        CompatibilityProfile::RustText(rust) | CompatibilityProfile::RustBytes(rust) => rust,
        CompatibilityProfile::Re2(_) => unreachable!("dispatch validated profile"),
    };
    let supported_constructor = match (&rust.constructor, profile) {
        (
            RustConstructor::RegexBuilder {
                size_limit,
                dfa_size_limit,
                text_syntax_utf8,
                bytes_syntax_utf8,
                text_utf8_empty,
                bytes_utf8_empty,
                match_kind: crate::RustMatchKind::LeftmostFirst,
            }
            | RustConstructor::RegexSetBuilder {
                size_limit,
                dfa_size_limit,
                text_syntax_utf8,
                bytes_syntax_utf8,
                text_utf8_empty,
                bytes_utf8_empty,
                match_kind: crate::RustMatchKind::LeftmostFirst,
            },
            _,
        ) => {
            // Exact compiled-size admission is enforced after HIR parsing.
            usize::try_from(*size_limit).is_ok()
                // The DFA option accepts any `usize` and only changes lazy-
                // DFA cache behavior, not constructor acceptance.
                && usize::try_from(*dfa_size_limit).is_ok()
                && *text_syntax_utf8
                && !*bytes_syntax_utf8
                && *text_utf8_empty
                && !*bytes_utf8_empty
        }
        (
            RustConstructor::RebarMeta {
                rebar_revision,
                regex_default_features,
                regex_logging,
                regex_perf_dfa_full,
                regex_automata_default_features,
                syntax_utf8,
                utf8_empty,
                match_kind: crate::RustMatchKind::LeftmostFirst,
                build_many_ordered,
                thompson_nfa_size_limit,
                admission_status: AdmissionStatus::UpstreamOraclePending,
            },
            CompatibilityProfile::RustBytes(_),
        ) => {
            *rebar_revision == crate::UpstreamRevision::Rebar463d00f
                && *regex_default_features
                && *regex_logging
                && *regex_perf_dfa_full
                && *regex_automata_default_features
                && !*syntax_utf8
                && !*utf8_empty
                && *build_many_ordered
                && *thompson_nfa_size_limit == 100 * 1_048_576
                && rebar_options_match_runner_surface(options)
        }
        (
            RustConstructor::RebarMeta { .. },
            CompatibilityProfile::RustBytes(_) | CompatibilityProfile::RustText(_),
        ) => false,
        (RustConstructor::RebarMeta { .. }, CompatibilityProfile::Re2(_)) => {
            unreachable!("dispatch validated profile")
        }
    };
    if rust.regex != crate::PackageIdentity::REGEX_1_12_4
        || rust.regex_automata != crate::PackageIdentity::REGEX_AUTOMATA_0_4_14
        || rust.regex_syntax != crate::PackageIdentity::REGEX_SYNTAX_0_8_11
        || rust.unicode != UnicodeVersion::RUST_16_0_0
        || !supported_constructor
    {
        return Err(ParseError::new(
            profile.clone(),
            ErrorCategory::InvalidConfiguration,
            "this parser only implements the exact regex 1.12.4 / regex-automata 0.4.14 / regex-syntax 0.8.11 / Unicode 16.0 high-level and Rebar profiles",
        ));
    }
    Ok(())
}

fn checked_add(
    value: &mut u64,
    add: u64,
    profile: &CompatibilityProfile,
    admission: AdmissionPolicy,
    safety: SafetyEnvelope,
    resource: ResourceKind,
) -> Result<(), ParseError> {
    let observed = value.checked_add(add).unwrap_or(u64::MAX);
    let limit = admission.limit_for(resource, safety);
    if observed > limit {
        return Err(admission.limit_error(profile.clone(), resource, safety, observed));
    }
    *value = observed;
    Ok(())
}

fn summarize_hir(
    hir: &Hir,
    source_bytes: u64,
    profile: &CompatibilityProfile,
    admission: AdmissionPolicy,
    safety: SafetyEnvelope,
) -> Result<ParseSummary, ParseError> {
    let mut summary = ParseSummary {
        parse_work: source_bytes,
        guarantees_valid_utf8_nonempty: hir.properties().is_utf8(),
        ..ParseSummary::default()
    };
    let mut stack = Vec::new();
    stack.push((hir, 0_u64));
    while let Some((node, depth)) = stack.pop() {
        checked_add(
            &mut summary.hir_nodes,
            1,
            profile,
            admission,
            safety,
            ResourceKind::HirNodes,
        )?;
        checked_add(
            &mut summary.parse_work,
            1,
            profile,
            admission,
            safety,
            ResourceKind::ParseWork,
        )?;
        summary.max_depth = summary.max_depth.max(depth);
        if depth > admission.limit_for(ResourceKind::Nesting, safety) {
            return Err(admission.limit_error(
                profile.clone(),
                ResourceKind::Nesting,
                safety,
                depth,
            ));
        }
        charge_kind(&mut summary, node.kind(), profile, admission, safety)?;
        for sub in node.kind().subs() {
            let pending = u64::try_from(stack.len()).unwrap_or(u64::MAX);
            let limit = admission.limit_for(ResourceKind::TraversalStack, safety);
            if pending >= limit {
                return Err(admission.limit_error(
                    profile.clone(),
                    ResourceKind::TraversalStack,
                    safety,
                    pending.saturating_add(1),
                ));
            }
            stack.push((sub, depth.saturating_add(1)));
        }
    }
    Ok(summary)
}

fn charge_kind(
    summary: &mut ParseSummary,
    kind: &HirKind,
    profile: &CompatibilityProfile,
    admission: AdmissionPolicy,
    safety: SafetyEnvelope,
) -> Result<(), ParseError> {
    let work = match kind {
        HirKind::Literal(literal) => {
            let len = u64::try_from(literal.0.len()).unwrap_or(u64::MAX);
            checked_add(
                &mut summary.literal_bytes,
                len,
                profile,
                admission,
                safety,
                ResourceKind::ParseWork,
            )?;
            len
        }
        HirKind::Class(class) => {
            let ranges = match class {
                Class::Unicode(class) => class.ranges().len(),
                Class::Bytes(class) => class.ranges().len(),
            };
            let ranges = u64::try_from(ranges).unwrap_or(u64::MAX);
            checked_add(
                &mut summary.class_ranges,
                ranges,
                profile,
                admission,
                safety,
                ResourceKind::ParseWork,
            )?;
            ranges
        }
        HirKind::Capture(_) => {
            summary.captures = summary.captures.saturating_add(1);
            0
        }
        HirKind::Repetition(repetition) => {
            summary.repetitions = summary.repetitions.saturating_add(1);
            if let Some(max) = repetition.max {
                summary.largest_finite_repeat = Some(
                    summary
                        .largest_finite_repeat
                        .map_or(max, |old| old.max(max)),
                );
            }
            0
        }
        HirKind::Empty | HirKind::Look(_) | HirKind::Concat(_) | HirKind::Alternation(_) => 0,
    };
    checked_add(
        &mut summary.parse_work,
        work,
        profile,
        admission,
        safety,
        ResourceKind::ParseWork,
    )
}
