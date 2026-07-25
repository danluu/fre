use crate::{
    AdmissionStatus, CacheKey, CanonicalPattern, CompatibilityProfile, ErrorCategory, ParseError,
    ParseRecord, ParseRequest, ParseSummary, Re2Encoding, Re2Literal, Re2Parsed, Re2Syntax,
    ResourceKind, SCHEMA_VERSION, SourceSpan, UnicodeVersion, UpstreamRevision,
};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Re2Surface {
    LiteralMode,
    Utf8PatternValidation,
    Latin1PatternBytes,
    CountedRepeatPreflight,
    PerlSyntaxParser,
    PosixSyntaxParser,
    CaptureAndNameSemantics,
    ExactDiagnostics,
    QuoteMeta,
    RewriteGrammar,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Re2CapabilityStatus {
    Implemented,
    OracleCheckedSlice,
    PreflightOnly,
    NotYetImplemented,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Re2Capability {
    pub surface: Re2Surface,
    pub status: Re2CapabilityStatus,
    pub note: &'static str,
}

static RE2_SURFACES: [Re2Capability; 10] = [
    Re2Capability {
        surface: Re2Surface::LiteralMode,
        status: Re2CapabilityStatus::Implemented,
        note: "literal bytes plus the complete option stamp",
    },
    Re2Capability {
        surface: Re2Surface::Utf8PatternValidation,
        status: Re2CapabilityStatus::Implemented,
        note: "validates literal-mode UTF-8 patterns",
    },
    Re2Capability {
        surface: Re2Surface::Latin1PatternBytes,
        status: Re2CapabilityStatus::Implemented,
        note: "preserves arbitrary literal bytes",
    },
    Re2Capability {
        surface: Re2Surface::CountedRepeatPreflight,
        status: Re2CapabilityStatus::OracleCheckedSlice,
        note: "direct parser enforces the pinned 1000 and nested-product rules",
    },
    Re2Capability {
        surface: Re2Surface::PerlSyntaxParser,
        status: Re2CapabilityStatus::OracleCheckedSlice,
        note: "direct source-mapped parser; initial pinned constructor slice passed",
    },
    Re2Capability {
        surface: Re2Surface::PosixSyntaxParser,
        status: Re2CapabilityStatus::OracleCheckedSlice,
        note: "direct source-mapped parser; initial pinned constructor slice passed",
    },
    Re2Capability {
        surface: Re2Surface::CaptureAndNameSemantics,
        status: Re2CapabilityStatus::OracleCheckedSlice,
        note: "numbered/ASCII named syntax retained; non-ASCII name validation remains typed NYI",
    },
    Re2Capability {
        surface: Re2Surface::ExactDiagnostics,
        status: Re2CapabilityStatus::OracleCheckedSlice,
        note: "pinned error code and argument slice passed; exhaustive diagnostics remain open",
    },
    Re2Capability {
        surface: Re2Surface::QuoteMeta,
        status: Re2CapabilityStatus::Implemented,
        note: "independent source-mapped helper lives in fre-re2-syntax",
    },
    Re2Capability {
        surface: Re2Surface::RewriteGrammar,
        status: Re2CapabilityStatus::Implemented,
        note: "validation grammar is implemented; application belongs to matching",
    },
];

#[must_use]
pub fn re2_surface_inventory() -> &'static [Re2Capability] {
    &RE2_SURFACES
}

pub(crate) fn parse_re2(request: ParseRequest) -> Result<ParseRecord, ParseError> {
    let (pattern, profile, admission, safety, attempt_source_owner) = request.into_parts();
    let CompatibilityProfile::Re2(re2) = &profile else {
        unreachable!("dispatch validated profile")
    };
    if re2.revision != UpstreamRevision::Re2_972a15c || re2.unicode != UnicodeVersion::RE2_15_1_0 {
        return Err(ParseError::new(
            profile,
            ErrorCategory::InvalidConfiguration,
            "this scaffold only implements the pinned RE2 972a15c / Unicode 15.1 profile",
        ));
    }
    let encoding = re2.options.encoding;
    let literal = re2.options.literal;
    if encoding == Re2Encoding::Utf8 && core::str::from_utf8(pattern.as_bytes()).is_err() {
        return Err(ParseError::new(
            profile,
            ErrorCategory::InvalidPatternEncoding,
            "RE2 UTF-8 mode rejects an invalid UTF-8 pattern",
        ));
    }
    if !literal {
        let options = native_options(re2);
        let limits = native_limits(admission, safety);
        return match fre_re2_syntax::parse(pattern.as_bytes(), options, limits) {
            fre_re2_syntax::ParseOutcome::Parsed { ast, usage } => {
                let summary = native_summary(&ast, usage, encoding);
                Ok(ParseRecord {
                    key: CacheKey {
                        schema_version: SCHEMA_VERSION,
                        pattern,
                        profile,
                        admission,
                        safety,
                        attempt_source_owner,
                    },
                    admission_status: AdmissionStatus::from_policy(admission),
                    summary,
                    pattern: CanonicalPattern::Re2(Re2Parsed { ast }),
                })
            }
            fre_re2_syntax::ParseOutcome::Rejected(error) => {
                Err(map_native_error(profile, admission, safety, error))
            }
            fre_re2_syntax::ParseOutcome::NotYetImplemented(incomplete) => {
                let span = SourceSpan {
                    start: u64::try_from(incomplete.span.start).unwrap_or(u64::MAX),
                    end: u64::try_from(incomplete.span.end).unwrap_or(u64::MAX),
                };
                Err(ParseError::new(
                    profile,
                    ErrorCategory::UnsupportedNotYetImplemented {
                        surface: Re2Surface::CaptureAndNameSemantics,
                    },
                    incomplete.evidence,
                )
                .with_span(span))
            }
        };
    }

    let bytes = pattern.as_bytes().to_vec();
    let byte_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let parse_work = byte_len.saturating_add(1);
    let work_limit = admission.limit_for(crate::ResourceKind::ParseWork, safety);
    if parse_work > work_limit {
        return Err(admission.limit_error(
            profile,
            crate::ResourceKind::ParseWork,
            safety,
            parse_work,
        ));
    }
    Ok(ParseRecord {
        key: CacheKey {
            schema_version: SCHEMA_VERSION,
            pattern,
            profile,
            admission,
            safety,
            attempt_source_owner,
        },
        admission_status: AdmissionStatus::from_policy(admission),
        summary: ParseSummary {
            hir_nodes: 1,
            max_depth: 0,
            parse_work,
            literal_bytes: byte_len,
            class_ranges: 0,
            captures: 0,
            repetitions: 0,
            largest_finite_repeat: None,
            guarantees_valid_utf8_nonempty: encoding == Re2Encoding::Utf8,
        },
        pattern: CanonicalPattern::Re2Literal(Re2Literal { bytes }),
    })
}

fn native_options(profile: &crate::Re2Profile) -> fre_re2_syntax::Options {
    fre_re2_syntax::Options {
        max_mem: profile.options.max_mem,
        encoding: match profile.options.encoding {
            Re2Encoding::Utf8 => fre_re2_syntax::Encoding::Utf8,
            Re2Encoding::Latin1 => fre_re2_syntax::Encoding::Latin1,
        },
        syntax: match profile.syntax() {
            Re2Syntax::Perl => fre_re2_syntax::SyntaxMode::Perl,
            Re2Syntax::Posix => fre_re2_syntax::SyntaxMode::Posix,
        },
        longest_match: profile.options.longest_match,
        log_errors: profile.options.log_errors,
        literal: profile.options.literal,
        never_nl: profile.options.never_nl,
        dot_nl: profile.options.dot_nl,
        never_capture: profile.options.never_capture,
        case_sensitive: profile.options.case_sensitive,
        perl_classes: profile.options.perl_classes,
        word_boundary: profile.options.word_boundary,
        one_line: profile.options.one_line,
    }
}

fn native_limits(
    admission: crate::AdmissionPolicy,
    safety: crate::SafetyEnvelope,
) -> fre_re2_syntax::ParseLimits {
    let pattern = limit_as_usize(admission.limit_for(ResourceKind::PatternBytes, safety));
    let nodes = limit_as_usize(admission.limit_for(ResourceKind::HirNodes, safety));
    let work = limit_as_usize(admission.limit_for(ResourceKind::ParseWork, safety));
    fre_re2_syntax::ParseLimits {
        max_pattern_bytes: pattern,
        max_nodes: nodes,
        max_tokens: work,
        max_nesting: limit_as_usize(admission.limit_for(ResourceKind::Nesting, safety)),
        max_captures: nodes,
        max_class_items: nodes,
        max_work: work,
    }
}

fn limit_as_usize(limit: u64) -> usize {
    usize::try_from(limit).unwrap_or(usize::MAX)
}

fn native_summary(
    ast: &fre_re2_syntax::Ast,
    usage: fre_re2_syntax::ResourceUsage,
    encoding: Re2Encoding,
) -> ParseSummary {
    let mut literal_bytes = 0_u64;
    let mut repetitions = 0_u64;
    let mut largest_finite_repeat = None;
    for node in &ast.nodes {
        match &node.kind {
            fre_re2_syntax::NodeKind::Literal { .. } => {
                let bytes = node.span.end.saturating_sub(node.span.start);
                literal_bytes =
                    literal_bytes.saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
            }
            fre_re2_syntax::NodeKind::Repeat { range, .. } => {
                repetitions = repetitions.saturating_add(1);
                if let Some(maximum) = range.max {
                    largest_finite_repeat = Some(
                        largest_finite_repeat
                            .unwrap_or(0_u32)
                            .max(u32::from(maximum)),
                    );
                }
            }
            _ => {}
        }
    }
    ParseSummary {
        hir_nodes: u64::try_from(usage.nodes).unwrap_or(u64::MAX),
        max_depth: u64::try_from(usage.maximum_nesting).unwrap_or(u64::MAX),
        parse_work: u64::try_from(usage.work).unwrap_or(u64::MAX),
        literal_bytes,
        class_ranges: u64::try_from(usage.class_items).unwrap_or(u64::MAX),
        captures: u64::try_from(usage.captures).unwrap_or(u64::MAX),
        repetitions,
        largest_finite_repeat,
        guarantees_valid_utf8_nonempty: encoding == Re2Encoding::Utf8,
    }
}

fn map_native_error(
    profile: CompatibilityProfile,
    admission: crate::AdmissionPolicy,
    safety: crate::SafetyEnvelope,
    error: fre_re2_syntax::ParseError,
) -> ParseError {
    if let Some(limit) = error.limit {
        let (resource, usage_observed) = native_limit_observation(limit, error.usage);
        let observed = error.observed.map_or(usage_observed, |value| {
            u64::try_from(value).unwrap_or(u64::MAX)
        });
        return admission.limit_error(profile, resource, safety, observed);
    }
    let span = SourceSpan {
        start: u64::try_from(error.argument.start).unwrap_or(u64::MAX),
        end: u64::try_from(error.argument.end).unwrap_or(u64::MAX),
    };
    ParseError::new(
        profile,
        ErrorCategory::Re2Syntax {
            code: native_error_code(error.code),
            argument_bytes: error.argument_bytes.into_vec(),
        },
        error.message,
    )
    .with_span(span)
}

fn native_limit_observation(
    limit: fre_re2_syntax::LimitKind,
    usage: fre_re2_syntax::ResourceUsage,
) -> (ResourceKind, u64) {
    let (resource, observed) = match limit {
        fre_re2_syntax::LimitKind::PatternBytes => (ResourceKind::PatternBytes, usage.source_bytes),
        fre_re2_syntax::LimitKind::Nesting => (ResourceKind::Nesting, usage.maximum_nesting),
        fre_re2_syntax::LimitKind::AstNodes => (ResourceKind::HirNodes, usage.nodes),
        fre_re2_syntax::LimitKind::Tokens => (ResourceKind::ParseWork, usage.tokens),
        fre_re2_syntax::LimitKind::Captures => (ResourceKind::HirNodes, usage.captures),
        fre_re2_syntax::LimitKind::ClassItems => (ResourceKind::HirNodes, usage.class_items),
        fre_re2_syntax::LimitKind::Work => (ResourceKind::ParseWork, usage.work),
        fre_re2_syntax::LimitKind::IntegerArithmetic => {
            return (ResourceKind::ParseWork, u64::MAX);
        }
    };
    (resource, u64::try_from(observed).unwrap_or(u64::MAX))
}

const fn native_error_code(code: fre_re2_syntax::ParseErrorCode) -> u8 {
    match code {
        fre_re2_syntax::ParseErrorCode::Internal => 1,
        fre_re2_syntax::ParseErrorCode::BadEscape => 2,
        fre_re2_syntax::ParseErrorCode::BadCharClass => 3,
        fre_re2_syntax::ParseErrorCode::BadCharRange => 4,
        fre_re2_syntax::ParseErrorCode::MissingBracket => 5,
        fre_re2_syntax::ParseErrorCode::MissingParen => 6,
        fre_re2_syntax::ParseErrorCode::UnexpectedParen => 7,
        fre_re2_syntax::ParseErrorCode::TrailingBackslash => 8,
        fre_re2_syntax::ParseErrorCode::RepeatArgument => 9,
        fre_re2_syntax::ParseErrorCode::RepeatSize => 10,
        fre_re2_syntax::ParseErrorCode::RepeatOp => 11,
        fre_re2_syntax::ParseErrorCode::BadPerlOp => 12,
        fre_re2_syntax::ParseErrorCode::BadUtf8 => 13,
        fre_re2_syntax::ParseErrorCode::BadNamedCapture => 14,
        fre_re2_syntax::ParseErrorCode::PatternTooLarge => 15,
    }
}
