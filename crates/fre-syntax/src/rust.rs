use regex_automata::{MatchKind, meta, nfa::thompson::WhichCaptures, util::syntax};
use regex_syntax::{
    ParserBuilder,
    ast::{self, Ast},
    hir::{Class, Hir, HirKind},
};

use crate::{
    AdmissionPolicy, AdmissionStatus, CacheKey, CanonicalPattern, CompatibilityProfile,
    ErrorCategory, ParseError, ParseRecord, ParseRequest, ParseSummary, ResourceKind,
    RustConstructor, RustOptions, RustParsed, RustRegexSetAdmissionError, RustUnicodeFeatures,
    SCHEMA_VERSION, SafetyEnvelope, UnicodeVersion,
};

pub(crate) fn parse_rust(
    request: ParseRequest,
    enforce_single_size_limit: bool,
) -> Result<ParseRecord, ParseError> {
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

    let features = match &profile {
        CompatibilityProfile::RustText(rust) | CompatibilityProfile::RustBytes(rust) => {
            rust.unicode_features
        }
        CompatibilityProfile::Re2(_) => unreachable!("dispatch validated profile"),
    };
    let (hir, parse_work) = if features.is_all() {
        (
            configured_parser(options, utf8)
                .build()
                .parse(source)
                .map_err(|error| map_regex_syntax_error(&profile, &error))?,
            u64::try_from(source.len()).unwrap_or(u64::MAX),
        )
    } else {
        parse_with_unicode_availability(
            source, &profile, options, utf8, features, admission, safety,
        )?
    };
    if enforce_single_size_limit {
        enforce_high_level_size_limit(&hir, &profile, options)?;
    }
    let summary = summarize_hir(&hir, parse_work, &profile, admission, safety)?;
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

fn configured_parser(options: &RustOptions, utf8: bool) -> ParserBuilder {
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
    builder
}

fn map_regex_syntax_error(
    profile: &CompatibilityProfile,
    error: &regex_syntax::Error,
) -> ParseError {
    let span = match error {
        regex_syntax::Error::Parse(error) => Some(error.span()),
        regex_syntax::Error::Translate(error) => Some(error.span()),
        _ => None,
    };
    let record = ParseError::new(
        profile.clone(),
        ErrorCategory::UpstreamRustSyntax,
        error.to_string(),
    );
    with_regex_span(record, span)
}

fn with_regex_span(record: ParseError, span: Option<&ast::Span>) -> ParseError {
    if let Some(span) = span {
        record.with_span(crate::SourceSpan {
            start: u64::try_from(span.start.offset).unwrap_or(u64::MAX),
            end: u64::try_from(span.end.offset).unwrap_or(u64::MAX),
        })
    } else {
        record
    }
}

fn parse_with_unicode_availability(
    source: &str,
    profile: &CompatibilityProfile,
    options: &RustOptions,
    utf8: bool,
    features: RustUnicodeFeatures,
    admission: AdmissionPolicy,
    safety: SafetyEnvelope,
) -> Result<(Hir, u64), ParseError> {
    // `ParseRequest::validate_and_charge_source` checked the initial source
    // byte charge before this single AST allocation. The availability walk
    // charges every visited AST/class node. The walk only rejects constructs
    // that require unavailable data; it performs no Unicode table expansion,
    // alias normalization or second parse.
    let mut ast_builder = ast::parse::ParserBuilder::new();
    ast_builder
        .nest_limit(options.nest_limit)
        .octal(options.octal)
        .ignore_whitespace(options.ignore_whitespace);
    let ast = ast_builder.build().parse(source).map_err(|error| {
        with_regex_span(
            ParseError::new(
                profile.clone(),
                ErrorCategory::UpstreamRustSyntax,
                error.to_string(),
            ),
            Some(error.span()),
        )
    })?;
    let initial_work = u64::try_from(source.len()).unwrap_or(u64::MAX);
    let visitor = UnicodeAvailabilityVisitor {
        profile,
        admission,
        safety,
        features,
        work: initial_work,
        flags: ActiveUnicodeFlags {
            case_insensitive: options.case_insensitive,
            unicode: options.unicode,
        },
        group_flags: Vec::new(),
    };
    let work = ast::visit(&ast, visitor)?;

    let mut translator = regex_syntax::hir::translate::TranslatorBuilder::new();
    translator
        .utf8(utf8)
        .line_terminator(options.line_terminator)
        .case_insensitive(options.case_insensitive)
        .multi_line(options.multi_line)
        .dot_matches_new_line(options.dot_matches_new_line)
        .crlf(options.crlf)
        .swap_greed(options.swap_greed)
        .unicode(options.unicode);
    let hir = translator
        .build()
        .translate(source, &ast)
        .map_err(|error| {
            with_regex_span(
                ParseError::new(
                    profile.clone(),
                    ErrorCategory::UpstreamRustSyntax,
                    error.to_string(),
                ),
                Some(error.span()),
            )
        })?;
    Ok((hir, work))
}

struct UnicodeAvailabilityVisitor<'a> {
    profile: &'a CompatibilityProfile,
    admission: AdmissionPolicy,
    safety: SafetyEnvelope,
    features: RustUnicodeFeatures,
    work: u64,
    flags: ActiveUnicodeFlags,
    group_flags: Vec<ActiveUnicodeFlags>,
}

#[derive(Clone, Copy)]
struct ActiveUnicodeFlags {
    case_insensitive: bool,
    unicode: bool,
}

impl UnicodeAvailabilityVisitor<'_> {
    fn charge(&mut self, amount: u64) -> Result<(), ParseError> {
        checked_add(
            &mut self.work,
            amount,
            self.profile,
            self.admission,
            self.safety,
            ResourceKind::ParseWork,
        )
    }

    fn reject(&self, span: &ast::Span, message: &'static str) -> Result<(), ParseError> {
        Err(with_regex_span(
            ParseError::new(
                self.profile.clone(),
                ErrorCategory::UpstreamRustSyntax,
                message,
            ),
            Some(span),
        ))
    }

    fn apply_flags(&mut self, flags: &ast::Flags) {
        if let Some(case_insensitive) = flags.flag_state(ast::Flag::CaseInsensitive) {
            self.flags.case_insensitive = case_insensitive;
        }
        if let Some(unicode) = flags.flag_state(ast::Flag::Unicode) {
            self.flags.unicode = unicode;
        }
    }

    fn require_case(&self, span: &ast::Span) -> Result<(), ParseError> {
        if !self.flags.case_insensitive || !self.flags.unicode {
            return Ok(());
        }
        self.reject(
            span,
            "Unicode case-folding data is unavailable in this Rust profile",
        )
    }

    fn class_perl(&self, class: &ast::ClassPerl) -> Result<(), ParseError> {
        if !self.flags.unicode {
            return Ok(());
        }
        self.reject(
            &class.span,
            "Unicode Perl-class data is unavailable in this Rust profile",
        )
    }

    fn class_unicode(&mut self, class: &ast::ClassUnicode) -> Result<(), ParseError> {
        if !self.flags.unicode {
            return Ok(());
        }
        let ast::ClassUnicodeKind::NamedValue { name, .. } = &class.kind else {
            return self.reject(
                &class.span,
                "Unicode property data is unavailable in this Rust profile",
            );
        };
        if self.features.has_age() {
            self.charge(u64::try_from(name.len()).unwrap_or(u64::MAX))?;
            if is_unicode_age_property_name(name) {
                self.require_case(&class.span)?;
                return Ok(());
            }
        }
        self.reject(
            &class.span,
            "Unicode property data is unavailable in this Rust profile",
        )
    }
}

fn is_unicode_age_property_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    let bytes = if bytes.len() >= 2
        && bytes[0].eq_ignore_ascii_case(&b'i')
        && bytes[1].eq_ignore_ascii_case(&b's')
    {
        &bytes[2..]
    } else {
        bytes
    };
    bytes
        .iter()
        .copied()
        .filter_map(|byte| match byte {
            b' ' | b'_' | b'-' => None,
            0x00..=0x7F => Some(byte.to_ascii_lowercase()),
            _ => None,
        })
        .eq(b"age".iter().copied())
}

impl ast::Visitor for UnicodeAvailabilityVisitor<'_> {
    type Output = u64;
    type Err = ParseError;

    fn finish(self) -> Result<Self::Output, Self::Err> {
        Ok(self.work)
    }

    fn visit_pre(&mut self, node: &Ast) -> Result<(), Self::Err> {
        self.charge(1)?;
        if let Ast::Group(group) = node {
            self.group_flags.push(self.flags);
            if let Some(flags) = group.flags() {
                self.apply_flags(flags);
            }
        }
        match node {
            Ast::Literal(literal) => self.require_case(&literal.span),
            Ast::ClassBracketed(class) => self.require_case(&class.span),
            Ast::Assertion(assertion)
                if self.flags.unicode
                    && matches!(
                        assertion.kind,
                        ast::AssertionKind::WordBoundary
                            | ast::AssertionKind::NotWordBoundary
                            | ast::AssertionKind::WordBoundaryStart
                            | ast::AssertionKind::WordBoundaryEnd
                            | ast::AssertionKind::WordBoundaryStartAngle
                            | ast::AssertionKind::WordBoundaryEndAngle
                            | ast::AssertionKind::WordBoundaryStartHalf
                            | ast::AssertionKind::WordBoundaryEndHalf
                    ) =>
            {
                self.reject(
                    &assertion.span,
                    "Unicode word-boundary data is unavailable in this Rust profile",
                )
            }
            Ast::ClassPerl(class) => self.class_perl(class),
            Ast::ClassUnicode(class) => self.class_unicode(class),
            _ => Ok(()),
        }
    }

    fn visit_post(&mut self, node: &Ast) -> Result<(), Self::Err> {
        match node {
            Ast::Flags(flags) => self.apply_flags(&flags.flags),
            Ast::Group(_) => {
                self.flags = self.group_flags.pop().ok_or_else(|| {
                    ParseError::new(
                        self.profile.clone(),
                        ErrorCategory::InvalidConfiguration,
                        "Unicode availability traversal lost group flag state",
                    )
                })?;
            }
            _ => {}
        }
        Ok(())
    }

    fn visit_class_set_item_pre(&mut self, item: &ast::ClassSetItem) -> Result<(), Self::Err> {
        self.charge(1)?;
        match item {
            ast::ClassSetItem::Perl(class) => self.class_perl(class),
            ast::ClassSetItem::Unicode(class) => self.class_unicode(class),
            _ => Ok(()),
        }
    }

    fn visit_class_set_binary_op_pre(
        &mut self,
        _op: &ast::ClassSetBinaryOp,
    ) -> Result<(), Self::Err> {
        self.charge(1)
    }
}

pub(crate) fn validate_regex_set_admission<P: AsRef<str>>(
    patterns: &[P],
    profile: &CompatibilityProfile,
) -> Result<(), RustRegexSetAdmissionError> {
    let (rust, utf8) = match profile {
        CompatibilityProfile::RustText(rust) => (rust, true),
        CompatibilityProfile::RustBytes(rust) => (rust, false),
        CompatibilityProfile::Re2(_) => {
            return Err(RustRegexSetAdmissionError {
                pattern: None,
                source: ParseError::new(
                    profile.clone(),
                    ErrorCategory::InvalidConfiguration,
                    "Rust regex set admission requires a Rust profile",
                ),
            });
        }
    };
    validate_rust_configuration(profile, &rust.options).map_err(|source| {
        RustRegexSetAdmissionError {
            pattern: None,
            source,
        }
    })?;
    if !rust.unicode_features.is_all() {
        for (index, pattern) in patterns.iter().enumerate() {
            let request = ParseRequest::rust(pattern.as_ref(), profile.clone());
            request
                .validate_and_charge_source()
                .and_then(|()| parse_rust(request, false).map(|_| ()))
                .map_err(|source| RustRegexSetAdmissionError {
                    pattern: Some(index),
                    source,
                })?;
        }
    }
    let (size_limit, dfa_size_limit) = match rust.constructor {
        RustConstructor::RegexBuilder {
            size_limit,
            dfa_size_limit,
            ..
        }
        | RustConstructor::RegexSetBuilder {
            size_limit,
            dfa_size_limit,
            ..
        } => (size_limit, dfa_size_limit),
        RustConstructor::RebarMeta { .. } => return Ok(()),
    };
    let limit = usize::try_from(size_limit).map_err(|_| RustRegexSetAdmissionError {
        pattern: None,
        source: ParseError::new(
            profile.clone(),
            ErrorCategory::InvalidConfiguration,
            "the high-level Rust regex set size limit does not fit this target",
        ),
    })?;
    let dfa_size_limit =
        usize::try_from(dfa_size_limit).map_err(|_| RustRegexSetAdmissionError {
            pattern: None,
            source: ParseError::new(
                profile.clone(),
                ErrorCategory::InvalidConfiguration,
                "the high-level Rust regex set DFA size limit does not fit this target",
            ),
        })?;
    let options = &rust.options;
    let metac = meta::Config::new()
        .nfa_size_limit(Some(limit))
        .hybrid_cache_capacity(dfa_size_limit)
        .match_kind(MatchKind::All)
        .utf8_empty(utf8)
        .line_terminator(options.line_terminator)
        .which_captures(WhichCaptures::None);
    let syntaxc = syntax::Config::new()
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
    meta::Builder::new()
        .configure(metac)
        .syntax(syntaxc)
        .build_many(patterns)
        .map(|_| ())
        .map_err(|error| map_regex_set_build_error(&error, profile))
}

fn map_regex_set_build_error(
    error: &meta::BuildError,
    profile: &CompatibilityProfile,
) -> RustRegexSetAdmissionError {
    let pattern = error.pattern().map(|id| id.as_usize());
    let mut source = if let Some(limit) = error.size_limit() {
        ParseError::new(
            profile.clone(),
            ErrorCategory::UpstreamRustCompiledTooBig {
                limit: u64::try_from(limit).unwrap_or(u64::MAX),
            },
            format!("Compiled regex exceeds size limit of {limit} bytes."),
        )
    } else if let Some(syntax_error) = error.syntax_error() {
        ParseError::new(
            profile.clone(),
            ErrorCategory::UpstreamRustSyntax,
            syntax_error.to_string(),
        )
    } else {
        ParseError::new(
            profile.clone(),
            ErrorCategory::UpstreamRustSyntax,
            error.to_string(),
        )
    };
    if let Some(syntax_error) = error.syntax_error() {
        let span = match syntax_error {
            regex_syntax::Error::Parse(error) => Some(error.span()),
            regex_syntax::Error::Translate(error) => Some(error.span()),
            _ => None,
        };
        if let Some(span) = span {
            source = source.with_span(crate::SourceSpan {
                start: u64::try_from(span.start.offset).unwrap_or(u64::MAX),
                end: u64::try_from(span.end.offset).unwrap_or(u64::MAX),
            });
        }
    }
    RustRegexSetAdmissionError { pattern, source }
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
        // NFA in `validate_regex_set_admission`, never to a constituent pattern.
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
                && rust.unicode_features.is_all()
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
