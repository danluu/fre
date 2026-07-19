use regex_automata::{MatchKind, meta, nfa::thompson::WhichCaptures, util::syntax};
use regex_syntax::{
    ParserBuilder,
    ast::{self, Ast},
    hir::{Class, Hir, HirKind},
};

const UNICODE_BOOL_PROPERTY_ALIASES: &[&str] = include!("unicode_bool_aliases.in");
const MAX_UNICODE_BOOL_ALIAS_BYTES: usize = 30;
const UNICODE_GENCAT_ALIASES: &[&str] = include!("unicode_gencat_aliases.in");
const MAX_UNICODE_GENCAT_ALIAS_BYTES: usize = 20;

use crate::{
    AdmissionPolicy, AdmissionStatus, CacheKey, CanonicalPattern, CompatibilityProfile,
    ErrorCategory, ParseError, ParseRecord, ParseRequest, ParseSummary, ResourceKind,
    RustAstRecord, RustConstructor, RustOptions, RustParsed, RustRegexSetAdmissionError,
    RustUnicodeFeatures, SCHEMA_VERSION, SafetyEnvelope, UnicodeVersion,
};

// The 0.8.11 AST parser is single-pass. Its final AST can contain synthetic
// empty branches in addition to nodes directly introduced by source tokens:
// for example, `|` produces an Alternation containing two Empty children.
// Inspection of the pinned parser's primitive, group, repetition, class,
// Concat::into_ast and Alternation::into_ast construction sites gives the
// conservative bound `2 * source_bytes + 2`: leaf and unary nodes are bounded
// by source bytes plus one synthetic empty endpoint, and branching containers
// have at least two children and are therefore bounded by the leaves beneath
// them. Nesting, parser-stack and work reservations remain separately bounded
// by source units. The fixed work multiplier covers token classification,
// UTF-8 decoding, span maintenance, checked nesting, and collection
// bookkeeping before any of those operations execute.
const AST_PARSE_WORK_PER_SOURCE_UNIT: u64 = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AstParseReservation {
    nodes: u64,
    max_nesting: u64,
    parser_stack: u64,
    work: u64,
}

pub(crate) fn parse_rust_ast(request: ParseRequest) -> Result<RustAstRecord, ParseError> {
    let (pattern, profile, admission, safety) = request.into_parts();
    let Some(source) = pattern.as_str() else {
        return Err(ParseError::new(
            profile,
            ErrorCategory::InvalidPatternEncoding,
            "Rust regex patterns must be valid UTF-8 strings",
        ));
    };
    let options = match &profile {
        CompatibilityProfile::RustText(rust) | CompatibilityProfile::RustBytes(rust) => {
            &rust.options
        }
        CompatibilityProfile::Re2(_) => unreachable!("dispatch validated profile"),
    };
    validate_rust_configuration(&profile, options)?;
    let reservation = reserve_ast_parse(source, options, &profile, admission, safety)?;

    let mut builder = ast::parse::ParserBuilder::new();
    builder
        .nest_limit(options.nest_limit)
        .octal(options.octal)
        .ignore_whitespace(options.ignore_whitespace);
    let ast = builder.build().parse(source).map_err(|error| {
        with_regex_span(
            ParseError::new(
                profile.clone(),
                ErrorCategory::UpstreamRustSyntax,
                error.to_string(),
            ),
            Some(error.span()),
        )
    })?;
    Ok(RustAstRecord {
        key: CacheKey {
            schema_version: SCHEMA_VERSION,
            pattern,
            profile,
            admission,
            safety,
        },
        admission_status: AdmissionStatus::from_policy(admission),
        reserved_ast_nodes: reservation.nodes,
        reserved_max_nesting: reservation.max_nesting,
        reserved_parser_stack: reservation.parser_stack,
        reserved_parse_work: reservation.work,
        ast,
    })
}

fn reserve_ast_parse(
    source: &str,
    options: &RustOptions,
    profile: &CompatibilityProfile,
    admission: AdmissionPolicy,
    safety: SafetyEnvelope,
) -> Result<AstParseReservation, ParseError> {
    let bytes = u64::try_from(source.len()).unwrap_or(u64::MAX);
    let source_units = bytes.saturating_add(1);
    let nodes = ast_node_upper_bound(bytes);
    // No nested parser construct can begin without consuming a source byte,
    // and the pinned parser independently refuses depth above `nest_limit`.
    let configured_depth = u64::from(options.nest_limit).saturating_add(1);
    let max_nesting = source_units.min(configured_depth);
    let parser_stack = max_nesting;
    let work = source_units.saturating_mul(AST_PARSE_WORK_PER_SOURCE_UNIT);
    for (resource, observed) in [
        (ResourceKind::HirNodes, nodes),
        (ResourceKind::Nesting, max_nesting),
        (ResourceKind::TraversalStack, parser_stack),
        (ResourceKind::ParseWork, work),
    ] {
        if observed > admission.limit_for(resource, safety) {
            return Err(admission.limit_error(profile.clone(), resource, safety, observed));
        }
    }
    Ok(AstParseReservation {
        nodes,
        max_nesting,
        parser_stack,
        work,
    })
}

fn ast_node_upper_bound(source_bytes: u64) -> u64 {
    source_bytes
        .checked_mul(2)
        .and_then(|nodes| nodes.checked_add(2))
        .unwrap_or(u64::MAX)
}

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

enum ClassAnalysisNode<'a> {
    Set(&'a ast::ClassSet),
    Item(&'a ast::ClassSetItem),
}

const UNICODE_CASE_CODEPOINTS: u64 = 0x11_0000;
const UNICODE_CASE_TABLE_KEYS: u64 = 2_938;
const UNICODE_CASE_MAX_FOLDS_PER_KEY: u64 = 3;
const UNICODE_CASE_MAPPING_WORK_PER_CODEPOINT: u64 = 20;
const UNICODE_CASE_CANONICALIZE_WORK_PER_RANGE: u64 = 256;
const UNICODE_GENCAT_MAX_TABLE_RANGES: u64 = 736;
const UNICODE_GENCAT_SCALAR_RANGE_CEILING: u64 = 0x10_F800;
const UNICODE_GENCAT_CLASS_WORK_PER_RANGE: u64 = 24;
const UNICODE_GENCAT_SET_WORK_PER_RANGE_SITE: u64 = 128;

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

    fn require_case(&mut self, span: &ast::Span) -> Result<bool, ParseError> {
        // Charge each branch/feature comparison performed by this classifier.
        // `has_case` performs at most two comparisons (`ALL`, then `CASE`), so
        // both are charged before consulting it. This keeps the gate bounded
        // independently of whether the requested profile owns the table.
        self.charge(1)?;
        if !self.flags.case_insensitive {
            return Ok(false);
        }
        self.charge(1)?;
        if !self.flags.unicode {
            return Ok(false);
        }
        self.charge(2)?;
        if self.features.has_case() {
            return Ok(true);
        }
        self.reject(
            span,
            "Unicode case-folding data is unavailable in this Rust profile",
        )?;
        Ok(false)
    }

    fn charge_case_fold_literal(&mut self) -> Result<(), ParseError> {
        // Two pinned-table binary searches, the ordered mapping lookup and a
        // maximum three-member equivalence class all fit within this bound.
        // Reserving it before translation prevents a quota from being checked
        // only after regex-syntax has already done the work.
        self.charge(64)
    }

    fn charge_case_fold_class(&mut self, class: &ast::ClassBracketed) -> Result<(), ParseError> {
        // regex-syntax 0.8.11 / Unicode 16.0 has exactly 2,938 simple-fold
        // keys and at most three mapped scalars per key. Its class folder does
        // an ordered mapping lookup for every scalar in each canonical input
        // range, then canonicalizes the original and appended ranges. We
        // derive conservative scalar/range upper bounds from this exact AST,
        // charging the auxiliary analysis itself as it runs.
        let mut stack = Vec::new();
        self.push_class_analysis_node(&mut stack, ClassAnalysisNode::Set(&class.kind))?;
        let mut codepoints = 0_u64;
        let mut ranges = 0_u64;
        // The root bracket is folded once. ASCII items and nested brackets
        // are folded before union, and each binary operator folds both sides
        // before applying the operator. Multiplying the aggregate upper bound
        // by all sites conservatively covers repeated folding at every level.
        let mut fold_sites = 1_u64;
        loop {
            // Charge the emptiness comparison before the pop, then reserve
            // the enum/cardinality branch and checked/capped arithmetic.
            self.charge(1)?;
            let Some(node) = stack.pop() else {
                break;
            };
            self.charge(7)?;
            match node {
                ClassAnalysisNode::Set(ast::ClassSet::Item(item)) => {
                    self.push_class_analysis_node(&mut stack, ClassAnalysisNode::Item(item))?;
                }
                ClassAnalysisNode::Set(ast::ClassSet::BinaryOp(op)) => {
                    fold_sites = fold_sites.saturating_add(2);
                    self.push_class_analysis_node(&mut stack, ClassAnalysisNode::Set(&op.lhs))?;
                    self.push_class_analysis_node(&mut stack, ClassAnalysisNode::Set(&op.rhs))?;
                }
                ClassAnalysisNode::Item(
                    ast::ClassSetItem::Empty(_)
                    | ast::ClassSetItem::Unicode(_)
                    | ast::ClassSetItem::Perl(_),
                ) => {
                    // A CASE-only profile rejects Unicode/Perl families later
                    // in this same walk, before translation can fold them.
                    // An empty set likewise requires no table work.
                }
                ClassAnalysisNode::Item(ast::ClassSetItem::Literal(_)) => {
                    codepoints = codepoints.saturating_add(1).min(UNICODE_CASE_CODEPOINTS);
                    ranges = ranges.saturating_add(1);
                }
                ClassAnalysisNode::Item(ast::ClassSetItem::Range(range)) => {
                    let width = u64::from(u32::from(range.end.c))
                        .saturating_sub(u64::from(u32::from(range.start.c)))
                        .saturating_add(1);
                    codepoints = codepoints
                        .saturating_add(width)
                        .min(UNICODE_CASE_CODEPOINTS);
                    ranges = ranges.saturating_add(1);
                }
                ClassAnalysisNode::Item(ast::ClassSetItem::Ascii(_)) => {
                    // Every POSIX ASCII class is a subset of the 128 ASCII
                    // scalars and has at most that many singleton ranges.
                    codepoints = codepoints.saturating_add(128).min(UNICODE_CASE_CODEPOINTS);
                    ranges = ranges.saturating_add(128);
                    fold_sites = fold_sites.saturating_add(1);
                }
                ClassAnalysisNode::Item(ast::ClassSetItem::Bracketed(nested)) => {
                    fold_sites = fold_sites.saturating_add(1);
                    // regex-syntax folds the positive nested class before
                    // negation and preserves the folded marker through that
                    // negation. Therefore only the nested positive operands,
                    // visited below, contribute table lookups.
                    self.push_class_analysis_node(
                        &mut stack,
                        ClassAnalysisNode::Set(&nested.kind),
                    )?;
                }
                ClassAnalysisNode::Item(ast::ClassSetItem::Union(union)) => {
                    ranges =
                        ranges.saturating_add(u64::try_from(union.items.len()).unwrap_or(u64::MAX));
                    for item in &union.items {
                        self.push_class_analysis_node(&mut stack, ClassAnalysisNode::Item(item))?;
                    }
                }
            }
        }

        if codepoints == 0 {
            return Ok(());
        }
        let mapping_work = codepoints
            .saturating_mul(fold_sites)
            .saturating_mul(UNICODE_CASE_MAPPING_WORK_PER_CODEPOINT);
        let fold_outputs = UNICODE_CASE_TABLE_KEYS.saturating_mul(UNICODE_CASE_MAX_FOLDS_PER_KEY);
        let canonicalize_work = ranges
            .saturating_add(fold_outputs)
            .saturating_mul(fold_sites)
            .saturating_mul(UNICODE_CASE_CANONICALIZE_WORK_PER_RANGE);
        self.charge(mapping_work)?;
        self.charge(canonicalize_work)
    }

    fn push_class_analysis_node<'a>(
        &mut self,
        stack: &mut Vec<ClassAnalysisNode<'a>>,
        node: ClassAnalysisNode<'a>,
    ) -> Result<(), ParseError> {
        // Reserve the length conversion, checked increment and limit
        // comparison before observing or mutating the auxiliary stack.
        self.charge(3)?;
        let pending = u64::try_from(stack.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let limit = self
            .admission
            .limit_for(ResourceKind::TraversalStack, self.safety);
        if pending > limit {
            return Err(self.admission.limit_error(
                self.profile.clone(),
                ResourceKind::TraversalStack,
                self.safety,
                pending,
            ));
        }
        stack.push(node);
        Ok(())
    }

    fn charge_gencat_class_set(&mut self, class: &ast::ClassBracketed) -> Result<(), ParseError> {
        // Charge the Unicode-flag branch and both comparisons in `has_gencat`
        // before selecting this analysis. Profiles without the table never
        // reach translation.
        self.charge(3)?;
        if !self.flags.unicode || !self.features.has_gencat() {
            return Ok(());
        }

        // A general-category range vector can be copied, canonicalized and
        // combined again at every nested bracket or binary-set site. Analyze
        // the exact class topology prospectively. The range ceiling is the
        // number of Rust Unicode scalar values; the table ceiling is the 736
        // ranges in regex-syntax 0.8.11's largest category (`Other`). The
        // per-site multiplier covers Vec allocation/copy, sorting,
        // comparison, deduplication, union/intersection/difference and the
        // extra clone/three set operations used by symmetric difference.
        let mut stack = Vec::new();
        self.push_class_analysis_node(&mut stack, ClassAnalysisNode::Set(&class.kind))?;
        let mut range_ceiling = 0_u64;
        let mut translation_sites = 1_u64;
        let mut gencat_sources = 0_u64;
        loop {
            self.charge(1)?;
            let Some(node) = stack.pop() else {
                break;
            };
            self.charge(7)?;
            match node {
                ClassAnalysisNode::Set(ast::ClassSet::Item(item)) => {
                    self.push_class_analysis_node(&mut stack, ClassAnalysisNode::Item(item))?;
                }
                ClassAnalysisNode::Set(ast::ClassSet::BinaryOp(op)) => {
                    // The worst operation is symmetric difference: clone,
                    // intersect, union and difference, followed by union into
                    // the enclosing frame.
                    translation_sites = translation_sites.saturating_add(5);
                    self.push_class_analysis_node(&mut stack, ClassAnalysisNode::Set(&op.lhs))?;
                    self.push_class_analysis_node(&mut stack, ClassAnalysisNode::Set(&op.rhs))?;
                }
                ClassAnalysisNode::Item(ast::ClassSetItem::Empty(_)) => {}
                ClassAnalysisNode::Item(
                    ast::ClassSetItem::Literal(_) | ast::ClassSetItem::Range(_),
                ) => {
                    range_ceiling = range_ceiling.saturating_add(1);
                    translation_sites = translation_sites.saturating_add(1);
                }
                ClassAnalysisNode::Item(ast::ClassSetItem::Ascii(_)) => {
                    range_ceiling = range_ceiling.saturating_add(128);
                    translation_sites = translation_sites.saturating_add(2);
                }
                ClassAnalysisNode::Item(ast::ClassSetItem::Unicode(_)) => {
                    range_ceiling = range_ceiling.saturating_add(UNICODE_GENCAT_MAX_TABLE_RANGES);
                    translation_sites = translation_sites.saturating_add(2);
                    gencat_sources = gencat_sources.saturating_add(1);
                }
                ClassAnalysisNode::Item(ast::ClassSetItem::Perl(perl)) => {
                    if matches!(perl.kind, ast::ClassPerlKind::Digit) {
                        range_ceiling =
                            range_ceiling.saturating_add(UNICODE_GENCAT_MAX_TABLE_RANGES);
                        translation_sites = translation_sites.saturating_add(2);
                        gencat_sources = gencat_sources.saturating_add(1);
                    }
                }
                ClassAnalysisNode::Item(ast::ClassSetItem::Bracketed(nested)) => {
                    translation_sites = translation_sites.saturating_add(2);
                    self.push_class_analysis_node(
                        &mut stack,
                        ClassAnalysisNode::Set(&nested.kind),
                    )?;
                }
                ClassAnalysisNode::Item(ast::ClassSetItem::Union(union)) => {
                    translation_sites = translation_sites
                        .saturating_add(u64::try_from(union.items.len()).unwrap_or(u64::MAX));
                    for item in &union.items {
                        self.push_class_analysis_node(&mut stack, ClassAnalysisNode::Item(item))?;
                    }
                }
            }
            range_ceiling = range_ceiling.min(UNICODE_GENCAT_SCALAR_RANGE_CEILING);
        }
        if gencat_sources == 0 {
            return Ok(());
        }
        self.charge(
            range_ceiling
                .saturating_mul(translation_sites)
                .saturating_mul(UNICODE_GENCAT_SET_WORK_PER_RANGE_SITE),
        )
    }

    fn normalize_gencat_symbol(
        &mut self,
        raw: &str,
        normalized: &mut [u8; MAX_UNICODE_GENCAT_ALIAS_BYTES],
    ) -> Result<Option<usize>, ParseError> {
        let raw_len = u64::try_from(raw.len()).unwrap_or(u64::MAX);
        // Reserve our classifier scan plus regex-syntax's Vec allocation,
        // source copy, in-place normalization and UTF-8 validation before
        // examining the bytes.
        self.charge(raw_len.saturating_mul(4).saturating_add(4))?;
        let bytes = raw.as_bytes();
        let starts_with_is = bytes.len() >= 2
            && bytes[0].eq_ignore_ascii_case(&b'i')
            && bytes[1].eq_ignore_ascii_case(&b's');
        let start = if starts_with_is { 2 } else { 0 };
        let mut len = 0_usize;
        for &byte in &bytes[start..] {
            let Some(byte) = (match byte {
                b' ' | b'_' | b'-' => None,
                0x00..=0x7F => Some(byte.to_ascii_lowercase()),
                _ => None,
            }) else {
                continue;
            };
            if len == normalized.len() {
                return Ok(None);
            }
            normalized[len] = byte;
            len = len.saturating_add(1);
        }
        // Match regex-syntax's ISO_Comment collision exception: `IsC`
        // normalizes to `isc`, not the general category alias `c`.
        if starts_with_is && len == 1 && normalized[0] == b'c' {
            normalized[0] = b'i';
            normalized[1] = b's';
            normalized[2] = b'c';
            len = 3;
        }
        Ok(Some(len))
    }

    fn normalized_is_gencat_alias(&mut self, normalized: &[u8]) -> Result<bool, ParseError> {
        for &alias in UNICODE_GENCAT_ALIASES {
            self.charge(1)?;
            if alias.len() != normalized.len() {
                continue;
            }
            let mut equal = true;
            for (&actual, &expected) in normalized.iter().zip(alias.as_bytes()) {
                self.charge(1)?;
                if actual != expected {
                    equal = false;
                    break;
                }
            }
            if equal {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn normalized_is_gencat_property_name(
        &mut self,
        normalized: &[u8],
    ) -> Result<bool, ParseError> {
        for expected in [b"gc".as_slice(), b"generalcategory".as_slice()] {
            self.charge(1)?;
            if normalized.len() != expected.len() {
                continue;
            }
            let mut equal = true;
            for (&actual, &expected) in normalized.iter().zip(expected) {
                self.charge(1)?;
                if actual != expected {
                    equal = false;
                    break;
                }
            }
            if equal {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn charge_gencat_table_translation(&mut self, query_bytes: u64) -> Result<(), ParseError> {
        // The exact pinned tables contain 271 property-name aliases, seven
        // property-value families, 80 General_Category value aliases and 37
        // materialized category sets. Thirty-two full-query comparisons are
        // a conservative ceiling for all binary searches and collision
        // branches. The range term reserves the largest source table, its
        // Vec allocation/copy, canonical-order scan/dedup and a possible
        // negation allocation before translation begins.
        self.charge(query_bytes.saturating_mul(32).saturating_add(512))?;
        self.charge(
            UNICODE_GENCAT_MAX_TABLE_RANGES.saturating_mul(UNICODE_GENCAT_CLASS_WORK_PER_RANGE),
        )
    }

    fn is_unicode_gencat_class(&mut self, class: &ast::ClassUnicode) -> Result<bool, ParseError> {
        // Reserve the AST-kind branch and both feature comparisons before
        // classifying the query.
        self.charge(3)?;
        if !self.features.has_gencat() {
            return Ok(false);
        }
        let mut name_buf = [0_u8; MAX_UNICODE_GENCAT_ALIAS_BYTES];
        let mut value_buf = [0_u8; MAX_UNICODE_GENCAT_ALIAS_BYTES];
        let (accepted, query_bytes) = match &class.kind {
            ast::ClassUnicodeKind::OneLetter(value) => {
                let mut encoded = [0_u8; 4];
                let raw = value.encode_utf8(&mut encoded);
                let Some(len) = self.normalize_gencat_symbol(raw, &mut value_buf)? else {
                    return Ok(false);
                };
                (
                    self.normalized_is_gencat_alias(&value_buf[..len])?,
                    u64::try_from(raw.len()).unwrap_or(u64::MAX),
                )
            }
            ast::ClassUnicodeKind::Named(value) => {
                let Some(len) = self.normalize_gencat_symbol(value, &mut value_buf)? else {
                    return Ok(false);
                };
                (
                    self.normalized_is_gencat_alias(&value_buf[..len])?,
                    u64::try_from(value.len()).unwrap_or(u64::MAX),
                )
            }
            ast::ClassUnicodeKind::NamedValue { name, value, .. } => {
                let Some(name_len) = self.normalize_gencat_symbol(name, &mut name_buf)? else {
                    return Ok(false);
                };
                let Some(value_len) = self.normalize_gencat_symbol(value, &mut value_buf)? else {
                    return Ok(false);
                };
                let name_matches =
                    self.normalized_is_gencat_property_name(&name_buf[..name_len])?;
                let value_matches = self.normalized_is_gencat_alias(&value_buf[..value_len])?;
                self.charge(1)?;
                (
                    name_matches && value_matches,
                    u64::try_from(name.len())
                        .unwrap_or(u64::MAX)
                        .saturating_add(u64::try_from(value.len()).unwrap_or(u64::MAX)),
                )
            }
        };
        if accepted {
            self.charge_gencat_table_translation(query_bytes)?;
        }
        Ok(accepted)
    }

    fn class_perl(&mut self, class: &ast::ClassPerl) -> Result<(), ParseError> {
        self.charge(3)?;
        if !self.flags.unicode {
            return Ok(());
        }
        if self.features.has_bool() && matches!(class.kind, ast::ClassPerlKind::Space) {
            // Upstream treats direct Perl classes as already closed under
            // simple case folding. (`[\s]` remains a bracketed class and is
            // checked separately.)
            return Ok(());
        }
        self.charge(2)?;
        if self.features.has_gencat() && matches!(class.kind, ast::ClassPerlKind::Digit) {
            self.charge_gencat_table_translation(1)?;
            return Ok(());
        }
        self.reject(
            &class.span,
            "Unicode Perl-class data is unavailable in this Rust profile",
        )
    }

    fn class_unicode(&mut self, class: &ast::ClassUnicode) -> Result<(), ParseError> {
        // Reserve the Unicode-flag branch plus the AGE and BOOL feature
        // guards before any family-specific classifier executes. GENCAT's
        // own feature/class-kind branches are charged in its helper.
        self.charge(5)?;
        if !self.flags.unicode {
            return Ok(());
        }
        match &class.kind {
            ast::ClassUnicodeKind::NamedValue { name, .. } if self.features.has_age() => {
                self.charge(u64::try_from(name.len()).unwrap_or(u64::MAX))?;
                if is_unicode_age_property_name(name) {
                    self.require_case(&class.span)?;
                    return Ok(());
                }
            }
            ast::ClassUnicodeKind::Named(name) if self.features.has_bool() => {
                if self.is_unicode_bool_property_name(name)? {
                    self.require_case(&class.span)?;
                    return Ok(());
                }
            }
            _ if self.is_unicode_gencat_class(class)? => {
                self.require_case(&class.span)?;
                return Ok(());
            }
            _ => {}
        }
        self.reject(
            &class.span,
            "Unicode property data is unavailable in this Rust profile",
        )
    }

    fn is_unicode_bool_property_name(&mut self, name: &str) -> Result<bool, ParseError> {
        // Match `regex-syntax` 0.8.11's UAX44-LM3 normalization without an
        // allocation. Every source byte and every alias comparison is charged
        // before it is examined. The fixed buffer is exactly the longest
        // authenticated alias in `unicode_bool_aliases.in`.
        self.charge(u64::try_from(name.len()).unwrap_or(u64::MAX))?;
        let raw = name.as_bytes();
        let starts_with_is = raw.len() >= 2
            && raw[0].eq_ignore_ascii_case(&b'i')
            && raw[1].eq_ignore_ascii_case(&b's');
        let start = if starts_with_is { 2 } else { 0 };
        let mut normalized = [0_u8; MAX_UNICODE_BOOL_ALIAS_BYTES];
        let mut normalized_len = 0_usize;
        for &byte in &raw[start..] {
            let Some(byte) = (match byte {
                b' ' | b'_' | b'-' => None,
                0x00..=0x7F => Some(byte.to_ascii_lowercase()),
                _ => None,
            }) else {
                continue;
            };
            if normalized_len == normalized.len() {
                return Ok(false);
            }
            normalized[normalized_len] = byte;
            normalized_len = normalized_len.saturating_add(1);
        }
        let normalized = &normalized[..normalized_len];
        // `isc` is upstream's exception to stripping an `Is` prefix. Charge
        // the length and byte comparisons explicitly before applying it. It
        // is an ISO_Comment alias, never a binary-property alias.
        if starts_with_is {
            self.charge(1)?;
            if normalized.len() == 1 {
                self.charge(1)?;
                if normalized[0] == b'c' {
                    return Ok(false);
                }
            }
        }
        for &alias in UNICODE_BOOL_PROPERTY_ALIASES {
            self.charge(1)?;
            if alias.len() != normalized.len() {
                continue;
            }
            let mut equal = true;
            for (&actual, &expected) in normalized.iter().zip(alias.as_bytes()) {
                self.charge(1)?;
                if actual != expected {
                    equal = false;
                    break;
                }
            }
            if equal {
                return Ok(true);
            }
        }
        Ok(false)
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
            Ast::Literal(literal) => {
                if self.require_case(&literal.span)? {
                    self.charge_case_fold_literal()?;
                }
                Ok(())
            }
            Ast::ClassBracketed(class) => {
                self.charge_gencat_class_set(class)?;
                if self.require_case(&class.span)? {
                    self.charge_case_fold_class(class)?;
                }
                Ok(())
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ast_node_upper_bound_covers_empty_alternations_and_overflow() {
        assert_eq!(ast_node_upper_bound(0), 2);
        assert_eq!(ast_node_upper_bound(1), 4);
        assert_eq!(ast_node_upper_bound(2), 6);
        assert_eq!(ast_node_upper_bound((u64::MAX - 2) / 2), u64::MAX - 1);
        assert_eq!(ast_node_upper_bound((u64::MAX - 1) / 2), u64::MAX);
        assert_eq!(ast_node_upper_bound(u64::MAX), u64::MAX);
    }

    #[test]
    fn unicode_case_work_constants_cover_pinned_lookup_and_sort_bounds() {
        const COMPARISON_EQUIVALENTS_PER_SORT_LEVEL: u64 = 8;
        const CANONICALIZE_LINEAR_PASSES: u64 = 4;

        let table_search_levels =
            u64::from(u64::BITS - (UNICODE_CASE_TABLE_KEYS.saturating_sub(1)).leading_zeros());
        // Besides binary search, mapping checks ordered input, the next
        // cursor, key equality, exhaustion and the successful-index invariant.
        assert!(UNICODE_CASE_MAPPING_WORK_PER_CODEPOINT >= table_search_levels + 7);

        let max_authenticated_input_ranges = SafetyEnvelope::default().max_pattern_bytes;
        let max_fold_outputs = UNICODE_CASE_TABLE_KEYS * UNICODE_CASE_MAX_FOLDS_PER_KEY;
        let max_sort_ranges = max_authenticated_input_ranges + max_fold_outputs;
        let sort_levels = u64::from(u64::BITS - max_sort_ranges.saturating_sub(1).leading_zeros());
        assert!(sort_levels <= 26);
        assert!(
            UNICODE_CASE_CANONICALIZE_WORK_PER_RANGE
                >= sort_levels * COMPARISON_EQUIVALENTS_PER_SORT_LEVEL + CANONICALIZE_LINEAR_PASSES
        );
        assert_eq!(UNICODE_CASE_CODEPOINTS, 0x11_0000);
    }
}
