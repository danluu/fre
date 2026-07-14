//! Iterative checked parser implementation.

use crate::ast::{
    AnchorKind, Ast, ClassAtom, ClassItem, ClassKind, Greediness, Node, NodeId, NodeKind,
    PatternSpan, PosixClass, RepeatRange, RepeatSyntax, Token, TokenKind,
};
use crate::error::{
    LimitKind, NotYetImplemented, ParseError, ParseErrorCode, ParseOutcome, ResourceUsage,
    UnsupportedFeature,
};
use crate::options::{Encoding, Options, ParseLimits, SyntaxMode};

const MAXIMUM_REPEAT_COUNT: u16 = 1_000;
const MAX_UNICODE: u32 = 0x10_FFFF;

#[allow(
    clippy::struct_excessive_bools,
    reason = "these bits are a direct internal projection of RE2 ParseFlags"
)]
#[derive(Clone, Copy, Debug)]
struct Flags {
    fold_case: bool,
    dot_nl: bool,
    one_line: bool,
    non_greedy: bool,
    perl_classes: bool,
    perl_b: bool,
    perl_x: bool,
    unicode_groups: bool,
    never_nl: bool,
}

impl Flags {
    fn from_options(options: Options) -> Self {
        let perl = options.syntax == SyntaxMode::Perl;
        Self {
            fold_case: !options.case_sensitive,
            dot_nl: options.dot_nl,
            // `Regexp::LikePerl` contains OneLine. `Options::one_line` can
            // additionally enable it in POSIX mode.
            one_line: perl || options.one_line,
            non_greedy: false,
            perl_classes: perl || options.perl_classes,
            perl_b: perl || options.word_boundary,
            perl_x: perl,
            unicode_groups: perl,
            never_nl: options.never_nl,
        }
    }
}

#[derive(Debug)]
struct Frame {
    open_start: usize,
    content_start: usize,
    saved_flags: Flags,
    capture: Option<(u32, Option<String>)>,
    branches: Vec<NodeId>,
    concat: Vec<NodeId>,
}

impl Frame {
    fn root(flags: Flags) -> Self {
        Self {
            open_start: 0,
            content_start: 0,
            saved_flags: flags,
            capture: None,
            branches: Vec::new(),
            concat: Vec::new(),
        }
    }
}

#[derive(Debug)]
enum Stop {
    Error(Box<ParseError>),
    NotYetImplemented(NotYetImplemented),
}

type PResult<T> = Result<T, Stop>;

/// Parses one RE2 pattern under an explicit resource envelope.
///
/// This recognizes a coherent direct subset of the pinned parser. Any syntax
/// whose exact behavior depends on an unimported upstream table returns
/// [`ParseOutcome::NotYetImplemented`].
#[must_use]
pub fn parse(pattern: &[u8], options: Options, limits: ParseLimits) -> ParseOutcome {
    let mut usage = ResourceUsage {
        source_bytes: pattern.len(),
        ..ResourceUsage::default()
    };
    if pattern.len() > limits.max_pattern_bytes {
        return ParseOutcome::Rejected(ParseError {
            code: ParseErrorCode::PatternTooLarge,
            argument: PatternSpan::new(0, pattern.len()),
            argument_bytes: pattern.into(),
            message: "pattern byte limit exceeded".to_owned(),
            limit: Some(LimitKind::PatternBytes),
            observed: Some(pattern.len()),
            usage,
        });
    }
    // UTF-8 validation and the mandatory source scan are linear work even
    // before the token loop begins.
    usage.work = pattern.len();
    if usage.work > limits.max_work {
        return ParseOutcome::Rejected(ParseError {
            code: ParseErrorCode::PatternTooLarge,
            argument: PatternSpan::new(0, 0),
            argument_bytes: Box::default(),
            message: "parser resource limit exceeded: Work".to_owned(),
            limit: Some(LimitKind::Work),
            observed: Some(usage.work),
            usage,
        });
    }
    if options.encoding == Encoding::Utf8 && core::str::from_utf8(pattern).is_err() {
        return ParseOutcome::Rejected(ParseError {
            code: ParseErrorCode::BadUtf8,
            // RE2's StringViewToRune sets an empty error argument.
            argument: PatternSpan::new(0, 0),
            argument_bytes: Box::default(),
            message: "invalid UTF-8 in pattern".to_owned(),
            limit: None,
            observed: None,
            usage,
        });
    }

    let mut parser = Parser::new(pattern, options, limits, usage);
    match parser.run() {
        Ok((nodes, root, tokens)) => {
            let Ok(capture_count) = u32::try_from(parser.capture_count) else {
                return ParseOutcome::Rejected(ParseError {
                    code: ParseErrorCode::PatternTooLarge,
                    argument: PatternSpan::new(0, 0),
                    argument_bytes: Box::default(),
                    message: "capture identifier range exceeded".to_owned(),
                    limit: Some(LimitKind::Captures),
                    observed: Some(parser.capture_count),
                    usage: parser.usage,
                });
            };
            ParseOutcome::Parsed {
                ast: Ast {
                    pattern: pattern.into(),
                    options,
                    nodes,
                    root,
                    tokens,
                    capture_count,
                },
                usage: parser.usage,
            }
        }
        Err(Stop::Error(error)) => ParseOutcome::Rejected(*error),
        Err(Stop::NotYetImplemented(incomplete)) => ParseOutcome::NotYetImplemented(incomplete),
    }
}

#[derive(Debug)]
struct Parser<'a> {
    source: &'a [u8],
    options: Options,
    limits: ParseLimits,
    usage: ResourceUsage,
    nodes: Vec<Node>,
    tokens: Vec<Token>,
    frames: Vec<Frame>,
    flags: Flags,
    position: usize,
    capture_count: usize,
    last_unary: Option<PatternSpan>,
}

impl<'a> Parser<'a> {
    fn new(source: &'a [u8], options: Options, limits: ParseLimits, usage: ResourceUsage) -> Self {
        let flags = Flags::from_options(options);
        Self {
            source,
            options,
            limits,
            usage,
            nodes: Vec::new(),
            tokens: Vec::new(),
            frames: vec![Frame::root(flags)],
            flags,
            position: 0,
            capture_count: 0,
            last_unary: None,
        }
    }

    fn run(&mut self) -> PResult<(Vec<Node>, NodeId, Vec<Token>)> {
        if self.options.literal {
            while self.position < self.source.len() {
                self.charge_work(1)?;
                let start = self.position;
                let (value, end) = self.decode_at(start)?;
                self.position = end;
                self.push_literal(value, PatternSpan::new(start, end), TokenKind::Literal)?;
            }
        } else {
            while self.position < self.source.len() {
                self.charge_work(1)?;
                let unary = self.parse_one()?;
                self.last_unary = unary;
            }
        }

        if self.frames.len() != 1 {
            return Err(self.error(
                ParseErrorCode::MissingParen,
                PatternSpan::new(0, self.source.len()),
                "missing closing parenthesis",
            ));
        }
        let frame = self.frames.pop().ok_or_else(|| {
            self.error(
                ParseErrorCode::Internal,
                PatternSpan::new(0, 0),
                "missing root parser frame",
            )
        })?;
        let root = self.finish_frame(frame, self.source.len())?;
        Ok((
            core::mem::take(&mut self.nodes),
            root,
            core::mem::take(&mut self.tokens),
        ))
    }

    /// Parses one main-loop token and returns a unary operator span when the
    /// token was a quantifier. RE2 resets `lastunary` after every other token.
    fn parse_one(&mut self) -> PResult<Option<PatternSpan>> {
        let start = self.position;
        match self.source[start] {
            b'(' => {
                self.parse_open_parenthesis()?;
                Ok(None)
            }
            b')' => {
                self.parse_close_parenthesis()?;
                Ok(None)
            }
            b'|' => {
                self.position = self.checked_advance(start, 1)?;
                self.add_token(
                    TokenKind::Alternation,
                    PatternSpan::new(start, self.position),
                )?;
                self.finish_current_branch(start)?;
                Ok(None)
            }
            b'^' | b'$' => {
                self.position = self.checked_advance(start, 1)?;
                let kind = if self.source[start] == b'^' {
                    if self.flags.one_line {
                        AnchorKind::BeginText
                    } else {
                        AnchorKind::BeginLine
                    }
                } else if self.flags.one_line {
                    AnchorKind::EndText
                } else {
                    AnchorKind::EndLine
                };
                let span = PatternSpan::new(start, self.position);
                let node = self.add_node(NodeKind::Anchor(kind), span)?;
                self.push_current(node)?;
                self.add_token(TokenKind::Anchor, span)?;
                Ok(None)
            }
            b'.' => {
                self.position = self.checked_advance(start, 1)?;
                let span = PatternSpan::new(start, self.position);
                let node = self.add_node(
                    NodeKind::AnyChar {
                        matches_newline: self.flags.dot_nl && !self.flags.never_nl,
                    },
                    span,
                )?;
                self.push_current(node)?;
                self.add_token(TokenKind::Dot, span)?;
                Ok(None)
            }
            b'[' => {
                let (node, end) = self.parse_class(start)?;
                self.position = end;
                self.push_current(node)?;
                Ok(None)
            }
            b'*' | b'+' | b'?' => self.parse_simple_repeat(start).map(Some),
            b'{' => {
                if let Some((range, end)) = self.maybe_counted_repeat(start)? {
                    self.apply_repeat(start, end, range, RepeatSyntax::Counted)?;
                    self.position = end;
                    let span = PatternSpan::new(start, end);
                    self.add_token(TokenKind::Quantifier, span)?;
                    Ok(Some(span))
                } else {
                    self.position = self.checked_advance(start, 1)?;
                    self.push_literal(
                        u32::from(b'{'),
                        PatternSpan::new(start, self.position),
                        TokenKind::Literal,
                    )?;
                    Ok(None)
                }
            }
            b'\\' => {
                self.parse_escape_outside(start)?;
                Ok(None)
            }
            _ => {
                let (value, end) = self.decode_at(start)?;
                self.position = end;
                self.push_literal(value, PatternSpan::new(start, end), TokenKind::Literal)?;
                Ok(None)
            }
        }
    }

    fn parse_open_parenthesis(&mut self) -> PResult<()> {
        let start = self.position;
        if self.flags.perl_x && self.source.get(start.saturating_add(1)).copied() == Some(b'?') {
            return self.parse_perl_parenthesis(start);
        }
        let end = self.checked_advance(start, 1)?;
        let capture = if self.options.never_capture {
            None
        } else {
            Some((self.next_capture(PatternSpan::new(start, end))?, None))
        };
        self.open_frame(start, end, capture, self.flags)?;
        self.position = end;
        self.add_token(TokenKind::OpenCapture, PatternSpan::new(start, end))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "keeping the pinned ParsePerlFlags state machine contiguous makes conformance auditing easier"
    )]
    fn parse_perl_parenthesis(&mut self, start: usize) -> PResult<()> {
        let tail = self.source.get(start..).unwrap_or_default();
        if tail.len() > 3 && (tail.starts_with(b"(?=") || tail.starts_with(b"(?!")) {
            return Err(self.error(
                ParseErrorCode::BadPerlOp,
                PatternSpan::new(start, start.saturating_add(3)),
                "look-around is not supported by RE2",
            ));
        }
        if tail.len() > 4 && (tail.starts_with(b"(?<=") || tail.starts_with(b"(?<!")) {
            return Err(self.error(
                ParseErrorCode::BadPerlOp,
                PatternSpan::new(start, start.saturating_add(4)),
                "look-around is not supported by RE2",
            ));
        }

        let name_start = if tail.len() > 4 && tail.starts_with(b"(?P<") {
            Some(start.saturating_add(4))
        } else if tail.len() > 3 && tail.starts_with(b"(?<") {
            Some(start.saturating_add(3))
        } else {
            None
        };
        if let Some(name_start) = name_start {
            let Some(name_end) = self.find_byte(name_start, b'>')? else {
                return Err(self.error(
                    ParseErrorCode::BadNamedCapture,
                    PatternSpan::new(start, self.source.len()),
                    "unterminated named capture",
                ));
            };
            let capture_end = name_end
                .checked_add(1)
                .ok_or_else(|| self.limit(LimitKind::IntegerArithmetic, start))?;
            let name_bytes = self.source.get(name_start..name_end).ok_or_else(|| {
                self.error(
                    ParseErrorCode::Internal,
                    PatternSpan::new(start, capture_end),
                    "named capture span escaped source",
                )
            })?;
            if name_bytes.iter().any(|byte| !byte.is_ascii()) {
                return Err(self.nyi(
                    UnsupportedFeature::UnicodeCaptureName,
                    PatternSpan::new(start, capture_end),
                    "RE2 validates Unicode category membership using generated tables",
                ));
            }
            if name_bytes.is_empty()
                || !name_bytes
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            {
                return Err(self.error(
                    ParseErrorCode::BadNamedCapture,
                    PatternSpan::new(start, capture_end),
                    "invalid named capture",
                ));
            }
            let name = String::from_utf8(name_bytes.to_vec()).map_err(|_| {
                self.error(
                    ParseErrorCode::Internal,
                    PatternSpan::new(name_start, name_end),
                    "ASCII capture name conversion failed",
                )
            })?;
            let capture = self.next_capture(PatternSpan::new(start, capture_end))?;
            self.open_frame(start, capture_end, Some((capture, Some(name))), self.flags)?;
            self.position = capture_end;
            return self.add_token(
                TokenKind::OpenNamedCapture,
                PatternSpan::new(start, capture_end),
            );
        }

        let mut flags = self.flags;
        let mut index = self.checked_advance(start, 2)?;
        let mut negated = false;
        let mut saw_flags = false;
        loop {
            if self.source.get(index).is_none() {
                return Err(self.error(
                    ParseErrorCode::BadPerlOp,
                    PatternSpan::new(start, self.source.len()),
                    "unterminated Perl flag operation",
                ));
            }
            self.charge_work(1)?;
            let (scalar, next) = self.decode_at(index)?;
            index = next;
            match u8::try_from(scalar).ok() {
                Some(b'i') => {
                    saw_flags = true;
                    flags.fold_case = !negated;
                }
                Some(b'm') => {
                    saw_flags = true;
                    flags.one_line = negated;
                }
                Some(b's') => {
                    saw_flags = true;
                    flags.dot_nl = !negated;
                }
                Some(b'U') => {
                    saw_flags = true;
                    flags.non_greedy = !negated;
                }
                Some(b'-') if !negated => {
                    negated = true;
                    saw_flags = false;
                }
                Some(b':') => {
                    if negated && !saw_flags {
                        return Err(self.error(
                            ParseErrorCode::BadPerlOp,
                            PatternSpan::new(start, index),
                            "empty negated Perl flag set",
                        ));
                    }
                    self.open_frame(start, index, None, flags)?;
                    self.flags = flags;
                    self.position = index;
                    return self
                        .add_token(TokenKind::OpenNonCapture, PatternSpan::new(start, index));
                }
                Some(b')') => {
                    if negated && !saw_flags {
                        return Err(self.error(
                            ParseErrorCode::BadPerlOp,
                            PatternSpan::new(start, index),
                            "empty negated Perl flag set",
                        ));
                    }
                    self.flags = flags;
                    self.position = index;
                    return self.add_token(TokenKind::InlineFlags, PatternSpan::new(start, index));
                }
                _ => {
                    return Err(self.error(
                        ParseErrorCode::BadPerlOp,
                        PatternSpan::new(start, index),
                        "unsupported Perl operator",
                    ));
                }
            }
        }
    }

    fn parse_close_parenthesis(&mut self) -> PResult<()> {
        let start = self.position;
        let end = self.checked_advance(start, 1)?;
        if self.frames.len() == 1 {
            return Err(self.error(
                ParseErrorCode::UnexpectedParen,
                PatternSpan::new(0, self.source.len()),
                "unexpected closing parenthesis",
            ));
        }
        let frame = self.frames.pop().ok_or_else(|| {
            self.error(
                ParseErrorCode::Internal,
                PatternSpan::new(start, end),
                "group frame stack underflow",
            )
        })?;
        self.flags = frame.saved_flags;
        let group = self.finish_frame(frame, end)?;
        self.push_current(group)?;
        self.position = end;
        self.add_token(TokenKind::CloseGroup, PatternSpan::new(start, end))
    }

    fn open_frame(
        &mut self,
        open_start: usize,
        content_start: usize,
        capture: Option<(u32, Option<String>)>,
        group_flags: Flags,
    ) -> PResult<()> {
        let depth = self.frames.len();
        if depth > self.limits.max_nesting {
            return Err(self.limit(LimitKind::Nesting, open_start));
        }
        let next_depth = depth
            .checked_add(1)
            .ok_or_else(|| self.limit(LimitKind::IntegerArithmetic, open_start))?;
        self.usage.maximum_nesting = self.usage.maximum_nesting.max(next_depth.saturating_sub(1));
        self.frames.push(Frame {
            open_start,
            content_start,
            saved_flags: self.flags,
            capture,
            branches: Vec::new(),
            concat: Vec::new(),
        });
        self.flags = group_flags;
        Ok(())
    }

    fn next_capture(&mut self, span: PatternSpan) -> PResult<u32> {
        if self.capture_count >= self.limits.max_captures {
            return Err(self.limit(LimitKind::Captures, span.start));
        }
        self.capture_count = self
            .capture_count
            .checked_add(1)
            .ok_or_else(|| self.limit(LimitKind::IntegerArithmetic, span.start))?;
        self.usage.captures = self.capture_count;
        u32::try_from(self.capture_count).map_err(|_| self.limit(LimitKind::Captures, span.start))
    }

    fn finish_current_branch(&mut self, empty_at: usize) -> PResult<()> {
        if self.frames.is_empty() {
            return Err(self.error(
                ParseErrorCode::Internal,
                PatternSpan::new(empty_at, empty_at),
                "missing parser frame",
            ));
        }
        let concat = {
            let Some(frame) = self.frames.last_mut() else {
                unreachable!("frame emptiness checked above");
            };
            core::mem::take(&mut frame.concat)
        };
        let branch = self.collapse_concat(concat, empty_at)?;
        let Some(frame) = self.frames.last_mut() else {
            unreachable!("branch collapse does not remove frames");
        };
        frame.branches.push(branch);
        Ok(())
    }

    fn finish_frame(&mut self, mut frame: Frame, end: usize) -> PResult<NodeId> {
        let current = self.collapse_concat(core::mem::take(&mut frame.concat), end)?;
        frame.branches.push(current);
        let inner = if frame.branches.len() == 1 {
            frame.branches[0]
        } else {
            self.add_node(
                NodeKind::Alternation {
                    branches: frame.branches,
                },
                PatternSpan::new(frame.content_start, end),
            )?
        };
        if let Some((index, name)) = frame.capture {
            self.add_node(
                NodeKind::Capture {
                    index,
                    name,
                    child: inner,
                },
                PatternSpan::new(frame.open_start, end),
            )
        } else {
            Ok(inner)
        }
    }

    fn collapse_concat(&mut self, children: Vec<NodeId>, empty_at: usize) -> PResult<NodeId> {
        match children.len() {
            0 => self.add_node(NodeKind::Empty, PatternSpan::new(empty_at, empty_at)),
            1 => Ok(children[0]),
            _ => {
                let start = children
                    .first()
                    .and_then(|id| self.node(*id))
                    .map_or(empty_at, |node| node.span.start);
                let end = children
                    .last()
                    .and_then(|id| self.node(*id))
                    .map_or(empty_at, |node| node.span.end);
                self.add_node(NodeKind::Concat { children }, PatternSpan::new(start, end))
            }
        }
    }

    fn parse_simple_repeat(&mut self, start: usize) -> PResult<PatternSpan> {
        let (min, max) = match self.source[start] {
            b'*' => (0, None),
            b'+' => (1, None),
            b'?' => (0, Some(1)),
            _ => {
                return Err(self.error(
                    ParseErrorCode::Internal,
                    PatternSpan::new(start, start),
                    "invalid simple repetition dispatch",
                ));
            }
        };
        let mut end = self.checked_advance(start, 1)?;
        if self.flags.perl_x && self.source.get(end).copied() == Some(b'?') {
            end = self.checked_advance(end, 1)?;
        }
        if self.flags.perl_x
            && let Some(previous) = self.last_unary
        {
            return Err(self.error(
                ParseErrorCode::RepeatOp,
                PatternSpan::new(previous.start, end),
                "stacked repetition operators",
            ));
        }
        self.apply_repeat(start, end, RepeatRange { min, max }, RepeatSyntax::Simple)?;
        self.position = end;
        let span = PatternSpan::new(start, end);
        self.add_token(TokenKind::Quantifier, span)?;
        Ok(span)
    }

    fn maybe_counted_repeat(&mut self, start: usize) -> PResult<Option<(RepeatRange, usize)>> {
        let mut index = self.checked_advance(start, 1)?;
        let Some((min, after_min)) = self.parse_decimal(index)? else {
            return Ok(None);
        };
        index = after_min;
        let max;
        match self.source.get(index).copied() {
            Some(b',') => {
                index = self.checked_advance(index, 1)?;
                if self.source.get(index).copied() == Some(b'}') {
                    max = None;
                } else {
                    let Some((parsed_max, after_max)) = self.parse_decimal(index)? else {
                        return Ok(None);
                    };
                    max = Some(parsed_max);
                    index = after_max;
                }
            }
            _ => max = Some(min),
        }
        if self.source.get(index).copied() != Some(b'}') {
            return Ok(None);
        }
        index = self.checked_advance(index, 1)?;
        if self.flags.perl_x && self.source.get(index).copied() == Some(b'?') {
            index = self.checked_advance(index, 1)?;
        }
        Ok(Some((RepeatRange { min, max }, index)))
    }

    fn parse_decimal(&mut self, start: usize) -> PResult<Option<(u16, usize)>> {
        let Some(&first) = self.source.get(start) else {
            return Ok(None);
        };
        if !first.is_ascii_digit() {
            return Ok(None);
        }
        if first == b'0'
            && self
                .source
                .get(start.saturating_add(1))
                .is_some_and(u8::is_ascii_digit)
        {
            return Ok(None);
        }
        let mut index = start;
        let mut value = 0u32;
        while let Some(&digit) = self.source.get(index) {
            if !digit.is_ascii_digit() {
                break;
            }
            self.charge_work(1)?;
            // Pinned RE2 refuses to recognize the suffix if its integer parser
            // reaches 100,000,000. Returning `None` makes `{` literal.
            if value >= 100_000_000 {
                return Ok(None);
            }
            value = value
                .checked_mul(10)
                .and_then(|n| n.checked_add(u32::from(digit.wrapping_sub(b'0'))))
                .ok_or_else(|| self.limit(LimitKind::IntegerArithmetic, start))?;
            index = self.checked_advance(index, 1)?;
        }
        // Values above u16 still form a recognized repetition and are rejected
        // by the 1000 bound. Saturation retains that classification.
        let narrowed = u16::try_from(value).unwrap_or(u16::MAX);
        Ok(Some((narrowed, index)))
    }

    fn apply_repeat(
        &mut self,
        start: usize,
        end: usize,
        range: RepeatRange,
        syntax: RepeatSyntax,
    ) -> PResult<()> {
        let span = PatternSpan::new(start, end);
        if range.min > MAXIMUM_REPEAT_COUNT
            || range.max.is_some_and(|max| max > MAXIMUM_REPEAT_COUNT)
            || range.max.is_some_and(|max| max < range.min)
        {
            return Err(self.error(ParseErrorCode::RepeatSize, span, "invalid repetition size"));
        }
        let explicit_non_greedy = self.flags.perl_x
            && end >= 1
            && self.source.get(end.saturating_sub(1)).copied() == Some(b'?')
            && end.saturating_sub(1) > start;
        let non_greedy = self.flags.non_greedy ^ explicit_non_greedy;
        let greediness = if non_greedy {
            Greediness::NonGreedy
        } else {
            Greediness::Greedy
        };
        let parse_flags = self.parse_flag_bits(non_greedy);

        if self.frames.is_empty() {
            return Err(self.error(
                ParseErrorCode::Internal,
                span,
                "missing parser frame for repetition",
            ));
        }
        let child = self
            .frames
            .last_mut()
            .and_then(|frame| frame.concat.pop())
            .ok_or_else(|| {
                self.error(
                    ParseErrorCode::RepeatArgument,
                    span,
                    "repetition operator has no argument",
                )
            })?;

        // Adjacent Perl operators were rejected using `last_unary`. Operators
        // separated by a non-capturing group, plus all POSIX operators, reach
        // RE2's flag-sensitive squash logic here.
        if syntax == RepeatSyntax::Simple
            && let Some(Node {
                kind:
                    NodeKind::Repeat {
                        child: inner,
                        range: prior_range,
                        greediness: prior_greediness,
                        syntax: RepeatSyntax::Simple,
                        parse_flags: prior_flags,
                    },
                span: prior_span,
            }) = self.node(child).cloned()
            && prior_flags == parse_flags
        {
            let same = prior_range == range && prior_greediness == greediness;
            let squashed_range = if same {
                prior_range
            } else {
                RepeatRange { min: 0, max: None }
            };
            let squashed = self.add_node(
                NodeKind::Repeat {
                    child: inner,
                    range: squashed_range,
                    greediness,
                    syntax,
                    parse_flags,
                },
                PatternSpan::new(prior_span.start, end),
            )?;
            return self.push_current(squashed);
        }

        let child_start = self.node(child).map_or(start, |node| node.span.start);
        let repeat = self.add_node(
            NodeKind::Repeat {
                child,
                range,
                greediness,
                syntax,
                parse_flags,
            },
            PatternSpan::new(child_start, end),
        )?;
        if syntax == RepeatSyntax::Counted
            && (range.min >= 2 || range.max.is_some_and(|max| max >= 2))
            && !self.counted_repeat_product_ok(repeat)?
        {
            return Err(self.error(
                ParseErrorCode::RepeatSize,
                span,
                "nested counted repetition product exceeds 1000",
            ));
        }
        self.push_current(repeat)
    }

    fn counted_repeat_product_ok(&mut self, root: NodeId) -> PResult<bool> {
        let mut stack = vec![(root, u32::from(MAXIMUM_REPEAT_COUNT))];
        while let Some((id, mut budget)) = stack.pop() {
            self.charge_work(1)?;
            let Some(node) = self.node(id) else {
                return Err(self.error(
                    ParseErrorCode::Internal,
                    PatternSpan::new(0, 0),
                    "counted repetition traversal found invalid node",
                ));
            };
            match &node.kind {
                NodeKind::Repeat {
                    child,
                    range,
                    syntax: RepeatSyntax::Counted,
                    ..
                } => {
                    let multiplier = range.max.unwrap_or(range.min);
                    if multiplier > 0 {
                        budget = budget.checked_div(u32::from(multiplier)).ok_or_else(|| {
                            self.error(
                                ParseErrorCode::Internal,
                                node.span,
                                "nonzero repetition multiplier failed division",
                            )
                        })?;
                    }
                    if budget == 0 {
                        return Ok(false);
                    }
                    stack.push((*child, budget));
                }
                NodeKind::Repeat { child, .. } | NodeKind::Capture { child, .. } => {
                    stack.push((*child, budget));
                }
                NodeKind::Concat { children } => {
                    stack.extend(children.iter().copied().map(|child| (child, budget)));
                }
                NodeKind::Alternation { branches } => {
                    stack.extend(branches.iter().copied().map(|child| (child, budget)));
                }
                _ => {}
            }
        }
        Ok(true)
    }

    fn parse_escape_outside(&mut self, start: usize) -> PResult<()> {
        let second = self
            .source
            .get(start.saturating_add(1))
            .copied()
            .ok_or_else(|| {
                self.error(
                    ParseErrorCode::TrailingBackslash,
                    PatternSpan::new(0, 0),
                    "trailing backslash",
                )
            })?;
        if self.flags.perl_b && matches!(second, b'b' | b'B') {
            let end = self.checked_advance(start, 2)?;
            let kind = if second == b'b' {
                AnchorKind::WordBoundary
            } else {
                AnchorKind::NotWordBoundary
            };
            let span = PatternSpan::new(start, end);
            let node = self.add_node(NodeKind::Anchor(kind), span)?;
            self.push_current(node)?;
            self.position = end;
            return self.add_token(TokenKind::Anchor, span);
        }
        if self.flags.perl_x {
            match second {
                b'A' | b'z' => {
                    let end = self.checked_advance(start, 2)?;
                    let kind = if second == b'A' {
                        AnchorKind::BeginText
                    } else {
                        AnchorKind::EndText
                    };
                    let span = PatternSpan::new(start, end);
                    let node = self.add_node(NodeKind::Anchor(kind), span)?;
                    self.push_current(node)?;
                    self.position = end;
                    return self.add_token(TokenKind::Anchor, span);
                }
                b'C' => {
                    let end = self.checked_advance(start, 2)?;
                    let span = PatternSpan::new(start, end);
                    let node = self.add_node(NodeKind::AnyByte, span)?;
                    self.push_current(node)?;
                    self.position = end;
                    return self.add_token(TokenKind::Escape, span);
                }
                b'Q' => return self.parse_quoted_literals(start),
                _ => {}
            }
        }
        if matches!(second, b'p' | b'P') && self.flags.unicode_groups {
            let (item, end) = self.parse_unicode_item(start)?;
            let span = PatternSpan::new(start, end);
            let node = self.add_node(
                NodeKind::Class {
                    kind: ClassKind::Unicode,
                    items: vec![item],
                    fold_case: self.flags.fold_case,
                    class_newline: true,
                    never_newline: self.flags.never_nl,
                },
                span,
            )?;
            self.charge_class_item(start)?;
            self.push_current(node)?;
            self.position = end;
            return self.add_token(TokenKind::Escape, span);
        }
        if self.flags.perl_classes
            && let Some(atom) = perl_class_atom(second)
        {
            let end = self.checked_advance(start, 2)?;
            let span = PatternSpan::new(start, end);
            let node = self.add_node(
                NodeKind::Class {
                    kind: ClassKind::Perl,
                    items: vec![ClassItem::Perl { atom, span }],
                    fold_case: self.flags.fold_case,
                    class_newline: true,
                    never_newline: self.flags.never_nl,
                },
                span,
            )?;
            self.charge_class_item(start)?;
            self.push_current(node)?;
            self.position = end;
            return self.add_token(TokenKind::Escape, span);
        }
        let (value, end) = self.parse_core_escape(start)?;
        self.position = end;
        self.push_literal(value, PatternSpan::new(start, end), TokenKind::Escape)
    }

    fn parse_quoted_literals(&mut self, start: usize) -> PResult<()> {
        let mut index = self.checked_advance(start, 2)?;
        while index < self.source.len() {
            self.charge_work(1)?;
            if self
                .source
                .get(index..)
                .is_some_and(|tail| tail.starts_with(b"\\E"))
            {
                index = self.checked_advance(index, 2)?;
                self.position = index;
                return self.add_token(TokenKind::QuotedLiteral, PatternSpan::new(start, index));
            }
            let literal_start = index;
            let (value, end) = self.decode_at(index)?;
            index = end;
            self.push_literal_node(value, PatternSpan::new(literal_start, end))?;
        }
        self.position = index;
        self.add_token(TokenKind::QuotedLiteral, PatternSpan::new(start, index))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "keeping the pinned ParseCharClass loop contiguous makes conformance auditing easier"
    )]
    fn parse_class(&mut self, start: usize) -> PResult<(NodeId, usize)> {
        let mut index = self.checked_advance(start, 1)?;
        let negated = self.source.get(index).copied() == Some(b'^');
        if negated {
            index = self.checked_advance(index, 1)?;
        }
        let mut first = true;
        let mut items = Vec::new();
        let mut posix_close_exhausted = false;
        loop {
            self.charge_work(1)?;
            let Some(&byte) = self.source.get(index) else {
                return Err(self.error(
                    ParseErrorCode::MissingBracket,
                    PatternSpan::new(start, self.source.len()),
                    "missing closing character-class bracket",
                ));
            };
            if byte == b']' && !first {
                index = self.checked_advance(index, 1)?;
                break;
            }

            if byte == b'-'
                && !first
                && !self.flags.perl_x
                && (self.source.get(index.saturating_add(1)).is_none()
                    || self.source.get(index.saturating_add(1)).copied() != Some(b']'))
            {
                let error_end = if index.saturating_add(1) < self.source.len() {
                    self.decode_at(index.saturating_add(1))?.1
                } else {
                    self.source.len()
                };
                return Err(self.error(
                    ParseErrorCode::BadCharRange,
                    PatternSpan::new(index, error_end),
                    "invalid unescaped hyphen placement",
                ));
            }
            first = false;

            if !posix_close_exhausted
                && self
                    .source
                    .get(index..)
                    .is_some_and(|tail| tail.starts_with(b"[:"))
            {
                if let Some(close_start) = self.find_pair(index.saturating_add(2), *b":]")? {
                    let end = close_start
                        .checked_add(2)
                        .ok_or_else(|| self.limit(LimitKind::IntegerArithmetic, index))?;
                    let name = self
                        .source
                        .get(index.saturating_add(2)..close_start)
                        .ok_or_else(|| {
                            self.error(
                                ParseErrorCode::Internal,
                                PatternSpan::new(index, end),
                                "POSIX class name span escaped source",
                            )
                        })?;
                    let Some((class, negated)) = posix_class(name) else {
                        return Err(self.error(
                            ParseErrorCode::BadCharRange,
                            PatternSpan::new(index, end),
                            "invalid POSIX character class name",
                        ));
                    };
                    let span = PatternSpan::new(index, end);
                    items.push(ClassItem::Posix {
                        class,
                        negated,
                        span,
                    });
                    self.charge_class_item(index)?;
                    index = end;
                    continue;
                }
                posix_close_exhausted = true;
            }
            if matches!(byte, b'\\')
                && self
                    .source
                    .get(index.saturating_add(1))
                    .is_some_and(|next| matches!(next, b'p' | b'P'))
                && self.flags.unicode_groups
            {
                let (item, end) = self.parse_unicode_item(index)?;
                items.push(item);
                self.charge_class_item(index)?;
                index = end;
                continue;
            }
            if byte == b'\\'
                && self.flags.perl_classes
                && let Some(atom) = self
                    .source
                    .get(index.saturating_add(1))
                    .copied()
                    .and_then(perl_class_atom)
            {
                let end = self.checked_advance(index, 2)?;
                let span = PatternSpan::new(index, end);
                items.push(ClassItem::Perl { atom, span });
                self.charge_class_item(index)?;
                index = end;
                continue;
            }

            let item_start = index;
            let (lo, after_lo) = self.parse_class_character(index, start)?;
            if self.source.get(after_lo).copied() == Some(b'-')
                && self.source.get(after_lo.saturating_add(1)).is_some()
                && self.source.get(after_lo.saturating_add(1)).copied() != Some(b']')
            {
                let (hi, after_hi) =
                    self.parse_class_character(after_lo.saturating_add(1), start)?;
                if hi < lo {
                    return Err(self.error(
                        ParseErrorCode::BadCharRange,
                        PatternSpan::new(item_start, after_hi),
                        "character-class range is reversed",
                    ));
                }
                let span = PatternSpan::new(item_start, after_hi);
                items.push(ClassItem::Range { lo, hi, span });
                self.charge_class_item(item_start)?;
                index = after_hi;
            } else {
                let span = PatternSpan::new(item_start, after_lo);
                items.push(ClassItem::Range { lo, hi: lo, span });
                self.charge_class_item(item_start)?;
                index = after_lo;
            }
        }
        let span = PatternSpan::new(start, index);
        let node = self.add_node(
            NodeKind::Class {
                kind: ClassKind::Bracket { negated },
                items,
                fold_case: self.flags.fold_case,
                class_newline: true,
                never_newline: self.flags.never_nl,
            },
            span,
        )?;
        self.add_token(TokenKind::CharacterClass, span)?;
        Ok((node, index))
    }

    fn parse_class_character(&mut self, start: usize, class_start: usize) -> PResult<(u32, usize)> {
        if start >= self.source.len() {
            return Err(self.error(
                ParseErrorCode::MissingBracket,
                PatternSpan::new(class_start, self.source.len()),
                "missing closing character-class bracket",
            ));
        }
        if self.source[start] == b'\\' {
            self.parse_core_escape(start)
        } else {
            self.decode_at(start)
        }
    }

    fn parse_core_escape(&mut self, start: usize) -> PResult<(u32, usize)> {
        let mut index = self.checked_advance(start, 1)?;
        if index >= self.source.len() {
            return Err(self.error(
                ParseErrorCode::TrailingBackslash,
                PatternSpan::new(0, 0),
                "trailing backslash",
            ));
        }
        let (escaped, after_escaped) = self.decode_at(index)?;
        index = after_escaped;
        if escaped < 0x80 {
            let byte = u8::try_from(escaped).unwrap_or_default();
            if !byte.is_ascii_alphanumeric() {
                return Ok((escaped, index));
            }
            match byte {
                b'0'..=b'7' => {
                    if byte != b'0'
                        && !self
                            .source
                            .get(index)
                            .is_some_and(|next| matches!(next, b'0'..=b'7'))
                    {
                        return Err(self.bad_escape(start, index));
                    }
                    let mut value = u32::from(byte.wrapping_sub(b'0'));
                    for _ in 0..2 {
                        let Some(&digit @ b'0'..=b'7') = self.source.get(index) else {
                            break;
                        };
                        value = value
                            .checked_mul(8)
                            .and_then(|n| n.checked_add(u32::from(digit.wrapping_sub(b'0'))))
                            .ok_or_else(|| self.limit(LimitKind::IntegerArithmetic, start))?;
                        index = self.checked_advance(index, 1)?;
                    }
                    if value > self.rune_max() {
                        return Err(self.bad_escape(start, index));
                    }
                    return Ok((value, index));
                }
                b'x' => return self.parse_hex_escape(start, index),
                b'n' => return Ok((u32::from(b'\n'), index)),
                b'r' => return Ok((u32::from(b'\r'), index)),
                b't' => return Ok((u32::from(b'\t'), index)),
                b'a' => return Ok((7, index)),
                b'f' => return Ok((12, index)),
                b'v' => return Ok((11, index)),
                _ => {}
            }
        }
        Err(self.bad_escape(start, index))
    }

    fn parse_hex_escape(&mut self, start: usize, mut index: usize) -> PResult<(u32, usize)> {
        if self.source.get(index).is_none() {
            return Err(self.bad_escape(start, index));
        }
        let (first, after_first) = self.decode_at(index)?;
        if first == u32::from(b'{') {
            index = after_first;
            let mut digits = 0usize;
            let mut value = 0u32;
            loop {
                if self.source.get(index).is_none() {
                    return Err(self.bad_escape(start, index));
                }
                let (scalar, next) = self.decode_at(index)?;
                let digit = u8::try_from(scalar).ok().and_then(hex_value);
                let Some(digit) = digit else {
                    if scalar == u32::from(b'}') && digits > 0 {
                        return Ok((value, next));
                    }
                    return Err(self.bad_escape(start, next));
                };
                digits = digits
                    .checked_add(1)
                    .ok_or_else(|| self.limit(LimitKind::IntegerArithmetic, start))?;
                value = value
                    .checked_mul(16)
                    .and_then(|n| n.checked_add(digit))
                    .ok_or_else(|| self.bad_escape(start, index))?;
                index = next;
                if value > self.rune_max() {
                    return Err(self.bad_escape(start, index));
                }
            }
        }
        if self.source.get(after_first).is_none() {
            return Err(self.bad_escape(start, after_first));
        }
        let (second, after_second) = self.decode_at(after_first)?;
        let high = u8::try_from(first).ok().and_then(hex_value);
        let low = u8::try_from(second).ok().and_then(hex_value);
        let (Some(high), Some(low)) = (high, low) else {
            return Err(self.bad_escape(start, after_second));
        };
        index = after_second;
        Ok((high.saturating_mul(16).saturating_add(low), index))
    }

    fn parse_unicode_item(&mut self, start: usize) -> PResult<(ClassItem, usize)> {
        let prefix_end = self.checked_advance(start, 2)?;
        let negating_escape = self.source.get(start.saturating_add(1)).copied() == Some(b'P');
        let (name_start, name_end, end) = if self.source.get(prefix_end).copied() == Some(b'{') {
            let name_start = self.checked_advance(prefix_end, 1)?;
            let Some(close) = self.find_byte(name_start, b'}')? else {
                return Err(self.error(
                    ParseErrorCode::BadCharRange,
                    PatternSpan::new(start, self.source.len()),
                    "unterminated Unicode character class",
                ));
            };
            (name_start, close, self.checked_advance(close, 1)?)
        } else {
            if prefix_end >= self.source.len() {
                return Err(self.error(
                    ParseErrorCode::BadCharRange,
                    PatternSpan::new(start, self.source.len()),
                    "missing Unicode character class name",
                ));
            }
            let (_, name_end) = self.decode_at(prefix_end)?;
            (prefix_end, name_end, name_end)
        };
        let raw_name = self.source.get(name_start..name_end).ok_or_else(|| {
            self.error(
                ParseErrorCode::Internal,
                PatternSpan::new(start, end),
                "Unicode class name span escaped source",
            )
        })?;
        let (raw_name, negated) = if raw_name.first().copied() == Some(b'^') {
            (&raw_name[1..], !negating_escape)
        } else {
            (raw_name, negating_escape)
        };
        // Every name in the pinned generated non-ICU table is ASCII. Latin-1
        // bytes above 0x7f therefore cannot match after RE2's UTF-8 conversion.
        let name = core::str::from_utf8(raw_name)
            .ok()
            .filter(|name| name.is_ascii());
        self.charge_work(8)?;
        let Some(name) = name.filter(|name| crate::unicode::is_group(name)) else {
            return Err(self.error(
                ParseErrorCode::BadCharRange,
                PatternSpan::new(start, end),
                "invalid Unicode character class name",
            ));
        };
        let span = PatternSpan::new(start, end);
        Ok((
            ClassItem::Unicode {
                name: name.to_owned(),
                negated,
                span,
            },
            end,
        ))
    }

    fn decode_at(&self, start: usize) -> PResult<(u32, usize)> {
        let Some(&byte) = self.source.get(start) else {
            return Err(self.error(
                ParseErrorCode::Internal,
                PatternSpan::new(start, start),
                "decode past end of pattern",
            ));
        };
        match self.options.encoding {
            Encoding::Latin1 => Ok((u32::from(byte), start.saturating_add(1))),
            Encoding::Utf8 => {
                let width = utf8_width(byte);
                let end = start
                    .checked_add(width)
                    .ok_or_else(|| self.limit(LimitKind::IntegerArithmetic, start))?;
                let bytes = self.source.get(start..end).ok_or_else(|| {
                    self.error(
                        ParseErrorCode::BadUtf8,
                        PatternSpan::new(0, 0),
                        "invalid UTF-8 in pattern",
                    )
                })?;
                let text = core::str::from_utf8(bytes).map_err(|_| {
                    self.error(
                        ParseErrorCode::BadUtf8,
                        PatternSpan::new(0, 0),
                        "invalid UTF-8 in pattern",
                    )
                })?;
                let character = text.chars().next().ok_or_else(|| {
                    self.error(
                        ParseErrorCode::Internal,
                        PatternSpan::new(start, start),
                        "empty UTF-8 decode suffix",
                    )
                })?;
                Ok((u32::from(character), end))
            }
        }
    }

    fn find_byte(&mut self, mut index: usize, wanted: u8) -> PResult<Option<usize>> {
        while let Some(&byte) = self.source.get(index) {
            self.charge_work(1)?;
            if byte == wanted {
                return Ok(Some(index));
            }
            index = self.checked_advance(index, 1)?;
        }
        Ok(None)
    }

    fn find_pair(&mut self, mut index: usize, wanted: [u8; 2]) -> PResult<Option<usize>> {
        while index < self.source.len() {
            self.charge_work(1)?;
            if self
                .source
                .get(index..)
                .is_some_and(|tail| tail.starts_with(&wanted))
            {
                return Ok(Some(index));
            }
            index = self.checked_advance(index, 1)?;
        }
        Ok(None)
    }

    fn push_literal(
        &mut self,
        value: u32,
        span: PatternSpan,
        token_kind: TokenKind,
    ) -> PResult<()> {
        self.push_literal_node(value, span)?;
        self.add_token(token_kind, span)
    }

    fn push_literal_node(&mut self, value: u32, span: PatternSpan) -> PResult<()> {
        let kind = if self.flags.never_nl && value == u32::from(b'\n') {
            NodeKind::NoMatch
        } else {
            NodeKind::Literal {
                value,
                fold_case: self.flags.fold_case,
            }
        };
        let node = self.add_node(kind, span)?;
        self.push_current(node)
    }

    fn push_current(&mut self, node: NodeId) -> PResult<()> {
        if self.frames.is_empty() {
            return Err(self.error(
                ParseErrorCode::Internal,
                PatternSpan::new(self.position, self.position),
                "missing parser frame",
            ));
        }
        let Some(frame) = self.frames.last_mut() else {
            unreachable!("frame emptiness checked above");
        };
        frame.concat.push(node);
        Ok(())
    }

    fn add_node(&mut self, kind: NodeKind, span: PatternSpan) -> PResult<NodeId> {
        if self.nodes.len() >= self.limits.max_nodes {
            return Err(self.limit(LimitKind::AstNodes, span.start));
        }
        let id = u32::try_from(self.nodes.len())
            .map(NodeId)
            .map_err(|_| self.limit(LimitKind::AstNodes, span.start))?;
        self.nodes.push(Node { kind, span });
        self.usage.nodes = self.nodes.len();
        Ok(id)
    }

    fn add_token(&mut self, kind: TokenKind, span: PatternSpan) -> PResult<()> {
        if self.tokens.len() >= self.limits.max_tokens {
            return Err(self.limit(LimitKind::Tokens, span.start));
        }
        self.tokens.push(Token { kind, span });
        self.usage.tokens = self.tokens.len();
        Ok(())
    }

    fn charge_class_item(&mut self, at: usize) -> PResult<()> {
        if self.usage.class_items >= self.limits.max_class_items {
            return Err(self.limit(LimitKind::ClassItems, at));
        }
        self.usage.class_items = self
            .usage
            .class_items
            .checked_add(1)
            .ok_or_else(|| self.limit(LimitKind::IntegerArithmetic, at))?;
        Ok(())
    }

    fn charge_work(&mut self, amount: usize) -> PResult<()> {
        let next = self
            .usage
            .work
            .checked_add(amount)
            .ok_or_else(|| self.limit(LimitKind::IntegerArithmetic, self.position))?;
        if next > self.limits.max_work {
            return Err(self.limit_observed(LimitKind::Work, self.position, next));
        }
        self.usage.work = next;
        Ok(())
    }

    fn checked_advance(&self, at: usize, amount: usize) -> PResult<usize> {
        at.checked_add(amount)
            .ok_or_else(|| self.limit(LimitKind::IntegerArithmetic, at))
    }

    fn rune_max(&self) -> u32 {
        match self.options.encoding {
            Encoding::Utf8 => MAX_UNICODE,
            Encoding::Latin1 => 0xFF,
        }
    }

    fn parse_flag_bits(&self, non_greedy: bool) -> u16 {
        let mut bits = 1_u16 << 2; // ClassNL: public RE2 options always set it.
        bits |= u16::from(self.flags.fold_case);
        bits |= u16::from(self.flags.dot_nl) << 3;
        bits |= u16::from(self.flags.one_line) << 4;
        bits |= u16::from(self.options.encoding == Encoding::Latin1) << 5;
        bits |= u16::from(non_greedy) << 6;
        bits |= u16::from(self.flags.perl_classes) << 7;
        bits |= u16::from(self.flags.perl_b) << 8;
        bits |= u16::from(self.flags.perl_x) << 9;
        bits |= u16::from(self.flags.unicode_groups) << 10;
        bits |= u16::from(self.flags.never_nl) << 11;
        bits |= u16::from(self.options.never_capture) << 12;
        bits
    }

    fn node(&self, id: NodeId) -> Option<&Node> {
        usize::try_from(id.0)
            .ok()
            .and_then(|index| self.nodes.get(index))
    }

    fn bad_escape(&self, start: usize, end: usize) -> Stop {
        self.error(
            ParseErrorCode::BadEscape,
            PatternSpan::new(start, end.min(self.source.len())),
            "invalid escape sequence",
        )
    }

    fn error(&self, code: ParseErrorCode, argument: PatternSpan, message: &str) -> Stop {
        Stop::Error(Box::new(ParseError {
            code,
            argument,
            argument_bytes: self.error_argument_bytes(argument),
            message: message.to_owned(),
            limit: None,
            observed: None,
            usage: self.usage,
        }))
    }

    fn limit(&self, kind: LimitKind, at: usize) -> Stop {
        let observed = match kind {
            LimitKind::PatternBytes => self.source.len(),
            LimitKind::AstNodes => self.nodes.len().saturating_add(1),
            LimitKind::Tokens => self.tokens.len().saturating_add(1),
            // `frames` includes the root frame, so its current length is the
            // parenthesis depth an attempted push would create.
            LimitKind::Nesting => self.frames.len(),
            LimitKind::Captures => self.capture_count.saturating_add(1),
            LimitKind::ClassItems => self.usage.class_items.saturating_add(1),
            LimitKind::Work => self.usage.work.saturating_add(1),
            LimitKind::IntegerArithmetic => usize::MAX,
        };
        self.limit_observed(kind, at, observed)
    }

    fn limit_observed(&self, kind: LimitKind, at: usize, observed: usize) -> Stop {
        Stop::Error(Box::new(ParseError {
            code: ParseErrorCode::PatternTooLarge,
            argument: PatternSpan::new(at, at),
            argument_bytes: Box::default(),
            message: format!("parser resource limit exceeded: {kind:?}"),
            limit: Some(kind),
            observed: Some(observed),
            usage: self.usage,
        }))
    }

    fn nyi(&self, feature: UnsupportedFeature, span: PatternSpan, evidence: &'static str) -> Stop {
        Stop::NotYetImplemented(NotYetImplemented {
            feature,
            span,
            usage: self.usage,
            evidence,
        })
    }

    fn error_argument_bytes(&self, span: PatternSpan) -> Box<[u8]> {
        let source = self.source.get(span.start..span.end).unwrap_or_default();
        if self.options.encoding == Encoding::Utf8 {
            return source.into();
        }
        let mut utf8 = Vec::with_capacity(source.len().saturating_mul(2));
        for &byte in source {
            if byte < 0x80 {
                utf8.push(byte);
            } else {
                utf8.push(0xC0 | (byte >> 6));
                utf8.push(0x80 | (byte & 0x3F));
            }
        }
        utf8.into_boxed_slice()
    }
}

fn perl_class_atom(byte: u8) -> Option<ClassAtom> {
    match byte {
        b'd' => Some(ClassAtom::Digit),
        b'D' => Some(ClassAtom::NotDigit),
        b's' => Some(ClassAtom::Space),
        b'S' => Some(ClassAtom::NotSpace),
        b'w' => Some(ClassAtom::Word),
        b'W' => Some(ClassAtom::NotWord),
        _ => None,
    }
}

fn posix_class(name: &[u8]) -> Option<(PosixClass, bool)> {
    let (name, negated) = name
        .strip_prefix(b"^")
        .map_or((name, false), |name| (name, true));
    let class = match name {
        b"alnum" => PosixClass::Alnum,
        b"alpha" => PosixClass::Alpha,
        b"ascii" => PosixClass::Ascii,
        b"blank" => PosixClass::Blank,
        b"cntrl" => PosixClass::Cntrl,
        b"digit" => PosixClass::Digit,
        b"graph" => PosixClass::Graph,
        b"lower" => PosixClass::Lower,
        b"print" => PosixClass::Print,
        b"punct" => PosixClass::Punct,
        b"space" => PosixClass::Space,
        b"upper" => PosixClass::Upper,
        b"word" => PosixClass::Word,
        b"xdigit" => PosixClass::Xdigit,
        _ => return None,
    };
    Some((class, negated))
}

fn hex_value(byte: u8) -> Option<u32> {
    match byte {
        b'0'..=b'9' => Some(u32::from(byte.wrapping_sub(b'0'))),
        b'a'..=b'f' => Some(u32::from(byte.wrapping_sub(b'a')).saturating_add(10)),
        b'A'..=b'F' => Some(u32::from(byte.wrapping_sub(b'A')).saturating_add(10)),
        _ => None,
    }
}

fn utf8_width(first: u8) -> usize {
    match first {
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        // The entire source is validated once before parser construction, so
        // this branch is unreachable for UTF-8 mode. One keeps all indexing
        // bounded even if that invariant changes.
        _ => 1,
    }
}
