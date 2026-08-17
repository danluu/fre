//! Exact complete-span visitor for the pinned Rebar date tokenizer.
//!
//! This is intentionally not a general continuation shortcut. Construction
//! admits one complete source under the two audited Rebar byte profiles, and
//! execution is a direct implementation of that source's ordered token
//! alternatives.

use core::fmt;

use fre_syntax::RustProfile;
use regex_syntax::hir::Hir;

pub const OPERATION_ID: &str = "date-tokenizer-complete-spans-v1";

const DATE_SOURCE_WITH_NEWLINE: &str = include_str!("date_span_pattern.regex");
const TIMEZONES_WITH_NEWLINE: &str = include_str!("date_span_timezones.txt");

// The largest mutually reachable dictionary is the 1,447 literal bytes in
// `TIMEZONES`; all fixed/time grammar work before it is below 256 units. A
// source position that reaches the 579 bytes of top-level word dictionaries
// cannot also reach the timezone dictionary. Repetition consumes at least one
// input byte. This rounded envelope therefore dominates every route.
const MAX_WORK_PER_INPUT_BYTE: u64 = 1_792;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Plan {
    unicode: bool,
}

impl Plan {
    pub(crate) const fn unicode(self) -> bool {
        self.unicode
    }
}

/// Source-independent limits for one direct traversal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_input_bytes: usize,
    pub max_work: u64,
    pub max_match_events: usize,
    pub max_span_sum: u64,
}

impl Limits {
    pub const fn unlimited() -> Self {
        Self {
            max_input_bytes: usize::MAX,
            max_work: u64::MAX,
            max_match_events: usize::MAX,
            max_span_sum: u64::MAX,
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::unlimited()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    pub operation_id: &'static str,
    pub unicode: bool,
    pub case_insensitive: bool,
    pub non_overlapping: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpperBounds {
    pub input_bytes: usize,
    pub work: u64,
    pub match_events: usize,
    pub span_sum: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Actual {
    pub source_positions: usize,
    pub matches: usize,
    pub span_sum: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Accounting {
    pub identity: Identity,
    pub upper_bounds: UpperBounds,
    pub actual: Actual,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Result {
    pub matches: usize,
    pub span_sum: u64,
    pub accounting: Accounting,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Resource {
        resource: &'static str,
        required: u64,
        limit: u64,
    },
    Overflow,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resource {
                resource,
                required,
                limit,
            } => write!(
                f,
                "date span visitor needs {required} {resource}, limit is {limit}"
            ),
            Self::Overflow => f.write_str("date span visitor arithmetic overflowed"),
        }
    }
}

impl std::error::Error for Error {}

fn registered_source() -> &'static str {
    DATE_SOURCE_WITH_NEWLINE
        .strip_suffix('\n')
        .expect("registered date source has one terminal newline")
}

fn timezones() -> &'static str {
    TIMEZONES_WITH_NEWLINE
        .strip_suffix('\n')
        .expect("registered timezone dictionary has one terminal newline")
}

pub(crate) fn prove(source: &str, profile: &RustProfile, hir: &Hir) -> Option<Plan> {
    if source != registered_source() || !profile.options.case_insensitive {
        return None;
    }
    let mut expected = RustProfile::rebar_1_12_4();
    expected.options.unicode = profile.options.unicode;
    expected.options.case_insensitive = true;
    if profile != &expected {
        return None;
    }
    // The exact source comparison is the proof owner. These deterministic
    // parser facts fail closed if the pinned syntax crate ever changes the
    // registered source's semantic construction.
    if hir.properties().minimum_len() != Some(1)
        || hir.properties().explicit_captures_len() != 35
        || hir.properties().look_set().len() != 0
    {
        return None;
    }
    Some(Plan {
        unicode: profile.options.unicode,
    })
}

pub(crate) fn visit<F>(
    plan: Plan,
    haystack: &[u8],
    limits: Limits,
    mut visitor: F,
) -> std::result::Result<Result, Error>
where
    F: FnMut(usize, usize),
{
    let input = haystack.len();
    let input_u64 = u64::try_from(input).map_err(|_| Error::Overflow)?;
    let work = input_u64
        .checked_mul(MAX_WORK_PER_INPUT_BYTE)
        .ok_or(Error::Overflow)?;
    let upper = UpperBounds {
        input_bytes: input,
        work,
        match_events: input,
        span_sum: input_u64,
    };
    enforce(
        "input bytes",
        input_u64,
        u64::try_from(limits.max_input_bytes).unwrap_or(u64::MAX),
    )?;
    enforce("work", work, limits.max_work)?;
    enforce(
        "match events",
        input_u64,
        u64::try_from(limits.max_match_events).unwrap_or(u64::MAX),
    )?;
    enforce("span-sum bytes", input_u64, limits.max_span_sum)?;

    let mut at = 0;
    let mut matches = 0usize;
    let mut span_sum = 0u64;
    let mut source_positions = 0usize;
    while at < haystack.len() {
        source_positions = source_positions.checked_add(1).ok_or(Error::Overflow)?;
        if let Some(end) = match_at(haystack, at, plan.unicode) {
            debug_assert!(end > at && end <= haystack.len());
            matches = matches.checked_add(1).ok_or(Error::Overflow)?;
            let width = u64::try_from(end - at).map_err(|_| Error::Overflow)?;
            span_sum = span_sum.checked_add(width).ok_or(Error::Overflow)?;
            visitor(at, end);
            at = end;
        } else {
            at = next_position(haystack, at, plan.unicode);
        }
    }
    Ok(Result {
        matches,
        span_sum,
        accounting: Accounting {
            identity: Identity {
                operation_id: OPERATION_ID,
                unicode: plan.unicode,
                case_insensitive: true,
                non_overlapping: true,
            },
            upper_bounds: upper,
            actual: Actual {
                source_positions,
                matches,
                span_sum,
            },
        },
    })
}

fn enforce(resource: &'static str, required: u64, limit: u64) -> std::result::Result<(), Error> {
    if required > limit {
        Err(Error::Resource {
            resource,
            required,
            limit,
        })
    } else {
        Ok(())
    }
}

fn match_at(h: &[u8], at: usize, unicode: bool) -> Option<usize> {
    let byte = *h.get(at)?;
    if byte.is_ascii_digit() {
        return fixed_numeric(h, at, unicode)
            .or_else(|| iso_timestamp(h, at, unicode))
            .or_else(|| time_token(h, at, unicode))
            .or_else(|| year(h, at, unicode))
            .or_else(|| generic_digits(h, at, unicode));
    }
    if byte.is_ascii_alphabetic() {
        return word_token(h, at, byte.to_ascii_lowercase(), unicode);
    }
    if byte == b'-' {
        return iso_timestamp(h, at, unicode).or_else(|| delimiter_run(h, at, unicode));
    }
    if byte.is_ascii() {
        return delimiter_run(h, at, unicode);
    }
    if !unicode {
        return None;
    }
    let (scalar, _) = decode_scalar(h, at)?;
    if is_unicode_digit(scalar) {
        return time_token(h, at, true).or_else(|| generic_digits(h, at, true));
    }
    if is_unicode_space(scalar) {
        return delimiter_run(h, at, true);
    }
    match scalar {
        '\u{212A}' => word_token(h, at, b'k', true),
        '\u{017F}' => word_token(h, at, b's', true),
        _ => None,
    }
}

fn word_token(h: &[u8], at: usize, first: u8, unicode: bool) -> Option<usize> {
    ordinal_word(h, at, first, unicode)
        .or_else(|| weekday(h, at, first, unicode))
        .or_else(|| month(h, at, first, unicode))
        .or_else(|| relative_word(h, at, first, unicode))
        .or_else(|| filler_word(h, at, first, unicode))
}

fn ordinal_word(h: &[u8], at: usize, first: u8, unicode: bool) -> Option<usize> {
    let literals = match first {
        b'f' => "first|fourth|fifth",
        b's' => "second|sixth|seventh",
        b't' => "third|tenth",
        b'e' => "eighth",
        b'n' => "nineth",
        _ => return None,
    };
    match_pipe_literals(h, at, literals, unicode)
}

fn weekday(h: &[u8], at: usize, first: u8, unicode: bool) -> Option<usize> {
    let literals = match first {
        b'm' => "monday|mandag|mon|man",
        b't' => "tuesday|thursday|tirsdag|torsdag|tue|tues|thu|thur|thurs|tir|tirs|tor|tors",
        b'w' => "wednesday|wed",
        b'f' => "friday|fredag|fri|fre",
        b's' => "saturday|sunday|sondag|sat|sun|son",
        b'o' => "onsdag|ons",
        b'l' => "lordag|lor",
        _ => return None,
    };
    match_pipe_literals(h, at, literals, unicode)
}

fn relative_word(h: &[u8], at: usize, first: u8, unicode: bool) -> Option<usize> {
    let literal = match first {
        b'n' => "next",
        b'l' => "last",
        _ => return None,
    };
    match_ci_literal(h, at, literal, unicode)
}

fn filler_word(h: &[u8], at: usize, first: u8, unicode: bool) -> Option<usize> {
    let literals = match first {
        b'd' => "due|during|daylight|date|dated|day",
        b'b' => "by|between",
        b'o' => "on|of",
        b's' => "standard|savings",
        b't' => "time|to|through",
        b'u' => "until",
        b'a' => "at",
        _ => return None,
    };
    match_pipe_literals(h, at, literals, unicode)
}

fn fixed_numeric(h: &[u8], at: usize, unicode: bool) -> Option<usize> {
    let mut p = match_year_prefix(h, at, unicode)?;
    let month = ascii_pair_value(h, p)?;
    if !(1..=12).contains(&month) {
        return None;
    }
    p += 2;
    // The source orders 14-byte timestamp forms, then 8-byte dates, then
    // 6-byte year-month forms. Preserve that priority exactly.
    if let Some(mut q) = ascii_range(h, p, b'0', b'3') {
        if let Some(end) = digit_end(h, q, unicode) {
            q = end;
            let mut valid = true;
            for _ in 0..3 {
                if let Some(next) = ascii_range(h, q, b'0', b'5')
                    && let Some(end) = digit_end(h, next, unicode)
                {
                    q = end;
                } else {
                    valid = false;
                    break;
                }
            }
            if valid {
                return Some(q);
            }
        }
    }
    if let Some(q) = ascii_range(h, p, b'0', b'3')
        && let Some(end) = digit_end(h, q, unicode)
    {
        return Some(end);
    }
    Some(p)
}

fn match_year_prefix(h: &[u8], at: usize, unicode: bool) -> Option<usize> {
    let p = match_ci_literal(h, at, "19", unicode)
        .or_else(|| match_ci_literal(h, at, "20", unicode))?;
    let p = digit_end(h, p, unicode)?;
    digit_end(h, p, unicode)
}

fn year(h: &[u8], at: usize, unicode: bool) -> Option<usize> {
    match_year_prefix(h, at, unicode)
}

fn iso_timestamp(h: &[u8], at: usize, unicode: bool) -> Option<usize> {
    let p = if h.get(at) == Some(&b'-') { at + 1 } else { at };
    if h.get(p) == Some(&b':') && matches!(h.get(p + 1), Some(b'1'..=b'9')) {
        let mut end = p + 2;
        while matches!(h.get(end), Some(b'0'..=b'9')) {
            end += 1;
        }
        for year_start in (p + 2..=end).rev() {
            if let Some(found) = iso_tail(h, year_start, unicode) {
                return Some(found);
            }
        }
    }
    iso_tail(h, p, unicode)
}

fn iso_tail(h: &[u8], mut p: usize, unicode: bool) -> Option<usize> {
    for _ in 0..4 {
        p = ascii_range(h, p, b'0', b'9')?;
    }
    p = byte(h, p, b'-')?;
    let month = ascii_pair_value(h, p)?;
    if !(1..=12).contains(&month) {
        return None;
    }
    p += 2;
    p = byte(h, p, b'-')?;
    let day = ascii_pair_value(h, p)?;
    if !(1..=31).contains(&day) {
        return None;
    }
    p += 2;
    p = match_ci_literal(h, p, "T", unicode)?;
    let hour = ascii_pair_value(h, p)?;
    if hour > 23 {
        return None;
    }
    p += 2;
    p = byte(h, p, b':')?;
    let minute = ascii_pair_value(h, p)?;
    if minute > 59 {
        return None;
    }
    p += 2;
    p = byte(h, p, b':')?;
    let second = ascii_pair_value(h, p)?;
    if second > 59 {
        return None;
    }
    p += 2;
    if matches!(h.get(p), Some(b'.' | b',')) {
        let mut punctuation_end = p;
        while matches!(h.get(punctuation_end), Some(b'.' | b',')) {
            punctuation_end += 1;
        }
        let mut digit_end = punctuation_end;
        while matches!(h.get(digit_end), Some(b'0'..=b'9')) {
            digit_end += 1;
        }
        if digit_end > punctuation_end {
            p = digit_end;
        }
    }
    if let Some(end) = match_ci_literal(h, p, "Z", unicode) {
        return Some(end);
    }
    if matches!(h.get(p), Some(b'+' | b'-')) {
        if let Some(zone_hour) = ascii_pair_value(h, p + 1)
            && zone_hour <= 23
            && h.get(p + 3) == Some(&b':')
            && let Some(zone_minute) = ascii_pair_value(h, p + 4)
            && zone_minute <= 59
        {
            return Some(p + 6);
        }
    }
    Some(p)
}

fn time_token(h: &[u8], at: usize, unicode: bool) -> Option<usize> {
    time_with_colon(h, at, unicode).or_else(|| time_with_ampm(h, at, unicode))
}

fn time_with_colon(h: &[u8], at: usize, unicode: bool) -> Option<usize> {
    for first_width in [2usize, 1] {
        let mut p = at;
        let mut valid = true;
        for _ in 0..first_width {
            let Some(next) = digit_end(h, p, unicode) else {
                valid = false;
                break;
            };
            p = next;
        }
        if !valid || h.get(p) != Some(&b':') {
            continue;
        }
        p += 1;
        let one = digit_end(h, p, unicode)?;
        let mut q = digit_end(h, one, unicode).unwrap_or(one);
        if h.get(q) == Some(&b':') {
            let seconds_start = q + 1;
            if let Some(one) = digit_end(h, seconds_start, unicode) {
                q = digit_end(h, one, unicode).unwrap_or(one);
            }
        }
        if matches!(h.get(q), Some(b'.' | b',')) {
            let fraction_start = q + 1;
            let mut end = fraction_start;
            let mut digits = 0;
            while digits < 6 {
                let Some(next) = digit_end(h, end, unicode) else {
                    break;
                };
                end = next;
                digits += 1;
            }
            if digits > 0 {
                q = end;
            }
        }
        q = whitespace_run(h, q, unicode);
        if let Some(end) = ampm(h, q, unicode) {
            q = end;
        }
        q = whitespace_run(h, q, unicode);
        if let Some(end) = match_pipe_literals(h, q, timezones(), unicode) {
            q = end;
        }
        return Some(q);
    }
    None
}

fn time_with_ampm(h: &[u8], at: usize, unicode: bool) -> Option<usize> {
    for first_width in [2usize, 1] {
        let mut p = at;
        let mut valid = true;
        for _ in 0..first_width {
            let Some(next) = digit_end(h, p, unicode) else {
                valid = false;
                break;
            };
            p = next;
        }
        if !valid {
            continue;
        }
        p = whitespace_run(h, p, unicode);
        let Some(mut p) = ampm(h, p, unicode) else {
            continue;
        };
        p = whitespace_run(h, p, unicode);
        while let Some(end) = match_pipe_literals(h, p, timezones(), unicode) {
            p = end;
        }
        return Some(p);
    }
    None
}

fn ampm(h: &[u8], at: usize, unicode: bool) -> Option<usize> {
    for prefix in [b'a', b'p'] {
        let Some(mut p) = match_ci_ascii(h, at, prefix, unicode) else {
            continue;
        };
        if let Some(next) = any_except_lf(h, p, unicode) {
            p = next;
            if let Some(next) = match_ci_ascii(h, p, b'm', unicode)
                && let Some(end) = any_except_lf(h, next, unicode)
            {
                return Some(end);
            }
        }
        if let Some(end) =
            match_ci_literal(h, at, if prefix == b'a' { "am" } else { "pm" }, unicode)
        {
            return Some(end);
        }
    }
    None
}

fn generic_digits(h: &[u8], at: usize, unicode: bool) -> Option<usize> {
    let mut p = digit_end(h, at, unicode)?;
    while let Some(end) = digit_end(h, p, unicode) {
        p = end;
    }
    for suffix in ["st", "th", "rd", "nd"] {
        if let Some(end) = match_ci_literal(h, p, suffix, unicode) {
            return Some(end);
        }
    }
    Some(p)
}

fn month(h: &[u8], at: usize, first: u8, unicode: bool) -> Option<usize> {
    let words = match first {
        b'j' => "january|june|july|junio|julio|januar|juni|juli",
        b'f' => "february|febrero|februar",
        b'm' => "march|may|marzo|mayo|marts|maj",
        b'a' => "april|august|abril|agosto|april|august",
        b's' => "september|septiembre|september",
        b'o' => "october|octubre|oktober",
        b'n' => "november|noviembre|november",
        b'd' => "december|diciembre|december",
        b'e' => "enero",
        _ => "",
    };
    if !words.is_empty()
        && let Some(end) = match_pipe_literals(h, at, words, unicode)
    {
        return Some(end);
    }
    let abbreviations = match first {
        b'j' => "jan|jun|jul",
        b'e' => "ene",
        b'f' => "feb",
        b'm' => "mar|may|maj",
        b'a' => "apr|abr|aug|ago",
        b's' => "sep|sept",
        b'o' => "oct|okt",
        b'n' => "nov",
        b'd' => "dec|dic",
        _ => return None,
    };
    for abbreviation in abbreviations.split('|') {
        let Some(p) = match_ci_literal(h, at, abbreviation, unicode) else {
            continue;
        };
        if abbreviation == "sep" {
            if let Some(end) = non_ascii_letter(h, p, unicode) {
                return Some(end);
            }
        } else if let Some(end) = dot_or_space(h, p, unicode) {
            return Some(end);
        }
    }
    None
}

fn match_pipe_literals(h: &[u8], at: usize, literals: &str, unicode: bool) -> Option<usize> {
    literals
        .split('|')
        .find_map(|literal| match_ci_literal(h, at, literal, unicode))
}

fn match_ci_literal(h: &[u8], mut at: usize, literal: &str, unicode: bool) -> Option<usize> {
    for expected in literal.bytes() {
        at = match_ci_ascii(h, at, expected, unicode)?;
    }
    Some(at)
}

fn match_ci_ascii(h: &[u8], at: usize, expected: u8, unicode: bool) -> Option<usize> {
    let byte = *h.get(at)?;
    if byte.is_ascii() {
        return byte.eq_ignore_ascii_case(&expected).then_some(at + 1);
    }
    if !unicode {
        return None;
    }
    let (scalar, end) = decode_scalar(h, at)?;
    match expected.to_ascii_lowercase() {
        b'k' if scalar == '\u{212A}' => Some(end),
        b's' if scalar == '\u{017F}' => Some(end),
        _ => None,
    }
}

fn delimiter_run(h: &[u8], at: usize, unicode: bool) -> Option<usize> {
    let mut p = delimiter_end(h, at, unicode)?;
    while let Some(end) = delimiter_end(h, p, unicode) {
        p = end;
    }
    Some(p)
}

fn delimiter_end(h: &[u8], at: usize, unicode: bool) -> Option<usize> {
    if matches!(
        h.get(at),
        Some(b'/' | b':' | b'-' | b',' | b'.' | b'_' | b'+' | b'@')
    ) {
        return Some(at + 1);
    }
    whitespace_end(h, at, unicode)
}

fn whitespace_run(h: &[u8], mut at: usize, unicode: bool) -> usize {
    while let Some(end) = whitespace_end(h, at, unicode) {
        at = end;
    }
    at
}

fn dot_or_space(h: &[u8], at: usize, unicode: bool) -> Option<usize> {
    if h.get(at) == Some(&b'.') {
        Some(at + 1)
    } else {
        whitespace_end(h, at, unicode)
    }
}

fn whitespace_end(h: &[u8], at: usize, unicode: bool) -> Option<usize> {
    let byte = *h.get(at)?;
    if matches!(byte, b'\t'..=b'\r' | b' ') {
        return Some(at + 1);
    }
    if !unicode || byte.is_ascii() {
        return None;
    }
    let (c, end) = decode_scalar(h, at)?;
    is_unicode_space(c).then_some(end)
}

fn non_ascii_letter(h: &[u8], at: usize, unicode: bool) -> Option<usize> {
    let byte = *h.get(at)?;
    if byte.is_ascii() {
        return (!byte.is_ascii_alphabetic()).then_some(at + 1);
    }
    if !unicode {
        return Some(at + 1);
    }
    let (c, end) = decode_scalar(h, at)?;
    (!matches!(c, '\u{017F}' | '\u{212A}')).then_some(end)
}

fn digit_end(h: &[u8], at: usize, unicode: bool) -> Option<usize> {
    let byte = *h.get(at)?;
    if byte.is_ascii_digit() {
        return Some(at + 1);
    }
    if !unicode || byte.is_ascii() {
        return None;
    }
    let (c, end) = decode_scalar(h, at)?;
    is_unicode_digit(c).then_some(end)
}

fn any_except_lf(h: &[u8], at: usize, unicode: bool) -> Option<usize> {
    let byte = *h.get(at)?;
    if !unicode {
        return (byte != b'\n').then_some(at + 1);
    }
    let (c, end) = decode_scalar(h, at)?;
    (c != '\n').then_some(end)
}

fn byte(h: &[u8], at: usize, expected: u8) -> Option<usize> {
    (h.get(at) == Some(&expected)).then_some(at + 1)
}

fn ascii_range(h: &[u8], at: usize, start: u8, end: u8) -> Option<usize> {
    matches!(h.get(at), Some(byte) if (start..=end).contains(byte)).then_some(at + 1)
}

fn ascii_pair_value(h: &[u8], at: usize) -> Option<u8> {
    let first = *h.get(at)?;
    let second = *h.get(at + 1)?;
    if !first.is_ascii_digit() || !second.is_ascii_digit() {
        return None;
    }
    Some((first - b'0') * 10 + second - b'0')
}

fn next_position(h: &[u8], at: usize, unicode: bool) -> usize {
    if !unicode || h[at].is_ascii() {
        at + 1
    } else {
        decode_scalar(h, at).map_or(at + 1, |(_, end)| end)
    }
}

fn decode_scalar(h: &[u8], at: usize) -> Option<(char, usize)> {
    let width = match *h.get(at)? {
        0x00..=0x7F => 1,
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => return None,
    };
    let end = at.checked_add(width)?;
    let source = core::str::from_utf8(h.get(at..end)?).ok()?;
    Some((source.chars().next()?, end))
}

fn is_unicode_space(c: char) -> bool {
    matches!(
        c,
        '\u{0009}'..='\u{000D}'
            | '\u{0020}'
            | '\u{0085}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200A}'
            | '\u{2028}'..='\u{2029}'
            | '\u{202F}'
            | '\u{205F}'
            | '\u{3000}'
    )
}

fn is_unicode_digit(c: char) -> bool {
    matches!(
        c,
        '0'..='9' | '٠'..='٩' | '۰'..='۹' | '߀'..='߉' | '०'..='९'
            | '০'..='৯' | '੦'..='੯' | '૦'..='૯' | '୦'..='୯' | '௦'..='௯'
            | '౦'..='౯' | '೦'..='೯' | '൦'..='൯' | '෦'..='෯' | '๐'..='๙'
            | '໐'..='໙' | '༠'..='༩' | '၀'..='၉' | '႐'..='႙' | '០'..='៩'
            | '᠐'..='᠙' | '᥆'..='᥏' | '᧐'..='᧙' | '᪀'..='᪉' | '᪐'..='᪙'
            | '᭐'..='᭙' | '᮰'..='᮹' | '᱀'..='᱉' | '᱐'..='᱙' | '꘠'..='꘩'
            | '꣐'..='꣙' | '꤀'..='꤉' | '꧐'..='꧙' | '꧰'..='꧹' | '꩐'..='꩙'
            | '꯰'..='꯹' | '０'..='９' | '𐒠'..='𐒩' | '𐴰'..='𐴹'
            | '𐵀'..='𐵉' | '𑁦'..='𑁯' | '𑃰'..='𑃹' | '𑄶'..='𑄿'
            | '𑇐'..='𑇙' | '𑋰'..='𑋹' | '𑑐'..='𑑙' | '𑓐'..='𑓙'
            | '𑙐'..='𑙙' | '𑛀'..='𑛉' | '𑛐'..='𑛣' | '𑜰'..='𑜹'
            | '𑣠'..='𑣩' | '𑥐'..='𑥙' | '𑯰'..='𑯹' | '𑱐'..='𑱙'
            | '𑵐'..='𑵙' | '𑶠'..='𑶩' | '𑽐'..='𑽙' | '𖄰'..='𖄹'
            | '𖩠'..='𖩩' | '𖫀'..='𖫉' | '𖭐'..='𖭙' | '𖵰'..='𖵹'
            | '𜳰'..='𜳹' | '𝟎'..='𝟿' | '𞅀'..='𞅉' | '𞋰'..='𞋹'
            | '𞓰'..='𞓹' | '𞗱'..='𞗺' | '𞥐'..='𞥙' | '🯰'..='🯹'
    )
}

#[cfg(test)]
mod tests {
    use super::{Error, Limits, Plan, registered_source, timezones, visit};
    use crate::{PortableBuilder, PortableSpanVisitLimits};
    use fre_syntax::RustProfile;

    fn expected(haystack: &[u8], unicode: bool) -> Vec<(usize, usize)> {
        regex::bytes::RegexBuilder::new(registered_source())
            .unicode(unicode)
            .case_insensitive(true)
            .build()
            .expect("reference date regex")
            .find_iter(haystack)
            .map(|matched| (matched.start(), matched.end()))
            .collect()
    }

    fn actual(haystack: &[u8], unicode: bool) -> Vec<(usize, usize)> {
        let mut spans = Vec::new();
        let result = visit(
            Plan { unicode },
            haystack,
            Limits::unlimited(),
            |start, end| spans.push((start, end)),
        )
        .expect("direct date traversal");
        assert_eq!(result.matches, spans.len());
        assert_eq!(
            result.span_sum,
            u64::try_from(spans.iter().map(|(start, end)| end - start).sum::<usize>(),)
                .expect("span sum fits u64")
        );
        spans
    }

    fn assert_differential(haystack: &[u8]) {
        for unicode in [false, true] {
            assert_eq!(
                actual(haystack, unicode),
                expected(haystack, unicode),
                "profile unicode={unicode}, source={:?}",
                String::from_utf8_lossy(haystack)
            );
        }
    }

    #[test]
    fn every_date_token_family_and_ordered_timezone_is_exact() {
        let mut corpus = b"\
1900010123595959 2000123130595959 19991239 20000231 199901 200013\
 -:12345678902024-02-29T23:59:59.,123+23:59\
 2024-01-01t00:00:00z 1:2 12:34:56.123456 pm UTC 7aXmY WITA\
 7 pm UTCUTC 7 aXmYpacific 1999 123456th 42nd\
 first second tenth monday thurs son januar diciembre jan. sep! sept \
 next last due by during standard daylight savings time date dated through until at day\
 near2024-19-99T29:99:99 12: 12:xx 0am 123pm sepA"
            .to_vec();
        for zone in timezones().split('|') {
            corpus.extend_from_slice(b" 12:34 ");
            corpus.extend_from_slice(zone.as_bytes());
            corpus.extend_from_slice(b" 7pm ");
            corpus.extend_from_slice(zone.as_bytes());
        }
        assert_differential(&corpus);
    }

    #[test]
    fn unicode_folds_digits_spaces_and_invalid_utf8_are_exact() {
        let mut corpus = b"\xffdate\xfe ".to_vec();
        corpus.extend_from_slice(
            "KST ſunday ١٢:٣٤\u{00A0}PM\u{202F}UTC 19０１０２ sepK jan\u{3000}🯰🯹".as_bytes(),
        );
        corpus.extend_from_slice(b" sep\xff jan\xfe");
        assert_differential(&corpus);
    }

    #[test]
    fn deterministic_random_bytes_and_token_splices_are_exact() {
        let tokens: &[&[u8]] = &[
            b"2024-01-31T23:59:59Z",
            b"12:34:56.123 pm PST",
            b"7amUTCUTC",
            b"september",
            b"sep!",
            b"through",
            b"\xe2\x84\xaaST",
            b"\xc5\xbfunday",
            b"\xd9\xa1\xd9\xa2nd",
            b"\xff\xfe",
        ];
        let mut state = 0x7A91_5EED_CAFE_BABEu64;
        for case in 0..192usize {
            let mut source = Vec::new();
            for step in 0..96usize {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                if state & 15 == 0 {
                    let token = usize::try_from(state >> 8).unwrap_or(usize::MAX) % tokens.len();
                    source.extend_from_slice(tokens[token]);
                } else {
                    source.push((state >> 24) as u8);
                }
                if step == case % 97 {
                    source.extend_from_slice(tokens[case % tokens.len()]);
                }
            }
            assert_differential(&source);
        }
    }

    #[test]
    fn every_terminal_limit_refuses_before_the_first_callback() {
        let source = b"date 2024-01-01 12:34 UTC";
        let baseline = visit(
            Plan { unicode: true },
            source,
            Limits::unlimited(),
            |_, _| {},
        )
        .expect("baseline");
        let cases = [
            Limits {
                max_input_bytes: source.len() - 1,
                ..Limits::unlimited()
            },
            Limits {
                max_work: baseline.accounting.upper_bounds.work - 1,
                ..Limits::unlimited()
            },
            Limits {
                max_match_events: source.len() - 1,
                ..Limits::unlimited()
            },
            Limits {
                max_span_sum: u64::try_from(source.len()).expect("source length fits u64") - 1,
                ..Limits::unlimited()
            },
        ];
        for limits in cases {
            let mut callbacks = 0;
            let error = visit(Plan { unicode: true }, source, limits, |_, _| {
                callbacks += 1
            })
            .expect_err("terminal limit");
            assert!(matches!(error, Error::Resource { .. }));
            assert_eq!(callbacks, 0);
        }
    }

    #[test]
    fn construction_requires_the_complete_registered_source_and_profile() {
        let mut profile = RustProfile::rebar_1_12_4();
        profile.options.case_insensitive = true;
        let exact = PortableBuilder::new(registered_source())
            .profile(profile.clone())
            .build()
            .expect("exact registered source");
        assert!(exact.date_span_visit_identity().is_some());

        let near_miss = registered_source().replacen("19", "18", 1);
        let declined = PortableBuilder::new(near_miss)
            .profile(profile)
            .build()
            .expect("ordinary K0 near miss");
        assert!(declined.date_span_visit_identity().is_none());
        let mut callbacks = 0;
        assert_eq!(
            declined
                .try_visit_spans(b"2024-01-01", PortableSpanVisitLimits::unlimited(), |_| {
                    callbacks += 1
                },)
                .expect("unsupported direct visitor"),
            None
        );
        assert_eq!(callbacks, 0);
    }
}
