use regex_syntax::{
    ParserBuilder,
    hir::{Class, Hir, HirKind, Look},
};

use crate::{Match, SearchLimits, SearchWindow};

pub(crate) const UNICODE_PLAN_ID: &str = "unicode-word-run-linear-v1";
pub(crate) const ASCII_PLAN_ID: &str = "ascii-word-run-linear-v1";
pub(crate) const UNICODE_BOUNDED_PLAN_ID: &str = "unicode-word-run-bounded-linear-v1";
pub(crate) const ASCII_BOUNDED_PLAN_ID: &str = "ascii-word-run-bounded-linear-v1";
pub(crate) const UNICODE_DIRECT_PLAN_ID: &str = "unicode-word-look-direct-linear-v1";
pub(crate) const ASCII_DIRECT_PLAN_ID: &str = "ascii-word-look-direct-linear-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WordMode {
    Ascii,
    Unicode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Plan {
    minimum_scalars: usize,
    maximum_scalars: Option<usize>,
    require_start_boundary: bool,
    require_end_boundary: bool,
    mode: WordMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Accounting {
    pub(crate) work: u64,
    pub(crate) bytes_examined: usize,
    pub(crate) scalars_decoded: usize,
    pub(crate) matches: usize,
    pub(crate) matched_bytes: usize,
}

impl Accounting {
    #[must_use]
    pub const fn work(self) -> u64 {
        self.work
    }

    #[must_use]
    pub const fn bytes_examined(self) -> usize {
        self.bytes_examined
    }

    #[must_use]
    pub const fn scalars_decoded(self) -> usize {
        self.scalars_decoded
    }

    #[must_use]
    pub const fn matches(self) -> usize {
        self.matches
    }

    #[must_use]
    pub const fn matched_bytes(self) -> usize {
        self.matched_bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidWindow {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
    WorkLimitExceeded {
        needed: u64,
        limit: u64,
    },
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::InvalidWindow {
                start,
                end,
                haystack_len,
            } => write!(
                f,
                "word-run window {start}..{end} exceeds haystack length {haystack_len}"
            ),
            Self::WorkLimitExceeded { needed, limit } => write!(
                f,
                "word-run search needs {needed} work units, exceeding {limit}"
            ),
        }
    }
}

impl std::error::Error for Error {}

impl Plan {
    const fn new(
        minimum_scalars: usize,
        maximum_scalars: Option<usize>,
        require_start_boundary: bool,
        require_end_boundary: bool,
        mode: WordMode,
    ) -> Self {
        Self {
            minimum_scalars,
            maximum_scalars,
            require_start_boundary,
            require_end_boundary,
            mode,
        }
    }

    pub(crate) const fn plan_id(self) -> &'static str {
        if !self.require_start_boundary || !self.require_end_boundary {
            return match self.mode {
                WordMode::Ascii => ASCII_DIRECT_PLAN_ID,
                WordMode::Unicode => UNICODE_DIRECT_PLAN_ID,
            };
        }
        match (self.mode, self.maximum_scalars) {
            (WordMode::Ascii, None) => ASCII_PLAN_ID,
            (WordMode::Unicode, None) => UNICODE_PLAN_ID,
            (WordMode::Ascii, Some(_)) => ASCII_BOUNDED_PLAN_ID,
            (WordMode::Unicode, Some(_)) => UNICODE_BOUNDED_PLAN_ID,
        }
    }

    pub(crate) fn find_window(
        self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, Accounting), Error> {
        if window.start() > window.end() || window.end() > haystack.len() {
            return Err(Error::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len: haystack.len(),
            });
        }
        let mut accounting = Accounting::new();
        let matched = self.find_next(haystack, window, limits, &mut accounting)?;
        if let Some(matched) = matched {
            accounting.record_match(matched);
        }
        Ok((matched, accounting))
    }

    pub(crate) fn reduce(self, haystack: &[u8], limits: SearchLimits) -> Result<Accounting, Error> {
        let mut accounting = Accounting::new();
        let mut start = 0_usize;
        while start < haystack.len() {
            let Some(matched) = self.find_next(
                haystack,
                SearchWindow::new(start, haystack.len()),
                limits,
                &mut accounting,
            )?
            else {
                break;
            };
            accounting.record_match(matched);
            debug_assert!(matched.end > start, "word-run matches are nonempty");
            start = matched.end;
        }
        Ok(accounting)
    }

    fn find_next(
        self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
        accounting: &mut Accounting,
    ) -> Result<Option<Match>, Error> {
        match self.mode {
            WordMode::Ascii => self.find_ascii_window(haystack, window, limits, accounting),
            WordMode::Unicode => self.find_unicode_window(haystack, window, limits, accounting),
        }
    }

    fn find_ascii_window(
        self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
        accounting: &mut Accounting,
    ) -> Result<Option<Match>, Error> {
        let mut position = window.start();
        while position < window.end() {
            charge(accounting, limits)?;
            let byte = haystack[position];
            accounting.bytes_examined = accounting.bytes_examined.saturating_add(1);
            accounting.scalars_decoded = accounting.scalars_decoded.saturating_add(1);
            if !is_ascii_word(byte)
                || (self.require_start_boundary
                    && position
                        .checked_sub(1)
                        .is_some_and(|before| is_ascii_word(haystack[before])))
            {
                position = position.checked_add(1).ok_or(Error::WorkLimitExceeded {
                    needed: u64::MAX,
                    limit: limits.max_work,
                })?;
                continue;
            }

            let mut start = position;
            position = position.checked_add(1).ok_or(Error::WorkLimitExceeded {
                needed: u64::MAX,
                limit: limits.max_work,
            })?;
            while position < window.end()
                && is_ascii_word(haystack[position])
                && (self.require_end_boundary
                    || self
                        .maximum_scalars
                        .is_none_or(|maximum| position.saturating_sub(start) < maximum))
            {
                charge(accounting, limits)?;
                accounting.bytes_examined = accounting.bytes_examined.saturating_add(1);
                accounting.scalars_decoded = accounting.scalars_decoded.saturating_add(1);
                position = position.checked_add(1).ok_or(Error::WorkLimitExceeded {
                    needed: u64::MAX,
                    limit: limits.max_work,
                })?;
            }
            let mut count = position.saturating_sub(start);
            if self.require_end_boundary
                && !self.require_start_boundary
                && let Some(maximum) = self.maximum_scalars
                && count > maximum
            {
                start = position.saturating_sub(maximum);
                count = maximum;
            }
            if count >= self.minimum_scalars
                && self.maximum_scalars.is_none_or(|maximum| count <= maximum)
                && (!self.require_end_boundary
                    || !haystack
                        .get(position)
                        .is_some_and(|&byte| is_ascii_word(byte)))
            {
                return Ok(Some(Match {
                    start,
                    end: position,
                }));
            }
        }
        Ok(None)
    }

    fn find_unicode_window(
        self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
        accounting: &mut Accounting,
    ) -> Result<Option<Match>, Error> {
        let mut position = window.start();
        while position < window.end() {
            charge(accounting, limits)?;
            let Some((scalar, width)) = decode_first(&haystack[position..window.end()]) else {
                position = position.checked_add(1).ok_or(Error::WorkLimitExceeded {
                    needed: u64::MAX,
                    limit: limits.max_work,
                })?;
                accounting.bytes_examined = accounting.bytes_examined.saturating_add(1);
                continue;
            };
            accounting.scalars_decoded = accounting.scalars_decoded.saturating_add(1);
            accounting.bytes_examined = accounting.bytes_examined.saturating_add(width);
            if !is_unicode_word(scalar)
                || (self.require_start_boundary && unicode_word_before(haystack, position))
            {
                position = position
                    .checked_add(width)
                    .ok_or(Error::WorkLimitExceeded {
                        needed: u64::MAX,
                        limit: limits.max_work,
                    })?;
                continue;
            }

            let mut start = position;
            let mut count = 1_usize;
            position = position
                .checked_add(width)
                .ok_or(Error::WorkLimitExceeded {
                    needed: u64::MAX,
                    limit: limits.max_work,
                })?;
            while position < window.end() {
                if !self.require_end_boundary
                    && self.maximum_scalars.is_some_and(|maximum| count >= maximum)
                {
                    break;
                }
                charge(accounting, limits)?;
                let Some((next, next_width)) = decode_first(&haystack[position..window.end()])
                else {
                    break;
                };
                accounting.scalars_decoded = accounting.scalars_decoded.saturating_add(1);
                accounting.bytes_examined = accounting.bytes_examined.saturating_add(next_width);
                if !is_unicode_word(next) {
                    break;
                }
                count = count.saturating_add(1);
                position = position
                    .checked_add(next_width)
                    .ok_or(Error::WorkLimitExceeded {
                        needed: u64::MAX,
                        limit: limits.max_work,
                    })?;
            }
            if self.require_end_boundary
                && !self.require_start_boundary
                && let Some(maximum) = self.maximum_scalars
                && count > maximum
            {
                start = position;
                for _ in 0..maximum {
                    charge(accounting, limits)?;
                    let Some((_, width)) = decode_last(&haystack[..start]) else {
                        return Ok(None);
                    };
                    accounting.scalars_decoded = accounting.scalars_decoded.saturating_add(1);
                    accounting.bytes_examined = accounting.bytes_examined.saturating_add(width);
                    start = start.saturating_sub(width);
                }
                count = maximum;
            }
            if count >= self.minimum_scalars
                && self.maximum_scalars.is_none_or(|maximum| count <= maximum)
                && (!self.require_end_boundary || !unicode_word_after(haystack, position))
            {
                return Ok(Some(Match {
                    start,
                    end: position,
                }));
            }
        }
        Ok(None)
    }
}

impl Accounting {
    const fn new() -> Self {
        Self {
            work: 0,
            bytes_examined: 0,
            scalars_decoded: 0,
            matches: 0,
            matched_bytes: 0,
        }
    }

    fn record_match(&mut self, matched: Match) {
        self.matches = self.matches.saturating_add(1);
        self.matched_bytes = self
            .matched_bytes
            .saturating_add(matched.end.saturating_sub(matched.start));
    }
}

pub(crate) fn extract(hir: &Hir) -> Option<Plan> {
    extract_impl(hir, false).map(|(plan, _, _)| plan)
}

pub(crate) fn extract_accounted(hir: &Hir) -> Option<(Plan, usize, usize)> {
    extract_impl(hir, true)
}

fn extract_impl(hir: &Hir, allow_bounded: bool) -> Option<(Plan, usize, usize)> {
    let root = transparent(hir);
    let (repeated, mode, require_start_boundary, require_end_boundary) = match root.kind() {
        HirKind::Repetition(repetition) if allow_bounded => {
            (root, class_mode(&repetition.sub)?, false, false)
        }
        HirKind::Concat(parts) => match parts.as_slice() {
            [start, repeated, end] => (repeated, boundary_mode(start, end)?, true, true),
            [first, second] if allow_bounded => {
                if let Some(mode) = single_boundary_mode(first) {
                    (second, mode, true, false)
                } else if let Some(mode) = single_boundary_mode(second) {
                    (first, mode, false, true)
                } else {
                    return None;
                }
            }
            _ => return None,
        },
        _ => return None,
    };
    let HirKind::Repetition(repetition) = transparent(repeated).kind() else {
        return None;
    };
    if repetition.min == 0 || (!allow_bounded && repetition.max.is_some()) || !repetition.greedy {
        return None;
    }
    match (mode, transparent(&repetition.sub).kind()) {
        (WordMode::Ascii, HirKind::Class(Class::Bytes(class)))
            if class == &parse_ascii_word_class()? => {}
        (WordMode::Unicode, HirKind::Class(Class::Unicode(class)))
            if class == &parse_unicode_word_class()? => {}
        _ => return None,
    }
    let plan = Plan::new(
        usize::try_from(repetition.min).ok()?,
        repetition.max.map(usize::try_from).transpose().ok()?,
        require_start_boundary,
        require_end_boundary,
        mode,
    );
    let (hir_nodes, captures) = count_hir(hir)?;
    Some((plan, hir_nodes, captures))
}

fn single_boundary_mode(hir: &Hir) -> Option<WordMode> {
    match transparent(hir).kind() {
        HirKind::Look(Look::WordAscii) => Some(WordMode::Ascii),
        HirKind::Look(Look::WordUnicode) => Some(WordMode::Unicode),
        _ => None,
    }
}

fn boundary_mode(start: &Hir, end: &Hir) -> Option<WordMode> {
    let start = single_boundary_mode(start)?;
    (single_boundary_mode(end)? == start).then_some(start)
}

fn class_mode(hir: &Hir) -> Option<WordMode> {
    match transparent(hir).kind() {
        HirKind::Class(Class::Bytes(class)) if class == &parse_ascii_word_class()? => {
            Some(WordMode::Ascii)
        }
        HirKind::Class(Class::Unicode(class)) if class == &parse_unicode_word_class()? => {
            Some(WordMode::Unicode)
        }
        _ => None,
    }
}

fn count_hir(hir: &Hir) -> Option<(usize, usize)> {
    let (mut nodes, mut captures) = (1_usize, 0_usize);
    match hir.kind() {
        HirKind::Empty | HirKind::Literal(_) | HirKind::Class(_) | HirKind::Look(_) => {}
        HirKind::Repetition(repetition) => {
            let child = count_hir(&repetition.sub)?;
            nodes = nodes.checked_add(child.0)?;
            captures = captures.checked_add(child.1)?;
        }
        HirKind::Capture(capture) => {
            let child = count_hir(&capture.sub)?;
            nodes = nodes.checked_add(child.0)?;
            captures = captures.checked_add(1)?.checked_add(child.1)?;
        }
        HirKind::Concat(children) | HirKind::Alternation(children) => {
            for child in children {
                let child = count_hir(child)?;
                nodes = nodes.checked_add(child.0)?;
                captures = captures.checked_add(child.1)?;
            }
        }
    }
    Some((nodes, captures))
}

fn transparent(mut hir: &Hir) -> &Hir {
    while let HirKind::Capture(capture) = hir.kind() {
        hir = &capture.sub;
    }
    hir
}

fn parse_ascii_word_class() -> Option<regex_syntax::hir::ClassBytes> {
    let hir = ParserBuilder::new()
        .unicode(false)
        .utf8(false)
        .build()
        .parse(r"\w")
        .ok()?;
    let HirKind::Class(Class::Bytes(class)) = hir.kind() else {
        return None;
    };
    Some(class.clone())
}

fn parse_unicode_word_class() -> Option<regex_syntax::hir::ClassUnicode> {
    let hir = ParserBuilder::new()
        .unicode(true)
        .utf8(false)
        .build()
        .parse(r"\w")
        .ok()?;
    let HirKind::Class(Class::Unicode(class)) = hir.kind() else {
        return None;
    };
    Some(class.clone())
}

fn charge(accounting: &mut Accounting, limits: SearchLimits) -> Result<(), Error> {
    let needed = accounting.work.saturating_add(1);
    if needed > limits.max_work {
        return Err(Error::WorkLimitExceeded {
            needed,
            limit: limits.max_work,
        });
    }
    accounting.work = needed;
    Ok(())
}

fn unicode_word_before(haystack: &[u8], position: usize) -> bool {
    decode_last(&haystack[..position]).is_some_and(|(scalar, _)| is_unicode_word(scalar))
}

fn unicode_word_after(haystack: &[u8], position: usize) -> bool {
    decode_first(&haystack[position..]).is_some_and(|(scalar, _)| is_unicode_word(scalar))
}

fn is_ascii_word(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn is_unicode_word(scalar: char) -> bool {
    if scalar.is_ascii() {
        return scalar == '_' || scalar.is_ascii_alphanumeric();
    }
    regex_syntax::try_is_word_character(scalar)
        .expect("fre enables regex-syntax's Unicode Perl tables")
}

fn decode_first(bytes: &[u8]) -> Option<(char, usize)> {
    let first = *bytes.first()?;
    if first.is_ascii() {
        return Some((char::from(first), 1));
    }
    let width = match first {
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => return None,
    };
    let scalar = core::str::from_utf8(bytes.get(..width)?)
        .ok()?
        .chars()
        .next()?;
    Some((scalar, width))
}

fn decode_last(bytes: &[u8]) -> Option<(char, usize)> {
    let mut start = bytes.len().checked_sub(1)?;
    let lower = bytes.len().saturating_sub(4);
    while start > lower && matches!(bytes[start], 0x80..=0xBF) {
        start = start.checked_sub(1)?;
    }
    let (scalar, width) = decode_first(&bytes[start..])?;
    (start.checked_add(width) == Some(bytes.len())).then_some((scalar, width))
}
