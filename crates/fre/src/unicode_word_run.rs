use regex_syntax::{
    ParserBuilder,
    hir::{Class, Hir, HirKind, Look},
};

use crate::{Match, SearchLimits, SearchWindow};

pub(crate) const UNICODE_PLAN_ID: &str = "unicode-word-run-linear-v1";
pub(crate) const ASCII_PLAN_ID: &str = "ascii-word-run-linear-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WordMode {
    Ascii,
    Unicode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Plan {
    minimum_scalars: usize,
    mode: WordMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Accounting {
    pub(crate) work: u64,
    pub(crate) bytes_examined: usize,
    pub(crate) scalars_decoded: usize,
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
    const fn new(minimum_scalars: usize, mode: WordMode) -> Self {
        Self {
            minimum_scalars,
            mode,
        }
    }

    pub(crate) const fn plan_id(self) -> &'static str {
        match self.mode {
            WordMode::Ascii => ASCII_PLAN_ID,
            WordMode::Unicode => UNICODE_PLAN_ID,
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
        match self.mode {
            WordMode::Ascii => self.find_ascii_window(haystack, window, limits),
            WordMode::Unicode => self.find_unicode_window(haystack, window, limits),
        }
    }

    fn find_ascii_window(
        self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, Accounting), Error> {
        let mut accounting = Accounting {
            work: 0,
            bytes_examined: 0,
            scalars_decoded: 0,
        };
        let mut position = window.start();
        while position < window.end() {
            charge(&mut accounting, limits)?;
            let byte = haystack[position];
            accounting.bytes_examined = accounting.bytes_examined.saturating_add(1);
            accounting.scalars_decoded = accounting.scalars_decoded.saturating_add(1);
            if !is_ascii_word(byte)
                || position
                    .checked_sub(1)
                    .is_some_and(|before| is_ascii_word(haystack[before]))
            {
                position = position.checked_add(1).ok_or(Error::WorkLimitExceeded {
                    needed: u64::MAX,
                    limit: limits.max_work,
                })?;
                continue;
            }

            let start = position;
            position = position.checked_add(1).ok_or(Error::WorkLimitExceeded {
                needed: u64::MAX,
                limit: limits.max_work,
            })?;
            while position < window.end() && is_ascii_word(haystack[position]) {
                charge(&mut accounting, limits)?;
                accounting.bytes_examined = accounting.bytes_examined.saturating_add(1);
                accounting.scalars_decoded = accounting.scalars_decoded.saturating_add(1);
                position = position.checked_add(1).ok_or(Error::WorkLimitExceeded {
                    needed: u64::MAX,
                    limit: limits.max_work,
                })?;
            }
            if position.saturating_sub(start) >= self.minimum_scalars
                && !haystack
                    .get(position)
                    .is_some_and(|&byte| is_ascii_word(byte))
            {
                return Ok((
                    Some(Match {
                        start,
                        end: position,
                    }),
                    accounting,
                ));
            }
        }
        Ok((None, accounting))
    }

    fn find_unicode_window(
        self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, Accounting), Error> {
        let mut accounting = Accounting {
            work: 0,
            bytes_examined: 0,
            scalars_decoded: 0,
        };
        let mut position = window.start();
        while position < window.end() {
            charge(&mut accounting, limits)?;
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
            if !is_unicode_word(scalar) || unicode_word_before(haystack, position) {
                position = position
                    .checked_add(width)
                    .ok_or(Error::WorkLimitExceeded {
                        needed: u64::MAX,
                        limit: limits.max_work,
                    })?;
                continue;
            }

            let start = position;
            let mut count = 1_usize;
            position = position
                .checked_add(width)
                .ok_or(Error::WorkLimitExceeded {
                    needed: u64::MAX,
                    limit: limits.max_work,
                })?;
            while position < window.end() {
                charge(&mut accounting, limits)?;
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
            if count >= self.minimum_scalars && !unicode_word_after(haystack, position) {
                return Ok((
                    Some(Match {
                        start,
                        end: position,
                    }),
                    accounting,
                ));
            }
        }
        Ok((None, accounting))
    }
}

pub(crate) fn extract(hir: &Hir) -> Option<Plan> {
    let HirKind::Concat(parts) = transparent(hir).kind() else {
        return None;
    };
    let [start, repeated, end] = parts.as_slice() else {
        return None;
    };
    let mode = match (transparent(start).kind(), transparent(end).kind()) {
        (HirKind::Look(Look::WordAscii), HirKind::Look(Look::WordAscii)) => WordMode::Ascii,
        (HirKind::Look(Look::WordUnicode), HirKind::Look(Look::WordUnicode)) => WordMode::Unicode,
        _ => return None,
    };
    let HirKind::Repetition(repetition) = transparent(repeated).kind() else {
        return None;
    };
    if repetition.min == 0 || repetition.max.is_some() || !repetition.greedy {
        return None;
    }
    match (mode, transparent(&repetition.sub).kind()) {
        (WordMode::Ascii, HirKind::Class(Class::Bytes(class)))
            if class == &parse_ascii_word_class()? => {}
        (WordMode::Unicode, HirKind::Class(Class::Unicode(class)))
            if class == &parse_unicode_word_class()? => {}
        _ => return None,
    }
    Some(Plan::new(usize::try_from(repetition.min).ok()?, mode))
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
        return is_ascii_word(scalar as u8);
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
