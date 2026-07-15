use regex_syntax::hir::Look;

use crate::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ByteSet(pub(crate) [u64; 4]);

impl ByteSet {
    pub(crate) const fn empty() -> Self {
        Self([0; 4])
    }

    pub(crate) fn insert(&mut self, byte: u8) {
        let index = usize::from(byte) / 64;
        let bit = usize::from(byte) % 64;
        self.0[index] |= 1_u64 << bit;
    }

    pub(crate) fn insert_range(&mut self, start: u8, end: u8) {
        for byte in start..=end {
            self.insert(byte);
        }
    }

    pub(crate) fn contains(self, byte: u8) -> bool {
        let index = usize::from(byte) / 64;
        let bit = usize::from(byte) % 64;
        self.0[index] & (1_u64 << bit) != 0
    }
}

/// A constant-time zero-width predicate admitted by the continuation engine.
///
/// This is deliberately distinct from `regex_syntax::hir::Look`: every
/// variant here has one audited implementation below, while HIR variants that
/// require direction-specific Unicode word state or CRLF state remain typed
/// refusals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Assertion {
    StartText,
    EndText,
    StartLf,
    EndLf,
    WordAscii,
    WordAsciiNegate,
    WordStartAscii,
    WordEndAscii,
    WordStartHalfAscii,
    WordEndHalfAscii,
    WordUnicode,
}

impl Assertion {
    pub(crate) const fn from_look(look: Look) -> Option<Self> {
        match look {
            Look::Start => Some(Self::StartText),
            Look::End => Some(Self::EndText),
            Look::StartLF => Some(Self::StartLf),
            Look::EndLF => Some(Self::EndLf),
            Look::WordAscii => Some(Self::WordAscii),
            Look::WordAsciiNegate => Some(Self::WordAsciiNegate),
            Look::WordStartAscii => Some(Self::WordStartAscii),
            Look::WordEndAscii => Some(Self::WordEndAscii),
            Look::WordStartHalfAscii => Some(Self::WordStartHalfAscii),
            Look::WordEndHalfAscii => Some(Self::WordEndHalfAscii),
            Look::WordUnicode => Some(Self::WordUnicode),
            Look::StartCRLF
            | Look::EndCRLF
            | Look::WordUnicodeNegate
            | Look::WordStartUnicode
            | Look::WordEndUnicode
            | Look::WordStartHalfUnicode
            | Look::WordEndHalfUnicode => None,
        }
    }

    pub(crate) const fn identity_tag(self) -> u8 {
        match self {
            Self::StartText => 0,
            Self::EndText => 1,
            Self::StartLf => 2,
            Self::EndLf => 3,
            Self::WordAscii => 4,
            Self::WordAsciiNegate => 5,
            Self::WordStartAscii => 6,
            Self::WordEndAscii => 7,
            Self::WordStartHalfAscii => 8,
            Self::WordEndHalfAscii => 9,
            Self::WordUnicode => 10,
        }
    }
}

/// Original-haystack context for predicates evaluated at local range
/// boundaries. Consuming transitions never use this context and therefore
/// remain confined to the requested operation range.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AssertionContext<'h> {
    haystack: &'h [u8],
    base: usize,
    local_len: usize,
}

impl<'h> AssertionContext<'h> {
    pub(crate) fn new(haystack: &'h [u8], base: usize, local_len: usize) -> Result<Self, Error> {
        let end = base
            .checked_add(local_len)
            .ok_or(Error::InternalInvariant("assertion range overflow"))?;
        if end > haystack.len() {
            return Err(Error::InternalInvariant(
                "assertion range outside original haystack",
            ));
        }
        Ok(Self {
            haystack,
            base,
            local_len,
        })
    }

    pub(crate) fn is_match(
        self,
        assertion: Assertion,
        local_position: usize,
    ) -> Result<bool, Error> {
        if local_position > self.local_len {
            return Err(Error::InternalInvariant(
                "assertion position outside operation range",
            ));
        }
        let absolute = self
            .base
            .checked_add(local_position)
            .ok_or(Error::InternalInvariant("assertion position overflow"))?;
        let left_byte = absolute
            .checked_sub(1)
            .and_then(|index| self.haystack.get(index));
        let right_byte = self.haystack.get(absolute);
        let left_word = left_byte.is_some_and(|&byte| is_ascii_word(byte));
        let right_word = right_byte.is_some_and(|&byte| is_ascii_word(byte));
        Ok(match assertion {
            Assertion::StartText => absolute == 0,
            Assertion::EndText => absolute == self.haystack.len(),
            Assertion::StartLf => absolute == 0 || left_byte.is_some_and(|&byte| byte == b'\n'),
            Assertion::EndLf => {
                absolute == self.haystack.len() || right_byte.is_some_and(|&byte| byte == b'\n')
            }
            Assertion::WordAscii => left_word != right_word,
            Assertion::WordAsciiNegate => left_word == right_word,
            Assertion::WordStartAscii => !left_word && right_word,
            Assertion::WordEndAscii => left_word && !right_word,
            Assertion::WordStartHalfAscii => !left_word,
            Assertion::WordEndHalfAscii => !right_word,
            Assertion::WordUnicode => {
                let before = self
                    .haystack
                    .get(..absolute)
                    .ok_or(Error::InternalInvariant("Unicode assertion prefix missing"))?;
                let after = self
                    .haystack
                    .get(absolute..)
                    .ok_or(Error::InternalInvariant("Unicode assertion suffix missing"))?;
                let word_before = unicode_word_scalar(decode_last_scalar(before))?;
                let word_after = unicode_word_scalar(decode_first_scalar(after))?;
                word_before != word_after
            }
        })
    }

    pub(crate) const fn base(self) -> usize {
        self.base
    }
}

const fn is_ascii_word(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn unicode_word_scalar(scalar: Option<char>) -> Result<bool, Error> {
    let Some(scalar) = scalar else {
        return Ok(false);
    };
    regex_syntax::try_is_word_character(scalar)
        .map_err(|_| Error::InternalInvariant("pinned Unicode word table is unavailable"))
}

fn decode_first_scalar(bytes: &[u8]) -> Option<char> {
    let first = *bytes.first()?;
    let width = match first {
        0x00..=0x7F => 1,
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => return None,
    };
    let encoded = bytes.get(..width)?;
    core::str::from_utf8(encoded).ok()?.chars().next()
}

fn decode_last_scalar(bytes: &[u8]) -> Option<char> {
    let end = bytes.len();
    let mut start = end.checked_sub(1)?;
    let limit = end.saturating_sub(4);
    while start > limit && matches!(bytes[start], 0x80..=0xBF) {
        start = start.checked_sub(1)?;
    }
    let encoded = bytes.get(start..end)?;
    let scalar = decode_first_scalar(encoded)?;
    (scalar.len_utf8() == encoded.len()).then_some(scalar)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Inst {
    Unfilled,
    Fail,
    Match,
    Consume { bytes: ByteSet, next: usize },
    Assert { assertion: Assertion, next: usize },
    Split { preferred: usize, fallback: usize },
}

#[derive(Debug)]
pub(crate) struct Program {
    pub(crate) insts: Vec<Inst>,
    pub(crate) entry: usize,
    pub(crate) epsilon_order: Vec<usize>,
    pub(crate) split_rank: Vec<Option<usize>>,
    pub(crate) split_count: usize,
}

impl Program {
    pub(crate) fn contains_unicode_word_boundary(&self) -> bool {
        self.insts.iter().any(|inst| {
            matches!(
                inst,
                Inst::Assert {
                    assertion: Assertion::WordUnicode,
                    ..
                }
            )
        })
    }

    pub(crate) fn instruction(&self, pc: usize) -> Result<&Inst, Error> {
        self.insts
            .get(pc)
            .ok_or(Error::InternalInvariant("program counter outside program"))
    }
}
