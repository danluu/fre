use core::fmt;

use regex_syntax::hir::Look;

/// A fail-closed refusal from the directional Unicode-look primitive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnicodeLookError {
    InvalidPosition { at: usize, haystack_len: usize },
    UnsupportedLook { look: Look },
}

impl fmt::Display for UnicodeLookError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPosition { at, haystack_len } => write!(
                formatter,
                "Unicode look position {at} exceeds the {haystack_len}-byte haystack"
            ),
            Self::UnsupportedLook { look } => {
                write!(
                    formatter,
                    "look assertion {look:?} is not a Unicode word look"
                )
            }
        }
    }
}

impl std::error::Error for UnicodeLookError {}

/// Allocation-free Unicode word-look evaluation over original haystack bytes.
///
/// At most one scalar is decoded on each side. Invalid leading bytes are
/// non-word context; negated and half assertions additionally require the
/// corresponding side to be empty or valid UTF-8, matching K0 semantics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UnicodeLookMatcher;

impl UnicodeLookMatcher {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    pub fn matches(self, look: Look, haystack: &[u8], at: usize) -> Result<bool, UnicodeLookError> {
        if at > haystack.len() {
            return Err(UnicodeLookError::InvalidPosition {
                at,
                haystack_len: haystack.len(),
            });
        }
        if !is_supported(look) {
            return Err(UnicodeLookError::UnsupportedLook { look });
        }
        Ok(Self::matches_prevalidated(look, haystack, at))
    }

    pub(crate) fn matches_prevalidated(look: Look, haystack: &[u8], at: usize) -> bool {
        debug_assert!(at <= haystack.len());
        debug_assert!(is_supported(look));
        let before = &haystack[..at];
        let after = &haystack[at..];
        let left_scalar = decode_last_utf8(before);
        let right_scalar = decode_utf8(after);
        let left_valid = before.is_empty() || left_scalar.is_some();
        let right_valid = after.is_empty() || right_scalar.is_some();
        let left_word = left_scalar.is_some_and(is_unicode_word_character);
        let right_word = right_scalar.is_some_and(is_unicode_word_character);
        match look {
            Look::WordUnicode => left_word != right_word,
            Look::WordUnicodeNegate => left_valid && right_valid && left_word == right_word,
            Look::WordStartUnicode => !left_word && right_word,
            Look::WordEndUnicode => left_word && !right_word,
            Look::WordStartHalfUnicode => left_valid && !left_word,
            Look::WordEndHalfUnicode => right_valid && !right_word,
            _ => unreachable!("matches rejects non-Unicode looks"),
        }
    }
}

const fn is_supported(look: Look) -> bool {
    matches!(
        look,
        Look::WordUnicode
            | Look::WordUnicodeNegate
            | Look::WordStartUnicode
            | Look::WordEndUnicode
            | Look::WordStartHalfUnicode
            | Look::WordEndHalfUnicode
    )
}

fn is_unicode_word_character(character: char) -> bool {
    regex_syntax::try_is_word_character(character)
        .expect("fre-automata enables regex-syntax's Unicode Perl tables")
}

fn decode_utf8(bytes: &[u8]) -> Option<char> {
    let first = *bytes.first()?;
    let len = match first {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF7 => 4,
        _ => return None,
    };
    let scalar = core::str::from_utf8(bytes.get(..len)?).ok()?;
    scalar.chars().next()
}

fn decode_last_utf8(bytes: &[u8]) -> Option<char> {
    let last = bytes.len().checked_sub(1)?;
    let lower = bytes.len().saturating_sub(4);
    let mut start = last;
    while start > lower && matches!(bytes[start], 0x80..=0xBF) {
        start = start.checked_sub(1)?;
    }
    decode_utf8(&bytes[start..])
}
