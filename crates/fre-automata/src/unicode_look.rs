use core::fmt;

use regex_syntax::hir::Look;

use crate::EdgeKind;

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

/// The validity and Unicode-word status of the scalars adjacent to one byte
/// boundary.
///
/// K0's contextual executor uses this once per boundary to answer every
/// Unicode word-look variant used by the compiled automaton. Keeping validity
/// separate from word membership preserves the fail-closed semantics of
/// negated and half assertions on malformed UTF-8.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UnicodeWordBoundary {
    left: UnicodeWordSide,
    right: UnicodeWordSide,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnicodeWordSide {
    Invalid,
    NonWord,
    Word,
}

impl UnicodeWordSide {
    const fn valid(self) -> bool {
        !matches!(self, Self::Invalid)
    }

    const fn word(self) -> bool {
        matches!(self, Self::Word)
    }
}

impl UnicodeWordBoundary {
    pub(crate) const fn class(self) -> usize {
        match (self.left, self.right) {
            (UnicodeWordSide::Invalid, UnicodeWordSide::Invalid) => 0,
            (UnicodeWordSide::NonWord, UnicodeWordSide::Invalid) => 1,
            (UnicodeWordSide::Word, UnicodeWordSide::Invalid) => 2,
            (UnicodeWordSide::Invalid, UnicodeWordSide::NonWord) => 3,
            (UnicodeWordSide::NonWord, UnicodeWordSide::NonWord) => 4,
            (UnicodeWordSide::Word, UnicodeWordSide::NonWord) => 5,
            (UnicodeWordSide::Invalid, UnicodeWordSide::Word) => 6,
            (UnicodeWordSide::NonWord, UnicodeWordSide::Word) => 7,
            (UnicodeWordSide::Word, UnicodeWordSide::Word) => 8,
        }
    }

    fn matches(self, look: Look) -> bool {
        let left_valid = self.left.valid();
        let right_valid = self.right.valid();
        let left_word = self.left.word();
        let right_word = self.right.word();
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

impl UnicodeLookMatcher {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// The exact pinned UTS#18 Perl-word interval table used by this matcher.
    ///
    /// Native object builders copy these scalar endpoints into immutable
    /// artifact-local data. Generated entries never call back into Rust for
    /// Unicode classification.
    #[doc(hidden)]
    #[must_use]
    pub fn perl_word_ranges_v16() -> &'static [(char, char)] {
        crate::unicode_perl_word_v16::PERL_WORD
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
        Self::classify_prevalidated(haystack, at).matches(look)
    }

    pub(crate) fn classify_prevalidated(haystack: &[u8], at: usize) -> UnicodeWordBoundary {
        debug_assert!(at <= haystack.len());
        let before = &haystack[..at];
        let after = &haystack[at..];
        UnicodeWordBoundary {
            left: classify_unicode_word_before(before),
            right: classify_unicode_word_after(after),
        }
    }

    /// Evaluate one canonical Unicode-word Thompson edge at an already
    /// validated original-haystack boundary.
    ///
    /// This narrow seam lets fixed-layout native-table simulators share K0's
    /// pinned decoder and Unicode table without depending on `regex-syntax`'s
    /// public `Look` representation. `None` rejects a non-Unicode edge or an
    /// out-of-bounds boundary before any source byte is inspected.
    #[doc(hidden)]
    #[must_use]
    pub fn matches_edge_kind_prevalidated(
        kind: EdgeKind,
        haystack: &[u8],
        at: usize,
    ) -> Option<bool> {
        if at > haystack.len() {
            return None;
        }
        let look = match kind {
            EdgeKind::AssertWordUnicode => Look::WordUnicode,
            EdgeKind::AssertWordUnicodeNegate => Look::WordUnicodeNegate,
            EdgeKind::AssertWordStartUnicode => Look::WordStartUnicode,
            EdgeKind::AssertWordEndUnicode => Look::WordEndUnicode,
            EdgeKind::AssertWordStartHalfUnicode => Look::WordStartHalfUnicode,
            EdgeKind::AssertWordEndHalfUnicode => Look::WordEndHalfUnicode,
            _ => return None,
        };
        Some(Self::matches_prevalidated(look, haystack, at))
    }
}

fn classify_unicode_word_before(bytes: &[u8]) -> UnicodeWordSide {
    match bytes.last().copied() {
        None => UnicodeWordSide::NonWord,
        Some(byte) if byte.is_ascii() => classify_ascii_word_byte(byte),
        Some(_) => classify_decoded_unicode_word_side(decode_last_utf8(bytes)),
    }
}

fn classify_unicode_word_after(bytes: &[u8]) -> UnicodeWordSide {
    match bytes.first().copied() {
        None => UnicodeWordSide::NonWord,
        Some(byte) if byte.is_ascii() => classify_ascii_word_byte(byte),
        Some(_) => classify_decoded_unicode_word_side(decode_utf8(bytes)),
    }
}

fn classify_ascii_word_byte(byte: u8) -> UnicodeWordSide {
    if byte == b'_' || byte.is_ascii_alphanumeric() {
        UnicodeWordSide::Word
    } else {
        UnicodeWordSide::NonWord
    }
}

fn classify_decoded_unicode_word_side(scalar: Option<char>) -> UnicodeWordSide {
    match scalar {
        Some(character) if is_unicode_word_character(character) => UnicodeWordSide::Word,
        Some(_) => UnicodeWordSide::NonWord,
        None => UnicodeWordSide::Invalid,
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
