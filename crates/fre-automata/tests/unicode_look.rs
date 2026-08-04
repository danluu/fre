use fre_automata::{UnicodeLookError, UnicodeLookMatcher};
use regex_syntax::hir::Look;

#[test]
fn unicode_word_and_directional_cases_match_pinned_context() {
    let matcher = UnicodeLookMatcher::new();
    let cases = [
        (Look::WordUnicode, " α-β ".as_bytes(), &[1, 3, 4, 6][..]),
        (Look::WordUnicodeNegate, " α-β ".as_bytes(), &[0, 7][..]),
        (Look::WordStartUnicode, " α-β ".as_bytes(), &[1, 4][..]),
        (Look::WordEndUnicode, " α-β ".as_bytes(), &[3, 6][..]),
        (
            Look::WordStartHalfUnicode,
            " α-β ".as_bytes(),
            &[0, 1, 4, 7][..],
        ),
        (
            Look::WordEndHalfUnicode,
            " α-β ".as_bytes(),
            &[0, 3, 6, 7][..],
        ),
    ];
    for (look, haystack, expected) in cases {
        for at in 0..=haystack.len() {
            assert_eq!(
                expected.contains(&at),
                matcher.matches(look, haystack, at).unwrap(),
                "look={look:?} at={at}"
            );
        }
    }
}

#[test]
fn malformed_leading_bytes_are_nonword_but_negation_requires_valid_context() {
    let matcher = UnicodeLookMatcher::new();
    assert!(matcher.matches(Look::WordUnicode, b"\x80a", 1).unwrap());
    assert!(!matcher
        .matches(Look::WordUnicodeNegate, b"\x80a", 1)
        .unwrap());
    assert!(!matcher
        .matches(Look::WordStartHalfUnicode, b"\x80a", 1)
        .unwrap());
    assert!(!matcher
        .matches(Look::WordEndHalfUnicode, b"a\x80", 1)
        .unwrap());
}

#[test]
fn every_single_byte_boundary_pair_matches_an_independent_word_oracle() {
    let matcher = UnicodeLookMatcher::new();
    let looks = [
        Look::WordUnicode,
        Look::WordUnicodeNegate,
        Look::WordStartUnicode,
        Look::WordEndUnicode,
        Look::WordStartHalfUnicode,
        Look::WordEndHalfUnicode,
    ];
    let sides = core::iter::once(None)
        .chain((0_u8..=u8::MAX).map(Some))
        .collect::<Vec<_>>();

    for &left in &sides {
        for &right in &sides {
            let mut haystack = Vec::with_capacity(2);
            if let Some(byte) = left {
                haystack.push(byte);
            }
            let at = haystack.len();
            if let Some(byte) = right {
                haystack.push(byte);
            }
            let (left_valid, left_word) = single_byte_word_side(left);
            let (right_valid, right_word) = single_byte_word_side(right);
            for look in looks {
                let expected = match look {
                    Look::WordUnicode => left_word != right_word,
                    Look::WordUnicodeNegate => {
                        left_valid && right_valid && left_word == right_word
                    }
                    Look::WordStartUnicode => !left_word && right_word,
                    Look::WordEndUnicode => left_word && !right_word,
                    Look::WordStartHalfUnicode => left_valid && !left_word,
                    Look::WordEndHalfUnicode => right_valid && !right_word,
                    _ => unreachable!("the test enumerates only Unicode word assertions"),
                };
                assert_eq!(
                    matcher.matches(look, &haystack, at).unwrap(),
                    expected,
                    "look={look:?} left={left:?} right={right:?}"
                );
            }
        }
    }
}

fn single_byte_word_side(byte: Option<u8>) -> (bool, bool) {
    match byte {
        None => (true, false),
        Some(byte) if byte.is_ascii() => {
            (true, byte == b'_' || byte.is_ascii_alphanumeric())
        }
        Some(_) => (false, false),
    }
}

#[test]
fn invalid_position_and_non_unicode_look_fail_closed() {
    let matcher = UnicodeLookMatcher::new();
    assert_eq!(
        UnicodeLookError::InvalidPosition {
            at: 2,
            haystack_len: 1,
        },
        matcher.matches(Look::WordUnicode, b"a", 2).unwrap_err()
    );
    assert_eq!(
        UnicodeLookError::UnsupportedLook {
            look: Look::WordAscii,
        },
        matcher.matches(Look::WordAscii, b"a", 0).unwrap_err()
    );
}
