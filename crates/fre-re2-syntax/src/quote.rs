//! RE2 `QuoteMeta` compatibility helper.

/// Quotes arbitrary bytes using RE2's pinned `QuoteMeta` algorithm.
#[must_use]
pub fn quote_meta(unquoted: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(unquoted.len().saturating_mul(2));
    for &byte in unquoted {
        let word = byte.is_ascii_alphanumeric() || byte == b'_';
        if !word && byte & 0x80 == 0 {
            if byte == 0 {
                result.extend_from_slice(br"\x00");
                continue;
            }
            result.push(b'\\');
        }
        result.push(byte);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::quote_meta;

    #[test]
    fn mirrors_re2_special_cases() {
        assert_eq!(quote_meta(b"a_b-\0\xff"), b"a_b\\-\\x00\xff");
        assert_eq!(
            quote_meta(b"[](){}.*+?$^|#\\"),
            br"\[\]\(\)\{\}\.\*\+\?\$\^\|\#\\"
        );
    }
}
