//! RE2 rewrite-schema validation.

/// Failure from `RE2::CheckRewriteString`, with stable equivalent prose.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RewriteError {
    TrailingBackslash,
    InvalidEscape,
    CaptureOutOfRange { requested: u8, captures: u32 },
}

/// Checks RE2's single-digit rewrite grammar against a capture count.
pub fn check_rewrite(rewrite: &[u8], capture_count: u32) -> Result<(), RewriteError> {
    let mut index = 0usize;
    let mut maximum = None;
    while index < rewrite.len() {
        if rewrite[index] != b'\\' {
            index = index.saturating_add(1);
            continue;
        }
        index = index.saturating_add(1);
        let Some(&escaped) = rewrite.get(index) else {
            return Err(RewriteError::TrailingBackslash);
        };
        if escaped == b'\\' {
            index = index.saturating_add(1);
            continue;
        }
        if !escaped.is_ascii_digit() {
            return Err(RewriteError::InvalidEscape);
        }
        let capture = escaped.wrapping_sub(b'0');
        maximum = Some(maximum.map_or(capture, |prior: u8| prior.max(capture)));
        index = index.saturating_add(1);
    }
    if let Some(requested) = maximum
        && u32::from(requested) > capture_count
    {
        return Err(RewriteError::CaptureOutOfRange {
            requested,
            captures: capture_count,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{RewriteError, check_rewrite};

    #[test]
    fn grammar_is_single_digit_and_backslash() {
        assert_eq!(check_rewrite(br"x\1-\\-\0", 1), Ok(()));
        assert_eq!(
            check_rewrite(br"\2", 1),
            Err(RewriteError::CaptureOutOfRange {
                requested: 2,
                captures: 1
            })
        );
        assert_eq!(check_rewrite(br"\x", 9), Err(RewriteError::InvalidEscape));
        assert_eq!(
            check_rewrite(b"x\\", 9),
            Err(RewriteError::TrailingBackslash)
        );
    }
}
