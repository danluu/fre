//! Executable adapters for the remaining pinned builder doctests.

use fre::{
    CaptureAggregateLimits, CaptureBuilder, CaptureSearchLimits, PortableBuilder,
    PortableRegexSetBuilder, PortableRegexSetRunLimits, PortableTextBuilder,
    PortableTextCaptureBuilder, PortableTextRegexSetBuilder, RustProfile,
};

#[derive(Clone, Copy, Debug)]
pub(crate) enum BuilderRefusal {
    Unsupported(&'static str),
    Fault(&'static str),
}

pub(crate) type BuilderExecution = Result<(Vec<u8>, Vec<u8>), BuilderRefusal>;

#[derive(Clone, Copy)]
enum BuilderProbe {
    TextLineTerminator { set: bool },
    IgnoreWhitespace { text: bool, set: bool },
    UpstreamSizeThreshold,
    ByteUnicodeDot { set: bool },
    ByteLineTerminator { set: bool },
}

const UPSTREAM_SIZE_THRESHOLD_REASON: &str = "doctest.upstream-size-threshold-not-promised";

const PERSON_PATTERN: &str = r"
    \b
    (?<first>\p{Uppercase}\w*)
    [\s--\n]+
    (?:
        (?:(?<initial>\p{Uppercase})\.|(?<middle>\p{Uppercase}\w*))
        [\s--\n]+
    )?
    (?<last>\p{Uppercase}\w*)
    \b
";

/// Execute one source-line-bound builder example handled by this adapter.
pub(crate) fn execute_remaining_builder_doctest(line: usize) -> Option<BuilderExecution> {
    let probe = match line {
        511 => BuilderProbe::TextLineTerminator { set: false },
        1088 => BuilderProbe::TextLineTerminator { set: true },
        577 => BuilderProbe::IgnoreWhitespace {
            text: true,
            set: false,
        },
        1158 => BuilderProbe::IgnoreWhitespace {
            text: true,
            set: true,
        },
        1750 => BuilderProbe::IgnoreWhitespace {
            text: false,
            set: false,
        },
        2342 => BuilderProbe::IgnoreWhitespace {
            text: false,
            set: true,
        },
        // These examples assert the upstream 45,000-byte compiled-size boundary.
        // Their authenticated expected value remains upstream-owned; FRE's native
        // representation has no equivalent threshold to compare.
        681 | 1249 | 1860 | 2433 => BuilderProbe::UpstreamSizeThreshold,
        1452 => BuilderProbe::ByteUnicodeDot { set: false },
        2052 => BuilderProbe::ByteUnicodeDot { set: true },
        1683 => BuilderProbe::ByteLineTerminator { set: false },
        2281 => BuilderProbe::ByteLineTerminator { set: true },
        _ => return None,
    };
    Some(run_probe(probe))
}

fn run_probe(probe: BuilderProbe) -> BuilderExecution {
    let (expected, observed) = match probe {
        BuilderProbe::TextLineTerminator { set } => (
            b"true,true".to_vec(),
            text_line_terminator(set).into_bytes(),
        ),
        BuilderProbe::IgnoreWhitespace { text, set } => {
            let expected = if set {
                "true,true,true,false"
            } else {
                "Harry|_|_|Potter,Harry|J|_|Potter,Harry|_|James|Potter"
            };
            (
                expected.as_bytes().to_vec(),
                ignore_whitespace(text, set)?.into_bytes(),
            )
        }
        BuilderProbe::UpstreamSizeThreshold => {
            return Err(BuilderRefusal::Unsupported(UPSTREAM_SIZE_THRESHOLD_REASON));
        }
        BuilderProbe::ByteUnicodeDot { set } => {
            (b"true".to_vec(), byte_unicode_dot(set)?.into_bytes())
        }
        BuilderProbe::ByteLineTerminator { set } => (
            b"true".to_vec(),
            byte_line_terminator(set).to_string().into_bytes(),
        ),
    };
    Ok((expected, observed))
}

fn text_line_terminator(set: bool) -> String {
    let (dot_error, literal_ok) = if set {
        let dot = vec![".".to_owned()];
        let literal = vec!["a".to_owned()];
        (
            PortableTextRegexSetBuilder::new(&dot)
                .line_terminator(0x80)
                .build()
                .is_err(),
            PortableTextRegexSetBuilder::new(&literal)
                .line_terminator(0x80)
                .build()
                .is_ok(),
        )
    } else {
        (
            PortableTextBuilder::new(".")
                .line_terminator(0x80)
                .build()
                .is_err(),
            PortableTextBuilder::new("a")
                .line_terminator(0x80)
                .build()
                .is_ok(),
        )
    };
    format!("{dot_error},{literal_ok}")
}

fn ignore_whitespace(text: bool, set: bool) -> Result<String, BuilderRefusal> {
    let mut profile = RustProfile::regex_1_12_4();
    profile.options.ignore_whitespace = true;
    if set {
        return ignore_whitespace_set(text, profile);
    }
    if text {
        ignore_whitespace_text_captures(profile)
    } else {
        ignore_whitespace_byte_captures(profile)
    }
}

fn ignore_whitespace_set(text: bool, profile: RustProfile) -> Result<String, BuilderRefusal> {
    let patterns = vec![PERSON_PATTERN.to_owned()];
    let values = if text {
        let regex = PortableTextRegexSetBuilder::new(&patterns)
            .profile(profile)
            .build()
            .map_err(|_| BuilderRefusal::Unsupported("doctest.builder-set-build-refused"))?;
        [
            regex.is_match("Harry Potter", PortableRegexSetRunLimits::unlimited()),
            regex.is_match("Harry J. Potter", PortableRegexSetRunLimits::unlimited()),
            regex.is_match("Harry James Potter", PortableRegexSetRunLimits::unlimited()),
            regex.is_match("harry J. Potter", PortableRegexSetRunLimits::unlimited()),
        ]
        .map(|result| {
            result
                .map(|(matched, _)| matched)
                .map_err(|_| BuilderRefusal::Unsupported("doctest.builder-set-search-refused"))
        })
    } else {
        let regex = PortableRegexSetBuilder::new(&patterns)
            .profile(profile)
            .build()
            .map_err(|_| BuilderRefusal::Unsupported("doctest.builder-set-build-refused"))?;
        [
            regex.is_match(b"Harry Potter", PortableRegexSetRunLimits::unlimited()),
            regex.is_match(b"Harry J. Potter", PortableRegexSetRunLimits::unlimited()),
            regex.is_match(
                b"Harry James Potter",
                PortableRegexSetRunLimits::unlimited(),
            ),
            regex.is_match(b"harry J. Potter", PortableRegexSetRunLimits::unlimited()),
        ]
        .map(|result| {
            result
                .map(|(matched, _)| matched)
                .map_err(|_| BuilderRefusal::Unsupported("doctest.builder-set-search-refused"))
        })
    };
    values
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map(|values| {
            values
                .into_iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
                .join(",")
        })
}

fn ignore_whitespace_text_captures(profile: RustProfile) -> Result<String, BuilderRefusal> {
    let regex = PortableTextCaptureBuilder::new(PERSON_PATTERN)
        .profile(profile)
        .build()
        .map_err(|_| BuilderRefusal::Unsupported("doctest.builder-capture-build-refused"))?;
    ["Harry Potter", "Harry J. Potter", "Harry James Potter"]
        .into_iter()
        .map(|haystack| {
            let (captures, _) = regex
                .captures(haystack, CaptureSearchLimits::default())
                .map_err(|_| {
                    BuilderRefusal::Unsupported("doctest.builder-capture-search-refused")
                })?;
            let captures = captures.ok_or(BuilderRefusal::Fault(
                "doctest.builder-capture-match-missing",
            ))?;
            Ok(["first", "initial", "middle", "last"]
                .map(|name| {
                    captures
                        .name(name)
                        .map_or("_", fre::PortableTextCaptureMatch::as_str)
                })
                .join("|"))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|values| values.join(","))
}

fn ignore_whitespace_byte_captures(profile: RustProfile) -> Result<String, BuilderRefusal> {
    let regex = CaptureBuilder::new(PERSON_PATTERN)
        .profile(profile)
        .build()
        .map_err(|_| BuilderRefusal::Unsupported("doctest.builder-capture-build-refused"))?;
    [
        b"Harry Potter".as_slice(),
        b"Harry J. Potter",
        b"Harry James Potter",
    ]
    .into_iter()
    .map(|haystack| {
        let report = regex
            .captures_iter(haystack, CaptureAggregateLimits::default())
            .map_err(|_| BuilderRefusal::Unsupported("doctest.builder-capture-search-refused"))?;
        let record = report.captures.first().ok_or(BuilderRefusal::Fault(
            "doctest.builder-capture-match-missing",
        ))?;
        ["first", "initial", "middle", "last"]
            .map(|name| {
                record
                    .groups
                    .iter()
                    .find(|group| group.name.as_deref() == Some(name))
                    .ok_or(BuilderRefusal::Fault(
                        "doctest.builder-capture-group-missing",
                    ))
                    .and_then(|group| {
                        group.span.map_or(Ok("_"), |span| {
                            haystack
                                .get(span.start..span.end)
                                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                                .ok_or(BuilderRefusal::Fault(
                                    "doctest.builder-capture-span-invalid",
                                ))
                        })
                    })
            })
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .map(|values| values.join("|"))
    })
    .collect::<Result<Vec<_>, _>>()
    .map(|values| values.join(","))
}

fn byte_unicode_dot(set: bool) -> Result<String, BuilderRefusal> {
    let matched = if set {
        let patterns = vec![".".to_owned()];
        PortableRegexSetBuilder::new(&patterns)
            .unicode(false)
            .build()
            .map_err(|_| BuilderRefusal::Unsupported("doctest.builder-set-build-refused"))?
            .is_match(b"\xFF", PortableRegexSetRunLimits::unlimited())
            .map_err(|_| BuilderRefusal::Unsupported("doctest.builder-set-search-refused"))?
            .0
    } else {
        PortableBuilder::new(".")
            .unicode(false)
            .build()
            .map_err(|_| BuilderRefusal::Unsupported("doctest.builder-build-refused"))?
            .is_match(b"\xFF")
    };
    Ok(matched.to_string())
}

fn byte_line_terminator(set: bool) -> bool {
    if set {
        let patterns = vec![".".to_owned()];
        PortableRegexSetBuilder::new(&patterns)
            .unicode(false)
            .line_terminator(0x80)
            .build()
            .is_ok()
    } else {
        PortableBuilder::new(".")
            .unicode(false)
            .line_terminator(0x80)
            .build()
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_remaining_builder_probe_matches() {
        const SUPPORTED_LINES: [usize; 10] =
            [511, 577, 1088, 1158, 1452, 1683, 1750, 2052, 2281, 2342];
        for line in SUPPORTED_LINES {
            let (expected, observed) = execute_remaining_builder_doctest(line)
                .unwrap_or_else(|| panic!("missing builder probe {line}"))
                .unwrap_or_else(|error| panic!("builder probe {line} refused: {error:?}"));
            assert_eq!(expected, observed, "builder probe {line}");
        }
        for line in [681, 1249, 1860, 2433] {
            assert!(matches!(
                execute_remaining_builder_doctest(line),
                Some(Err(BuilderRefusal::Unsupported(
                    UPSTREAM_SIZE_THRESHOLD_REASON
                )))
            ));
        }
        assert!(execute_remaining_builder_doctest(1).is_none());
    }
}
