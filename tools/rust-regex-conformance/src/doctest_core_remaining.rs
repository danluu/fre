//! Executable adapters for the remaining pinned core regex doctests.

use fre::{
    CaptureExpansionLimits, CaptureSearchLimits, PortableBuilder, PortableFindIterLimits,
    PortableTextBuilder, PortableTextCaptureBuilder, RustProfile, SearchLimits, SearchWindow,
};

#[derive(Clone, Copy, Debug)]
pub(crate) enum RemainingCoreRefusal {
    Unsupported(&'static str),
    Fault(&'static str),
}

pub(crate) type RemainingCoreExecution = Result<(Vec<u8>, Vec<u8>), RemainingCoreRefusal>;

#[derive(Clone, Copy)]
enum Probe {
    LazySearch,
    Dates,
    EmptyIteration,
    ConstructorErrors { text: bool },
    NamedCapture,
    ContextCapture,
    AlternativeCapture,
    CaptureExpand,
    Shortest { text: bool, contextual: bool },
}

/// Execute one source-line-bound core example handled by this adapter.
pub(crate) fn execute_remaining_core_doctest(id: &str) -> Option<RemainingCoreExecution> {
    let probe = match id {
        "README.md:89" | "src/lib.rs:481" => Probe::LazySearch,
        "src/lib.rs:253" => Probe::Dates,
        "src/lib.rs:746" => Probe::EmptyIteration,
        "src/regex/bytes.rs:166" => Probe::ConstructorErrors { text: false },
        "src/regex/string.rs:168" => Probe::ConstructorErrors { text: true },
        "src/lib.rs:197" => Probe::NamedCapture,
        "src/regex/string.rs:1133" => Probe::ContextCapture,
        "src/regex/string.rs:1804" => Probe::AlternativeCapture,
        "src/regex/string.rs:1870" => Probe::CaptureExpand,
        "src/regex/bytes.rs:1003" => Probe::Shortest {
            text: false,
            contextual: false,
        },
        "src/regex/bytes.rs:1035" => Probe::Shortest {
            text: false,
            contextual: true,
        },
        "src/regex/string.rs:990" => Probe::Shortest {
            text: true,
            contextual: false,
        },
        "src/regex/string.rs:1022" => Probe::Shortest {
            text: true,
            contextual: true,
        },
        _ => return None,
    };
    Some(run_probe(probe))
}

fn run_probe(probe: Probe) -> RemainingCoreExecution {
    let (expected, observed) = match probe {
        Probe::LazySearch => (b"true,false".to_vec(), lazy_search()?.into_bytes()),
        Probe::Dates => (
            b"1865-04-14,1881-07-02,1901-09-06,1963-11-22".to_vec(),
            dates()?.into_bytes(),
        ),
        Probe::EmptyIteration => (
            b"0-0,4-4|0-0,1-1,2-2,3-3,4-4".to_vec(),
            empty_iteration()?.into_bytes(),
        ),
        Probe::ConstructorErrors { text } => (
            b"true,true,true".to_vec(),
            constructor_errors(text).into_bytes(),
        ),
        Probe::NamedCapture => (b"J".to_vec(), named_capture()?.into_bytes()),
        Probe::ContextCapture => (b"chew|false".to_vec(), context_capture()?.into_bytes()),
        Probe::AlternativeCapture => (b"foo,bar".to_vec(), alternative_capture()?.into_bytes()),
        Probe::CaptureExpand => (b"year=2010, month=03, day=14".to_vec(), capture_expand()?),
        Probe::Shortest { text, contextual } => {
            let expected = if contextual { "4|_" } else { "1" };
            (
                expected.as_bytes().to_vec(),
                shortest(text, contextual)?.into_bytes(),
            )
        }
    };
    Ok((expected, observed))
}

fn build(pattern: &str) -> Result<fre::PortableRegex, RemainingCoreRefusal> {
    PortableBuilder::new(pattern)
        .profile(RustProfile::regex_1_12_4())
        .build()
        .map_err(|_| RemainingCoreRefusal::Unsupported("doctest.remaining-build-refused"))
}

fn lazy_search() -> Result<String, RemainingCoreRefusal> {
    let regex = build("...")?;
    let first = regex
        .is_match(b"abc", SearchLimits::unlimited())
        .map_err(|_| RemainingCoreRefusal::Unsupported("doctest.remaining-search-refused"))?
        .0;
    let second = regex
        .is_match(b"ac", SearchLimits::unlimited())
        .map_err(|_| RemainingCoreRefusal::Unsupported("doctest.remaining-search-refused"))?
        .0;
    Ok(format!("{first},{second}"))
}

fn dates() -> Result<String, RemainingCoreRefusal> {
    let regex = build(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")?;
    let haystack = b"What do 1865-04-14, 1881-07-02, 1901-09-06 and 1963-11-22 have in common?";
    regex
        .find_iter(haystack, PortableFindIterLimits::unlimited())
        .map_err(|_| RemainingCoreRefusal::Unsupported("doctest.remaining-iteration-refused"))?
        .map(|result| {
            let matched = result.map_err(|_| {
                RemainingCoreRefusal::Unsupported("doctest.remaining-search-refused")
            })?;
            let bytes =
                haystack
                    .get(matched.start()..matched.end())
                    .ok_or(RemainingCoreRefusal::Fault(
                        "doctest.remaining-span-invalid",
                    ))?;
            std::str::from_utf8(bytes)
                .map(str::to_owned)
                .map_err(|_| RemainingCoreRefusal::Fault("doctest.remaining-utf8-invalid"))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|matches| matches.join(","))
}

fn empty_iteration() -> Result<String, RemainingCoreRefusal> {
    let haystack = "💩";
    let text = PortableTextBuilder::new("")
        .build()
        .map_err(|_| RemainingCoreRefusal::Unsupported("doctest.remaining-text-build-refused"))?;
    let text_ranges = text
        .find_iter(haystack, PortableFindIterLimits::unlimited())
        .map_err(|_| RemainingCoreRefusal::Unsupported("doctest.remaining-iteration-refused"))?
        .map(|result| {
            result
                .map(|matched| format!("{}-{}", matched.start(), matched.end()))
                .map_err(|_| RemainingCoreRefusal::Unsupported("doctest.remaining-search-refused"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let bytes = build("")?;
    let byte_ranges = bytes
        .find_iter(haystack.as_bytes(), PortableFindIterLimits::unlimited())
        .map_err(|_| RemainingCoreRefusal::Unsupported("doctest.remaining-iteration-refused"))?
        .map(|result| {
            result
                .map(|matched| format!("{}-{}", matched.start(), matched.end()))
                .map_err(|_| RemainingCoreRefusal::Unsupported("doctest.remaining-search-refused"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(format!(
        "{}|{}",
        text_ranges.join(","),
        byte_ranges.join(",")
    ))
}

fn constructor_errors(text: bool) -> String {
    let (invalid, unicode_large, ascii_large) = if text {
        (
            PortableTextBuilder::new(r"foo(bar").build().is_err(),
            PortableTextBuilder::new(r"\w{1000}").build().is_err(),
            PortableTextBuilder::new(r"(?-u:\w){1000}").build().is_ok(),
        )
    } else {
        (
            PortableBuilder::new(r"foo(bar").build().is_err(),
            PortableBuilder::new(r"\w{1000}").build().is_err(),
            PortableBuilder::new(r"(?-u:\w){1000}").build().is_ok(),
        )
    };
    format!("{invalid},{unicode_large},{ascii_large}")
}

fn named_capture() -> Result<String, RemainingCoreRefusal> {
    let regex = PortableTextCaptureBuilder::new(r"Homer (?<middle>.)\. Simpson")
        .profile(RustProfile::regex_1_12_4())
        .build()
        .map_err(|_| {
            RemainingCoreRefusal::Unsupported("doctest.remaining-capture-build-refused")
        })?;
    let (captures, _) = regex
        .captures("Homer J. Simpson", CaptureSearchLimits::default())
        .map_err(|_| RemainingCoreRefusal::Unsupported("doctest.remaining-capture-refused"))?;
    captures
        .and_then(|captures| captures.name("middle"))
        .map(fre::PortableTextCaptureMatch::as_str)
        .map(str::to_owned)
        .ok_or(RemainingCoreRefusal::Fault(
            "doctest.remaining-capture-missing",
        ))
}

fn context_capture() -> Result<String, RemainingCoreRefusal> {
    let pattern = r"\bchew\b";
    let haystack = "eschew";
    let captures = PortableTextCaptureBuilder::new(pattern)
        .profile(RustProfile::regex_1_12_4())
        .build()
        .map_err(|_| {
            RemainingCoreRefusal::Unsupported("doctest.remaining-capture-build-refused")
        })?;
    let (sliced, _) = captures
        .captures(&haystack[2..], CaptureSearchLimits::default())
        .map_err(|_| RemainingCoreRefusal::Unsupported("doctest.remaining-capture-refused"))?;
    let sliced = sliced
        .and_then(|captures| captures.get(0))
        .map(fre::PortableTextCaptureMatch::as_str)
        .ok_or(RemainingCoreRefusal::Fault(
            "doctest.remaining-capture-missing",
        ))?;
    let contextual = PortableTextBuilder::new(pattern)
        .build()
        .map_err(|_| RemainingCoreRefusal::Unsupported("doctest.remaining-text-build-refused"))?
        .find_window(
            haystack,
            SearchWindow::new(2, haystack.len()),
            SearchLimits::unlimited(),
        )
        .map_err(|_| RemainingCoreRefusal::Unsupported("doctest.remaining-search-refused"))?
        .0
        .is_some();
    Ok(format!("{sliced}|{contextual}"))
}

fn alternative_capture() -> Result<String, RemainingCoreRefusal> {
    let pattern = r#"id:(?:"([^"]+)"|'([^']+)')"#;
    let haystack = r#"The first is id:"foo" and the second is id:'bar'."#;
    let regex = PortableTextCaptureBuilder::new(pattern)
        .profile(RustProfile::regex_1_12_4())
        .build()
        .map_err(|_| {
            RemainingCoreRefusal::Unsupported("doctest.remaining-capture-build-refused")
        })?;
    regex
        .captures_iter(haystack, fre::CaptureAggregateLimits::default())
        .map_err(|_| RemainingCoreRefusal::Unsupported("doctest.remaining-capture-refused"))?
        .captures
        .into_iter()
        .map(|record| {
            let values = [1_usize, 2]
                .into_iter()
                .filter_map(|index| record.groups.get(index).and_then(|group| group.span))
                .map(|span| {
                    haystack
                        .get(span.start..span.end)
                        .ok_or(RemainingCoreRefusal::Fault(
                            "doctest.remaining-span-invalid",
                        ))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if values.len() != 1 {
                return Err(RemainingCoreRefusal::Fault(
                    "doctest.remaining-capture-participation-invalid",
                ));
            }
            Ok(values[0].to_owned())
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|values| values.join(","))
}

fn capture_expand() -> Result<Vec<u8>, RemainingCoreRefusal> {
    let pattern = r"(?<day>[0-9]{2})-(?<month>[0-9]{2})-(?<year>[0-9]{4})";
    let haystack = "On 14-03-2010, I became a Tennessee lamb.";
    let regex = PortableTextCaptureBuilder::new(pattern)
        .profile(RustProfile::regex_1_12_4())
        .build()
        .map_err(|_| {
            RemainingCoreRefusal::Unsupported("doctest.remaining-capture-build-refused")
        })?;
    let (captures, _) = regex
        .captures(haystack, CaptureSearchLimits::default())
        .map_err(|_| RemainingCoreRefusal::Unsupported("doctest.remaining-capture-refused"))?;
    let captures = captures.ok_or(RemainingCoreRefusal::Fault(
        "doctest.remaining-capture-missing",
    ))?;
    let values = (0..captures.len())
        .map(|index| {
            captures
                .get(index)
                .map(|matched| matched.as_str().as_bytes())
        })
        .collect::<Vec<_>>();
    build(pattern)?
        .expand_capture_template(
            &values,
            b"year=$year, month=$month, day=$day",
            CaptureExpansionLimits::default(),
        )
        .map(fre::CaptureExpansionResult::into_bytes)
        .map_err(|_| RemainingCoreRefusal::Unsupported("doctest.remaining-expansion-refused"))
}

fn shortest(text: bool, contextual: bool) -> Result<String, RemainingCoreRefusal> {
    let (pattern, haystack, start) = if contextual {
        (r"\bchew\b", b"eschew".as_slice(), 2_usize)
    } else {
        (r"a+", b"aaaaa".as_slice(), 0_usize)
    };
    if text {
        PortableTextBuilder::new(pattern).build().map_err(|_| {
            RemainingCoreRefusal::Unsupported("doctest.remaining-text-build-refused")
        })?;
    }
    let regex = build(pattern)?;
    let sliced = regex
        .shortest_match(&haystack[start..], SearchLimits::unlimited())
        .map_err(|_| RemainingCoreRefusal::Unsupported("doctest.remaining-search-refused"))?
        .0;
    if !contextual {
        return Ok(sliced.map_or_else(|| "_".to_owned(), |offset| offset.to_string()));
    }
    let contextual = regex
        .shortest_match_at(haystack, start, SearchLimits::unlimited())
        .map_err(|_| RemainingCoreRefusal::Unsupported("doctest.remaining-search-refused"))?
        .0;
    Ok(format!(
        "{}|{}",
        sliced.map_or_else(|| "_".to_owned(), |offset| offset.to_string()),
        contextual.map_or_else(|| "_".to_owned(), |offset| offset.to_string())
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_remaining_core_probe_matches() {
        let ids = [
            "README.md:89",
            "src/lib.rs:197",
            "src/lib.rs:253",
            "src/lib.rs:481",
            "src/lib.rs:746",
            "src/regex/bytes.rs:166",
            "src/regex/bytes.rs:1003",
            "src/regex/bytes.rs:1035",
            "src/regex/string.rs:168",
            "src/regex/string.rs:990",
            "src/regex/string.rs:1022",
            "src/regex/string.rs:1133",
            "src/regex/string.rs:1804",
            "src/regex/string.rs:1870",
        ];
        for id in ids {
            let (expected, observed) = execute_remaining_core_doctest(id)
                .unwrap_or_else(|| panic!("missing probe for {id}"))
                .unwrap_or_else(|error| panic!("probe refused for {id}: {error:?}"));
            assert_eq!(expected, observed, "probe mismatch for {id}");
        }
    }
}
