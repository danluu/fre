//! Executable adapters for pinned arbitrary-byte capture doctests.

use fre::{
    CaptureAggregateLimits, CaptureBuilder, CaptureExpansionLimits, PortableBuilder, RustProfile,
    SearchLimits, SearchWindow,
};

#[derive(Clone, Copy, Debug)]
pub(crate) enum ByteCaptureRefusal {
    Unsupported(&'static str),
    Fault(&'static str),
}

pub(crate) type ByteCaptureExecution = Result<(Vec<u8>, Vec<u8>), ByteCaptureRefusal>;

#[derive(Clone, Copy)]
enum Selector {
    Index(usize),
    Name(&'static str),
}

#[derive(Clone, Copy)]
enum ByteCaptureProbe {
    Select {
        pattern: &'static str,
        haystack: &'static [u8],
        selectors: &'static [Selector],
        all: bool,
        expected: &'static str,
    },
    Context,
    FirstParticipating {
        pattern: &'static str,
        haystack: &'static [u8],
        alternatives: &'static [usize],
        expected: &'static str,
    },
    Expand {
        pattern: &'static str,
        haystack: &'static [u8],
        template: &'static [u8],
        expected: &'static [u8],
    },
    Len {
        pattern: &'static str,
        haystack: &'static [u8],
        expected: usize,
    },
}

const CSTR_PATTERN: &str = r"(?-u)(?<cstr>[^\x00]+)\x00";
const MOVIE_PATTERN: &str = r"'([^']+)'\s+\(([0-9]{4})\)";
const NAMED_MOVIE_PATTERN: &str = r"'(?<title>[^']+)'\s+\((?<year>[0-9]{4})\)";
const MOVIES: &[u8] = b"'Citizen Kane' (1941), 'The Wizard of Oz' (1939), 'M' (1931).";
const DATE_PATTERN: &str = r"([0-9]{4})-([0-9]{2})-([0-9]{2})";

/// Execute one authenticated byte-capture example handled by this adapter.
#[allow(
    clippy::too_many_lines,
    reason = "the fixed source-line table keeps every byte-capture obligation auditable"
)]
pub(crate) fn execute_byte_capture_doctest(case_id: &str) -> Option<ByteCaptureExecution> {
    let probe = match case_id {
        "README.md:127" => ByteCaptureProbe::Select {
            pattern: CSTR_PATTERN,
            haystack: b"foo\xFFbar\x00baz\x00",
            selectors: &[Selector::Name("cstr")],
            all: true,
            expected: "666f6fff626172,62617a",
        },
        "src/bytes.rs:17" => ByteCaptureProbe::Select {
            pattern: CSTR_PATTERN,
            haystack: b"foo\x00qu\xFFux\x00baz\x00",
            selectors: &[Selector::Name("cstr")],
            all: true,
            expected: "666f6f,7175ff7578,62617a",
        },
        "src/bytes.rs:37" => ByteCaptureProbe::Select {
            pattern: r"(?-u)\x7b\xa9(?:[\x80-\xfe]|[\x40-\xff].)(?u:(.*))",
            haystack: b"\x12\xd0\x3b\x5f\x7b\xa9\x85\xe2\x98\x83\x80\x98\x54\x76\x68\x65",
            selectors: &[Selector::Index(1)],
            all: false,
            expected: "e29883",
        },
        "src/regex/bytes.rs:48" => ByteCaptureProbe::Select {
            pattern: r"(?m)^\s*(\S+)\s+([0-9]+)\s+(true|false)\s*$",
            haystack:
                b"\nrabbit         54 true\ngroundhog 2 true\ndoes not match\nfox   109    false\n",
            selectors: &[Selector::Index(1), Selector::Index(2), Selector::Index(3)],
            all: true,
            expected: "726162626974|3534|74727565,67726f756e64686f67|32|74727565,666f78|313039|66616c7365",
        },
        "src/regex/bytes.rs:87" => ByteCaptureProbe::Select {
            pattern: r"(?s)(?-u:.)*?(?<f1>.+)(?-u:.)*?(?<f2>.+)",
            haystack: b"\xFF\xFFfoo\xFF\xFF\xFF\xF0\x9F\x92\xA9\xFF",
            selectors: &[Selector::Name("f1"), Selector::Name("f2")],
            all: false,
            expected: "666f6f|f09f92a9",
        },
        "src/regex/bytes.rs:290" | "src/regex/bytes.rs:342" => ByteCaptureProbe::Select {
            pattern: r"'([^']+)'\s+\((\d{4})\)",
            haystack: b"Not my favorite movie: 'Citizen Kane' (1941).",
            selectors: &[Selector::Index(0), Selector::Index(1), Selector::Index(2)],
            all: false,
            expected: "27436974697a656e204b616e652720283139343129|436974697a656e204b616e65|31393431",
        },
        "src/regex/bytes.rs:313" => ByteCaptureProbe::Select {
            pattern: r"'(?<title>[^']+)'\s+\((?<year>\d{4})\)",
            haystack: b"Not my favorite movie: 'Citizen Kane' (1941).",
            selectors: &[
                Selector::Index(0),
                Selector::Name("title"),
                Selector::Name("year"),
            ],
            all: false,
            expected: "27436974697a656e204b616e652720283139343129|436974697a656e204b616e65|31393431",
        },
        "src/regex/bytes.rs:379" => ByteCaptureProbe::Select {
            pattern: MOVIE_PATTERN,
            haystack: MOVIES,
            selectors: &[Selector::Index(1), Selector::Index(2)],
            all: true,
            expected: "436974697a656e204b616e65|31393431,5468652057697a617264206f66204f7a|31393339,4d|31393331",
        },
        "src/regex/bytes.rs:400" => ByteCaptureProbe::Select {
            pattern: NAMED_MOVIE_PATTERN,
            haystack: MOVIES,
            selectors: &[Selector::Name("title"), Selector::Name("year")],
            all: true,
            expected: "436974697a656e204b616e65|31393431,5468652057697a617264206f66204f7a|31393339,4d|31393331",
        },
        "src/regex/bytes.rs:1142" => ByteCaptureProbe::Context,
        "src/regex/bytes.rs:1622" => ByteCaptureProbe::Select {
            pattern: r"(?<first>\w)(\w)(?:\w)\w(?<last>\w)",
            haystack: b"toady",
            selectors: &[
                Selector::Index(0),
                Selector::Name("first"),
                Selector::Index(2),
                Selector::Name("last"),
            ],
            all: false,
            expected: "746f616479|74|6f|79",
        },
        "src/regex/bytes.rs:1650" => ByteCaptureProbe::Select {
            pattern: r"[a-z]+(?:([0-9]+)|([A-Z]+))",
            haystack: b"abc123",
            selectors: &[Selector::Index(1), Selector::Index(2)],
            all: false,
            expected: "313233|",
        },
        "src/regex/bytes.rs:1675" => ByteCaptureProbe::Select {
            pattern: r"[a-z]+([0-9]+)",
            haystack: b"   abc123-def",
            selectors: &[Selector::Index(0)],
            all: false,
            expected: "616263313233",
        },
        "src/regex/bytes.rs:1704" => ByteCaptureProbe::Select {
            pattern: r"[a-z]+(?:(?<numbers>[0-9]+)|(?<letters>[A-Z]+))",
            haystack: b"abc123",
            selectors: &[Selector::Name("numbers"), Selector::Name("letters")],
            all: false,
            expected: "313233|",
        },
        "src/regex/bytes.rs:1752" => ByteCaptureProbe::Select {
            pattern: DATE_PATTERN,
            haystack: b"On 2010-03-14, I became a Tennessee lamb.",
            selectors: &[
                Selector::Index(0),
                Selector::Index(1),
                Selector::Index(2),
                Selector::Index(3),
            ],
            all: false,
            expected: "323031302d30332d3134|32303130|3033|3134",
        },
        "src/regex/bytes.rs:1770" => ByteCaptureProbe::Select {
            pattern: DATE_PATTERN,
            haystack: b"1973-01-05, 1975-08-25 and 1980-10-18",
            selectors: &[Selector::Index(1), Selector::Index(2), Selector::Index(3)],
            all: true,
            expected: "31393733|3031|3035,31393735|3038|3235,31393830|3130|3138",
        },
        "src/regex/bytes.rs:1793" => ByteCaptureProbe::FirstParticipating {
            pattern: r#"id:(?:"([^"]+)"|'([^']+)')"#,
            haystack: br#"The first is id:"foo" and the second is id:'bar'."#,
            alternatives: &[1, 2],
            expected: "666f6f,626172",
        },
        "src/regex/bytes.rs:1859" => ByteCaptureProbe::Expand {
            pattern: r"(?<day>[0-9]{2})-(?<month>[0-9]{2})-(?<year>[0-9]{4})",
            haystack: b"On 14-03-2010, I became a Tennessee lamb.",
            template: b"year=$year, month=$month, day=$day",
            expected: b"year=2010, month=03, day=14",
        },
        "src/regex/bytes.rs:1889" => ByteCaptureProbe::Select {
            pattern: r"(\w)(\d)?(\w)",
            haystack: b"AZ",
            selectors: &[
                Selector::Index(0),
                Selector::Index(1),
                Selector::Index(2),
                Selector::Index(3),
            ],
            all: false,
            expected: "415a|41||5a",
        },
        "src/regex/bytes.rs:1917" => ByteCaptureProbe::Len {
            pattern: r"(\w)(\d)?(\w)",
            haystack: b"AZ",
            expected: 4,
        },
        _ => return None,
    };
    Some(run_probe(probe))
}

fn run_probe(probe: ByteCaptureProbe) -> ByteCaptureExecution {
    match probe {
        ByteCaptureProbe::Select {
            pattern,
            haystack,
            selectors,
            all,
            expected,
        } => Ok((
            expected.as_bytes().to_vec(),
            select_captures(pattern, haystack, selectors, all)?.into_bytes(),
        )),
        ByteCaptureProbe::Context => Ok((b"63686577|_".to_vec(), context_capture()?.into_bytes())),
        ByteCaptureProbe::FirstParticipating {
            pattern,
            haystack,
            alternatives,
            expected,
        } => Ok((
            expected.as_bytes().to_vec(),
            first_participating(pattern, haystack, alternatives)?.into_bytes(),
        )),
        ByteCaptureProbe::Expand {
            pattern,
            haystack,
            template,
            expected,
        } => Ok((
            expected.to_vec(),
            expand_capture(pattern, haystack, template)?,
        )),
        ByteCaptureProbe::Len {
            pattern,
            haystack,
            expected,
        } => Ok((
            expected.to_string().into_bytes(),
            capture_len(pattern, haystack)?.to_string().into_bytes(),
        )),
    }
}

fn select_captures(
    pattern: &str,
    haystack: &[u8],
    selectors: &[Selector],
    all: bool,
) -> Result<String, ByteCaptureRefusal> {
    let report = capture_regex(pattern)?
        .captures_iter(haystack, CaptureAggregateLimits::default())
        .map_err(|_| ByteCaptureRefusal::Unsupported("doctest.byte-capture-search-refused"))?;
    let records = if all {
        report.captures.as_slice()
    } else {
        report.captures.get(..1).ok_or(ByteCaptureRefusal::Fault(
            "doctest.byte-capture-match-missing",
        ))?
    };
    if records.is_empty() {
        return Err(ByteCaptureRefusal::Fault(
            "doctest.byte-capture-match-missing",
        ));
    }
    records
        .iter()
        .map(|record| {
            selectors
                .iter()
                .map(|selector| {
                    let group = match selector {
                        Selector::Index(index) => record.groups.get(*index),
                        Selector::Name(name) => record
                            .groups
                            .iter()
                            .find(|group| group.name.as_deref() == Some(*name)),
                    }
                    .ok_or(ByteCaptureRefusal::Fault(
                        "doctest.byte-capture-group-missing",
                    ))?;
                    group
                        .span
                        .map(|span| {
                            haystack.get(span.start..span.end).map(hex).ok_or(
                                ByteCaptureRefusal::Fault("doctest.byte-capture-span-invalid"),
                            )
                        })
                        .transpose()
                        .map(Option::unwrap_or_default)
                })
                .collect::<Result<Vec<_>, _>>()
                .map(|groups| groups.join("|"))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|records| records.join(","))
}

fn first_participating(
    pattern: &str,
    haystack: &[u8],
    alternatives: &[usize],
) -> Result<String, ByteCaptureRefusal> {
    let report = capture_regex(pattern)?
        .captures_iter(haystack, CaptureAggregateLimits::default())
        .map_err(|_| ByteCaptureRefusal::Unsupported("doctest.byte-capture-search-refused"))?;
    report
        .captures
        .iter()
        .map(|record| {
            alternatives
                .iter()
                .filter_map(|index| record.groups.get(*index))
                .find_map(|group| group.span)
                .and_then(|span| haystack.get(span.start..span.end))
                .map(hex)
                .ok_or(ByteCaptureRefusal::Fault(
                    "doctest.byte-capture-participating-group-missing",
                ))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|values| values.join(","))
}

fn context_capture() -> Result<String, ByteCaptureRefusal> {
    const PATTERN: &str = r"\bchew\b";
    const HAYSTACK: &[u8] = b"eschew";
    let sliced = select_captures(PATTERN, &HAYSTACK[2..], &[Selector::Index(0)], false)?;
    let contextual = PortableBuilder::new(PATTERN)
        .profile(RustProfile::regex_1_12_4())
        .build()
        .map_err(|_| ByteCaptureRefusal::Unsupported("doctest.byte-capture-build-refused"))?
        .find_window(
            HAYSTACK,
            SearchWindow::new(2, HAYSTACK.len()),
            SearchLimits::unlimited(),
        )
        .map_err(|_| ByteCaptureRefusal::Unsupported("doctest.byte-capture-search-refused"))?
        .0
        .map_or_else(|| "_".to_owned(), |matched| hex(&HAYSTACK[matched.range()]));
    Ok(format!("{sliced}|{contextual}"))
}

fn expand_capture(
    pattern: &str,
    haystack: &[u8],
    template: &[u8],
) -> Result<Vec<u8>, ByteCaptureRefusal> {
    let report = capture_regex(pattern)?
        .captures_iter(haystack, CaptureAggregateLimits::default())
        .map_err(|_| ByteCaptureRefusal::Unsupported("doctest.byte-capture-search-refused"))?;
    let record = report.captures.first().ok_or(ByteCaptureRefusal::Fault(
        "doctest.byte-capture-match-missing",
    ))?;
    let values = record
        .groups
        .iter()
        .enumerate()
        .map(|(expected_index, group)| {
            if usize::try_from(group.index) != Ok(expected_index) {
                return Err(ByteCaptureRefusal::Fault(
                    "doctest.byte-capture-index-invalid",
                ));
            }
            group
                .span
                .map(|span| {
                    haystack
                        .get(span.start..span.end)
                        .ok_or(ByteCaptureRefusal::Fault(
                            "doctest.byte-capture-span-invalid",
                        ))
                })
                .transpose()
        })
        .collect::<Result<Vec<_>, _>>()?;
    PortableBuilder::new(pattern)
        .profile(RustProfile::regex_1_12_4())
        .build()
        .map_err(|_| ByteCaptureRefusal::Unsupported("doctest.byte-capture-build-refused"))?
        .expand_capture_template(&values, template, CaptureExpansionLimits::default())
        .map(fre::CaptureExpansionResult::into_bytes)
        .map_err(|_| ByteCaptureRefusal::Unsupported("doctest.byte-capture-expansion-refused"))
}

fn capture_len(pattern: &str, haystack: &[u8]) -> Result<usize, ByteCaptureRefusal> {
    let report = capture_regex(pattern)?
        .captures_iter(haystack, CaptureAggregateLimits::default())
        .map_err(|_| ByteCaptureRefusal::Unsupported("doctest.byte-capture-search-refused"))?;
    report
        .captures
        .first()
        .map(|record| record.groups.len())
        .ok_or(ByteCaptureRefusal::Fault(
            "doctest.byte-capture-match-missing",
        ))
}

fn capture_regex(pattern: &str) -> Result<fre::CaptureRegex, ByteCaptureRefusal> {
    CaptureBuilder::new(pattern)
        .profile(RustProfile::regex_1_12_4())
        .build()
        .map_err(|_| ByteCaptureRefusal::Unsupported("doctest.byte-capture-build-refused"))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0F)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_byte_capture_probe_matches() {
        const IDS: [&str; 21] = [
            "README.md:127",
            "src/bytes.rs:17",
            "src/bytes.rs:37",
            "src/regex/bytes.rs:48",
            "src/regex/bytes.rs:87",
            "src/regex/bytes.rs:290",
            "src/regex/bytes.rs:313",
            "src/regex/bytes.rs:342",
            "src/regex/bytes.rs:379",
            "src/regex/bytes.rs:400",
            "src/regex/bytes.rs:1142",
            "src/regex/bytes.rs:1622",
            "src/regex/bytes.rs:1650",
            "src/regex/bytes.rs:1675",
            "src/regex/bytes.rs:1704",
            "src/regex/bytes.rs:1752",
            "src/regex/bytes.rs:1770",
            "src/regex/bytes.rs:1793",
            "src/regex/bytes.rs:1859",
            "src/regex/bytes.rs:1889",
            "src/regex/bytes.rs:1917",
        ];
        for id in IDS {
            let (expected, observed) = execute_byte_capture_doctest(id)
                .unwrap_or_else(|| panic!("missing probe {id}"))
                .unwrap_or_else(|error| panic!("probe {id} refused: {error:?}"));
            assert_eq!(expected, observed, "probe {id}");
        }
        assert!(execute_byte_capture_doctest("foreign:1").is_none());
    }
}
