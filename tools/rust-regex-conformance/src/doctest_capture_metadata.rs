//! Executable adapters for pinned capture-location public doctests.

use fre::{
    CaptureBuilder, CaptureSearchLimits, PortableBuilder, RustProfile, SearchLimits, SearchWindow,
};

/// A typed adapter refusal. Unsupported product surface and adapter invariant failures remain
/// distinguishable in the mandatory doctest report.
#[derive(Clone, Copy, Debug)]
pub(crate) enum CaptureMetadataRefusal {
    Unsupported(&'static str),
    Fault(&'static str),
}

pub(crate) type CaptureMetadataExecution = Result<(Vec<u8>, Vec<u8>), CaptureMetadataRefusal>;

#[derive(Clone, Copy)]
enum CaptureMetadataProbe {
    Locations {
        pattern: &'static str,
        haystack: &'static [u8],
        include_invalid: bool,
        expected: &'static str,
    },
    Context,
    StableLen,
    EmptyLen,
}

/// Execute one of the complete pinned capture-location examples handled by this adapter.
pub(crate) fn execute_capture_metadata_doctest(case_id: &str) -> Option<CaptureMetadataExecution> {
    let probe = match case_id {
        "src/regex/string.rs:1183" | "src/regex/bytes.rs:1187" => CaptureMetadataProbe::Locations {
            pattern: r"^([a-z]+)=(\S*)$",
            haystack: b"id=foo123",
            include_invalid: false,
            expected: "0-9,0-2,3-9",
        },
        "src/regex/string.rs:1222" | "src/regex/bytes.rs:1223" => CaptureMetadataProbe::Context,
        "src/regex/string.rs:1410" | "src/regex/bytes.rs:1407" => CaptureMetadataProbe::Locations {
            pattern: r"(.)(.)(\w+)",
            haystack: b"Padron",
            include_invalid: false,
            expected: "0-6,0-1,1-2,2-6",
        },
        "src/regex/string.rs:2073" | "src/regex/bytes.rs:2064" => CaptureMetadataProbe::Locations {
            pattern: r"(?<first>\w+)\s+(?<last>\w+)",
            haystack: b"Bruce Springsteen",
            include_invalid: true,
            expected: "0-17,0-5,6-17,_",
        },
        "src/regex/string.rs:2110" | "src/regex/bytes.rs:2101" => CaptureMetadataProbe::Locations {
            pattern: r"(?<first>\w+)\s+(?<last>\w+)",
            haystack: b"Bruce Springsteen",
            include_invalid: false,
            expected: "0-17,0-5,6-17",
        },
        "src/regex/string.rs:2133" | "src/regex/bytes.rs:2124" => CaptureMetadataProbe::StableLen,
        "src/regex/string.rs:2145" | "src/regex/bytes.rs:2136" => CaptureMetadataProbe::EmptyLen,
        _ => return None,
    };
    Some(run_probe(probe))
}

fn run_probe(probe: CaptureMetadataProbe) -> CaptureMetadataExecution {
    let (expected, observed) = match probe {
        CaptureMetadataProbe::Locations {
            pattern,
            haystack,
            include_invalid,
            expected,
        } => (
            expected.as_bytes().to_vec(),
            capture_locations(pattern, haystack, include_invalid)?.into_bytes(),
        ),
        CaptureMetadataProbe::Context => (
            b"true,false".to_vec(),
            capture_context_probe()?.into_bytes(),
        ),
        CaptureMetadataProbe::StableLen => {
            (b"3,3".to_vec(), stable_capture_len_probe()?.into_bytes())
        }
        CaptureMetadataProbe::EmptyLen => {
            (b"1,1".to_vec(), empty_capture_len_probe()?.into_bytes())
        }
    };
    Ok((expected, observed))
}

fn capture_locations(
    pattern: &str,
    haystack: &[u8],
    include_invalid: bool,
) -> Result<String, CaptureMetadataRefusal> {
    let regex = capture_regex(pattern)?;
    let outcome = regex
        .captures(haystack, CaptureSearchLimits::default())
        .map_err(|_| {
            CaptureMetadataRefusal::Unsupported("doctest.capture-location-search-refused")
        })?;
    let record = outcome.captures.ok_or(CaptureMetadataRefusal::Fault(
        "doctest.capture-location-match-missing",
    ))?;
    let mut locations = Vec::with_capacity(
        record
            .groups
            .len()
            .saturating_add(usize::from(include_invalid)),
    );
    for (expected_index, group) in record.groups.iter().enumerate() {
        if usize::try_from(group.index) != Ok(expected_index) {
            return Err(CaptureMetadataRefusal::Fault(
                "doctest.capture-location-index-invalid",
            ));
        }
        locations.push(group.span.map_or_else(
            || "_".to_owned(),
            |span| format!("{}-{}", span.start, span.end),
        ));
    }
    if include_invalid {
        let invalid = record
            .groups
            .get(record.groups.len())
            .and_then(|group| group.span);
        locations.push(invalid.map_or_else(
            || "_".to_owned(),
            |span| format!("{}-{}", span.start, span.end),
        ));
    }
    Ok(locations.join(","))
}

fn capture_context_probe() -> Result<String, CaptureMetadataRefusal> {
    const PATTERN: &str = r"\bchew\b";
    const HAYSTACK: &[u8] = b"eschew";
    let sliced = capture_regex(PATTERN)?
        .captures(&HAYSTACK[2..], CaptureSearchLimits::default())
        .map_err(|_| {
            CaptureMetadataRefusal::Unsupported("doctest.capture-location-search-refused")
        })?
        .captures
        .is_some();
    let contextual = PortableBuilder::new(PATTERN)
        .profile(RustProfile::regex_1_12_4())
        .build()
        .map_err(|_| CaptureMetadataRefusal::Unsupported("doctest.capture-location-build-refused"))?
        .find_window(
            HAYSTACK,
            SearchWindow::new(2, HAYSTACK.len()),
            SearchLimits::unlimited(),
        )
        .map_err(|_| {
            CaptureMetadataRefusal::Unsupported("doctest.capture-location-search-refused")
        })?
        .0
        .is_some();
    Ok(format!("{sliced},{contextual}"))
}

fn stable_capture_len_probe() -> Result<String, CaptureMetadataRefusal> {
    const PATTERN: &str = r"(?<first>\w+)\s+(?<last>\w+)";
    const HAYSTACK: &[u8] = b"Bruce Springsteen";
    let before = PortableBuilder::new(PATTERN)
        .profile(RustProfile::regex_1_12_4())
        .build()
        .map_err(|_| CaptureMetadataRefusal::Unsupported("doctest.capture-location-build-refused"))?
        .captures_len();
    let regex = capture_regex(PATTERN)?;
    let outcome = regex
        .captures(HAYSTACK, CaptureSearchLimits::default())
        .map_err(|_| {
            CaptureMetadataRefusal::Unsupported("doctest.capture-location-search-refused")
        })?;
    let after = outcome
        .captures
        .ok_or(CaptureMetadataRefusal::Fault(
            "doctest.capture-location-match-missing",
        ))?
        .groups
        .len();
    Ok(format!("{before},{after}"))
}

fn empty_capture_len_probe() -> Result<String, CaptureMetadataRefusal> {
    let mut lengths = Vec::new();
    for pattern in ["", r"[a&&b]"] {
        let regex = PortableBuilder::new(pattern)
            .profile(RustProfile::regex_1_12_4())
            .build()
            .map_err(|_| {
                CaptureMetadataRefusal::Unsupported("doctest.capture-location-build-refused")
            })?;
        lengths.push(regex.captures_len().to_string());
    }
    Ok(lengths.join(","))
}

fn capture_regex(pattern: &str) -> Result<fre::CaptureRegex, CaptureMetadataRefusal> {
    CaptureBuilder::new(pattern)
        .profile(RustProfile::regex_1_12_4())
        .build()
        .map_err(|_| CaptureMetadataRefusal::Unsupported("doctest.capture-location-build-refused"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_capture_metadata_probe_matches() {
        const IDS: [&str; 14] = [
            "src/regex/string.rs:1183",
            "src/regex/bytes.rs:1187",
            "src/regex/string.rs:1222",
            "src/regex/bytes.rs:1223",
            "src/regex/string.rs:1410",
            "src/regex/bytes.rs:1407",
            "src/regex/string.rs:2073",
            "src/regex/bytes.rs:2064",
            "src/regex/string.rs:2110",
            "src/regex/bytes.rs:2101",
            "src/regex/string.rs:2133",
            "src/regex/bytes.rs:2124",
            "src/regex/string.rs:2145",
            "src/regex/bytes.rs:2136",
        ];
        for id in IDS {
            let (expected, observed) = execute_capture_metadata_doctest(id)
                .unwrap_or_else(|| panic!("missing probe {id}"))
                .unwrap_or_else(|error| panic!("probe {id} refused: {error:?}"));
            assert_eq!(expected, observed, "probe {id}");
        }
        assert!(execute_capture_metadata_doctest("foreign:1").is_none());
    }
}
