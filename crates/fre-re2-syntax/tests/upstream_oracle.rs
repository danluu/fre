//! Opt-in differential test against the separately built pinned C++ oracle.

use fre_re2_syntax::{
    Encoding, Options, ParseErrorCode, ParseLimits, ParseOutcome, SyntaxMode, parse,
};
use std::process::Command;

#[derive(Clone, Copy)]
struct Case {
    pattern: &'static [u8],
    haystack: &'static [u8],
    options: Options,
    expected_match: Option<bool>,
    expected_spans: &'static str,
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0F)]));
    }
    if encoded.is_empty() {
        "-".to_owned()
    } else {
        encoded
    }
}

fn error_arg_hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        String::new()
    } else {
        hex(bytes)
    }
}

fn oracle_flags(options: Options) -> String {
    let mut flags = Vec::new();
    if options.literal {
        flags.push("literal");
    }
    if options.longest_match {
        flags.push("longest");
    }
    if options.never_nl {
        flags.push("never_nl");
    }
    if options.dot_nl {
        flags.push("dot_nl");
    }
    if options.never_capture {
        flags.push("never_capture");
    }
    if !options.case_sensitive {
        flags.push("insensitive");
    }
    if options.perl_classes {
        flags.push("perl_classes");
    }
    if options.word_boundary {
        flags.push("word_boundary");
    }
    if options.one_line {
        flags.push("one_line");
    }
    if flags.is_empty() {
        "-".to_owned()
    } else {
        flags.join(",")
    }
}

fn public_error_number(code: ParseErrorCode) -> u8 {
    match code {
        ParseErrorCode::Internal => 1,
        ParseErrorCode::BadEscape => 2,
        ParseErrorCode::BadCharClass => 3,
        ParseErrorCode::BadCharRange => 4,
        ParseErrorCode::MissingBracket => 5,
        ParseErrorCode::MissingParen => 6,
        ParseErrorCode::UnexpectedParen => 7,
        ParseErrorCode::TrailingBackslash => 8,
        ParseErrorCode::RepeatArgument => 9,
        ParseErrorCode::RepeatSize => 10,
        ParseErrorCode::RepeatOp => 11,
        ParseErrorCode::BadPerlOp => 12,
        ParseErrorCode::BadUtf8 => 13,
        ParseErrorCode::BadNamedCapture => 14,
        ParseErrorCode::PatternTooLarge => 15,
    }
}

#[test]
#[ignore = "requires FRE_RE2_ORACLE built from pinned RE2 plus Abseil"]
#[allow(
    clippy::too_many_lines,
    reason = "the option/diagnostic matrix is intentionally visible in one differential test"
)]
fn pinned_constructor_diagnostics_and_match_receipts() {
    let oracle = std::env::var_os("FRE_RE2_ORACLE")
        .expect("set FRE_RE2_ORACLE to research/re2-syntax/oracle build output");
    let cases = [
        Case {
            pattern: b"a",
            haystack: b"za",
            options: Options::default(),
            expected_match: Some(true),
            expected_spans: "1:2",
        },
        Case {
            pattern: b"(a)",
            haystack: b"za",
            options: Options::default(),
            expected_match: Some(true),
            expected_spans: "1:2,1:2",
        },
        Case {
            pattern: b"(?P<name>a)",
            haystack: b"za",
            options: Options::default(),
            expected_match: Some(true),
            expected_spans: "1:2,1:2",
        },
        Case {
            pattern: b"a++",
            haystack: b"aaa",
            options: Options::posix(),
            expected_match: Some(true),
            expected_spans: "0:3",
        },
        Case {
            pattern: br"\p{Han}",
            haystack: "一".as_bytes(),
            options: Options::default(),
            expected_match: Some(true),
            expected_spans: "0:3",
        },
        Case {
            pattern: &[0xFF],
            haystack: &[0xFF],
            options: Options::latin1(),
            expected_match: Some(true),
            expected_spans: "0:1",
        },
        Case {
            pattern: b"(a)",
            haystack: b"a",
            options: Options {
                never_capture: true,
                ..Options::default()
            },
            expected_match: Some(true),
            expected_spans: "0:1",
        },
        Case {
            pattern: b"a++",
            haystack: b"",
            options: Options::default(),
            expected_match: None,
            expected_spans: "",
        },
        Case {
            pattern: b"[z-a]",
            haystack: b"",
            options: Options::default(),
            expected_match: None,
            expected_spans: "",
        },
        Case {
            pattern: &[0xFF],
            haystack: b"",
            options: Options::default(),
            expected_match: None,
            expected_spans: "",
        },
        Case {
            pattern: b"(?:a)",
            haystack: b"",
            options: Options::posix(),
            expected_match: None,
            expected_spans: "",
        },
    ];

    for case in cases {
        let syntax = match case.options.syntax {
            SyntaxMode::Perl => "perl",
            SyntaxMode::Posix => "posix",
        };
        let encoding = match case.options.encoding {
            Encoding::Utf8 => "utf8",
            Encoding::Latin1 => "latin1",
        };
        let output = Command::new(&oracle)
            .args([
                hex(case.pattern),
                hex(case.haystack),
                syntax.to_owned(),
                encoding.to_owned(),
                oracle_flags(case.options),
            ])
            .output()
            .expect("run pinned RE2 oracle");
        assert!(
            output.status.success(),
            "oracle stderr: {:?}",
            output.stderr
        );
        let stdout = String::from_utf8(output.stdout).expect("oracle output is ASCII TSV");
        let record = stdout.trim_end_matches('\n').trim_end_matches('\r');
        let fields: Vec<_> = record.split('\t').collect();
        assert_eq!(fields.len(), 10, "oracle record: {stdout:?}");
        assert_eq!(fields[0], "fre.re2-oracle.v1");
        assert_eq!(fields[1], fre_re2_syntax::RE2_SOURCE_REVISION);

        match parse(case.pattern, case.options, ParseLimits::default()) {
            ParseOutcome::Parsed { ast, .. } => {
                assert_eq!(fields[2], "1", "pattern: {:?}", case.pattern);
                assert_eq!(fields[6].parse::<u32>().ok(), Some(ast.capture_count));
            }
            ParseOutcome::Rejected(error) => {
                assert_eq!(fields[2], "0", "pattern: {:?}", case.pattern);
                assert_eq!(
                    fields[3].parse::<u8>().ok(),
                    Some(public_error_number(error.code))
                );
                assert_eq!(fields[4], error_arg_hex(&error.argument_bytes));
            }
            ParseOutcome::NotYetImplemented(_) => continue,
        }
        if let Some(expected_match) = case.expected_match {
            assert_eq!(fields[8], if expected_match { "1" } else { "0" });
            assert_eq!(fields[9], case.expected_spans);
        }
    }
}

fn decode_hex(encoded: &str) -> Vec<u8> {
    if encoded == "-" {
        return Vec::new();
    }
    assert_eq!(encoded.len() % 2, 0, "fixture hex must have byte pairs");
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = core::str::from_utf8(pair).unwrap();
            u8::from_str_radix(pair, 16).unwrap()
        })
        .collect()
}

fn fixture_options(syntax: &str, encoding: &str, flags: &str) -> Options {
    let mut options = Options {
        syntax: match syntax {
            "perl" => SyntaxMode::Perl,
            "posix" => SyntaxMode::Posix,
            other => panic!("unknown fixture syntax {other:?}"),
        },
        encoding: match encoding {
            "utf8" => Encoding::Utf8,
            "latin1" => Encoding::Latin1,
            other => panic!("unknown fixture encoding {other:?}"),
        },
        ..Options::default()
    };
    if flags != "-" {
        for flag in flags.split(',') {
            match flag {
                "longest" => options.longest_match = true,
                "literal" => options.literal = true,
                "never_nl" => options.never_nl = true,
                "dot_nl" => options.dot_nl = true,
                "never_capture" => options.never_capture = true,
                "insensitive" => options.case_sensitive = false,
                "perl_classes" => options.perl_classes = true,
                "word_boundary" => options.word_boundary = true,
                "one_line" => options.one_line = true,
                other => panic!("unknown fixture option {other:?}"),
            }
        }
    }
    options
}

#[test]
#[ignore = "requires FRE_RE2_ORACLE built from pinned RE2 plus Abseil"]
fn pinned_source_fixture_constructors_match_the_oracle() {
    let oracle = std::env::var_os("FRE_RE2_ORACLE")
        .expect("set FRE_RE2_ORACLE to research/re2-syntax/oracle build output");
    let fixtures = include_str!("../../../research/re2-syntax/fixtures.tsv");
    let mut compared = 0_usize;
    for line in fixtures.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 7, "fixture record: {line:?}");
        let label = fields[0];
        let pattern = decode_hex(fields[4]);
        let haystack = decode_hex(fields[5]);
        let expected_ok = match fields[6] {
            "construct-ok" => true,
            "construct-error" => false,
            other => panic!("unknown fixture expectation {other:?}"),
        };
        let options = fixture_options(fields[1], fields[2], fields[3]);
        let output = Command::new(&oracle)
            .args([
                hex(&pattern),
                hex(&haystack),
                fields[1].to_owned(),
                fields[2].to_owned(),
                oracle_flags(options),
            ])
            .output()
            .expect("run pinned RE2 oracle for source fixture");
        assert!(
            output.status.success(),
            "label={label:?}, stderr={:?}",
            output.stderr
        );
        let stdout = String::from_utf8(output.stdout).expect("oracle output is ASCII TSV");
        let record = stdout.trim_end_matches(['\n', '\r']);
        let oracle_fields: Vec<_> = record.split('\t').collect();
        assert_eq!(
            oracle_fields.len(),
            10,
            "label={label:?}, record={stdout:?}"
        );
        assert_eq!(oracle_fields[0], "fre.re2-oracle.v1");
        assert_eq!(oracle_fields[1], fre_re2_syntax::RE2_SOURCE_REVISION);
        assert_eq!(oracle_fields[2] == "1", expected_ok, "label={label:?}");
        match parse(&pattern, options, ParseLimits::default()) {
            ParseOutcome::Parsed { ast, .. } => {
                assert_eq!(oracle_fields[2], "1", "label={label:?}");
                assert_eq!(
                    oracle_fields[6].parse::<u32>().ok(),
                    Some(ast.capture_count),
                    "label={label:?}"
                );
            }
            ParseOutcome::Rejected(error) => {
                assert_eq!(oracle_fields[2], "0", "label={label:?}");
                assert_eq!(
                    oracle_fields[3].parse::<u8>().ok(),
                    Some(public_error_number(error.code)),
                    "label={label:?}"
                );
                assert_eq!(
                    oracle_fields[4],
                    error_arg_hex(&error.argument_bytes),
                    "label={label:?}"
                );
            }
            ParseOutcome::NotYetImplemented(reason) => {
                panic!("fixture {label:?} remained unimplemented: {reason:?}");
            }
        }
        compared = compared.checked_add(1).unwrap();
    }
    assert_eq!(compared, 34);
}
