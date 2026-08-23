//! Command-line contract for the job-specialized runner.

/// Parsed runner arguments.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Arguments {
    pub quiet: bool,
    pub version: bool,
    pub provenance: bool,
    /// Expected scalar selected by the authenticated external schedule.
    pub expected_value: Option<u64>,
}

/// Parse arguments after the executable name.
pub fn parse<I, S>(arguments: I) -> Result<Arguments, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut parsed = Arguments::default();
    for argument in arguments {
        let argument = argument.as_ref();
        match argument {
            "--quiet" | "-q" => parsed.quiet = true,
            "--version" => parsed.version = true,
            "--provenance" => parsed.provenance = true,
            "--help" | "-h" => return Err(usage().to_owned()),
            other => {
                let Some(value) = other.strip_prefix("--expected-value=") else {
                    return Err(format!("unrecognized argument {other:?}"));
                };
                if parsed.expected_value.is_some() {
                    return Err("--expected-value may be supplied only once".to_owned());
                }
                if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(format!(
                        "invalid --expected-value {value:?}; expected an unsigned decimal u64"
                    ));
                }
                parsed.expected_value = Some(value.parse::<u64>().map_err(|_| {
                    format!("invalid --expected-value {value:?}; expected an unsigned decimal u64")
                })?);
            }
        }
    }
    if parsed.version && parsed.provenance {
        return Err("--version and --provenance are mutually exclusive".to_owned());
    }
    if parsed.expected_value.is_some() && (parsed.version || parsed.provenance) {
        return Err(
            "--expected-value is valid only for benchmark execution, not metadata queries"
                .to_owned(),
        );
    }
    Ok(parsed)
}

/// Stable usage text shared by parser errors and tests.
#[must_use]
pub const fn usage() -> &'static str {
    "usage: fre-aot-rebar-runner [--quiet] [--expected-value=<u64>] [--version | --provenance]"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected_value_is_optional_and_accepts_the_complete_u64_domain() {
        assert_eq!(parse([] as [&str; 0]), Ok(Arguments::default()));
        assert_eq!(
            parse(["--quiet", "--expected-value=18446744073709551615"]),
            Ok(Arguments {
                quiet: true,
                expected_value: Some(u64::MAX),
                ..Arguments::default()
            })
        );
    }

    #[test]
    fn expected_value_rejects_duplicate_malformed_and_overflowing_values() {
        for arguments in [
            vec!["--expected-value=1", "--expected-value=1"],
            vec!["--expected-value="],
            vec!["--expected-value=-1"],
            vec!["--expected-value=1x"],
            vec!["--expected-value=18446744073709551616"],
        ] {
            assert!(parse(arguments).is_err());
        }
    }

    #[test]
    fn expected_value_cannot_be_attached_to_metadata_queries() {
        assert!(parse(["--version", "--expected-value=1"]).is_err());
        assert!(parse(["--provenance", "--expected-value=1"]).is_err());
        assert!(parse(["--version", "--provenance"]).is_err());
    }

    #[test]
    fn unknown_and_help_arguments_fail_without_becoming_execution_requests() {
        assert_eq!(parse(["--help"]), Err(usage().to_owned()));
        assert!(parse(["--expected-value", "1"]).is_err());
        assert!(parse(["--unknown"]).is_err());
    }
}
