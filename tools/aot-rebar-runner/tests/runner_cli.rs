use std::{
    io::Write,
    process::{Command, Output, Stdio},
};

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fre-aot-rebar-runner"))
        .args(arguments)
        .output()
        .expect("run unconfigured AOT Rebar runner")
}

fn run_with_input(arguments: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_fre-aot-rebar-runner"))
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn configured AOT Rebar runner");
    child
        .stdin
        .take()
        .expect("runner stdin")
        .write_all(input)
        .expect("write runner KLV");
    child
        .wait_with_output()
        .expect("wait for configured runner")
}

#[test]
fn metadata_queries_reject_expected_values_before_running() {
    let version = run(&["--version"]);
    assert!(version.status.success());

    for query in ["--version", "--provenance"] {
        let output = run(&[query, "--expected-value=1"]);
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("--expected-value is valid only for benchmark execution")
        );
    }
}

#[test]
fn malformed_or_split_expected_values_fail_before_configuration() {
    for arguments in [
        &["--expected-value="][..],
        &["--expected-value=-1"][..],
        &["--expected-value=18446744073709551616"][..],
        &["--expected-value", "1"][..],
        &["--expected-value=1", "--expected-value=1"][..],
    ] {
        let output = run(arguments);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("expected-value"));
    }
}

#[test]
fn valid_expected_value_reaches_the_execution_configuration_gate() {
    let output = run(&["--quiet", "--expected-value=18446744073709551615"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("runner is unconfigured"));
}

#[test]
fn configured_runner_uses_the_authenticated_external_expectation() {
    let (Ok(klv_path), Ok(expected)) = (
        std::env::var("FRE_AOT_REBAR_KLV"),
        std::env::var("FRE_AOT_REBAR_TEST_EXPECTED"),
    ) else {
        return;
    };
    let expected = expected.parse::<u64>().expect("test expected u64");
    let input = std::fs::read(klv_path).expect("read configured runner KLV");
    let expected_argument = format!("--expected-value={expected}");
    let output = run_with_input(&[&expected_argument], &input);
    assert!(
        output.status.success(),
        "externally validated runner failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    for sample in String::from_utf8(output.stdout)
        .expect("ASCII runner samples")
        .lines()
    {
        let (_, actual) = sample.split_once(',').expect("nanoseconds,value sample");
        assert_eq!(actual.parse::<u64>(), Ok(expected));
    }

    let wrong = if expected == u64::MAX {
        expected - 1
    } else {
        expected + 1
    };
    let wrong_argument = format!("--expected-value={wrong}");
    let output = run_with_input(&[&wrong_argument], &input);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("selected-comparator expectation supplied by the authenticated schedule")
    );

    if std::env::var_os("FRE_AOT_REBAR_TEST_REQUIRE_STANDALONE_MISMATCH").is_some() {
        let output = run_with_input(&[], &input);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("standalone Rust Rebar oracle"));
    }
}
