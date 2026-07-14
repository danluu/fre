use std::{fs, path::PathBuf};

use fre_holdout::{
    AuthenticatedSuite, CaseSpec, DigestManifest, DimensionDeclaration, ExecutionMode,
    ExplicitInput, GeneratorSpec, OracleDeclaration, Status, SuiteManifest, TimingEngine,
    TimingPolicy, authenticate_bytes, authenticate_paths, derive_digest_manifest,
    enforce_strict_gate, expand_manifest, run_correctness, run_performance,
};

const RECEIPTS_SHA256: &str = "ae87090ef85bf119f72d27d128a2bf1211c18fd393bd04a848e3990f6246eb67";

fn research_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../research/holdout")
        .join(name)
}

fn committed_bytes() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    (
        fs::read(research_path("suite.json")).expect("read frozen suite"),
        fs::read(research_path("schema.json")).expect("read frozen schema"),
        fs::read(research_path("digests.json")).expect("read frozen digests"),
    )
}

#[test]
fn committed_suite_authenticates_and_matches_derived_root() {
    let authenticated = authenticate_paths(
        &research_path("suite.json"),
        &research_path("schema.json"),
        &research_path("digests.json"),
    )
    .expect("authenticate frozen suite");
    assert_eq!(authenticated.manifest.cases.len(), 19);
    assert_eq!(authenticated.inputs.len(), 169);
    assert_eq!(
        authenticated.expanded_inputs_sha256,
        "28c31631ab5c27926c19582aefdaf257fe53f4ee1263641fc31789f551ccacea"
    );

    let (suite, schema, digests) = committed_bytes();
    let derived = derive_digest_manifest(&suite, &schema).expect("derive reviewed identity");
    let committed: DigestManifest =
        serde_json::from_slice(&digests).expect("parse committed identity");
    assert_eq!(derived, committed);
    assert_eq!(committed.semantic_comparisons, 1_014);
}

#[test]
fn suite_schema_and_expansion_tampering_are_rejected() {
    let (suite, schema, digests) = committed_bytes();

    let mut changed_suite = suite.clone();
    changed_suite.push(b'\n');
    assert!(authenticate_bytes(&changed_suite, &schema, &digests).is_err());

    let mut changed_schema = schema.clone();
    changed_schema.push(b'\n');
    assert!(authenticate_bytes(&suite, &changed_schema, &digests).is_err());

    let mut changed_root: DigestManifest =
        serde_json::from_slice(&digests).expect("parse digest manifest");
    changed_root.expanded_inputs_sha256.replace_range(0..1, "0");
    let changed_root = serde_json::to_vec(&changed_root).expect("serialize tampered root");
    assert!(authenticate_bytes(&suite, &schema, &changed_root).is_err());

    let mut changed_count: DigestManifest =
        serde_json::from_slice(&digests).expect("parse digest manifest");
    changed_count.semantic_comparisons = 1_013;
    let changed_count = serde_json::to_vec(&changed_count).expect("serialize tampered count");
    assert!(authenticate_bytes(&suite, &schema, &changed_count).is_err());
}

#[test]
fn correctness_receipts_are_deterministic_and_strict_gate_is_clean() {
    let authenticated = authenticate_paths(
        &research_path("suite.json"),
        &research_path("schema.json"),
        &research_path("digests.json"),
    )
    .expect("authenticate frozen suite");
    let first = run_correctness(&authenticated).expect("first correctness run");
    let second = run_correctness(&authenticated).expect("second correctness run");
    assert_eq!(first, second);
    assert_eq!(first.receipts_sha256, RECEIPTS_SHA256);
    assert_eq!(first.coverage.receipts, 1_014);
    assert_eq!(first.coverage.by_status.get(&Status::Pass), Some(&990));
    assert_eq!(
        first.coverage.by_status.get(&Status::Unsupported),
        Some(&24)
    );
    assert_eq!(first.coverage.by_status.get(&Status::Fail), None);
    assert_eq!(first.coverage.by_status.get(&Status::Fault), None);
    enforce_strict_gate(&first).expect("zero mismatch/fault gate");

    let mut failing = first;
    failing.coverage.by_status.insert(Status::Fail, 1);
    assert!(enforce_strict_gate(&failing).is_err());
}

#[test]
fn performance_report_has_both_engines_and_identical_modes() {
    let manifest = SuiteManifest {
        schema: "fre.holdout.suite.v1".to_string(),
        suite_id: "timing-contract-test".to_string(),
        freeze_date: "2026-07-14".to_string(),
        oracle: OracleDeclaration {
            implementation: "rust-regex".to_string(),
            version: "1.12.4".to_string(),
            api: "bytes".to_string(),
            unicode: false,
        },
        timing: TimingPolicy {
            warmup_iterations: 1,
            measured_iterations: 2,
        },
        dimensions: Vec::<DimensionDeclaration>::new(),
        cases: vec![CaseSpec {
            id: "literal".to_string(),
            family: "test".to_string(),
            labels: vec!["changing".to_string()],
            pattern: "needle".to_string(),
            generator: GeneratorSpec::Explicit {
                inputs: vec![
                    ExplicitInput {
                        hex: "6e6565646c65".to_string(),
                        intent: "positive".to_string(),
                    },
                    ExplicitInput {
                        hex: "7878".to_string(),
                        intent: "negative".to_string(),
                    },
                ],
            },
        }],
    };
    let inputs = expand_manifest(&manifest).expect("expand timing fixture");
    let authenticated = AuthenticatedSuite {
        manifest,
        inputs,
        suite_sha256: "fixture".to_string(),
        json_schema_sha256: "fixture".to_string(),
        expanded_inputs_sha256: "fixture".to_string(),
    };
    let correctness = run_correctness(&authenticated).expect("fixture correctness");
    let performance =
        run_performance(&authenticated, &correctness).expect("fixture performance diagnostics");
    assert!(!performance.normative);
    assert!(!performance.planner_feedback_permitted);
    assert_eq!(performance.builds.len(), 2);
    assert_eq!(performance.operations.len(), 12);
    for engine in [TimingEngine::FreCandidate, TimingEngine::RustRegexOracle] {
        let builds = performance
            .builds
            .iter()
            .filter(|series| series.engine == engine)
            .count();
        assert_eq!(builds, 1);
        for mode in [ExecutionMode::HotReuse, ExecutionMode::OneShot] {
            let operations = performance
                .operations
                .iter()
                .filter(|series| series.mode == mode && series.engine == engine)
                .count();
            assert_eq!(operations, 3);
        }
    }
}
